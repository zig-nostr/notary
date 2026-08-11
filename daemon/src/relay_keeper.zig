//! Watches the signer's relay connections for silence.
//!
//! Each relay gets a thread that dials, subscribes, and then blocks in
//! `receive` until the relay says something. When a peer goes away without
//! closing, that thread waits forever: no error, no timeout, no reconnect. For
//! a client that is bad; for a signer it is worse, because the symptom is that
//! remote signing stops working with nothing anywhere saying so. The approval
//! window never opens, the client's request times out, and the daemon's own
//! status still reads "connected".
//!
//! Nothing inside that thread can notice, which is the whole difficulty: a
//! thread waiting on a dead peer is the last thing able to tell that it is
//! waiting. So one more thread watches all of them. It sends the keepalive, and
//! it is the one still able to act when no answer comes.
//!
//! The numbers are Amethyst's, from their survey of 122 relays: idle timeouts
//! cluster around 60, 120, 240, 300 and 600 seconds, and a ping only reliably
//! holds a connection open when its interval is at most about half the shortest
//! tier. Ninety seconds is three missed answers.
//!
//! **Answering the relay's pings is not a substitute for sending our own.** A
//! relay's idle timer counts what it RECEIVES from us, so the pong the library
//! sends in reply to its ping does not reset it. Amethyst measured exactly that
//! against a live relay.
//!
//! **This is deliberately not a socket receive timeout.** `SO_RCVTIMEO` makes
//! the read return EAGAIN, and this io model treats EAGAIN as a programmer bug
//! and panics. It was tried in this very daemon, for the approval server
//! (notary#47): it compiled, passed every test, and panicked on the first
//! wedged connection, turning a stall into a remote crash. `shutdown` is a
//! syscall on the descriptor and is safe to call while another thread is
//! blocked reading it.

const std = @import("std");
const nostr = @import("nostr");

/// Silence after which the keeper asks the relay whether it is still there.
pub const ping_after_ms: i64 = 30_000;
/// Silence after which it stops asking and cuts the connection.
pub const dead_after_ms: i64 = 90_000;
/// How often the keeper looks. Short enough that ninety seconds means ninety,
/// long enough to cost nothing.
pub const tick_ms: u64 = 5_000;

/// What to do about one connection, given how long it has been silent and how
/// long since it was last pinged. Both null mean "no measurement".
///
/// A pure function, so the policy can be asserted without a socket, a thread or
/// a clock. Everything interesting about this file is in here.
pub const Action = enum { leave_it, ping, give_up };

pub fn action(idle_ms: ?i64, since_ping_ms: ?i64) Action {
    // Nothing has ever arrived on this connection. That is the window between
    // the handshake and the relay's first word, not a stall, and reading a
    // missing measurement as an infinite one would cut off every relay that
    // took a moment to answer.
    const idle = idle_ms orelse return .leave_it;
    if (idle >= dead_after_ms) return .give_up;
    if (idle < ping_after_ms) return .leave_it;
    // Silent past the interval. Ping, but only once per interval: at a five
    // second tick a socket that has stopped answering would otherwise collect a
    // dozen more pings on its way to being declared dead.
    const since = since_ping_ms orelse return .ping;
    return if (since >= ping_after_ms) .ping else .leave_it;
}

/// The live connections, one slot per relay.
///
/// A slot is filled by the thread that dialled it and cleared by that same
/// thread BEFORE the connection is freed, both under the lock, and the keeper
/// holds the lock for as long as it touches a pointer. That is what stops the
/// keeper being inside `ping` on a `Relay` whose owner has already returned and
/// run its `deinit`.
pub const Table = struct {
    lock: std.atomic.Value(bool) = .init(false),
    live: []?*nostr.relay.Relay,
    pinged_ms: []i64,
    /// Parallel to `live`, so the keeper can say a relay has gone quiet. Null
    /// in headless mode, where nothing reports status.
    status: ?[]std.atomic.Value(u8) = null,

    pub fn init(gpa: std.mem.Allocator, count: usize) !Table {
        const live = try gpa.alloc(?*nostr.relay.Relay, count);
        @memset(live, null);
        const pinged = try gpa.alloc(i64, count);
        @memset(pinged, 0);
        return .{ .live = live, .pinged_ms = pinged };
    }

    fn acquire(self: *Table) void {
        while (self.lock.cmpxchgWeak(false, true, .acquire, .monotonic) != null) {}
    }
    fn release(self: *Table) void {
        self.lock.store(false, .release);
    }

    /// Offers a connection to the keeper, or withdraws it with null.
    ///
    /// Named "offer" and not "publish": it hands over a pointer, and nothing
    /// here sends anything to a relay.
    pub fn offer(self: *Table, index: usize, relay: ?*nostr.relay.Relay) void {
        if (index >= self.live.len) return;
        self.acquire();
        defer self.release();
        self.live[index] = relay;
        self.pinged_ms[index] = 0;
    }

    fn setStatus(self: *Table, index: usize, value: u8) void {
        const st = self.status orelse return;
        if (index >= st.len) return;
        st[index].store(value, .monotonic);
    }
};

/// The keeper's loop. `quiet_status` and `dead_status` are the raw
/// `RelayStatus` values to publish, passed in so this file does not have to
/// know about the HTTP layer's enum.
pub fn run(gpa: std.mem.Allocator, table: *Table, quiet_status: u8, dead_status: u8) void {
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    while (true) {
        io.sleep(std.Io.Duration.fromMilliseconds(tick_ms), .awake) catch {};
        const now = std.Io.Timestamp.now(io, .awake).toMilliseconds();
        for (0..table.live.len) |i| {
            table.acquire();
            defer table.release();
            const relay = table.live[i] orelse continue;
            const idle = relay.idleMs(io);
            const since: ?i64 = if (table.pinged_ms[i] == 0) null else now - table.pinged_ms[i];
            switch (action(idle, since)) {
                .leave_it => {},
                .ping => {
                    // A failed write is not a verdict on its own; the silence
                    // deadline is. Tearing the socket down on a write error
                    // here would race the owning thread's own error handling.
                    relay.ping(io) catch {};
                    table.pinged_ms[i] = now;
                    table.setStatus(i, quiet_status);
                },
                .give_up => {
                    // Half-close, so the owner's blocked `receive` returns and
                    // it reconnects through its own path. NOT deinit: the owner
                    // still holds this and has to unwind.
                    relay.shutdown(io);
                    table.live[i] = null;
                    table.pinged_ms[i] = 0;
                    table.setStatus(i, dead_status);
                },
            }
        }
    }
}

test "a connection that has never spoken is not a stalled one" {
    // The window between the handshake and the relay's first word. Reading a
    // missing measurement as an infinite one would cut off every relay that
    // took a moment to answer, which on a slow network is all of them.
    try std.testing.expectEqual(Action.leave_it, action(null, null));
    try std.testing.expectEqual(Action.leave_it, action(null, 999_999));
}

test "a talking relay is left alone" {
    try std.testing.expectEqual(Action.leave_it, action(0, null));
    try std.testing.expectEqual(Action.leave_it, action(ping_after_ms - 1, null));
}

test "a relay that has gone quiet is asked whether it is still there" {
    try std.testing.expectEqual(Action.ping, action(ping_after_ms, null));
}

test "a quiet relay is asked once per interval, not once per look" {
    const idle = ping_after_ms + 5_000;
    try std.testing.expectEqual(Action.leave_it, action(idle, 5_000));
    try std.testing.expectEqual(Action.ping, action(idle, ping_after_ms));
}

test "a relay that answers none of three pings is given up on" {
    try std.testing.expectEqual(Action.give_up, action(dead_after_ms, 0));
    // The deadline wins over the ping interval: a socket this far gone is not
    // asked again, it is closed.
    try std.testing.expectEqual(Action.give_up, action(dead_after_ms + 60_000, dead_after_ms));
}

test "the deadline is a multiple of the interval, so silence is answered before it is fatal" {
    // Not decoration. If the deadline were under the interval the keeper would
    // declare a relay dead without ever having asked it anything, and every
    // quiet connection would be recycled on a timer.
    try std.testing.expect(dead_after_ms >= ping_after_ms * 2);
}

test "a slot past the end of the table is ignored rather than trusted" {
    // The table is sized from the relay list at startup. An index past it is a
    // caller bug, and the useful failure is nothing happening rather than a
    // write into whatever is next in memory.
    const gpa = std.testing.allocator;
    var table = try Table.init(gpa, 2);
    defer gpa.free(table.live);
    defer gpa.free(table.pinged_ms);
    table.offer(7, null);
    try std.testing.expectEqual(@as(usize, 2), table.live.len);
}

test "offering and withdrawing a slot clears the ping clock with it" {
    // A slot reused by the next connection must not inherit the last one's
    // ping time, or a fresh socket can be declared overdue before it has been
    // asked anything.
    const gpa = std.testing.allocator;
    var table = try Table.init(gpa, 1);
    defer gpa.free(table.live);
    defer gpa.free(table.pinged_ms);
    table.pinged_ms[0] = 12_345;
    table.offer(0, null);
    try std.testing.expectEqual(@as(i64, 0), table.pinged_ms[0]);
}
