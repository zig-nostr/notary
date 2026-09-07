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
//! When it pings and when it gives up is `nostr.liveness`, which is where those
//! numbers belong: they were the same numbers here and in the client built on
//! this library, written down in neither. They are Amethyst's, from their
//! survey of 122 relays.
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
        io.sleep(std.Io.Duration.fromMilliseconds(nostr.liveness.tick_ms), .awake) catch {};
        const now = std.Io.Timestamp.now(io, .awake).toMilliseconds();
        for (0..table.live.len) |i| {
            table.acquire();
            defer table.release();
            const relay = table.live[i] orelse continue;
            const idle = relay.idleMs(io);
            const since: ?i64 = if (table.pinged_ms[i] == 0) null else now - table.pinged_ms[i];
            switch (nostr.liveness.action(idle, since)) {
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
