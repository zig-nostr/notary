//! Cross-thread approval broker + the interactive NIP-46 policy for GUI mode.
//!
//! Architecture (see README): the daemon holds the key and does all Nostr work;
//! a separate GUI process approves requests over the loopback HTTP API (see
//! `approval_http.zig`). This module is the seam between the two:
//!
//! - A relay thread, inside `bunker.handle`, calls the interactive policy's
//!   `decide`. For a request the static allowlist already permits, `decide`
//!   SUBMITS it to the broker and blocks the relay thread until the GUI resolves
//!   it (or a timeout denies it, so a relay thread never blocks forever).
//! - The HTTP server thread lists the queue (`snapshot`) and applies the GUI's
//!   decisions (`resolve`).
//!
//! The broker is deliberately independent of the `std.Io` model: a tiny atomic
//! spinlock guards the small pending array (contention is near-zero, approvals
//! are human-paced and rare), and each entry carries an atomic decision slot.
//! Only the submit poll-wait uses the caller's `io.sleep`, exactly as the relay
//! reconnect loop already does.

const std = @import("std");
const nostr = @import("nostr");
const PolicyConfig = nostr.nip46.PolicyConfig;

const nip46 = nostr.nip46;

pub const Decision = enum(u8) { pending, approve, reject };

/// Display metadata for one awaiting request. Strings are copied in, so the
/// broker never aliases relay-thread memory.
pub const Pending = struct {
    id: u64 = 0,
    method_buf: [24]u8 = undefined,
    method_len: u8 = 0,
    /// Event kind for `sign_event`, else -1.
    kind: i32 = -1,
    created_at: i64 = 0,

    pub fn method(self: *const Pending) []const u8 {
        return self.method_buf[0..self.method_len];
    }
};

const Slot = struct {
    in_use: bool = false,
    info: Pending = .{},
    decision: std.atomic.Value(Decision) = .init(.pending),
};

pub const Broker = struct {
    /// Max simultaneously-pending approvals; further submits fail closed.
    pub const capacity = 32;

    lock: std.atomic.Value(bool) = .init(false),
    slots: [capacity]Slot = [_]Slot{.{}} ** capacity,
    next_id: u64 = 1,
    /// Bumps on every queue change so a poller can detect activity.
    version: std.atomic.Value(u64) = .init(0),
    /// Milliseconds a submitted request waits before it is auto-denied when no
    /// GUI resolves it.
    timeout_ms: u64 = 120_000,

    fn acquire(self: *Broker) void {
        while (self.lock.cmpxchgWeak(false, true, .acquire, .monotonic) != null) {
            std.Thread.yield() catch {};
        }
    }
    fn release(self: *Broker) void {
        self.lock.store(false, .release);
    }

    /// Submits `info` and blocks until the GUI resolves it or the timeout denies
    /// it. Runs on a relay thread; `io.sleep` paces the poll.
    pub fn submit(self: *Broker, io: std.Io, info: Pending) Decision {
        const idx = self.claim(info) orelse return .reject;

        // Poll the decision slot, pacing with io.sleep (as the reconnect loop
        // does). Elapsed time is counted in sleep steps, no wall clock needed.
        const step_ms = 50;
        var waited_ms: u64 = 0;
        var decision = self.slots[idx].decision.load(.acquire);
        while (decision == .pending and waited_ms < self.timeout_ms) {
            io.sleep(std.Io.Duration.fromMilliseconds(step_ms), .awake) catch {};
            waited_ms += step_ms;
            decision = self.slots[idx].decision.load(.acquire);
        }

        // Honor a last-moment resolve that raced the timeout; else deny.
        self.acquire();
        const final = self.slots[idx].decision.load(.acquire);
        self.slots[idx].in_use = false;
        self.release();
        _ = self.version.fetchAdd(1, .monotonic);
        return if (final != .pending) final else .reject;
    }

    fn claim(self: *Broker, info: Pending) ?usize {
        self.acquire();
        defer self.release();
        for (&self.slots, 0..) |*slot, i| {
            if (!slot.in_use) {
                slot.* = .{ .in_use = true, .info = info, .decision = .init(.pending) };
                slot.info.id = self.next_id;
                self.next_id += 1;
                _ = self.version.fetchAdd(1, .monotonic);
                return i;
            }
        }
        return null;
    }

    /// Copies the still-pending entries into `out`, returning the count.
    pub fn snapshot(self: *Broker, out: []Pending) usize {
        self.acquire();
        defer self.release();
        var n: usize = 0;
        for (&self.slots) |*slot| {
            if (n >= out.len) break;
            if (slot.in_use and slot.decision.load(.monotonic) == .pending) {
                out[n] = slot.info;
                n += 1;
            }
        }
        return n;
    }

    /// Applies the GUI's decision to pending entry `id`. Returns true if it was
    /// found and still pending.
    pub fn resolve(self: *Broker, id: u64, decision: Decision) bool {
        if (decision == .pending) return false;
        self.acquire();
        var found = false;
        for (&self.slots) |*slot| {
            if (slot.in_use and slot.info.id == id and slot.decision.load(.monotonic) == .pending) {
                slot.decision.store(decision, .release);
                found = true;
                break;
            }
        }
        self.release();
        if (found) _ = self.version.fetchAdd(1, .monotonic);
        return found;
    }
};

/// The interactive policy: pre-filter through the static allowlist, then escalate
/// anything it permits to the GUI via the broker. One per relay thread (each
/// carries that thread's `io`/allocator), constructed in `serveRelayForever`.
pub const Interactive = struct {
    broker: *Broker,
    config: *const PolicyConfig,
    io: std.Io,
    gpa: std.mem.Allocator,

    pub fn asPolicy(self: *const Interactive) nip46.Policy {
        return .{ .ctx = @constCast(self), .decideFn = &decide };
    }
};

fn decide(ctx: ?*anyopaque, request: *const nip46.Request) nip46.Decision {
    const self: *const Interactive = @ptrCast(@alignCast(ctx.?));

    // The static allowlist is the first gate: a disallowed request is denied
    // outright and never bothers the human.
    if (self.config.policy().decide(request) == .reject) return .reject;

    var info = Pending{};
    const mlen = @min(request.method.len, info.method_buf.len);
    @memcpy(info.method_buf[0..mlen], request.method[0..mlen]);
    info.method_len = @intCast(mlen);
    info.created_at = std.Io.Timestamp.now(self.io, .real).toSeconds();
    if (nip46.Method.fromString(request.method)) |method| {
        if (method == .sign_event) {
            if (nostr.nip46.signEventKind(self.gpa, request)) |k| info.kind = k;
        }
    }

    return switch (self.broker.submit(self.io, info)) {
        .approve => .approve,
        else => .reject,
    };
}

// ---------------------------------------------------------------------------
// Tests, drive the broker across real threads (a resolver thread stands in for
// the GUI), and check the interactive policy's allowlist pre-filter.
// ---------------------------------------------------------------------------

const testing = std.testing;

/// Stand-in for the GUI: waits for one pending entry, then resolves it.
fn resolveFirst(broker: *Broker, decision: Decision) void {
    var buf: [4]Pending = undefined;
    var tries: usize = 0;
    while (tries < 1_000_000) : (tries += 1) {
        if (broker.snapshot(&buf) > 0) {
            _ = broker.resolve(buf[0].id, decision);
            return;
        }
        std.Thread.yield() catch {};
    }
}

test "broker submit blocks until the GUI resolves it" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var broker = Broker{ .timeout_ms = 5_000 };
    const t = try std.Thread.spawn(.{}, resolveFirst, .{ &broker, Decision.approve });
    defer t.join();

    var info = Pending{};
    info.method_len = 10;
    @memcpy(info.method_buf[0..10], "sign_event");
    try testing.expectEqual(Decision.approve, broker.submit(io, info));
}

test "broker denies on timeout when nothing resolves it" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var broker = Broker{ .timeout_ms = 120 };
    try testing.expectEqual(Decision.reject, broker.submit(io, Pending{}));
}

test "interactive policy denies allowlist-disallowed requests without prompting" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var broker = Broker{};
    const allowed = [_]nip46.Method{.get_public_key}; // sign_event NOT allowed
    var cfg = PolicyConfig{ .gpa = testing.allocator, .allowed_methods = &allowed };
    const inter = Interactive{ .broker = &broker, .config = &cfg, .io = io, .gpa = testing.allocator };
    const p = inter.asPolicy();

    const tmpl = "{\"kind\":1,\"content\":\"x\",\"tags\":[],\"created_at\":1}";
    const req = nip46.Request{ .id = "1", .method = "sign_event", .params = &[_][]const u8{tmpl} };
    try testing.expectEqual(nip46.Decision.reject, p.decide(&req));
    // Never enqueued: a disallowed request must not reach the GUI.
    var buf: [1]Pending = undefined;
    try testing.expectEqual(@as(usize, 0), broker.snapshot(&buf));
}

test "interactive policy escalates an allowed request and returns the GUI decision" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var broker = Broker{ .timeout_ms = 5_000 };
    var cfg = PolicyConfig{ .gpa = testing.allocator }; // no restriction
    const inter = Interactive{ .broker = &broker, .config = &cfg, .io = io, .gpa = testing.allocator };
    const p = inter.asPolicy();

    const t = try std.Thread.spawn(.{}, resolveFirst, .{ &broker, Decision.reject });
    defer t.join();

    const req = nip46.Request{ .id = "1", .method = "get_public_key", .params = &.{} };
    try testing.expectEqual(nip46.Decision.reject, p.decide(&req));
}
