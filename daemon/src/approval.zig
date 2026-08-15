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
    /// Who is asking: the pubkey of the event that carried the request, hex.
    ///
    /// A row that says "sign_event, kind 1" and nothing else asks a person to
    /// authorize a signature without telling them whose request it is. It reads
    /// identically whether it came from their own client or from somebody who
    /// read the connection token, and the second one is the whole reason this
    /// queue exists.
    client_buf: [64]u8 = [_]u8{0} ** 64,
    client_len: u8 = 0,
    /// What is being signed: the start of the event's content, for `sign_event`.
    ///
    /// The kind number says what SHAPE it is, never what it says. Approving a
    /// kind:1 without seeing its text is approving a sentence published under
    /// your name, sight unseen.
    preview_buf: [160]u8 = [_]u8{0} ** 160,
    preview_len: u8 = 0,

    pub fn method(self: *const Pending) []const u8 {
        return self.method_buf[0..self.method_len];
    }
    pub fn client(self: *const Pending) []const u8 {
        return self.client_buf[0..self.client_len];
    }
    pub fn preview(self: *const Pending) []const u8 {
        return self.preview_buf[0..self.preview_len];
    }
};

/// The `content` of a `sign_event` template, clipped to fit a `Pending`.
///
/// Clipped on a UTF-8 boundary, because half a character is not a character and
/// this string goes straight into a JSON response and then onto a screen.
fn signEventPreview(gpa: std.mem.Allocator, request: *const nip46.Request, out: *[160]u8) u8 {
    if (request.params.len < 1) return 0;
    const parsed = std.json.parseFromSlice(
        struct { content: []const u8 = "" },
        gpa,
        request.params[0],
        .{ .ignore_unknown_fields = true },
    ) catch return 0;
    defer parsed.deinit();
    const text = std.mem.trim(u8, parsed.value.content, " \t\r\n");
    var n = @min(text.len, out.len);
    while (n > 0 and n < text.len and (text[n] & 0xc0) == 0x80) n -= 1;
    @memcpy(out[0..n], text[0..n]);
    return @intCast(n);
}

const Slot = struct {
    in_use: bool = false,
    info: Pending = .{},
    decision: std.atomic.Value(Decision) = .init(.pending),
    /// How long the operator's answer should last. Written under the lock
    /// before the decision is published, and read after it.
    remember: nip46.Remember = .once,
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
    /// What the operator has already answered, and for how long.
    ///
    /// The library's, shared with Plaza's signer so the two cannot drift on what
    /// a permission means. Until this, Notary prompted for every request
    /// forever: there was no way to say "always allow this app to post notes"
    /// and no way to say "stop asking", which is the prompt fatigue that teaches
    /// people to approve without reading.
    permissions: nip46.Permissions = .{},

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
        return self.submitRemembering(io, info).decision;
    }

    /// What the operator said, and for how long, and whether they said anything
    /// at all. The last one matters: a timeout is not an answer.
    /// A decision and how long it stands. A request nobody answered comes back
    /// `.reject` with `.once`, and `.once` is never stored: only what a person
    /// actually said is remembered.
    pub const Answered = struct { decision: Decision, remember: nip46.Remember };

    pub fn submitRemembering(self: *Broker, io: std.Io, info: Pending) Answered {
        const idx = self.claim(info) orelse return .{ .decision = .reject, .remember = .once };

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
        const how_long = self.slots[idx].remember;
        self.slots[idx].in_use = false;
        self.release();
        _ = self.version.fetchAdd(1, .monotonic);
        if (final == .pending) return .{ .decision = .reject, .remember = .once };
        return .{ .decision = final, .remember = how_long };
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

    /// Denies everything still waiting and frees the slots.
    ///
    /// For signing out: a request that was queued against the key being removed
    /// must not sit there and be approved against whatever key comes next.
    /// REJECTED rather than dropped, because a relay thread is blocked waiting on
    /// each of these and dropping the slot would leave it waiting for a decision
    /// that can no longer arrive.
    pub fn reset(self: *Broker) void {
        self.acquire();
        for (&self.slots) |*slot| {
            if (slot.in_use and slot.decision.load(.monotonic) == .pending) {
                slot.decision.store(.reject, .release);
            }
        }
        self.release();
        _ = self.version.fetchAdd(1, .monotonic);
    }

    /// Applies the GUI's decision to pending entry `id`. Returns true if it was
    /// found and still pending.
    pub fn resolve(self: *Broker, id: u64, decision: Decision) bool {
        return self.resolveFor(id, decision, .once);
    }

    /// The same, with how long the answer should last.
    pub fn resolveFor(self: *Broker, id: u64, decision: Decision, how_long: nip46.Remember) bool {
        if (decision == .pending) return false;
        self.acquire();
        var found = false;
        for (&self.slots) |*slot| {
            if (slot.in_use and slot.info.id == id and slot.decision.load(.monotonic) == .pending) {
                // The duration first, so a thread waking on the decision cannot
                // read a remember value that has not been written yet.
                slot.remember = how_long;
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

/// Whether answering `method` needs the secret key, and so needs a human.
///
/// Everything else is bookkeeping: `connect` and `logout` move a client in and
/// out of the authorized set, `ping` is liveness, and `get_public_key` returns a
/// value that is already printed in the `bunker://` token the user hands out.
///
/// Sending those to the queue was not merely noisy, it was a way to switch the
/// signer off. `submit` parks the calling thread for the full two-minute
/// timeout, and that caller is the relay serve loop, so one request nobody
/// answers stops the signer answering anything. `ping` and `get_public_key`
/// are answered for clients that have NOT connected, by design, so a stranger
/// who knew the bunker pubkey could send one `ping` every two minutes and keep
/// the signer permanently busy without ever presenting the secret.
///
/// An unknown method reaches the human. The bunker rejects it afterwards, but a
/// name this does not recognise is not something to wave through here.
fn touchesKey(method_name: []const u8) bool {
    const method = nip46.Method.fromString(method_name) orelse return true;
    return switch (method) {
        .sign_event, .nip44_encrypt, .nip44_decrypt => true,
        .connect, .ping, .get_public_key, .logout => false,
    };
}

fn decide(ctx: ?*anyopaque, request: *const nip46.Request, client: [32]u8) nip46.Decision {
    const self: *const Interactive = @ptrCast(@alignCast(ctx.?));

    // The static allowlist is the first gate: a disallowed request is denied
    // outright and never bothers the human.
    if (self.config.policy().decide(request, client) == .reject) return .reject;

    // Only a request that uses the key is worth waking somebody up for.
    if (!touchesKey(request.method)) return .approve;

    // Already answered, and the answer has not lapsed. This is what stops
    // Notary asking about the same thing forever: the operator says "always" or
    // "for a day" once, and the queue stays for the things they have not
    // decided yet.
    const method = nip46.Method.fromString(request.method) orelse return .reject;
    // The library's reader, not a second one. Unreadable is -1, which the
    // store treats as a question of its own rather than letting it ride on a
    // permission granted for some other kind.
    const kind: i32 = if (nostr.nip46.signEventKind(self.gpa, request)) |k| @intCast(k) else -1;
    const now_ms = std.Io.Timestamp.now(self.io, .real).toMilliseconds();
    if (self.broker.permissions.remembered(client, method, kind, now_ms)) |allowed| {
        return if (allowed) .approve else .reject;
    }

    var info = Pending{};
    const mlen = @min(request.method.len, info.method_buf.len);
    @memcpy(info.method_buf[0..mlen], request.method[0..mlen]);
    info.method_len = @intCast(mlen);
    info.created_at = std.Io.Timestamp.now(self.io, .real).toSeconds();
    // Who, and what. Neither was here, so the row said "sign_event, kind 1" and
    // left the person to guess both.
    _ = std.fmt.bufPrint(&info.client_buf, "{x}", .{client}) catch {};
    info.client_len = 64;
    // Both already read above, for the permission lookup.
    info.kind = kind;
    if (method == .sign_event) {
        info.preview_len = signEventPreview(self.gpa, request, &info.preview_buf);
    }

    const answered = self.broker.submitRemembering(self.io, info);
    // `.once` is never written down, which is how a timeout leaves the question
    // open: an operator who walked away from the machine said nothing, and
    // storing silence as a denial would lock a client out over an absence.
    self.broker.permissions.remember(client, method, kind, answered.decision == .approve, answered.remember, now_ms);
    return switch (answered.decision) {
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
fn resolveFirstFor(broker: *Broker, decision: Decision, how_long: nip46.Remember) void {
    var buf: [4]Pending = undefined;
    var tries: usize = 0;
    while (tries < 1_000_000) : (tries += 1) {
        if (broker.snapshot(&buf) > 0) {
            _ = broker.resolveFor(buf[0].id, decision, how_long);
            return;
        }
        std.Thread.yield() catch {};
    }
}

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
    try testing.expectEqual(nip46.Decision.reject, p.decide(&req, [_]u8{0} ** 32));
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

    // sign_event, because that is what a human is for. get_public_key used to
    // stand in here and no longer escalates at all.
    const tmpl = "{\"kind\":1,\"content\":\"hi\",\"tags\":[],\"created_at\":1}";
    const params = [_][]const u8{tmpl};
    const req = nip46.Request{ .id = "1", .method = "sign_event", .params = &params };
    try testing.expectEqual(nip46.Decision.reject, p.decide(&req, [_]u8{0} ** 32));
}

test "housekeeping never reaches the human, so a stranger cannot park the relay thread" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Short timeout, and nothing is resolving. Anything that escalates parks
    // here for the whole timeout and then comes back .reject, so an .approve
    // that returns immediately is the assertion: it never went to the queue.
    var broker = Broker{ .timeout_ms = 400 };
    var cfg = PolicyConfig{ .gpa = testing.allocator };
    const inter = Interactive{ .broker = &broker, .config = &cfg, .io = io, .gpa = testing.allocator };
    const p = inter.asPolicy();

    // ping and get_public_key are answered for clients that have NOT connected,
    // so if these escalated, one every two minutes from anyone who knew the
    // bunker pubkey would keep the signer permanently busy.
    for ([_][]const u8{ "ping", "get_public_key", "connect", "logout" }) |m| {
        const req = nip46.Request{ .id = "1", .method = m, .params = &.{} };
        try testing.expectEqual(nip46.Decision.approve, p.decide(&req, [_]u8{0} ** 32));
    }
    try testing.expectEqual(@as(u64, 0), broker.version.load(.monotonic));

    // An unrecognised name is not waved through.
    const odd = nip46.Request{ .id = "2", .method = "nip04_decrypt", .params = &.{} };
    try testing.expectEqual(nip46.Decision.reject, p.decide(&odd, [_]u8{0} ** 32));
}

test "resetting the broker rejects what was waiting rather than dropping it" {
    var broker = Broker{};
    broker.slots[0] = .{ .in_use = true, .info = .{ .id = 1 }, .decision = std.atomic.Value(Decision).init(.pending) };
    broker.slots[1] = .{ .in_use = true, .info = .{ .id = 2 }, .decision = std.atomic.Value(Decision).init(.pending) };

    broker.reset();

    // REJECTED, not cleared. A relay thread is parked waiting on each of these,
    // and freeing the slot would leave it waiting for an answer that can never
    // arrive. Signing out has to unblock them, not strand them.
    try std.testing.expectEqual(Decision.reject, broker.slots[0].decision.load(.monotonic));
    try std.testing.expectEqual(Decision.reject, broker.slots[1].decision.load(.monotonic));

    // A request already decided keeps its answer.
    broker.slots[2] = .{ .in_use = true, .info = .{ .id = 3 }, .decision = std.atomic.Value(Decision).init(.approve) };
    broker.reset();
    try std.testing.expectEqual(Decision.approve, broker.slots[2].decision.load(.monotonic));
}

test "an answer the operator asked to remember is not asked again" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Nothing resolves the second request, and the timeout is short. Anything
    // that escalates parks for the whole timeout and comes back .reject, so an
    // immediate .approve is the assertion: it was answered from memory.
    var broker = Broker{ .timeout_ms = 400 };
    var cfg = PolicyConfig{ .gpa = testing.allocator };
    const inter = Interactive{ .broker = &broker, .config = &cfg, .io = io, .gpa = testing.allocator };
    const p = inter.asPolicy();

    const client = [_]u8{7} ** 32;
    const tmpl = "{\"kind\":1,\"content\":\"hi\",\"tags\":[],\"created_at\":1}";
    const req = nip46.Request{ .id = "1", .method = "sign_event", .params = &[_][]const u8{tmpl} };

    {
        const t = try std.Thread.spawn(.{}, resolveFirstFor, .{ &broker, Decision.approve, nip46.Remember.always });
        defer t.join();
        try testing.expectEqual(nip46.Decision.approve, p.decide(&req, client));
    }
    const asked = broker.version.load(.monotonic);

    // The same client, method and kind: answered without a prompt.
    try testing.expectEqual(nip46.Decision.approve, p.decide(&req, client));
    try testing.expectEqual(asked, broker.version.load(.monotonic));

    // A different kind is a separate question, so it escalates and times out.
    const other = "{\"kind\":30023,\"content\":\"hi\",\"tags\":[],\"created_at\":1}";
    const other_req = nip46.Request{ .id = "2", .method = "sign_event", .params = &[_][]const u8{other} };
    try testing.expectEqual(nip46.Decision.reject, p.decide(&other_req, client));
    try testing.expect(broker.version.load(.monotonic) > asked);

    // So is the same kind from a different client.
    var stranger = Broker{ .timeout_ms = 400 };
    const inter2 = Interactive{ .broker = &stranger, .config = &cfg, .io = io, .gpa = testing.allocator };
    stranger.permissions = broker.permissions;
    try testing.expectEqual(nip46.Decision.reject, inter2.asPolicy().decide(&req, [_]u8{9} ** 32));
}

test "a denial is remembered too, so a refused app cannot pester" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var broker = Broker{ .timeout_ms = 400 };
    var cfg = PolicyConfig{ .gpa = testing.allocator };
    const inter = Interactive{ .broker = &broker, .config = &cfg, .io = io, .gpa = testing.allocator };
    const p = inter.asPolicy();

    const client = [_]u8{3} ** 32;
    const tmpl = "{\"kind\":1,\"content\":\"hi\",\"tags\":[],\"created_at\":1}";
    const req = nip46.Request{ .id = "1", .method = "sign_event", .params = &[_][]const u8{tmpl} };

    {
        const t = try std.Thread.spawn(.{}, resolveFirstFor, .{ &broker, Decision.reject, nip46.Remember.hour });
        defer t.join();
        try testing.expectEqual(nip46.Decision.reject, p.decide(&req, client));
    }
    const asked = broker.version.load(.monotonic);

    // Refused again without waking anyone. A timed-out escalation would also
    // read .reject, so the version is what separates the two.
    try testing.expectEqual(nip46.Decision.reject, p.decide(&req, client));
    try testing.expectEqual(asked, broker.version.load(.monotonic));
}

test "an answer given once is asked again the next time" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var broker = Broker{ .timeout_ms = 400 };
    var cfg = PolicyConfig{ .gpa = testing.allocator };
    const inter = Interactive{ .broker = &broker, .config = &cfg, .io = io, .gpa = testing.allocator };
    const p = inter.asPolicy();

    const client = [_]u8{5} ** 32;
    const tmpl = "{\"kind\":1,\"content\":\"hi\",\"tags\":[],\"created_at\":1}";
    const req = nip46.Request{ .id = "1", .method = "sign_event", .params = &[_][]const u8{tmpl} };

    {
        const t = try std.Thread.spawn(.{}, resolveFirstFor, .{ &broker, Decision.approve, nip46.Remember.once });
        defer t.join();
        try testing.expectEqual(nip46.Decision.approve, p.decide(&req, client));
    }
    const asked = broker.version.load(.monotonic);

    // Nothing is resolving now, so a second ask parks and times out. If "once"
    // had been stored this would come back .approve at once.
    try testing.expectEqual(nip46.Decision.reject, p.decide(&req, client));
    try testing.expect(broker.version.load(.monotonic) > asked);
}

test "walking away is not an answer, so a timeout is not remembered as a denial" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var broker = Broker{ .timeout_ms = 300 };
    var cfg = PolicyConfig{ .gpa = testing.allocator };
    const inter = Interactive{ .broker = &broker, .config = &cfg, .io = io, .gpa = testing.allocator };
    const p = inter.asPolicy();

    const client = [_]u8{11} ** 32;
    const tmpl = "{\"kind\":1,\"content\":\"hi\",\"tags\":[],\"created_at\":1}";
    const req = nip46.Request{ .id = "1", .method = "sign_event", .params = &[_][]const u8{tmpl} };

    // Nobody is at the machine: this one times out.
    try testing.expectEqual(nip46.Decision.reject, p.decide(&req, client));

    // They come back and approve. If the timeout had been written down as a
    // denial, this would be refused from memory without ever reaching them.
    const t = try std.Thread.spawn(.{}, resolveFirstFor, .{ &broker, Decision.approve, nip46.Remember.once });
    defer t.join();
    try testing.expectEqual(nip46.Decision.approve, p.decide(&req, client));
}
