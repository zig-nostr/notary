//! Minimal, hardened loopback HTTP approval API for GUI mode.
//!
//! The GUI process drives approvals over this API. It never holds the key.
//! Deliberately tiny (fixed routes, no keep-alive, no chunked encoding) to keep
//! the key-holding daemon's attack surface small:
//!
//!   GET  /info              {"state":..,"pubkey":..,"bunker":..,"relays":[{"url":..,"status":..}],"timeout_ms":N}
//!   POST /setup             {"passphrase":..,"secret":..?} → create/import a key
//!   POST /unlock            {"passphrase":..} → decrypt the key file
//!   POST /lock              → clear sessions and exit, keeping the key
//!   POST /export            {"passphrase":..,"form":"ncryptsec"|"nsec"} → the key
//!   GET  /pending?since=N   long-poll (~1s) → {"version":N,"pending":[...]}
//!   POST /decision          {"id":N,"decision":"approve"|"reject"} → {"ok":bool}
//!
//! `/info` reports the key state (`uninitialized`/`locked`/`unlocked`); the GUI
//! drives first-run key onboarding through `/setup` and `/unlock`. The key is
//! created and decrypted in the daemon, only the passphrase (and, on import,
//! the operator's chosen secret) crosses the API, never a derived key.
//!
//! Every request must carry `Authorization: Bearer <token>`; the token is
//! generated at startup and written to a 0600 file only the same user can read.
//! Bound to loopback only.

const std = @import("std");
const nostr = @import("nostr");
const approval = @import("approval.zig");
const onboarding = @import("onboarding.zig");

const net = std.Io.net;
const nip46 = nostr.nip46;
const ipc = nostr.signer_ipc;
const Broker = approval.Broker;
const Pending = approval.Pending;
const Gate = onboarding.Gate;

/// Live connection state of one relay, reported per relay on `/info`.
/// A relay connection's live state.
///
/// `quiet` is the one this daemon could not express, and the reason
/// "connected" could be a lie: the socket is open, nothing has come down it for
/// a while, and a keepalive is out with no answer yet. Not disconnected,
/// because nothing has failed; not plainly connected either, because the last
/// evidence of that is a minute old. For a signer that distinction matters more
/// than for a client, since the failure it hides is "signing silently stopped".
pub const RelayStatus = enum(u8) { connecting, connected, disconnected, quiet };

pub const Info = struct {
    relays: []const []const u8,
    timeout_ms: u64,
    /// Optional connection secret clients must echo; folded into the `bunker://`
    /// URI reported on `/info`. Null in the turnkey case.
    secret: ?[]const u8 = null,
    /// Live per-relay status, parallel to `relays` (the relay threads update it,
    /// `/info` reads it). Null in headless mode, where nothing serves `/info`.
    relay_status: ?[]std.atomic.Value(u8) = null,
};

pub const Server = struct {
    gpa: std.mem.Allocator,
    broker: *Broker,
    /// The clients that have completed a connect, shared with every relay
    /// thread. `/nostrconnect` adds to it: adopting a client that invited us is
    /// authorizing it, and doing that here rather than on the relay threads is
    /// the whole point of the flow (nobody sends us a request first).
    clients: ?*nip46.AuthorizedClients = null,
    /// Key-onboarding gate: reports its state on /info and is driven by /setup
    /// and /unlock. The key it guards is created/decrypted in the daemon and
    /// never crosses this API.
    gate: *Gate,
    /// Bearer token clients must present.
    token: []const u8,
    info: Info,
    host: []const u8,
    port: u16,

    active: std.atomic.Value(u32) = .init(0),
    /// Filled once the listener is up. With `port` 0 this is the only place the
    /// real port exists.
    bound_port: std.atomic.Value(u16) = .init(0),
    in_flight: [max_conns]InFlight = [_]InFlight{.{}} ** max_conns,
    in_flight_lock: std.atomic.Value(bool) = .init(false),

    const max_conns = 8;

    /// A connection currently held by a handler thread, so it can be cut off
    /// if it stops making progress.
    const InFlight = struct {
        used: bool = false,
        stream: net.Stream = undefined,
        started_ms: i64 = 0,
    };

    /// How long one connection may hold a handler thread.
    ///
    /// Generous next to what the GUI does, which is one request and one
    /// response with a long poll bounded at a second. It is a floor under the
    /// worst case, not a budget anything normally touches.
    const conn_deadline_ms = 15_000;

    fn lockInFlight(self: *Server) void {
        while (self.in_flight_lock.cmpxchgWeak(false, true, .acquire, .monotonic) != null) {
            std.Thread.yield() catch {};
        }
    }
    fn unlockInFlight(self: *Server) void {
        self.in_flight_lock.store(false, .release);
    }

    fn track(self: *Server, stream: net.Stream, now_ms: i64) ?usize {
        self.lockInFlight();
        defer self.unlockInFlight();
        for (&self.in_flight, 0..) |*e, i| {
            if (!e.used) {
                e.* = .{ .used = true, .stream = stream, .started_ms = now_ms };
                return i;
            }
        }
        return null;
    }

    /// Releases slot `i`. Held under the lock and BEFORE the handler closes the
    /// socket, so the reaper can never act on a descriptor that has been closed
    /// and handed to something else.
    fn untrack(self: *Server, i: usize) void {
        self.lockInFlight();
        defer self.unlockInFlight();
        self.in_flight[i].used = false;
    }

    /// Cuts off every connection that has held a thread past the deadline.
    ///
    /// `shutdown` rather than `close`: the handler still owns the descriptor
    /// and will close it on its way out. Shutting the read side down makes its
    /// blocked read return, which is the whole point.
    fn reapStale(self: *Server, io: std.Io, now_ms: i64) void {
        self.lockInFlight();
        defer self.unlockInFlight();
        for (&self.in_flight) |*e| {
            if (!e.used) continue;
            if (now_ms - e.started_ms < conn_deadline_ms) continue;
            e.stream.shutdown(io, .both) catch {};
        }
    }

    /// Binds loopback and serves forever on the calling thread.
    ///
    /// The bind is EXCLUSIVE, deliberately. `reuse_address` reads like the
    /// ordinary "let me restart without waiting out TIME_WAIT" flag, and on
    /// POSIX it also sets SO_REUSEPORT: a second process may then bind the same
    /// address, and on this platform the newer socket takes the new
    /// connections. Any process running as this user could therefore quietly
    /// become the approval API without disturbing this one, and the GUI, which
    /// has no way to tell one from the other, would hand it the unlock
    /// passphrase or an imported nsec. That is measured behaviour, not theory.
    ///
    /// Without the flag a duplicate bind fails, this listener refuses to start,
    /// and the daemon exits instead of leaving a hole open.
    pub fn run(self: *Server, io: std.Io) !void {
        const addr = try net.IpAddress.parseIp4(self.host, self.port);
        var server = try addr.listen(io, .{});
        // Watches the connections the handlers hold and cuts off any that stops
        // making progress. There are only eight handler threads, and a peer
        // that opened a socket and wrote half a request line held one forever:
        // the read loop returns on EOF or a full head and nothing else. Eight
        // such sockets took the whole server, and holding one costs no
        // credential, because the bearer token is checked only after the
        // request head has been read.
        //
        // What that bought an attacker was not a broken API but a signer that
        // stops signing: the GUI cannot reach the queue, every request waiting
        // on a human is denied when the broker times out, and a daemon that
        // came up locked can never be unlocked.
        //
        // A watchdog rather than a socket timeout, and that is not a
        // preference. SO_RCVTIMEO makes `recv` return EAGAIN, which this io
        // model treats as a programmer bug and panics on, so the "fix" would
        // have turned a stall into a remote crash. Measured, not guessed.
        const reaper = std.Thread.spawn(.{}, runReaper, .{self}) catch
            return error.CouldNotStartConnectionReaper;
        reaper.detach();

        // Say which port we got. Asking for port 0 is how the GUI stops
        // anything else from being there first: a port nobody has chosen yet
        // cannot be squatted, and this line is the only way the GUI can learn
        // which one it turned out to be.
        //
        // STDOUT, and that matters. The SDK's line-mode spawn ignores the
        // child's stderr outright (`.stderr = ... else .ignore`), so the
        // ordinary `std.debug.print` banner below would be dropped on the
        // floor and the GUI would wait forever for a port it was never told.
        self.bound_port.store(boundPort(server), .release);
        var out_buf: [64]u8 = undefined;
        var stdout = std.Io.File.stdout().writer(io, &out_buf);
        stdout.interface.print("{s} {d}\n", .{ port_line_prefix, self.bound_port.load(.acquire) }) catch {};
        stdout.interface.flush() catch {};

        while (true) {
            const stream = server.accept(io) catch continue;
            if (self.active.load(.monotonic) >= max_conns) {
                stream.close(io);
                continue;
            }
            _ = self.active.fetchAdd(1, .monotonic);
            const t = std.Thread.spawn(.{}, handle, .{ self, stream }) catch {
                _ = self.active.fetchSub(1, .monotonic);
                stream.close(io);
                continue;
            };
            t.detach();
        }
    }
};

/// The one line the GUI parses out of the daemon's stdout. Anything else the
/// daemon prints is for a human reading a terminal.
pub const port_line_prefix = "notary-approval-port";

/// The port the listener actually bound, which is the entire point of asking
/// for zero. `net.Server` carries no bound address (checked), so this asks the
/// kernel. A pure query with no io involvement, unlike the socket-timeout
/// route, which panicked this io model.
fn boundPort(server: net.Server) u16 {
    var sa: std.c.sockaddr.in = undefined;
    var len: std.c.socklen_t = @sizeOf(std.c.sockaddr.in);
    if (std.c.getsockname(server.socket.handle, @ptrCast(&sa), &len) != 0) return 0;
    return std.mem.bigToNative(u16, sa.port);
}

/// Wakes once a second and cuts off connections that have stopped progressing.
fn runReaper(self: *Server) void {
    var threaded = std.Io.Threaded.init(self.gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    while (true) {
        io.sleep(std.Io.Duration.fromSeconds(1), .awake) catch {};
        self.reapStale(io, std.Io.Timestamp.now(io, .awake).toMilliseconds());
    }
}

/// One connection on its own thread with its own io (for the long-poll sleep).
fn handle(self: *Server, stream: net.Stream) void {
    defer _ = self.active.fetchSub(1, .monotonic);
    var threaded = std.Io.Threaded.init(self.gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    // Registered before any read and released before the close, so the reaper
    // only ever shuts down a descriptor this thread still owns. Defers unwind
    // in reverse, so the untrack is declared SECOND to run FIRST: closing the
    // socket while it is still tracked would let the reaper shut down a
    // descriptor number the kernel had already handed to somebody else.
    const slot = self.track(stream, std.Io.Timestamp.now(io, .awake).toMilliseconds());
    defer stream.close(io);
    defer if (slot) |i| self.untrack(i);
    handleConn(self, io, stream) catch {};
}

fn handleConn(self: *Server, io: std.Io, stream: net.Stream) !void {
    var read_storage: [8192]u8 = undefined;
    var write_storage: [4096]u8 = undefined;
    var sr = stream.reader(io, &read_storage);
    var sw = stream.writer(io, &write_storage);
    const r = &sr.interface;
    const w = &sw.interface;

    // Read the request head (and whatever body bytes ride with it) up to the
    // blank line separating headers from the body.
    // Read available bytes until the blank line ends the headers. `readVec`
    // returns after one read (unlike `readSliceShort`, which blocks until it has
    // filled the whole buffer or hit EOF, a deadlock when the client sends a
    // short request and then waits for our response).
    var buf: [8192]u8 = undefined;
    // A /setup or /unlock body carries a passphrase (and maybe an nsec) in these
    // stack buffers; wipe them before the frame unwinds.
    defer std.crypto.secureZero(u8, &buf);
    var len: usize = 0;
    const head_end = while (true) {
        if (len >= buf.len) return respond(w, 431, "{\"error\":\"headers too large\"}");
        var data: [1][]u8 = .{buf[len..]};
        const n = r.readVec(&data) catch return;
        if (n == 0) return; // EOF before a full request
        len += n;
        if (std.mem.indexOf(u8, buf[0..len], "\r\n\r\n")) |i| break i;
    };

    var lines = std.mem.splitSequence(u8, buf[0..head_end], "\r\n");
    const request_line = lines.next() orelse return respond(w, 400, bad_request);
    var parts = std.mem.splitScalar(u8, request_line, ' ');
    const method = parts.next() orelse return respond(w, 400, bad_request);
    const path = parts.next() orelse return respond(w, 400, bad_request);

    var auth: []const u8 = "";
    var content_length: usize = 0;
    while (lines.next()) |line| {
        if (headerValue(line, "authorization")) |v| auth = v;
        if (headerValue(line, "content-length")) |v|
            content_length = std.fmt.parseInt(usize, v, 10) catch 0;
    }

    if (!authOk(auth, self.token)) return respond(w, 401, "{\"error\":\"unauthorized\"}");

    // Assemble the body: bytes already read after the head, plus any remainder.
    var body_storage: [4096]u8 = undefined;
    defer std.crypto.secureZero(u8, &body_storage);
    var body: []const u8 = "";
    if (content_length > 0) {
        if (content_length > body_storage.len) return respond(w, 413, "{\"error\":\"body too large\"}");
        const body_start = head_end + 4;
        var got = @min(len - body_start, content_length);
        @memcpy(body_storage[0..got], buf[body_start .. body_start + got]);
        while (got < content_length) {
            const n = r.readSliceShort(body_storage[got..content_length]) catch break;
            if (n == 0) break;
            got += n;
        }
        body = body_storage[0..got];
    }

    if (eql(method, "GET") and eql(path, "/info"))
        return handleInfo(self, io, w);
    if (eql(method, "POST") and eql(path, "/setup"))
        return handleSetup(self, io, w, body);
    if (eql(method, "POST") and eql(path, "/forget"))
        return handleForget(self, io, w, body);
    if (eql(method, "POST") and eql(path, "/lock"))
        return handleLock(self, w);
    if (eql(method, "POST") and eql(path, "/export"))
        return handleExport(self, io, w, body);
    if (eql(method, "POST") and eql(path, "/nostrconnect"))
        return handleNostrConnect(self, io, w, body);
    if (eql(method, "POST") and eql(path, "/unlock"))
        return handleUnlock(self, io, w, body);
    if (eql(method, "GET") and std.mem.startsWith(u8, path, "/pending"))
        return handlePending(self, io, w, path);
    if (eql(method, "POST") and eql(path, "/decision"))
        return handleDecision(self, w, body);
    // The local signing protocol (nostr's `signer_ipc`), which is what lets a
    // client on this machine use this daemon without a relay round trip. The
    // paths come from the library so every product speaks one protocol rather
    // than each inventing its own.
    if (eql(method, "GET") and eql(path, ipc.path_pubkey))
        return handleSignerPubkey(self, w);
    if (eql(method, "POST") and eql(path, ipc.path_sign))
        return handleSignerSign(self, w, body);
    if (eql(method, "POST") and eql(path, ipc.path_nip44_encrypt))
        return handleSignerCipher(self, io, w, body, .encrypt);
    if (eql(method, "POST") and eql(path, ipc.path_nip44_decrypt))
        return handleSignerCipher(self, io, w, body, .decrypt);
    return respond(w, 404, "{\"error\":\"not found\"}");
}

fn handlePending(self: *Server, io: std.Io, w: *std.Io.Writer, path: []const u8) !void {
    const since = parseSince(path);
    // Long-poll: wait briefly for a queue change so the GUI can loop fetch→
    // refetch without busy-polling. Returns at once when something changed.
    var waited: u64 = 0;
    while (waited < 1000 and self.broker.version.load(.monotonic) == since) {
        io.sleep(std.Io.Duration.fromMilliseconds(100), .awake) catch {};
        waited += 100;
    }

    var pending: [Broker.capacity]Pending = undefined;
    const n = self.broker.snapshot(&pending);
    const version = self.broker.version.load(.monotonic);

    var json: std.ArrayList(u8) = .empty;
    defer json.deinit(self.gpa);
    const head = try std.fmt.allocPrint(self.gpa, "{{\"version\":{d},\"pending\":[", .{version});
    defer self.gpa.free(head);
    try json.appendSlice(self.gpa, head);
    for (pending[0..n], 0..) |p, i| {
        if (i != 0) try json.append(self.gpa, ',');
        // `method` and `client` are safe to interpolate: a request only reaches
        // the policy once its method has parsed as one of seven fixed names,
        // and the client is hex. `preview` is the requester's own text and is
        // escaped, or a quote in a note would end the string and the rest of it
        // would be read as fields of this object.
        const item = try std.fmt.allocPrint(
            self.gpa,
            "{{\"id\":{d},\"method\":\"{s}\",\"kind\":{d},\"created_at\":{d},\"client\":\"{s}\",\"preview\":",
            .{ p.id, p.method(), p.kind, p.created_at, p.client() },
        );
        defer self.gpa.free(item);
        try json.appendSlice(self.gpa, item);
        try appendJsonString(&json, self.gpa, p.preview());
        try json.append(self.gpa, '}');
    }
    try json.appendSlice(self.gpa, "]}");
    return respond(w, 200, json.items);
}

/// Appends `s` as a JSON string literal, quotes included.
///
/// Everything a control character or a backslash or a quote could otherwise do
/// to the surrounding document, it cannot do here. The one string in this API
/// that the requester writes goes through this.
fn appendJsonString(out: *std.ArrayList(u8), gpa: std.mem.Allocator, s: []const u8) !void {
    try out.append(gpa, '"');
    for (s) |c| switch (c) {
        '"' => try out.appendSlice(gpa, "\\\""),
        '\\' => try out.appendSlice(gpa, "\\\\"),
        '\n' => try out.appendSlice(gpa, "\\n"),
        '\r' => try out.appendSlice(gpa, "\\r"),
        '\t' => try out.appendSlice(gpa, "\\t"),
        0x00...0x08, 0x0b, 0x0c, 0x0e...0x1f => {
            var esc: [6]u8 = undefined;
            _ = std.fmt.bufPrint(&esc, "\\u{x:0>4}", .{c}) catch unreachable;
            try out.appendSlice(gpa, &esc);
        },
        else => try out.append(gpa, c),
    };
    try out.append(gpa, '"');
}

fn handleDecision(self: *Server, w: *std.Io.Writer, body: []const u8) !void {
    const Body = struct { id: u64, decision: []const u8, remember: []const u8 = "once" };
    const parsed = std.json.parseFromSlice(Body, self.gpa, body, .{ .ignore_unknown_fields = true }) catch
        return respond(w, 400, bad_request);
    defer parsed.deinit();

    const decision: approval.Decision = if (eql(parsed.value.decision, "approve"))
        .approve
    else if (eql(parsed.value.decision, "reject") or eql(parsed.value.decision, "deny"))
        .reject
    else
        return respond(w, 400, bad_request);

    // An unrecognised duration is `once`, the shortest. A typo must not silently
    // grant something forever.
    const how_long: nostr.nip46.Remember = if (eql(parsed.value.remember, "hour"))
        .hour
    else if (eql(parsed.value.remember, "day"))
        .day
    else if (eql(parsed.value.remember, "always"))
        .always
    else
        .once;

    const ok = self.broker.resolveFor(parsed.value.id, decision, how_long);
    var out: [32]u8 = undefined;
    const j = std.fmt.bufPrint(&out, "{{\"ok\":{s}}}", .{if (ok) "true" else "false"}) catch unreachable;
    return respond(w, 200, j);
}

fn handleInfo(self: *Server, io: std.Io, w: *std.Io.Writer) !void {
    // Ask the disk before answering. This is the poll the window sits on while
    // it is waiting to be set up or unlocked, so it is the one place that can
    // notice a key written by `signer import` in a terminal, which by design
    // cannot reach this process to announce itself.
    self.gate.rescan(io);
    const state = self.gate.current();
    const state_str = switch (state) {
        .uninitialized => "uninitialized",
        .locked => "locked",
        .unlocked => "unlocked",
    };
    // The pubkey and the bunker:// connection URI are known only once unlocked;
    // report "" until then. The URI is the string a client needs to connect, so
    // the GUI shows and copies it, building it here keeps the canonical NIP-46
    // format (and the connection secret) in the daemon.
    const pubkey = if (state == .unlocked) self.gate.pubkeyHex() else "";
    const bunker_uri: ?[]u8 = if (state == .unlocked)
        nip46.buildBunkerUri(self.gpa, self.gate.pubkey(), self.info.relays, self.info.secret) catch null
    else
        null;
    defer if (bunker_uri) |b| self.gpa.free(b);
    const bunker = bunker_uri orelse "";

    var json: std.ArrayList(u8) = .empty;
    defer json.deinit(self.gpa);
    // Relay URLs and the bunker URI carry no JSON metacharacters (the URI
    // percent-encodes relay params), so they are emitted without escaping.
    const head = try std.fmt.allocPrint(self.gpa, "{{\"state\":\"{s}\",\"pubkey\":\"{s}\",\"bunker\":\"{s}\",\"timeout_ms\":{d},\"relays\":[", .{ state_str, pubkey, bunker, self.info.timeout_ms });
    defer self.gpa.free(head);
    try json.appendSlice(self.gpa, head);
    for (self.info.relays, 0..) |relay, i| {
        if (i != 0) try json.append(self.gpa, ',');
        // Report each relay's live connection status (or "connecting" before the
        // threads have started / in a caller that tracks none). Relay URLs carry
        // no JSON metacharacters.
        const st: RelayStatus = if (self.info.relay_status) |rs| @enumFromInt(rs[i].load(.monotonic)) else .connecting;
        const item = try std.fmt.allocPrint(self.gpa, "{{\"url\":\"{s}\",\"status\":\"{s}\"}}", .{ relay, @tagName(st) });
        defer self.gpa.free(item);
        try json.appendSlice(self.gpa, item);
    }
    try json.appendSlice(self.gpa, "]}");
    return respond(w, 200, json.items);
}

/// POST /setup, first-run key creation. Body: `{"passphrase":..,"secret":..?}`.
/// A non-empty `secret` (an `nsec1…` or 64-char hex) imports an existing key;
/// absent/empty generates a fresh one. The key is created and encrypted in the
/// daemon; only the derived public key is returned.
/// POST /setup: mint a key, or take one the reader pasted.
///
/// The method is STATED, never inferred. This used to read "an empty secret
/// means create", which is the same sentence as "a client that meant to import
/// and sent nothing gets a brand new identity instead". That is one trimmed
/// whitespace-only paste away, it destroys nothing the daemon can see, and the
/// reader finds out later when their account is not theirs. A nostr key cannot
/// be replaced, so this asks rather than guesses, and refuses when the answer
/// does not make sense.
fn handleSetup(self: *Server, io: std.Io, w: *std.Io.Writer, body: []const u8) !void {
    const Body = struct { method: []const u8 = "", passphrase: []const u8 = "", secret: []const u8 = "" };
    const parsed = std.json.parseFromSlice(Body, self.gpa, body, .{ .ignore_unknown_fields = true }) catch
        return respond(w, 400, bad_request);
    defer parsed.deinit();

    const importing = eql(parsed.value.method, ipc.Setup.method_import);
    if (!importing and !eql(parsed.value.method, ipc.Setup.method_create))
        return respond(w, 400, "{\"error\":\"method must be create or import\"}");
    // An import with nothing to import is the dangerous one: it used to fall
    // through to minting a key. Refusing is the whole point of asking.
    if (importing and parsed.value.secret.len == 0)
        return respond(w, 400, "{\"error\":\"import needs a secret\"}");
    if (!importing and parsed.value.secret.len != 0)
        return respond(w, 400, "{\"error\":\"create takes no secret\"}");

    self.gate.setup(io, parsed.value.passphrase, parsed.value.secret) catch |err| return switch (err) {
        error.AlreadyInitialized => respond(w, 409, "{\"error\":\"already initialized\"}"),
        error.EmptyPassphrase => respond(w, 400, "{\"error\":\"passphrase required\"}"),
        error.InvalidSecretKey => respond(w, 400, "{\"error\":\"invalid secret key\"}"),
        else => respond(w, 500, "{\"error\":\"could not create the key\"}"),
    };
    return respondPubkey(self, w);
}

/// What `/forget` requires in its body before it will delete anything. Typed by
/// the reader, not clicked: this removes the only copy of a key on this Mac.
pub const forget_confirmation = "delete my key";

/// POST /forget, remove the key file so another account can be set up.
///
/// The destructive half of switching accounts, and the reason it is its own
/// endpoint rather than part of signing out: signing out is reversible and this
/// is not. The key file is the only copy of that identity here.
///
/// It ends the process on success, and that is not tidiness. The relay threads
/// were handed the key by value when serving began and still hold it, so
/// deleting the file alone would leave a signer that has lost its key on disk
/// and is still happily signing with it in memory. Exiting is what retracts it;
/// the GUI spawns the daemon again and it comes up with nothing to serve.
fn handleForget(self: *Server, io: std.Io, w: *std.Io.Writer, body: []const u8) !void {
    const Body = struct { confirm: []const u8 = "" };
    const parsed = std.json.parseFromSlice(Body, self.gpa, body, .{ .ignore_unknown_fields = true }) catch
        return respond(w, 400, bad_request);
    defer parsed.deinit();

    if (!eql(parsed.value.confirm, forget_confirmation))
        return respond(w, 400, "{\"error\":\"confirmation phrase does not match\"}");

    // Sessions granted against the key being removed must not outlive it. A
    // client still holding an authorization is one that would be recognised by
    // whatever key is set up next.
    if (self.clients) |c| c.clear();
    self.broker.reset();
    self.gate.forget(io);

    // Answered before exiting, so the GUI is told rather than seeing its
    // connection drop and guessing why.
    respond(w, 200, "{\"ok\":true}") catch {};
    w.flush() catch {};
    std.process.exit(0);
}

/// Hand the key back to the person who owns it.
///
/// A key that cannot leave is not the reader's key, whatever the copy says, and
/// a Nostr key cannot be rotated: one trapped in one app on one machine is an
/// identity that dies with the machine. So this exists, and it is deliberately
/// awkward: the passphrase every time, and the caller has to name which form it
/// wants.
///
/// `form` is "ncryptsec" (the default, still encrypted, safe to write down) or
/// "nsec" (the key in the clear). The answer is not logged and the daemon keeps
/// no copy of what it returned.
fn handleExport(self: *Server, io: std.Io, w: *std.Io.Writer, body: []const u8) !void {
    const Body = struct { passphrase: []const u8 = "", form: []const u8 = "ncryptsec" };
    const parsed = std.json.parseFromSlice(Body, self.gpa, body, .{ .ignore_unknown_fields = true }) catch
        return respond(w, 400, bad_request);
    defer parsed.deinit();

    const raw = eql(parsed.value.form, "nsec");
    if (!raw and !eql(parsed.value.form, "ncryptsec"))
        return respond(w, 400, "{\"error\":\"form must be ncryptsec or nsec\"}");

    const key = self.gate.exportKey(io, self.gpa, parsed.value.passphrase, raw) catch |err| return switch (err) {
        error.BadPassphrase => respond(w, 401, "{\"error\":\"bad passphrase\"}"),
        error.NotInitialized => respond(w, 409, "{\"error\":\"no key\"}"),
        else => respond(w, 500, "{\"error\":\"could not read the key\"}"),
    };
    defer {
        std.crypto.secureZero(u8, key);
        self.gpa.free(key);
    }

    var out: [512]u8 = undefined;
    const j = std.fmt.bufPrint(&out, "{{\"ok\":true,\"key\":\"{s}\"}}", .{key}) catch
        return respond(w, 500, "{\"error\":\"could not read the key\"}");
    return respond(w, 200, j);
}

/// Sign out: end the process, keeping the key.
///
/// Ending it is the whole point rather than an implementation detail. The relay
/// threads were handed the key by value when serving began, so nothing short of
/// exiting takes it back, and a signer that reports itself signed out while it
/// can still sign is worse than one that never offered.
///
/// The key stays where it is, encrypted, so the next daemon comes up locked and
/// asks for the passphrase. `/forget` is the one that removes it.
fn handleLock(self: *Server, w: *std.Io.Writer) !void {
    // Sessions granted before signing out must not outlive it: a client still
    // holding an authorization would be recognised by the daemon that follows.
    if (self.clients) |c| c.clear();
    self.broker.reset();

    // Answered before exiting, so the GUI is told rather than seeing its
    // connection drop and guessing why.
    respond(w, 200, "{\"ok\":true}") catch {};
    w.flush() catch {};
    std.process.exit(0);
}

/// Whether a relay URL from a `nostrconnect://` URI is one to dial.
///
/// The link is handed in by a person, but its contents are written by whatever
/// asked to connect, and this is the one place this daemon makes an OUTBOUND
/// connection to an address it did not choose. `wss://` only: a `ws://` would
/// carry the acceptance in the clear, and anything else is not a relay.
pub fn dialableRelay(url: []const u8) bool {
    if (!std.mem.startsWith(u8, url, "wss://")) return false;
    if (url.len <= "wss://".len) return false;
    // A control character in a URL is something being smuggled, not a typo.
    for (url) |c| {
        if (c < 0x20 or c == 0x7f) return false;
    }
    return true;
}

/// How many of a link's relays are worth trying. The client names where it is
/// listening, and one reachable relay is enough for it to adopt us; this bounds
/// what a hostile link can make this daemon dial.
pub const max_nostrconnect_relays = 4;

/// POST /nostrconnect, adopt a client that advertised itself.
///
/// The other direction of NIP-46: instead of the reader pasting our `bunker://`
/// token into a client, the client shows a `nostrconnect://` token and waits.
/// The answer carries the link's own secret as its result, which is how the
/// client knows the signer that replied is the one it invited.
fn handleNostrConnect(self: *Server, io: std.Io, w: *std.Io.Writer, body: []const u8) !void {
    const Body = struct { uri: []const u8 = "" };
    const parsed = std.json.parseFromSlice(Body, self.gpa, body, .{ .ignore_unknown_fields = true }) catch
        return respond(w, 400, bad_request);
    defer parsed.deinit();

    if (self.gate.current() != .unlocked)
        return respond(w, 409, "{\"error\":\"the key is locked\"}");
    const clients = self.clients orelse
        return respond(w, 503, "{\"error\":\"not serving yet\"}");

    var uri = nip46.parseNostrConnectUri(self.gpa, parsed.value.uri) catch
        return respond(w, 400, "{\"error\":\"that is not a nostrconnect link\"}");
    defer uri.deinit();

    var signer = nostr.keys.Signer.init();
    defer signer.deinit();
    const kp = signer.keyPairFromSecretKey(self.gate.secret_key) catch
        return respond(w, 500, "{\"error\":\"could not load the key\"}");

    const now = std.Io.Timestamp.now(io, .real).toSeconds();
    var sealed = nip46.acceptNostrConnect(self.gpa, io, signer, kp, uri.value, "notary-nostrconnect", now) catch
        return respond(w, 500, "{\"error\":\"could not build the reply\"}");
    defer sealed.deinit();

    // Published to the relays the CLIENT named, which are not necessarily ours:
    // it is listening there and nowhere else.
    var delivered = false;
    var tried: usize = 0;
    for (uri.value.relays) |url| {
        if (tried >= max_nostrconnect_relays) break;
        if (!dialableRelay(url)) continue;
        tried += 1;
        var relay = nostr.relay.dial(self.gpa, io, url) catch continue;
        defer relay.deinit();
        relay.publish(sealed.event) catch continue;
        delivered = true;
    }
    if (!delivered)
        return respond(w, 502, "{\"error\":\"could not reach any relay the link named\"}");

    // AFTER it is out, not before. Authorizing a client we failed to answer
    // leaves a grant standing for a connection that never happened.
    clients.authorize(uri.value.client_pubkey);
    return respond(w, 200, "{\"ok\":true}");
}

/// POST /unlock, decrypt an existing key file. Body: `{"passphrase":".."}`.
fn handleUnlock(self: *Server, io: std.Io, w: *std.Io.Writer, body: []const u8) !void {
    const Body = struct { passphrase: []const u8 = "" };
    const parsed = std.json.parseFromSlice(Body, self.gpa, body, .{ .ignore_unknown_fields = true }) catch
        return respond(w, 400, bad_request);
    defer parsed.deinit();

    self.gate.unlock(io, parsed.value.passphrase) catch |err| return switch (err) {
        error.BadPassphrase => respond(w, 401, "{\"error\":\"bad passphrase\"}"),
        error.NotLocked => respond(w, 409, "{\"error\":\"not locked\"}"),
        else => respond(w, 500, "{\"error\":\"could not unlock\"}"),
    };
    return respondPubkey(self, w);
}

// --- the local signing protocol ------------------------------------------
//
// `nostr.signer_ipc` over this same channel, so a client on this machine can
// use the key without a relay round trip. The relay side of this daemon serves
// clients that reached it over NIP-46; this serves the ones that are right
// here. Both end at the same key, the same gate and the same permissions.

/// The state the wire reports, from the gate's own.
///
/// Three states, not two, and the mapping is the point. A LOCKED daemon must
/// not report `uninitialized`: that reads as "there is no key here", and a
/// client that believes it offers to make one over the top of an identity that
/// already exists. A nostr key cannot be replaced, so that is the one mistake
/// worth designing the vocabulary around.
fn signerState(gate: *const Gate) []const u8 {
    return switch (gate.current()) {
        .uninitialized => ipc.state_uninitialized,
        .locked => ipc.state_locked,
        .unlocked => ipc.state_ready,
    };
}

fn respondIpcError(self: *Server, w: *std.Io.Writer, status: u16, message: []const u8) !void {
    const body = ipc.Failure{ .@"error" = message };
    const j = body.toJson(self.gpa) catch return respond(w, status, bad_request);
    defer self.gpa.free(j);
    return respond(w, status, j);
}

/// GET /pubkey: what state this daemon is in and whose key it holds.
///
/// The pubkey rides along while LOCKED as well as ready, because whose key it
/// is was never the secret and a client that knows it can name the account it
/// is asking to unlock rather than showing a passphrase box for nobody.
fn handleSignerPubkey(self: *Server, w: *std.Io.Writer) !void {
    const locked_or_ready = self.gate.current() != .uninitialized;
    const body = ipc.Pubkey{
        .state = signerState(self.gate),
        .pubkey = if (locked_or_ready) self.gate.pubkeyHex() else "",
    };
    const j = body.toJson(self.gpa) catch return respond(w, 500, bad_request);
    defer self.gpa.free(j);
    return respond(w, 200, j);
}

/// POST /sign: sign one event with the held key.
fn handleSignerSign(self: *Server, w: *std.Io.Writer, body: []const u8) !void {
    var parsed = ipc.parse(ipc.SignEvent, self.gpa, body) catch
        return respondIpcError(self, w, 400, "malformed sign request");
    defer parsed.deinit();

    var unsigned = nostr.event.fromJson(self.gpa, parsed.value.event) catch
        return respondIpcError(self, w, 400, "not a valid event");
    defer unsigned.deinit();
    const ev = unsigned.value;

    // Kinds 14 and 15 are the UNSIGNED rumors inside a NIP-59 gift wrap. A
    // signature on one destroys the deniability the whole scheme exists for,
    // so this refuses them however they are asked for.
    if (ev.kind == 14 or ev.kind == 15)
        return respondIpcError(self, w, 422, "kind 14 and 15 are never signed");

    if (self.gate.current() != .unlocked)
        return respondIpcError(self, w, 409, "the key is locked");

    var signer = nostr.keys.Signer.init();
    defer signer.deinit();
    const kp = signer.keyPairFromSecretKey(self.gate.secret_key) catch
        return respondIpcError(self, w, 500, "bad key");

    const signed = nostr.event.create(self.gpa, signer, kp, ev.created_at, ev.kind, ev.tags, ev.content, null) catch
        return respondIpcError(self, w, 500, "signing failed");
    const json = nostr.event.toJson(self.gpa, signed) catch
        return respondIpcError(self, w, 500, "out of memory");
    defer self.gpa.free(json);

    const out = ipc.SignEvent{ .event = json };
    const out_json = out.toJson(self.gpa) catch
        return respondIpcError(self, w, 500, "out of memory");
    defer self.gpa.free(out_json);
    return respond(w, 200, out_json);
}

/// POST /nip44/encrypt and /nip44/decrypt: batched, N items in and N out in
/// order. Batching is the point rather than a nicety: a DM catch-up is
/// thousands of decrypts and one round trip each would drown in overhead.
fn handleSignerCipher(
    self: *Server,
    io: std.Io,
    w: *std.Io.Writer,
    body: []const u8,
    comptime dir: enum { encrypt, decrypt },
) !void {
    var parsed = ipc.parse(ipc.Cipher, self.gpa, body) catch
        return respondIpcError(self, w, 400, "malformed cipher request");
    defer parsed.deinit();
    const req = parsed.value;

    var peer: [32]u8 = undefined;
    if (req.peer.len != 64 or (std.fmt.hexToBytes(&peer, req.peer) catch null) == null)
        return respondIpcError(self, w, 400, "peer must be 32-byte hex");

    if (self.gate.current() != .unlocked)
        return respondIpcError(self, w, 409, "the key is locked");

    var signer = nostr.keys.Signer.init();
    defer signer.deinit();

    var out: std.ArrayList([]const u8) = .empty;
    defer {
        for (out.items) |item| self.gpa.free(item);
        out.deinit(self.gpa);
    }
    for (req.items) |item| {
        const result = switch (dir) {
            .encrypt => nostr.nip44.encrypt(self.gpa, io, signer, self.gate.secret_key, peer, item),
            .decrypt => nostr.nip44.decrypt(self.gpa, signer, self.gate.secret_key, peer, item),
        } catch return respondIpcError(self, w, 422, "a cipher item failed");
        out.append(self.gpa, result) catch
            return respondIpcError(self, w, 500, "out of memory");
    }

    const res = ipc.CipherResult{ .items = out.items };
    const j = res.toJson(self.gpa) catch
        return respondIpcError(self, w, 500, "out of memory");
    defer self.gpa.free(j);
    return respond(w, 200, j);
}

fn respondPubkey(self: *Server, w: *std.Io.Writer) !void {
    var out: [128]u8 = undefined;
    const j = std.fmt.bufPrint(&out, "{{\"ok\":true,\"pubkey\":\"{s}\"}}", .{self.gate.pubkeyHex()}) catch unreachable;
    return respond(w, 200, j);
}

// --- HTTP plumbing -------------------------------------------------------

const bad_request = "{\"error\":\"bad request\"}";

fn respond(w: *std.Io.Writer, status: u16, json: []const u8) !void {
    var head: [160]u8 = undefined;
    const h = std.fmt.bufPrint(&head, "HTTP/1.1 {d} {s}\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{ status, reason(status), json.len }) catch unreachable;
    try w.writeAll(h);
    try w.writeAll(json);
    try w.flush();
}

fn reason(status: u16) []const u8 {
    return switch (status) {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        409 => "Conflict",
        413 => "Payload Too Large",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        else => "Error",
    };
}

/// Returns the value of header `name` (lowercased match) from `line`, trimmed.
fn headerValue(line: []const u8, name: []const u8) ?[]const u8 {
    const colon = std.mem.indexOfScalar(u8, line, ':') orelse return null;
    if (!std.ascii.eqlIgnoreCase(std.mem.trim(u8, line[0..colon], " "), name)) return null;
    return std.mem.trim(u8, line[colon + 1 ..], " ");
}

/// Constant-time check that `header` is `Bearer <token>`.
fn authOk(header: []const u8, token: []const u8) bool {
    const prefix = "Bearer ";
    if (!std.mem.startsWith(u8, header, prefix)) return false;
    const got = header[prefix.len..];
    if (got.len != token.len) return false;
    var diff: u8 = 0;
    for (got, token) |a, b| diff |= a ^ b;
    return diff == 0;
}

/// Parses the `?since=N` query value from a path, defaulting to 0.
fn parseSince(path: []const u8) u64 {
    const q = std.mem.indexOfScalar(u8, path, '?') orelse return 0;
    var params = std.mem.splitScalar(u8, path[q + 1 ..], '&');
    while (params.next()) |param| {
        if (std.mem.startsWith(u8, param, "since="))
            return std.fmt.parseInt(u64, param["since=".len..], 10) catch 0;
    }
    return 0;
}

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

// --- Tests ---------------------------------------------------------------

const testing = std.testing;

test "a note cannot write JSON into the approval listing" {
    // The preview is the requester's own text, and the requester is whoever got
    // past the connect secret. If it went in raw, a quote would end the string
    // and everything after it would be read as fields of this object: an
    // attacker could give their own request a different method, a different
    // kind, or somebody else's pubkey, on the very screen a human is using to
    // decide whether to sign it.
    const gpa = std.testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);

    try appendJsonString(&out, gpa, "\",\"kind\":1,\"client\":\"ffff");
    try std.testing.expectEqualStrings(
        "\"\\\",\\\"kind\\\":1,\\\"client\\\":\\\"ffff\"",
        out.items,
    );

    // It has to survive a round trip as one string, not merely look escaped.
    const parsed = try std.json.parseFromSlice([]const u8, gpa, out.items, .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings("\",\"kind\":1,\"client\":\"ffff", parsed.value);

    // Newlines, tabs and control bytes are all legal in event content and all
    // illegal raw inside a JSON string.
    out.clearRetainingCapacity();
    try appendJsonString(&out, gpa, "line\none\ttwo\x01\\end");
    const parsed2 = try std.json.parseFromSlice([]const u8, gpa, out.items, .{});
    defer parsed2.deinit();
    try std.testing.expectEqualStrings("line\none\ttwo\x01\\end", parsed2.value);
}

test "headerValue parses case-insensitively and trims" {
    try testing.expectEqualStrings("Bearer abc", headerValue("Authorization: Bearer abc", "authorization").?);
    try testing.expectEqualStrings("42", headerValue("content-length:  42 ", "content-length").?);
    try testing.expect(headerValue("Host: x", "authorization") == null);
}

test "authOk requires an exact bearer token" {
    try testing.expect(authOk("Bearer s3cret", "s3cret"));
    try testing.expect(!authOk("Bearer s3cret", "other"));
    try testing.expect(!authOk("Bearer s3cre", "s3cret"));
    try testing.expect(!authOk("s3cret", "s3cret"));
    try testing.expect(!authOk("", "s3cret"));
}

test "parseSince reads the query parameter" {
    try testing.expectEqual(@as(u64, 0), parseSince("/pending"));
    try testing.expectEqual(@as(u64, 7), parseSince("/pending?since=7"));
    try testing.expectEqual(@as(u64, 3), parseSince("/pending?foo=1&since=3"));
}

/// One `/sign` request body of the shape a client really sends: a complete
/// event whose id, pubkey and signature are zeroed, since those are the three
/// things it is asking the daemon to fill in.
fn signRequest(gpa: std.mem.Allocator, kind: u16) ![]u8 {
    const unsigned = nostr.event.Event{
        .id = [_]u8{0} ** 32,
        .pubkey = [_]u8{0} ** 32,
        .created_at = 1_700_000_000,
        .kind = kind,
        .tags = &.{},
        .content = "hello",
        .sig = [_]u8{0} ** 64,
    };
    const unsigned_json = try nostr.event.toJson(gpa, unsigned);
    defer gpa.free(unsigned_json);
    return (ipc.SignEvent{ .event = unsigned_json }).toJson(gpa);
}

test "GET /pubkey tells a local client which of THREE states this is" {
    // The mapping is the whole point. A locked daemon reporting
    // "uninitialized" would read as "there is no key here", and a client that
    // believes that offers to create one over the top of an identity that
    // already exists. A nostr key cannot be replaced, so this is the mistake
    // the vocabulary is shaped around.
    const gpa = testing.allocator;

    var signer = nostr.keys.Signer.init();
    defer signer.deinit();
    const secret = try nostr.hex.decodeFixed(32, "b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef");
    const kp = try signer.keyPairFromSecretKey(secret);
    const pubkey_hex = "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659";

    var broker: Broker = .{};

    // Nothing set up: no key, and no pubkey to name.
    {
        var gate = Gate.init(gpa, std.Io.Dir.cwd(), "unused.ncryptsec", .uninitialized);
        var server = Server{ .gpa = gpa, .broker = &broker, .gate = &gate, .token = "t", .info = .{ .relays = &.{}, .timeout_ms = 1000 }, .host = "127.0.0.1", .port = 0 };
        var out = std.Io.Writer.Allocating.init(gpa);
        defer out.deinit();
        try handleSignerPubkey(&server, &out.writer);
        var body = out.toArrayList();
        defer body.deinit(gpa);
        try testing.expect(std.mem.indexOf(u8, body.items, "\"state\":\"uninitialized\"") != null);
        try testing.expect(std.mem.indexOf(u8, body.items, "\"pubkey\":\"\"") != null);
    }

    // Holds a key, cannot use it yet. It says so, AND it says whose key it is,
    // so a client can name the account it is asking to unlock.
    {
        var gate = Gate.init(gpa, std.Io.Dir.cwd(), "unused.ncryptsec", .uninitialized);
        gate.preload(kp);
        gate.state.store(@intFromEnum(onboarding.State.locked), .release);
        var server = Server{ .gpa = gpa, .broker = &broker, .gate = &gate, .token = "t", .info = .{ .relays = &.{}, .timeout_ms = 1000 }, .host = "127.0.0.1", .port = 0 };
        var out = std.Io.Writer.Allocating.init(gpa);
        defer out.deinit();
        try handleSignerPubkey(&server, &out.writer);
        var body = out.toArrayList();
        defer body.deinit(gpa);
        try testing.expect(std.mem.indexOf(u8, body.items, "\"state\":\"locked\"") != null);
        try testing.expect(std.mem.indexOf(u8, body.items, pubkey_hex) != null);
        // The one reading that must never happen.
        try testing.expect(std.mem.indexOf(u8, body.items, "uninitialized") == null);
    }

    // Unlocked: ready, in the word the wire uses rather than the gate's own.
    {
        var gate = Gate.init(gpa, std.Io.Dir.cwd(), "unused.ncryptsec", .uninitialized);
        gate.preload(kp);
        var server = Server{ .gpa = gpa, .broker = &broker, .gate = &gate, .token = "t", .info = .{ .relays = &.{}, .timeout_ms = 1000 }, .host = "127.0.0.1", .port = 0 };
        var out = std.Io.Writer.Allocating.init(gpa);
        defer out.deinit();
        try handleSignerPubkey(&server, &out.writer);
        var body = out.toArrayList();
        defer body.deinit(gpa);
        try testing.expect(std.mem.indexOf(u8, body.items, "\"state\":\"ready\"") != null);
    }
}

test "POST /sign signs with the held key, and refuses a locked one" {
    const gpa = testing.allocator;

    var signer = nostr.keys.Signer.init();
    defer signer.deinit();
    const secret = try nostr.hex.decodeFixed(32, "b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef");
    const kp = try signer.keyPairFromSecretKey(secret);

    var broker: Broker = .{};
    // The shape a client actually sends: a complete event with the id, pubkey
    // and signature left zeroed, because those are what it is asking for.
    const req = try signRequest(gpa, 1);
    defer gpa.free(req);

    // Unlocked: the answer carries a signed event under the held key.
    {
        var gate = Gate.init(gpa, std.Io.Dir.cwd(), "unused.ncryptsec", .uninitialized);
        gate.preload(kp);
        var server = Server{ .gpa = gpa, .broker = &broker, .gate = &gate, .token = "t", .info = .{ .relays = &.{}, .timeout_ms = 1000 }, .host = "127.0.0.1", .port = 0 };
        var out = std.Io.Writer.Allocating.init(gpa);
        defer out.deinit();
        try handleSignerSign(&server, &out.writer, req);
        var body = out.toArrayList();
        defer body.deinit(gpa);
        try testing.expect(std.mem.indexOf(u8, body.items, "200") != null);
        // Signed as the key this daemon holds, not as somebody else.
        try testing.expect(std.mem.indexOf(u8, body.items, "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659") != null);
    }

    // Locked: refuses rather than signing with a key it has not been given.
    {
        var gate = Gate.init(gpa, std.Io.Dir.cwd(), "unused.ncryptsec", .locked);
        var server = Server{ .gpa = gpa, .broker = &broker, .gate = &gate, .token = "t", .info = .{ .relays = &.{}, .timeout_ms = 1000 }, .host = "127.0.0.1", .port = 0 };
        var out = std.Io.Writer.Allocating.init(gpa);
        defer out.deinit();
        try handleSignerSign(&server, &out.writer, req);
        var body = out.toArrayList();
        defer body.deinit(gpa);
        try testing.expect(std.mem.indexOf(u8, body.items, "409") != null);
    }
}

test "a gift-wrap rumor is never signed, locked or not" {
    // Kinds 14 and 15 are the UNSIGNED inner payloads of a NIP-59 gift wrap. A
    // signature on one destroys the deniability the whole scheme exists for,
    // and a messenger asking for it is asking for a mistake. Refused before the
    // gate is even consulted, so it reads the same whatever state the key is in.
    const gpa = testing.allocator;

    var signer = nostr.keys.Signer.init();
    defer signer.deinit();
    const secret = try nostr.hex.decodeFixed(32, "b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef");
    const kp = try signer.keyPairFromSecretKey(secret);

    var broker: Broker = .{};
    for ([_]u16{ 14, 15 }) |kind| {
        var gate = Gate.init(gpa, std.Io.Dir.cwd(), "unused.ncryptsec", .uninitialized);
        gate.preload(kp); // unlocked, so nothing else can be the reason
        var server = Server{ .gpa = gpa, .broker = &broker, .gate = &gate, .token = "t", .info = .{ .relays = &.{}, .timeout_ms = 1000 }, .host = "127.0.0.1", .port = 0 };

        const req = try signRequest(gpa, kind);
        defer gpa.free(req);

        var out = std.Io.Writer.Allocating.init(gpa);
        defer out.deinit();
        try handleSignerSign(&server, &out.writer, req);
        var body = out.toArrayList();
        defer body.deinit(gpa);
        try testing.expect(std.mem.indexOf(u8, body.items, "422") != null);
        try testing.expect(std.mem.indexOf(u8, body.items, "\"sig\"") == null);
    }
}

test "GET /info reports the bunker URI once unlocked" {
    const gpa = testing.allocator;

    var signer = nostr.keys.Signer.init();
    defer signer.deinit();
    // BIP-340 test vector, the same key/pubkey the main.zig bunker-token test uses.
    const secret = try nostr.hex.decodeFixed(32, "b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef");
    const kp = try signer.keyPairFromSecretKey(secret);

    var gate = Gate.init(gpa, std.Io.Dir.cwd(), "unused.ncryptsec", .uninitialized);
    gate.preload(kp); // marks unlocked and stores the pubkey; touches no key file

    var broker: Broker = .{};
    const relays = [_][]const u8{"wss://relay.example.com"};
    var server = Server{
        .gpa = gpa,
        .broker = &broker,
        .gate = &gate,
        .token = "t",
        .info = .{ .relays = &relays, .timeout_ms = 1000, .secret = "s3cret" },
        .host = "127.0.0.1",
        .port = 0,
    };

    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();

    var out = std.Io.Writer.Allocating.init(gpa);
    defer out.deinit();
    try handleInfo(&server, threaded.io(), &out.writer);
    var body = out.toArrayList();
    defer body.deinit(gpa);

    try testing.expect(std.mem.indexOf(u8, body.items, "\"state\":\"unlocked\"") != null);
    try testing.expect(std.mem.indexOf(u8, body.items, "\"bunker\":\"bunker://dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659?") != null);
    try testing.expect(std.mem.indexOf(u8, body.items, "secret=s3cret") != null);
}

test "GET /info omits the bunker URI until the key is unlocked" {
    const gpa = testing.allocator;

    var gate = Gate.init(gpa, std.Io.Dir.cwd(), "unused.ncryptsec", .uninitialized);
    var broker: Broker = .{};
    const relays = [_][]const u8{"wss://relay.example.com"};
    var server = Server{
        .gpa = gpa,
        .broker = &broker,
        .gate = &gate,
        .token = "t",
        .info = .{ .relays = &relays, .timeout_ms = 1000, .secret = null },
        .host = "127.0.0.1",
        .port = 0,
    };

    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();

    var out = std.Io.Writer.Allocating.init(gpa);
    defer out.deinit();
    try handleInfo(&server, threaded.io(), &out.writer);
    var body = out.toArrayList();
    defer body.deinit(gpa);

    try testing.expect(std.mem.indexOf(u8, body.items, "\"state\":\"uninitialized\"") != null);
    try testing.expect(std.mem.indexOf(u8, body.items, "\"bunker\":\"\"") != null);
}

test "GET /info reports live per-relay connection status" {
    const gpa = testing.allocator;

    var gate = Gate.init(gpa, std.Io.Dir.cwd(), "unused.ncryptsec", .uninitialized);
    var broker: Broker = .{};
    const relays = [_][]const u8{ "wss://a.example", "wss://b.example" };
    var status = [_]std.atomic.Value(u8){
        std.atomic.Value(u8).init(@intFromEnum(RelayStatus.connected)),
        std.atomic.Value(u8).init(@intFromEnum(RelayStatus.disconnected)),
    };
    var server = Server{
        .gpa = gpa,
        .broker = &broker,
        .gate = &gate,
        .token = "t",
        .info = .{ .relays = &relays, .timeout_ms = 0, .relay_status = &status },
        .host = "127.0.0.1",
        .port = 0,
    };

    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();

    var out = std.Io.Writer.Allocating.init(gpa);
    defer out.deinit();
    try handleInfo(&server, threaded.io(), &out.writer);
    var body = out.toArrayList();
    defer body.deinit(gpa);

    try testing.expect(std.mem.indexOf(u8, body.items, "{\"url\":\"wss://a.example\",\"status\":\"connected\"}") != null);
    try testing.expect(std.mem.indexOf(u8, body.items, "{\"url\":\"wss://b.example\",\"status\":\"disconnected\"}") != null);
}

test "only a wss relay named by a nostrconnect link is dialled" {
    // This is the one place the daemon opens an outbound connection to an
    // address it did not choose: the link is pasted by a person, but its
    // contents are written by whatever wants to connect.
    try testing.expect(dialableRelay("wss://relay.example.com"));
    try testing.expect(dialableRelay("wss://relay.example.com/nostr"));

    // Plaintext would carry the acceptance, and the acceptance carries the
    // secret that proves which signer answered.
    try testing.expect(!dialableRelay("ws://relay.example.com"));

    // Not relays at all. The last two are the ones worth naming: a link is a
    // string from a stranger, and these are what "just dial what it says" turns
    // into.
    try testing.expect(!dialableRelay("http://example.com"));
    try testing.expect(!dialableRelay("file:///etc/passwd"));
    try testing.expect(!dialableRelay(""));
    try testing.expect(!dialableRelay("wss://"));

    // A control character in a URL is something being smuggled.
    try testing.expect(!dialableRelay("wss://evil.example\r\nHOST: x"));
    try testing.expect(!dialableRelay("wss://evil.example\x00"));
}

test "a nostrconnect link cannot make the daemon dial without limit" {
    // A link may name any number of relays. One reachable one is enough for the
    // client to adopt us, so the rest is only a way to spend this daemon's
    // sockets on somebody else's list.
    try testing.expect(max_nostrconnect_relays > 0);
    try testing.expect(max_nostrconnect_relays <= 8);
}

test "an import with nothing to import is refused, not turned into a new key" {
    // The dangerous shape this replaced: "an empty secret means create". That
    // is the same sentence as "a client that meant to import and sent nothing
    // gets a brand new identity", which is one whitespace-only paste away and
    // is only discovered later, when the account turns out not to be theirs.
    // A nostr key cannot be replaced, so the method is stated and a request
    // that does not make sense is refused rather than guessed at.
    const gpa = testing.allocator;
    var broker: Broker = .{};

    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();

    const Case = struct { body: []const u8, want: []const u8 };
    for ([_]Case{
        // The one that used to mint a key.
        .{ .body = "{\"method\":\"import\",\"passphrase\":\"pw\",\"secret\":\"\"}", .want = "400" },
        // No method at all: the old clients' shape, now refused rather than
        // silently read as a create.
        .{ .body = "{\"passphrase\":\"pw\",\"secret\":\"\"}", .want = "400" },
        .{ .body = "{\"method\":\"\",\"passphrase\":\"pw\"}", .want = "400" },
        // A create that carries a secret is a confused client, not a create.
        .{ .body = "{\"method\":\"create\",\"passphrase\":\"pw\",\"secret\":\"nsec1x\"}", .want = "400" },
        // Nonsense method.
        .{ .body = "{\"method\":\"replace\",\"passphrase\":\"pw\"}", .want = "400" },
    }) |c| {
        var gate = Gate.init(gpa, std.Io.Dir.cwd(), "unused.ncryptsec", .uninitialized);
        var server = Server{ .gpa = gpa, .broker = &broker, .gate = &gate, .token = "t", .info = .{ .relays = &.{}, .timeout_ms = 1000 }, .host = "127.0.0.1", .port = 0 };
        var out = std.Io.Writer.Allocating.init(gpa);
        defer out.deinit();
        try handleSetup(&server, threaded.io(), &out.writer, c.body);
        var body = out.toArrayList();
        defer body.deinit(gpa);
        try testing.expect(std.mem.indexOf(u8, body.items, c.want) != null);
        // Whatever went wrong, no key was made.
        try testing.expectEqual(onboarding.State.uninitialized, gate.current());
    }
}

test "forgetting a key needs the exact confirmation phrase" {
    // Typed, not clicked. This deletes the only copy of an identity on this
    // Mac, and there is nothing on the other side of it that can undo it, so
    // the check is an exact match rather than a truthy flag.
    try testing.expect(eql(forget_confirmation, "delete my key"));
    try testing.expect(!eql(forget_confirmation, ""));
    try testing.expect(!eql(forget_confirmation, "Delete my key"));
    try testing.expect(!eql(forget_confirmation, "delete my key "));
    try testing.expect(!eql(forget_confirmation, "yes"));
}

test "POST /decision carries how long the answer lasts, and a bad duration is the shortest" {
    const gpa = testing.allocator;
    var gate = Gate.init(gpa, std.Io.Dir.cwd(), "unused.ncryptsec", .uninitialized);
    var broker: Broker = .{};
    var server = Server{ .gpa = gpa, .broker = &broker, .gate = &gate, .token = "t", .info = .{ .relays = &.{}, .timeout_ms = 1000 }, .host = "127.0.0.1", .port = 0 };

    const cases = [_]struct { body: []const u8, want: nostr.nip46.Remember }{
        .{ .body = "{\"id\":1,\"decision\":\"approve\",\"remember\":\"always\"}", .want = .always },
        .{ .body = "{\"id\":1,\"decision\":\"approve\",\"remember\":\"day\"}", .want = .day },
        .{ .body = "{\"id\":1,\"decision\":\"reject\",\"remember\":\"hour\"}", .want = .hour },
        // No duration at all, and a name the daemon does not know, both mean
        // "once". A typo must never quietly grant something forever.
        .{ .body = "{\"id\":1,\"decision\":\"approve\"}", .want = .once },
        .{ .body = "{\"id\":1,\"decision\":\"approve\",\"remember\":\"forever and ever\"}", .want = .once },
    };

    for (cases) |c| {
        broker = .{};
        broker.slots[0] = .{ .in_use = true, .info = .{ .id = 1 }, .decision = .init(.pending) };

        var out = std.Io.Writer.Allocating.init(gpa);
        defer out.deinit();
        try handleDecision(&server, &out.writer, c.body);
        var body = out.toArrayList();
        defer body.deinit(gpa);

        try testing.expect(std.mem.indexOf(u8, body.items, "\"ok\":true") != null);
        try testing.expectEqual(c.want, broker.slots[0].remember);
    }
}
