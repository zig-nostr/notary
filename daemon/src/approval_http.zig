//! Minimal, hardened loopback HTTP approval API for GUI mode.
//!
//! The GUI process drives approvals over this API. It never holds the key.
//! Deliberately tiny (fixed routes, no keep-alive, no chunked encoding) to keep
//! the key-holding daemon's attack surface small:
//!
//!   GET  /info              {"state":..,"pubkey":..,"bunker":..,"relays":[{"url":..,"status":..}],"timeout_ms":N}
//!   POST /setup             {"passphrase":..,"secret":..?} → create/import a key
//!   POST /unlock            {"passphrase":..} → decrypt the key file
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
const Broker = approval.Broker;
const Pending = approval.Pending;
const Gate = onboarding.Gate;

/// Live connection state of one relay, reported per relay on `/info`.
pub const RelayStatus = enum(u8) { connecting, connected, disconnected };

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
    const max_conns = 8;

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

/// One connection on its own thread with its own io (for the long-poll sleep).
fn handle(self: *Server, stream: net.Stream) void {
    defer _ = self.active.fetchSub(1, .monotonic);
    var threaded = std.Io.Threaded.init(self.gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    defer stream.close(io);
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
        return handleInfo(self, w);
    if (eql(method, "POST") and eql(path, "/setup"))
        return handleSetup(self, io, w, body);
    if (eql(method, "POST") and eql(path, "/unlock"))
        return handleUnlock(self, io, w, body);
    if (eql(method, "GET") and std.mem.startsWith(u8, path, "/pending"))
        return handlePending(self, io, w, path);
    if (eql(method, "POST") and eql(path, "/decision"))
        return handleDecision(self, w, body);
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
    const Body = struct { id: u64, decision: []const u8 };
    const parsed = std.json.parseFromSlice(Body, self.gpa, body, .{ .ignore_unknown_fields = true }) catch
        return respond(w, 400, bad_request);
    defer parsed.deinit();

    const decision: approval.Decision = if (eql(parsed.value.decision, "approve"))
        .approve
    else if (eql(parsed.value.decision, "reject") or eql(parsed.value.decision, "deny"))
        .reject
    else
        return respond(w, 400, bad_request);

    const ok = self.broker.resolve(parsed.value.id, decision);
    var out: [32]u8 = undefined;
    const j = std.fmt.bufPrint(&out, "{{\"ok\":{s}}}", .{if (ok) "true" else "false"}) catch unreachable;
    return respond(w, 200, j);
}

fn handleInfo(self: *Server, w: *std.Io.Writer) !void {
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
fn handleSetup(self: *Server, io: std.Io, w: *std.Io.Writer, body: []const u8) !void {
    const Body = struct { passphrase: []const u8 = "", secret: []const u8 = "" };
    const parsed = std.json.parseFromSlice(Body, self.gpa, body, .{ .ignore_unknown_fields = true }) catch
        return respond(w, 400, bad_request);
    defer parsed.deinit();

    self.gate.setup(io, parsed.value.passphrase, parsed.value.secret) catch |err| return switch (err) {
        error.AlreadyInitialized => respond(w, 409, "{\"error\":\"already initialized\"}"),
        error.EmptyPassphrase => respond(w, 400, "{\"error\":\"passphrase required\"}"),
        error.InvalidSecretKey => respond(w, 400, "{\"error\":\"invalid secret key\"}"),
        else => respond(w, 500, "{\"error\":\"could not create the key\"}"),
    };
    return respondPubkey(self, w);
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

    var out = std.Io.Writer.Allocating.init(gpa);
    defer out.deinit();
    try handleInfo(&server, &out.writer);
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

    var out = std.Io.Writer.Allocating.init(gpa);
    defer out.deinit();
    try handleInfo(&server, &out.writer);
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

    var out = std.Io.Writer.Allocating.init(gpa);
    defer out.deinit();
    try handleInfo(&server, &out.writer);
    var body = out.toArrayList();
    defer body.deinit(gpa);

    try testing.expect(std.mem.indexOf(u8, body.items, "{\"url\":\"wss://a.example\",\"status\":\"connected\"}") != null);
    try testing.expect(std.mem.indexOf(u8, body.items, "{\"url\":\"wss://b.example\",\"status\":\"disconnected\"}") != null);
}
