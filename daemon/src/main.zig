//! zig-nostr signer, a headless NIP-46 remote signer ("bunker").
//!
//! Keeps the user's secret key on a machine they control and signs for remote
//! clients over a relay. On startup it loads the key, decrypting an encrypted
//! NIP-49 key file at rest (`nostr.keystore`), or an unencrypted dev key,
//! prints the `bunker://` connection token, then connects to each configured
//! relay and serves NIP-46 requests (`nostr.signer.serve`) until stopped.
//! Requests are authorized by an optional method/event-kind allowlist
//! (`nostr.nip46.PolicyConfig`) behind the connection secret; a native approval
//! UI comes later.

const std = @import("std");
const nostr = @import("nostr");
// The key-at-rest, the serve loop, and the authorization config now live in the
// nostr library (a signer is a shell over it, not a fork). See `nostr.keystore`,
// `nostr.signer`, and `nostr.nip46.PolicyConfig`.
const keystore = nostr.keystore;
const PolicyConfig = nostr.nip46.PolicyConfig;
const approval = @import("approval.zig");
const approval_http = @import("approval_http.zig");
const onboarding = @import("onboarding.zig");
const relay_keeper = @import("relay_keeper.zig");

const keys = nostr.keys;
const nip46 = nostr.nip46;
const nip49 = nostr.nip49;
const hex = nostr.hex;

// Turnkey defaults for GUI mode, so a freshly downloaded app works with zero
// configuration; each is overridable via its environment variable. The key and
// token files sit under $HOME; relays default to a public relay.
const default_token_file = ".zig-nostr-signer.token";
const default_key_file = ".zig-nostr-signer.key";
const default_gui_relays = "wss://relay.damus.io";

const usage =
    \\zig-nostr signer: headless NIP-46 remote signer (bunker)
    \\
    \\Configure via environment variables:
    \\  SIGNER_KEY_FILE        path to an encrypted (NIP-49) key file
    \\  SIGNER_PASSPHRASE      passphrase for the encrypted key file
    \\  SIGNER_SECRET_KEY      64-char hex secret key (unencrypted; dev use only)
    \\  SIGNER_RELAYS          comma-separated wss:// relay URLs (required to serve)
    \\  SIGNER_CONNECT_SECRET  optional connection secret clients must echo
    \\  SIGNER_ALLOWED_METHODS comma-separated NIP-46 methods to honor (default: all;
    \\                         connect/ping/logout are always allowed)
    \\  SIGNER_ALLOWED_KINDS   comma-separated event kinds sign_event may sign
    \\                         (default: any kind)
    \\  SIGNER_INIT            if set, create/import an encrypted key file and exit
    \\
    \\Provide the key either as an encrypted file (SIGNER_KEY_FILE +
    \\SIGNER_PASSPHRASE, recommended) or as SIGNER_SECRET_KEY (dev only). To create
    \\an encrypted file, run once with SIGNER_INIT set plus SIGNER_KEY_FILE and
    \\SIGNER_PASSPHRASE. It imports SIGNER_SECRET_KEY if present, else generates a
    \\fresh key, then run again without SIGNER_INIT to start serving.
    \\
    \\Prints the signer's public key and the bunker:// token clients connect
    \\with, then serves NIP-46 requests over the relays until stopped.
    \\
;

pub fn main(init: std.process.Init) !void {
    const gpa = std.heap.page_allocator;

    // `SIGNER_INIT` bootstraps an encrypted key file at rest, then exits.
    if (getEnv("SIGNER_INIT") != null) runInit(gpa);

    const conn_secret = getEnv("SIGNER_CONNECT_SECRET");

    // Authorization rules, parsed once and shared read-only across relay threads.
    const policy_config = buildPolicyConfig(gpa);

    // GUI/managed mode: the daemon may boot WITHOUT a key. It stands up the
    // loopback approval API first (reporting its key state), lets the connected
    // GUI create or unlock the key over /setup and /unlock, and only then serves.
    // The key is created/decrypted here; the GUI never receives it (see
    // onboarding.zig + approval_http.zig). The approval address arrives as
    // `--approval-http <addr>`: how the GUI passes it when it spawns us, since a
    // Finder-launched app has no environment for the child to inherit, or via
    // `SIGNER_APPROVAL_HTTP`. Parse argv here so the slice lives for the process
    // (GUI/relay mode never returns).
    var approval_addr = getEnv("SIGNER_APPROVAL_HTTP");
    var args = std.process.Args.Iterator.init(init.minimal.args);
    _ = args.skip(); // argv[0]
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--approval-http")) {
            approval_addr = args.next();
            break;
        }
    }

    if (approval_addr) |addr| {
        runGuiMode(gpa, addr, conn_secret, &policy_config);
    }

    // Headless mode: the key must already be available (from an encrypted key
    // file or the dev-only SIGNER_SECRET_KEY), and relays are required up front.
    const relays_env = getEnv("SIGNER_RELAYS") orelse
        fail("set SIGNER_RELAYS to a comma-separated list of wss:// URLs");
    var relays: std.ArrayList([]const u8) = .empty;
    parseRelays(gpa, &relays, relays_env);
    if (relays.items.len == 0) fail("SIGNER_RELAYS contained no relay URLs");

    // Load the secret key once (decrypting the at-rest key file if configured).
    // The deliberately-expensive scrypt KDF runs here and only here; the relay
    // threads receive the already-derived 32-byte key, so no per-request or
    // per-connection key derivation ever happens.
    const secret_key = loadSecretKey(gpa);
    runRelays(gpa, relays.items, secret_key, conn_secret, &policy_config, null, null);
}

/// GUI mode: stand up the approval API (key-less if there is no key yet), run
/// first-run key onboarding over it, then serve with the resulting key. The
/// broker and server live in this frame, which never returns (it tail-calls the
/// forever-serving `runRelays`), so their addresses are stable for the process.
fn runGuiMode(gpa: std.mem.Allocator, addr: []const u8, conn_secret: ?[]const u8, policy_config: *const PolicyConfig) noreturn {
    const hp = parseHostPort(addr) orelse
        fail("SIGNER_APPROVAL_HTTP must be host:port, e.g. 127.0.0.1:8787");

    // Turnkey defaults so a fresh download needs no configuration.
    const token_path = getEnv("SIGNER_APPROVAL_TOKEN_FILE") orelse resolveHome(gpa, default_token_file);
    const key_file = getEnv("SIGNER_KEY_FILE") orelse resolveHome(gpa, default_key_file);
    const relays_env = getEnv("SIGNER_RELAYS") orelse default_gui_relays;

    var relays: std.ArrayList([]const u8) = .empty;
    parseRelays(gpa, &relays, relays_env);
    if (relays.items.len == 0) fail("SIGNER_RELAYS contained no relay URLs");

    var startup = std.Io.Threaded.init(gpa, .{});
    defer startup.deinit();
    const io = startup.io();

    // No key file yet → the GUI must create one; an encrypted file present →
    // the GUI must unlock it.
    const initial: onboarding.State = if (fileExists(io, key_file)) .locked else .uninitialized;

    var broker_storage: approval.Broker = .{};
    var gate = onboarding.Gate.init(gpa, std.Io.Dir.cwd(), key_file, initial);

    // Honor a preconfigured key (dev SIGNER_SECRET_KEY, or an existing key file
    // plus SIGNER_PASSPHRASE) so an operator can still bring their own; when none
    // is configured (the turnkey case) the GUI onboards one over the API.
    if (guiPreloadKey(gpa, io, key_file)) |kp| gate.preload(kp);
    const booted = gate.current();

    // Live per-relay connection status, shared with the approval server's
    // /info. Starts "connecting"; each relay thread flips its slot once it
    // dials or drops. Lives for the process (main never returns).
    const relay_status = gpa.alloc(std.atomic.Value(u8), relays.items.len) catch
        fail("out of memory tracking relay status");
    for (relay_status) |*s| s.* = std.atomic.Value(u8).init(@intFromEnum(approval_http.RelayStatus.connecting));

    const token_hex = makeAndWriteToken(gpa, token_path);
    var approval_server: approval_http.Server = .{
        .gpa = gpa,
        .broker = &broker_storage,
        .gate = &gate,
        .token = token_hex,
        .info = .{ .relays = relays.items, .timeout_ms = broker_storage.timeout_ms, .secret = conn_secret, .relay_status = relay_status },
        .host = hp.host,
        .port = hp.port,
    };
    const server_thread = std.Thread.spawn(.{}, runApprovalServer, .{&approval_server}) catch
        fail("could not start the approval server");
    server_thread.detach();

    const key_note = switch (booted) {
        .unlocked => "Key loaded from the environment; serving now.",
        .locked => "Waiting for the GUI to unlock the key…",
        .uninitialized => "Waiting for the GUI to set up the key…",
    };
    std.debug.print(
        \\zig-nostr signer (GUI mode)
        \\  approval API : http://{s}  (bearer token → {s})
        \\  key file     : {s}
        \\  key state    : {s}
        \\
        \\{s}
        \\
    , .{ addr, token_path, key_file, @tagName(booted), key_note });

    // Block until the GUI creates or unlocks the key (returns at once if a
    // preconfigured key was loaded above), then serve with it. The broker is
    // already live, so approvals work the moment serving starts.
    const secret_key = gate.waitUnlocked(io);
    runRelays(gpa, relays.items, secret_key, conn_secret, policy_config, &broker_storage, relay_status);
}

/// Derives the keypair, prints the connection banner, and serves every relay on
/// its own thread until stopped. Each thread owns its secp256k1 context and
/// bunker, so nothing mutable is shared between them; the only shared state is
/// the read-only key material and the allocator. Never returns.
fn runRelays(
    gpa: std.mem.Allocator,
    relays: []const []const u8,
    secret_key: [32]u8,
    conn_secret: ?[]const u8,
    policy_config: *const PolicyConfig,
    broker: ?*approval.Broker,
    relay_status: ?[]std.atomic.Value(u8),
) noreturn {
    var signer = keys.Signer.init();
    defer signer.deinit();
    const kp = signer.keyPairFromSecretKey(secret_key) catch
        fail("the configured key is not a valid secp256k1 secret key");

    const token = nip46.buildBunkerUri(gpa, kp.public_key, relays, conn_secret) catch
        fail("out of memory building the bunker token");
    const pk_hex = hex.encode(gpa, &kp.public_key) catch fail("out of memory encoding the public key");

    const approval_note = if (broker != null)
        "held until you approve them in the connected GUI"
    else if (conn_secret == null)
        "auto-approved (no connection secret set)"
    else
        "auto-approved behind the connection secret";

    std.debug.print(
        \\zig-nostr signer
        \\  pubkey : {s}
        \\  bunker : {s}
        \\
        \\Share the bunker:// token with a client to connect. Requests are
        \\{s}. Press Ctrl-C to stop.
        \\
    , .{ pk_hex, token, approval_note });
    gpa.free(token);
    gpa.free(pk_hex);

    // One table for every relay connection, and one thread watching them all.
    // It has to be a separate thread and not work folded into the relay
    // threads: each of those is blocked inside `receive` exactly when there is
    // something to notice, and a thread waiting on a dead peer is the last
    // thing that can tell it has stopped answering.
    var keeper_table = relay_keeper.Table.init(gpa, relays.len) catch
        fail("out of memory tracking relay connections");
    keeper_table.status = relay_status;
    const keeper: ?*relay_keeper.Table = &keeper_table;
    if (std.Thread.spawn(.{}, relay_keeper.run, .{
        gpa,
        keeper.?,
        @intFromEnum(approval_http.RelayStatus.quiet),
        @intFromEnum(approval_http.RelayStatus.disconnected),
    })) |k| {
        k.detach();
    } else |err| {
        // Not fatal: without it the daemon behaves as it did before, which is
        // to say a half-open socket sits there. Said out loud rather than
        // swallowed, because "signing quietly stopped working" is the symptom
        // and it looks nothing like its cause.
        std.debug.print("signer: relay keepalive did not start ({s}); a dropped connection will not be noticed\n", .{@errorName(err)});
    }

    var threads: std.ArrayList(std.Thread) = .empty;
    for (relays, 0..) |url, i| {
        const slot: ?*std.atomic.Value(u8) = if (relay_status) |rs| &rs[i] else null;
        const t = std.Thread.spawn(.{}, serveRelayForever, .{ gpa, url, secret_key, conn_secret, policy_config, broker, slot, keeper, i }) catch |err| {
            std.debug.print("signer: [{s}] could not start: {s}\n", .{ url, @errorName(err) });
            if (slot) |s| s.store(@intFromEnum(approval_http.RelayStatus.disconnected), .monotonic);
            continue;
        };
        threads.append(gpa, t) catch fail("out of memory tracking relay threads");
    }
    if (threads.items.len == 0) fail("could not start any relay connections");
    for (threads.items) |t| t.join();
    std.process.exit(0); // relay threads loop forever; reached only if all exit
}

/// Splits a comma-separated relay list into `list`, trimming and skipping empties.
fn parseRelays(gpa: std.mem.Allocator, list: *std.ArrayList([]const u8), csv: []const u8) void {
    var it = std.mem.splitScalar(u8, csv, ',');
    while (it.next()) |raw| {
        const url = std.mem.trim(u8, raw, " \t");
        if (url.len != 0) list.append(gpa, url) catch fail("out of memory parsing SIGNER_RELAYS");
    }
}

/// Resolves `$HOME/name`, or `name` alone if HOME is unset. The result is
/// process-lived (the env string is, and an allocPrint uses the page allocator).
fn resolveHome(gpa: std.mem.Allocator, name: []const u8) []const u8 {
    if (getEnv("HOME")) |home| return std.fmt.allocPrint(gpa, "{s}/{s}", .{ home, name }) catch name;
    return name;
}

/// Whether `path` exists (as a `Dir.cwd()` sub-path; an absolute path works too).
fn fileExists(io: std.Io, path: []const u8) bool {
    std.Io.Dir.cwd().access(io, path, .{}) catch return false;
    return true;
}

/// In GUI mode, loads a key straight from the environment when one is fully
/// specified, `SIGNER_SECRET_KEY` (dev), or an existing key file together with
/// `SIGNER_PASSPHRASE`: so an operator can still preconfigure the key. Returns
/// null (→ the GUI onboards the key) only when nothing is configured; a bad key
/// or wrong passphrase still fails loudly rather than silently onboarding.
fn guiPreloadKey(gpa: std.mem.Allocator, io: std.Io, key_file: []const u8) ?keys.KeyPair {
    var signer = keys.Signer.init();
    defer signer.deinit();

    if (getEnv("SIGNER_SECRET_KEY")) |secret_hex| {
        const sk = hex.decodeFixed(32, secret_hex) catch fail("SIGNER_SECRET_KEY must be exactly 64 hex characters");
        return signer.keyPairFromSecretKey(sk) catch fail("SIGNER_SECRET_KEY is not a valid secp256k1 secret key");
    }
    if (getEnv("SIGNER_PASSPHRASE")) |passphrase| {
        // Only unlock from the environment when the file is actually there;
        // otherwise fall through so the GUI can create one.
        if (fileExists(io, key_file)) {
            const ncryptsec = keystore.readKeyFile(gpa, io, std.Io.Dir.cwd(), key_file) catch |err|
                failFmt("could not read SIGNER_KEY_FILE '{s}': {s}", .{ key_file, @errorName(err) });
            defer gpa.free(ncryptsec);
            const sk = keystore.decryptKey(gpa, ncryptsec, passphrase) catch
                fail("could not decrypt the key file (wrong SIGNER_PASSPHRASE?)");
            return signer.keyPairFromSecretKey(sk) catch fail("the key file holds an invalid secret key");
        }
    }
    return null;
}

/// Connects to `url` and serves requests forever, reconnecting after a short
/// delay whenever the connection drops. Runs on its own thread with its own
/// signing context, derived from the shared read-only `secret_key`.
fn serveRelayForever(
    gpa: std.mem.Allocator,
    url: []const u8,
    secret_key: [32]u8,
    conn_secret: ?[]const u8,
    policy_config: *const PolicyConfig,
    broker: ?*approval.Broker,
    status: ?*std.atomic.Value(u8),
    keeper: ?*relay_keeper.Table,
    slot: usize,
) void {
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var signer = keys.Signer.init();
    defer signer.deinit();
    const kp = signer.keyPairFromSecretKey(secret_key) catch {
        std.debug.print("signer: [{s}] invalid secret key\n", .{url});
        return;
    };

    // In GUI mode the interactive policy escalates to the broker (which blocks
    // this thread until the GUI decides); otherwise the static allowlist policy
    // decides. `interactive` lives for this forever-looping frame, so the policy
    // may hold a pointer to it.
    var interactive = approval.Interactive{
        .broker = broker orelse undefined,
        .config = policy_config,
        .io = io,
        .gpa = gpa,
    };
    const request_policy = if (broker != null) interactive.asPolicy() else policy_config.policy();

    var bunker = nip46.Bunker.initSingleKey(signer, kp, request_policy);
    bunker.secret = conn_secret;
    // The bunker now remembers which clients have connected, and refuses to
    // sign for one it has not heard of. It lives out here, outside the dial
    // loop, so a dropped socket does not make every client connect again.
    //
    // One consequence worth naming: this bunker belongs to THIS relay thread,
    // which is how the rest of the state here works, so a client is authorized
    // per relay. A client that connects over one relay in the token and then
    // asks over another gets "not connected" and has to connect again. Clients
    // hold one connection at a time, so that is a reconnect and not a wall, but
    // a set shared across the threads would be better and is worth doing.

    while (true) {
        if (status) |s| s.store(@intFromEnum(approval_http.RelayStatus.connecting), .monotonic);
        serveOnce(gpa, io, url, &bunker, kp, status, keeper, slot) catch |err| {
            std.debug.print("signer: [{s}] {s}\n", .{ url, @errorName(err) });
        };
        if (status) |s| s.store(@intFromEnum(approval_http.RelayStatus.disconnected), .monotonic);
        std.debug.print("signer: [{s}] disconnected; reconnecting in 3s\n", .{url});
        io.sleep(std.Io.Duration.fromSeconds(3), .awake) catch {};
    }
}

/// Dials `url`, then serves requests until the connection closes.
fn serveOnce(
    gpa: std.mem.Allocator,
    io: std.Io,
    url: []const u8,
    bunker: *nip46.Bunker,
    remote: keys.KeyPair,
    status: ?*std.atomic.Value(u8),
    keeper: ?*relay_keeper.Table,
    slot: usize,
) !void {
    var relay = try nostr.relay.dial(gpa, io, url);
    // Withdrawn BEFORE the connection is freed. Defers unwind in reverse, so
    // this one is declared second and runs first; the other order hands the
    // keeper a pointer to a `Relay` that is already gone.
    defer relay.deinit();
    if (keeper) |k| k.offer(slot, relay);
    defer if (keeper) |k| k.offer(slot, null);
    if (status) |s| s.store(@intFromEnum(approval_http.RelayStatus.connected), .monotonic);
    std.debug.print("signer: [{s}] connected; listening for NIP-46 requests\n", .{url});
    try nostr.signer.serve(gpa, io, relay, bunker, remote, url);
}

/// Resolves the signer's 32-byte secret key from the environment, preferring
/// the encrypted-at-rest key file over the plaintext `SIGNER_SECRET_KEY`. The
/// scrypt decryption cost is paid once, here, at startup.
fn loadSecretKey(gpa: std.mem.Allocator) [32]u8 {
    if (getEnv("SIGNER_KEY_FILE")) |path| {
        const passphrase = getEnv("SIGNER_PASSPHRASE") orelse
            fail("SIGNER_KEY_FILE is set but SIGNER_PASSPHRASE is not");

        var startup = std.Io.Threaded.init(gpa, .{});
        defer startup.deinit();
        const io = startup.io();

        const ncryptsec = keystore.readKeyFile(gpa, io, std.Io.Dir.cwd(), path) catch |err|
            failFmt("could not read SIGNER_KEY_FILE '{s}': {s}", .{ path, @errorName(err) });
        defer gpa.free(ncryptsec);

        return keystore.decryptKey(gpa, ncryptsec, passphrase) catch
            fail("could not decrypt the key file (wrong SIGNER_PASSPHRASE?)");
    }

    if (getEnv("SIGNER_SECRET_KEY")) |secret_hex| {
        std.debug.print(
            \\warning: SIGNER_SECRET_KEY keeps your key UNENCRYPTED in the environment.
            \\         Prefer an encrypted key file: run once with SIGNER_INIT set plus
            \\         SIGNER_KEY_FILE + SIGNER_PASSPHRASE, then drop SIGNER_SECRET_KEY.
            \\
        , .{});
        return hex.decodeFixed(32, secret_hex) catch
            fail("SIGNER_SECRET_KEY must be exactly 64 hex characters");
    }

    fail("set SIGNER_KEY_FILE (+ SIGNER_PASSPHRASE), or SIGNER_SECRET_KEY (dev only)");
}

/// Creates the encrypted-at-rest key file and exits. Imports `SIGNER_SECRET_KEY`
/// if present (marked known-insecure, since it was plaintext in the environment),
/// otherwise generates a fresh key. Refuses to overwrite an existing file.
fn runInit(gpa: std.mem.Allocator) noreturn {
    const path = getEnv("SIGNER_KEY_FILE") orelse
        fail("SIGNER_INIT requires SIGNER_KEY_FILE (path to write the encrypted key to)");
    const passphrase = getEnv("SIGNER_PASSPHRASE") orelse
        fail("SIGNER_INIT requires SIGNER_PASSPHRASE (to encrypt the key with)");

    var startup = std.Io.Threaded.init(gpa, .{});
    defer startup.deinit();
    const io = startup.io();

    var signer = keys.Signer.init();
    defer signer.deinit();

    var security: nip49.KeySecurity = .known_secure;
    const kp = if (getEnv("SIGNER_SECRET_KEY")) |secret_hex| blk: {
        const secret_key = hex.decodeFixed(32, secret_hex) catch
            fail("SIGNER_SECRET_KEY must be exactly 64 hex characters");
        security = .known_insecure; // it sat in the environment as plaintext
        break :blk signer.keyPairFromSecretKey(secret_key) catch
            fail("SIGNER_SECRET_KEY is not a valid secp256k1 secret key");
    } else signer.generateKeyPair(io) catch |err|
        failFmt("could not generate a key: {s}", .{@errorName(err)});

    const ncryptsec = keystore.encryptKey(gpa, io, kp.secret_key, passphrase, security) catch |err|
        failFmt("could not encrypt the key: {s}", .{@errorName(err)});
    defer gpa.free(ncryptsec);

    keystore.writeNewKeyFile(io, std.Io.Dir.cwd(), path, ncryptsec) catch |err| switch (err) {
        keystore.Error.KeyFileExists => failFmt("SIGNER_KEY_FILE '{s}' already exists; refusing to overwrite", .{path}),
        else => failFmt("could not write '{s}': {s}", .{ path, @errorName(err) }),
    };

    const pk_hex = hex.encode(gpa, &kp.public_key) catch |err|
        failFmt("could not encode the public key: {s}", .{@errorName(err)});
    defer gpa.free(pk_hex);

    std.debug.print(
        \\Initialized encrypted signer key.
        \\  pubkey : {s}
        \\  file   : {s}  (mode 0600, NIP-49 ncryptsec)
        \\
        \\To start serving, unset SIGNER_INIT and run again with SIGNER_KEY_FILE,
        \\SIGNER_PASSPHRASE and SIGNER_RELAYS set.
        \\
    , .{ pk_hex, path });
    std.process.exit(0);
}

/// Parses the authorization allowlists from the environment into a
/// `PolicyConfig`. Empty/unset variables mean "no restriction"; an unknown
/// method name or a non-numeric kind is a startup error. The returned slices
/// live for the process (shared read-only by every relay thread).
fn buildPolicyConfig(gpa: std.mem.Allocator) PolicyConfig {
    var cfg = PolicyConfig{ .gpa = gpa };

    if (getEnv("SIGNER_ALLOWED_METHODS")) |raw| {
        var list: std.ArrayList(nip46.Method) = .empty;
        var it = std.mem.splitScalar(u8, raw, ',');
        while (it.next()) |item| {
            const name = std.mem.trim(u8, item, " \t");
            if (name.len == 0) continue;
            const method = nip46.Method.fromString(name) orelse
                failFmt("SIGNER_ALLOWED_METHODS: unknown method '{s}'", .{name});
            list.append(gpa, method) catch fail("out of memory building the method allowlist");
        }
        if (list.items.len == 0) list.deinit(gpa) else {
            cfg.allowed_methods = list.toOwnedSlice(gpa) catch fail("out of memory");
        }
    }

    if (getEnv("SIGNER_ALLOWED_KINDS")) |raw| {
        var list: std.ArrayList(u16) = .empty;
        var it = std.mem.splitScalar(u8, raw, ',');
        while (it.next()) |item| {
            const s = std.mem.trim(u8, item, " \t");
            if (s.len == 0) continue;
            const kind = std.fmt.parseInt(u16, s, 10) catch
                failFmt("SIGNER_ALLOWED_KINDS: invalid kind '{s}'", .{s});
            list.append(gpa, kind) catch fail("out of memory building the kind allowlist");
        }
        if (list.items.len == 0) list.deinit(gpa) else {
            cfg.allowed_kinds = list.toOwnedSlice(gpa) catch fail("out of memory");
        }
    }

    return cfg;
}

const HostPort = struct { host: []const u8, port: u16 };

/// Parses a `host:port` string (e.g. `127.0.0.1:8787`).
fn parseHostPort(s: []const u8) ?HostPort {
    const colon = std.mem.lastIndexOfScalar(u8, s, ':') orelse return null;
    const host = s[0..colon];
    if (host.len == 0) return null;
    const port = std.fmt.parseInt(u16, s[colon + 1 ..], 10) catch return null;
    return .{ .host = host, .port = port };
}

/// Generates a fresh random bearer token, writes it to `path` as a `0600` file
/// (overwriting a stale one), and returns the hex token (owned, process-lived).
fn makeAndWriteToken(gpa: std.mem.Allocator, path: []const u8) []u8 {
    var startup = std.Io.Threaded.init(gpa, .{});
    defer startup.deinit();
    const io = startup.io();

    var raw: [24]u8 = undefined;
    io.randomSecure(&raw) catch |err| failFmt("could not generate an API token: {s}", .{@errorName(err)});
    const token_hex = hex.encode(gpa, &raw) catch fail("out of memory generating the API token");

    std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = path,
        .data = token_hex,
        .flags = .{ .truncate = true, .permissions = std.Io.File.Permissions.fromMode(0o600) },
    }) catch |err| failFmt("could not write the token file '{s}': {s}", .{ path, @errorName(err) });
    return token_hex;
}

/// Runs the approval HTTP server on its own thread with its own io.
///
/// A listener that cannot come up KILLS the daemon. It used to print and let
/// the thread die, and the consequence was not a missing feature: the daemon
/// went on running with no listener, blocked forever waiting to be unlocked,
/// while whatever was already holding that port answered the GUI instead. The
/// GUI has no way to tell the difference, so it would read the token file, find
/// something answering, and post the unlock passphrase, or an imported nsec,
/// straight to it. Dying loudly is what turns that into a startup failure the
/// GUI's supervision already knows how to show.
fn runApprovalServer(server: *approval_http.Server) void {
    var threaded = std.Io.Threaded.init(server.gpa, .{});
    defer threaded.deinit();
    server.run(threaded.io()) catch |err| {
        std.debug.print("signer: approval server stopped: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
    // `run` loops forever, so reaching here at all means the listener is gone.
    std.debug.print("signer: approval server exited\n", .{});
    std.process.exit(1);
}

fn getEnv(name: [*:0]const u8) ?[]const u8 {
    const value = std.c.getenv(name) orelse return null;
    return std.mem.span(value);
}

fn fail(message: []const u8) noreturn {
    std.debug.print("error: {s}\n\n{s}", .{ message, usage });
    std.process.exit(1);
}

fn failFmt(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print("error: ", .{});
    std.debug.print(fmt, args);
    std.debug.print("\n\n{s}", .{usage});
    std.process.exit(1);
}

test {
    // Every source file with tests has to be named here. A file that is
    // imported by the code but not listed here compiles into the test binary
    // and its tests are never run: adding relay_keeper.zig left the count at
    // 19 and looked exactly like eight passing tests.
    //
    // The serve loop, keystore, and policy tests now run in the nostr library.
    _ = @import("approval.zig");
    _ = @import("approval_http.zig");
    _ = @import("onboarding.zig");
    _ = @import("relay_keeper.zig");
}

test "derives the pubkey and builds a bunker token" {
    const gpa = std.testing.allocator;
    var signer = keys.Signer.init();
    defer signer.deinit();

    // BIP-340 test vector: this secret key derives this x-only public key.
    const secret = try hex.decodeFixed(32, "b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef");
    const kp = try signer.keyPairFromSecretKey(secret);

    const relays = [_][]const u8{"wss://relay.example.com"};
    const token = try nip46.buildBunkerUri(gpa, kp.public_key, &relays, "s3cret");
    defer gpa.free(token);

    try std.testing.expectStringStartsWith(
        token,
        "bunker://dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659?",
    );
    try std.testing.expect(std.mem.indexOf(u8, token, "secret=s3cret") != null);
}
