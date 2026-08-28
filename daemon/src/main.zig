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
const audit = @import("audit.zig");
const relay_keeper = @import("relay_keeper.zig");

const keys = nostr.keys;
const nip46 = nostr.nip46;
const nip49 = nostr.nip49;
const hex = nostr.hex;

// Turnkey defaults for GUI mode, so a freshly downloaded app works with zero
// configuration; each is overridable via its environment variable. The key and
// files sit under $HOME; relays default to a public relay.
const default_log_file = audit.default_file;

/// How long the daemon stays up with nothing using it.
///
/// Fifteen minutes, and the number is a trade rather than a preference. Both
/// windows poll while they are open, so this clock only starts once every app
/// has gone; shorter and somebody who quits an app for two minutes has to type
/// their passphrase again, longer and a machine left alone keeps a decrypted
/// key for an afternoon.
///
/// `SIGNER_IDLE_EXIT_MS=0` keeps it up forever, which is what somebody running
/// this headless as a bunker for their phone wants: there is no window there
/// to poll, so silence is the normal state rather than a sign that everyone
/// left.
const default_idle_exit_ms: i64 = 15 * 60 * 1000;

fn idleExitMs() i64 {
    const raw = getEnv("SIGNER_IDLE_EXIT_MS") orelse return default_idle_exit_ms;
    return std.fmt.parseInt(i64, raw, 10) catch default_idle_exit_ms;
}

const default_key_file = ".zig-nostr-signer.key";
const default_conf_file = ".zig-nostr-signer.conf";
// What the GUI serves on when the reader has not chosen. THREE, not one.
//
// A signer on a single relay is a signer that stops signing when that relay
// does, and the failure is silent from the client's side: the request is
// published, nothing answers, and the app just sits there. Amber ships three
// defaults for the same reason (`defaultAppRelays` in AmberSettings.kt) and
// makes them editable, which is the shape copied here.
//
// These are Amber's three verbatim, three separate operators, so one going down
// is one thread reconnecting rather than a signer that has quietly stopped.
// Deliberately NOT relay.nsec.app, which is the obvious pick and the wrong one:
// it belongs to a signer project that looks unmaintained, and a default should
// not point at infrastructure whose owner has moved on.
/// The two pieces of state every relay thread shares, and the approval server
/// reaches as well.
///
/// Process-lived rather than owned by `runRelays`, because they outlive nothing
/// and two other things need them: `/nostrconnect` authorizes a client from the
/// HTTP thread, which is constructed before serving starts, and signing out has
/// to clear the same set. `runRelays` never returns, so the lifetime was always
/// the process; this only says so where both callers can see it.
var g_seen_requests: nostr.signer.SeenRequests = .{};
var g_authorized_clients: nip46.AuthorizedClients = .{};

/// Where every use of the key is written down.
///
/// Process-lived and shared, because both the relay threads and the approval
/// server write to it, and one file with one lock is the only way those lines
/// stay whole. Its path is set at startup; until then it is a log that goes
/// nowhere, which is what the non-GUI paths want anyway.
var g_audit: audit.Log = .{};

const default_gui_relays = "wss://nostr.oxtr.dev,wss://theforest.nostr1.com,wss://relay.primal.net";

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
    \\  SIGNER_LOG_FILE        where uses of the key are written down (default:
    \\                         $HOME/.zig-nostr-signer.log; empty turns it off)
    \\  SIGNER_IDLE_EXIT_MS    exit after this long with no request (default:
    \\                         900000, fifteen minutes; 0 stays up forever)
    \\  SIGNER_CONF_FILE       where this daemon's own settings live (default:
    \\                         $HOME/.zig-nostr-signer.conf), currently just
    \\                         whether it answers clients over relays
    \\
    \\Subcommands:
    \\  import                 paste an existing nsec, read from the terminal
    \\                         with echo off, and store it encrypted at rest
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

    // `signer import`: the strongest way in, and the reason it is a subcommand
    // rather than another environment variable. `SIGNER_INIT` below takes the
    // key from `SIGNER_SECRET_KEY`, which means it sits in the environment, in
    // shell history, and in `ps` output for anyone on the machine to read.
    // This reads it from the terminal with echo off instead.
    {
        var sub_args = std.process.Args.Iterator.init(init.minimal.args);
        _ = sub_args.skip(); // argv[0]
        if (sub_args.next()) |sub| {
            if (std.mem.eql(u8, sub, "import")) runImport(gpa);
        }
    }

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
    // Whether this daemon also answers clients over relays.
    //
    // The FLAG is an override for a terminal. The answer normally comes from
    // this daemon's own config file, and that is the point rather than a
    // convenience: whether the keyholder serves other devices is the
    // keyholder's decision, not something the app that happened to start it
    // gets to choose. An app embedding Notary spawns it and asks for nothing.
    //
    // Serving relays is not a second door to guard. A client that reaches this
    // over a relay is a NIP-46 client and proves who it is with its own
    // keypair, which is the one identity here that cannot be forged. What the
    // setting is really about is that turning it on puts the process holding
    // the key on the network at all.
    var serve_relays = false;
    var args = std.process.Args.Iterator.init(init.minimal.args);
    _ = args.skip(); // argv[0]
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--approval-http")) {
            approval_addr = args.next();
        } else if (std.mem.eql(u8, arg, "--serve-relays")) {
            serve_relays = true;
        }
    }

    if (approval_addr) |addr| {
        runGuiMode(gpa, addr, conn_secret, &policy_config, serve_relays);
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
fn runGuiMode(gpa: std.mem.Allocator, addr: []const u8, conn_secret: ?[]const u8, policy_config: *const PolicyConfig, forced_relays: bool) noreturn {
    const hp = parseHostPort(addr) orelse
        fail("SIGNER_APPROVAL_HTTP must be host:port, e.g. 127.0.0.1:0");

    // Turnkey defaults so a fresh download needs no configuration.
    const key_file = getEnv("SIGNER_KEY_FILE") orelse resolveHome(gpa, default_key_file);
    // The flag forces it on; otherwise this daemon's own config decides. An app
    // that embeds Notary passes nothing and gets whatever the reader chose in
    // Notary's window, which is where a question about signing belongs.
    const conf_path = getEnv("SIGNER_CONF_FILE") orelse resolveHome(gpa, default_conf_file);

    var startup = std.Io.Threaded.init(gpa, .{});
    defer startup.deinit();
    const io = startup.io();

    const serve_relays = forced_relays or approval_http.readServeRelays(gpa, io, conf_path);
    var relays: std.ArrayList([]const u8) = .empty;
    if (serve_relays) {
        parseRelays(gpa, &relays, getEnv("SIGNER_RELAYS") orelse default_gui_relays);
        if (relays.items.len == 0) fail("SIGNER_RELAYS contained no relay URLs");
    }

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

    // The one thing that lets anybody in, read before a single thread exists.
    // A parent that sends nothing gets a daemon with no local channel at all,
    // which is the right failure: better to serve nobody than everybody.
    const secret = readSecretFromStdin(gpa, io);
    if (secret.len == 0)
        fail("no secret arrived on stdin; this daemon is started BY the app it signs for");

    // Beside the key, and readable only by this user, because it is a list of
    // everything that key has done. `SIGNER_LOG_FILE=""` turns it off for
    // somebody who would rather it did not exist.
    g_audit = .{
        .dir = std.Io.Dir.cwd(),
        .path = getEnv("SIGNER_LOG_FILE") orelse resolveHome(gpa, default_log_file),
    };

    var approval_server: approval_http.Server = .{
        .gpa = gpa,
        .broker = &broker_storage,
        .gate = &gate,
        .token = secret,
        .log = &g_audit,
        .idle_exit_ms = idleExitMs(),
        .info = .{ .relays = relays.items, .timeout_ms = broker_storage.timeout_ms, .secret = conn_secret, .relay_status = relay_status, .serve_relays = serve_relays, .conf_file = conf_path },
        .clients = &g_authorized_clients,
        .host = hp.host,
        .port = hp.port,
    };
    // Bind BEFORE anything else, and before any thread exists, because the
    // next two things both depend on it: the spawner is told the port only if
    // there is one, and the fork that frees this daemon from its spawner has
    // to happen while this is still a single-threaded process.
    //
    // A bind that fails kills the daemon here, loudly, while the spawner is
    // still watching. That is the whole reason the port is reported before the
    // detach rather than after: afterwards there is nobody left to tell.
    approval_server.bind(io) catch |err|
        failFmt("could not bind the local channel on {s}: {s}", .{ addr, @errorName(err) });

    // The port goes out on stdout, where only the parent is reading. Asking the
    // kernel for a port rather than fixing one is the other half of having no
    // public front door: an address nobody has chosen yet cannot be squatted,
    // and there is no well-known number for anything else to try.
    announcePort(io, approval_server.bound_port.load(.acquire));

    const server_thread = std.Thread.spawn(.{}, runApprovalServer, .{&approval_server}) catch
        fail("could not start the approval server");
    server_thread.detach();

    const key_note = switch (booted) {
        .unlocked => "Key loaded from the environment; serving now.",
        .locked => "Waiting for the GUI to unlock the key…",
        .uninitialized => "Waiting for the GUI to set up the key…",
    };
    std.debug.print(
        \\zig-nostr signer (embedded)
        \\  serving      : the process that started me, on 127.0.0.1:{d}
        \\  key file     : {s}
        \\  key state    : {s}
        \\  audit log    : {s}
        \\
        \\{s}
        \\
    , .{ approval_server.bound_port.load(.acquire), key_file, @tagName(booted), if (g_audit.path.len == 0) "(off)" else g_audit.path, key_note });

    // Block until the GUI creates or unlocks the key (returns at once if a
    // preconfigured key was loaded above), then serve with it. The broker is
    // already live, so approvals work the moment serving starts.
    const secret_key = gate.waitUnlocked(io);
    if (!serve_relays) {
        // Embedded. There is nothing to serve but the app that started this,
        // and that is already being served on the other thread. Park here so
        // the process lives as long as its parent does rather than falling out
        // of a function that promised never to return.
        while (true) io.sleep(std.Io.Duration.fromSeconds(3600), .awake) catch {};
    }
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

    // ONE of each, shared by every relay thread, and this is what makes serving
    // more than one relay correct rather than merely possible.
    //
    // A bunker token names every relay the signer listens on, and a client
    // publishes its request to all of them, so one intent arrives as the same
    // event id on each thread. Held per thread, the record of answered requests
    // meant each relay answered its own copy: two approval prompts for one
    // question, and two signatures published for one intent. And the set of
    // clients that had completed `connect` was per bunker, so a client that
    // connected over one relay and asked over another was told "not connected".
    //
    // Both now live out here for the life of the process. This is exactly what
    // nostr v0.10.0 changed its two signatures for.
    var threads: std.ArrayList(std.Thread) = .empty;
    for (relays, 0..) |url, i| {
        const slot: ?*std.atomic.Value(u8) = if (relay_status) |rs| &rs[i] else null;
        const t = std.Thread.spawn(.{}, serveRelayForever, .{ gpa, url, secret_key, conn_secret, policy_config, broker, slot, keeper, i, &g_seen_requests, &g_authorized_clients }) catch |err| {
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
    seen: *nostr.signer.SeenRequests,
    clients: *nip46.AuthorizedClients,
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
        .log = &g_audit,
    };
    const request_policy = if (broker != null) interactive.asPolicy() else policy_config.policy();

    var bunker = nip46.Bunker.initSingleKey(signer, kp, request_policy, clients);
    bunker.secret = conn_secret;
    // The bunker refuses to sign for a client it has not heard of. It lives out
    // here, outside the dial loop, so a dropped socket does not make every
    // client connect again.
    //
    // The authorized set is the caller's and shared with every other relay
    // thread, so a client that connects over one relay and asks over another is
    // recognised. It used to be per bunker and therefore per relay, and that
    // reconnect-per-relay is what this fixes.

    while (true) {
        if (status) |s| s.store(@intFromEnum(approval_http.RelayStatus.connecting), .monotonic);
        serveOnce(gpa, io, url, &bunker, kp, status, keeper, slot, seen) catch |err| {
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
    seen: *nostr.signer.SeenRequests,
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
    try nostr.signer.serve(gpa, io, relay, bunker, remote, url, seen);
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
// ---------------------------------------------------------------- import CLI
//
// `signer import`: paste an existing nsec and Notary takes it over, encrypted
// at rest like any key it made itself.
//
// The key is read from the terminal with echo off (or from stdin when piped),
// so it never reaches an argument, the environment, the clipboard or the
// screen. A key given as an argument would be in shell history and visible in
// `ps` to every process on the machine, which is why this refuses to take one
// that way at all.
//
// The key is written for Notary to find, never handed to a running one: the
// reason is at the write itself. A Notary that is already open notices the file
// on its next /info poll and asks for the passphrase, so importing no longer
// costs a relaunch.

fn runImport(gpa: std.mem.Allocator) noreturn {
    var startup = std.Io.Threaded.init(gpa, .{});
    defer startup.deinit();
    const io = startup.io();

    var input_buf: [256]u8 = undefined;
    defer std.crypto.secureZero(u8, &input_buf);
    const input = readSecretLine("Paste your nsec (input hidden): ", &input_buf) orelse fail("no key read");
    if (input.len == 0) fail("nothing pasted");
    if (!std.mem.startsWith(u8, input, "nsec1") and input.len != 64) {
        fail("paste an nsec1... key, or 64 hex characters");
    }

    // Notary encrypts at rest, always, so the passphrase is not optional the
    // way it is for an app that keeps a raw key. Asked twice because a typo
    // here is not recoverable: the file it encrypts cannot be opened again.
    var pass_buf: [256]u8 = undefined;
    defer std.crypto.secureZero(u8, &pass_buf);
    const passphrase = readSecretLine("Passphrase to encrypt it with: ", &pass_buf) orelse fail("no passphrase");
    if (passphrase.len == 0) fail("a passphrase is required");

    var again_buf: [256]u8 = undefined;
    defer std.crypto.secureZero(u8, &again_buf);
    const again = readSecretLine("Again: ", &again_buf) orelse fail("no passphrase");
    if (!std.mem.eql(u8, passphrase, again)) fail("the two passphrases do not match");

    const key_file = getEnv("SIGNER_KEY_FILE") orelse resolveHome(gpa, default_key_file);

    // Written for the next launch, never handed to a running Notary, and that
    // is deliberate rather than a shortcut. The daemon binds an EPHEMERAL port
    // and tells only the GUI that spawned it which one, so that another process
    // running as this user cannot find the control channel by guessing. A CLI
    // that could reach it would need that port published somewhere readable,
    // which is exactly the property being protected. So this writes the file and
    // says nothing to anyone. A running Notary finds it on its next /info poll
    // (`Gate.rescan`) and asks for the passphrase, so the property is kept and
    // the relaunch it used to cost is not.
    const initial: onboarding.State = if (fileExists(io, key_file)) .locked else .uninitialized;
    var gate = onboarding.Gate.init(gpa, std.Io.Dir.cwd(), key_file, initial);
    gate.setup(io, passphrase, input) catch |err| switch (err) {
        error.AlreadyInitialized => fail("a key is already set up (remove it in Notary first)"),
        error.InvalidSecretKey => fail("that is not a valid nostr secret key"),
        else => failFmt("could not store the key: {s}", .{@errorName(err)}),
    };
    std.debug.print("Imported. Notary picks it up and asks for this passphrase.\n", .{});
    std.process.exit(0);
}

/// Reads ONE secret line. On a terminal echo is off, so nothing is shown; when
/// stdin is a pipe it takes exactly one line and leaves the rest. The slice
/// points into `buf`, which the caller zeroes.
///
/// A byte at a time, because this is asked three times in a row and a plain
/// `read` into a big buffer takes whatever the pipe has: the first call would
/// swallow the key AND both passphrases, and the second would find nothing
/// left. A terminal hides that (canonical mode hands over one line per read),
/// so it only shows up when the input is piped, which is exactly how a script
/// would drive this.
fn readSecretLine(prompt: []const u8, buf: []u8) ?[]const u8 {
    const stdin_fd: std.posix.fd_t = 0;
    // tcgetattr succeeds only on a terminal, and a pipe returns an error: that
    // is how this tells interactive from piped without a separate isatty.
    const restore: ?std.posix.termios = std.posix.tcgetattr(stdin_fd) catch null;
    if (restore) |base| {
        std.debug.print("{s}", .{prompt});
        var quiet = base;
        quiet.lflag.ECHO = false;
        std.posix.tcsetattr(stdin_fd, .NOW, quiet) catch {};
    }
    defer if (restore) |base| {
        std.posix.tcsetattr(stdin_fd, .NOW, base) catch {};
        std.debug.print("\n", .{});
    };

    var len: usize = 0;
    while (len < buf.len) {
        var one: [1]u8 = undefined;
        const n = std.posix.read(stdin_fd, &one) catch return null;
        if (n == 0) break; // end of input: whatever was read is the line
        if (one[0] == '\n') break;
        buf[len] = one[0];
        len += 1;
    }
    if (len == 0) return null;
    return std.mem.trim(u8, buf[0..len], " \t\r");
}

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

/// The one-time secret this daemon's parent handed it on stdin.
///
/// It replaces a bearer token in a 0600 file, and the reason is measured rather
/// than assumed. What another program running as the same user can see about a
/// process: its argv (`ps` prints it), its environment (`ps -Eww` prints it),
/// and any file it can read. A 0600 file separates USERS, not apps, so every
/// app you run could read the old token and sign as you.
///
/// A pipe from a parent is the one channel with none of those properties. It
/// has no name, no path, and no port: there is nothing for another process to
/// open. Possession of the channel IS the authentication, so this daemon does
/// not have to answer "which app is this", which is a question nobody has
/// solved on the desktop.
///
/// Read before anything else and before any thread exists. A parent that sends
/// nothing gets a daemon with no local channel at all, which is the correct
/// failure: better to serve nobody than to serve everybody.
fn readSecretFromStdin(gpa: std.mem.Allocator, io: std.Io) []const u8 {
    var buf: [256]u8 = undefined;
    var r = std.Io.File.stdin().reader(io, &buf);
    const line = r.interface.takeDelimiterExclusive('\n') catch |err| switch (err) {
        // The parent closed the pipe having written the whole secret and no
        // newline. Everything read so far is the secret.
        error.EndOfStream => r.interface.buffered(),
        else => return "",
    };
    const trimmed = std.mem.trim(u8, line, " \t\r\n");
    if (trimmed.len < 16) return ""; // too short to be a secret anybody minted
    return gpa.dupe(u8, trimmed) catch "";
}

/// The one line the spawner reads: the port this daemon is listening on.
///
/// STDOUT, and that matters. The SDK's line-mode spawn ignores a child's
/// stderr outright (`.stderr = ... else .ignore`), so the human-facing banner
/// below it is dropped on the floor and a spawner watching for this would wait
/// forever.
///
/// Printed after the bind and before the detach. Both halves of that are
/// deliberate: after, because a port nobody got is not worth reporting; before,
/// because once this process has detached there is nobody left listening.
fn announcePort(io: std.Io, port: u16) void {
    var out_buf: [64]u8 = undefined;
    var stdout = std.Io.File.stdout().writer(io, &out_buf);
    stdout.interface.print("{s} {d}\n", .{ approval_http.port_line_prefix, port }) catch {};
    stdout.interface.flush() catch {};
}

/// Runs the approval HTTP server on its own thread with its own io.
///
/// A listener that cannot come up KILLS the daemon. It used to print and let
/// the thread die, and the consequence was not a missing feature: the daemon
/// went on running with no listener, blocked forever waiting to be unlocked,
/// while whatever was already holding that port answered the GUI instead. The
/// parent has no way to tell the difference, so it would find something
/// answering and post the unlock passphrase, or an imported nsec, straight to
/// it. Dying loudly is what turns that into a startup failure the
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
    _ = @import("audit.zig");
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

test "the GUI default is more than one relay, and they are separate operators" {
    const gpa = std.testing.allocator;
    var relays: std.ArrayList([]const u8) = .empty;
    defer relays.deinit(gpa);
    parseRelays(gpa, &relays, default_gui_relays);

    // The property, not the list. A signer on one relay stops signing when that
    // relay does, and the client sees nothing: the request is published and
    // never answered. This is pinned against the literal 1 rather than counted
    // off the constant, so shrinking the default back to a single relay fails
    // here instead of passing quietly.
    try std.testing.expect(relays.items.len > 1);

    // Distinct hosts. Three URLs at one operator is one operator, and would
    // satisfy a count while delivering none of what the count is for.
    for (relays.items, 0..) |a, i| {
        try std.testing.expect(std.mem.startsWith(u8, a, "wss://"));
        for (relays.items[i + 1 ..]) |b| {
            try std.testing.expect(!std.mem.eql(u8, a, b));
        }
    }
}
