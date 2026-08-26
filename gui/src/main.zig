//! Notary, a native desktop approver for the signer daemon.
//!
//! Architecture: the signer daemon (the daemon/ package in this repo) holds the
//! secret key and does all Nostr work; this app is a *separate process* that
//! approves or denies each request over the daemon's loopback HTTP API, so
//! the key never enters this process. This app only ever sees request
//! metadata and sends back a yes/no.
//!
//! Two ways to run:
//!
//!  - **Attached** (default): the daemon is already running; the app connects
//!    to its approval API at `SIGNER_APPROVAL_HTTP`.
//!  - **Managed**: the app *spawns and supervises* the daemon binary as a child
//!    process, one launch brings up both. The daemon is either a `signer`
//!    bundled beside this executable (`…/Contents/MacOS/signer` in a packaged
//!    app, so a single download is self-contained) or, taking precedence, an
//!    explicit `SIGNER_BIN` override for development. The child inherits this
//!    process's environment (so it gets `SIGNER_KEY_FILE`, `SIGNER_PASSPHRASE`,
//!    `SIGNER_RELAYS`, `SIGNER_APPROVAL_HTTP`, `SIGNER_APPROVAL_TOKEN_FILE`),
//!    and the runtime kills it when the app quits, so no daemon is orphaned
//!    holding the approval port. The key still only ever lives in the daemon
//!    child.
//!
//! The view lives in `app.native`; this file is the logic. All I/O is through
//! the Native SDK effects channel (`fx.spawn` supervises the daemon, `fx.fetch`
//! talks HTTP, `fx.readFile` reads the token, `fx.startTimer` backs off), so
//! `update` stays a pure state transition and the view stays declarative.

const std = @import("std");
const runner = @import("runner");
const native_sdk = @import("native_sdk");

pub const panic = std.debug.FullPanic(native_sdk.debug.capturePanic);

const canvas = native_sdk.canvas;
const geometry = native_sdk.geometry;

const canvas_label = "main-canvas";
const window_width: f32 = 460;
const window_height: f32 = 560;

// `filesystem` is what lets the GUI read the daemon's bearer token. SDK 0.9.1
// confines raw file effects to the app's own directories unless this is
// declared, and the token lives at $HOME/.zig-nostr-signer.token, which is
// outside every one of them. Without it `fx.readFile` is rejected SILENTLY:
// `.token_read` arrives as `.rejected`, every non-ok outcome arms a retry,
// the phase never advances, and the app sits at "Connecting to the signer…"
// forever looking exactly like a network fault.
pub const app_permissions = [_][]const u8{ native_sdk.security.permission_command, native_sdk.security.permission_view, native_sdk.security.permission_clipboard, native_sdk.security.permission_filesystem };
const shell_views = [_]native_sdk.ShellView{
    .{ .label = canvas_label, .kind = .gpu_surface, .fill = true, .role = "Notary canvas", .accessibility_label = "Notary", .gpu_backend = .metal, .gpu_pixel_format = .bgra8_unorm, .gpu_present_mode = .timer, .gpu_alpha_mode = .@"opaque", .gpu_color_space = .srgb, .gpu_vsync = true },
};
const shell_windows = [_]native_sdk.ShellWindow{.{
    .label = "main",
    .title = "Notary",
    .width = window_width,
    .height = window_height,
    .restore_state = false,
    .views = &shell_views,
}};
const shell_scene: native_sdk.ShellConfig = .{ .windows = &shell_windows };

// ------------------------------------------------------------- config

const default_address = "127.0.0.1:8787";

/// The command that takes a key without it passing through this window.
///
/// The installed path, not one derived from argv[0]: a reader looking at this
/// is going to retype or paste it into a terminal, and the answer has to be
/// right for the app they installed rather than for wherever this binary
/// happens to be running from during development.
const import_command = "/Applications/Notary.app/Contents/MacOS/signer import";
const default_token_file = ".zig-nostr-signer.token";

// Effect keys. Fetch/spawn/file effects share one key space and 16 slots; the
// long-lived daemon spawn holds one slot for the process's lifetime. Timer
// keys are their own namespace. Decisions use a small pool so several can be
// in flight at once (a fast double-approve never collides on one key).
/// The one daemon stdout line the GUI parses. Must match
/// `approval_http.port_line_prefix` in the daemon.
const daemon_port_prefix = "notary-approval-port";

const daemon_key: u64 = 1;
const token_key: u64 = 2;
const info_key: u64 = 3;
const pending_key: u64 = 4;
const setup_key: u64 = 5;
const unlock_key: u64 = 6;
const nostrconnect_key: u64 = 11;
const forget_key: u64 = 12;
const lock_key: u64 = 18;
const export_key: u64 = 19;
const clipboard_key: u64 = 7;
/// Its own effect key: two clipboard writes under one key would have the second
/// rejected while the first is still in flight.
const command_clipboard_key: u64 = 17;
const info_refresh_key: u64 = 16; // periodic /info re-poll (distinct from the initial info_key)
const decision_key_base: u64 = 8;
const decision_key_slots: u64 = 8;
const retry_timer_key: u64 = 100;
const copy_reset_timer_key: u64 = 101;
const info_refresh_timer_key: u64 = 102;

fn decisionKey(id: u64) u64 {
    return decision_key_base + (id % decision_key_slots);
}

// ------------------------------------------------------------------ model

/// One pending signing request awaiting the operator's decision. Strings are
/// copied into fixed buffers so a row never aliases a fetch response body
/// (which is only valid during the `update` call that delivers it).
pub const Row = struct {
    id: u64 = 0,
    method_buf: [24]u8 = [_]u8{0} ** 24,
    method_len: u8 = 0,
    /// Event kind for `sign_event`, else -1.
    kind: i32 = -1,
    created_at: i64 = 0,
    /// The requesting client's pubkey, hex.
    client_buf: [64]u8 = [_]u8{0} ** 64,
    client_len: u8 = 0,
    /// The start of what would be signed.
    preview_buf: [160]u8 = [_]u8{0} ** 160,
    preview_len: u8 = 0,

    pub fn method(self: *const Row) []const u8 {
        return self.method_buf[0..self.method_len];
    }

    pub fn setMethod(self: *Row, m: []const u8) void {
        const n = @min(m.len, self.method_buf.len);
        @memcpy(self.method_buf[0..n], m[0..n]);
        self.method_len = @intCast(n);
    }

    pub fn client(self: *const Row) []const u8 {
        return self.client_buf[0..self.client_len];
    }

    pub fn setClient(self: *Row, c: []const u8) void {
        const n = @min(c.len, self.client_buf.len);
        @memcpy(self.client_buf[0..n], c[0..n]);
        self.client_len = @intCast(n);
    }

    pub fn preview(self: *const Row) []const u8 {
        return self.preview_buf[0..self.preview_len];
    }

    pub fn has_preview(self: *const Row) bool {
        return self.preview_len > 0;
    }

    pub fn setPreview(self: *Row, p: []const u8) void {
        const n = @min(p.len, self.preview_buf.len);
        @memcpy(self.preview_buf[0..n], p[0..n]);
        self.preview_len = @intCast(n);
    }

    /// One-line label for the row, e.g. "sign_event · kind 1" or
    /// "get_public_key". Formats into the build arena.
    pub fn label(self: *const Row, arena: std.mem.Allocator) []const u8 {
        if (self.kind >= 0) {
            return std.fmt.allocPrint(arena, "{s} · kind {d}", .{ self.method(), self.kind }) catch self.method();
        }
        return self.method();
    }

    /// Who is asking, short enough to read: the first and last of the pubkey.
    ///
    /// The whole point of putting it on the row is that a person can tell one
    /// requester from another, and sixty-four hex characters is not something
    /// anybody compares. Eight and eight is.
    pub fn asker(self: *const Row, arena: std.mem.Allocator) []const u8 {
        const c = self.client();
        if (c.len < 20) return if (c.len == 0) "unknown client" else c;
        return std.fmt.allocPrint(arena, "from {s}…{s}", .{ c[0..8], c[c.len - 8 ..] }) catch c;
    }
};

pub const max_relays = 8;

/// Live connection state of one relay, as reported by `/info`.
/// A relay's live state as the daemon reports it.
///
/// `quiet` means the socket is open but nothing has come down it for a while
/// and a keepalive is out unanswered. Shown as its own thing because the
/// alternative is a green dot over a connection that may already be dead, and
/// for a signer the failure that hides is "signing stopped working".
pub const RelayConn = enum { connecting, connected, disconnected, quiet };

/// One configured relay and its live status, listed on the serving screen.
pub const RelayRow = struct {
    id: usize = 0,
    url_buf: [96]u8 = [_]u8{0} ** 96,
    url_len: usize = 0,
    conn: RelayConn = .connecting,

    pub fn url(self: *const RelayRow) []const u8 {
        return self.url_buf[0..self.url_len];
    }
    pub fn status_label(self: *const RelayRow) []const u8 {
        return switch (self.conn) {
            .connecting => "connecting…",
            .connected => "connected",
            .disconnected => "offline",
            .quiet => "quiet",
        };
    }
    // Status predicates, the view picks a literally-colored status word off
    // these (`foreground` takes only a literal token, so the color can't bind).
    pub fn connected(self: *const RelayRow) bool {
        return self.conn == .connected;
    }
    pub fn quiet(self: *const RelayRow) bool {
        return self.conn == .quiet;
    }
    pub fn connecting(self: *const RelayRow) bool {
        return self.conn == .connecting;
    }
    pub fn offline(self: *const RelayRow) bool {
        return self.conn == .disconnected;
    }
};

/// Connection / supervision lifecycle, shown in the header.
pub const Phase = enum {
    /// Managed mode: the daemon child is starting and we do not have a working
    /// token / connection yet.
    starting,
    /// Attached mode: trying to reach an already-running daemon.
    connecting,
    connected,
    /// Was reachable, now failing, retrying.
    disconnected,
    /// The API rejected our bearer token (attached mode).
    unauthorized,
    /// Managed mode: the daemon child exited; awaiting a manual restart.
    daemon_exited,
    /// The daemon has no key yet (`state:uninitialized`): first-run key setup.
    needs_setup,
    /// The daemon's key is encrypted (`state:locked`): enter the passphrase.
    needs_unlock,
};

/// The daemon's key state, as reported by `GET /info`.
pub const InfoState = enum { unknown, uninitialized, locked, unlocked };

pub const max_pending = 32; // matches the daemon broker's capacity

pub const Model = struct {
    // Resolved at boot from the environment; stable for the process.
    base_url_buf: [96]u8 = [_]u8{0} ** 96,
    base_url_len: usize = 0,
    token_path_buf: [512]u8 = [_]u8{0} ** 512,
    token_path_len: usize = 0,
    daemon_bin_buf: [512]u8 = [_]u8{0} ** 512,
    daemon_bin_len: usize = 0,
    /// True when `SIGNER_BIN` is set: the app spawns and supervises the daemon.
    managed: bool = false,

    // Read from the token file via `fx.readFile`; the bearer header value.
    auth_buf: [96]u8 = [_]u8{0} ** 96,
    auth_len: usize = 0,

    phase: Phase = .connecting,
    pubkey_buf: [64]u8 = [_]u8{0} ** 64,
    pubkey_len: usize = 0,
    timeout_ms: u64 = 0,
    /// The `bunker://` connection URI from `/info`, valid while serving. This is
    /// the string the user pastes into a Nostr client to connect, so the serving
    /// screen shows it with a Copy button. Sized for the pubkey + several relays.
    bunker_buf: [1024]u8 = [_]u8{0} ** 1024,
    bunker_len: usize = 0,
    /// True briefly after the Copy button writes the URI to the clipboard, so the
    /// button can confirm with "Copied!". Reset by a short one-shot timer.
    copied: bool = false,
    /// The signer's relays and their live connection status, from `/info`; listed
    /// on the serving screen so the user can see the signer is actually online.
    relays: [max_relays]RelayRow = [_]RelayRow{.{}} ** max_relays,
    relays_len: usize = 0,
    /// Short human note for the `.daemon_exited` state, e.g. "signer exited
    /// (code 1)".
    exit_note_buf: [64]u8 = [_]u8{0} ** 64,
    exit_note_len: usize = 0,

    rows: [max_pending]Row = [_]Row{.{}} ** max_pending,
    rows_len: usize = 0,
    /// The daemon's queue version; sent back as `?since=` so a poll returns
    /// as soon as the queue changes.
    version: u64 = 0,

    // -- onboarding (first-run key setup / unlock) --

    /// The daemon's key state from the most recent `/info`.
    info_state: InfoState = .unknown,
    /// The passphrase, and (on import) the secret, typed on the setup/unlock
    /// screens. They transit this process once to reach `/setup` or `/unlock`
    /// and are cleared right after a successful send.
    passphrase_buf: canvas.TextBuffer(128) = .{},
    /// A `nostrconnect://` link pasted in from a client that is waiting to be
    /// adopted. Long, because it carries relays, a secret and app metadata.
    nostrconnect_buf: canvas.TextBuffer(512) = .{},
    nostrconnect_sending: bool = false,
    nostrconnect_error_buf: [96]u8 = [_]u8{0} ** 96,
    nostrconnect_error_len: usize = 0,
    /// Typed confirmation for removing the key file. A phrase rather than a
    /// checkbox, because this is the one control here that destroys something.
    forget_buf: canvas.TextBuffer(32) = .{},
    /// Whether the reader has asked to see the way out of this key. Folded away
    /// on every launch: this is not a thing to be one keystroke from.
    forget_showing: bool = false,
    forget_error_buf: [96]u8 = [_]u8{0} ** 96,
    forget_error_len: usize = 0,
    /// Backing up the key. Folded away on every launch for the same reason the
    /// way out is: the passphrase field for it should not be sitting open.
    backup_showing: bool = false,
    backup_pass: canvas.TextBuffer(128) = .{},
    /// The exported key, held only until the reader copies it or closes the
    /// panel. An `ncryptsec1…` unless they asked for the key in the clear.
    backup_key_buf: [256]u8 = [_]u8{0} ** 256,
    backup_key_len: usize = 0,
    /// Whether what is held is the key in the clear rather than the encrypted
    /// form, which decides what the panel warns about.
    backup_is_raw: bool = false,
    backup_sending: bool = false,
    backup_error_buf: [96]u8 = [_]u8{0} ** 96,
    backup_error_len: usize = 0,
    backup_copied: bool = false,
    secret_buf: canvas.TextBuffer(200) = .{},
    /// false: generate a fresh key; true: import an existing `nsec1…`/hex.
    import_mode: bool = false,
    /// Whether the terminal command is on the clipboard, for the button's own
    /// confirmation. Separate from `copied`, which belongs to the bunker URL:
    /// one flag for two buttons would light both.
    command_copied: bool = false,
    /// Managed mode: whether the daemon has told us which port it bound.
    ///
    /// It binds port 0 and reports what the kernel gave it, because a fixed
    /// port can be taken before the daemon starts. Anything that got there
    /// first would receive the unlock passphrase, or an imported nsec, from a
    /// GUI with no way to tell the difference. A port nobody has chosen yet
    /// cannot be squatted.
    ///
    /// Until this is true there is nothing to talk to, so no poll is sent.
    /// Attached mode sets it at boot: the address came from the environment and
    /// is the operator's business.
    port_known: bool = false,
    /// A `/setup` or `/unlock` POST is in flight (disables the submit button).
    submitting: bool = false,
    onboard_error_buf: [96]u8 = [_]u8{0} ** 96,
    onboard_error_len: usize = 0,

    // -- config accessors --

    pub fn setBaseUrl(self: *Model, host_port: []const u8) void {
        const s = std.fmt.bufPrint(&self.base_url_buf, "http://{s}", .{host_port}) catch return;
        self.base_url_len = s.len;
    }
    pub fn baseUrl(self: *const Model) []const u8 {
        return self.base_url_buf[0..self.base_url_len];
    }
    pub fn setTokenPath(self: *Model, path: []const u8) void {
        const n = @min(path.len, self.token_path_buf.len);
        @memcpy(self.token_path_buf[0..n], path[0..n]);
        self.token_path_len = n;
    }
    pub fn tokenPath(self: *const Model) []const u8 {
        return self.token_path_buf[0..self.token_path_len];
    }
    pub fn setDaemonBin(self: *Model, path: []const u8) void {
        const n = @min(path.len, self.daemon_bin_buf.len);
        @memcpy(self.daemon_bin_buf[0..n], path[0..n]);
        self.daemon_bin_len = n;
    }
    pub fn daemonBin(self: *const Model) []const u8 {
        return self.daemon_bin_buf[0..self.daemon_bin_len];
    }
    pub fn setAuth(self: *Model, token: []const u8) void {
        if (token.len == 0) {
            self.auth_len = 0;
            return;
        }
        const s = std.fmt.bufPrint(&self.auth_buf, "Bearer {s}", .{token}) catch return;
        self.auth_len = s.len;
    }
    pub fn auth(self: *const Model) []const u8 {
        return self.auth_buf[0..self.auth_len];
    }
    pub fn hasToken(self: *const Model) bool {
        return self.auth_len > 0;
    }

    // -- view bindings --

    /// The pending queue, iterated by `<for each="visible">`.
    pub fn visible(self: *const Model, arena: std.mem.Allocator) []const Row {
        _ = arena;
        return self.rows[0..self.rows_len];
    }
    pub fn count(self: *const Model) usize {
        return self.rows_len;
    }
    /// Body states, exactly one is true, so the view renders plain `<if>`
    /// blocks instead of nested else chains.
    pub fn daemon_down(self: *const Model) bool {
        return self.phase == .daemon_exited;
    }
    pub fn needs_setup(self: *const Model) bool {
        return self.phase == .needs_setup;
    }
    pub fn needs_unlock(self: *const Model) bool {
        return self.phase == .needs_unlock;
    }
    /// The full-screen states (stopped / setup / unlock) that replace the queue.
    fn onboarding_body(self: *const Model) bool {
        return self.phase == .daemon_exited or self.phase == .needs_setup or self.phase == .needs_unlock;
    }
    pub fn show_empty(self: *const Model) bool {
        return !self.onboarding_body() and self.rows_len == 0;
    }
    pub fn show_queue(self: *const Model) bool {
        return !self.onboarding_body() and self.rows_len > 0;
    }

    /// Footer text: the pending count while serving, nothing during onboarding.
    /// The app's ONE status line.
    ///
    /// There used to be a header block carrying the name, the phase and the key
    /// on three separate lines, above a status bar counting the queue. Four
    /// lines of chrome in a 460x560 window, three of which said nothing after
    /// the first second, and the app's own name told the reader nothing the
    /// title bar had not already said. Now there is one line, at the bottom,
    /// and the body starts at the top of the window.
    pub fn footer(self: *const Model, arena: std.mem.Allocator) []const u8 {
        // While onboarding, the phase IS the whole story and there is no queue
        // to count: the screen already says what it wants.
        if (self.onboarding_body()) return self.status();
        if (self.phase != .connected) return self.status();
        // No key yet means the daemon has not answered /info; the count alone
        // is the honest line, rather than "signer not connected" beside a queue.
        if (self.pubkey_len == 0) return std.fmt.allocPrint(arena, "{d} pending", .{self.rows_len}) catch "";
        const key = self.pubkey_short(arena);
        return std.fmt.allocPrint(arena, "signer {s} · {d} pending", .{ key, self.rows_len }) catch "";
    }

    // -- onboarding view bindings --

    pub fn import_command_text(self: *const Model) []const u8 {
        _ = self;
        return import_command;
    }
    /// "Copy", or the confirmation, on the terminal card's own button.
    pub fn command_copy_label(self: *const Model) []const u8 {
        return if (self.command_copied) "Copied!" else "Copy";
    }
    /// The card belongs to the import branch of setup, not to creating a key:
    /// there is nothing to bring in from a terminal when the signer is about to
    /// mint one.
    pub fn show_terminal_import(self: *const Model) bool {
        return self.phase == .needs_setup and self.import_mode;
    }

    pub fn forget_confirm(self: *const Model) []const u8 {
        return self.forget_buf.text();
    }
    /// Whether the unlock screen is showing the way OUT of this key.
    ///
    /// Folded away by default. It used to sit open under the passphrase field,
    /// so the first thing anybody saw on opening Notary was a box telling them
    /// to type "delete my key", which is a strange thing for an app to lead
    /// with when all the reader wants is to unlock it.
    pub fn forget_open(self: *const Model) bool {
        return self.forget_showing;
    }
    pub fn forget_closed(self: *const Model) bool {
        return !self.forget_showing;
    }
    pub fn forget_disabled(self: *const Model) bool {
        // The button is inert until the phrase matches exactly, so the
        // destructive press cannot be a mis-click.
        return !std.mem.eql(u8, self.forget_buf.text(), "delete my key");
    }
    pub fn backup_open(self: *const Model) bool {
        return self.backup_showing;
    }
    pub fn backup_closed(self: *const Model) bool {
        return !self.backup_showing;
    }
    pub fn backup_passphrase(self: *const Model) []const u8 {
        return self.backup_pass.text();
    }
    pub fn backup_disabled(self: *const Model) bool {
        return self.backup_sending or self.backup_pass.text().len == 0;
    }
    pub fn backup_key(self: *const Model) []const u8 {
        return self.backup_key_buf[0..self.backup_key_len];
    }
    pub fn has_backup_key(self: *const Model) bool {
        return self.backup_key_len > 0;
    }
    pub fn backup_is_encrypted(self: *const Model) bool {
        return self.backup_key_len > 0 and !self.backup_is_raw;
    }
    pub fn backup_is_secret(self: *const Model) bool {
        return self.backup_key_len > 0 and self.backup_is_raw;
    }
    pub fn backup_error(self: *const Model) []const u8 {
        return self.backup_error_buf[0..self.backup_error_len];
    }
    pub fn has_backup_error(self: *const Model) bool {
        return self.backup_error_len > 0;
    }
    pub fn backup_copy_label(self: *const Model) []const u8 {
        return if (self.backup_copied) "Copied" else "Copy";
    }

    /// Everything the backup panel was holding, gone. Called when it closes,
    /// when the account changes, and when the daemon does: a key sitting in a
    /// window nobody is looking at is the thing this whole app exists to avoid.
    fn setBackupError(self: *Model, text: []const u8) void {
        const n = @min(text.len, self.backup_error_buf.len);
        @memcpy(self.backup_error_buf[0..n], text[0..n]);
        self.backup_error_len = n;
    }

    pub fn clearBackup(self: *Model) void {
        self.backup_showing = false;
        self.backup_pass.set("");
        std.crypto.secureZero(u8, &self.backup_key_buf);
        self.backup_key_len = 0;
        self.backup_is_raw = false;
        self.backup_sending = false;
        self.backup_error_len = 0;
        self.backup_copied = false;
    }

    pub fn forget_error(self: *const Model) []const u8 {
        return self.forget_error_buf[0..self.forget_error_len];
    }
    pub fn has_forget_error(self: *const Model) bool {
        return self.forget_error_len > 0;
    }

    pub fn nostrconnect(self: *const Model) []const u8 {
        return self.nostrconnect_buf.text();
    }
    pub fn nostrconnect_disabled(self: *const Model) bool {
        return self.nostrconnect_sending or self.nostrconnect_buf.text().len == 0;
    }
    pub fn nostrconnect_label(self: *const Model) []const u8 {
        return if (self.nostrconnect_sending) "Connecting…" else "Connect";
    }
    pub fn nostrconnect_error(self: *const Model) []const u8 {
        return self.nostrconnect_error_buf[0..self.nostrconnect_error_len];
    }
    pub fn has_nostrconnect_error(self: *const Model) bool {
        return self.nostrconnect_error_len > 0;
    }

    pub fn passphrase(self: *const Model) []const u8 {
        return self.passphrase_buf.text();
    }
    pub fn secret(self: *const Model) []const u8 {
        return self.secret_buf.text();
    }
    pub fn create_selected(self: *const Model) bool {
        return !self.import_mode;
    }
    pub fn import_selected(self: *const Model) bool {
        return self.import_mode;
    }
    pub fn onboard_error(self: *const Model) []const u8 {
        return self.onboard_error_buf[0..self.onboard_error_len];
    }
    pub fn has_onboard_error(self: *const Model) bool {
        return self.onboard_error_len > 0;
    }
    /// Disables the submit button while a request is in flight or the passphrase
    /// is empty.
    pub fn submit_disabled(self: *const Model) bool {
        return self.submitting or self.passphrase_buf.isEmpty();
    }
    pub fn setup_label(self: *const Model) []const u8 {
        if (self.submitting) return "Working…";
        return if (self.import_mode) "Import key" else "Create key";
    }
    pub fn unlock_label(self: *const Model) []const u8 {
        return if (self.submitting) "Unlocking…" else "Unlock";
    }

    /// Connection state line in the header.
    pub fn status(self: *const Model) []const u8 {
        return switch (self.phase) {
            .starting => "Starting the signer…",
            .connecting => "Connecting to the signer…",
            .connected => "Connected",
            .disconnected => "Signer unreachable, retrying…",
            .unauthorized => "Unauthorized: check the token file",
            .daemon_exited => "Signer stopped",
            .needs_setup => "First-run setup",
            .needs_unlock => "Locked",
        };
    }

    /// Message shown in the body while the queue is empty. (The onboarding
    /// phases render their own screens, so their text here is never seen.)
    pub fn empty_text(self: *const Model) []const u8 {
        return switch (self.phase) {
            .connected => "No pending requests",
            .starting => "Starting the signer…",
            .connecting => "Connecting to the signer…",
            .disconnected => "Signer unreachable, retrying…",
            .unauthorized => "Unauthorized: check the token file",
            .daemon_exited, .needs_setup, .needs_unlock => "",
        };
    }

    pub fn exit_note(self: *const Model) []const u8 {
        if (self.exit_note_len == 0) return "The signer process stopped.";
        return self.exit_note_buf[0..self.exit_note_len];
    }

    /// Abbreviated signer public key for the header (`aabbccddee…11223344`).
    pub fn pubkey_short(self: *const Model, arena: std.mem.Allocator) []const u8 {
        const pk = self.pubkey_buf[0..self.pubkey_len];
        if (pk.len == 0) return "not connected";
        if (pk.len <= 20) return pk;
        return std.fmt.allocPrint(arena, "{s}…{s}", .{ pk[0..10], pk[pk.len - 8 ..] }) catch pk[0..20];
    }

    fn setPubkey(self: *Model, pk: []const u8) void {
        const n = @min(pk.len, self.pubkey_buf.len);
        @memcpy(self.pubkey_buf[0..n], pk[0..n]);
        self.pubkey_len = n;
    }

    /// The full `bunker://` connection URI, shown on the serving screen.
    pub fn bunker(self: *const Model) []const u8 {
        return self.bunker_buf[0..self.bunker_len];
    }
    /// Show the connection card only while serving with a URI in hand.
    /// Whether the serving screen has anything on it.
    ///
    /// The scroll around it is `grow`, so it must not exist when this screen is
    /// not the one showing: an empty one still takes its share of the window,
    /// and on the unlock screen it pushed the heading half way down.
    pub fn show_serving(self: *const Model) bool {
        return self.show_bunker() or self.show_relays() or self.show_empty();
    }

    pub fn show_bunker(self: *const Model) bool {
        return self.phase == .connected and self.bunker_len > 0;
    }
    /// Copy-button label, confirming briefly after a successful copy.
    pub fn copy_label(self: *const Model) []const u8 {
        return if (self.copied) "Copied!" else "Copy";
    }

    /// Stores the `bunker://` URI from `/info`; a changed URI clears the stale
    /// "Copied!" confirmation. An over-long URI (absurd relay count) is dropped
    /// rather than truncated, so the shown string is always a valid URI.
    fn setBunker(self: *Model, uri: []const u8) void {
        if (uri.len > self.bunker_buf.len) {
            self.clearBunker();
            return;
        }
        if (!std.mem.eql(u8, uri, self.bunker())) self.copied = false;
        @memcpy(self.bunker_buf[0..uri.len], uri);
        self.bunker_len = uri.len;
    }
    fn clearBunker(self: *Model) void {
        self.bunker_len = 0;
        self.copied = false;
    }

    /// The relay list, iterated by `<for each="relay_list">`.
    pub fn relay_list(self: *const Model, arena: std.mem.Allocator) []const RelayRow {
        _ = arena;
        return self.relays[0..self.relays_len];
    }
    /// Show the relay list only while serving with relays in hand.
    pub fn show_relays(self: *const Model) bool {
        return self.phase == .connected and self.relays_len > 0;
    }

    /// Replaces the relay list from `/info`'s `relays` array of `{url,status}`.
    /// Copies each URL into a fixed buffer (the parse arena is transient).
    fn setRelays(self: *Model, list: anytype) void {
        var n: usize = 0;
        for (list) |r| {
            if (n >= max_relays) break;
            var row = RelayRow{ .id = n };
            const un = @min(r.url.len, row.url_buf.len);
            @memcpy(row.url_buf[0..un], r.url[0..un]);
            row.url_len = un;
            row.conn = if (std.mem.eql(u8, r.status, "connected"))
                .connected
            else if (std.mem.eql(u8, r.status, "disconnected"))
                .disconnected
            else if (std.mem.eql(u8, r.status, "quiet"))
                .quiet
            else
                .connecting;
            self.relays[n] = row;
            n += 1;
        }
        self.relays_len = n;
    }
    fn clearRelays(self: *Model) void {
        self.relays_len = 0;
    }

    fn setExitNote(self: *Model, exit: native_sdk.EffectExit) void {
        const s = switch (exit.reason) {
            .spawn_failed, .rejected => std.fmt.bufPrint(&self.exit_note_buf, "The signer failed to start, check SIGNER_BIN.", .{}),
            .signaled => std.fmt.bufPrint(&self.exit_note_buf, "The signer was terminated (signal).", .{}),
            else => std.fmt.bufPrint(&self.exit_note_buf, "The signer exited (code {d}).", .{exit.code}),
        } catch return;
        self.exit_note_len = s.len;
    }

    pub fn clearRows(self: *Model) void {
        self.rows_len = 0;
    }

    fn setInfoState(self: *Model, s: []const u8) void {
        self.info_state = if (std.mem.eql(u8, s, "unlocked"))
            .unlocked
        else if (std.mem.eql(u8, s, "locked"))
            .locked
        else if (std.mem.eql(u8, s, "uninitialized"))
            .uninitialized
        else
            .unknown;
    }

    fn setOnboardError(self: *Model, msg: []const u8) void {
        const n = @min(msg.len, self.onboard_error_buf.len);
        @memcpy(self.onboard_error_buf[0..n], msg[0..n]);
        self.onboard_error_len = n;
    }
    fn clearOnboardError(self: *Model) void {
        self.onboard_error_len = 0;
    }
    /// Wipes the passphrase and secret buffers (after a successful send, or when
    /// the daemon goes away).
    fn clearSecrets(self: *Model) void {
        self.passphrase_buf.clear();
        self.secret_buf.clear();
    }

    pub fn removeRow(self: *Model, id: u64) void {
        var i: usize = 0;
        while (i < self.rows_len) : (i += 1) {
            if (self.rows[i].id == id) {
                var j = i;
                while (j + 1 < self.rows_len) : (j += 1) self.rows[j] = self.rows[j + 1];
                self.rows_len -= 1;
                return;
            }
        }
    }
};

// -------------------------------------------------------------------- msg

pub const Msg = union(enum) {
    daemon_line: native_sdk.EffectLine,
    daemon_exited: native_sdk.EffectExit,
    token_read: native_sdk.EffectFileResult,
    info: native_sdk.EffectResponse,
    pending: native_sdk.EffectResponse,
    decided: native_sdk.EffectResponse,
    tick: native_sdk.EffectTimer,
    // Four answers rather than two, Amber's shape: "not now", "for a while"
    // and "stop asking" are each one press, because a prompt with only yes and
    // no is one people learn to hit yes on.
    approve: u64,
    approve_day: u64,
    approve_always: u64,
    reject: u64,
    restart,

    // Copy the bunker:// URI to the clipboard, its result, and the timer that
    // clears the transient "Copied!" confirmation.
    copy_bunker,
    copy_command,
    command_copied_result: native_sdk.EffectClipboardResult,
    bunker_copied: native_sdk.EffectClipboardResult,

    // Adopting a client that showed a nostrconnect:// link.
    nostrconnect_edit: canvas.TextInputEvent,
    submit_nostrconnect,
    nostrconnect_done: native_sdk.EffectResponse,

    // Signing out (lock, reversible) and removing the key (not reversible).
    sign_out,
    /// The daemon answered the sign-out before exiting.
    lock_done: native_sdk.EffectResponse,
    reveal_backup,
    cancel_backup,
    backup_pass_edit: canvas.TextInputEvent,
    /// Ask for the encrypted key: still behind the passphrase, safe to keep.
    export_encrypted,
    /// Ask for the key in the clear, which is the one that can be stolen.
    export_secret,
    backup_done: native_sdk.EffectResponse,
    copy_backup,
    backup_copied: native_sdk.EffectClipboardResult,
    forget_edit: canvas.TextInputEvent,
    reveal_forget,
    cancel_forget,
    submit_forget,
    forget_done: native_sdk.EffectResponse,
    copy_reset: native_sdk.EffectTimer,

    // Periodic /info re-poll (keeps the live relay status fresh) and its response.
    refresh_tick: native_sdk.EffectTimer,
    info_refresh: native_sdk.EffectResponse,

    // Onboarding (first-run key setup / unlock).
    passphrase_edit: canvas.TextInputEvent,
    secret_edit: canvas.TextInputEvent,
    choose_create,
    choose_import,
    submit_setup,
    submit_unlock,
    setup_done: native_sdk.EffectResponse,
    unlock_done: native_sdk.EffectResponse,
};

// ---------------------------------------------------------------- effects

pub const AppUi = canvas.Ui(Msg);
pub const app_markup = @embedFile("app.native");

const NotaryApp = native_sdk.UiApp(Model, Msg);
const Effects = NotaryApp.Effects;

/// What we ask the daemon to bind in managed mode: loopback, port chosen by the
/// kernel. See `Model.port_known` for why.
const managed_bind_address = "127.0.0.1:0";

fn spawnDaemon(model: *Model, fx: *Effects) void {
    model.phase = .starting;
    // A restarted daemon gets a different port, so anything we knew is stale.
    model.port_known = false;
    fx.spawn(.{
        .key = daemon_key,
        .argv = &.{ model.daemonBin(), "--approval-http", managed_bind_address },
        .on_line = Effects.lineMsg(.daemon_line),
        .on_exit = Effects.exitMsg(.daemon_exited),
    });
}

/// One connection attempt: (re-)read the token file, then poll. Re-reading on
/// every attempt means a freshly (re)started daemon's new token is always
/// picked up, healing both the initial startup race and a restart.
fn attemptConnect(model: *Model, fx: *Effects) void {
    // Nothing to connect to until the daemon says where it landed. Staying in
    // `.starting` is the honest state, and it is what the retry tick already
    // knows how to leave.
    if (!model.port_known) return;
    if (model.tokenPath().len == 0) {
        // No token file configured at all: nothing to authenticate with.
        model.phase = .unauthorized;
        return;
    }
    fx.readFile(.{
        .key = token_key,
        .path = model.tokenPath(),
        .on_result = Effects.fileMsg(.token_read),
    });
}

fn fetchInfo(model: *Model, fx: *Effects) void {
    var buf: [128]u8 = undefined;
    const url = std.fmt.bufPrint(&buf, "{s}/info", .{model.baseUrl()}) catch return;
    const headers = [_]std.http.Header{.{ .name = "authorization", .value = model.auth() }};
    fx.fetch(.{
        .key = info_key,
        .url = url,
        .headers = &headers,
        .timeout_ms = 5_000,
        .on_response = Effects.responseMsg(.info),
    });
}

/// A lightweight /info re-poll that only refreshes the live relay status (and the
/// bunker URI), decoupled from the initial connect flow, its response never
/// touches the phase or the pending-poll chain, and its failures are ignored (the
/// pending poll is the real connection-health signal). Runs on its own effect key
/// so it never collides with the initial `fetchInfo`.
fn refreshInfo(model: *Model, fx: *Effects) void {
    var buf: [128]u8 = undefined;
    const url = std.fmt.bufPrint(&buf, "{s}/info", .{model.baseUrl()}) catch return;
    const headers = [_]std.http.Header{.{ .name = "authorization", .value = model.auth() }};
    fx.fetch(.{
        .key = info_refresh_key,
        .url = url,
        .headers = &headers,
        .timeout_ms = 5_000,
        .on_response = Effects.responseMsg(.info_refresh),
    });
}

fn pollPending(model: *Model, fx: *Effects) void {
    var buf: [160]u8 = undefined;
    const url = std.fmt.bufPrint(&buf, "{s}/pending?since={d}", .{ model.baseUrl(), model.version }) catch return;
    const headers = [_]std.http.Header{.{ .name = "authorization", .value = model.auth() }};
    // The daemon long-polls ~1s before answering; 35s is generous headroom.
    fx.fetch(.{
        .key = pending_key,
        .url = url,
        .headers = &headers,
        .timeout_ms = 35_000,
        .on_response = Effects.responseMsg(.pending),
    });
}

fn sendDecision(model: *Model, fx: *Effects, id: u64, approve: bool, remember: []const u8) void {
    var url_buf: [128]u8 = undefined;
    const url = std.fmt.bufPrint(&url_buf, "{s}/decision", .{model.baseUrl()}) catch return;
    var body_buf: [96]u8 = undefined;
    const body = std.fmt.bufPrint(&body_buf, "{{\"id\":{d},\"decision\":\"{s}\",\"remember\":\"{s}\"}}", .{ id, if (approve) "approve" else "reject", remember }) catch return;
    const headers = [_]std.http.Header{
        .{ .name = "authorization", .value = model.auth() },
        .{ .name = "content-type", .value = "application/json" },
    };
    fx.fetch(.{
        .key = decisionKey(id),
        .method = .POST,
        .url = url,
        .headers = &headers,
        .body = body,
        .timeout_ms = 5_000,
        .on_response = Effects.responseMsg(.decided),
    });
}

/// POST /setup, create the key (generate, or import the entered secret) and,
/// on success, start serving. The daemon's scrypt KDF makes this take a moment,
/// so the timeout is generous. The body buffer is wiped after the send (fx.fetch
/// copies it synchronously).
fn sendSetup(model: *Model, fx: *Effects) void {
    model.submitting = true;
    model.clearOnboardError();
    var url_buf: [128]u8 = undefined;
    const url = std.fmt.bufPrint(&url_buf, "{s}/setup", .{model.baseUrl()}) catch return;
    var body_buf: [768]u8 = undefined;
    const Body = struct { passphrase: []const u8, secret: []const u8 };
    // Trim whitespace so a stray space or newline (the key field is a wrapping
    // textarea) can't corrupt a pasted nsec/hex secret.
    const secret = if (model.import_mode) std.mem.trim(u8, model.secret(), " \t\r\n") else "";
    const body = std.fmt.bufPrint(&body_buf, "{f}", .{std.json.fmt(Body{ .passphrase = model.passphrase(), .secret = secret }, .{})}) catch return;
    const headers = [_]std.http.Header{
        .{ .name = "authorization", .value = model.auth() },
        .{ .name = "content-type", .value = "application/json" },
    };
    fx.fetch(.{ .key = setup_key, .method = .POST, .url = url, .headers = &headers, .body = body, .timeout_ms = 20_000, .on_response = Effects.responseMsg(.setup_done) });
    std.crypto.secureZero(u8, &body_buf);
}

/// POST /forget, remove the key file so another account can be set up.
///
/// The daemon answers and then exits, because its relay threads still hold the
/// key it just deleted. The response handler spawns it again.
fn sendForget(model: *Model, fx: *Effects) void {
    if (model.forget_disabled()) return;
    model.forget_error_len = 0;
    var url_buf: [128]u8 = undefined;
    const url = std.fmt.bufPrint(&url_buf, "{s}/forget", .{model.baseUrl()}) catch return;
    var body_buf: [128]u8 = undefined;
    const Body = struct { confirm: []const u8 };
    const body = std.fmt.bufPrint(&body_buf, "{f}", .{std.json.fmt(Body{ .confirm = model.forget_buf.text() }, .{})}) catch return;
    const headers = [_]std.http.Header{
        .{ .name = "authorization", .value = model.auth() },
        .{ .name = "content-type", .value = "application/json" },
    };
    fx.fetch(.{ .key = forget_key, .method = .POST, .url = url, .headers = &headers, .body = body, .timeout_ms = 20_000, .on_response = Effects.responseMsg(.forget_done) });
}

/// POST /export, the backup.
///
/// The passphrase goes with every request, including for the encrypted form
/// that does not strictly need it: an unlocked daemon is the normal state, and
/// whoever is at the keyboard then is not necessarily the person who set it up.
fn sendExport(model: *Model, fx: *Effects, raw: bool) void {
    if (model.backup_disabled()) return;
    model.backup_sending = true;
    model.backup_error_len = 0;
    model.backup_copied = false;
    model.backup_is_raw = raw;
    var url_buf: [128]u8 = undefined;
    const url = std.fmt.bufPrint(&url_buf, "{s}/export", .{model.baseUrl()}) catch return;
    var body_buf: [320]u8 = undefined;
    const Body = struct { passphrase: []const u8, form: []const u8 };
    const body = std.fmt.bufPrint(&body_buf, "{f}", .{std.json.fmt(Body{
        .passphrase = model.backup_pass.text(),
        .form = if (raw) "nsec" else "ncryptsec",
    }, .{})}) catch return;
    const headers = [_]std.http.Header{
        .{ .name = "authorization", .value = model.auth() },
        .{ .name = "content-type", .value = "application/json" },
    };
    fx.fetch(.{ .key = export_key, .method = .POST, .url = url, .headers = &headers, .body = body, .timeout_ms = 20_000, .on_response = Effects.responseMsg(.backup_done) });
}

/// POST /lock, the sign out.
///
/// Asking the daemon to end itself rather than starting a second one beside it.
/// A restart IS the sign out (the relay threads hold the key by value), and the
/// old daemon owns the loopback port until it goes, so spawning over the top of
/// a live one left the new process unable to bind and the window waiting on a
/// port line that never came.
fn sendLock(model: *Model, fx: *Effects) void {
    var url_buf: [128]u8 = undefined;
    const url = std.fmt.bufPrint(&url_buf, "{s}/lock", .{model.baseUrl()}) catch return;
    const headers = [_]std.http.Header{.{ .name = "authorization", .value = model.auth() }};
    fx.fetch(.{ .key = lock_key, .method = .POST, .url = url, .headers = &headers, .timeout_ms = 10_000, .on_response = Effects.responseMsg(.lock_done) });
}

/// POST /nostrconnect, adopt a client that showed a `nostrconnect://` link.
///
/// The link goes to the daemon whole and is parsed there, because the daemon is
/// what holds the key and what will publish the answer. The GUI does not read
/// it: a link is a stranger's string, and there is nothing this window could
/// usefully decide about one that the signer does not decide better.
fn sendNostrConnect(model: *Model, fx: *Effects) void {
    const link = model.nostrconnect_buf.text();
    if (link.len == 0 or model.nostrconnect_sending) return;
    model.nostrconnect_sending = true;
    model.nostrconnect_error_len = 0;
    var url_buf: [128]u8 = undefined;
    const url = std.fmt.bufPrint(&url_buf, "{s}/nostrconnect", .{model.baseUrl()}) catch return;
    var body_buf: [768]u8 = undefined;
    const Body = struct { uri: []const u8 };
    const body = std.fmt.bufPrint(&body_buf, "{f}", .{std.json.fmt(Body{ .uri = link }, .{})}) catch return;
    const headers = [_]std.http.Header{
        .{ .name = "authorization", .value = model.auth() },
        .{ .name = "content-type", .value = "application/json" },
    };
    fx.fetch(.{ .key = nostrconnect_key, .method = .POST, .url = url, .headers = &headers, .body = body, .timeout_ms = 20_000, .on_response = Effects.responseMsg(.nostrconnect_done) });
}

/// POST /unlock, decrypt the key file with the entered passphrase.
fn sendUnlock(model: *Model, fx: *Effects) void {
    model.submitting = true;
    model.clearOnboardError();
    var url_buf: [128]u8 = undefined;
    const url = std.fmt.bufPrint(&url_buf, "{s}/unlock", .{model.baseUrl()}) catch return;
    var body_buf: [256]u8 = undefined;
    const Body = struct { passphrase: []const u8 };
    const body = std.fmt.bufPrint(&body_buf, "{f}", .{std.json.fmt(Body{ .passphrase = model.passphrase() }, .{})}) catch return;
    const headers = [_]std.http.Header{
        .{ .name = "authorization", .value = model.auth() },
        .{ .name = "content-type", .value = "application/json" },
    };
    fx.fetch(.{ .key = unlock_key, .method = .POST, .url = url, .headers = &headers, .body = body, .timeout_ms = 20_000, .on_response = Effects.responseMsg(.unlock_done) });
    std.crypto.secureZero(u8, &body_buf);
}

/// Sets the pubkey from a `{"ok":true,"pubkey":".."}` setup/unlock response.
fn applyPubkey(model: *Model, body: []const u8) void {
    var buf: [512]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    const R = struct { pubkey: []const u8 = "" };
    const parsed = std.json.parseFromSliceLeaky(R, fba.allocator(), body, .{ .ignore_unknown_fields = true }) catch return;
    model.setPubkey(parsed.pubkey);
}

fn armRetry(fx: *Effects) void {
    fx.startTimer(.{
        .key = retry_timer_key,
        .interval_ms = 2_000,
        .mode = .one_shot,
        .on_fire = Effects.timerMsg(.tick),
    });
}

/// A poll came back unauthorized. In managed mode the daemon may have just
/// (re)written its token, so drop ours and re-acquire on the next tick; in
/// attached mode it is a real misconfiguration.
fn onUnauthorized(model: *Model, fx: *Effects) void {
    if (model.managed) {
        model.setAuth("");
        model.phase = .starting;
    } else {
        model.phase = .unauthorized;
    }
    armRetry(fx);
}

/// Boot command: in managed mode spawn the daemon; either way begin connecting.
pub fn boot(model: *Model, fx: *Effects) void {
    if (model.managed) {
        spawnDaemon(model, fx);
    } else {
        model.phase = .connecting;
    }
    attemptConnect(model, fx);
    // Keep the live relay status fresh while serving (the initial /info is a
    // one-shot; the pending poll doesn't carry relay state).
    fx.startTimer(.{
        .key = info_refresh_timer_key,
        .interval_ms = 3_000,
        .mode = .repeating,
        .on_fire = Effects.timerMsg(.refresh_tick),
    });
}

pub fn update(model: *Model, msg: Msg, fx: *Effects) void {
    switch (msg) {
        .daemon_line => |line| {
            // One line out of the daemon's stdout matters: the port it bound.
            // Everything else it prints is for a human reading a terminal.
            const text = std.mem.trim(u8, line.line, " \t\r\n");
            if (!std.mem.startsWith(u8, text, daemon_port_prefix)) return;
            const rest = std.mem.trim(u8, text[daemon_port_prefix.len..], " \t");
            const port = std.fmt.parseInt(u16, rest, 10) catch return;
            if (port == 0) return;
            var buf: [32]u8 = undefined;
            const host_port = std.fmt.bufPrint(&buf, "127.0.0.1:{d}", .{port}) catch return;
            model.setBaseUrl(host_port);
            model.port_known = true;
            // The daemon is listening by the time it prints this, so there is
            // no reason to wait for the retry tick.
            attemptConnect(model, fx);
        },

        .daemon_exited => |exit| {
            // A cancel we initiated (restart / app quit) reports `.cancelled`.
            // That is expected teardown, not a crash to report.
            if (exit.reason == .cancelled) return;
            model.phase = .daemon_exited;
            model.setExitNote(exit);
            model.setAuth("");
            model.clearRows();
            model.clearBunker(); // the connection URI is stale once the daemon is gone
            model.clearRelays();
            model.clearSecrets(); // don't keep a passphrase around a dead daemon
            model.clearOnboardError();
            model.submitting = false;
        },

        .token_read => |r| switch (r.outcome) {
            .ok => {
                const token = std.mem.trim(u8, r.bytes, " \t\r\n");
                if (token.len > 0) {
                    model.setAuth(token);
                    // Learn the key state from /info before doing anything else;
                    // it decides between onboarding and the approvals queue.
                    if (model.phase != .connected) model.phase = .connecting;
                    fetchInfo(model, fx);
                } else {
                    armRetry(fx); // empty file, the daemon has not written it yet
                }
            },
            // Not there yet (managed daemon still starting) or unreadable: retry.
            else => armRetry(fx),
        },

        // /info reports the daemon's key state, which selects the screen.
        .info => |r| {
            if (r.outcome == .ok and r.status == 200) {
                parseInfo(model, r.body);
                switch (model.info_state) {
                    // Serving (or an older daemon with no state field): the queue.
                    .unlocked, .unknown => {
                        model.phase = .connected;
                        pollPending(model, fx);
                    },
                    .uninitialized => model.phase = .needs_setup,
                    .locked => model.phase = .needs_unlock,
                }
            } else if (r.outcome == .ok and r.status == 401) {
                onUnauthorized(model, fx);
            } else {
                // The daemon may still be coming up; try again shortly.
                armRetry(fx);
            }
        },

        .pending => |r| switch (r.outcome) {
            .ok => switch (r.status) {
                200 => {
                    model.phase = .connected;
                    parsePending(model, r.body);
                    pollPending(model, fx); // re-arm the long-poll chain
                },
                401 => onUnauthorized(model, fx),
                else => {
                    model.phase = .disconnected;
                    armRetry(fx);
                },
            },
            // Never started (momentary duplicate key) or a transport failure:
            // fall back to a timed reconnect (which re-reads the token).
            .rejected => armRetry(fx),
            else => {
                if (model.phase == .connected) model.phase = .disconnected;
                armRetry(fx);
            },
        },

        // The poll chain reflects the removal; nothing else to do on ack.
        .decided => {},

        .tick => |t| {
            if (t.outcome != .fired) return;
            if (model.phase == .daemon_exited) return; // wait for the Restart button
            // A full reconnect attempt: re-read the token, then poll.
            attemptConnect(model, fx);
        },

        .approve => |id| {
            sendDecision(model, fx, id, true, "once");
            model.removeRow(id); // optimistic; a poll re-adds it if the send failed
        },
        .approve_day => |id| {
            sendDecision(model, fx, id, true, "day");
            model.removeRow(id);
        },
        .approve_always => |id| {
            sendDecision(model, fx, id, true, "always");
            model.removeRow(id);
        },
        .reject => |id| {
            // A denial lasts an hour: long enough that a rejected app cannot
            // pester, short enough that a misclick is not permanent.
            sendDecision(model, fx, id, false, "hour");
            model.removeRow(id);
        },

        .restart => {
            if (!model.managed) return;
            model.setAuth("");
            model.clearRows();
            model.clearSecrets();
            model.clearOnboardError();
            model.submitting = false;
            spawnDaemon(model, fx);
            attemptConnect(model, fx);
        },

        .copy_command => fx.writeClipboard(.{
            .key = command_clipboard_key,
            .text = import_command,
            .on_result = Effects.clipboardMsg(.command_copied_result),
        }),
        .command_copied_result => |result| {
            if (result.outcome != .ok) return;
            model.command_copied = true;
        },
        .reveal_backup => model.backup_showing = true,
        .cancel_backup => model.clearBackup(),
        .backup_pass_edit => |e| {
            model.backup_pass.apply(e);
            model.backup_error_len = 0;
        },
        .export_encrypted => sendExport(model, fx, false),
        .export_secret => sendExport(model, fx, true),
        .backup_done => |response| {
            model.backup_sending = false;
            if (response.outcome == .ok and response.status == 200) {
                var buf: [512]u8 = undefined;
                var fba = std.heap.FixedBufferAllocator.init(&buf);
                const Body = struct { key: []const u8 = "" };
                const parsed = std.json.parseFromSliceLeaky(Body, fba.allocator(), response.body, .{ .ignore_unknown_fields = true }) catch {
                    model.setBackupError("Could not read the answer.");
                    return;
                };
                const key = parsed.key;
                const n = @min(key.len, model.backup_key_buf.len);
                @memcpy(model.backup_key_buf[0..n], key[0..n]);
                model.backup_key_len = n;
                // The passphrase has done its job. Holding it after the answer
                // arrives buys nothing and leaves it in a window.
                model.backup_pass.set("");
                return;
            }
            model.setBackupError(if (response.status == 401)
                "That passphrase does not match."
            else
                "Could not read the key.");
        },
        .copy_backup => {
            const key = model.backup_key();
            if (key.len == 0) return;
            fx.writeClipboard(.{
                .key = clipboard_key,
                .text = key,
                .on_result = Effects.clipboardMsg(.backup_copied),
            });
        },
        .backup_copied => |result| {
            if (result.outcome != .ok) return;
            model.backup_copied = true;
        },
        .copy_bunker => {
            const uri = model.bunker();
            if (uri.len == 0) return;
            fx.writeClipboard(.{
                .key = clipboard_key,
                .text = uri,
                .on_result = Effects.clipboardMsg(.bunker_copied),
            });
        },
        .bunker_copied => |result| {
            if (result.outcome != .ok) return;
            model.copied = true;
            // Return the button to "Copy" shortly after confirming.
            fx.startTimer(.{
                .key = copy_reset_timer_key,
                .interval_ms = 1_500,
                .mode = .one_shot,
                .on_fire = Effects.timerMsg(.copy_reset),
            });
        },
        .copy_reset => |t| {
            if (t.outcome == .fired) model.copied = false;
        },

        .refresh_tick => |t| {
            if (t.outcome != .fired or !model.hasToken()) return;
            // Serving: the live relay status, on the poll that never touches the
            // phase.
            if (model.phase == .connected) {
                refreshInfo(model, fx);
                return;
            }
            // Waiting to be set up or unlocked, and this is the only thing that
            // ever notices a key arriving from somewhere else. `signer import`
            // writes the key file from a terminal and deliberately cannot reach
            // this daemon to announce it, so without asking again the window
            // sits on "First-run setup" until the app is restarted.
            //
            // Through `fetchInfo` rather than `refreshInfo`: the `.info` handler
            // is the one that picks the screen from the daemon's state, which is
            // exactly what has to happen here. Not while a passphrase is in
            // flight, because that response owns the same effect key next.
            if (model.submitting) return;
            if (model.phase == .needs_setup or model.phase == .needs_unlock)
                fetchInfo(model, fx);
        },
        .info_refresh => |r| {
            // Live-status refresh only: update relay status (and bunker); never
            // touch the phase or the pending-poll chain. Failures are ignored.
            if (r.outcome == .ok and r.status == 200) parseInfo(model, r.body);
        },

        // -- onboarding --
        .passphrase_edit => |e| model.passphrase_buf.apply(e),
        .nostrconnect_edit => |e| {
            model.nostrconnect_buf.apply(e);
            model.nostrconnect_error_len = 0;
        },
        .submit_nostrconnect => sendNostrConnect(model, fx),

        .sign_out => {
            // A restart IS the sign out. The relay threads were handed the key
            // by value when serving began, so nothing short of ending the
            // process takes it back; the daemon then comes up locked and asks
            // for the passphrase. Doing it any other way would leave a signer
            // that reports itself signed out and still signs.
            //
            // Ask the daemon to end itself and wait for the answer, rather than
            // spawning a second one over the top of it. The running daemon owns
            // the loopback port until it exits, so the new process could not
            // bind and never printed the port line the window waits for: the
            // sign out parked at "Starting the signer…" until the app was
            // restarted. `/lock` keeps the key; `/forget` is the one that
            // removes it.
            if (!model.managed) return;
            model.clearOnboardError();
            model.submitting = false;
            sendLock(model, fx);
        },
        .lock_done => |response| {
            // Whatever it answered, the daemon is on its way out or already
            // gone, so what this window knew about it is stale either way.
            _ = response;
            model.setAuth("");
            model.clearRows();
            model.clearBunker();
            model.clearRelays();
            model.clearSecrets();
            spawnDaemon(model, fx);
            attemptConnect(model, fx);
        },
        .forget_edit => |e| {
            model.forget_buf.apply(e);
            model.forget_error_len = 0;
        },
        .reveal_forget => model.forget_showing = true,
        .cancel_forget => {
            // Anything half-typed goes with it, so re-opening starts from the
            // beginning rather than one keystroke from removing the key.
            model.forget_showing = false;
            model.forget_buf.set("");
            model.forget_error_len = 0;
        },
        .submit_forget => sendForget(model, fx),
        .forget_done => |response| {
            if (response.outcome == .ok and response.status == 200) {
                // The daemon deletes the key and exits, so what follows is a
                // fresh one with nothing to serve: it will come up asking to
                // create or import.
                model.forget_buf.set("");
                model.forget_error_len = 0;
                model.setAuth("");
                model.clearRows();
                model.clearSecrets();
                spawnDaemon(model, fx);
                attemptConnect(model, fx);
                return;
            }
            const text = if (response.status == 400)
                "Type the phrase exactly to confirm."
            else
                "Could not remove the key.";
            const n = @min(text.len, model.forget_error_buf.len);
            @memcpy(model.forget_error_buf[0..n], text[0..n]);
            model.forget_error_len = n;
        },
        .nostrconnect_done => |response| {
            model.nostrconnect_sending = false;
            if (response.outcome == .ok and response.status == 200) {
                // Adopted. The field is cleared because the link is single use:
                // the client has its answer and is not waiting any more.
                model.nostrconnect_buf.set("");
                model.nostrconnect_error_len = 0;
                return;
            }
            const text = switch (response.status) {
                400 => "That does not look like a nostrconnect link.",
                409 => "Unlock your signer first.",
                502 => "Could not reach any relay that link named.",
                503 => "The signer is not serving yet.",
                else => "Could not connect to that client.",
            };
            const n = @min(text.len, model.nostrconnect_error_buf.len);
            @memcpy(model.nostrconnect_error_buf[0..n], text[0..n]);
            model.nostrconnect_error_len = n;
        },
        .secret_edit => |e| model.secret_buf.apply(e),
        .choose_create => {
            model.import_mode = false;
            model.clearOnboardError();
        },
        .choose_import => {
            model.import_mode = true;
            model.clearOnboardError();
        },
        .submit_setup => {
            if (model.submitting or model.passphrase_buf.isEmpty()) return;
            sendSetup(model, fx);
        },
        .submit_unlock => {
            if (model.submitting or model.passphrase_buf.isEmpty()) return;
            sendUnlock(model, fx);
        },
        .setup_done => |r| onOnboardResponse(model, fx, r, .setup),
        .unlock_done => |r| onOnboardResponse(model, fx, r, .unlock),
    }
}

const OnboardKind = enum { setup, unlock };

/// Applies a `/setup` or `/unlock` response. On success the key is loaded and
/// the daemon is serving, so clear the secrets and switch to the approvals
/// queue; on failure keep what the user typed and show why.
fn onOnboardResponse(model: *Model, fx: *Effects, r: native_sdk.EffectResponse, kind: OnboardKind) void {
    model.submitting = false;
    if (r.outcome == .ok and r.status == 200) {
        applyPubkey(model, r.body);
        model.clearSecrets();
        model.clearOnboardError();
        model.version = 0; // a fresh serving session; poll the queue from the start
        model.phase = .connected;
        // Pull /info so we learn the bunker:// URI to show the user; its handler
        // arms the pending-queue poll once it confirms the unlocked state.
        fetchInfo(model, fx);
        return;
    }
    if (r.outcome == .ok) switch (r.status) {
        401 => model.setOnboardError("Wrong passphrase."),
        400 => model.setOnboardError(if (kind == .setup) "Check the passphrase and key." else "Bad request."),
        // Initialized/unlocked out from under us: re-sync from /info.
        409 => fetchInfo(model, fx),
        else => model.setOnboardError("The signer rejected the request."),
    } else {
        model.setOnboardError("Could not reach the signer.");
    }
}

// -------------------------------------------------------- response parsing

/// Fills `model` from a `GET /info` body:
/// `{"state":..,"pubkey":..,"bunker":..,"relays":[{"url":..,"status":..}],"timeout_ms":..}`.
/// `state` selects the screen (onboarding vs the queue); `bunker` is the
/// connection URI shown while serving (empty until unlocked); `relays` carries
/// each relay's live status; malformed input is ignored.
pub fn parseInfo(model: *Model, body: []const u8) void {
    var buf: [8192]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    const Info = struct {
        state: []const u8 = "",
        pubkey: []const u8 = "",
        bunker: []const u8 = "",
        timeout_ms: u64 = 0,
        relays: []const struct { url: []const u8 = "", status: []const u8 = "" } = &.{},
    };
    const parsed = std.json.parseFromSliceLeaky(Info, fba.allocator(), body, .{ .ignore_unknown_fields = true }) catch return;
    model.setInfoState(parsed.state);
    model.setPubkey(parsed.pubkey);
    model.setBunker(parsed.bunker);
    model.setRelays(parsed.relays);
    model.timeout_ms = parsed.timeout_ms;
}

/// Replaces the queue from a `GET /pending` body:
/// `{"version":N,"pending":[{"id":,"method":,"kind":,"created_at":},..]}`.
/// Malformed input leaves the previous queue untouched.
pub fn parsePending(model: *Model, body: []const u8) void {
    var buf: [16 * 1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    const Pending = struct {
        version: u64 = 0,
        pending: []const struct {
            id: u64 = 0,
            method: []const u8 = "",
            kind: i32 = -1,
            created_at: i64 = 0,
            client: []const u8 = "",
            preview: []const u8 = "",
        } = &.{},
    };
    const parsed = std.json.parseFromSliceLeaky(Pending, fba.allocator(), body, .{ .ignore_unknown_fields = true }) catch return;

    model.version = parsed.version;
    var n: usize = 0;
    for (parsed.pending) |p| {
        if (n >= max_pending) break;
        var row = Row{ .id = p.id, .kind = p.kind, .created_at = p.created_at };
        row.setMethod(p.method);
        row.setClient(p.client);
        row.setPreview(p.preview);
        model.rows[n] = row;
        n += 1;
    }
    model.rows_len = n;
}

// -------------------------------------------------------------------- app

pub fn initialModel() Model {
    return .{};
}

/// Which daemon binary to supervise, or null for attached mode (connect to a
/// daemon someone else started). An explicit `SIGNER_BIN` always wins. It is
/// the development / override path, otherwise a `signer` bundled beside this
/// executable is used, so a downloaded app needs no configuration. `bundled`
/// is expected to be null or non-empty (see `bundledDaemonPath`).
pub fn chooseDaemonBin(env_bin: ?[]const u8, bundled: ?[]const u8) ?[]const u8 {
    if (env_bin) |b| {
        if (b.len > 0) return b;
    }
    return bundled;
}

/// Absolute path to a runnable `signer` sitting next to this executable, the
/// layout a packaged app has (`…/Contents/MacOS/signer` beside the GUI binary),
/// so a single download is self-contained. Returns null when there is no
/// runnable sibling (e.g. under `native dev`, where the binary lives in the
/// build cache with no daemon beside it), so the app falls back to attached
/// mode. The path is written into `buf`.
fn bundledDaemonPath(io: std.Io, buf: []u8) ?[]const u8 {
    var dir_buf: [1024]u8 = undefined;
    const dir_len = std.process.executableDirPath(io, &dir_buf) catch return null;
    const path = std.fmt.bufPrint(buf, "{s}/signer", .{dir_buf[0..dir_len]}) catch return null;
    // Only claim managed mode when the sibling is actually there and runnable;
    // otherwise the spawn would fail at boot and mask the intended attached mode.
    std.Io.Dir.accessAbsolute(io, path, .{ .execute = true }) catch return null;
    return path;
}

/// Resolves the daemon address, token-file path, and (optional) daemon binary.
/// `SIGNER_APPROVAL_HTTP` defaults to 127.0.0.1:8787; the token-file path
/// defaults to `$HOME/.zig-nostr-signer.token`. Managed mode is switched on by
/// a `signer` bundled beside the app, or an overriding `SIGNER_BIN`. The token
/// *contents* are read later through the effects channel, so a managed daemon
/// that writes the file after we launch is picked up on retry.
fn loadConfig(model: *Model, io: std.Io, environ: *const std.process.Environ.Map) void {
    const address = environ.get("SIGNER_APPROVAL_HTTP") orelse default_address;
    model.setBaseUrl(address);

    var bundled_buf: [1024]u8 = undefined;
    const bundled = bundledDaemonPath(io, &bundled_buf);
    if (chooseDaemonBin(environ.get("SIGNER_BIN"), bundled)) |bin| {
        model.setDaemonBin(bin);
        model.managed = true;
    }
    // Attached mode talks to whatever the operator pointed us at, so the
    // address above is already the answer. Managed mode waits to be told.
    model.port_known = !model.managed;

    if (environ.get("SIGNER_APPROVAL_TOKEN_FILE")) |path| {
        model.setTokenPath(path);
    } else if (environ.get("HOME")) |home| {
        var buf: [512]u8 = undefined;
        if (std.fmt.bufPrint(&buf, "{s}/{s}", .{ home, default_token_file })) |path| {
            model.setTokenPath(path);
        } else |_| {}
    }
}

pub fn main(init: std.process.Init) !void {
    const app_state = try NotaryApp.create(std.heap.page_allocator, .{
        .name = "notary",
        .scene = shell_scene,
        .canvas_label = canvas_label,
        .init_fx = boot,
        .update_fx = update,
        .markup = .{ .source = app_markup, .watch_path = "src/app.native", .io = init.io },
    });
    defer app_state.destroy();
    app_state.model = initialModel();
    loadConfig(&app_state.model, init.io, init.environ_map);

    try runner.runWithOptions(app_state.app(), .{
        .app_name = "notary",
        .window_title = "Notary",
        .bundle_id = "com.zig-nostr.notary",
        .icon_path = "assets/icon.png",
        .default_frame = geometry.RectF.init(0, 0, window_width, window_height),
        .restore_state = false,
        .js_window_api = false,
        .security = .{
            .permissions = &app_permissions,
            .navigation = .{ .allowed_origins = &.{ "zero://inline", "zero://app" } },
        },
    }, init);
}

test {
    _ = @import("tests.zig");
}
