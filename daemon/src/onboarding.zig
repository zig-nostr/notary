//! First-run key onboarding for GUI mode.
//!
//! In GUI mode the daemon may boot without a key. This gate lets the connected
//! GUI create one, generate a fresh key, or import an existing `nsec1…`/hex,
//! or unlock an existing encrypted key file, all over the loopback approval API
//! (see `approval_http.zig`). The secret key is generated and decrypted HERE,
//! inside the key-holding daemon; only the passphrase (and, on import, the
//! secret the operator chose to type) ever crosses the API. The key itself is
//! never serialized back, the GUI only learns the derived public key.
//!
//! Once a key is available the gate publishes it to the serving path, which
//! blocks in `waitUnlocked` until then. The handoff is a single atomic flip
//! (release/acquire): the same io-model-independent idiom the broker uses,
//! so no key derivation happens on any request path.

const std = @import("std");
const nostr = @import("nostr");
const keystore = nostr.keystore;

const keys = nostr.keys;
const nip19 = nostr.nip19;
const nip49 = nostr.nip49;
const hex = nostr.hex;
const Dir = std.Io.Dir;

pub const State = enum(u8) {
    /// No key file yet, the GUI must `setup` (generate or import) one.
    uninitialized,
    /// A key file exists but is still encrypted, the GUI must `unlock` it.
    locked,
    /// The key is loaded and the daemon can serve.
    unlocked,
};

pub const SetupError = error{ AlreadyInitialized, EmptyPassphrase, InvalidSecretKey, EncryptFailed, WriteFailed };
pub const UnlockError = error{ NotLocked, BadPassphrase, ReadFailed };

/// Coordinates the key-less boot with the setup/unlock handlers. Lives in the
/// daemon's `main` frame (which never returns), so the HTTP server may hold a
/// pointer to it for the process's lifetime.
pub const Gate = struct {
    gpa: std.mem.Allocator,
    /// Directory holding the key file (the process cwd in production).
    dir: Dir,
    /// Encrypted key-file path within `dir`.
    key_file: []const u8,

    /// `State` as a plain integer for atomic access.
    state: std.atomic.Value(u8),

    // Published once, under the state flip (`.release`), and read by the serving
    // path only after it observes `.unlocked` (`.acquire`). Never leaves the
    // process.
    secret_key: [32]u8 = undefined,
    pubkey_bytes: [32]u8 = undefined,
    pubkey_hex_buf: [64]u8 = undefined,
    pubkey_len: usize = 0,

    pub fn init(gpa: std.mem.Allocator, dir: Dir, key_file: []const u8, initial: State) Gate {
        return .{
            .gpa = gpa,
            .dir = dir,
            .key_file = key_file,
            .state = std.atomic.Value(u8).init(@intFromEnum(initial)),
        };
    }

    pub fn current(self: *const Gate) State {
        return @enumFromInt(self.state.load(.acquire));
    }

    /// The derived public key (hex), valid once `current() == .unlocked`.
    pub fn pubkeyHex(self: *const Gate) []const u8 {
        return self.pubkey_hex_buf[0..self.pubkey_len];
    }

    /// The derived public key (x-only bytes), valid once `current() == .unlocked`.
    /// Used to build the `bunker://` connection URI reported on `/info`.
    pub fn pubkey(self: *const Gate) [32]u8 {
        return self.pubkey_bytes;
    }

    /// Creates the encrypted key file: imports `secret` (an `nsec1…` or 64-char
    /// hex) when it is non-empty, otherwise generates a fresh key; encrypts it
    /// with `passphrase` (NIP-49) and writes it `0600`. On success the gate is
    /// `unlocked` and holds the derived key + public key. Only valid from the
    /// `uninitialized` state.
    pub fn setup(self: *Gate, io: std.Io, passphrase: []const u8, secret: []const u8) SetupError!void {
        if (self.current() != .uninitialized) return error.AlreadyInitialized;
        if (passphrase.len == 0) return error.EmptyPassphrase;

        var signer = keys.Signer.init();
        defer signer.deinit();

        // Imported material has unknown provenance (it was typed in), so it is
        // marked known-insecure in the NIP-49 metadata; a generated key is secure.
        var security: nip49.KeySecurity = .known_secure;
        const kp = if (secret.len != 0) blk: {
            const sk = decodeSecret(self.gpa, secret) orelse return error.InvalidSecretKey;
            security = .known_insecure;
            break :blk signer.keyPairFromSecretKey(sk) catch return error.InvalidSecretKey;
        } else signer.generateKeyPair(io) catch return error.EncryptFailed;

        const ncryptsec = keystore.encryptKey(self.gpa, io, kp.secret_key, passphrase, security) catch
            return error.EncryptFailed;
        defer self.gpa.free(ncryptsec);

        keystore.writeNewKeyFile(io, self.dir, self.key_file, ncryptsec) catch |err| switch (err) {
            keystore.Error.KeyFileExists => return error.AlreadyInitialized,
            else => return error.WriteFailed,
        };

        self.publish(kp);
    }

    /// Decrypts the existing key file with `passphrase`. On success the gate is
    /// `unlocked` and holds the key + public key. Only valid from the `locked`
    /// state; a wrong passphrase leaves it `locked` for a retry.
    pub fn unlock(self: *Gate, io: std.Io, passphrase: []const u8) UnlockError!void {
        if (self.current() != .locked) return error.NotLocked;

        const ncryptsec = keystore.readKeyFile(self.gpa, io, self.dir, self.key_file) catch
            return error.ReadFailed;
        defer self.gpa.free(ncryptsec);

        const sk = keystore.decryptKey(self.gpa, ncryptsec, passphrase) catch return error.BadPassphrase;

        var signer = keys.Signer.init();
        defer signer.deinit();
        const kp = signer.keyPairFromSecretKey(sk) catch return error.BadPassphrase;
        self.publish(kp);
    }

    /// Marks the gate `unlocked` with a key loaded outside the API, used in GUI
    /// mode when the operator preconfigured a key in the environment, so the GUI
    /// skips onboarding. `kp` must already be validated.
    pub fn preload(self: *Gate, kp: keys.KeyPair) void {
        self.publish(kp);
    }

    /// Blocks the calling (serving) thread until the gate is `unlocked`, then
    /// returns the secret key. Paces with `io.sleep`, exactly like the broker's
    /// poll-wait, so it never busy-spins.
    pub fn waitUnlocked(self: *Gate, io: std.Io) [32]u8 {
        while (self.current() != .unlocked) {
            io.sleep(std.Io.Duration.fromMilliseconds(100), .awake) catch {};
        }
        return self.secret_key;
    }

    /// Removes the key file and returns to `uninitialized`, so the next boot
    /// onboards a fresh key.
    ///
    /// This is the destructive half of switching accounts, and the key file is
    /// the only copy of that identity on this Mac. Callers must have said so to
    /// the reader FIRST; nothing here can un-delete it.
    ///
    /// The in-memory key is zeroed too, but that is not the whole story and the
    /// caller has to finish it: the relay threads were handed the key by value
    /// when serving started and still hold it. Ending the process is what
    /// actually retracts it, which is why the endpoint that calls this exits.
    pub const ExportError = error{ BadPassphrase, NotInitialized, ReadFailed, OutOfMemory };

    /// The key itself, handed back to the person who owns it.
    ///
    /// `raw` chooses the form: false gives the NIP-49 `ncryptsec1…` exactly as
    /// it sits on disk, which is safe to write down because it is still behind
    /// the passphrase; true gives the `nsec1…`, which is the key in the clear.
    ///
    /// The passphrase is checked by decrypting whichever form is asked for,
    /// including the encrypted one that does not strictly need it. Being
    /// unlocked already is not enough to hand out a key: an unlocked daemon is
    /// the normal state, and whoever is at the keyboard then is not necessarily
    /// the person who set it up.
    pub fn exportKey(self: *Gate, io: std.Io, gpa: std.mem.Allocator, passphrase: []const u8, raw: bool) ExportError![]u8 {
        if (self.current() == .uninitialized) return error.NotInitialized;
        if (passphrase.len == 0) return error.BadPassphrase;

        const ncryptsec = keystore.readKeyFile(gpa, io, self.dir, self.key_file) catch return error.ReadFailed;
        defer gpa.free(ncryptsec);

        var secret = keystore.decryptKey(gpa, ncryptsec, passphrase) catch return error.BadPassphrase;
        defer std.crypto.secureZero(u8, &secret);

        if (!raw) return gpa.dupe(u8, ncryptsec) catch return error.OutOfMemory;
        return nip19.encodeNsec(gpa, secret) catch return error.OutOfMemory;
    }

    pub fn forget(self: *Gate, io: std.Io) void {
        self.dir.deleteFile(io, self.key_file) catch {};
        std.crypto.secureZero(u8, &self.secret_key);
        self.pubkey_bytes = [_]u8{0} ** 32;
        self.pubkey_len = 0;
        self.state.store(@intFromEnum(State.uninitialized), .release);
    }

    fn publish(self: *Gate, kp: keys.KeyPair) void {
        self.secret_key = kp.secret_key;
        self.pubkey_bytes = kp.public_key;
        const h = hex.encode(self.gpa, &kp.public_key) catch "";
        defer if (h.len != 0) self.gpa.free(h);
        const n = @min(h.len, self.pubkey_hex_buf.len);
        @memcpy(self.pubkey_hex_buf[0..n], h[0..n]);
        self.pubkey_len = n;
        // Release: pairs with the acquire in `current()` so a thread that sees
        // `.unlocked` also sees `secret_key`/`pubkey_hex_buf` fully written.
        self.state.store(@intFromEnum(State.unlocked), .release);
    }
};

/// Decodes a secret key from an `nsec1…` (NIP-19) or a 64-char hex string.
/// Returns null on anything that is not a well-formed 32-byte key.
fn decodeSecret(gpa: std.mem.Allocator, s: []const u8) ?[32]u8 {
    const t = std.mem.trim(u8, s, " \t\r\n");
    if (std.mem.startsWith(u8, t, "nsec1")) return nip19.decodeNsec(gpa, t) catch null;
    return hex.decodeFixed(32, t) catch null;
}

// ---------------------------------------------------------------------------
// Tests, exercise the gate end to end against a real temp dir: generate,
// import (nsec + hex), reject bad input, unlock a locked file, and prove the
// state machine's rails (no double-init, wrong passphrase stays locked).
// ---------------------------------------------------------------------------

const testing = std.testing;
const key_name = "k.ncryptsec";

test "setup generates a key, writes it 0600, and unlocks" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var gate = Gate.init(gpa, tmp.dir, key_name, .uninitialized);
    try gate.setup(io, "correct horse battery staple", "");
    try testing.expectEqual(State.unlocked, gate.current());
    try testing.expectEqual(@as(usize, 64), gate.pubkeyHex().len);

    // The file is a real 0600 ncryptsec that decrypts back to the gate's key.
    const st = try tmp.dir.statFile(io, key_name, .{});
    try testing.expectEqual(@as(std.posix.mode_t, 0), st.permissions.toMode() & 0o077);
    const ncryptsec = try keystore.readKeyFile(gpa, io, tmp.dir, key_name);
    defer gpa.free(ncryptsec);
    const sk = try keystore.decryptKey(gpa, ncryptsec, "correct horse battery staple");
    try testing.expectEqualSlices(u8, &gate.secret_key, &sk);
}

test "setup imports an existing nsec and round-trips to the same key" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const secret = [_]u8{0x11} ** 32;
    const nsec = try nip19.encodeNsec(gpa, secret);
    defer gpa.free(nsec);

    var gate = Gate.init(gpa, tmp.dir, key_name, .uninitialized);
    try gate.setup(io, "pw", nsec);
    try testing.expectEqualSlices(u8, &secret, &gate.secret_key);
}

test "setup accepts a 64-char hex secret" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var gate = Gate.init(gpa, tmp.dir, key_name, .uninitialized);
    try gate.setup(io, "pw", "b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef");
    const expect = try hex.decodeFixed(32, "b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef");
    try testing.expectEqualSlices(u8, &expect, &gate.secret_key);
}

test "setup rejects an empty passphrase and an invalid secret, and refuses a second init" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var gate = Gate.init(gpa, tmp.dir, key_name, .uninitialized);
    try testing.expectError(error.EmptyPassphrase, gate.setup(io, "", ""));
    try testing.expectError(error.InvalidSecretKey, gate.setup(io, "pw", "not-a-key"));
    try testing.expectEqual(State.uninitialized, gate.current()); // failures don't advance

    try gate.setup(io, "pw", ""); // now succeeds
    try testing.expectError(error.AlreadyInitialized, gate.setup(io, "pw", ""));
}

test "unlock decrypts a locked file and rejects a wrong passphrase" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    // Create a key with one gate, then unlock it with a fresh (locked) gate.
    var creator = Gate.init(gpa, tmp.dir, key_name, .uninitialized);
    try creator.setup(io, "hunter2", "");
    const created_key = creator.secret_key;

    var gate = Gate.init(gpa, tmp.dir, key_name, .locked);
    try testing.expectError(error.BadPassphrase, gate.unlock(io, "wrong"));
    try testing.expectEqual(State.locked, gate.current()); // wrong passphrase → retry
    try gate.unlock(io, "hunter2");
    try testing.expectEqual(State.unlocked, gate.current());
    try testing.expectEqualSlices(u8, &created_key, &gate.secret_key);
}
