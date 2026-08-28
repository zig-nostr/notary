//! What the key did, written down.
//!
//! Until this, nothing was. The daemon printed relay lifecycle to stderr, and
//! when the window starts it the SDK's spawn discards that stream outright, so
//! for everybody who runs this as an application there was no record anywhere
//! of a single signature. "Did something sign as me while I was away" had no
//! answer, and neither did "how did this note get published".
//!
//! One JSON object per line, appended. Line-oriented because the reader is
//! `tail -f` or `grep`, and a format that has to be closed to be valid is a
//! format that a crash leaves unreadable.
//!
//! What is NOT here is as deliberate as what is. No passphrases, no keys, no
//! plaintext, no note content. A signed event is recorded by its id, which is
//! public the moment it is published and is exactly what finds it again. A
//! cipher is recorded by peer and item count. An audit log that quotes what you
//! wrote is a second copy of your messages in a file nothing else protects.
//!
//! Best effort, always. A log that cannot be written must never stop a
//! signature: the failure mode of "audit or refuse" on a full disk is a signer
//! that will not sign, which is a worse day than a gap in a log.

const std = @import("std");

/// Where the log goes when nobody chose, under $HOME beside the key.
pub const default_file = ".zig-nostr-signer.log";

/// How large the log may get before it is rolled over to `<path>.1`.
///
/// One line is around 150 bytes and one line is one use of the key, so this is
/// years of ordinary use, and two files is a bound on the disk a signer can
/// take rather than a history worth pruning.
pub const max_bytes: u64 = 4 << 20;

/// One thing that happened. Only what is set is written, so the lines stay
/// short enough to read in a terminal.
pub const Event = struct {
    /// What happened, in one word: `sign`, `cipher`, `decision`, `unlock`,
    /// `setup`, `lock`, `forget`.
    what: []const u8,
    /// How it ended: `ok`, `refused`, `awaiting`, `locked`, `unnamed`, `bad`.
    outcome: []const u8 = "",
    /// Who asked. A pubkey in hex over a relay, a self-chosen name from an app
    /// on this machine, and `local` says which, because they are not the same
    /// kind of fact.
    who: []const u8 = "",
    local: bool = false,
    method: []const u8 = "",
    /// The event kind for a signature, or -1 where there is none.
    kind: i32 = -1,
    /// The id of what was signed. Not its content.
    id: []const u8 = "",
    /// The other side of a NIP-44 conversation, and how many items were in the
    /// batch. Not the messages.
    peer: []const u8 = "",
    count: usize = 0,
    /// How long an answer was recorded for, on a `decision`.
    remember: []const u8 = "",
};

pub const Log = struct {
    /// The directory `path` is resolved against. Held rather than assumed, the
    /// way the key gate holds its own, so a test writes into a temporary
    /// directory instead of the reader's home.
    dir: std.Io.Dir = undefined,
    /// Empty disables the log. Tests that are not about the log run this way,
    /// and so does a reader who set the path to nothing on purpose.
    path: []const u8 = "",
    lock: std.atomic.Value(bool) = .init(false),

    fn acquire(self: *Log) void {
        while (self.lock.cmpxchgWeak(false, true, .acquire, .monotonic) != null) {
            std.Thread.yield() catch {};
        }
    }
    fn release(self: *Log) void {
        self.lock.store(false, .release);
    }

    /// Appends one line. Never fails, never blocks anything real.
    pub fn note(self: *Log, io: std.Io, at: i64, event: Event) void {
        if (self.path.len == 0) return;

        var line: [640]u8 = undefined;
        var lw = std.Io.Writer.fixed(&line);
        format(&lw, at, event) catch return; // A line too long to fit is dropped, not truncated into a half-object.
        const bytes = lw.buffered();

        self.acquire();
        defer self.release();

        var file = self.dir.createFile(io, self.path, .{
            .truncate = false,
            .permissions = std.Io.File.Permissions.fromMode(0o600),
        }) catch return;
        var end: u64 = if (file.stat(io)) |st| st.size else |_| 0;

        // Rolled rather than truncated: the last four megabytes of history are
        // worth more than the first four, and losing both at once is how a log
        // that was supposed to answer a question comes up empty.
        if (end + bytes.len > max_bytes) {
            file.close(io);
            if (!self.roll(io)) {
                // The rename did not happen, so the old file is still there and
                // still full. Assuming otherwise and writing at offset zero
                // would paint this line over the START of the history, which is
                // the worst possible outcome for a log: not a gap, a forgery.
                // Better to lose this line than to corrupt the ones before it.
                return;
            }
            file = self.dir.createFile(io, self.path, .{
                .truncate = false,
                .permissions = std.Io.File.Permissions.fromMode(0o600),
            }) catch return;
            // Re-read rather than assume. The rename succeeded, but between it
            // and this open anything could have put a file back.
            end = if (file.stat(io)) |st| st.size else |_| {
                file.close(io);
                return;
            };
        }
        defer file.close(io);

        var buf: [640]u8 = undefined;
        var w = file.writer(io, &buf);
        w.seekTo(end) catch return;
        w.interface.writeAll(bytes) catch return;
        w.interface.flush() catch return;
    }

    /// Moves the full log aside, saying whether it actually happened.
    fn roll(self: *Log, io: std.Io) bool {
        var old: [1024]u8 = undefined;
        if (self.path.len + 2 > old.len) return false;
        const prev = std.fmt.bufPrint(&old, "{s}.1", .{self.path}) catch return false;
        self.dir.rename(self.path, self.dir, prev, io) catch return false;
        return true;
    }
};

/// Writes one line, including its newline.
fn format(w: *std.Io.Writer, at: i64, e: Event) !void {
    try w.print("{{\"at\":{d},\"what\":\"{s}\"", .{ at, e.what });
    if (e.outcome.len != 0) try w.print(",\"outcome\":\"{s}\"", .{e.outcome});
    // `local` stands on its own, because a local request has nobody to name:
    // the one client is whoever started this daemon. Tying it to `who` meant
    // the only line that needed the distinction was the one that lost it.
    if (e.local) try w.writeAll(",\"local\":true");
    if (e.who.len != 0) {
        if (!e.local) try w.writeAll(",\"local\":false");
        try w.writeAll(",\"who\":");
        try jsonString(w, e.who);
    }
    if (e.method.len != 0) try w.print(",\"method\":\"{s}\"", .{e.method});
    if (e.kind >= 0) try w.print(",\"kind\":{d}", .{e.kind});
    if (e.id.len != 0) try w.print(",\"id\":\"{s}\"", .{e.id});
    if (e.peer.len != 0) try w.print(",\"peer\":\"{s}\"", .{e.peer});
    if (e.count != 0) try w.print(",\"count\":{d}", .{e.count});
    if (e.remember.len != 0) try w.print(",\"remember\":\"{s}\"", .{e.remember});
    try w.writeAll("}\n");
}

/// `s` as a JSON string literal, quotes included.
///
/// Only `who` needs this, and only since apps on this machine started choosing
/// what goes in it: printable ASCII includes the quote and the backslash, so a
/// name can close the string it is written into and put whatever it likes in
/// the object around it. The queue's JSON has the same problem and its own
/// answer in `approval_http.appendJsonString`; this one writes to a stream
/// rather than an allocating list.
fn jsonString(w: *std.Io.Writer, s: []const u8) !void {
    try w.writeByte('"');
    for (s) |c| switch (c) {
        '"' => try w.writeAll("\\\""),
        '\\' => try w.writeAll("\\\\"),
        '\n' => try w.writeAll("\\n"),
        '\r' => try w.writeAll("\\r"),
        '\t' => try w.writeAll("\\t"),
        0x00...0x08, 0x0b, 0x0c, 0x0e...0x1f => try w.print("\\u{x:0>4}", .{c}),
        else => try w.writeByte(c),
    };
    try w.writeByte('"');
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn render(gpa: std.mem.Allocator, at: i64, e: Event) ![]u8 {
    var out = std.Io.Writer.Allocating.init(gpa);
    errdefer out.deinit();
    try format(&out.writer, at, e);
    return out.toOwnedSlice();
}

test "a line carries what happened and nothing it was told in confidence" {
    const gpa = testing.allocator;
    const l = try render(gpa, 1700000000, .{
        .what = "sign",
        .outcome = "ok",
        .who = "plaza",
        .local = true,
        .method = "sign_event",
        .kind = 1,
        .id = "ab" ** 32,
    });
    defer gpa.free(l);

    try testing.expect(std.mem.endsWith(u8, l, "}\n"));
    const parsed = try std.json.parseFromSlice(struct {
        at: i64,
        what: []const u8,
        outcome: []const u8,
        local: bool,
        who: []const u8,
        method: []const u8,
        kind: i32,
        id: []const u8,
    }, gpa, l, .{});
    defer parsed.deinit();
    try testing.expectEqual(@as(i64, 1700000000), parsed.value.at);
    try testing.expectEqualStrings("plaza", parsed.value.who);
    try testing.expect(parsed.value.local);
    try testing.expectEqual(@as(i32, 1), parsed.value.kind);
}

test "an app cannot name itself out of the log either" {
    // The same hole as the approval queue's JSON, in a second sink. A name is
    // printable ASCII, and printable ASCII includes the quote: a line that
    // interpolated it raw would let an app write its own fields into the
    // record of what it did, which is precisely the record it would want to
    // rewrite.
    const gpa = testing.allocator;
    const hostile = "a\",\"what\":\"nothing happened\",\"x\":\"";
    const l = try render(gpa, 1, .{ .what = "sign", .outcome = "ok", .who = hostile, .local = true });
    defer gpa.free(l);

    const parsed = try std.json.parseFromSlice(
        struct { what: []const u8, who: []const u8 },
        gpa,
        l,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();
    try testing.expectEqualStrings(hostile, parsed.value.who);
    try testing.expectEqualStrings("sign", parsed.value.what);
}

test "a field nobody set is left out rather than written empty" {
    const gpa = testing.allocator;
    const l = try render(gpa, 5, .{ .what = "lock" });
    defer gpa.free(l);
    try testing.expectEqualStrings("{\"at\":5,\"what\":\"lock\"}\n", l);
}

test "the log appends, and rolls over rather than growing without end" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var log = Log{ .dir = tmp.dir, .path = "audit.log" };
    log.note(io, 1, .{ .what = "unlock", .outcome = "ok" });
    log.note(io, 2, .{ .what = "sign", .outcome = "refused", .who = "plaza", .local = true });

    const first = try tmp.dir.readFileAlloc(io, "audit.log", gpa, .unlimited);
    defer gpa.free(first);
    // Appended, not overwritten. A log that keeps only the last thing that
    // happened answers no question worth asking.
    try testing.expectEqual(@as(usize, 2), std.mem.count(u8, first, "\n"));
    try testing.expect(std.mem.indexOf(u8, first, "\"what\":\"unlock\"") != null);
    try testing.expect(std.mem.indexOf(u8, first, "\"what\":\"sign\"") != null);

    // Only the same user may read what the key has been doing.
    const st = try tmp.dir.statFile(io, "audit.log", .{});
    try testing.expectEqual(@as(std.posix.mode_t, 0), st.permissions.toMode() & 0o077);
}

test "a full log is rolled to one side, not thrown away" {
    const io = testing.io;
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    // Already at the cap, so the next line has to make room. Written straight
    // to the file rather than by logging four megabytes a line at a time.
    const filler = try gpa.alloc(u8, max_bytes);
    defer gpa.free(filler);
    @memset(filler, 'x');
    try tmp.dir.writeFile(io, .{ .sub_path = "audit.log", .data = filler });

    var log = Log{ .dir = tmp.dir, .path = "audit.log" };
    log.note(io, 9, .{ .what = "sign", .outcome = "ok" });

    // The new line is alone in a fresh file, and the old one is beside it. An
    // audit log that truncated itself would drop the older half of the history
    // at the moment somebody most wants to read it.
    const now = try tmp.dir.readFileAlloc(io, "audit.log", gpa, .unlimited);
    defer gpa.free(now);
    try testing.expectEqualStrings("{\"at\":9,\"what\":\"sign\",\"outcome\":\"ok\"}\n", now);

    const kept = try tmp.dir.readFileAlloc(io, "audit.log.1", gpa, .unlimited);
    defer gpa.free(kept);
    try testing.expectEqual(max_bytes, kept.len);
}

test "a rollover that did not happen never writes over the history" {
    // The failure this exists for is not a gap, it is a forgery. If the rename
    // is refused and the code assumes it worked, the next line lands at offset
    // zero, on top of the OLDEST entries, and the file still parses. A reader
    // would be looking at a log whose beginning is somebody else's afternoon.
    const io = testing.io;
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const filler = try gpa.alloc(u8, max_bytes);
    defer gpa.free(filler);
    @memset(filler, 'x');
    // A recognisable head, so overwriting it is visible rather than inferred.
    @memcpy(filler[0..5], "HEAD.");
    try tmp.dir.writeFile(io, .{ .sub_path = "audit.log", .data = filler });

    // A DIRECTORY where the rolled-aside file would go. Renaming a file onto a
    // directory is refused by the OS, which is the failure without simulating
    // one.
    try tmp.dir.createDirPath(io, "audit.log.1");

    var log = Log{ .dir = tmp.dir, .path = "audit.log" };
    log.note(io, 9, .{ .what = "sign", .outcome = "ok" });

    const after = try tmp.dir.readFileAlloc(io, "audit.log", gpa, .unlimited);
    defer gpa.free(after);
    try testing.expectEqual(max_bytes, after.len);
    try testing.expectEqualStrings("HEAD.", after[0..5]);
    // And the line that could not be filed is simply absent, rather than
    // sitting where the history used to be.
    try testing.expect(std.mem.indexOf(u8, after, "\"what\":\"sign\"") == null);
}
