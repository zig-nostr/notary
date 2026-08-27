const std = @import("std");
const native_sdk = @import("native_sdk");
const main = @import("main.zig");

const canvas = native_sdk.canvas;
const testing = std.testing;

const AppUi = main.AppUi;
const Model = main.Model;
const Msg = main.Msg;

const AppMarkup = canvas.MarkupView(Model, Msg);

fn buildTree(arena: std.mem.Allocator, model: *const Model) !AppUi.Tree {
    var view = try AppMarkup.init(arena, main.app_markup);
    var ui = AppUi.init(arena);
    const node = view.build(&ui, model) catch |err| {
        // Name the app.native position instead of leaving a bare error
        // trace: the usual causes are a binding without a matching Model
        // field/method or an on-* message without a Msg arm.
        if (err == error.MarkupBuild) {
            std.debug.print("app.native:{d}:{d}: {s}\n", .{ view.diagnostic.line, view.diagnostic.column, view.diagnostic.message });
        }
        return err;
    };
    return ui.finalize(node);
}

fn findByText(widget: canvas.Widget, kind: canvas.WidgetKind, text: []const u8) ?canvas.Widget {
    if (widget.kind == kind and std.mem.eql(u8, widget.text, text)) return widget;
    for (widget.children) |child| {
        if (findByText(child, kind, text)) |found| return found;
    }
    return null;
}

/// A miss fails the test with the mismatch spelled out instead of a
/// null-unwrap panic: the usual cause is app.native and this test drifting
/// apart after an edit.
fn expectByText(widget: canvas.Widget, kind: canvas.WidgetKind, text: []const u8) !canvas.Widget {
    return findByText(widget, kind, text) orelse {
        std.debug.print("no {t} with text \"{s}\" in the view - if you changed app.native, update this test to match\n", .{ kind, text });
        return error.WidgetNotFound;
    };
}

/// The same lookup for an icon-only control, which carries no text: its
/// accessible label is the only name it has.
fn findByLabel(widget: canvas.Widget, kind: canvas.WidgetKind, label: []const u8) ?canvas.Widget {
    if (widget.kind == kind and std.mem.eql(u8, widget.semantics.label, label)) return widget;
    for (widget.children) |child| {
        if (findByLabel(child, kind, label)) |found| return found;
    }
    return null;
}

fn expectByLabel(widget: canvas.Widget, kind: canvas.WidgetKind, label: []const u8) !canvas.Widget {
    return findByLabel(widget, kind, label) orelse {
        std.debug.print("no {t} labelled \"{s}\" in the view - if you changed app.native, update this test to match\n", .{ kind, label });
        return error.WidgetNotFound;
    };
}

// ------------------------------------------------------------- parsing

test "a window looks for a daemon before starting one" {
    // The daemon is shared. It outlives the window that spawned it (only
    // `/lock` ends it), another app on this machine may have started it, and
    // the reader may have opened that app first. A window that spawned
    // unconditionally would put a second daemon on a port the first holds
    // exclusively: the loser exits, and this window waits for something that is
    // never coming while a perfectly good daemon is already serving.

    // Nothing is answering and this window has started nothing: its turn.
    try testing.expect(main.shouldStartDaemonForTest(true, false, .connecting));
    try testing.expect(main.shouldStartDaemonForTest(true, false, .disconnected));

    // Something IS answering. Attaching to a daemon somebody else started is
    // the ordinary case, not a fallback.
    try testing.expect(!main.shouldStartDaemonForTest(true, false, .connected));

    // Already started one. A second races the first onto a port held
    // exclusively, and the loser exits.
    try testing.expect(!main.shouldStartDaemonForTest(true, true, .connecting));

    // Attached mode was pointed at somebody else's daemon on purpose.
    try testing.expect(!main.shouldStartDaemonForTest(false, false, .connecting));
    try testing.expect(!main.shouldStartDaemonForTest(false, false, .disconnected));
}

test "parseInfo fills the header fields" {
    var m = Model{};
    main.parseInfo(&m, "{\"pubkey\":\"aabbccddeeff00112233\",\"timeout_ms\":120000}");
    try testing.expectEqualStrings("aabbccddeeff00112233", m.pubkey_buf[0..m.pubkey_len]);
    try testing.expectEqual(@as(u64, 120000), m.timeout_ms);
}

test "parseInfo reads the bunker URI and show_bunker gates on serving" {
    var m = Model{};
    main.parseInfo(&m, "{\"state\":\"unlocked\",\"pubkey\":\"aabb\",\"bunker\":\"bunker://aabb?relay=wss%3A%2F%2Fr.example\",\"timeout_ms\":0}");
    try testing.expectEqualStrings("bunker://aabb?relay=wss%3A%2F%2Fr.example", m.bunker());

    // The connection card shows only while serving (phase == .connected).
    try testing.expect(!m.show_bunker());
    m.phase = .connected;
    try testing.expect(m.show_bunker());

    // A still-locked daemon reports no URI, so there is nothing to show or copy.
    var locked = Model{};
    locked.phase = .connected;
    main.parseInfo(&locked, "{\"state\":\"locked\"}");
    try testing.expectEqualStrings("", locked.bunker());
    try testing.expect(!locked.show_bunker());
}

test "the copy confirmation resets only when the bunker URI changes" {
    var m = Model{};
    const same = "{\"state\":\"unlocked\",\"bunker\":\"bunker://aabb?relay=wss%3A%2F%2Fr.example\"}";
    main.parseInfo(&m, same);

    m.copied = true;
    main.parseInfo(&m, same); // an unchanged URI keeps the "Copied!" confirmation
    try testing.expect(m.copied);
    try testing.expectEqualStrings("Copied!", m.copy_label());

    main.parseInfo(&m, "{\"state\":\"unlocked\",\"bunker\":\"bunker://cccc?relay=wss%3A%2F%2Fr.example\"}");
    try testing.expect(!m.copied); // a changed URI clears the stale confirmation
    try testing.expectEqualStrings("Copy", m.copy_label());
}

test "parseInfo reads the relay list with per-relay status" {
    var m = Model{};
    m.phase = .connected;
    main.parseInfo(&m, "{\"state\":\"unlocked\",\"relays\":[" ++
        "{\"url\":\"wss://a.example\",\"status\":\"connected\"}," ++
        "{\"url\":\"wss://b.example\",\"status\":\"connecting\"}," ++
        "{\"url\":\"wss://c.example\",\"status\":\"disconnected\"}]}");

    const list = m.relay_list(testing.allocator); // arena arg is unused
    try testing.expectEqual(@as(usize, 3), list.len);
    try testing.expectEqualStrings("wss://a.example", list[0].url());
    try testing.expectEqual(main.RelayConn.connected, list[0].conn);
    try testing.expectEqualStrings("connected", list[0].status_label());
    try testing.expect(list[0].connected());
    try testing.expectEqual(main.RelayConn.connecting, list[1].conn);
    try testing.expect(list[1].connecting());
    try testing.expectEqual(main.RelayConn.disconnected, list[2].conn);
    try testing.expect(list[2].offline());

    // Listed only while serving.
    try testing.expect(m.show_relays());
    m.phase = .starting;
    try testing.expect(!m.show_relays());
}

test "parsePending loads the queue with kinds and formatted labels" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var m = Model{};
    const body =
        \\{"version":7,"pending":[
        \\  {"id":1,"method":"sign_event","kind":1,"created_at":100},
        \\  {"id":2,"method":"get_public_key","kind":-1,"created_at":200}
        \\]}
    ;
    main.parsePending(&m, body);

    try testing.expectEqual(@as(u64, 7), m.version);
    try testing.expectEqual(@as(usize, 2), m.rows_len);
    try testing.expectEqual(@as(u64, 1), m.rows[0].id);
    try testing.expectEqualStrings("sign_event", m.rows[0].method());
    try testing.expectEqual(@as(i32, 1), m.rows[0].kind);
    try testing.expectEqualStrings("sign_event · kind 1", m.rows[0].label(arena));
    try testing.expectEqualStrings("get_public_key", m.rows[1].label(arena));
}

test "parsePending on an empty queue clears the rows" {
    var m = Model{};
    // Seed a row, then parse an empty queue: it must clear.
    main.parsePending(&m, "{\"version\":1,\"pending\":[{\"id\":9,\"method\":\"ping\",\"kind\":-1,\"created_at\":0}]}");
    try testing.expectEqual(@as(usize, 1), m.rows_len);

    main.parsePending(&m, "{\"version\":3,\"pending\":[]}");
    try testing.expectEqual(@as(usize, 0), m.rows_len);
    try testing.expectEqual(@as(u64, 3), m.version);
}

test "parsePending ignores malformed input, keeping the previous queue" {
    var m = Model{};
    main.parsePending(&m, "{\"version\":2,\"pending\":[{\"id\":5,\"method\":\"sign_event\",\"kind\":4,\"created_at\":0}]}");
    main.parsePending(&m, "not json at all");
    try testing.expectEqual(@as(usize, 1), m.rows_len);
    try testing.expectEqual(@as(u64, 5), m.rows[0].id);
}

test "removeRow drops the matching id and shifts the rest down" {
    var m = Model{};
    main.parsePending(&m,
        \\{"version":1,"pending":[
        \\  {"id":1,"method":"a","kind":-1,"created_at":0},
        \\  {"id":2,"method":"b","kind":-1,"created_at":0},
        \\  {"id":3,"method":"c","kind":-1,"created_at":0}
        \\]}
    );
    m.removeRow(2);
    try testing.expectEqual(@as(usize, 2), m.rows_len);
    try testing.expectEqual(@as(u64, 1), m.rows[0].id);
    try testing.expectEqual(@as(u64, 3), m.rows[1].id);

    m.removeRow(999); // unknown id is a no-op
    try testing.expectEqual(@as(usize, 2), m.rows_len);
}

// ---------------------------------------------------------------- view

test "the empty view shows the connection status and a zero count" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();

    var model = main.initialModel(); // .connecting, empty queue
    const tree = try buildTree(arena_state.allocator(), &model);

    // ONE status line, and it is the status bar. The header block that used to
    // repeat the app's name above the phase above the key is gone: four lines
    // of chrome in a small window, three of them saying nothing after the first
    // second, and the name was already in the title bar.
    _ = try expectByText(tree.root, .status_bar, "Connecting to the signer…");
    try testing.expect(findByText(tree.root, .text, "Notary") == null);
}

test "an approval row says who is asking and what would be signed" {
    // A row that reads "sign_event · kind 1" and nothing else asks somebody to
    // authorize a signature without telling them whose request it is or what it
    // says. It looks identical whether it came from their own client or from
    // anyone else who reached the signer, and telling those apart is the only
    // reason a human is in this loop at all.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();

    var model = Model{};
    model.phase = .connected;
    main.parsePending(&model,
        \\{"version":1,"pending":[{"id":7,"method":"sign_event","kind":1,"created_at":0,
        \\"client":"ab12cd34ef56ab78cd90ef12ab34cd56ef78ab90cd12ef34ab56cd78ef90ab12",
        \\"preview":"gm from a stranger"}]}
    );

    const tree = try buildTree(arena_state.allocator(), &model);
    _ = try expectByText(tree.root, .text, "from ab12cd34…ef90ab12");
    _ = try expectByText(tree.root, .text, "gm from a stranger");

    // A method with nothing to preview does not draw an empty line.
    var quiet = Model{};
    quiet.phase = .connected;
    main.parsePending(&quiet,
        \\{"version":1,"pending":[{"id":8,"method":"get_public_key","kind":-1,"created_at":0,
        \\"client":"ab12cd34ef56ab78cd90ef12ab34cd56ef78ab90cd12ef34ab56cd78ef90ab12","preview":""}]}
    );
    const quiet_tree = try buildTree(arena_state.allocator(), &quiet);
    _ = try expectByText(quiet_tree.root, .text, "from ab12cd34…ef90ab12");
    try testing.expect(!quiet.rows[0].has_preview());

    // A daemon that sent no client at all must not print a misleading identity.
    var old = Model{};
    old.phase = .connected;
    main.parsePending(&old, "{\"version\":1,\"pending\":[{\"id\":9,\"method\":\"sign_event\",\"kind\":1,\"created_at\":0}]}");
    const old_tree = try buildTree(arena_state.allocator(), &old);
    _ = try expectByText(old_tree.root, .text, "unknown client");
}

test "a populated view renders rows and dispatches typed approve/deny" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();

    var model = Model{};
    model.phase = .connected;
    main.parsePending(&model, "{\"version\":1,\"pending\":[{\"id\":42,\"method\":\"sign_event\",\"kind\":1,\"created_at\":0}]}");

    const tree = try buildTree(arena_state.allocator(), &model);

    _ = try expectByText(tree.root, .text, "sign_event · kind 1");
    _ = try expectByText(tree.root, .status_bar, "1 pending");

    // Every answer carries the row id in its typed message, and each duration
    // is its own press: no second screen between wanting to allow for a day
    // and having done it.
    const once = try expectByText(tree.root, .button, "Allow once");
    switch (tree.msgForPointer(once.id, .up).?) {
        .approve => |id| try testing.expectEqual(@as(u64, 42), id),
        else => return error.WrongMessage,
    }

    const day = try expectByText(tree.root, .button, "For a day");
    switch (tree.msgForPointer(day.id, .up).?) {
        .approve_day => |id| try testing.expectEqual(@as(u64, 42), id),
        else => return error.WrongMessage,
    }

    const always = try expectByText(tree.root, .button, "Always");
    switch (tree.msgForPointer(always.id, .up).?) {
        .approve_always => |id| try testing.expectEqual(@as(u64, 42), id),
        else => return error.WrongMessage,
    }

    const deny = try expectByText(tree.root, .button, "Deny");
    switch (tree.msgForPointer(deny.id, .up).?) {
        .reject => |id| try testing.expectEqual(@as(u64, 42), id),
        else => return error.WrongMessage,
    }
}

// ------------------------------------------------------- supervision

test "chooseDaemonBin prefers SIGNER_BIN, then a bundled sibling, else attached" {
    // An explicit SIGNER_BIN overrides a bundled sibling (the dev path).
    try testing.expectEqualStrings("/env/signer", main.chooseDaemonBin("/env/signer", "/bundle/signer").?);
    // An empty SIGNER_BIN is treated as unset and falls through to the bundle.
    try testing.expectEqualStrings("/bundle/signer", main.chooseDaemonBin("", "/bundle/signer").?);
    // No override: the bundled sibling is supervised (the single-download path).
    try testing.expectEqualStrings("/bundle/signer", main.chooseDaemonBin(null, "/bundle/signer").?);
    // Neither present: attached mode (connect to a daemon someone else started).
    try testing.expect(main.chooseDaemonBin(null, null) == null);
    try testing.expect(main.chooseDaemonBin("", null) == null);
}

test "the phase and row count pick exactly one body state" {
    var m = Model{};

    m.phase = .connected;
    try testing.expect(m.show_empty());
    try testing.expect(!m.show_queue());
    try testing.expect(!m.daemon_down());

    m.rows_len = 1;
    try testing.expect(!m.show_empty());
    try testing.expect(m.show_queue());
    try testing.expect(!m.daemon_down());

    m.phase = .daemon_exited;
    try testing.expect(m.daemon_down());
    try testing.expect(!m.show_empty());
    try testing.expect(!m.show_queue());
}

test "setAuth builds and clears the bearer header" {
    var m = Model{};
    try testing.expect(!m.hasToken());
    m.setAuth("deadbeef");
    try testing.expect(m.hasToken());
    try testing.expectEqualStrings("Bearer deadbeef", m.auth());
    m.setAuth("");
    try testing.expect(!m.hasToken());
    try testing.expectEqual(@as(usize, 0), m.auth().len);
}

test "the daemon-stopped view offers a restart" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();

    var model = Model{};
    model.phase = .daemon_exited; // as set when the daemon child exits
    const tree = try buildTree(arena_state.allocator(), &model);

    _ = try expectByText(tree.root, .status_bar, "Signer stopped");
    _ = try expectByText(tree.root, .text, "The signer process stopped.");

    const restart = try expectByText(tree.root, .button, "Restart signer");
    switch (tree.msgForPointer(restart.id, .up).?) {
        .restart => {},
        else => return error.WrongMessage,
    }
}

// ------------------------------------------------------- onboarding

test "parseInfo reads the daemon key state" {
    var m = Model{};
    main.parseInfo(&m, "{\"state\":\"uninitialized\",\"pubkey\":\"\",\"timeout_ms\":0}");
    try testing.expectEqual(main.InfoState.uninitialized, m.info_state);

    main.parseInfo(&m, "{\"state\":\"locked\"}");
    try testing.expectEqual(main.InfoState.locked, m.info_state);

    main.parseInfo(&m, "{\"state\":\"unlocked\",\"pubkey\":\"aabb\",\"timeout_ms\":120000}");
    try testing.expectEqual(main.InfoState.unlocked, m.info_state);
    try testing.expectEqualStrings("aabb", m.pubkey_buf[0..m.pubkey_len]);
}

test "the setup and unlock phases each select their own exclusive body" {
    var m = Model{};

    m.phase = .needs_setup;
    try testing.expect(m.needs_setup());
    try testing.expect(!m.needs_unlock());
    try testing.expect(!m.daemon_down());
    try testing.expect(!m.show_empty());
    try testing.expect(!m.show_queue());

    m.phase = .needs_unlock;
    try testing.expect(m.needs_unlock());
    try testing.expect(!m.needs_setup());
    try testing.expect(!m.show_empty());
    try testing.expect(!m.show_queue());
}

test "submit is disabled until a passphrase is typed, and while in flight" {
    var m = Model{};
    m.phase = .needs_unlock;
    try testing.expect(m.submit_disabled()); // empty passphrase

    m.passphrase_buf.apply(.{ .insert_text = "hunter2" });
    try testing.expectEqualStrings("hunter2", m.passphrase());
    try testing.expect(!m.submit_disabled());

    m.submitting = true; // a request in flight re-disables it
    try testing.expect(m.submit_disabled());
}

test "the passphrase field draws stars, and the daemon still gets the passphrase" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();

    var model = Model{};
    model.phase = .needs_unlock;
    model.passphrase_buf.apply(.{ .insert_text = "hunter2" });

    const tree = try buildTree(arena_state.allocator(), &model);

    // The characters are not on the glass anywhere in the view: not in the
    // field, not in a stray label built from the same binding.
    try testing.expect(findByText(tree.root, .text_field, "hunter2") == null);
    _ = try expectByText(tree.root, .text_field, "*******");

    // What gets sent is untouched. This is the half that would break silently
    // if the mask were ever applied to the buffer instead of to the drawing.
    try testing.expectEqualStrings("hunter2", model.passphrase());
}

test "the reveal toggle shows the characters, and starts off" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();

    var model = Model{};
    model.phase = .needs_unlock;
    model.passphrase_buf.apply(.{ .insert_text = "hunter2" });

    // A fresh model hides. Nothing has to be pressed to get there.
    try testing.expect(!model.passphrase_showing);
    try testing.expectEqualStrings("*******", model.shown_passphrase());
    try testing.expectEqualStrings("Show the passphrase", model.passphrase_toggle_label());

    const hidden = try buildTree(arena_state.allocator(), &model);
    const eye = try expectByLabel(hidden.root, .toggle_button, "Show the passphrase");
    switch (hidden.msgForPointer(eye.id, .up).?) {
        .toggle_passphrase => {},
        else => return error.WrongMessage,
    }

    model.passphrase_showing = true;
    try testing.expectEqualStrings("hunter2", model.shown_passphrase());
    try testing.expectEqualStrings("Hide the passphrase", model.passphrase_toggle_label());

    const shown = try buildTree(arena_state.allocator(), &model);
    _ = try expectByText(shown.root, .text_field, "hunter2");
}

test "the mask is exactly as long as what it covers" {
    // Not cosmetic. The runtime stamps caret and selection offsets into the
    // string it DREW, and those offsets are replayed onto the buffer holding
    // the real text. They only line up while the two are the same length, so a
    // three-byte bullet in place of the star would put every click on the wrong
    // character. Multibyte input is the case that proves the rule.
    var m = Model{};
    m.passphrase_buf.apply(.{ .insert_text = "hüntér2" });
    try testing.expectEqual(m.passphrase().len, m.shown_passphrase().len);

    m.backup_pass.apply(.{ .insert_text = "hüntér2" });
    try testing.expectEqual(m.backup_passphrase().len, m.shown_backup_passphrase().len);
}

test "typing into a hidden field leaves the caret where the field draws it" {
    // The runtime edits its OWN copy of what it drew. Once that copy is stars
    // and this one is characters, an insert makes them disagree and the runtime
    // puts the drawn caret back at the end of the line. If this buffer kept its
    // own idea of where it was, the next keystroke would land somewhere the
    // reader is not looking - and with every character a star, the only symptom
    // would be the daemon refusing a passphrase they typed correctly.
    var m = Model{};
    m.passphrase_buf.apply(.{ .insert_text = "abcdef" });
    m.passphrase_buf.apply(.{ .set_selection = .{ .anchor = 3, .focus = 3 } });

    main.update(&m, Msg{ .passphrase_edit = .{ .insert_text = "Z" } }, undefined);
    try testing.expectEqualStrings("abcZdef", m.passphrase());
    try testing.expectEqual(@as(usize, 7), m.passphrase_buf.selection.focus);
    try testing.expectEqual(@as(usize, 7), m.passphrase_buf.selection.anchor);

    // Revealed, the drawn text IS this text, so the runtime keeps the caret and
    // this buffer must keep it too: ordinary mid-string editing comes back.
    m.passphrase_showing = true;
    m.passphrase_buf.apply(.{ .set_selection = .{ .anchor = 3, .focus = 3 } });
    main.update(&m, Msg{ .passphrase_edit = .{ .insert_text = "Y" } }, undefined);
    try testing.expectEqualStrings("abcYZdef", m.passphrase());
    try testing.expectEqual(@as(usize, 4), m.passphrase_buf.selection.focus);

    // Deleting never re-seeds: both sides lose one glyph, so the caret stays.
    m.passphrase_showing = false;
    m.passphrase_buf.apply(.{ .set_selection = .{ .anchor = 3, .focus = 3 } });
    main.update(&m, Msg{ .passphrase_edit = .delete_backward }, undefined);
    try testing.expectEqualStrings("abYZdef", m.passphrase());
    try testing.expectEqual(@as(usize, 2), m.passphrase_buf.selection.focus);
}

test "a revealed passphrase does not survive the send, or the panel closing" {
    var m = Model{};
    m.passphrase_buf.apply(.{ .insert_text = "hunter2" });
    m.passphrase_showing = true;
    m.clearSecrets();
    try testing.expect(!m.passphrase_showing);
    try testing.expectEqualStrings("", m.shown_passphrase());

    m.backup_pass.apply(.{ .insert_text = "hunter2" });
    m.backup_pass_showing = true;
    m.clearBackup();
    try testing.expect(!m.backup_pass_showing);
    try testing.expectEqualStrings("", m.shown_backup_passphrase());
}

test "the backup panel hides its passphrase too" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();

    var model = Model{};
    model.phase = .connected;
    // The panel lives inside the serving view, so give the model a bunker URI
    // to be serving with.
    main.parseInfo(&model, "{\"state\":\"unlocked\",\"bunker\":\"bunker://aabb?relay=wss%3A%2F%2Fr.example\"}");
    model.backup_showing = true;
    model.backup_pass.apply(.{ .insert_text = "hunter2" });

    const tree = try buildTree(arena_state.allocator(), &model);
    try testing.expect(findByText(tree.root, .text_field, "hunter2") == null);
    _ = try expectByText(tree.root, .text_field, "*******");

    const eye = try expectByLabel(tree.root, .toggle_button, "Show the passphrase");
    switch (tree.msgForPointer(eye.id, .up).?) {
        .toggle_backup_passphrase => {},
        else => return error.WrongMessage,
    }
    try testing.expectEqualStrings("hunter2", model.backup_passphrase());
}

test "the setup screen renders create/import and dispatches submit_setup" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();

    var model = Model{};
    model.phase = .needs_setup;
    model.passphrase_buf.apply(.{ .insert_text = "pw" }); // enables the submit button

    const tree = try buildTree(arena_state.allocator(), &model);

    _ = try expectByText(tree.root, .text, "Set up your signer");

    const create = try expectByText(tree.root, .toggle_button, "Create new");
    switch (tree.msgForPointer(create.id, .up).?) {
        .choose_create => {},
        else => return error.WrongMessage,
    }
    const import = try expectByText(tree.root, .toggle_button, "Import existing");
    switch (tree.msgForPointer(import.id, .up).?) {
        .choose_import => {},
        else => return error.WrongMessage,
    }
    // The primary button submits setup; its label reflects create mode.
    const submit = try expectByText(tree.root, .button, "Create key");
    switch (tree.msgForPointer(submit.id, .up).?) {
        .submit_setup => {},
        else => return error.WrongMessage,
    }
}

test "the unlock screen renders and dispatches submit_unlock" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();

    var model = Model{};
    model.phase = .needs_unlock;
    model.passphrase_buf.apply(.{ .insert_text = "pw" });

    const tree = try buildTree(arena_state.allocator(), &model);

    _ = try expectByText(tree.root, .text, "Unlock your signer");
    const submit = try expectByText(tree.root, .button, "Unlock");
    switch (tree.msgForPointer(submit.id, .up).?) {
        .submit_unlock => {},
        else => return error.WrongMessage,
    }
}

test "a refused nostrconnect link says which thing went wrong" {
    var m = main.Model{};
    // Nothing typed: the button is inert rather than sending an empty link.
    try testing.expect(m.nostrconnect_disabled());
    try testing.expect(!m.has_nostrconnect_error());

    m.nostrconnect_buf.set("nostrconnect://abc?relay=wss%3A%2F%2Fr.example&secret=s");
    try testing.expect(!m.nostrconnect_disabled());

    // Each status the daemon can answer with maps to a sentence a person can
    // act on. "Could not connect" for all of them would be true and useless:
    // locking, a bad link and an unreachable relay need different things done.
    const cases = [_]struct { status: u16, needle: []const u8 }{
        .{ .status = 400, .needle = "nostrconnect link" },
        .{ .status = 409, .needle = "Unlock" },
        .{ .status = 502, .needle = "relay" },
        .{ .status = 503, .needle = "not serving" },
    };
    for (cases) |c| {
        m.nostrconnect_sending = true;
        main.update(&m, main.Msg{ .nostrconnect_done = .{ .key = 11, .outcome = .ok, .status = c.status, .body = "" } }, undefined);
        try testing.expect(!m.nostrconnect_sending);
        try testing.expect(m.has_nostrconnect_error());
        try testing.expect(std.mem.indexOf(u8, m.nostrconnect_error(), c.needle) != null);
    }

    // And success clears the field, because the link is single use: the client
    // has its answer and is not waiting any more.
    m.nostrconnect_sending = true;
    main.update(&m, main.Msg{ .nostrconnect_done = .{ .key = 11, .outcome = .ok, .status = 200, .body = "" } }, undefined);
    try testing.expect(!m.has_nostrconnect_error());
    try testing.expectEqualStrings("", m.nostrconnect());
}

test "the destructive key removal is inert until the phrase matches exactly" {
    var m = main.Model{};
    // Disabled by default, so the press that removes somebody's only copy of an
    // identity on this Mac cannot be a mis-click.
    try testing.expect(m.forget_disabled());

    m.forget_buf.set("yes");
    try testing.expect(m.forget_disabled());
    m.forget_buf.set("Delete my key");
    try testing.expect(m.forget_disabled());
    m.forget_buf.set("delete my key ");
    try testing.expect(m.forget_disabled());

    m.forget_buf.set("delete my key");
    try testing.expect(!m.forget_disabled());

    // A refusal from the daemon is reported rather than swallowed.
    main.update(&m, main.Msg{ .forget_done = .{ .key = 12, .outcome = .ok, .status = 400, .body = "" } }, undefined);
    try testing.expect(m.has_forget_error());
}

test "the way out of a key is folded away until it is asked for" {
    // The opening screen used to lead with a box telling the reader to type
    // "delete my key", which is a strange first thing to show somebody who
    // only wants to unlock their signer.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();

    var model = main.initialModel();
    model.phase = .needs_unlock;

    {
        const tree = try buildTree(arena_state.allocator(), &model);
        // One red button, and none of the machinery behind it.
        const opener = try expectByText(tree.root, .button, "Use another key");
        switch (tree.msgForPointer(opener.id, .up).?) {
            .reveal_forget => {},
            else => return error.WrongMessage,
        }
        try testing.expect(findByText(tree.root, .button, "Remove this key") == null);
    }

    // Asked for: the warning, the phrase to type, and a way back out.
    model.forget_showing = true;
    {
        const tree = try buildTree(arena_state.allocator(), &model);
        _ = try expectByText(tree.root, .button, "Remove this key");
        const cancel = try expectByText(tree.root, .button, "Cancel");
        switch (tree.msgForPointer(cancel.id, .up).?) {
            .cancel_forget => {},
            else => return error.WrongMessage,
        }
    }

    // The button stays inert until the phrase is exact, revealed or not:
    // folding it away is the first of two guards, not a replacement for one.
    try testing.expect(model.forget_disabled());
    model.forget_buf.set("delete my key");
    try testing.expect(!model.forget_disabled());
}

test "the terminal path is offered beside the paste field, not instead of it" {
    // The nsec goes through this window and the clipboard when it is pasted
    // here. The terminal takes it without either, so the command is offered
    // rather than hidden, exactly as Plaza's own key window offers it.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();

    var model = main.initialModel();
    model.phase = .needs_setup;

    // Creating a key has nothing to bring in, so the card stays away.
    model.import_mode = false;
    {
        const tree = try buildTree(arena_state.allocator(), &model);
        try testing.expect(findByText(tree.root, .button, "Copy") == null);
    }

    model.import_mode = true;
    {
        const tree = try buildTree(arena_state.allocator(), &model);
        const copy = try expectByText(tree.root, .button, "Copy");
        switch (tree.msgForPointer(copy.id, .up).?) {
            .copy_command => {},
            else => return error.WrongMessage,
        }
        // The command names the INSTALLED binary. A path derived from argv[0]
        // would be right in development and wrong for everybody else.
        _ = try expectByText(tree.root, .text, "/Applications/Notary.app/Contents/MacOS/signer import");
        // And it says to reopen, because the import writes the key for the next
        // launch rather than handing it to a daemon it cannot reach.
        _ = try expectByText(tree.root, .text, "Run it, then reopen Notary to pick the key up.");
    }
}

test "one status line, and it says the phase before there is a queue to count" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Onboarding: the phase is the whole story, and there is no queue.
    var m = Model{};
    m.phase = .needs_unlock;
    try testing.expectEqualStrings("Locked", m.footer(arena));

    // Serving: the key and the count, on one line rather than three.
    m.phase = .connected;
    main.parseInfo(&m, "{\"state\":\"unlocked\",\"pubkey\":\"aabbccddeeff00112233445566778899\"}");
    const line = m.footer(arena);
    try testing.expect(std.mem.startsWith(u8, line, "signer "));
    try testing.expect(std.mem.endsWith(u8, line, "0 pending"));

    // Serving before the daemon has said who it is: the count alone, never
    // "signer not connected" sitting beside a live queue.
    var fresh = Model{};
    fresh.phase = .connected;
    try testing.expectEqualStrings("0 pending", fresh.footer(arena));
}

test "the app declares the filesystem permission it needs to read the token" {
    // Regression guard. SDK 0.9.1 began confining raw file effects to the app's
    // own directories unless `filesystem` is declared. The GUI reads the
    // daemon's bearer token from $HOME, which is outside every one of them, so
    // without this permission `fx.readFile` is REJECTED SILENTLY: `.token_read`
    // arrives as `.rejected`, the retry arms, the phase never leaves
    // `.connecting`, and the app sits on "Connecting to the signer…" forever
    // looking exactly like a network fault. It shipped working only because the
    // release pinned an older CLI, and nothing here caught it, because every
    // check passes on an app that cannot reach its own daemon.
    //
    // `native check`, `native test` and `native build` all pass without it, so
    // this test is the only thing standing between that bug and a release.
    try testing.expect(native_sdk.security.hasPermission(
        &main.app_permissions,
        native_sdk.security.permission_filesystem,
    ));
}
