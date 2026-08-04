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

// ------------------------------------------------------------- parsing

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

    _ = try expectByText(tree.root, .text, "Notary");
    _ = try expectByText(tree.root, .text, "Connecting to the signer…");
    _ = try expectByText(tree.root, .status_bar, "0 pending");
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

    // The Approve/Deny bindings carry the row id in the typed message.
    const approve = try expectByText(tree.root, .button, "Approve");
    switch (tree.msgForPointer(approve.id, .up).?) {
        .approve => |id| try testing.expectEqual(@as(u64, 42), id),
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

    _ = try expectByText(tree.root, .text, "Signer stopped");
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
