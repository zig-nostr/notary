//! This build belongs to your app, written once by `native eject`:
//! the `native` CLI stops generating a build graph and
//! drives this file through `zig build` instead, and it will
//! never rewrite it. `addApp` wires the complete standard app
//! build — executable, `zig build run`, `zig build test`, and
//! the -Dplatform/-Dweb-engine/-Dautomation/-Doptimize flags —
//! from the framework's build/app.zig, so a framework upgrade
//! still upgrades your build. Extend from here with
//! `addAppArtifacts` when you need extra sources or steps.

const std = @import("std");
const native_sdk = @import("native_sdk");

pub fn build(b: *std.Build) void {
    // Linux builds read `app.linux.zon`, everything else reads `app.zon`.
    //
    // `app.zon` declares the background resident: a window whose close hides it
    // instead of ending the app, and no Dock icon. The Linux host has no status
    // item to bring a hidden window back, so the toolkit refuses that
    // declaration at compile time there rather than strand the window. The two
    // files differ by exactly those lines, and `scripts/check-manifests.sh`
    // fails when they drift anywhere else.
    const manifest = if (targetsLinux(b)) "app.linux.zon" else "app.zon";
    native_sdk.addApp(b, b.dependency("native_sdk", .{}), .{ .name = "notary", .manifest = manifest });
}

/// Whether this build is for Linux, read without declaring `-Dtarget` again:
/// `addApp` declares it, and declaring an option twice aborts the build.
fn targetsLinux(b: *std.Build) bool {
    if (b.user_input_options.get("target")) |option| switch (option.value) {
        .scalar => |triple| {
            const query = std.Target.Query.parse(.{ .arch_os_abi = triple }) catch return false;
            return (query.os_tag orelse b.graph.host.result.os.tag) == .linux;
        },
        else => {},
    };
    return b.graph.host.result.os.tag == .linux;
}
