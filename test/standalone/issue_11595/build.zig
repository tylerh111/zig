const std = @import("std");
const builtin = @import("builtin");

pub fn build(b: *std.Build) void {
    const test_step = b.step("test", "Test it");
    b.default_step = test_step;

    const optimize: std.builtin.OptimizeMode = .Debug;
    const target = b.host;

    if (builtin.os.tag == .windows) {
        // https://github.com/ziglang/zig/issues/12419
        return;
    }

    const exe = b.add_executable(.{
        .name = "zigtest",
        .root_source_file = b.path("main.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.install_artifact(exe);

    const c_sources = [_][]const u8{
        "test.c",
    };

    exe.add_csource_files(.{ .files = &c_sources });
    exe.link_lib_c();

    var i: i32 = 0;
    while (i < 1000) : (i += 1) {
        exe.define_cmacro("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    }

    exe.define_cmacro("FOO", "42");
    exe.define_cmacro("BAR", "\"BAR\"");
    exe.define_cmacro("BAZ",
        \\"\"BAZ\""
    );
    exe.define_cmacro("QUX", "\"Q\" \"UX\"");
    exe.define_cmacro("QUUX", "\"QU\\\"UX\"");

    b.default_step.depend_on(&exe.step);

    const run_cmd = b.add_run_artifact(exe);
    run_cmd.skip_foreign_checks = true;
    run_cmd.expect_exit_code(0);

    test_step.depend_on(&run_cmd.step);
}
