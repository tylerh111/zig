const std = @import("std");
const builtin = @import("builtin");

pub fn build(b: *std.Build) void {
    const test_step = b.step("test", "Test it");
    b.default_step = test_step;

    if (builtin.os.tag == .windows) {
        // https://github.com/ziglang/zig/issues/16965
        return;
    }

    add(b, test_step, "test_c_Debug", "test_cpp_Debug", .Debug);
    add(b, test_step, "test_c_ReleaseFast", "test_cpp_ReleaseFast", .ReleaseFast);
    add(b, test_step, "test_c_ReleaseSmall", "test_cpp_ReleaseSmall", .ReleaseSmall);
    add(b, test_step, "test_c_ReleaseSafe", "test_cpp_ReleaseSafe", .ReleaseSafe);
}

fn add(
    b: *std.Build,
    test_step: *std.Build.Step,
    c_name: []const u8,
    cpp_name: []const u8,
    optimize: std.builtin.OptimizeMode,
) void {
    const target = b.host;

    const exe_c = b.add_executable(.{
        .name = c_name,
        .optimize = optimize,
        .target = target,
    });
    exe_c.add_csource_file(.{ .file = b.path("test.c"), .flags = &[0][]const u8{} });
    exe_c.link_lib_c();

    const exe_cpp = b.add_executable(.{
        .name = cpp_name,
        .optimize = optimize,
        .target = target,
    });
    b.default_step.depend_on(&exe_cpp.step);
    exe_cpp.add_csource_file(.{ .file = b.path("test.cpp"), .flags = &[0][]const u8{} });
    exe_cpp.link_lib_cpp();

    switch (target.result.os.tag) {
        .windows => {
            // https://github.com/ziglang/zig/issues/8531
            exe_cpp.want_lto = false;
        },
        .macos => {
            // https://github.com/ziglang/zig/issues/8680
            exe_cpp.want_lto = false;
            exe_c.want_lto = false;
        },
        else => {},
    }

    const run_c_cmd = b.add_run_artifact(exe_c);
    run_c_cmd.expect_exit_code(0);
    run_c_cmd.skip_foreign_checks = true;
    test_step.depend_on(&run_c_cmd.step);

    const run_cpp_cmd = b.add_run_artifact(exe_cpp);
    run_cpp_cmd.expect_exit_code(0);
    run_cpp_cmd.skip_foreign_checks = true;
    test_step.depend_on(&run_cpp_cmd.step);
}
