const std = @import("std");

pub const requires_stage2 = true;

pub fn build(b: *std.Build) void {
    const test_step = b.step("test", "Test it");
    b.default_step = test_step;

    add(b, test_step, .Debug);
    add(b, test_step, .ReleaseFast);
    add(b, test_step, .ReleaseSmall);
    add(b, test_step, .ReleaseSafe);
}

fn add(b: *std.Build, test_step: *std.Build.Step, optimize: std.builtin.OptimizeMode) void {
    const exe = b.add_executable(.{
        .name = "lib",
        .root_source_file = b.path("lib.zig"),
        .target = b.resolve_target_query(.{ .cpu_arch = .wasm32, .os_tag = .freestanding }),
        .optimize = optimize,
        .strip = false,
    });
    exe.entry = .disabled;
    exe.use_llvm = false;
    exe.use_lld = false;
    exe.root_module.export_symbol_names = &.{"foo"};
    b.install_artifact(exe);

    const check_exe = exe.check_object();
    check_exe.check_in_headers();
    check_exe.check_exact("Section type");
    // only 2 entries, although we have more functions.
    // This is to test functions with the same function signature
    // have their types deduplicated.
    check_exe.check_exact("entries 2");
    check_exe.check_exact("params 1");
    check_exe.check_exact("type i32");
    check_exe.check_exact("returns 1");
    check_exe.check_exact("type i64");
    check_exe.check_exact("params 0");
    check_exe.check_exact("returns 0");

    test_step.depend_on(&check_exe.step);
}
