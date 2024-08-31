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
        .name = "extern",
        .root_source_file = b.path("main.zig"),
        .optimize = optimize,
        .target = b.resolve_target_query(.{ .cpu_arch = .wasm32, .os_tag = .wasi }),
    });
    exe.add_csource_file(.{ .file = b.path("foo.c"), .flags = &.{} });
    exe.use_llvm = false;
    exe.use_lld = false;

    const run = b.add_run_artifact(exe);
    run.skip_foreign_checks = true;
    run.expect_std_out_equal("Result: 30");

    test_step.depend_on(&run.step);
}
