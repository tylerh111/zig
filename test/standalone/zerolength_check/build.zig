const std = @import("std");

pub fn build(b: *std.Build) void {
    const test_step = b.step("test", "Test it");
    b.default_step = test_step;

    add(b, test_step, .Debug);
    add(b, test_step, .ReleaseFast);
    add(b, test_step, .ReleaseSmall);
    add(b, test_step, .ReleaseSafe);
}

fn add(b: *std.Build, test_step: *std.Build.Step, optimize: std.builtin.OptimizeMode) void {
    const unit_tests = b.add_test(.{
        .root_source_file = b.path("src/main.zig"),
        .target = b.resolve_target_query(.{
            .os_tag = .wasi,
            .cpu_arch = .wasm32,
            .cpu_features_add = std.Target.wasm.feature_set(&.{.bulk_memory}),
        }),
        .optimize = optimize,
    });

    const run_unit_tests = b.add_run_artifact(unit_tests);
    run_unit_tests.skip_foreign_checks = true;
    test_step.depend_on(&run_unit_tests.step);
}
