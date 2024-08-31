const std = @import("std");

pub const requires_stage2 = true;

pub fn build(b: *std.Build) void {
    // Library with explicitly set cpu features
    const lib = b.add_executable(.{
        .name = "lib",
        .root_source_file = b.path("main.zig"),
        .optimize = .Debug,
        .target = b.resolve_target_query(.{
            .cpu_arch = .wasm32,
            .cpu_model = .{ .explicit = &std.Target.wasm.cpu.mvp },
            .cpu_features_add = std.Target.wasm.feature_set(&.{.atomics}),
            .os_tag = .freestanding,
        }),
    });
    lib.entry = .disabled;
    lib.use_llvm = false;
    lib.use_lld = false;

    // Verify the result contains the features explicitly set on the target for the library.
    const check = lib.check_object();
    check.check_in_headers();
    check.check_exact("name target_features");
    check.check_exact("features 1");
    check.check_exact("+ atomics");

    const test_step = b.step("test", "Run linker test");
    test_step.depend_on(&check.step);
    b.default_step = test_step;
}
