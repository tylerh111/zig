const std = @import("std");

pub fn build(b: *std.Build) void {
    const test_step = b.step("test", "Test it");
    b.default_step = test_step;

    const main = b.add_test(.{
        .root_source_file = b.path("main.zig"),
        .optimize = b.standard_optimize_option(.{}),
    });
    // TODO: actually check these two artifacts for correctness
    _ = main.get_emitted_bin();
    _ = main.get_emitted_asm();

    test_step.depend_on(&b.add_run_artifact(main).step);
}
