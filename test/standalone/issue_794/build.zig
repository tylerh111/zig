const std = @import("std");

pub fn build(b: *std.Build) void {
    const test_step = b.step("test", "Test it");
    b.default_step = test_step;

    const test_artifact = b.add_test(.{
        .root_source_file = b.path("main.zig"),
    });
    test_artifact.add_include_path(b.path("a_directory"));

    // TODO: actually check the output
    _ = test_artifact.get_emitted_bin();

    test_step.depend_on(&test_artifact.step);
}
