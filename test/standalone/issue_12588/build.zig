const std = @import("std");

pub fn build(b: *std.Build) void {
    const test_step = b.step("test", "Test it");
    b.default_step = test_step;

    const optimize: std.builtin.OptimizeMode = .Debug;

    const obj = b.add_object(.{
        .name = "main",
        .root_source_file = b.path("main.zig"),
        .optimize = optimize,
        .target = b.host,
    });
    _ = obj.get_emitted_llvm_ir();
    _ = obj.get_emitted_llvm_bc();
    b.default_step.depend_on(&obj.step);

    test_step.depend_on(&obj.step);
}
