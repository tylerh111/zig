const std = @import("std");

pub fn build(b: *std.Build) !void {
    const test_step = b.step("test", "Test it");
    b.default_step = test_step;

    const optimize: std.builtin.OptimizeMode = .Debug;
    const target = b.resolve_target_query(.{
        .os_tag = .freestanding,
        .cpu_arch = .arm,
        .cpu_model = .{
            .explicit = &std.Target.arm.cpu.arm1176jz_s,
        },
    });

    const kernel = b.add_executable(.{
        .name = "kernel",
        .root_source_file = b.path("./main.zig"),
        .optimize = optimize,
        .target = target,
    });
    kernel.add_object_file(b.path("./boot.S"));
    kernel.set_linker_script(b.path("./linker.ld"));
    b.install_artifact(kernel);

    test_step.depend_on(&kernel.step);
}
