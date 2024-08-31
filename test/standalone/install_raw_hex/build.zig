const builtin = @import("builtin");
const std = @import("std");

pub fn build(b: *std.Build) void {
    const test_step = b.step("test", "Test it");
    b.default_step = test_step;

    const target = b.resolve_target_query(.{
        .cpu_arch = .thumb,
        .cpu_model = .{ .explicit = &std.Target.arm.cpu.cortex_m4 },
        .os_tag = .freestanding,
        .abi = .gnueabihf,
    });

    const optimize: std.builtin.OptimizeMode = .Debug;

    const elf = b.add_executable(.{
        .name = "zig-nrf52-blink.elf",
        .root_source_file = b.path("main.zig"),
        .target = target,
        .optimize = optimize,
    });

    const hex_step = elf.add_obj_copy(.{
        .basename = "hello.hex",
    });
    test_step.depend_on(&hex_step.step);

    const explicit_format_hex_step = elf.add_obj_copy(.{
        .basename = "hello.foo",
        .format = .hex,
    });
    test_step.depend_on(&explicit_format_hex_step.step);
}
