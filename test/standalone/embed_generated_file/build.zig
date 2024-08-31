const std = @import("std");

pub fn build(b: *std.Build) void {
    const test_step = b.step("test", "Test it");
    b.default_step = test_step;

    const bootloader = b.add_executable(.{
        .name = "bootloader",
        .root_source_file = b.path("bootloader.zig"),
        .target = b.resolve_target_query(.{
            .cpu_arch = .x86,
            .os_tag = .freestanding,
        }),
        .optimize = .ReleaseSmall,
    });

    const exe = b.add_test(.{
        .root_source_file = b.path("main.zig"),
        .optimize = .Debug,
    });
    exe.root_module.add_anonymous_import("bootloader.elf", .{
        .root_source_file = bootloader.get_emitted_bin(),
    });

    // TODO: actually check the output
    _ = exe.get_emitted_bin();

    test_step.depend_on(&exe.step);
}
