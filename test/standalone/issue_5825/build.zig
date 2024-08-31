const builtin = @import("builtin");
const std = @import("std");

pub fn build(b: *std.Build) void {
    const test_step = b.step("test", "Test it");
    b.default_step = test_step;

    // Building for the msvc abi requires a native MSVC installation
    if (builtin.os.tag != .windows or builtin.cpu.arch != .x86_64) return;

    const target = b.resolve_target_query(.{
        .cpu_arch = .x86_64,
        .os_tag = .windows,
        .abi = .msvc,
    });
    const optimize: std.builtin.OptimizeMode = .Debug;
    const obj = b.add_object(.{
        .name = "issue_5825",
        .root_source_file = b.path("main.zig"),
        .optimize = optimize,
        .target = target,
    });

    const exe = b.add_executable(.{
        .name = "issue_5825",
        .optimize = optimize,
        .target = target,
    });
    exe.subsystem = .Console;
    exe.link_system_library("kernel32");
    exe.link_system_library("ntdll");
    exe.add_object(obj);

    // TODO: actually check the output
    _ = exe.get_emitted_bin();

    test_step.depend_on(&exe.step);
}
