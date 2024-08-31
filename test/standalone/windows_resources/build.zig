const std = @import("std");

pub fn build(b: *std.Build) void {
    const test_step = b.step("test", "Test it");
    b.default_step = test_step;

    const target = b.resolve_target_query(.{
        .cpu_arch = .x86_64,
        .os_tag = .windows,
        .abi = .gnu,
    });

    const generated_h_step = b.add_write_file("generated.h", "#define GENERATED_DEFINE \"foo\"");

    add(b, b.host, .any, test_step, generated_h_step);
    add(b, target, .any, test_step, generated_h_step);

    add(b, b.host, .gnu, test_step, generated_h_step);
    add(b, target, .gnu, test_step, generated_h_step);
}

fn add(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    rc_includes: enum { any, gnu },
    test_step: *std.Build.Step,
    generated_h_step: *std.Build.Step.WriteFile,
) void {
    const exe = b.add_executable(.{
        .name = "zig_resource_test",
        .root_source_file = b.path("main.zig"),
        .target = target,
        .optimize = .Debug,
    });
    exe.add_win32_resource_file(.{
        .file = b.path("res/zig.rc"),
        .flags = &.{"/c65001"}, // UTF-8 code page
        .include_paths = &.{
            .{ .generated = .{ .file = &generated_h_step.generated_directory } },
        },
    });
    exe.rc_includes = switch (rc_includes) {
        .any => .any,
        .gnu => .gnu,
    };

    _ = exe.get_emitted_bin();

    test_step.depend_on(&exe.step);
}
