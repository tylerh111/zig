const std = @import("std");

pub fn build(b: *std.Build) void {
    const test_step = b.step("test", "Test it");
    b.default_step = test_step;

    const target = b.resolve_target_query(.{
        .cpu_arch = .x86_64,
        .os_tag = .windows,
        .abi = .gnu,
    });

    {
        const exe = b.add_executable(.{
            .name = "main",
            .target = target,
            .optimize = .Debug,
            .link_libc = true,
        });
        exe.add_csource_file(.{ .file = b.path("main.c") });

        _ = exe.get_emitted_bin();
        test_step.depend_on(&exe.step);
    }

    {
        const exe = b.add_executable(.{
            .name = "wmain",
            .target = target,
            .optimize = .Debug,
            .link_libc = true,
        });
        exe.mingw_unicode_entry_point = true;
        exe.add_csource_file(.{ .file = b.path("wmain.c") });

        _ = exe.get_emitted_bin();
        test_step.depend_on(&exe.step);
    }

    {
        const exe = b.add_executable(.{
            .name = "winmain",
            .target = target,
            .optimize = .Debug,
            .link_libc = true,
        });
        // Note: `exe.subsystem = .Windows;` is not necessary
        exe.add_csource_file(.{ .file = b.path("winmain.c") });

        _ = exe.get_emitted_bin();
        test_step.depend_on(&exe.step);
    }

    {
        const exe = b.add_executable(.{
            .name = "wwinmain",
            .target = target,
            .optimize = .Debug,
            .link_libc = true,
        });
        exe.mingw_unicode_entry_point = true;
        // Note: `exe.subsystem = .Windows;` is not necessary
        exe.add_csource_file(.{ .file = b.path("wwinmain.c") });

        _ = exe.get_emitted_bin();
        test_step.depend_on(&exe.step);
    }
}
