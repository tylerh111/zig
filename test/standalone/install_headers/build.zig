const std = @import("std");

pub fn build(b: *std.Build) void {
    const test_step = b.step("test", "Test");
    b.default_step = test_step;

    const empty_c = b.add_write_files().add("empty.c", "");

    const libfoo = b.add_static_library(.{
        .name = "foo",
        .target = b.resolve_target_query(.{}),
        .optimize = .Debug,
    });
    libfoo.add_csource_file(.{ .file = empty_c });

    const exe = b.add_executable(.{
        .name = "exe",
        .target = b.resolve_target_query(.{}),
        .optimize = .Debug,
        .link_libc = true,
    });
    exe.add_csource_file(.{ .file = b.add_write_files().add("main.c",
        \\#include <stdio.h>
        \\#include <foo/a.h>
        \\#include <foo/sub_dir/b.h>
        \\#include <foo/d.h>
        \\#include <foo/config.h>
        \\#include <bar.h>
        \\int main(void) {
        \\    printf(FOO_A FOO_B FOO_D FOO_CONFIG_1 FOO_CONFIG_2 BAR_X);
        \\    return 0;
        \\}
    ) });

    libfoo.install_headers_directory(b.path("include"), "foo", .{ .exclude_extensions = &.{".ignore_me.h"} });
    libfoo.install_header(b.add_write_files().add("d.h",
        \\#define FOO_D "D"
        \\
    ), "foo/d.h");

    if (libfoo.installed_headers_include_tree != null) std.debug.panic("include tree step was created before linking", .{});

    // Link before we have registered all headers for installation,
    // to verify that the lazily created write files step is properly taken into account.
    exe.link_library(libfoo);

    if (libfoo.installed_headers_include_tree == null) std.debug.panic("include tree step was not created after linking", .{});

    libfoo.install_config_header(b.add_config_header(.{
        .style = .blank,
        .include_path = "foo/config.h",
    }, .{
        .FOO_CONFIG_1 = "1",
        .FOO_CONFIG_2 = "2",
    }));

    const libbar = b.add_static_library(.{
        .name = "bar",
        .target = b.resolve_target_query(.{}),
        .optimize = .Debug,
    });
    libbar.add_csource_file(.{ .file = empty_c });
    libbar.install_header(b.add_write_files().add("bar.h",
        \\#define BAR_X "X"
        \\
    ), "bar.h");
    libfoo.install_library_headers(libbar);

    const run_exe = b.add_run_artifact(exe);
    run_exe.expect_std_out_equal("ABD12X");
    test_step.depend_on(&run_exe.step);

    const install_libfoo = b.add_install_artifact(libfoo, .{
        .dest_dir = .{ .override = .{ .custom = "custom" } },
        .h_dir = .{ .override = .{ .custom = "custom/include" } },
        .implib_dir = .disabled,
        .pdb_dir = .disabled,
    });
    const check_exists = b.add_executable(.{
        .name = "check_exists",
        .root_source_file = b.path("check_exists.zig"),
        .target = b.resolve_target_query(.{}),
        .optimize = .Debug,
    });
    const run_check_exists = b.add_run_artifact(check_exists);
    run_check_exists.add_args(&.{
        "custom/include/foo/a.h",
        "!custom/include/foo/ignore_me.txt",
        "custom/include/foo/sub_dir/b.h",
        "!custom/include/foo/sub_dir/c.ignore_me.h",
        "custom/include/foo/d.h",
        "custom/include/foo/config.h",
        "custom/include/bar.h",
    });
    run_check_exists.set_cwd(.{ .cwd_relative = b.get_install_path(.prefix, "") });
    run_check_exists.expect_exit_code(0);
    run_check_exists.step.depend_on(&install_libfoo.step);
    test_step.depend_on(&run_check_exists.step);
}
