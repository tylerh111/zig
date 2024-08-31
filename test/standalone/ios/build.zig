const std = @import("std");

pub const requires_symlinks = true;
pub const requires_ios_sdk = true;

pub fn build(b: *std.Build) void {
    const test_step = b.step("test", "Test it");
    b.default_step = test_step;

    const optimize: std.builtin.OptimizeMode = .Debug;
    const target = b.resolve_target_query(.{
        .cpu_arch = .aarch64,
        .os_tag = .ios,
    });
    const sdk = std.zig.system.darwin.get_sdk(b.allocator, target.result) orelse
        @panic("no iOS SDK found");
    b.sysroot = sdk;

    const exe = b.add_executable(.{
        .name = "main",
        .optimize = optimize,
        .target = target,
    });
    exe.add_csource_file(.{ .file = b.path("main.m"), .flags = &.{} });
    exe.add_system_include_path(.{ .cwd_relative = b.path_join(&.{ sdk, "/usr/include" }) });
    exe.add_system_framework_path(.{ .cwd_relative = b.path_join(&.{ sdk, "/System/Library/Frameworks" }) });
    exe.add_library_path(.{ .cwd_relative = b.path_join(&.{ sdk, "/usr/lib" }) });
    exe.link_framework("Foundation");
    exe.link_framework("UIKit");
    exe.link_lib_c();

    const check = exe.check_object();
    check.check_in_headers();
    check.check_exact("cmd BUILD_VERSION");
    check.check_exact("platform IOS");
    test_step.depend_on(&check.step);
}
