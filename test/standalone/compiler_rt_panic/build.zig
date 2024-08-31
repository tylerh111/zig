const std = @import("std");

pub fn build(b: *std.Build) void {
    const test_step = b.step("test", "Test it");
    b.default_step = test_step;

    const target = b.standard_target_options(.{});
    const optimize = b.standard_optimize_option(.{});

    if (target.result.ofmt != .elf or !(target.result.abi.is_musl() or target.result.abi.is_gnu()))
        return;

    const exe = b.add_executable(.{
        .name = "main",
        .optimize = optimize,
        .target = target,
    });
    exe.link_lib_c();
    exe.add_csource_file(.{
        .file = b.path("main.c"),
        .flags = &.{},
    });
    exe.link_gc_sections = false;
    exe.bundle_compiler_rt = true;

    // Verify compiler_rt hasn't pulled in any debug handlers
    const check_exe = exe.check_object();
    check_exe.check_in_symtab();
    check_exe.check_not_present("debug.read_elf_debug_info");
    test_step.depend_on(&check_exe.step);
}
