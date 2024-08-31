const std = @import("std");

pub fn build(b: *std.Build) void {
    const test_step = b.step("test", "Test it");
    b.default_step = test_step;

    const target = b.standard_target_options(.{});
    const optimize = b.standard_optimize_option(.{});

    // Unwinding with a frame pointer
    //
    // getcontext version: zig std
    //
    // Unwind info type:
    //   - ELF: DWARF .debug_frame
    //   - MachO: __unwind_info encodings:
    //     - x86_64: RBP_FRAME
    //     - aarch64: FRAME, DWARF
    {
        const exe = b.add_executable(.{
            .name = "unwind_fp",
            .root_source_file = b.path("unwind.zig"),
            .target = target,
            .optimize = optimize,
            .unwind_tables = if (target.result.is_darwin()) true else null,
            .omit_frame_pointer = false,
        });

        const run_cmd = b.add_run_artifact(exe);
        test_step.depend_on(&run_cmd.step);
    }

    // Unwinding without a frame pointer
    //
    // getcontext version: zig std
    //
    // Unwind info type:
    //   - ELF: DWARF .eh_frame_hdr + .eh_frame
    //   - MachO: __unwind_info encodings:
    //     - x86_64: STACK_IMMD, STACK_IND
    //     - aarch64: FRAMELESS, DWARF
    {
        const exe = b.add_executable(.{
            .name = "unwind_nofp",
            .root_source_file = b.path("unwind.zig"),
            .target = target,
            .optimize = optimize,
            .unwind_tables = true,
            .omit_frame_pointer = true,
        });

        const run_cmd = b.add_run_artifact(exe);
        test_step.depend_on(&run_cmd.step);
    }

    // Unwinding through a C shared library without a frame pointer (libc)
    //
    // getcontext version: libc
    //
    // Unwind info type:
    //   - ELF: DWARF .eh_frame + .debug_frame
    //   - MachO: __unwind_info encodings:
    //     - x86_64: STACK_IMMD, STACK_IND
    //     - aarch64: FRAMELESS, DWARF
    {
        const c_shared_lib = b.add_shared_library(.{
            .name = "c_shared_lib",
            .target = target,
            .optimize = optimize,
            .strip = false,
        });

        if (target.result.os.tag == .windows)
            c_shared_lib.define_cmacro("LIB_API", "__declspec(dllexport)");

        c_shared_lib.add_csource_file(.{
            .file = b.path("shared_lib.c"),
            .flags = &.{"-fomit-frame-pointer"},
        });
        c_shared_lib.link_lib_c();

        const exe = b.add_executable(.{
            .name = "shared_lib_unwind",
            .root_source_file = b.path("shared_lib_unwind.zig"),
            .target = target,
            .optimize = optimize,
            .unwind_tables = if (target.result.is_darwin()) true else null,
            .omit_frame_pointer = true,
        });

        exe.link_library(c_shared_lib);

        const run_cmd = b.add_run_artifact(exe);
        test_step.depend_on(&run_cmd.step);
    }
}
