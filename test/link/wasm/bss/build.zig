const std = @import("std");

pub const requires_stage2 = true;

pub fn build(b: *std.Build) void {
    const test_step = b.step("test", "Test");
    b.default_step = test_step;

    add(b, test_step, .Debug, true);
    add(b, test_step, .ReleaseFast, false);
    add(b, test_step, .ReleaseSmall, false);
    add(b, test_step, .ReleaseSafe, true);
}

fn add(b: *std.Build, test_step: *std.Build.Step, optimize_mode: std.builtin.OptimizeMode, is_safe: bool) void {
    {
        const lib = b.add_executable(.{
            .name = "lib",
            .root_source_file = b.path("lib.zig"),
            .target = b.resolve_target_query(.{ .cpu_arch = .wasm32, .os_tag = .freestanding }),
            .optimize = optimize_mode,
            .strip = false,
        });
        lib.entry = .disabled;
        lib.use_llvm = false;
        lib.use_lld = false;
        // to make sure the bss segment is emitted, we must import memory
        lib.import_memory = true;
        lib.link_gc_sections = false;

        const check_lib = lib.check_object();

        // since we import memory, make sure it exists with the correct naming
        check_lib.check_in_headers();
        check_lib.check_exact("Section import");
        check_lib.check_exact("entries 1");
        check_lib.check_exact("module env"); // default module name is "env"
        check_lib.check_exact("name memory"); // as per linker specification

        // since we are importing memory, ensure it's not exported
        check_lib.check_in_headers();
        check_lib.check_not_present("Section export");

        // validate the name of the stack pointer
        check_lib.check_in_headers();
        check_lib.check_exact("Section custom");
        check_lib.check_exact("type data_segment");
        check_lib.check_exact("names 2");
        check_lib.check_exact("index 0");
        check_lib.check_exact("name .rodata");
        // for safe optimization modes `undefined` is stored in data instead of bss.
        if (is_safe) {
            check_lib.check_exact("index 1");
            check_lib.check_exact("name .data");
            check_lib.check_not_present("name .bss");
        } else {
            check_lib.check_exact("index 1"); // bss section always last
            check_lib.check_exact("name .bss");
        }
        test_step.depend_on(&check_lib.step);
    }

    // verify zero'd declaration is stored in bss for all optimization modes.
    {
        const lib = b.add_executable(.{
            .name = "lib",
            .root_source_file = b.path("lib2.zig"),
            .target = b.resolve_target_query(.{ .cpu_arch = .wasm32, .os_tag = .freestanding }),
            .optimize = optimize_mode,
            .strip = false,
        });
        lib.entry = .disabled;
        lib.use_llvm = false;
        lib.use_lld = false;
        // to make sure the bss segment is emitted, we must import memory
        lib.import_memory = true;
        lib.link_gc_sections = false;

        const check_lib = lib.check_object();
        check_lib.check_in_headers();
        check_lib.check_exact("Section custom");
        check_lib.check_exact("type data_segment");
        check_lib.check_exact("names 2");
        check_lib.check_exact("index 0");
        check_lib.check_exact("name .rodata");
        check_lib.check_exact("index 1");
        check_lib.check_exact("name .bss");

        test_step.depend_on(&check_lib.step);
    }
}
