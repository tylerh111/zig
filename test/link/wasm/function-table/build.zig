const std = @import("std");

pub const requires_stage2 = true;

pub fn build(b: *std.Build) void {
    const test_step = b.step("test", "Test it");
    b.default_step = test_step;

    add(b, test_step, .Debug);
    add(b, test_step, .ReleaseFast);
    add(b, test_step, .ReleaseSmall);
    add(b, test_step, .ReleaseSafe);
}

fn add(b: *std.Build, test_step: *std.Build.Step, optimize: std.builtin.OptimizeMode) void {
    const import_table = b.add_executable(.{
        .name = "import_table",
        .root_source_file = b.path("lib.zig"),
        .target = b.resolve_target_query(.{ .cpu_arch = .wasm32, .os_tag = .freestanding }),
        .optimize = optimize,
    });
    import_table.entry = .disabled;
    import_table.use_llvm = false;
    import_table.use_lld = false;
    import_table.import_table = true;
    import_table.link_gc_sections = false;

    const export_table = b.add_executable(.{
        .name = "export_table",
        .root_source_file = b.path("lib.zig"),
        .target = b.resolve_target_query(.{ .cpu_arch = .wasm32, .os_tag = .freestanding }),
        .optimize = optimize,
    });
    export_table.entry = .disabled;
    export_table.use_llvm = false;
    export_table.use_lld = false;
    export_table.export_table = true;
    export_table.link_gc_sections = false;

    const regular_table = b.add_executable(.{
        .name = "regular_table",
        .root_source_file = b.path("lib.zig"),
        .target = b.resolve_target_query(.{ .cpu_arch = .wasm32, .os_tag = .freestanding }),
        .optimize = optimize,
    });
    regular_table.entry = .disabled;
    regular_table.use_llvm = false;
    regular_table.use_lld = false;
    regular_table.link_gc_sections = false; // Ensure function table is not empty

    const check_import = import_table.check_object();
    const check_export = export_table.check_object();
    const check_regular = regular_table.check_object();

    check_import.check_in_headers();
    check_import.check_exact("Section import");
    check_import.check_exact("entries 1");
    check_import.check_exact("module env");
    check_import.check_exact("name __indirect_function_table");
    check_import.check_exact("kind table");
    check_import.check_exact("type funcref");
    check_import.check_exact("min 1"); // 1 function pointer
    check_import.check_not_present("max"); // when importing, we do not provide a max
    check_import.check_not_present("Section table"); // we're importing it

    check_export.check_in_headers();
    check_export.check_exact("Section export");
    check_export.check_exact("entries 2");
    check_export.check_exact("name __indirect_function_table"); // as per linker specification
    check_export.check_exact("kind table");

    check_regular.check_in_headers();
    check_regular.check_exact("Section table");
    check_regular.check_exact("entries 1");
    check_regular.check_exact("type funcref");
    check_regular.check_exact("min 2"); // index starts at 1 & 1 function pointer = 2.
    check_regular.check_exact("max 2");

    check_regular.check_in_headers();
    check_regular.check_exact("Section element");
    check_regular.check_exact("entries 1");
    check_regular.check_exact("table index 0");
    check_regular.check_exact("i32.const 1"); // we want to start function indexes at 1
    check_regular.check_exact("indexes 1"); // 1 function pointer

    test_step.depend_on(&check_import.step);
    test_step.depend_on(&check_export.step);
    test_step.depend_on(&check_regular.step);
}
