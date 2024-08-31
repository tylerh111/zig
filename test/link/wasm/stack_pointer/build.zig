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
    const lib = b.add_executable(.{
        .name = "lib",
        .root_source_file = b.path("lib.zig"),
        .target = b.resolve_target_query(.{ .cpu_arch = .wasm32, .os_tag = .freestanding }),
        .optimize = optimize,
        .strip = false,
    });
    lib.entry = .disabled;
    lib.use_llvm = false;
    lib.use_lld = false;
    lib.stack_size = std.wasm.page_size * 2; // set an explicit stack size
    lib.link_gc_sections = false;
    b.install_artifact(lib);

    const check_lib = lib.check_object();

    // ensure global exists and its initial value is equal to explitic stack size
    check_lib.check_in_headers();
    check_lib.check_exact("Section global");
    check_lib.check_exact("entries 1");
    check_lib.check_exact("type i32"); // on wasm32 the stack pointer must be i32
    check_lib.check_exact("mutable true"); // must be able to mutate the stack pointer
    check_lib.check_extract("i32.const {stack_pointer}");
    check_lib.check_compute_compare("stack_pointer", .{ .op = .eq, .value = .{ .literal = lib.stack_size.? } });

    // validate memory section starts after virtual stack
    check_lib.check_in_headers();
    check_lib.check_exact("Section data");
    check_lib.check_extract("i32.const {data_start}");
    check_lib.check_compute_compare("data_start", .{ .op = .eq, .value = .{ .variable = "stack_pointer" } });

    // validate the name of the stack pointer
    check_lib.check_in_headers();
    check_lib.check_exact("Section custom");
    check_lib.check_exact("type global");
    check_lib.check_exact("names 1");
    check_lib.check_exact("index 0");
    check_lib.check_exact("name __stack_pointer");
    test_step.depend_on(&check_lib.step);
}
