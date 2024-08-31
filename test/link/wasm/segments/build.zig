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
    lib.link_gc_sections = false; // so data is not garbage collected and we can verify data section
    b.install_artifact(lib);

    const check_lib = lib.check_object();
    check_lib.check_in_headers();
    check_lib.check_exact("Section data");
    check_lib.check_exact("entries 2"); // rodata & data, no bss because we're exporting memory

    check_lib.check_in_headers();
    check_lib.check_exact("Section custom");
    check_lib.check_in_headers();
    check_lib.check_exact("name name"); // names custom section
    check_lib.check_in_headers();
    check_lib.check_exact("type data_segment");
    check_lib.check_exact("names 2");
    check_lib.check_exact("index 0");
    check_lib.check_exact("name .rodata");
    check_lib.check_exact("index 1");
    check_lib.check_exact("name .data");
    test_step.depend_on(&check_lib.step);
}
