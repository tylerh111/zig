const std = @import("std");

pub fn build(b: *std.Build) void {
    const test_step = b.step("test", "Test");
    b.default_step = test_step;

    if (@import("builtin").os.tag == .windows) {
        // TODO: Fix open handle in wasm-linker refraining rename from working on Windows.
        return;
    }

    const lib = b.add_executable(.{
        .name = "lib",
        .root_source_file = b.path("lib.zig"),
        .optimize = .ReleaseSafe, // to make the output deterministic in address positions
        .target = b.resolve_target_query(.{ .cpu_arch = .wasm32, .os_tag = .freestanding }),
    });
    lib.entry = .disabled;
    lib.use_lld = false;
    lib.root_module.export_symbol_names = &.{ "foo", "bar" };
    lib.global_base = 0; // put data section at address 0 to make data symbols easier to parse

    const check_lib = lib.check_object();

    check_lib.check_in_headers();
    check_lib.check_exact("Section global");
    check_lib.check_exact("entries 3");
    check_lib.check_exact("type i32"); // stack pointer so skip other fields
    check_lib.check_exact("type i32");
    check_lib.check_exact("mutable false");
    check_lib.check_extract("i32.const {foo_address}");
    check_lib.check_exact("type i32");
    check_lib.check_exact("mutable false");
    check_lib.check_extract("i32.const {bar_address}");
    check_lib.check_compute_compare("foo_address", .{ .op = .eq, .value = .{ .literal = 4 } });
    check_lib.check_compute_compare("bar_address", .{ .op = .eq, .value = .{ .literal = 0 } });

    check_lib.check_in_headers();
    check_lib.check_exact("Section export");
    check_lib.check_exact("entries 3");
    check_lib.check_exact("name foo");
    check_lib.check_exact("kind global");
    check_lib.check_exact("index 1");
    check_lib.check_exact("name bar");
    check_lib.check_exact("kind global");
    check_lib.check_exact("index 2");

    test_step.depend_on(&check_lib.step);
}
