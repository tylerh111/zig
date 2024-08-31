const std = @import("std");
const builtin = @import("builtin");

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
    b.install_artifact(lib);

    const version_fmt = "version " ++ builtin.zig_version_string;

    const check_lib = lib.check_object();
    check_lib.check_in_headers();
    check_lib.check_exact("name producers");
    check_lib.check_exact("fields 2");
    check_lib.check_exact("field_name language");
    check_lib.check_exact("values 1");
    check_lib.check_exact("value_name Zig");
    check_lib.check_exact(version_fmt);
    check_lib.check_exact("field_name processed-by");
    check_lib.check_exact("values 1");
    check_lib.check_exact("value_name Zig");
    check_lib.check_exact(version_fmt);

    test_step.depend_on(&check_lib.step);
}
