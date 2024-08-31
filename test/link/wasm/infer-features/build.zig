const std = @import("std");

pub const requires_stage2 = true;

pub fn build(b: *std.Build) void {
    // Wasm Object file which we will use to infer the features from
    const c_obj = b.add_object(.{
        .name = "c_obj",
        .optimize = .Debug,
        .target = b.resolve_target_query(.{
            .cpu_arch = .wasm32,
            .cpu_model = .{ .explicit = &std.Target.wasm.cpu.bleeding_edge },
            .os_tag = .freestanding,
        }),
    });
    c_obj.add_csource_file(.{ .file = b.path("foo.c"), .flags = &.{} });

    // Wasm library that doesn't have any features specified. This will
    // infer its featureset from other linked object files.
    const lib = b.add_executable(.{
        .name = "lib",
        .root_source_file = b.path("main.zig"),
        .optimize = .Debug,
        .target = b.resolve_target_query(.{
            .cpu_arch = .wasm32,
            .cpu_model = .{ .explicit = &std.Target.wasm.cpu.mvp },
            .os_tag = .freestanding,
        }),
    });
    lib.entry = .disabled;
    lib.use_llvm = false;
    lib.use_lld = false;
    lib.add_object(c_obj);

    // Verify the result contains the features from the C Object file.
    const check = lib.check_object();
    check.check_in_headers();
    check.check_exact("name target_features");
    check.check_exact("features 7");
    check.check_exact("+ atomics");
    check.check_exact("+ bulk-memory");
    check.check_exact("+ mutable-globals");
    check.check_exact("+ nontrapping-fptoint");
    check.check_exact("+ sign-ext");
    check.check_exact("+ simd128");
    check.check_exact("+ tail-call");

    const test_step = b.step("test", "Run linker test");
    test_step.depend_on(&check.step);
    b.default_step = test_step;
}
