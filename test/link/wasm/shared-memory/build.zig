const std = @import("std");

pub fn build(b: *std.Build) void {
    const test_step = b.step("test", "Test");
    b.default_step = test_step;

    add(b, test_step, .Debug);
    add(b, test_step, .ReleaseFast);
    add(b, test_step, .ReleaseSmall);
    add(b, test_step, .ReleaseSafe);
}

fn add(b: *std.Build, test_step: *std.Build.Step, optimize_mode: std.builtin.OptimizeMode) void {
    const exe = b.add_executable(.{
        .name = "lib",
        .root_source_file = b.path("lib.zig"),
        .target = b.resolve_target_query(.{
            .cpu_arch = .wasm32,
            .cpu_model = .{ .explicit = &std.Target.wasm.cpu.mvp },
            .cpu_features_add = std.Target.wasm.feature_set(&.{ .atomics, .bulk_memory }),
            .os_tag = .freestanding,
        }),
        .optimize = optimize_mode,
        .strip = false,
        .single_threaded = false,
    });
    exe.entry = .disabled;
    exe.use_lld = false;
    exe.import_memory = true;
    exe.export_memory = true;
    exe.shared_memory = true;
    exe.max_memory = 67108864;
    exe.root_module.export_symbol_names = &.{"foo"};

    const check_exe = exe.check_object();

    check_exe.check_in_headers();
    check_exe.check_exact("Section import");
    check_exe.check_exact("entries 1");
    check_exe.check_exact("module env");
    check_exe.check_exact("name memory"); // ensure we are importing memory

    check_exe.check_in_headers();
    check_exe.check_exact("Section export");
    check_exe.check_exact("entries 2");
    check_exe.check_exact("name memory"); // ensure we also export memory again

    // This section *must* be emit as the start function is set to the index
    // of __wasm_init_memory
    // release modes will have the TLS segment optimized out in our test-case.
    // This means we won't have __wasm_init_memory in such case, and therefore
    // should also not have a section "start"
    if (optimize_mode == .Debug) {
        check_exe.check_in_headers();
        check_exe.check_exact("Section start");
    }

    // This section is only and *must* be emit when shared-memory is enabled
    // release modes will have the TLS segment optimized out in our test-case.
    if (optimize_mode == .Debug) {
        check_exe.check_in_headers();
        check_exe.check_exact("Section data_count");
        check_exe.check_exact("count 1");
    }

    check_exe.check_in_headers();
    check_exe.check_exact("Section custom");
    check_exe.check_exact("name name");
    check_exe.check_exact("type function");
    if (optimize_mode == .Debug) {
        check_exe.check_exact("name __wasm_init_memory");
    }
    check_exe.check_exact("name __wasm_init_tls");
    check_exe.check_exact("type global");

    // In debug mode the symbol __tls_base is resolved to an undefined symbol
    // from the object file, hence its placement differs than in release modes
    // where the entire tls segment is optimized away, and tls_base will have
    // its original position.
    check_exe.check_exact("name __tls_base");
    check_exe.check_exact("name __tls_size");
    check_exe.check_exact("name __tls_align");

    check_exe.check_exact("type data_segment");
    if (optimize_mode == .Debug) {
        check_exe.check_exact("names 1");
        check_exe.check_exact("index 0");
        check_exe.check_exact("name .tdata");
    }

    test_step.depend_on(&check_exe.step);
}
