//! Here we test our MachO linker for correctness and functionality.

pub fn test_all(b: *Build, build_opts: BuildOptions) *Step {
    const macho_step = b.step("test-macho", "Run MachO tests");

    const x86_64_target = b.resolve_target_query(.{
        .cpu_arch = .x86_64,
        .os_tag = .macos,
    });
    const aarch64_target = b.resolve_target_query(.{
        .cpu_arch = .aarch64,
        .os_tag = .macos,
    });

    const default_target = switch (builtin.cpu.arch) {
        .x86_64, .aarch64 => b.resolve_target_query(.{
            .os_tag = .macos,
        }),
        else => aarch64_target,
    };

    // Exercise linker with self-hosted backend (no LLVM)
    macho_step.depend_on(test_empty_zig(b, .{ .use_llvm = false, .target = x86_64_target }));
    macho_step.depend_on(test_hello_zig(b, .{ .use_llvm = false, .target = x86_64_target }));
    macho_step.depend_on(test_linking_static_lib(b, .{ .use_llvm = false, .target = x86_64_target }));
    macho_step.depend_on(test_reexports_zig(b, .{ .use_llvm = false, .target = x86_64_target }));
    macho_step.depend_on(test_relocatable_zig(b, .{ .use_llvm = false, .target = x86_64_target }));

    // Exercise linker with LLVM backend
    macho_step.depend_on(test_dead_strip(b, .{ .target = default_target }));
    macho_step.depend_on(test_empty_object(b, .{ .target = default_target }));
    macho_step.depend_on(test_empty_zig(b, .{ .target = default_target }));
    macho_step.depend_on(test_entry_point(b, .{ .target = default_target }));
    macho_step.depend_on(test_header_weak_flags(b, .{ .target = default_target }));
    macho_step.depend_on(test_hello_c(b, .{ .target = default_target }));
    macho_step.depend_on(test_hello_zig(b, .{ .target = default_target }));
    macho_step.depend_on(test_large_bss(b, .{ .target = default_target }));
    macho_step.depend_on(test_layout(b, .{ .target = default_target }));
    macho_step.depend_on(test_linking_static_lib(b, .{ .target = default_target }));
    macho_step.depend_on(test_linksection(b, .{ .target = default_target }));
    macho_step.depend_on(test_merge_literals_x64(b, .{ .target = x86_64_target }));
    macho_step.depend_on(test_merge_literals_arm64(b, .{ .target = aarch64_target }));
    macho_step.depend_on(test_merge_literals_arm642(b, .{ .target = aarch64_target }));
    macho_step.depend_on(test_merge_literals_alignment(b, .{ .target = aarch64_target }));
    macho_step.depend_on(test_mh_execute_header(b, .{ .target = default_target }));
    macho_step.depend_on(test_no_dead_strip(b, .{ .target = default_target }));
    macho_step.depend_on(test_no_exports_dylib(b, .{ .target = default_target }));
    macho_step.depend_on(test_pagezero_size(b, .{ .target = default_target }));
    macho_step.depend_on(test_reexports_zig(b, .{ .target = default_target }));
    macho_step.depend_on(test_relocatable(b, .{ .target = default_target }));
    macho_step.depend_on(test_relocatable_zig(b, .{ .target = default_target }));
    macho_step.depend_on(test_section_boundary_symbols(b, .{ .target = default_target }));
    macho_step.depend_on(test_segment_boundary_symbols(b, .{ .target = default_target }));
    macho_step.depend_on(test_symbol_stabs(b, .{ .target = default_target }));
    macho_step.depend_on(test_stack_size(b, .{ .target = default_target }));
    macho_step.depend_on(test_tentative(b, .{ .target = default_target }));
    macho_step.depend_on(test_thunks(b, .{ .target = aarch64_target }));
    macho_step.depend_on(test_tls_large_tbss(b, .{ .target = default_target }));
    macho_step.depend_on(test_undefined_flag(b, .{ .target = default_target }));
    macho_step.depend_on(test_unwind_info(b, .{ .target = default_target }));
    macho_step.depend_on(test_unwind_info_no_subsections_x64(b, .{ .target = x86_64_target }));
    macho_step.depend_on(test_unwind_info_no_subsections_arm64(b, .{ .target = aarch64_target }));
    macho_step.depend_on(test_weak_bind(b, .{ .target = x86_64_target }));
    macho_step.depend_on(test_weak_ref(b, .{ .target = b.resolve_target_query(.{
        .cpu_arch = .x86_64,
        .os_tag = .macos,
        .os_version_min = .{ .semver = .{ .major = 10, .minor = 13, .patch = 0 } },
    }) }));

    // Tests requiring symlinks
    if (build_opts.has_symlinks) {
        macho_step.depend_on(test_entry_point_archive(b, .{ .target = default_target }));
        macho_step.depend_on(test_entry_point_dylib(b, .{ .target = default_target }));
        macho_step.depend_on(test_dylib(b, .{ .target = default_target }));
        macho_step.depend_on(test_dylib_version_tbd(b, .{ .target = default_target }));
        macho_step.depend_on(test_needed_library(b, .{ .target = default_target }));
        macho_step.depend_on(test_search_strategy(b, .{ .target = default_target }));
        macho_step.depend_on(test_tbdv3(b, .{ .target = default_target }));
        macho_step.depend_on(test_tls(b, .{ .target = default_target }));
        macho_step.depend_on(test_tls_pointers(b, .{ .target = default_target }));
        macho_step.depend_on(test_two_level_namespace(b, .{ .target = default_target }));
        macho_step.depend_on(test_weak_library(b, .{ .target = default_target }));

        // Tests requiring presence of macOS SDK in system path
        if (build_opts.has_macos_sdk) {
            macho_step.depend_on(test_dead_strip_dylibs(b, .{ .target = b.host }));
            macho_step.depend_on(test_headerpad(b, .{ .target = b.host }));
            macho_step.depend_on(test_link_directly_cpp_tbd(b, .{ .target = b.host }));
            macho_step.depend_on(test_merge_literals_objc(b, .{ .target = b.host }));
            macho_step.depend_on(test_needed_framework(b, .{ .target = b.host }));
            macho_step.depend_on(test_objc(b, .{ .target = b.host }));
            macho_step.depend_on(test_objcpp(b, .{ .target = b.host }));
            macho_step.depend_on(test_weak_framework(b, .{ .target = b.host }));
        }
    }

    return macho_step;
}

fn test_dead_strip(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "dead-strip", opts);

    const obj = add_object(b, opts, .{ .name = "a", .cpp_source_bytes = 
    \\#include <stdio.h>
    \\int two() { return 2; }
    \\int live_var1 = 1;
    \\int live_var2 = two();
    \\int dead_var1 = 3;
    \\int dead_var2 = 4;
    \\void live_fn1() {}
    \\void live_fn2() { live_fn1(); }
    \\void dead_fn1() {}
    \\void dead_fn2() { dead_fn1(); }
    \\int main() {
    \\  printf("%d %d\n", live_var1, live_var2);
    \\  live_fn2();
    \\}
    });

    {
        const exe = add_executable(b, opts, .{ .name = "no_dead_strip" });
        exe.add_object(obj);
        exe.link_gc_sections = false;

        const check = exe.check_object();
        check.check_in_symtab();
        check.check_contains("live_var1");
        check.check_in_symtab();
        check.check_contains("live_var2");
        check.check_in_symtab();
        check.check_contains("dead_var1");
        check.check_in_symtab();
        check.check_contains("dead_var2");
        check.check_in_symtab();
        check.check_contains("live_fn1");
        check.check_in_symtab();
        check.check_contains("live_fn2");
        check.check_in_symtab();
        check.check_contains("dead_fn1");
        check.check_in_symtab();
        check.check_contains("dead_fn2");
        test_step.depend_on(&check.step);

        const run = add_run_artifact(exe);
        run.expect_std_out_equal("1 2\n");
        test_step.depend_on(&run.step);
    }

    {
        const exe = add_executable(b, opts, .{ .name = "yes_dead_strip" });
        exe.add_object(obj);
        exe.link_gc_sections = true;

        const check = exe.check_object();
        check.check_in_symtab();
        check.check_contains("live_var1");
        check.check_in_symtab();
        check.check_contains("live_var2");
        check.check_in_symtab();
        check.check_not_present("dead_var1");
        check.check_in_symtab();
        check.check_not_present("dead_var2");
        check.check_in_symtab();
        check.check_contains("live_fn1");
        check.check_in_symtab();
        check.check_contains("live_fn2");
        check.check_in_symtab();
        check.check_not_present("dead_fn1");
        check.check_in_symtab();
        check.check_not_present("dead_fn2");
        test_step.depend_on(&check.step);

        const run = add_run_artifact(exe);
        run.expect_std_out_equal("1 2\n");
        test_step.depend_on(&run.step);
    }

    return test_step;
}

fn test_dead_strip_dylibs(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "dead-strip-dylibs", opts);

    const main_o = add_object(b, opts, .{ .name = "main", .c_source_bytes = 
    \\#include <objc/runtime.h>
    \\int main() {
    \\  if (objc_getClass("NSObject") == 0) {
    \\    return -1;
    \\  }
    \\  if (objc_getClass("NSApplication") == 0) {
    \\    return -2;
    \\  }
    \\  return 0;
    \\}
    });

    {
        const exe = add_executable(b, opts, .{ .name = "main1" });
        exe.add_object(main_o);
        exe.root_module.link_framework("Cocoa", .{});

        const check = exe.check_object();
        check.check_in_headers();
        check.check_exact("cmd LOAD_DYLIB");
        check.check_contains("Cocoa");
        check.check_in_headers();
        check.check_exact("cmd LOAD_DYLIB");
        check.check_contains("libobjc");
        test_step.depend_on(&check.step);

        const run = add_run_artifact(exe);
        run.expect_exit_code(0);
        test_step.depend_on(&run.step);
    }

    {
        const exe = add_executable(b, opts, .{ .name = "main2" });
        exe.add_object(main_o);
        exe.root_module.link_framework("Cocoa", .{});
        exe.dead_strip_dylibs = true;

        const run = add_run_artifact(exe);
        run.expect_exit_code(@as(u8, @bit_cast(@as(i8, -2))));
        test_step.depend_on(&run.step);
    }

    return test_step;
}

fn test_dylib(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "dylib", opts);

    const dylib = add_shared_library(b, opts, .{ .name = "a", .c_source_bytes = 
    \\#include<stdio.h>
    \\char world[] = "world";
    \\char* hello() {
    \\  return "Hello";
    \\}
    });

    const check = dylib.check_object();
    check.check_in_headers();
    check.check_exact("header");
    check.check_not_present("PIE");
    test_step.depend_on(&check.step);

    const exe = add_executable(b, opts, .{ .name = "main", .c_source_bytes = 
    \\#include<stdio.h>
    \\char* hello();
    \\extern char world[];
    \\int main() {
    \\  printf("%s %s", hello(), world);
    \\  return 0;
    \\}
    });
    exe.root_module.link_system_library("a", .{});
    exe.root_module.add_library_path(dylib.get_emitted_bin_directory());
    exe.root_module.add_rpath(dylib.get_emitted_bin_directory());

    const run = add_run_artifact(exe);
    run.expect_std_out_equal("Hello world");
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_dylib_version_tbd(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "dylib-version-tbd", opts);

    const tbd = tbd: {
        const wf = WriteFile.create(b);
        break :tbd wf.add("liba.tbd",
            \\--- !tapi-tbd
            \\tbd-version:     4
            \\targets:         [ x86_64-macos, arm64-macos ]
            \\uuids:
            \\  - target:          x86_64-macos
            \\    value:           DEADBEEF
            \\  - target:          arm64-macos
            \\    value:           BEEFDEAD
            \\install-name:    '@rpath/liba.dylib'
            \\current-version: 1.2
            \\exports:
            \\  - targets:     [ x86_64-macos, arm64-macos ]
            \\    symbols:     [ _foo ]
        );
    };

    const exe = add_executable(b, opts, .{ .name = "main", .c_source_bytes = "int main() {}" });
    exe.root_module.link_system_library("a", .{});
    exe.root_module.add_library_path(tbd.dirname());

    const check = exe.check_object();
    check.check_in_headers();
    check.check_exact("cmd LOAD_DYLIB");
    check.check_exact("name @rpath/liba.dylib");
    check.check_exact("current version 10200");
    test_step.depend_on(&check.step);

    return test_step;
}

fn test_empty_object(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "empty-object", opts);

    const empty = add_object(b, opts, .{ .name = "empty", .c_source_bytes = "" });

    const exe = add_executable(b, opts, .{ .name = "main", .c_source_bytes = 
    \\#include <stdio.h>
    \\int main() {
    \\  printf("Hello world!");
    \\}
    });
    exe.add_object(empty);

    const run = add_run_artifact(exe);
    run.expect_std_out_equal("Hello world!");
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_empty_zig(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "empty-zig", opts);

    const exe = add_executable(b, opts, .{ .name = "empty", .zig_source_bytes = "pub fn main() void {}" });

    const run = add_run_artifact(exe);
    run.expect_exit_code(0);
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_entry_point(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "entry-point", opts);

    const exe = add_executable(b, opts, .{ .name = "main", .c_source_bytes = 
    \\#include<stdio.h>
    \\int non_main() {
    \\  printf("%d", 42);
    \\  return 0;
    \\}
    });
    exe.entry = .{ .symbol_name = "_non_main" };

    const run = add_run_artifact(exe);
    run.expect_std_out_equal("42");
    test_step.depend_on(&run.step);

    const check = exe.check_object();
    check.check_in_headers();
    check.check_exact("segname __TEXT");
    check.check_extract("vmaddr {vmaddr}");
    check.check_in_headers();
    check.check_exact("cmd MAIN");
    check.check_extract("entryoff {entryoff}");
    check.check_in_symtab();
    check.check_extract("{n_value} (__TEXT,__text) external _non_main");
    check.check_compute_compare("vmaddr entryoff +", .{ .op = .eq, .value = .{ .variable = "n_value" } });
    test_step.depend_on(&check.step);

    return test_step;
}

fn test_entry_point_archive(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "entry-point-archive", opts);

    const lib = add_static_library(b, opts, .{ .name = "main", .c_source_bytes = "int main() { return 0; }" });

    {
        const exe = add_executable(b, opts, .{ .name = "main", .c_source_bytes = "" });
        exe.root_module.link_system_library("main", .{});
        exe.root_module.add_library_path(lib.get_emitted_bin_directory());

        const run = add_run_artifact(exe);
        run.expect_exit_code(0);
        test_step.depend_on(&run.step);
    }

    {
        const exe = add_executable(b, opts, .{ .name = "main", .c_source_bytes = "" });
        exe.root_module.link_system_library("main", .{});
        exe.root_module.add_library_path(lib.get_emitted_bin_directory());
        exe.link_gc_sections = true;

        const run = add_run_artifact(exe);
        run.expect_exit_code(0);
        test_step.depend_on(&run.step);
    }

    return test_step;
}

fn test_entry_point_dylib(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "entry-point-dylib", opts);

    const dylib = add_shared_library(b, opts, .{ .name = "a" });
    add_csource_bytes(dylib,
        \\extern int my_main();
        \\int bootstrap() {
        \\  return my_main();
        \\}
    , &.{});
    dylib.linker_allow_shlib_undefined = true;

    const exe = add_executable(b, opts, .{ .name = "main" });
    add_csource_bytes(dylib,
        \\#include<stdio.h>
        \\int my_main() {
        \\  fprintf(stdout, "Hello!\n");
        \\  return 0;
        \\}
    , &.{});
    exe.link_library(dylib);
    exe.entry = .{ .symbol_name = "_bootstrap" };
    exe.force_undefined_symbol("_my_main");

    const check = exe.check_object();
    check.check_in_headers();
    check.check_exact("segname __TEXT");
    check.check_extract("vmaddr {text_vmaddr}");
    check.check_in_headers();
    check.check_exact("sectname __stubs");
    check.check_extract("addr {stubs_vmaddr}");
    check.check_in_headers();
    check.check_exact("sectname __stubs");
    check.check_extract("size {stubs_vmsize}");
    check.check_in_headers();
    check.check_exact("cmd MAIN");
    check.check_extract("entryoff {entryoff}");
    check.check_compute_compare("text_vmaddr entryoff +", .{
        .op = .gte,
        .value = .{ .variable = "stubs_vmaddr" }, // The entrypoint should be a synthetic stub
    });
    check.check_compute_compare("text_vmaddr entryoff + stubs_vmaddr -", .{
        .op = .lt,
        .value = .{ .variable = "stubs_vmsize" }, // The entrypoint should be a synthetic stub
    });
    test_step.depend_on(&check.step);

    const run = add_run_artifact(exe);
    run.expect_std_out_equal("Hello!\n");
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_headerpad(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "headerpad", opts);

    const add_exe = struct {
        fn add_exe(bb: *Build, o: Options, name: []const u8) *Compile {
            const exe = add_executable(bb, o, .{
                .name = name,
                .c_source_bytes = "int main() { return 0; }",
            });
            exe.root_module.link_framework("CoreFoundation", .{});
            exe.root_module.link_framework("Foundation", .{});
            exe.root_module.link_framework("Cocoa", .{});
            exe.root_module.link_framework("CoreGraphics", .{});
            exe.root_module.link_framework("CoreHaptics", .{});
            exe.root_module.link_framework("CoreAudio", .{});
            exe.root_module.link_framework("AVFoundation", .{});
            exe.root_module.link_framework("CoreImage", .{});
            exe.root_module.link_framework("CoreLocation", .{});
            exe.root_module.link_framework("CoreML", .{});
            exe.root_module.link_framework("CoreVideo", .{});
            exe.root_module.link_framework("CoreText", .{});
            exe.root_module.link_framework("CryptoKit", .{});
            exe.root_module.link_framework("GameKit", .{});
            exe.root_module.link_framework("SwiftUI", .{});
            exe.root_module.link_framework("StoreKit", .{});
            exe.root_module.link_framework("SpriteKit", .{});
            return exe;
        }
    }.add_exe;

    {
        const exe = add_exe(b, opts, "main1");
        exe.headerpad_max_install_names = true;

        const check = exe.check_object();
        check.check_in_headers();
        check.check_exact("sectname __text");
        check.check_extract("offset {offset}");
        switch (opts.target.result.cpu.arch) {
            .aarch64 => check.check_compute_compare("offset", .{ .op = .gte, .value = .{ .literal = 0x4000 } }),
            .x86_64 => check.check_compute_compare("offset", .{ .op = .gte, .value = .{ .literal = 0x1000 } }),
            else => unreachable,
        }
        test_step.depend_on(&check.step);

        const run = add_run_artifact(exe);
        run.expect_exit_code(0);
        test_step.depend_on(&run.step);
    }

    {
        const exe = add_exe(b, opts, "main2");
        exe.headerpad_size = 0x10000;

        const check = exe.check_object();
        check.check_in_headers();
        check.check_exact("sectname __text");
        check.check_extract("offset {offset}");
        check.check_compute_compare("offset", .{ .op = .gte, .value = .{ .literal = 0x10000 } });
        test_step.depend_on(&check.step);

        const run = add_run_artifact(exe);
        run.expect_exit_code(0);
        test_step.depend_on(&run.step);
    }

    {
        const exe = add_exe(b, opts, "main3");
        exe.headerpad_max_install_names = true;
        exe.headerpad_size = 0x10000;

        const check = exe.check_object();
        check.check_in_headers();
        check.check_exact("sectname __text");
        check.check_extract("offset {offset}");
        check.check_compute_compare("offset", .{ .op = .gte, .value = .{ .literal = 0x10000 } });
        test_step.depend_on(&check.step);

        const run = add_run_artifact(exe);
        run.expect_exit_code(0);
        test_step.depend_on(&run.step);
    }

    {
        const exe = add_exe(b, opts, "main4");
        exe.headerpad_max_install_names = true;
        exe.headerpad_size = 0x1000;

        const check = exe.check_object();
        check.check_in_headers();
        check.check_exact("sectname __text");
        check.check_extract("offset {offset}");
        switch (opts.target.result.cpu.arch) {
            .aarch64 => check.check_compute_compare("offset", .{ .op = .gte, .value = .{ .literal = 0x4000 } }),
            .x86_64 => check.check_compute_compare("offset", .{ .op = .gte, .value = .{ .literal = 0x1000 } }),
            else => unreachable,
        }
        test_step.depend_on(&check.step);

        const run = add_run_artifact(exe);
        run.expect_exit_code(0);
        test_step.depend_on(&run.step);
    }

    return test_step;
}

// Adapted from https://github.com/llvm/llvm-project/blob/main/lld/test/MachO/weak-header-flags.s
fn test_header_weak_flags(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "header-weak-flags", opts);

    const obj1 = add_object(b, opts, .{ .name = "a", .asm_source_bytes = 
    \\.globl _x
    \\.weak_definition _x
    \\_x:
    \\ ret
    });

    const lib = add_shared_library(b, opts, .{ .name = "a" });
    lib.add_object(obj1);

    {
        const exe = add_executable(b, opts, .{ .name = "main1", .c_source_bytes = "int main() { return 0; }" });
        exe.add_object(obj1);

        const check = exe.check_object();
        check.check_in_headers();
        check.check_exact("header");
        check.check_contains("WEAK_DEFINES");
        check.check_in_headers();
        check.check_exact("header");
        check.check_contains("BINDS_TO_WEAK");
        check.check_in_exports();
        check.check_extract("[WEAK] {vmaddr} _x");
        test_step.depend_on(&check.step);
    }

    {
        const obj = add_object(b, opts, .{ .name = "b" });

        switch (opts.target.result.cpu.arch) {
            .aarch64 => add_asm_source_bytes(obj,
                \\.globl _main
                \\_main:
                \\  bl _x
                \\  ret
            ),
            .x86_64 => add_asm_source_bytes(obj,
                \\.globl _main
                \\_main:
                \\  callq _x
                \\  ret
            ),
            else => unreachable,
        }

        const exe = add_executable(b, opts, .{ .name = "main2" });
        exe.link_library(lib);
        exe.add_object(obj);

        const check = exe.check_object();
        check.check_in_headers();
        check.check_exact("header");
        check.check_not_present("WEAK_DEFINES");
        check.check_in_headers();
        check.check_exact("header");
        check.check_contains("BINDS_TO_WEAK");
        check.check_in_exports();
        check.check_not_present("[WEAK] {vmaddr} _x");
        test_step.depend_on(&check.step);
    }

    {
        const exe = add_executable(b, opts, .{ .name = "main3", .asm_source_bytes = 
        \\.globl _main, _x
        \\_x:
        \\
        \\_main:
        \\  ret
        });
        exe.link_library(lib);

        const check = exe.check_object();
        check.check_in_headers();
        check.check_exact("header");
        check.check_not_present("WEAK_DEFINES");
        check.check_in_headers();
        check.check_exact("header");
        check.check_not_present("BINDS_TO_WEAK");
        test_step.depend_on(&check.step);
    }

    return test_step;
}

fn test_hello_c(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "hello-c", opts);

    const exe = add_executable(b, opts, .{ .name = "main", .c_source_bytes = 
    \\#include <stdio.h>
    \\int main() { 
    \\  printf("Hello world!\n");
    \\  return 0;
    \\}
    });

    const run = add_run_artifact(exe);
    run.expect_std_out_equal("Hello world!\n");
    test_step.depend_on(&run.step);

    const check = exe.check_object();
    check.check_in_headers();
    check.check_exact("header");
    check.check_contains("PIE");
    test_step.depend_on(&check.step);

    return test_step;
}

fn test_hello_zig(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "hello-zig", opts);

    const exe = add_executable(b, opts, .{ .name = "main", .zig_source_bytes = 
    \\const std = @import("std");
    \\pub fn main() void {
    \\    std.io.get_std_out().writer().print("Hello world!\n", .{}) catch unreachable;
    \\}
    });

    const run = add_run_artifact(exe);
    run.expect_std_out_equal("Hello world!\n");
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_large_bss(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "large-bss", opts);

    // TODO this test used use a 4GB zerofill section but this actually fails and causes every
    // linker I tried misbehave in different ways. This only happened on arm64. I thought that
    // maybe S_GB_ZEROFILL section is an answer to this but it doesn't seem supported by dyld
    // anymore. When I get some free time I will re-investigate this.
    const exe = add_executable(b, opts, .{ .name = "main", .c_source_bytes = 
    \\char arr[0x1000000];
    \\int main() {
    \\  return arr[2000];
    \\}
    });

    const run = add_run_artifact(exe);
    run.expect_exit_code(0);
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_layout(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "layout", opts);

    const exe = add_executable(b, opts, .{ .name = "main", .c_source_bytes = 
    \\#include <stdio.h>
    \\int main() {
    \\  printf("Hello world!");
    \\  return 0;
    \\}
    });

    const check = exe.check_object();
    check.check_in_headers();
    check.check_exact("cmd SEGMENT_64");
    check.check_exact("segname __LINKEDIT");
    check.check_extract("fileoff {fileoff}");
    check.check_extract("filesz {filesz}");
    check.check_in_headers();
    check.check_exact("cmd DYLD_INFO_ONLY");
    check.check_extract("rebaseoff {rebaseoff}");
    check.check_extract("rebasesize {rebasesize}");
    check.check_extract("bindoff {bindoff}");
    check.check_extract("bindsize {bindsize}");
    check.check_extract("lazybindoff {lazybindoff}");
    check.check_extract("lazybindsize {lazybindsize}");
    check.check_extract("exportoff {exportoff}");
    check.check_extract("exportsize {exportsize}");
    check.check_in_headers();
    check.check_exact("cmd FUNCTION_STARTS");
    check.check_extract("dataoff {fstartoff}");
    check.check_extract("datasize {fstartsize}");
    check.check_in_headers();
    check.check_exact("cmd DATA_IN_CODE");
    check.check_extract("dataoff {diceoff}");
    check.check_extract("datasize {dicesize}");
    check.check_in_headers();
    check.check_exact("cmd SYMTAB");
    check.check_extract("symoff {symoff}");
    check.check_extract("nsyms {symnsyms}");
    check.check_extract("stroff {stroff}");
    check.check_extract("strsize {strsize}");
    check.check_in_headers();
    check.check_exact("cmd DYSYMTAB");
    check.check_extract("indirectsymoff {dysymoff}");
    check.check_extract("nindirectsyms {dysymnsyms}");

    switch (opts.target.result.cpu.arch) {
        .aarch64 => {
            check.check_in_headers();
            check.check_exact("cmd CODE_SIGNATURE");
            check.check_extract("dataoff {codesigoff}");
            check.check_extract("datasize {codesigsize}");
        },
        .x86_64 => {},
        else => unreachable,
    }

    // DYLD_INFO_ONLY subsections are in order: rebase < bind < lazy < export,
    // and there are no gaps between them
    check.check_compute_compare("rebaseoff rebasesize +", .{ .op = .eq, .value = .{ .variable = "bindoff" } });
    check.check_compute_compare("bindoff bindsize +", .{ .op = .eq, .value = .{ .variable = "lazybindoff" } });
    check.check_compute_compare("lazybindoff lazybindsize +", .{ .op = .eq, .value = .{ .variable = "exportoff" } });

    // FUNCTION_STARTS directly follows DYLD_INFO_ONLY (no gap)
    check.check_compute_compare("exportoff exportsize +", .{ .op = .eq, .value = .{ .variable = "fstartoff" } });

    // DATA_IN_CODE directly follows FUNCTION_STARTS (no gap)
    check.check_compute_compare("fstartoff fstartsize +", .{ .op = .eq, .value = .{ .variable = "diceoff" } });

    // SYMTAB directly follows DATA_IN_CODE (no gap)
    check.check_compute_compare("diceoff dicesize +", .{ .op = .eq, .value = .{ .variable = "symoff" } });

    // DYSYMTAB directly follows SYMTAB (no gap)
    check.check_compute_compare("symnsyms 16 symoff * +", .{ .op = .eq, .value = .{ .variable = "dysymoff" } });

    // STRTAB follows DYSYMTAB with possible gap
    check.check_compute_compare("dysymnsyms 4 dysymoff * +", .{ .op = .lte, .value = .{ .variable = "stroff" } });

    // all LINKEDIT sections apart from CODE_SIGNATURE are 8-bytes aligned
    check.check_compute_compare("rebaseoff 8 %", .{ .op = .eq, .value = .{ .literal = 0 } });
    check.check_compute_compare("bindoff 8 %", .{ .op = .eq, .value = .{ .literal = 0 } });
    check.check_compute_compare("lazybindoff 8 %", .{ .op = .eq, .value = .{ .literal = 0 } });
    check.check_compute_compare("exportoff 8 %", .{ .op = .eq, .value = .{ .literal = 0 } });
    check.check_compute_compare("fstartoff 8 %", .{ .op = .eq, .value = .{ .literal = 0 } });
    check.check_compute_compare("diceoff 8 %", .{ .op = .eq, .value = .{ .literal = 0 } });
    check.check_compute_compare("symoff 8 %", .{ .op = .eq, .value = .{ .literal = 0 } });
    check.check_compute_compare("stroff 8 %", .{ .op = .eq, .value = .{ .literal = 0 } });
    check.check_compute_compare("dysymoff 8 %", .{ .op = .eq, .value = .{ .literal = 0 } });

    switch (opts.target.result.cpu.arch) {
        .aarch64 => {
            // LINKEDIT segment does not extend beyond, or does not include, CODE_SIGNATURE data
            check.check_compute_compare("fileoff filesz codesigoff codesigsize + - -", .{
                .op = .eq,
                .value = .{ .literal = 0 },
            });

            // CODE_SIGNATURE data offset is 16-bytes aligned
            check.check_compute_compare("codesigoff 16 %", .{ .op = .eq, .value = .{ .literal = 0 } });
        },
        .x86_64 => {
            // LINKEDIT segment does not extend beyond, or does not include, strtab data
            check.check_compute_compare("fileoff filesz stroff strsize + - -", .{
                .op = .eq,
                .value = .{ .literal = 0 },
            });
        },
        else => unreachable,
    }

    test_step.depend_on(&check.step);

    const run = add_run_artifact(exe);
    run.expect_std_out_equal("Hello world!");
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_link_directly_cpp_tbd(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "link-directly-cpp-tbd", opts);

    const sdk = std.zig.system.darwin.get_sdk(b.allocator, opts.target.result) orelse
        @panic("macOS SDK is required to run the test");

    const exe = add_executable(b, opts, .{
        .name = "main",
        .cpp_source_bytes =
        \\#include <new>
        \\#include <cstdio>
        \\int main() {
        \\    int *x = new int;
        \\    *x = 5;
        \\    fprintf(stderr, "x: %d\n", *x);
        \\    delete x;
        \\}
        ,
        .cpp_source_flags = &.{ "-nostdlib++", "-nostdinc++" },
    });
    exe.root_module.add_system_include_path(.{ .cwd_relative = b.path_join(&.{ sdk, "/usr/include" }) });
    exe.root_module.add_include_path(.{ .cwd_relative = b.path_join(&.{ sdk, "/usr/include/c++/v1" }) });
    exe.root_module.add_object_file(.{ .cwd_relative = b.path_join(&.{ sdk, "/usr/lib/libc++.tbd" }) });

    const check = exe.check_object();
    check.check_in_symtab();
    check.check_contains("[referenced dynamically] external __mh_execute_header");
    test_step.depend_on(&check.step);

    return test_step;
}

fn test_linking_static_lib(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "linking-static-lib", opts);

    const obj = add_object(b, opts, .{
        .name = "bobj",
        .zig_source_bytes = "export var bar: i32 = -42;",
        .strip = true, // TODO for self-hosted, we don't really emit any valid DWARF yet since we only export a global
    });

    const lib = add_static_library(b, opts, .{
        .name = "alib",
        .zig_source_bytes =
        \\export fn foo() i32 {
        \\    return 42;
        \\}
        ,
    });
    lib.add_object(obj);

    const exe = add_executable(b, opts, .{
        .name = "testlib",
        .zig_source_bytes =
        \\const std = @import("std");
        \\extern fn foo() i32;
        \\extern var bar: i32;
        \\pub fn main() void {
        \\    std.debug.print("{d}\n", .{foo() + bar});
        \\}
        ,
    });
    exe.link_library(lib);

    const run = add_run_artifact(exe);
    run.expect_std_err_equal("0\n");
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_linksection(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "linksection", opts);

    const obj = add_object(b, opts, .{ .name = "main", .zig_source_bytes = 
    \\export var test_global: u32 linksection("__DATA,__TestGlobal") = undefined;
    \\export fn test_fn() linksection("__TEXT,__TestFn") callconv(.C) void {
    \\    test_generic_fn("A");
    \\}
    \\fn test_generic_fn(comptime suffix: []const u8) linksection("__TEXT,__TestGenFn" ++ suffix) void {}
    });

    const check = obj.check_object();
    check.check_in_symtab();
    check.check_contains("(__DATA,__TestGlobal) external _test_global");
    check.check_in_symtab();
    check.check_contains("(__TEXT,__TestFn) external _testFn");

    if (opts.optimize == .Debug) {
        check.check_in_symtab();
        check.check_contains("(__TEXT,__TestGenFnA) _a.testGenericFn__anon_");
    }

    test_step.depend_on(&check.step);

    return test_step;
}

fn test_merge_literals_x64(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "merge-literals-x64", opts);

    const a_o = add_object(b, opts, .{ .name = "a", .asm_source_bytes = 
    \\.globl _q1
    \\.globl _s1
    \\
    \\.align 4
    \\_q1:
    \\  lea L._q1(%rip), %rax
    \\  mov (%rax), %xmm0
    \\  ret
    \\ 
    \\.section __TEXT,__cstring,cstring_literals
    \\l._s1:
    \\  .asciz "hello"
    \\
    \\.section __TEXT,__literal8,8byte_literals
    \\.align 8
    \\L._q1:
    \\  .double 1.2345
    \\
    \\.section __DATA,__data
    \\.align 8
    \\_s1:
    \\  .quad l._s1
    });

    const b_o = add_object(b, opts, .{ .name = "b", .asm_source_bytes = 
    \\.globl _q2
    \\.globl _s2
    \\.globl _s3
    \\
    \\.align 4
    \\_q2:
    \\  lea L._q2(%rip), %rax
    \\  mov (%rax), %xmm0
    \\  ret
    \\ 
    \\.section __TEXT,__cstring,cstring_literals
    \\l._s2:
    \\  .asciz "hello"
    \\l._s3:
    \\  .asciz "world"
    \\
    \\.section __TEXT,__literal8,8byte_literals
    \\.align 8
    \\L._q2:
    \\  .double 1.2345
    \\
    \\.section __DATA,__data
    \\.align 8
    \\_s2:
    \\   .quad l._s2
    \\_s3:
    \\   .quad l._s3
    });

    const main_o = add_object(b, opts, .{ .name = "main", .c_source_bytes = 
    \\#include <stdio.h>
    \\extern double q1();
    \\extern double q2();
    \\extern const char* s1;
    \\extern const char* s2;
    \\extern const char* s3;
    \\int main() {
    \\  printf("%s, %s, %s, %f, %f", s1, s2, s3, q1(), q2());
    \\  return 0;
    \\}
    });

    const run_with_checks = struct {
        fn run_with_checks(step: *Step, exe: *Compile) void {
            const run = add_run_artifact(exe);
            run.expect_std_out_equal("hello, hello, world, 1.234500, 1.234500");
            step.depend_on(&run.step);

            const check = exe.check_object();
            check.dump_section("__TEXT,__const");
            check.check_contains("\x8d\x97n\x12\x83\xc0\xf3?");
            check.dump_section("__TEXT,__cstring");
            check.check_contains("hello\x00world\x00%s, %s, %s, %f, %f\x00");
            step.depend_on(&check.step);
        }
    }.run_with_checks;

    {
        const exe = add_executable(b, opts, .{ .name = "main1" });
        exe.add_object(a_o);
        exe.add_object(b_o);
        exe.add_object(main_o);
        run_with_checks(test_step, exe);
    }

    {
        const exe = add_executable(b, opts, .{ .name = "main2" });
        exe.add_object(b_o);
        exe.add_object(a_o);
        exe.add_object(main_o);
        run_with_checks(test_step, exe);
    }

    {
        const c_o = add_object(b, opts, .{ .name = "c" });
        c_o.add_object(a_o);
        c_o.add_object(b_o);
        c_o.add_object(main_o);

        const exe = add_executable(b, opts, .{ .name = "main3" });
        exe.add_object(c_o);
        run_with_checks(test_step, exe);
    }

    return test_step;
}

fn test_merge_literals_arm64(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "merge-literals-arm64", opts);

    const a_o = add_object(b, opts, .{ .name = "a", .asm_source_bytes = 
    \\.globl _q1
    \\.globl _s1
    \\
    \\.align 4
    \\_q1:
    \\  adrp x8, L._q1@PAGE
    \\  ldr d0, [x8, L._q1@PAGEOFF]
    \\  ret
    \\ 
    \\.section __TEXT,__cstring,cstring_literals
    \\l._s1:
    \\  .asciz "hello"
    \\
    \\.section __TEXT,__literal8,8byte_literals
    \\.align 8
    \\L._q1:
    \\  .double 1.2345
    \\
    \\.section __DATA,__data
    \\.align 8
    \\_s1:
    \\  .quad l._s1
    });

    const b_o = add_object(b, opts, .{ .name = "b", .asm_source_bytes = 
    \\.globl _q2
    \\.globl _s2
    \\.globl _s3
    \\
    \\.align 4
    \\_q2:
    \\  adrp x8, L._q2@PAGE
    \\  ldr d0, [x8, L._q2@PAGEOFF]
    \\  ret
    \\ 
    \\.section __TEXT,__cstring,cstring_literals
    \\l._s2:
    \\  .asciz "hello"
    \\l._s3:
    \\  .asciz "world"
    \\
    \\.section __TEXT,__literal8,8byte_literals
    \\.align 8
    \\L._q2:
    \\  .double 1.2345
    \\
    \\.section __DATA,__data
    \\.align 8
    \\_s2:
    \\   .quad l._s2
    \\_s3:
    \\   .quad l._s3
    });

    const main_o = add_object(b, opts, .{ .name = "main", .c_source_bytes = 
    \\#include <stdio.h>
    \\extern double q1();
    \\extern double q2();
    \\extern const char* s1;
    \\extern const char* s2;
    \\extern const char* s3;
    \\int main() {
    \\  printf("%s, %s, %s, %f, %f", s1, s2, s3, q1(), q2());
    \\  return 0;
    \\}
    });

    const run_with_checks = struct {
        fn run_with_checks(step: *Step, exe: *Compile) void {
            const run = add_run_artifact(exe);
            run.expect_std_out_equal("hello, hello, world, 1.234500, 1.234500");
            step.depend_on(&run.step);

            const check = exe.check_object();
            check.dump_section("__TEXT,__const");
            check.check_contains("\x8d\x97n\x12\x83\xc0\xf3?");
            check.dump_section("__TEXT,__cstring");
            check.check_contains("hello\x00world\x00%s, %s, %s, %f, %f\x00");
            step.depend_on(&check.step);
        }
    }.run_with_checks;

    {
        const exe = add_executable(b, opts, .{ .name = "main1" });
        exe.add_object(a_o);
        exe.add_object(b_o);
        exe.add_object(main_o);
        run_with_checks(test_step, exe);
    }

    {
        const exe = add_executable(b, opts, .{ .name = "main2" });
        exe.add_object(b_o);
        exe.add_object(a_o);
        exe.add_object(main_o);
        run_with_checks(test_step, exe);
    }

    {
        const c_o = add_object(b, opts, .{ .name = "c" });
        c_o.add_object(a_o);
        c_o.add_object(b_o);
        c_o.add_object(main_o);

        const exe = add_executable(b, opts, .{ .name = "main3" });
        exe.add_object(c_o);
        run_with_checks(test_step, exe);
    }

    return test_step;
}

/// This particular test case will generate invalid machine code that will segfault at runtime.
/// However, this is by design as we want to test that the linker does not panic when linking it
/// which is also the case for the system linker and lld - linking succeeds, runtime segfaults.
/// It should also be mentioned that runtime segfault is not due to the linker but faulty input asm.
fn test_merge_literals_arm642(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "merge-literals-arm64-2", opts);

    const a_o = add_object(b, opts, .{ .name = "a", .asm_source_bytes = 
    \\.globl _q1
    \\.globl _s1
    \\
    \\.align 4
    \\_q1:
    \\  adrp x0, L._q1@PAGE
    \\  ldr x0, [x0, L._q1@PAGEOFF]
    \\  ret
    \\ 
    \\.section __TEXT,__cstring,cstring_literals
    \\_s1:
    \\  .asciz "hello"
    \\
    \\.section __TEXT,__literal8,8byte_literals
    \\.align 8
    \\L._q1:
    \\  .double 1.2345
    });

    const b_o = add_object(b, opts, .{ .name = "b", .asm_source_bytes = 
    \\.globl _q2
    \\.globl _s2
    \\.globl _s3
    \\
    \\.align 4
    \\_q2:
    \\  adrp x0, L._q2@PAGE
    \\  ldr x0, [x0, L._q2@PAGEOFF]
    \\  ret
    \\ 
    \\.section __TEXT,__cstring,cstring_literals
    \\_s2:
    \\  .asciz "hello"
    \\_s3:
    \\  .asciz "world"
    \\
    \\.section __TEXT,__literal8,8byte_literals
    \\.align 8
    \\L._q2:
    \\  .double 1.2345
    });

    const main_o = add_object(b, opts, .{ .name = "main", .c_source_bytes = 
    \\#include <stdio.h>
    \\extern double q1();
    \\extern double q2();
    \\extern const char* s1;
    \\extern const char* s2;
    \\extern const char* s3;
    \\int main() {
    \\  printf("%s, %s, %s, %f, %f", s1, s2, s3, q1(), q2());
    \\  return 0;
    \\}
    });

    const exe = add_executable(b, opts, .{ .name = "main1" });
    exe.add_object(a_o);
    exe.add_object(b_o);
    exe.add_object(main_o);

    const check = exe.check_object();
    check.dump_section("__TEXT,__const");
    check.check_contains("\x8d\x97n\x12\x83\xc0\xf3?");
    check.dump_section("__TEXT,__cstring");
    check.check_contains("hello\x00world\x00%s, %s, %s, %f, %f\x00");
    test_step.depend_on(&check.step);

    return test_step;
}

fn test_merge_literals_alignment(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "merge-literals-alignment", opts);

    const a_o = add_object(b, opts, .{ .name = "a", .asm_source_bytes = 
    \\.globl _s1
    \\.globl _s2
    \\
    \\.section __TEXT,__cstring,cstring_literals
    \\.align 3
    \\_s1:
    \\  .asciz "str1"
    \\_s2:
    \\  .asciz "str2"
    });

    const b_o = add_object(b, opts, .{ .name = "b", .asm_source_bytes = 
    \\.globl _s3
    \\.globl _s4
    \\
    \\.section __TEXT,__cstring,cstring_literals
    \\.align 2
    \\_s3:
    \\  .asciz "str1"
    \\_s4:
    \\  .asciz "str2"
    });

    const main_o = add_object(b, opts, .{ .name = "main", .c_source_bytes = 
    \\#include <assert.h>
    \\#include <stdint.h>
    \\#include <stdio.h>
    \\extern const char* s1;
    \\extern const char* s2;
    \\extern const char* s3;
    \\extern const char* s4;
    \\int main() {
    \\  assert((uintptr_t)(&s1) % 8 == 0 && s1 == s3);
    \\  assert((uintptr_t)(&s2) % 8 == 0 && s2 == s4);
    \\  printf("%s%s%s%s", &s1, &s2, &s3, &s4);
    \\  return 0;
    \\}
    , .c_source_flags = &.{"-Wno-format"} });

    const run_with_checks = struct {
        fn run_with_checks(step: *Step, exe: *Compile) void {
            const run = add_run_artifact(exe);
            run.expect_std_out_equal("str1str2str1str2");
            step.depend_on(&run.step);

            const check = exe.check_object();
            check.dump_section("__TEXT,__cstring");
            check.check_contains("str1\x00\x00\x00\x00str2\x00");
            check.check_in_headers();
            check.check_exact("segname __TEXT");
            check.check_exact("sectname __cstring");
            check.check_exact("align 3");
            step.depend_on(&check.step);
        }
    }.run_with_checks;

    {
        const exe = add_executable(b, opts, .{ .name = "main1" });
        exe.add_object(a_o);
        exe.add_object(b_o);
        exe.add_object(main_o);
        run_with_checks(test_step, exe);
    }

    {
        const exe = add_executable(b, opts, .{ .name = "main2" });
        exe.add_object(b_o);
        exe.add_object(a_o);
        exe.add_object(main_o);
        run_with_checks(test_step, exe);
    }

    return test_step;
}

fn test_merge_literals_objc(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "merge-literals-objc", opts);

    const main_o = add_object(b, opts, .{ .name = "main", .objc_source_bytes = 
    \\#import <Foundation/Foundation.h>;
    \\
    \\extern void foo();
    \\
    \\int main() {
    \\  NSString *thing = @"aaa";
    \\
    \\  SEL sel = @selector(lowercaseString);
    \\  NSString *lower = (([thing respondsToSelector:sel]) ? @"YES" : @"NO");
    \\  NSLog (@"Responds to lowercaseString: %@", lower);
    \\  if ([thing respondsToSelector:sel]) //(lower == @"YES")
    \\      NSLog(@"lowercaseString is: %@", [thing lowercaseString]);
    \\
    \\  foo();
    \\}
    });

    const a_o = add_object(b, opts, .{ .name = "a", .objc_source_bytes = 
    \\#import <Foundation/Foundation.h>;
    \\
    \\void foo() {
    \\  NSString *thing = @"aaa";
    \\  SEL sel = @selector(lowercaseString);
    \\  NSString *lower = (([thing respondsToSelector:sel]) ? @"YES" : @"NO");
    \\  NSLog (@"Responds to lowercaseString in foo(): %@", lower);
    \\  if ([thing respondsToSelector:sel]) //(lower == @"YES")
    \\      NSLog(@"lowercaseString in foo() is: %@", [thing lowercaseString]);
    \\  SEL sel2 = @selector(uppercaseString);
    \\  NSString *upper = (([thing respondsToSelector:sel2]) ? @"YES" : @"NO");
    \\  NSLog (@"Responds to uppercaseString in foo(): %@", upper);
    \\  if ([thing respondsToSelector:sel2]) //(upper == @"YES")
    \\      NSLog(@"uppercaseString in foo() is: %@", [thing uppercaseString]);
    \\}
    });

    const run_with_checks = struct {
        fn run_with_checks(step: *Step, exe: *Compile) void {
            const builder = step.owner;
            const run = add_run_artifact(exe);
            run.add_check(.{ .expect_stderr_match = builder.dupe("Responds to lowercaseString: YES") });
            run.add_check(.{ .expect_stderr_match = builder.dupe("lowercaseString is: aaa") });
            run.add_check(.{ .expect_stderr_match = builder.dupe("Responds to lowercaseString in foo(): YES") });
            run.add_check(.{ .expect_stderr_match = builder.dupe("lowercaseString in foo() is: aaa") });
            run.add_check(.{ .expect_stderr_match = builder.dupe("Responds to uppercaseString in foo(): YES") });
            run.add_check(.{ .expect_stderr_match = builder.dupe("uppercaseString in foo() is: AAA") });
            step.depend_on(&run.step);

            const check = exe.check_object();
            check.dump_section("__TEXT,__objc_methname");
            check.check_contains("lowercaseString\x00");
            check.dump_section("__TEXT,__objc_methname");
            check.check_contains("uppercaseString\x00");
            step.depend_on(&check.step);
        }
    }.run_with_checks;

    {
        const exe = add_executable(b, opts, .{ .name = "main1" });
        exe.add_object(main_o);
        exe.add_object(a_o);
        exe.root_module.link_framework("Foundation", .{});
        run_with_checks(test_step, exe);
    }

    {
        const exe = add_executable(b, opts, .{ .name = "main2" });
        exe.add_object(a_o);
        exe.add_object(main_o);
        exe.root_module.link_framework("Foundation", .{});
        run_with_checks(test_step, exe);
    }

    {
        const b_o = add_object(b, opts, .{ .name = "b" });
        b_o.add_object(a_o);
        b_o.add_object(main_o);

        const exe = add_executable(b, opts, .{ .name = "main3" });
        exe.add_object(b_o);
        exe.root_module.link_framework("Foundation", .{});
        run_with_checks(test_step, exe);
    }

    return test_step;
}

fn test_mh_execute_header(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "mh-execute-header", opts);

    const exe = add_executable(b, opts, .{ .name = "main", .c_source_bytes = "int main() { return 0; }" });

    const check = exe.check_object();
    check.check_in_symtab();
    check.check_contains("[referenced dynamically] external __mh_execute_header");
    test_step.depend_on(&check.step);

    return test_step;
}

fn test_no_dead_strip(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "no-dead-strip", opts);

    const exe = add_executable(b, opts, .{ .name = "name", .c_source_bytes = 
    \\__attribute__((used)) int bogus1 = 0;
    \\int bogus2 = 0;
    \\int foo = 42;
    \\int main() {
    \\  return foo - 42;
    \\}
    });
    exe.link_gc_sections = true;

    const check = exe.check_object();
    check.check_in_symtab();
    check.check_contains("external _bogus1");
    check.check_in_symtab();
    check.check_not_present("external _bogus2");
    test_step.depend_on(&check.step);

    const run = add_run_artifact(exe);
    run.expect_exit_code(0);
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_no_exports_dylib(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "no-exports-dylib", opts);

    const dylib = add_shared_library(b, opts, .{ .name = "a", .c_source_bytes = "static void abc() {}" });

    const check = dylib.check_object();
    check.check_in_symtab();
    check.check_not_present("external _abc");
    test_step.depend_on(&check.step);

    return test_step;
}

fn test_needed_framework(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "needed-framework", opts);

    const exe = add_executable(b, opts, .{ .name = "main", .c_source_bytes = "int main() { return 0; }" });
    exe.root_module.link_framework("Cocoa", .{ .needed = true });
    exe.dead_strip_dylibs = true;

    const check = exe.check_object();
    check.check_in_headers();
    check.check_exact("cmd LOAD_DYLIB");
    check.check_contains("Cocoa");
    test_step.depend_on(&check.step);

    const run = add_run_artifact(exe);
    run.expect_exit_code(0);
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_needed_library(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "needed-library", opts);

    const dylib = add_shared_library(b, opts, .{ .name = "a", .c_source_bytes = "int a = 42;" });

    const exe = add_executable(b, opts, .{ .name = "main", .c_source_bytes = "int main() { return 0; }" });
    exe.root_module.link_system_library("a", .{ .needed = true });
    exe.root_module.add_library_path(dylib.get_emitted_bin_directory());
    exe.root_module.add_rpath(dylib.get_emitted_bin_directory());
    exe.dead_strip_dylibs = true;

    const check = exe.check_object();
    check.check_in_headers();
    check.check_exact("cmd LOAD_DYLIB");
    check.check_contains("liba.dylib");
    test_step.depend_on(&check.step);

    const run = add_run_artifact(exe);
    run.expect_exit_code(0);
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_objc(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "objc", opts);

    const lib = add_static_library(b, opts, .{ .name = "a", .objc_source_bytes = 
    \\#import <Foundation/Foundation.h>
    \\@interface Foo : NSObject
    \\@end
    \\@implementation Foo
    \\@end
    });

    {
        const exe = add_executable(b, opts, .{ .name = "main", .c_source_bytes = "int main() { return 0; }" });
        exe.root_module.link_system_library("a", .{});
        exe.root_module.link_framework("Foundation", .{});
        exe.root_module.add_library_path(lib.get_emitted_bin_directory());

        const check = exe.check_object();
        check.check_in_symtab();
        check.check_not_present("_OBJC_");
        test_step.depend_on(&check.step);

        const run = add_run_artifact(exe);
        run.expect_exit_code(0);
        test_step.depend_on(&run.step);
    }

    {
        const exe = add_executable(b, opts, .{ .name = "main2", .c_source_bytes = "int main() { return 0; }" });
        exe.root_module.link_system_library("a", .{});
        exe.root_module.link_framework("Foundation", .{});
        exe.root_module.add_library_path(lib.get_emitted_bin_directory());
        exe.force_load_objc = true;

        const check = exe.check_object();
        check.check_in_symtab();
        check.check_contains("_OBJC_");
        test_step.depend_on(&check.step);

        const run = add_run_artifact(exe);
        run.expect_exit_code(0);
        test_step.depend_on(&run.step);
    }

    return test_step;
}

fn test_objcpp(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "objcpp", opts);

    const foo_h = foo_h: {
        const wf = WriteFile.create(b);
        break :foo_h wf.add("Foo.h",
            \\#import <Foundation/Foundation.h>
            \\@interface Foo : NSObject
            \\- (NSString *)name;
            \\@end
        );
    };

    const foo_o = add_object(b, opts, .{ .name = "foo", .objcpp_source_bytes = 
    \\#import "Foo.h"
    \\@implementation Foo
    \\- (NSString *)name
    \\{
    \\      NSString *str = [[NSString alloc] initWithFormat:@"Zig"];
    \\      return str;
    \\}
    \\@end
    });
    foo_o.root_module.add_include_path(foo_h.dirname());
    foo_o.link_lib_cpp();

    const exe = add_executable(b, opts, .{ .name = "main", .objcpp_source_bytes = 
    \\#import "Foo.h"
    \\#import <assert.h>
    \\#include <iostream>
    \\int main(int argc, char *argv[])
    \\{
    \\  @autoreleasepool {
    \\      Foo *foo = [[Foo alloc] init];
    \\      NSString *result = [foo name];
    \\      std::cout << "Hello from C++ and " << [result UTF8String];
    \\      assert([result isEqualToString:@"Zig"]);
    \\      return 0;
    \\  }
    \\}
    });
    exe.root_module.add_include_path(foo_h.dirname());
    exe.add_object(foo_o);
    exe.link_lib_cpp();
    exe.root_module.link_framework("Foundation", .{});

    const run = add_run_artifact(exe);
    run.expect_std_out_equal("Hello from C++ and Zig");
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_pagezero_size(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "pagezero-size", opts);

    {
        const exe = add_executable(b, opts, .{ .name = "main", .c_source_bytes = "int main () { return 0; }" });
        exe.pagezero_size = 0x4000;

        const check = exe.check_object();
        check.check_in_headers();
        check.check_exact("LC 0");
        check.check_exact("segname __PAGEZERO");
        check.check_exact("vmaddr 0");
        check.check_exact("vmsize 4000");
        check.check_in_headers();
        check.check_exact("segname __TEXT");
        check.check_exact("vmaddr 4000");
        test_step.depend_on(&check.step);
    }

    {
        const exe = add_executable(b, opts, .{ .name = "main", .c_source_bytes = "int main () { return 0; }" });
        exe.pagezero_size = 0;

        const check = exe.check_object();
        check.check_in_headers();
        check.check_exact("LC 0");
        check.check_exact("segname __TEXT");
        check.check_exact("vmaddr 0");
        test_step.depend_on(&check.step);
    }

    return test_step;
}

fn test_reexports_zig(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "reexports-zig", opts);

    const lib = add_static_library(b, opts, .{ .name = "a", .zig_source_bytes = 
    \\const x: i32 = 42;
    \\export fn foo() i32 {
    \\    return x;
    \\}
    \\comptime {
    \\    @export(foo, .{ .name = "bar", .linkage = .strong });
    \\}
    });

    const exe = add_executable(b, opts, .{ .name = "main", .c_source_bytes = 
    \\extern int foo();
    \\extern int bar();
    \\int main() {
    \\  return bar() - foo();
    \\}
    });
    exe.link_library(lib);

    const run = add_run_artifact(exe);
    run.expect_exit_code(0);
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_relocatable(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "relocatable", opts);

    const a_o = add_object(b, opts, .{ .name = "a", .cpp_source_bytes = 
    \\#include <stdexcept>
    \\int try_me() {
    \\  throw std::runtime_error("Oh no!");
    \\}
    });
    a_o.link_lib_cpp();

    const b_o = add_object(b, opts, .{ .name = "b", .cpp_source_bytes = 
    \\extern int try_me();
    \\int try_again() {
    \\  return try_me();
    \\}
    });

    const main_o = add_object(b, opts, .{ .name = "main", .cpp_source_bytes = 
    \\#include <iostream>
    \\#include <stdexcept>
    \\extern int try_again();
    \\int main() {
    \\  try {
    \\    try_again();
    \\  } catch (const std::exception &e) {
    \\    std::cout << "exception=" << e.what();
    \\  }
    \\  return 0;
    \\}
    });
    main_o.link_lib_cpp();

    const exp_stdout = "exception=Oh no!";

    {
        const c_o = add_object(b, opts, .{ .name = "c" });
        c_o.add_object(a_o);
        c_o.add_object(b_o);

        const exe = add_executable(b, opts, .{ .name = "main1" });
        exe.add_object(main_o);
        exe.add_object(c_o);
        exe.link_lib_cpp();

        const run = add_run_artifact(exe);
        run.expect_std_out_equal(exp_stdout);
        test_step.depend_on(&run.step);
    }

    {
        const d_o = add_object(b, opts, .{ .name = "d" });
        d_o.add_object(a_o);
        d_o.add_object(b_o);
        d_o.add_object(main_o);

        const exe = add_executable(b, opts, .{ .name = "main2" });
        exe.add_object(d_o);
        exe.link_lib_cpp();

        const run = add_run_artifact(exe);
        run.expect_std_out_equal(exp_stdout);
        test_step.depend_on(&run.step);
    }

    return test_step;
}

fn test_relocatable_zig(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "relocatable-zig", opts);

    const a_o = add_object(b, opts, .{ .name = "a", .zig_source_bytes = 
    \\const std = @import("std");
    \\export var foo: i32 = 0;
    \\export fn incr_foo() void {
    \\    foo += 1;
    \\    std.debug.print("incr_foo={d}\n", .{foo});
    \\}
    });

    const b_o = add_object(b, opts, .{ .name = "b", .zig_source_bytes = 
    \\const std = @import("std");
    \\extern var foo: i32;
    \\export fn decr_foo() void {
    \\    foo -= 1;
    \\    std.debug.print("decr_foo={d}\n", .{foo});
    \\}
    });

    const main_o = add_object(b, opts, .{ .name = "main", .zig_source_bytes = 
    \\const std = @import("std");
    \\extern var foo: i32;
    \\extern fn incr_foo() void;
    \\extern fn decr_foo() void;
    \\pub fn main() void {
    \\    const init = foo;
    \\    incr_foo();
    \\    decr_foo();
    \\    if (init == foo) @panic("Oh no!");
    \\}
    });

    const c_o = add_object(b, opts, .{ .name = "c" });
    c_o.add_object(a_o);
    c_o.add_object(b_o);
    c_o.add_object(main_o);

    const exe = add_executable(b, opts, .{ .name = "main" });
    exe.add_object(c_o);

    const run = add_run_artifact(exe);
    run.add_check(.{ .expect_stderr_match = b.dupe("incr_foo=1") });
    run.add_check(.{ .expect_stderr_match = b.dupe("decr_foo=0") });
    run.add_check(.{ .expect_stderr_match = b.dupe("panic: Oh no!") });
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_search_strategy(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "search-strategy", opts);

    const obj = add_object(b, opts, .{ .name = "a", .c_source_bytes = 
    \\#include<stdio.h>
    \\char world[] = "world";
    \\char* hello() {
    \\  return "Hello";
    \\}
    });

    const liba = add_static_library(b, opts, .{ .name = "a" });
    liba.add_object(obj);

    const dylib = add_shared_library(b, opts, .{ .name = "a" });
    dylib.add_object(obj);

    const main_o = add_object(b, opts, .{ .name = "main", .c_source_bytes = 
    \\#include<stdio.h>
    \\char* hello();
    \\extern char world[];
    \\int main() {
    \\  printf("%s %s", hello(), world);
    \\  return 0;
    \\}
    });

    {
        const exe = add_executable(b, opts, .{ .name = "main" });
        exe.add_object(main_o);
        exe.root_module.link_system_library("a", .{ .use_pkg_config = .no, .search_strategy = .mode_first });
        exe.root_module.add_library_path(liba.get_emitted_bin_directory());
        exe.root_module.add_library_path(dylib.get_emitted_bin_directory());
        exe.root_module.add_rpath(dylib.get_emitted_bin_directory());

        const run = add_run_artifact(exe);
        run.expect_std_out_equal("Hello world");
        test_step.depend_on(&run.step);

        const check = exe.check_object();
        check.check_in_headers();
        check.check_exact("cmd LOAD_DYLIB");
        check.check_contains("liba.dylib");
        test_step.depend_on(&check.step);
    }

    {
        const exe = add_executable(b, opts, .{ .name = "main" });
        exe.add_object(main_o);
        exe.root_module.link_system_library("a", .{ .use_pkg_config = .no, .search_strategy = .paths_first });
        exe.root_module.add_library_path(liba.get_emitted_bin_directory());
        exe.root_module.add_library_path(dylib.get_emitted_bin_directory());
        exe.root_module.add_rpath(dylib.get_emitted_bin_directory());

        const run = add_run_artifact(exe);
        run.expect_std_out_equal("Hello world");
        test_step.depend_on(&run.step);

        const check = exe.check_object();
        check.check_in_headers();
        check.check_exact("cmd LOAD_DYLIB");
        check.check_not_present("liba.dylib");
        test_step.depend_on(&check.step);
    }

    return test_step;
}

fn test_section_boundary_symbols(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "section-boundary-symbols", opts);

    const obj1 = add_object(b, opts, .{
        .name = "obj1",
        .cpp_source_bytes =
        \\constexpr const char* MESSAGE __attribute__((used, section("__DATA_CONST,__message_ptr"))) = "codebase";
        ,
    });

    const main_o = add_object(b, opts, .{
        .name = "main",
        .zig_source_bytes =
        \\const std = @import("std");
        \\extern fn interop() ?[*:0]const u8;
        \\pub fn main() !void {
        \\    std.debug.print("All your {s} are belong to us.\n", .{
        \\        if (interop()) |ptr| std.mem.span(ptr) else "(null)",
        \\    });
        \\}
        ,
    });

    {
        const obj2 = add_object(b, opts, .{
            .name = "obj2",
            .cpp_source_bytes =
            \\extern const char* message_pointer __asm("section$start$__DATA_CONST$__message_ptr");
            \\extern "C" const char* interop() {
            \\  return message_pointer;
            \\}
            ,
        });

        const exe = add_executable(b, opts, .{ .name = "test" });
        exe.add_object(obj1);
        exe.add_object(obj2);
        exe.add_object(main_o);

        const run = b.add_run_artifact(exe);
        run.skip_foreign_checks = true;
        run.expect_std_err_equal("All your codebase are belong to us.\n");
        test_step.depend_on(&run.step);

        const check = exe.check_object();
        check.check_in_symtab();
        check.check_not_present("external section$start$__DATA_CONST$__message_ptr");
        test_step.depend_on(&check.step);
    }

    {
        const obj3 = add_object(b, opts, .{
            .name = "obj3",
            .cpp_source_bytes =
            \\extern const char* message_pointer __asm("section$start$__DATA_CONST$__not_present");
            \\extern "C" const char* interop() {
            \\  return message_pointer;
            \\}
            ,
        });

        const exe = add_executable(b, opts, .{ .name = "test" });
        exe.add_object(obj1);
        exe.add_object(obj3);
        exe.add_object(main_o);

        const run = b.add_run_artifact(exe);
        run.skip_foreign_checks = true;
        run.expect_std_err_equal("All your (null) are belong to us.\n");
        test_step.depend_on(&run.step);

        const check = exe.check_object();
        check.check_in_symtab();
        check.check_not_present("external section$start$__DATA_CONST$__not_present");
        test_step.depend_on(&check.step);
    }

    return test_step;
}

fn test_segment_boundary_symbols(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "segment-boundary-symbols", opts);

    const obj1 = add_object(b, opts, .{ .name = "a", .cpp_source_bytes = 
    \\constexpr const char* MESSAGE __attribute__((used, section("__DATA_CONST_1,__message_ptr"))) = "codebase";
    });

    const main_o = add_object(b, opts, .{ .name = "main", .c_source_bytes = 
    \\#include <stdio.h>
    \\const char* interop();
    \\int main() {
    \\  printf("All your %s are belong to us.\n", interop());
    \\  return 0;
    \\}
    });

    {
        const obj2 = add_object(b, opts, .{ .name = "b", .cpp_source_bytes = 
        \\extern const char* message_pointer __asm("segment$start$__DATA_CONST_1");
        \\extern "C" const char* interop() {
        \\  return message_pointer;
        \\}
        });

        const exe = add_executable(b, opts, .{ .name = "main" });
        exe.add_object(obj1);
        exe.add_object(obj2);
        exe.add_object(main_o);

        const run = add_run_artifact(exe);
        run.expect_std_out_equal("All your codebase are belong to us.\n");
        test_step.depend_on(&run.step);

        const check = exe.check_object();
        check.check_in_symtab();
        check.check_not_present("external segment$start$__DATA_CONST_1");
        test_step.depend_on(&check.step);
    }

    {
        const obj2 = add_object(b, opts, .{ .name = "c", .cpp_source_bytes = 
        \\extern const char* message_pointer __asm("segment$start$__DATA_1");
        \\extern "C" const char* interop() {
        \\  return message_pointer;
        \\}
        });

        const exe = add_executable(b, opts, .{ .name = "main2" });
        exe.add_object(obj1);
        exe.add_object(obj2);
        exe.add_object(main_o);

        const check = exe.check_object();
        check.check_in_headers();
        check.check_exact("cmd SEGMENT_64");
        check.check_exact("segname __DATA_1");
        check.check_extract("vmsize {vmsize}");
        check.check_extract("filesz {filesz}");
        check.check_compute_compare("vmsize", .{ .op = .eq, .value = .{ .literal = 0 } });
        check.check_compute_compare("filesz", .{ .op = .eq, .value = .{ .literal = 0 } });
        check.check_in_symtab();
        check.check_not_present("external segment$start$__DATA_1");
        test_step.depend_on(&check.step);
    }

    return test_step;
}

fn test_symbol_stabs(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "symbol-stabs", opts);

    const a_o = add_object(b, opts, .{ .name = "a", .c_source_bytes = 
    \\int foo = 42;
    \\int get_foo() {
    \\  return foo;
    \\}
    });

    const b_o = add_object(b, opts, .{ .name = "b", .c_source_bytes = 
    \\int bar = 24;
    \\int getBar() {
    \\  return bar;
    \\}
    });

    const main_o = add_object(b, opts, .{ .name = "main", .c_source_bytes = 
    \\#include <stdio.h>
    \\extern int get_foo();
    \\extern int getBar();
    \\int main() {
    \\  printf("foo=%d,bar=%d", get_foo(), getBar());
    \\  return 0;
    \\}
    });

    const exe = add_executable(b, opts, .{ .name = "main" });
    exe.add_object(a_o);
    exe.add_object(b_o);
    exe.add_object(main_o);

    const run = add_run_artifact(exe);
    run.expect_std_out_equal("foo=42,bar=24");
    test_step.depend_on(&run.step);

    const check = exe.check_object();
    check.check_in_symtab();
    check.check_contains("a.o"); // TODO we really should do a fuzzy search like OSO <ignore>/a.o
    check.check_in_symtab();
    check.check_contains("b.o");
    check.check_in_symtab();
    check.check_contains("main.o");
    test_step.depend_on(&check.step);

    return test_step;
}

fn test_stack_size(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "stack-size", opts);

    const exe = add_executable(b, opts, .{ .name = "main", .c_source_bytes = "int main() { return 0; }" });
    exe.stack_size = 0x100000000;

    const run = add_run_artifact(exe);
    run.expect_exit_code(0);
    test_step.depend_on(&run.step);

    const check = exe.check_object();
    check.check_in_headers();
    check.check_exact("cmd MAIN");
    check.check_exact("stacksize 100000000");
    test_step.depend_on(&check.step);

    return test_step;
}

fn test_tbdv3(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "tbdv3", opts);

    const dylib = add_shared_library(b, opts, .{ .name = "a", .c_source_bytes = "int get_foo() { return 42; }" });

    const tbd = tbd: {
        const wf = WriteFile.create(b);
        break :tbd wf.add("liba.tbd",
            \\--- !tapi-tbd-v3
            \\archs:           [ arm64, x86_64 ]
            \\uuids:           [ 'arm64: DEADBEEF', 'x86_64: BEEFDEAD' ]
            \\platform:        macos
            \\install-name:    @rpath/liba.dylib
            \\current-version: 0
            \\exports:
            \\  - archs:           [ arm64, x86_64 ]
            \\    symbols:         [ _getFoo ]
        );
    };

    const exe = add_executable(b, opts, .{ .name = "main", .c_source_bytes = 
    \\#include <stdio.h>
    \\int get_foo();
    \\int main() {
    \\  return get_foo() - 42;
    \\}
    });
    exe.root_module.link_system_library("a", .{});
    exe.root_module.add_library_path(tbd.dirname());
    exe.root_module.add_rpath(dylib.get_emitted_bin_directory());

    const run = add_run_artifact(exe);
    run.expect_exit_code(0);
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_tentative(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "tentative", opts);

    const exe = add_executable(b, opts, .{ .name = "main" });
    add_csource_bytes(exe,
        \\int foo;
        \\int bar;
        \\int baz = 42;
    , &.{"-fcommon"});
    add_csource_bytes(exe,
        \\#include<stdio.h>
        \\int foo;
        \\int bar = 5;
        \\int baz;
        \\int main() {
        \\  printf("%d %d %d\n", foo, bar, baz);
        \\}
    , &.{"-fcommon"});

    const run = add_run_artifact(exe);
    run.expect_std_out_equal("0 5 42\n");
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_thunks(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "thunks", opts);

    const exe = add_executable(b, opts, .{ .name = "main", .c_source_bytes = 
    \\#include <stdio.h>
    \\__attribute__((aligned(0x8000000))) int bar() {
    \\  return 42;
    \\}
    \\int foobar();
    \\int foo() {
    \\  return bar() - foobar();
    \\}
    \\__attribute__((aligned(0x8000000))) int foobar() {
    \\  return 42;
    \\}
    \\int main() {
    \\  printf("bar=%d, foo=%d, foobar=%d", bar(), foo(), foobar());
    \\  return foo();
    \\}
    });

    const run = add_run_artifact(exe);
    run.expect_std_out_equal("bar=42, foo=0, foobar=42");
    run.expect_exit_code(0);
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_tls(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "tls", opts);

    const dylib = add_shared_library(b, opts, .{ .name = "a", .c_source_bytes = 
    \\_Thread_local int a;
    \\int get_a() {
    \\  return a;
    \\}
    });

    const exe = add_executable(b, opts, .{ .name = "main", .c_source_bytes = 
    \\#include<stdio.h>
    \\extern _Thread_local int a;
    \\extern int get_a();
    \\int getA2() {
    \\  return a;
    \\}
    \\int main() {
    \\  a = 2;
    \\  printf("%d %d %d", a, get_a(), getA2());
    \\  return 0;
    \\}
    });
    exe.root_module.link_system_library("a", .{});
    exe.root_module.add_library_path(dylib.get_emitted_bin_directory());
    exe.root_module.add_rpath(dylib.get_emitted_bin_directory());

    const run = add_run_artifact(exe);
    run.expect_std_out_equal("2 2 2");
    test_step.depend_on(&run.step);

    return test_step;
}

// https://github.com/ziglang/zig/issues/19221
fn test_tls_pointers(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "tls-pointers", opts);

    const foo_h = foo_h: {
        const wf = WriteFile.create(b);
        break :foo_h wf.add("foo.h",
            \\template<typename just4fun>
            \\struct Foo {
            \\
            \\public:
            \\  static int getVar() {
            \\  static int thread_local var = 0;
            \\  ++var;
            \\  return var;
            \\}
            \\};
        );
    };

    const bar_o = add_object(b, opts, .{ .name = "bar", .cpp_source_bytes = 
    \\#include "foo.h"
    \\int bar() {
    \\  int v1 = Foo<int>::getVar();
    \\  return v1;
    \\}
    });
    bar_o.root_module.add_include_path(foo_h.dirname());
    bar_o.link_lib_cpp();

    const baz_o = add_object(b, opts, .{ .name = "baz", .cpp_source_bytes = 
    \\#include "foo.h"
    \\int baz() {
    \\  int v1 = Foo<unsigned>::getVar();
    \\  return v1;
    \\}
    });
    baz_o.root_module.add_include_path(foo_h.dirname());
    baz_o.link_lib_cpp();

    const main_o = add_object(b, opts, .{ .name = "main", .cpp_source_bytes = 
    \\extern int bar();
    \\extern int baz();
    \\int main() {
    \\  int v1 = bar();
    \\  int v2 = baz();
    \\  return v1 != v2;
    \\}
    });
    main_o.root_module.add_include_path(foo_h.dirname());
    main_o.link_lib_cpp();

    const exe = add_executable(b, opts, .{ .name = "main" });
    exe.add_object(bar_o);
    exe.add_object(baz_o);
    exe.add_object(main_o);
    exe.link_lib_cpp();

    const run = add_run_artifact(exe);
    run.expect_exit_code(0);
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_tls_large_tbss(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "tls-large-tbss", opts);

    const exe = add_executable(b, opts, .{ .name = "main", .c_source_bytes = 
    \\#include <stdio.h>
    \\_Thread_local int x[0x8000];
    \\_Thread_local int y[0x8000];
    \\int main() {
    \\  x[0] = 3;
    \\  x[0x7fff] = 5;
    \\  printf("%d %d %d %d %d %d\n", x[0], x[1], x[0x7fff], y[0], y[1], y[0x7fff]);
    \\}
    });

    const run = add_run_artifact(exe);
    run.expect_std_out_equal("3 0 5 0 0 0\n");
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_two_level_namespace(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "two-level-namespace", opts);

    const liba = add_shared_library(b, opts, .{ .name = "a", .c_source_bytes = 
    \\#include <stdio.h>
    \\int foo = 1;
    \\int* ptr_to_foo = &foo;
    \\int get_foo() {
    \\  return foo;
    \\}
    \\void printInA() {
    \\  printf("liba: get_foo()=%d, ptr_to_foo=%d\n", get_foo(), *ptr_to_foo);
    \\}
    });

    {
        const check = liba.check_object();
        check.check_in_dyld_lazy_bind();
        check.check_not_present("(flat lookup) _getFoo");
        check.check_in_indirect_symtab();
        check.check_not_present("_getFoo");
        test_step.depend_on(&check.step);
    }

    const libb = add_shared_library(b, opts, .{ .name = "b", .c_source_bytes = 
    \\#include <stdio.h>
    \\int foo = 2;
    \\int* ptr_to_foo = &foo;
    \\int get_foo() {
    \\  return foo;
    \\}
    \\void printInB() {
    \\  printf("libb: get_foo()=%d, ptr_to_foo=%d\n", get_foo(), *ptr_to_foo);
    \\}
    });

    {
        const check = libb.check_object();
        check.check_in_dyld_lazy_bind();
        check.check_not_present("(flat lookup) _getFoo");
        check.check_in_indirect_symtab();
        check.check_not_present("_getFoo");
        test_step.depend_on(&check.step);
    }

    const main_o = add_object(b, opts, .{ .name = "main", .c_source_bytes = 
    \\#include <stdio.h>
    \\int get_foo();
    \\extern int* ptr_to_foo;
    \\void printInA();
    \\void printInB();
    \\int main() {
    \\  printf("main: get_foo()=%d, ptr_to_foo=%d\n", get_foo(), *ptr_to_foo);
    \\  printInA();
    \\  printInB();
    \\  return 0;
    \\}
    });

    {
        const exe = add_executable(b, opts, .{ .name = "main1" });
        exe.add_object(main_o);
        exe.root_module.link_system_library("a", .{});
        exe.root_module.link_system_library("b", .{});
        exe.root_module.add_library_path(liba.get_emitted_bin_directory());
        exe.root_module.add_library_path(libb.get_emitted_bin_directory());
        exe.root_module.add_rpath(liba.get_emitted_bin_directory());
        exe.root_module.add_rpath(libb.get_emitted_bin_directory());

        const check = exe.check_object();
        check.check_in_symtab();
        check.check_exact("(undefined) external _getFoo (from liba)");
        check.check_in_symtab();
        check.check_exact("(undefined) external _printInA (from liba)");
        check.check_in_symtab();
        check.check_exact("(undefined) external _printInB (from libb)");
        test_step.depend_on(&check.step);

        const run = add_run_artifact(exe);
        run.expect_std_out_equal(
            \\main: get_foo()=1, ptr_to_foo=1
            \\liba: get_foo()=1, ptr_to_foo=1
            \\libb: get_foo()=2, ptr_to_foo=2
            \\
        );
        test_step.depend_on(&run.step);
    }

    {
        const exe = add_executable(b, opts, .{ .name = "main2" });
        exe.add_object(main_o);
        exe.root_module.link_system_library("b", .{});
        exe.root_module.link_system_library("a", .{});
        exe.root_module.add_library_path(liba.get_emitted_bin_directory());
        exe.root_module.add_library_path(libb.get_emitted_bin_directory());
        exe.root_module.add_rpath(liba.get_emitted_bin_directory());
        exe.root_module.add_rpath(libb.get_emitted_bin_directory());

        const check = exe.check_object();
        check.check_in_symtab();
        check.check_exact("(undefined) external _getFoo (from libb)");
        check.check_in_symtab();
        check.check_exact("(undefined) external _printInA (from liba)");
        check.check_in_symtab();
        check.check_exact("(undefined) external _printInB (from libb)");
        test_step.depend_on(&check.step);

        const run = add_run_artifact(exe);
        run.expect_std_out_equal(
            \\main: get_foo()=2, ptr_to_foo=2
            \\liba: get_foo()=1, ptr_to_foo=1
            \\libb: get_foo()=2, ptr_to_foo=2
            \\
        );
        test_step.depend_on(&run.step);
    }

    return test_step;
}

fn test_undefined_flag(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "undefined-flag", opts);

    const obj = add_object(b, opts, .{ .name = "a", .c_source_bytes = "int foo = 42;" });

    const lib = add_static_library(b, opts, .{ .name = "a" });
    lib.add_object(obj);

    const main_o = add_object(b, opts, .{ .name = "main", .c_source_bytes = "int main() { return 0; }" });

    {
        const exe = add_executable(b, opts, .{ .name = "main1" });
        exe.add_object(main_o);
        exe.link_library(lib);
        exe.force_undefined_symbol("_foo");

        const run = add_run_artifact(exe);
        run.expect_exit_code(0);
        test_step.depend_on(&run.step);

        const check = exe.check_object();
        check.check_in_symtab();
        check.check_contains("_foo");
        test_step.depend_on(&check.step);
    }

    {
        const exe = add_executable(b, opts, .{ .name = "main2" });
        exe.add_object(main_o);
        exe.link_library(lib);
        exe.force_undefined_symbol("_foo");
        exe.link_gc_sections = true;

        const run = add_run_artifact(exe);
        run.expect_exit_code(0);
        test_step.depend_on(&run.step);

        const check = exe.check_object();
        check.check_in_symtab();
        check.check_contains("_foo");
        test_step.depend_on(&check.step);
    }

    {
        const exe = add_executable(b, opts, .{ .name = "main3" });
        exe.add_object(main_o);
        exe.add_object(obj);

        const run = add_run_artifact(exe);
        run.expect_exit_code(0);
        test_step.depend_on(&run.step);

        const check = exe.check_object();
        check.check_in_symtab();
        check.check_contains("_foo");
        test_step.depend_on(&check.step);
    }

    {
        const exe = add_executable(b, opts, .{ .name = "main4" });
        exe.add_object(main_o);
        exe.add_object(obj);
        exe.link_gc_sections = true;

        const run = add_run_artifact(exe);
        run.expect_exit_code(0);
        test_step.depend_on(&run.step);

        const check = exe.check_object();
        check.check_in_symtab();
        check.check_not_present("_foo");
        test_step.depend_on(&check.step);
    }

    return test_step;
}

fn test_unwind_info(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "unwind-info", opts);

    const all_h = all_h: {
        const wf = WriteFile.create(b);
        break :all_h wf.add("all.h",
            \\#ifndef ALL
            \\#define ALL
            \\
            \\#include <cstddef>
            \\#include <string>
            \\#include <stdexcept>
            \\
            \\struct SimpleString {
            \\  SimpleString(size_t max_size);
            \\  ~SimpleString();
            \\
            \\  void print(const char* tag) const;
            \\  bool append_line(const char* x);
            \\
            \\private:
            \\  size_t max_size;
            \\  char* buffer;
            \\  size_t length;
            \\};
            \\
            \\struct SimpleStringOwner {
            \\  SimpleStringOwner(const char* x);
            \\  ~SimpleStringOwner();
            \\
            \\private:
            \\  SimpleString string;
            \\};
            \\
            \\class Error: public std::exception {
            \\public:
            \\  explicit Error(const char* msg) : msg{ msg } {}
            \\  virtual ~Error() noexcept {}
            \\  virtual const char* what() const noexcept {
            \\    return msg.c_str();
            \\  }
            \\
            \\protected:
            \\  std::string msg;
            \\};
            \\
            \\#endif
        );
    };

    const main_o = add_object(b, opts, .{ .name = "main", .cpp_source_bytes = 
    \\#include "all.h"
    \\#include <cstdio>
    \\
    \\void fn_c() {
    \\  SimpleStringOwner c{ "cccccccccc" };
    \\}
    \\
    \\void fn_b() {
    \\  SimpleStringOwner b{ "b" };
    \\  fn_c();
    \\}
    \\
    \\int main() {
    \\  try {
    \\    SimpleStringOwner a{ "a" };
    \\    fn_b();
    \\    SimpleStringOwner d{ "d" };
    \\  } catch (const Error& e) {
    \\    printf("Error: %s\n", e.what());
    \\  } catch(const std::exception& e) {
    \\    printf("Exception: %s\n", e.what());
    \\  }
    \\  return 0;
    \\}
    });
    main_o.root_module.add_include_path(all_h.dirname());
    main_o.link_lib_cpp();

    const simple_string_o = add_object(b, opts, .{ .name = "simple_string", .cpp_source_bytes = 
    \\#include "all.h"
    \\#include <cstdio>
    \\#include <cstring>
    \\
    \\SimpleString::SimpleString(size_t max_size)
    \\: max_size{ max_size }, length{} {
    \\  if (max_size == 0) {
    \\    throw Error{ "Max size must be at least 1." };
    \\  }
    \\  buffer = new char[max_size];
    \\  buffer[0] = 0;
    \\}
    \\
    \\SimpleString::~SimpleString() {
    \\  delete[] buffer;
    \\}
    \\
    \\void SimpleString::print(const char* tag) const {
    \\  printf("%s: %s", tag, buffer);
    \\}
    \\
    \\bool SimpleString::append_line(const char* x) {
    \\  const auto x_len = strlen(x);
    \\  if (x_len + length + 2 > max_size) return false;
    \\  std::strncpy(buffer + length, x, max_size - length);
    \\  length += x_len;
    \\  buffer[length++] = '\n';
    \\  buffer[length] = 0;
    \\  return true;
    \\}
    });
    simple_string_o.root_module.add_include_path(all_h.dirname());
    simple_string_o.link_lib_cpp();

    const simple_string_owner_o = add_object(b, opts, .{ .name = "simple_string_owner", .cpp_source_bytes = 
    \\#include "all.h"
    \\
    \\SimpleStringOwner::SimpleStringOwner(const char* x) : string{ 10 } {
    \\  if (!string.append_line(x)) {
    \\    throw Error{ "Not enough memory!" };
    \\  }
    \\  string.print("Constructed");
    \\}
    \\
    \\SimpleStringOwner::~SimpleStringOwner() {
    \\  string.print("About to destroy");
    \\}
    });
    simple_string_owner_o.root_module.add_include_path(all_h.dirname());
    simple_string_owner_o.link_lib_cpp();

    const exp_stdout =
        \\Constructed: a
        \\Constructed: b
        \\About to destroy: b
        \\About to destroy: a
        \\Error: Not enough memory!
        \\
    ;

    const exe = add_executable(b, opts, .{ .name = "main" });
    exe.add_object(main_o);
    exe.add_object(simple_string_o);
    exe.add_object(simple_string_owner_o);
    exe.link_lib_cpp();

    const run = add_run_artifact(exe);
    run.expect_std_out_equal(exp_stdout);
    test_step.depend_on(&run.step);

    const check = exe.check_object();
    check.check_in_symtab();
    check.check_contains("(was private external) ___gxx_personality_v0");
    test_step.depend_on(&check.step);

    return test_step;
}

fn test_unwind_info_no_subsections_arm64(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "unwind-info-no-subsections-arm64", opts);

    const a_o = add_object(b, opts, .{ .name = "a", .asm_source_bytes = 
    \\.globl _foo
    \\.align 4
    \\_foo:
    \\  .cfi_startproc
    \\  stp     x29, x30, [sp, #-32]!
    \\  .cfi_def_cfa_offset 32
    \\  .cfi_offset w30, -24
    \\  .cfi_offset w29, -32
    \\  mov x29, sp
    \\  .cfi_def_cfa w29, 32
    \\  bl      _bar
    \\  ldp     x29, x30, [sp], #32
    \\  .cfi_restore w29
    \\  .cfi_restore w30
    \\  .cfi_def_cfa_offset 0
    \\  ret
    \\  .cfi_endproc
    \\
    \\.globl _bar
    \\.align 4
    \\_bar:
    \\  .cfi_startproc
    \\  sub     sp, sp, #32
    \\  .cfi_def_cfa_offset -32
    \\  stp     x29, x30, [sp, #16]
    \\  .cfi_offset w30, -24
    \\  .cfi_offset w29, -32
    \\  mov x29, sp
    \\  .cfi_def_cfa w29, 32
    \\  mov     w0, #4
    \\  ldp     x29, x30, [sp, #16]
    \\  .cfi_restore w29
    \\  .cfi_restore w30
    \\  add     sp, sp, #32
    \\  .cfi_def_cfa_offset 0
    \\  ret
    \\  .cfi_endproc
    });

    const exe = add_executable(b, opts, .{ .name = "main", .c_source_bytes = 
    \\#include <stdio.h>
    \\int foo();
    \\int main() {
    \\  printf("%d\n", foo());
    \\  return 0;
    \\}
    });
    exe.add_object(a_o);

    const run = add_run_artifact(exe);
    run.expect_std_out_equal("4\n");
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_unwind_info_no_subsections_x64(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "unwind-info-no-subsections-x64", opts);

    const a_o = add_object(b, opts, .{ .name = "a", .asm_source_bytes = 
    \\.globl _foo
    \\_foo:
    \\  .cfi_startproc
    \\  push    %rbp
    \\  .cfi_def_cfa_offset 8
    \\  .cfi_offset %rbp, -8
    \\  mov     %rsp, %rbp
    \\  .cfi_def_cfa_register %rbp
    \\  call    _bar
    \\  pop     %rbp
    \\  .cfi_restore %rbp
    \\  .cfi_def_cfa_offset 0
    \\  ret
    \\  .cfi_endproc
    \\
    \\.globl _bar
    \\_bar:
    \\  .cfi_startproc
    \\  push     %rbp
    \\  .cfi_def_cfa_offset 8
    \\  .cfi_offset %rbp, -8
    \\  mov     %rsp, %rbp
    \\  .cfi_def_cfa_register %rbp
    \\  mov     $4, %rax
    \\  pop     %rbp
    \\  .cfi_restore %rbp
    \\  .cfi_def_cfa_offset 0
    \\  ret
    \\  .cfi_endproc
    });

    const exe = add_executable(b, opts, .{ .name = "main", .c_source_bytes = 
    \\#include <stdio.h>
    \\int foo();
    \\int main() {
    \\  printf("%d\n", foo());
    \\  return 0;
    \\}
    });
    exe.add_object(a_o);

    const run = add_run_artifact(exe);
    run.expect_std_out_equal("4\n");
    test_step.depend_on(&run.step);

    return test_step;
}

// Adapted from https://github.com/llvm/llvm-project/blob/main/lld/test/MachO/weak-binding.s
fn test_weak_bind(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "weak-bind", opts);

    const lib = add_shared_library(b, opts, .{ .name = "foo", .asm_source_bytes = 
    \\.globl _weak_dysym
    \\.weak_definition _weak_dysym
    \\_weak_dysym:
    \\  .quad 0x1234
    \\
    \\.globl _weak_dysym_for_gotpcrel
    \\.weak_definition _weak_dysym_for_gotpcrel
    \\_weak_dysym_for_gotpcrel:
    \\  .quad 0x1234
    \\
    \\.globl _weak_dysym_fn
    \\.weak_definition _weak_dysym_fn
    \\_weak_dysym_fn:
    \\  ret
    \\
    \\.section __DATA,__thread_vars,thread_local_variables
    \\
    \\.globl _weak_dysym_tlv
    \\.weak_definition _weak_dysym_tlv
    \\_weak_dysym_tlv:
    \\  .quad 0x1234
    });

    {
        const check = lib.check_object();
        check.check_in_exports();
        check.check_extract("[WEAK] {vmaddr1} _weak_dysym");
        check.check_extract("[WEAK] {vmaddr2} _weak_dysym_for_gotpcrel");
        check.check_extract("[WEAK] {vmaddr3} _weak_dysym_fn");
        check.check_extract("[THREAD_LOCAL, WEAK] {vmaddr4} _weak_dysym_tlv");
        test_step.depend_on(&check.step);
    }

    const exe = add_executable(b, opts, .{ .name = "main", .asm_source_bytes = 
    \\.globl _main, _weak_external, _weak_external_for_gotpcrel, _weak_external_fn
    \\.weak_definition _weak_external, _weak_external_for_gotpcrel, _weak_external_fn, _weak_internal, _weak_internal_for_gotpcrel, _weak_internal_fn
    \\
    \\_main:
    \\  mov _weak_dysym_for_gotpcrel@GOTPCREL(%rip), %rax
    \\  mov _weak_external_for_gotpcrel@GOTPCREL(%rip), %rax
    \\  mov _weak_internal_for_gotpcrel@GOTPCREL(%rip), %rax
    \\  mov _weak_tlv@TLVP(%rip), %rax
    \\  mov _weak_dysym_tlv@TLVP(%rip), %rax
    \\  mov _weak_internal_tlv@TLVP(%rip), %rax
    \\  callq _weak_dysym_fn
    \\  callq _weak_external_fn
    \\  callq _weak_internal_fn
    \\  mov $0, %rax
    \\  ret
    \\
    \\_weak_external:
    \\  .quad 0x1234
    \\
    \\_weak_external_for_gotpcrel:
    \\  .quad 0x1234
    \\
    \\_weak_external_fn:
    \\  ret
    \\
    \\_weak_internal:
    \\  .quad 0x1234
    \\
    \\_weak_internal_for_gotpcrel:
    \\  .quad 0x1234
    \\
    \\_weak_internal_fn:
    \\  ret
    \\
    \\.data
    \\  .quad _weak_dysym
    \\  .quad _weak_external + 2
    \\  .quad _weak_internal
    \\
    \\.tbss _weak_tlv$tlv$init, 4, 2
    \\.tbss _weak_internal_tlv$tlv$init, 4, 2
    \\
    \\.section __DATA,__thread_vars,thread_local_variables
    \\.globl _weak_tlv
    \\.weak_definition  _weak_tlv, _weak_internal_tlv
    \\
    \\_weak_tlv:
    \\  .quad __tlv_bootstrap
    \\  .quad 0
    \\  .quad _weak_tlv$tlv$init
    \\
    \\_weak_internal_tlv:
    \\  .quad __tlv_bootstrap
    \\  .quad 0
    \\  .quad _weak_internal_tlv$tlv$init
    });
    exe.link_library(lib);

    {
        const check = exe.check_object();

        check.check_in_exports();
        check.check_extract("[WEAK] {vmaddr1} _weak_external");
        check.check_extract("[WEAK] {vmaddr2} _weak_external_for_gotpcrel");
        check.check_extract("[WEAK] {vmaddr3} _weak_external_fn");
        check.check_extract("[THREAD_LOCAL, WEAK] {vmaddr4} _weak_tlv");

        check.check_in_dyld_bind();
        check.check_contains("(libfoo.dylib) _weak_dysym_for_gotpcrel");
        check.check_contains("(libfoo.dylib) _weak_dysym_fn");
        check.check_contains("(libfoo.dylib) _weak_dysym");
        check.check_contains("(libfoo.dylib) _weak_dysym_tlv");

        check.check_in_dyld_weak_bind();
        check.check_contains("_weak_external_for_gotpcrel");
        check.check_contains("_weak_dysym_for_gotpcrel");
        check.check_contains("_weak_external_fn");
        check.check_contains("_weak_dysym_fn");
        check.check_contains("_weak_dysym");
        check.check_contains("_weak_external");
        check.check_contains("_weak_tlv");
        check.check_contains("_weak_dysym_tlv");

        test_step.depend_on(&check.step);
    }

    const run = add_run_artifact(exe);
    run.expect_exit_code(0);
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_weak_framework(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "weak-framework", opts);

    const exe = add_executable(b, opts, .{ .name = "main", .c_source_bytes = "int main() { return 0; }" });
    exe.root_module.link_framework("Cocoa", .{ .weak = true });

    const run = add_run_artifact(exe);
    run.expect_exit_code(0);
    test_step.depend_on(&run.step);

    const check = exe.check_object();
    check.check_in_headers();
    check.check_exact("cmd LOAD_WEAK_DYLIB");
    check.check_contains("Cocoa");
    test_step.depend_on(&check.step);

    return test_step;
}

fn test_weak_library(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "weak-library", opts);

    const dylib = add_shared_library(b, opts, .{ .name = "a", .c_source_bytes = 
    \\#include<stdio.h>
    \\int a = 42;
    \\const char* asStr() {
    \\  static char str[3];
    \\  sprintf(str, "%d", 42);
    \\  return str;
    \\}
    });

    const exe = add_executable(b, opts, .{ .name = "main", .c_source_bytes = 
    \\#include<stdio.h>
    \\extern int a;
    \\extern const char* asStr();
    \\int main() {
    \\  printf("%d %s", a, asStr());
    \\  return 0;
    \\}
    });
    exe.root_module.link_system_library("a", .{ .weak = true });
    exe.root_module.add_library_path(dylib.get_emitted_bin_directory());
    exe.root_module.add_rpath(dylib.get_emitted_bin_directory());

    const check = exe.check_object();
    check.check_in_headers();
    check.check_exact("cmd LOAD_WEAK_DYLIB");
    check.check_contains("liba.dylib");
    check.check_in_symtab();
    check.check_exact("(undefined) weakref external _a (from liba)");
    check.check_in_symtab();
    check.check_exact("(undefined) weakref external _asStr (from liba)");
    test_step.depend_on(&check.step);

    const run = add_run_artifact(exe);
    run.expect_std_out_equal("42 42");
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_weak_ref(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "weak-ref", opts);

    const exe = add_executable(b, opts, .{ .name = "main", .c_source_bytes = 
    \\#include <stdio.h>
    \\#include <sys/_types/_fd_def.h>
    \\int main(int argc, char** argv) {
    \\    printf("__darwin_check_fd_set_overflow: %p\n", __darwin_check_fd_set_overflow);
    \\}
    });

    const check = exe.check_object();
    check.check_in_symtab();
    check.check_exact("(undefined) weakref external ___darwin_check_fd_set_overflow (from libSystem.B)");
    test_step.depend_on(&check.step);

    return test_step;
}

fn add_test_step(b: *Build, comptime prefix: []const u8, opts: Options) *Step {
    return link.add_test_step(b, "" ++ prefix, opts);
}

const builtin = @import("builtin");
const add_asm_source_bytes = link.add_asm_source_bytes;
const add_csource_bytes = link.add_csource_bytes;
const add_run_artifact = link.add_run_artifact;
const add_object = link.add_object;
const add_executable = link.add_executable;
const add_static_library = link.add_static_library;
const add_shared_library = link.add_shared_library;
const expect_link_errors = link.expect_link_errors;
const link = @import("link.zig");
const std = @import("std");

const Build = std.Build;
const BuildOptions = link.BuildOptions;
const Compile = Step.Compile;
const Options = link.Options;
const Step = Build.Step;
const WriteFile = Step.WriteFile;
