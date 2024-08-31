//! Here we test our ELF linker for correctness and functionality.
//! Currently, we support linking x86_64 Linux, but in the future we
//! will progressively relax those to exercise more combinations.

pub fn test_all(b: *Build, build_opts: BuildOptions) *Step {
    _ = build_opts;
    const elf_step = b.step("test-elf", "Run ELF tests");

    const default_target = b.resolve_target_query(.{
        .cpu_arch = .x86_64, // TODO relax this once ELF linker is able to handle other archs
        .os_tag = .linux,
    });
    const x86_64_musl = b.resolve_target_query(.{
        .cpu_arch = .x86_64,
        .os_tag = .linux,
        .abi = .musl,
    });
    const x86_64_gnu = b.resolve_target_query(.{
        .cpu_arch = .x86_64,
        .os_tag = .linux,
        .abi = .gnu,
    });
    const aarch64_musl = b.resolve_target_query(.{
        .cpu_arch = .aarch64,
        .os_tag = .linux,
        .abi = .musl,
    });
    const riscv64_musl = b.resolve_target_query(.{
        .cpu_arch = .riscv64,
        .os_tag = .linux,
        .abi = .musl,
    });

    // Common tests
    for (&[_]std.Target.Cpu.Arch{
        .x86_64,
        .aarch64,
    }) |cpu_arch| {
        const musl_target = b.resolve_target_query(.{
            .cpu_arch = cpu_arch,
            .os_tag = .linux,
            .abi = .musl,
        });
        const gnu_target = b.resolve_target_query(.{
            .cpu_arch = cpu_arch,
            .os_tag = .linux,
            .abi = .gnu,
        });

        // Exercise linker in -r mode
        elf_step.depend_on(test_emit_relocatable(b, .{ .target = musl_target }));
        elf_step.depend_on(test_relocatable_archive(b, .{ .target = musl_target }));
        elf_step.depend_on(test_relocatable_eh_frame(b, .{ .target = musl_target }));
        elf_step.depend_on(test_relocatable_no_eh_frame(b, .{ .target = musl_target }));

        // Exercise linker in ar mode
        elf_step.depend_on(test_emit_static_lib(b, .{ .target = musl_target }));

        // Exercise linker with LLVM backend
        // musl tests
        elf_step.depend_on(test_abs_symbols(b, .{ .target = musl_target }));
        elf_step.depend_on(test_common_symbols(b, .{ .target = musl_target }));
        elf_step.depend_on(test_common_symbols_in_archive(b, .{ .target = musl_target }));
        elf_step.depend_on(test_comment_string(b, .{ .target = musl_target }));
        elf_step.depend_on(test_empty_object(b, .{ .target = musl_target }));
        elf_step.depend_on(test_entry_point(b, .{ .target = musl_target }));
        elf_step.depend_on(test_gc_sections(b, .{ .target = musl_target }));
        elf_step.depend_on(test_image_base(b, .{ .target = musl_target }));
        elf_step.depend_on(test_init_array_order(b, .{ .target = musl_target }));
        elf_step.depend_on(test_large_alignment_exe(b, .{ .target = musl_target }));
        // https://github.com/ziglang/zig/issues/17449
        // elf_step.depend_on(test_large_bss(b, .{ .target = musl_target }));
        elf_step.depend_on(test_linking_c(b, .{ .target = musl_target }));
        elf_step.depend_on(test_linking_cpp(b, .{ .target = musl_target }));
        elf_step.depend_on(test_linking_zig(b, .{ .target = musl_target }));
        elf_step.depend_on(test_merge_strings(b, .{ .target = musl_target }));
        elf_step.depend_on(test_merge_strings2(b, .{ .target = musl_target }));
        // https://github.com/ziglang/zig/issues/17451
        // elf_step.depend_on(test_no_eh_frame_hdr(b, .{ .target = musl_target }));
        elf_step.depend_on(test_tls_static(b, .{ .target = musl_target }));
        elf_step.depend_on(test_strip(b, .{ .target = musl_target }));

        // glibc tests
        elf_step.depend_on(test_as_needed(b, .{ .target = gnu_target }));
        // https://github.com/ziglang/zig/issues/17430
        // elf_step.depend_on(test_canonical_plt(b, .{ .target = gnu_target }));
        elf_step.depend_on(test_comment_string(b, .{ .target = gnu_target }));
        elf_step.depend_on(test_copyrel(b, .{ .target = gnu_target }));
        // https://github.com/ziglang/zig/issues/17430
        // elf_step.depend_on(test_copyrel_alias(b, .{ .target = gnu_target }));
        // https://github.com/ziglang/zig/issues/17430
        // elf_step.depend_on(test_copyrel_alignment(b, .{ .target = gnu_target }));
        elf_step.depend_on(test_dso_plt(b, .{ .target = gnu_target }));
        elf_step.depend_on(test_dso_undef(b, .{ .target = gnu_target }));
        elf_step.depend_on(test_export_dynamic(b, .{ .target = gnu_target }));
        elf_step.depend_on(test_export_symbols_from_exe(b, .{ .target = gnu_target }));
        // https://github.com/ziglang/zig/issues/17430
        // elf_step.depend_on(test_func_address(b, .{ .target = gnu_target }));
        elf_step.depend_on(test_hidden_weak_undef(b, .{ .target = gnu_target }));
        elf_step.depend_on(test_ifunc_alias(b, .{ .target = gnu_target }));
        // https://github.com/ziglang/zig/issues/17430
        // elf_step.depend_on(test_ifunc_dlopen(b, .{ .target = gnu_target }));
        elf_step.depend_on(test_ifunc_dso(b, .{ .target = gnu_target }));
        elf_step.depend_on(test_ifunc_dynamic(b, .{ .target = gnu_target }));
        elf_step.depend_on(test_ifunc_export(b, .{ .target = gnu_target }));
        elf_step.depend_on(test_ifunc_func_ptr(b, .{ .target = gnu_target }));
        elf_step.depend_on(test_ifunc_no_plt(b, .{ .target = gnu_target }));
        // https://github.com/ziglang/zig/issues/17430 ??
        // elf_step.depend_on(test_ifunc_static(b, .{ .target = gnu_target }));
        // elf_step.depend_on(test_ifunc_static_pie(b, .{ .target = gnu_target }));
        elf_step.depend_on(test_init_array_order(b, .{ .target = gnu_target }));
        elf_step.depend_on(test_large_alignment_dso(b, .{ .target = gnu_target }));
        elf_step.depend_on(test_large_alignment_exe(b, .{ .target = gnu_target }));
        elf_step.depend_on(test_large_bss(b, .{ .target = gnu_target }));
        elf_step.depend_on(test_link_order(b, .{ .target = gnu_target }));
        elf_step.depend_on(test_ld_script(b, .{ .target = gnu_target }));
        elf_step.depend_on(test_ld_script_path_error(b, .{ .target = gnu_target }));
        elf_step.depend_on(test_ld_script_allow_undefined_version(b, .{ .target = gnu_target, .use_lld = true }));
        elf_step.depend_on(test_ld_script_disallow_undefined_version(b, .{ .target = gnu_target, .use_lld = true }));
        // https://github.com/ziglang/zig/issues/17451
        // elf_step.depend_on(test_no_eh_frame_hdr(b, .{ .target = gnu_target }));
        elf_step.depend_on(test_pie(b, .{ .target = gnu_target }));
        elf_step.depend_on(test_plt_got(b, .{ .target = gnu_target }));
        elf_step.depend_on(test_preinit_array(b, .{ .target = gnu_target }));
        elf_step.depend_on(test_shared_abs_symbol(b, .{ .target = gnu_target }));
        elf_step.depend_on(test_tls_df_static_tls(b, .{ .target = gnu_target }));
        elf_step.depend_on(test_tls_dso(b, .{ .target = gnu_target }));
        elf_step.depend_on(test_tls_gd(b, .{ .target = gnu_target }));
        elf_step.depend_on(test_tls_gd_no_plt(b, .{ .target = gnu_target }));
        elf_step.depend_on(test_tls_gd_to_ie(b, .{ .target = gnu_target }));
        elf_step.depend_on(test_tls_ie(b, .{ .target = gnu_target }));
        elf_step.depend_on(test_tls_large_alignment(b, .{ .target = gnu_target }));
        elf_step.depend_on(test_tls_large_tbss(b, .{ .target = gnu_target }));
        elf_step.depend_on(test_tls_large_static_image(b, .{ .target = gnu_target }));
        elf_step.depend_on(test_tls_ld(b, .{ .target = gnu_target }));
        elf_step.depend_on(test_tls_ld_dso(b, .{ .target = gnu_target }));
        elf_step.depend_on(test_tls_ld_no_plt(b, .{ .target = gnu_target }));
        // https://github.com/ziglang/zig/issues/17430
        // elf_step.depend_on(test_tls_no_pic(b, .{ .target = gnu_target }));
        elf_step.depend_on(test_tls_offset_alignment(b, .{ .target = gnu_target }));
        elf_step.depend_on(test_tls_pic(b, .{ .target = gnu_target }));
        elf_step.depend_on(test_tls_small_alignment(b, .{ .target = gnu_target }));
        elf_step.depend_on(test_unknown_file_type_error(b, .{ .target = gnu_target }));
        elf_step.depend_on(test_unresolved_error(b, .{ .target = gnu_target }));
        elf_step.depend_on(test_weak_exports(b, .{ .target = gnu_target }));
        elf_step.depend_on(test_weak_undefs_dso(b, .{ .target = gnu_target }));
        elf_step.depend_on(test_znow(b, .{ .target = gnu_target }));
        elf_step.depend_on(test_zstack_size(b, .{ .target = gnu_target }));
    }

    // x86_64 specific tests
    elf_step.depend_on(test_mismatched_cpu_architecture_error(b, .{ .target = x86_64_musl }));
    elf_step.depend_on(test_ztext(b, .{ .target = x86_64_gnu }));

    // aarch64 specific tests
    elf_step.depend_on(test_thunks(b, .{ .target = aarch64_musl }));

    // x86_64 self-hosted backend
    elf_step.depend_on(test_comment_string(b, .{ .use_llvm = false, .target = default_target }));
    elf_step.depend_on(test_comment_string_static_lib(b, .{ .use_llvm = false, .target = default_target }));
    elf_step.depend_on(test_emit_relocatable(b, .{ .use_llvm = false, .target = x86_64_musl }));
    elf_step.depend_on(test_emit_static_lib_zig(b, .{ .use_llvm = false, .target = x86_64_musl }));
    elf_step.depend_on(test_gc_sections_zig(b, .{ .use_llvm = false, .target = default_target }));
    elf_step.depend_on(test_linking_obj(b, .{ .use_llvm = false, .target = default_target }));
    elf_step.depend_on(test_linking_static_lib(b, .{ .use_llvm = false, .target = default_target }));
    elf_step.depend_on(test_linking_zig(b, .{ .use_llvm = false, .target = default_target }));
    elf_step.depend_on(test_importing_data_dynamic(b, .{ .use_llvm = false, .target = x86_64_gnu }));
    elf_step.depend_on(test_importing_data_static(b, .{ .use_llvm = false, .target = x86_64_musl }));

    // riscv64 linker backend is currently not complete enough to support more
    elf_step.depend_on(test_linking_c(b, .{ .target = riscv64_musl }));

    return elf_step;
}

fn test_abs_symbols(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "abs-symbols", opts);

    const obj = add_object(b, opts, .{
        .name = "obj",
        .asm_source_bytes =
        \\.globl foo
        \\foo = 0x800008
        \\
        ,
    });

    const exe = add_executable(b, opts, .{
        .name = "test",
        .c_source_bytes =
        \\#include <signal.h>
        \\#include <stdio.h>
        \\#include <stdlib.h>
        \\#include <ucontext.h>
        \\#include <assert.h>
        \\void handler(int signum, siginfo_t *info, void *ptr) {
        \\  assert((size_t)info->si_addr == 0x800008);
        \\  exit(0);
        \\}
        \\extern int foo;
        \\int main() {
        \\  struct sigaction act;
        \\  act.sa_flags = SA_SIGINFO | SA_RESETHAND;
        \\  act.sa_sigaction = handler;
        \\  sigemptyset(&act.sa_mask);
        \\  sigaction(SIGSEGV, &act, 0);
        \\  foo = 5;
        \\  return 0;
        \\}
        ,
    });
    exe.add_object(obj);
    exe.link_lib_c();

    const run = add_run_artifact(exe);
    run.expect_exit_code(0);
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_as_needed(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "as-needed", opts);

    const main_o = add_object(b, opts, .{
        .name = "main",
        .c_source_bytes =
        \\#include <stdio.h>
        \\int baz();
        \\int main() {
        \\  printf("%d\n", baz());
        \\  return 0;
        \\}
        \\
        ,
    });
    main_o.link_lib_c();

    const libfoo = add_shared_library(b, opts, .{ .name = "foo" });
    add_csource_bytes(libfoo, "int foo() { return 42; }", &.{});

    const libbar = add_shared_library(b, opts, .{ .name = "bar" });
    add_csource_bytes(libbar, "int bar() { return 42; }", &.{});

    const libbaz = add_shared_library(b, opts, .{ .name = "baz" });
    add_csource_bytes(libbaz,
        \\int foo();
        \\int baz() { return foo(); }
    , &.{});

    {
        const exe = add_executable(b, opts, .{
            .name = "test",
        });
        exe.add_object(main_o);
        exe.link_system_library2("foo", .{ .needed = true });
        exe.add_library_path(libfoo.get_emitted_bin_directory());
        exe.add_rpath(libfoo.get_emitted_bin_directory());
        exe.link_system_library2("bar", .{ .needed = true });
        exe.add_library_path(libbar.get_emitted_bin_directory());
        exe.add_rpath(libbar.get_emitted_bin_directory());
        exe.link_system_library2("baz", .{ .needed = true });
        exe.add_library_path(libbaz.get_emitted_bin_directory());
        exe.add_rpath(libbaz.get_emitted_bin_directory());
        exe.link_lib_c();

        const run = add_run_artifact(exe);
        run.expect_std_out_equal("42\n");
        test_step.depend_on(&run.step);

        const check = exe.check_object();
        check.check_in_dynamic_section();
        check.check_exact("NEEDED libfoo.so");
        check.check_exact("NEEDED libbar.so");
        check.check_exact("NEEDED libbaz.so");
        test_step.depend_on(&check.step);
    }

    {
        const exe = add_executable(b, opts, .{
            .name = "test",
        });
        exe.add_object(main_o);
        exe.link_system_library2("foo", .{ .needed = false });
        exe.add_library_path(libfoo.get_emitted_bin_directory());
        exe.add_rpath(libfoo.get_emitted_bin_directory());
        exe.link_system_library2("bar", .{ .needed = false });
        exe.add_library_path(libbar.get_emitted_bin_directory());
        exe.add_rpath(libbar.get_emitted_bin_directory());
        exe.link_system_library2("baz", .{ .needed = false });
        exe.add_library_path(libbaz.get_emitted_bin_directory());
        exe.add_rpath(libbaz.get_emitted_bin_directory());
        exe.link_lib_c();

        const run = add_run_artifact(exe);
        run.expect_std_out_equal("42\n");
        test_step.depend_on(&run.step);

        const check = exe.check_object();
        check.check_in_dynamic_section();
        check.check_not_present("NEEDED libbar.so");
        check.check_in_dynamic_section();
        check.check_exact("NEEDED libfoo.so");
        check.check_exact("NEEDED libbaz.so");
        test_step.depend_on(&check.step);
    }

    return test_step;
}

fn test_canonical_plt(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "canonical-plt", opts);

    const dso = add_shared_library(b, opts, .{ .name = "a" });
    add_csource_bytes(dso,
        \\void *foo() {
        \\  return foo;
        \\}
        \\void *bar() {
        \\  return bar;
        \\}
    , &.{});

    const b_o = add_object(b, opts, .{
        .name = "obj",
        .c_source_bytes =
        \\void *bar();
        \\void *baz() {
        \\  return bar;
        \\}
        \\
        ,
        .pic = true,
    });

    const main_o = add_object(b, opts, .{
        .name = "main",
        .c_source_bytes =
        \\#include <assert.h>
        \\void *foo();
        \\void *bar();
        \\void *baz();
        \\int main() {
        \\  assert(foo == foo());
        \\  assert(bar == bar());
        \\  assert(bar == baz());
        \\  return 0;
        \\}
        \\
        ,
        .pic = false,
    });
    main_o.link_lib_c();

    const exe = add_executable(b, opts, .{
        .name = "main",
    });
    exe.add_object(main_o);
    exe.add_object(b_o);
    exe.link_library(dso);
    exe.link_lib_c();
    exe.pie = false;

    const run = add_run_artifact(exe);
    run.expect_exit_code(0);
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_comment_string(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "comment-string", opts);

    const exe = add_executable(b, opts, .{ .name = "main", .zig_source_bytes = 
    \\pub fn main() void {}
    });

    const check = exe.check_object();
    check.dump_section(".comment");
    check.check_contains("zig");
    test_step.depend_on(&check.step);

    return test_step;
}

fn test_comment_string_static_lib(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "comment-string-static-lib", opts);

    const lib = add_static_library(b, opts, .{ .name = "lib", .zig_source_bytes = 
    \\export fn foo() void {}
    });

    const check = lib.check_object();
    check.dump_section(".comment");
    check.check_contains("zig");
    test_step.depend_on(&check.step);

    return test_step;
}

fn test_common_symbols(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "common-symbols", opts);

    const exe = add_executable(b, opts, .{
        .name = "test",
    });
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
    exe.link_lib_c();

    const run = add_run_artifact(exe);
    run.expect_std_out_equal("0 5 42\n");
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_common_symbols_in_archive(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "common-symbols-in-archive", opts);

    const a_o = add_object(b, opts, .{
        .name = "a",
        .c_source_bytes =
        \\#include <stdio.h>
        \\int foo;
        \\int bar;
        \\extern int baz;
        \\__attribute__((weak)) int two();
        \\int main() {
        \\  printf("%d %d %d %d\n", foo, bar, baz, two ? two() : -1);
        \\}
        \\
        ,
        .c_source_flags = &.{"-fcommon"},
    });
    a_o.link_lib_c();

    const b_o = add_object(b, opts, .{
        .name = "b",
        .c_source_bytes = "int foo = 5;",
        .c_source_flags = &.{"-fcommon"},
    });

    {
        const c_o = add_object(b, opts, .{
            .name = "c",
            .c_source_bytes =
            \\int bar;
            \\int two() { return 2; }
            \\
            ,
            .c_source_flags = &.{"-fcommon"},
        });

        const d_o = add_object(b, opts, .{
            .name = "d",
            .c_source_bytes = "int baz;",
            .c_source_flags = &.{"-fcommon"},
        });

        const lib = add_static_library(b, opts, .{ .name = "lib" });
        lib.add_object(b_o);
        lib.add_object(c_o);
        lib.add_object(d_o);

        const exe = add_executable(b, opts, .{
            .name = "test",
        });
        exe.add_object(a_o);
        exe.link_library(lib);
        exe.link_lib_c();

        const run = add_run_artifact(exe);
        run.expect_std_out_equal("5 0 0 -1\n");
        test_step.depend_on(&run.step);
    }

    {
        const e_o = add_object(b, opts, .{
            .name = "e",
            .c_source_bytes =
            \\int bar = 0;
            \\int baz = 7;
            \\int two() { return 2; }
            ,
            .c_source_flags = &.{"-fcommon"},
        });

        const lib = add_static_library(b, opts, .{ .name = "lib" });
        lib.add_object(b_o);
        lib.add_object(e_o);

        const exe = add_executable(b, opts, .{
            .name = "test",
        });
        exe.add_object(a_o);
        exe.link_library(lib);
        exe.link_lib_c();

        const run = add_run_artifact(exe);
        run.expect_std_out_equal("5 0 7 2\n");
        test_step.depend_on(&run.step);
    }

    return test_step;
}

fn test_copyrel(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "copyrel", opts);

    const dso = add_shared_library(b, opts, .{ .name = "a" });
    add_csource_bytes(dso,
        \\int foo = 3;
        \\int bar = 5;
    , &.{});

    const exe = add_executable(b, opts, .{
        .name = "main",
        .c_source_bytes =
        \\#include<stdio.h>
        \\extern int foo, bar;
        \\int main() {
        \\  printf("%d %d\n", foo, bar);
        \\  return 0;
        \\}
        ,
    });
    exe.link_library(dso);
    exe.link_lib_c();

    const run = add_run_artifact(exe);
    run.expect_std_out_equal("3 5\n");
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_copyrel_alias(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "copyrel-alias", opts);

    const dso = add_shared_library(b, opts, .{ .name = "a" });
    add_csource_bytes(dso,
        \\int bruh = 31;
        \\int foo = 42;
        \\extern int bar __attribute__((alias("foo")));
        \\extern int baz __attribute__((alias("foo")));
    , &.{});

    const exe = add_executable(b, opts, .{
        .name = "main",
        .pic = false,
    });
    add_csource_bytes(exe,
        \\#include<stdio.h>
        \\extern int foo;
        \\extern int *get_bar();
        \\int main() {
        \\  printf("%d %d %d\n", foo, *get_bar(), &foo == get_bar());
        \\  return 0;
        \\}
    , &.{});
    add_csource_bytes(exe,
        \\extern int bar;
        \\int *get_bar() { return &bar; }
    , &.{});
    exe.link_library(dso);
    exe.link_lib_c();
    exe.pie = false;

    const run = add_run_artifact(exe);
    run.expect_std_out_equal("42 42 1\n");
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_copyrel_alignment(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "copyrel-alignment", opts);

    const a_so = add_shared_library(b, opts, .{ .name = "a" });
    add_csource_bytes(a_so, "__attribute__((aligned(32))) int foo = 5;", &.{});

    const b_so = add_shared_library(b, opts, .{ .name = "b" });
    add_csource_bytes(b_so, "__attribute__((aligned(8))) int foo = 5;", &.{});

    const c_so = add_shared_library(b, opts, .{ .name = "c" });
    add_csource_bytes(c_so, "__attribute__((aligned(256))) int foo = 5;", &.{});

    const obj = add_object(b, opts, .{
        .name = "main",
        .c_source_bytes =
        \\#include <stdio.h>
        \\extern int foo;
        \\int main() { printf("%d\n", foo); }
        \\
        ,
        .pic = false,
    });
    obj.link_lib_c();

    const exp_stdout = "5\n";

    {
        const exe = add_executable(b, opts, .{ .name = "main" });
        exe.add_object(obj);
        exe.link_library(a_so);
        exe.link_lib_c();
        exe.pie = false;

        const run = add_run_artifact(exe);
        run.expect_std_out_equal(exp_stdout);
        test_step.depend_on(&run.step);

        const check = exe.check_object();
        check.check_in_headers();
        check.check_exact("section headers");
        check.check_exact("name .copyrel");
        check.check_exact("addralign 20");
        test_step.depend_on(&check.step);
    }

    {
        const exe = add_executable(b, opts, .{ .name = "main" });
        exe.add_object(obj);
        exe.link_library(b_so);
        exe.link_lib_c();
        exe.pie = false;

        const run = add_run_artifact(exe);
        run.expect_std_out_equal(exp_stdout);
        test_step.depend_on(&run.step);

        const check = exe.check_object();
        check.check_in_headers();
        check.check_exact("section headers");
        check.check_exact("name .copyrel");
        check.check_exact("addralign 8");
        test_step.depend_on(&check.step);
    }

    {
        const exe = add_executable(b, opts, .{ .name = "main" });
        exe.add_object(obj);
        exe.link_library(c_so);
        exe.link_lib_c();
        exe.pie = false;

        const run = add_run_artifact(exe);
        run.expect_std_out_equal(exp_stdout);
        test_step.depend_on(&run.step);

        const check = exe.check_object();
        check.check_in_headers();
        check.check_exact("section headers");
        check.check_exact("name .copyrel");
        check.check_exact("addralign 100");
        test_step.depend_on(&check.step);
    }

    return test_step;
}

fn test_dso_plt(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "dso-plt", opts);

    const dso = add_shared_library(b, opts, .{ .name = "dso" });
    add_csource_bytes(dso,
        \\#include<stdio.h>
        \\void world() {
        \\  printf("world\n");
        \\}
        \\void real_hello() {
        \\  printf("Hello ");
        \\  world();
        \\}
        \\void hello() {
        \\  real_hello();
        \\}
    , &.{});
    dso.link_lib_c();

    const exe = add_executable(b, opts, .{ .name = "test" });
    add_csource_bytes(exe,
        \\#include<stdio.h>
        \\void world() {
        \\  printf("WORLD\n");
        \\}
        \\void hello();
        \\int main() {
        \\  hello();
        \\}
    , &.{});
    exe.link_library(dso);
    exe.link_lib_c();

    const run = add_run_artifact(exe);
    run.expect_std_out_equal("Hello WORLD\n");
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_dso_undef(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "dso-undef", opts);

    const dso = add_shared_library(b, opts, .{ .name = "dso" });
    add_csource_bytes(dso,
        \\extern int foo;
        \\int bar = 5;
        \\int baz() { return foo; }
    , &.{});
    dso.link_lib_c();

    const obj = add_object(b, opts, .{
        .name = "obj",
        .c_source_bytes = "int foo = 3;",
    });

    const lib = add_static_library(b, opts, .{ .name = "lib" });
    lib.add_object(obj);

    const exe = add_executable(b, opts, .{ .name = "test" });
    exe.link_library(dso);
    exe.link_library(lib);
    add_csource_bytes(exe,
        \\extern int bar;
        \\int main() {
        \\  return bar - 5;
        \\}
    , &.{});
    exe.link_lib_c();

    const run = add_run_artifact(exe);
    run.expect_exit_code(0);
    test_step.depend_on(&run.step);

    const check = exe.check_object();
    check.check_in_dynamic_symtab();
    check.check_contains("foo");
    test_step.depend_on(&check.step);

    return test_step;
}

fn test_emit_relocatable(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "emit-relocatable", opts);

    const a_o = add_object(b, opts, .{ .name = "a", .zig_source_bytes = 
    \\const std = @import("std");
    \\extern var bar: i32;
    \\export fn foo() i32 {
    \\   return bar;
    \\}
    \\export fn print_foo() void {
    \\    std.debug.print("foo={d}\n", .{foo()});
    \\}
    });
    a_o.link_lib_c();

    const b_o = add_object(b, opts, .{ .name = "b", .c_source_bytes = 
    \\#include <stdio.h>
    \\int bar = 42;
    \\void print_bar() {
    \\  fprintf(stderr, "bar=%d\n", bar);
    \\}
    });
    b_o.link_lib_c();

    const c_o = add_object(b, opts, .{ .name = "c" });
    c_o.add_object(a_o);
    c_o.add_object(b_o);

    const exe = add_executable(b, opts, .{ .name = "test", .zig_source_bytes = 
    \\const std = @import("std");
    \\extern fn print_foo() void;
    \\extern fn print_bar() void;
    \\pub fn main() void {
    \\    print_foo();
    \\    print_bar();
    \\}
    });
    exe.add_object(c_o);
    exe.link_lib_c();

    const run = add_run_artifact(exe);
    run.expect_std_err_equal(
        \\foo=42
        \\bar=42
        \\
    );
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_emit_static_lib(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "emit-static-lib", opts);

    const obj1 = add_object(b, opts, .{
        .name = "obj1",
        .c_source_bytes =
        \\int foo = 0;
        \\int bar = 2;
        \\int foo_bar() {
        \\  return foo + bar;
        \\}
        ,
    });

    const obj2 = add_object(b, opts, .{
        .name = "obj2",
        .c_source_bytes = "int tentative;",
        .c_source_flags = &.{"-fcommon"},
    });

    const obj3 = add_object(b, opts, .{
        .name = "a_very_long_file_name_so_that_it_ends_up_in_strtab",
        .zig_source_bytes =
        \\fn weak_foo() callconv(.C) usize {
        \\    return 42;
        \\}
        \\export var strongBar: usize = 100;
        \\comptime {
        \\    @export(weak_foo, .{ .name = "weak_foo", .linkage = .weak });
        \\    @export(strongBar, .{ .name = "strongBarAlias", .linkage = .strong });
        \\}
        ,
    });

    const lib = add_static_library(b, opts, .{ .name = "lib" });
    lib.add_object(obj1);
    lib.add_object(obj2);
    lib.add_object(obj3);

    const check = lib.check_object();
    check.check_in_archive_symtab();
    check.check_exact_path("in object", obj1.get_emitted_bin());
    check.check_exact("foo");
    check.check_in_archive_symtab();
    check.check_exact_path("in object", obj1.get_emitted_bin());
    check.check_exact("bar");
    check.check_in_archive_symtab();
    check.check_exact_path("in object", obj1.get_emitted_bin());
    check.check_exact("foo_bar");
    check.check_in_archive_symtab();
    check.check_exact_path("in object", obj2.get_emitted_bin());
    check.check_exact("tentative");
    check.check_in_archive_symtab();
    check.check_exact_path("in object", obj3.get_emitted_bin());
    check.check_exact("weak_foo");
    check.check_in_archive_symtab();
    check.check_exact_path("in object", obj3.get_emitted_bin());
    check.check_exact("strongBar");
    check.check_in_archive_symtab();
    check.check_exact_path("in object", obj3.get_emitted_bin());
    check.check_exact("strongBarAlias");
    test_step.depend_on(&check.step);

    return test_step;
}

fn test_emit_static_lib_zig(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "emit-static-lib-zig", opts);

    const obj1 = add_object(b, opts, .{
        .name = "obj1",
        .zig_source_bytes =
        \\export var foo: i32 = 42;
        \\export var bar: i32 = 2;
        ,
    });

    const lib = add_static_library(b, opts, .{
        .name = "lib",
        .zig_source_bytes =
        \\extern var foo: i32;
        \\extern var bar: i32;
        \\export fn foo_bar() i32 {
        \\  return foo + bar;
        \\}
        ,
    });
    lib.add_object(obj1);

    const exe = add_executable(b, opts, .{
        .name = "test",
        .zig_source_bytes =
        \\const std = @import("std");
        \\extern fn foo_bar() i32;
        \\pub fn main() void {
        \\  std.debug.print("{d}", .{foo_bar()});
        \\}
        ,
    });
    exe.link_library(lib);

    const run = add_run_artifact(exe);
    run.expect_std_err_equal("44");
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_empty_object(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "empty-object", opts);

    const exe = add_executable(b, opts, .{ .name = "test" });
    add_csource_bytes(exe, "int main() { return 0; }", &.{});
    add_csource_bytes(exe, "", &.{});
    exe.link_lib_c();

    const run = add_run_artifact(exe);
    run.expect_exit_code(0);
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_entry_point(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "entry-point", opts);

    const a_o = add_object(b, opts, .{
        .name = "a",
        .asm_source_bytes =
        \\.globl foo, bar
        \\foo = 0x1000
        \\bar = 0x2000
        \\
        ,
    });

    const b_o = add_object(b, opts, .{
        .name = "b",
        .c_source_bytes = "int main() { return 0; }",
    });

    {
        const exe = add_executable(b, opts, .{ .name = "main" });
        exe.add_object(a_o);
        exe.add_object(b_o);
        exe.entry = .{ .symbol_name = "foo" };

        const check = exe.check_object();
        check.check_in_headers();
        check.check_exact("header");
        check.check_exact("entry 1000");
        test_step.depend_on(&check.step);
    }

    {
        // TODO looks like not assigning a unique name to this executable will
        // cause an artifact collision taking the cached executable from the above
        // step instead of generating a new one.
        const exe = add_executable(b, opts, .{ .name = "other" });
        exe.add_object(a_o);
        exe.add_object(b_o);
        exe.entry = .{ .symbol_name = "bar" };

        const check = exe.check_object();
        check.check_in_headers();
        check.check_exact("header");
        check.check_exact("entry 2000");
        test_step.depend_on(&check.step);
    }

    return test_step;
}

fn test_export_dynamic(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "export-dynamic", opts);

    const obj = add_object(b, opts, .{
        .name = "obj",
        .asm_source_bytes =
        \\.text
        \\  .globl foo
        \\  .hidden foo
        \\foo:
        \\  nop
        \\  .globl bar
        \\bar:
        \\  nop
        \\  .globl _start
        \\_start:
        \\  nop
        \\
        ,
    });

    const dso = add_shared_library(b, opts, .{ .name = "a" });
    add_csource_bytes(dso, "int baz = 10;", &.{});

    const exe = add_executable(b, opts, .{ .name = "main" });
    add_csource_bytes(exe,
        \\extern int baz;
        \\int callBaz() {
        \\  return baz;
        \\}
    , &.{});
    exe.add_object(obj);
    exe.link_library(dso);
    exe.rdynamic = true;

    const check = exe.check_object();
    check.check_in_dynamic_symtab();
    check.check_contains("bar");
    check.check_in_dynamic_symtab();
    check.check_contains("_start");
    test_step.depend_on(&check.step);

    return test_step;
}

fn test_export_symbols_from_exe(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "export-symbols-from-exe", opts);

    const dso = add_shared_library(b, opts, .{ .name = "a" });
    add_csource_bytes(dso,
        \\void expfn1();
        \\void expfn2() {}
        \\
        \\void foo() {
        \\  expfn1();
        \\}
    , &.{});

    const exe = add_executable(b, opts, .{ .name = "main" });
    add_csource_bytes(exe,
        \\void expfn1() {}
        \\void expfn2() {}
        \\void foo();
        \\
        \\int main() {
        \\  expfn1();
        \\  expfn2();
        \\  foo();
        \\}
    , &.{});
    exe.link_library(dso);
    exe.link_lib_c();

    const check = exe.check_object();
    check.check_in_dynamic_symtab();
    check.check_contains("expfn2");
    check.check_in_dynamic_symtab();
    check.check_contains("expfn1");
    test_step.depend_on(&check.step);

    return test_step;
}

fn test_func_address(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "func-address", opts);

    const dso = add_shared_library(b, opts, .{ .name = "a" });
    add_csource_bytes(dso, "void fn() {}", &.{});

    const exe = add_executable(b, opts, .{ .name = "main" });
    add_csource_bytes(exe,
        \\#include <assert.h>
        \\typedef void Func();
        \\void fn();
        \\Func *const ptr = fn;
        \\int main() {
        \\  assert(fn == ptr);
        \\}
    , &.{});
    exe.link_library(dso);
    exe.root_module.pic = false;
    exe.pie = false;

    const run = add_run_artifact(exe);
    run.expect_exit_code(0);
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_gc_sections(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "gc-sections", opts);

    const obj = add_object(b, opts, .{
        .name = "obj",
        .cpp_source_bytes =
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
        ,
    });
    obj.link_function_sections = true;
    obj.link_data_sections = true;
    obj.link_lib_c();
    obj.link_lib_cpp();

    {
        const exe = add_executable(b, opts, .{ .name = "test" });
        exe.add_object(obj);
        exe.link_gc_sections = false;
        exe.link_lib_c();
        exe.link_lib_cpp();

        const run = add_run_artifact(exe);
        run.expect_std_out_equal("1 2\n");
        test_step.depend_on(&run.step);

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
    }

    {
        const exe = add_executable(b, opts, .{ .name = "test" });
        exe.add_object(obj);
        exe.link_gc_sections = true;
        exe.link_lib_c();
        exe.link_lib_cpp();

        const run = add_run_artifact(exe);
        run.expect_std_out_equal("1 2\n");
        test_step.depend_on(&run.step);

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
    }

    return test_step;
}

fn test_gc_sections_zig(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "gc-sections-zig", opts);

    const obj = add_object(b, .{
        .target = opts.target,
        .use_llvm = true,
    }, .{
        .name = "obj",
        .c_source_bytes =
        \\int live_var1 = 1;
        \\int live_var2 = 2;
        \\int dead_var1 = 3;
        \\int dead_var2 = 4;
        \\void live_fn1() {}
        \\void live_fn2() { live_fn1(); }
        \\void dead_fn1() {}
        \\void dead_fn2() { dead_fn1(); }
        ,
    });
    obj.link_function_sections = true;
    obj.link_data_sections = true;

    {
        const exe = add_executable(b, opts, .{
            .name = "test1",
            .zig_source_bytes =
            \\const std = @import("std");
            \\extern var live_var1: i32;
            \\extern var live_var2: i32;
            \\extern fn live_fn2() void;
            \\pub fn main() void {
            \\    const stdout = std.io.get_std_out();
            \\    stdout.writer().print("{d} {d}\n", .{ live_var1, live_var2 }) catch unreachable;
            \\    live_fn2();
            \\}
            ,
        });
        exe.add_object(obj);
        exe.link_gc_sections = false;

        const run = add_run_artifact(exe);
        run.expect_std_out_equal("1 2\n");
        test_step.depend_on(&run.step);

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
    }

    {
        const exe = add_executable(b, opts, .{
            .name = "test2",
            .zig_source_bytes =
            \\const std = @import("std");
            \\extern var live_var1: i32;
            \\extern var live_var2: i32;
            \\extern fn live_fn2() void;
            \\pub fn main() void {
            \\    const stdout = std.io.get_std_out();
            \\    stdout.writer().print("{d} {d}\n", .{ live_var1, live_var2 }) catch unreachable;
            \\    live_fn2();
            \\}
            ,
        });
        exe.add_object(obj);
        exe.link_gc_sections = true;

        const run = add_run_artifact(exe);
        run.expect_std_out_equal("1 2\n");
        test_step.depend_on(&run.step);

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
    }

    return test_step;
}

fn test_hidden_weak_undef(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "hidden-weak-undef", opts);

    const dso = add_shared_library(b, opts, .{ .name = "a" });
    add_csource_bytes(dso,
        \\__attribute__((weak, visibility("hidden"))) void foo();
        \\void bar() { foo(); }
    , &.{});

    const check = dso.check_object();
    check.check_in_dynamic_symtab();
    check.check_not_present("foo");
    check.check_in_dynamic_symtab();
    check.check_contains("bar");
    test_step.depend_on(&check.step);

    return test_step;
}

fn test_ifunc_alias(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "ifunc-alias", opts);

    const exe = add_executable(b, opts, .{ .name = "main" });
    add_csource_bytes(exe,
        \\#include <assert.h>
        \\void foo() {}
        \\int bar() __attribute__((ifunc("resolve_bar")));
        \\void *resolve_bar() { return foo; }
        \\void *bar2 = bar;
        \\int main() {
        \\  assert(bar == bar2);
        \\}
    , &.{});
    exe.root_module.pic = true;
    exe.link_lib_c();

    const run = add_run_artifact(exe);
    run.expect_exit_code(0);
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_ifunc_dlopen(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "ifunc-dlopen", opts);

    const dso = add_shared_library(b, opts, .{ .name = "a" });
    add_csource_bytes(dso,
        \\__attribute__((ifunc("resolve_foo")))
        \\void foo(void);
        \\static void real_foo(void) {
        \\}
        \\typedef void Func();
        \\static Func *resolve_foo(void) {
        \\  return real_foo;
        \\}
    , &.{});

    const exe = add_executable(b, opts, .{ .name = "main" });
    add_csource_bytes(exe,
        \\#include <dlfcn.h>
        \\#include <assert.h>
        \\#include <stdlib.h>
        \\typedef void Func();
        \\void foo(void);
        \\int main() {
        \\  void *handle = dlopen(NULL, RTLD_NOW);
        \\  Func *p = dlsym(handle, "foo");
        \\
        \\  foo();
        \\  p();
        \\  assert(foo == p);
        \\}
    , &.{});
    exe.link_library(dso);
    exe.link_lib_c();
    exe.link_system_library2("dl", .{});
    exe.root_module.pic = false;
    exe.pie = false;

    const run = add_run_artifact(exe);
    run.expect_exit_code(0);
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_ifunc_dso(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "ifunc-dso", opts);

    const dso = add_shared_library(b, opts, .{
        .name = "a",
        .c_source_bytes =
        \\#include<stdio.h>
        \\__attribute__((ifunc("resolve_foobar")))
        \\void foobar(void);
        \\static void real_foobar(void) {
        \\  printf("Hello world\n");
        \\}
        \\typedef void Func();
        \\static Func *resolve_foobar(void) {
        \\  return real_foobar;
        \\}
        ,
    });
    dso.link_lib_c();

    const exe = add_executable(b, opts, .{
        .name = "main",
        .c_source_bytes =
        \\void foobar(void);
        \\int main() {
        \\  foobar();
        \\}
        ,
    });
    exe.link_library(dso);

    const run = add_run_artifact(exe);
    run.expect_std_out_equal("Hello world\n");
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_ifunc_dynamic(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "ifunc-dynamic", opts);

    const main_c =
        \\#include <stdio.h>
        \\__attribute__((ifunc("resolve_foobar")))
        \\static void foobar(void);
        \\static void real_foobar(void) {
        \\  printf("Hello world\n");
        \\}
        \\typedef void Func();
        \\static Func *resolve_foobar(void) {
        \\  return real_foobar;
        \\}
        \\int main() {
        \\  foobar();
        \\}
    ;

    {
        const exe = add_executable(b, opts, .{ .name = "main" });
        add_csource_bytes(exe, main_c, &.{});
        exe.link_lib_c();
        exe.link_z_lazy = true;

        const run = add_run_artifact(exe);
        run.expect_std_out_equal("Hello world\n");
        test_step.depend_on(&run.step);
    }
    {
        const exe = add_executable(b, opts, .{ .name = "other" });
        add_csource_bytes(exe, main_c, &.{});
        exe.link_lib_c();

        const run = add_run_artifact(exe);
        run.expect_std_out_equal("Hello world\n");
        test_step.depend_on(&run.step);
    }

    return test_step;
}

fn test_ifunc_export(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "ifunc-export", opts);

    const dso = add_shared_library(b, opts, .{ .name = "a" });
    add_csource_bytes(dso,
        \\#include <stdio.h>
        \\__attribute__((ifunc("resolve_foobar")))
        \\void foobar(void);
        \\void real_foobar(void) {
        \\  printf("Hello world\n");
        \\}
        \\typedef void Func();
        \\Func *resolve_foobar(void) {
        \\  return real_foobar;
        \\}
    , &.{});
    dso.link_lib_c();

    const check = dso.check_object();
    check.check_in_dynamic_symtab();
    check.check_contains("IFUNC GLOBAL DEFAULT foobar");
    test_step.depend_on(&check.step);

    return test_step;
}

fn test_ifunc_func_ptr(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "ifunc-func-ptr", opts);

    const exe = add_executable(b, opts, .{ .name = "main" });
    add_csource_bytes(exe,
        \\typedef int Fn();
        \\int foo() __attribute__((ifunc("resolve_foo")));
        \\int real_foo() { return 3; }
        \\Fn *resolve_foo(void) {
        \\  return real_foo;
        \\}
    , &.{});
    add_csource_bytes(exe,
        \\typedef int Fn();
        \\int foo();
        \\Fn *get_foo() { return foo; }
    , &.{});
    add_csource_bytes(exe,
        \\#include <stdio.h>
        \\typedef int Fn();
        \\Fn *get_foo();
        \\int main() {
        \\  Fn *f = get_foo();
        \\  printf("%d\n", f());
        \\}
    , &.{});
    exe.root_module.pic = true;
    exe.link_lib_c();

    const run = add_run_artifact(exe);
    run.expect_std_out_equal("3\n");
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_ifunc_no_plt(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "ifunc-noplt", opts);

    const exe = add_executable(b, opts, .{ .name = "main" });
    add_csource_bytes(exe,
        \\#include <stdio.h>
        \\__attribute__((ifunc("resolve_foo")))
        \\void foo(void);
        \\void hello(void) {
        \\  printf("Hello world\n");
        \\}
        \\typedef void Fn();
        \\Fn *resolve_foo(void) {
        \\  return hello;
        \\}
        \\int main() {
        \\  foo();
        \\}
    , &.{"-fno-plt"});
    exe.root_module.pic = true;
    exe.link_lib_c();

    const run = add_run_artifact(exe);
    run.expect_std_out_equal("Hello world\n");
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_ifunc_static(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "ifunc-static", opts);

    const exe = add_executable(b, opts, .{ .name = "main" });
    add_csource_bytes(exe,
        \\#include <stdio.h>
        \\void foo() __attribute__((ifunc("resolve_foo")));
        \\void hello() {
        \\  printf("Hello world\n");
        \\}
        \\void *resolve_foo() {
        \\  return hello;
        \\}
        \\int main() {
        \\  foo();
        \\  return 0;
        \\}
    , &.{});
    exe.link_lib_c();
    exe.linkage = .static;

    const run = add_run_artifact(exe);
    run.expect_std_out_equal("Hello world\n");
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_ifunc_static_pie(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "ifunc-static-pie", opts);

    const exe = add_executable(b, opts, .{ .name = "main" });
    add_csource_bytes(exe,
        \\#include <stdio.h>
        \\void foo() __attribute__((ifunc("resolve_foo")));
        \\void hello() {
        \\  printf("Hello world\n");
        \\}
        \\void *resolve_foo() {
        \\  return hello;
        \\}
        \\int main() {
        \\  foo();
        \\  return 0;
        \\}
    , &.{});
    exe.linkage = .static;
    exe.root_module.pic = true;
    exe.pie = true;
    exe.link_lib_c();

    const run = add_run_artifact(exe);
    run.expect_std_out_equal("Hello world\n");
    test_step.depend_on(&run.step);

    const check = exe.check_object();
    check.check_in_headers();
    check.check_exact("header");
    check.check_exact("type DYN");
    check.check_in_headers();
    check.check_exact("section headers");
    check.check_exact("name .dynamic");
    check.check_in_headers();
    check.check_exact("section headers");
    check.check_not_present("name .interp");
    test_step.depend_on(&check.step);

    return test_step;
}

fn test_image_base(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "image-base", opts);

    {
        const exe = add_executable(b, opts, .{ .name = "main1" });
        add_csource_bytes(exe,
            \\#include <stdio.h>
            \\int main() {
            \\  printf("Hello World!\n");
            \\  return 0;
            \\}
        , &.{});
        exe.link_lib_c();
        exe.image_base = 0x8000000;

        const run = add_run_artifact(exe);
        run.expect_std_out_equal("Hello World!\n");
        test_step.depend_on(&run.step);

        const check = exe.check_object();
        check.check_in_headers();
        check.check_exact("header");
        check.check_extract("entry {addr}");
        check.check_compute_compare("addr", .{ .op = .gte, .value = .{ .literal = 0x8000000 } });
        test_step.depend_on(&check.step);
    }

    {
        const exe = add_executable(b, opts, .{ .name = "main2" });
        add_csource_bytes(exe, "void _start() {}", &.{});
        exe.image_base = 0xffffffff8000000;

        const check = exe.check_object();
        check.check_in_headers();
        check.check_exact("header");
        check.check_extract("entry {addr}");
        check.check_compute_compare("addr", .{ .op = .gte, .value = .{ .literal = 0xffffffff8000000 } });
        test_step.depend_on(&check.step);
    }

    return test_step;
}

fn test_importing_data_dynamic(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "importing-data-dynamic", opts);

    const dso = add_shared_library(b, .{
        .target = opts.target,
        .optimize = opts.optimize,
        .use_llvm = true,
    }, .{
        .name = "a",
        .c_source_bytes = "int foo = 42;",
    });

    const main = add_executable(b, opts, .{
        .name = "main",
        .zig_source_bytes =
        \\extern var foo: i32;
        \\pub fn main() void {
        \\    @import("std").debug.print("{d}\n", .{foo});
        \\}
        ,
        .strip = true, // TODO temp hack
    });
    main.pie = true;
    main.link_library(dso);
    main.link_lib_c();

    const run = add_run_artifact(main);
    run.expect_std_err_equal("42\n");
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_importing_data_static(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "importing-data-static", opts);

    const obj = add_object(b, .{
        .target = opts.target,
        .optimize = opts.optimize,
        .use_llvm = true,
    }, .{
        .name = "a",
        .c_source_bytes = "int foo = 42;",
    });

    const lib = add_static_library(b, .{
        .target = opts.target,
        .optimize = opts.optimize,
        .use_llvm = true,
    }, .{
        .name = "a",
    });
    lib.add_object(obj);

    const main = add_executable(b, opts, .{
        .name = "main",
        .zig_source_bytes =
        \\extern var foo: i32;
        \\pub fn main() void {
        \\    @import("std").debug.print("{d}\n", .{foo});
        \\}
        ,
        .strip = true, // TODO temp hack
    });
    main.link_library(lib);
    main.link_lib_c();

    const run = add_run_artifact(main);
    run.expect_std_err_equal("42\n");
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_init_array_order(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "init-array-order", opts);

    const a_o = add_object(b, opts, .{
        .name = "a",
        .c_source_bytes =
        \\#include <stdio.h>
        \\__attribute__((constructor(10000))) void init4() { printf("1"); }
        ,
    });
    a_o.link_lib_c();

    const b_o = add_object(b, opts, .{
        .name = "b",
        .c_source_bytes =
        \\#include <stdio.h>
        \\__attribute__((constructor(1000))) void init3() { printf("2"); }
        ,
    });
    b_o.link_lib_c();

    const c_o = add_object(b, opts, .{
        .name = "c",
        .c_source_bytes =
        \\#include <stdio.h>
        \\__attribute__((constructor)) void init1() { printf("3"); }
        ,
    });
    c_o.link_lib_c();

    const d_o = add_object(b, opts, .{
        .name = "d",
        .c_source_bytes =
        \\#include <stdio.h>
        \\__attribute__((constructor)) void init2() { printf("4"); }
        ,
    });
    d_o.link_lib_c();

    const e_o = add_object(b, opts, .{
        .name = "e",
        .c_source_bytes =
        \\#include <stdio.h>
        \\__attribute__((destructor(10000))) void fini4() { printf("5"); }
        ,
    });
    e_o.link_lib_c();

    const f_o = add_object(b, opts, .{
        .name = "f",
        .c_source_bytes =
        \\#include <stdio.h>
        \\__attribute__((destructor(1000))) void fini3() { printf("6"); }
        ,
    });
    f_o.link_lib_c();

    const g_o = add_object(b, opts, .{
        .name = "g",
        .c_source_bytes =
        \\#include <stdio.h>
        \\__attribute__((destructor)) void fini1() { printf("7"); }
        ,
    });
    g_o.link_lib_c();

    const h_o = add_object(b, opts, .{ .name = "h", .c_source_bytes = 
    \\#include <stdio.h>
    \\__attribute__((destructor)) void fini2() { printf("8"); }
    });
    h_o.link_lib_c();

    const exe = add_executable(b, opts, .{ .name = "main" });
    add_csource_bytes(exe, "int main() { return 0; }", &.{});
    exe.add_object(a_o);
    exe.add_object(b_o);
    exe.add_object(c_o);
    exe.add_object(d_o);
    exe.add_object(e_o);
    exe.add_object(f_o);
    exe.add_object(g_o);
    exe.add_object(h_o);

    if (opts.target.result.is_gnu_lib_c()) {
        // TODO I think we need to clarify our use of `-fPIC -fPIE` flags for different targets
        exe.pie = true;
    }

    const run = add_run_artifact(exe);
    run.expect_std_out_equal("21348756");
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_large_alignment_dso(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "large-alignment-dso", opts);

    const dso = add_shared_library(b, opts, .{ .name = "dso" });
    add_csource_bytes(dso,
        \\#include <stdio.h>
        \\#include <stdint.h>
        \\void hello() __attribute__((aligned(32768), section(".hello")));
        \\void world() __attribute__((aligned(32768), section(".world")));
        \\void hello() {
        \\  printf("Hello");
        \\}
        \\void world() {
        \\  printf(" world");
        \\}
        \\void greet() {
        \\  hello();
        \\  world();
        \\}
    , &.{});
    dso.link_function_sections = true;
    dso.link_lib_c();

    const check = dso.check_object();
    check.check_in_symtab();
    check.check_extract("{addr1} {size1} {shndx1} FUNC GLOBAL DEFAULT hello");
    check.check_in_symtab();
    check.check_extract("{addr2} {size2} {shndx2} FUNC GLOBAL DEFAULT world");
    check.check_compute_compare("addr1 16 %", .{ .op = .eq, .value = .{ .literal = 0 } });
    check.check_compute_compare("addr2 16 %", .{ .op = .eq, .value = .{ .literal = 0 } });
    test_step.depend_on(&check.step);

    const exe = add_executable(b, opts, .{ .name = "test" });
    add_csource_bytes(exe,
        \\void greet();
        \\int main() { greet(); }
    , &.{});
    exe.link_library(dso);
    exe.link_lib_c();

    const run = add_run_artifact(exe);
    run.expect_std_out_equal("Hello world");
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_large_alignment_exe(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "large-alignment-exe", opts);

    const exe = add_executable(b, opts, .{ .name = "test" });
    add_csource_bytes(exe,
        \\#include <stdio.h>
        \\#include <stdint.h>
        \\
        \\void hello() __attribute__((aligned(32768), section(".hello")));
        \\void world() __attribute__((aligned(32768), section(".world")));
        \\
        \\void hello() {
        \\  printf("Hello");
        \\}
        \\
        \\void world() {
        \\  printf(" world");
        \\}
        \\
        \\int main() {
        \\  hello();
        \\  world();
        \\}
    , &.{});
    exe.link_function_sections = true;
    exe.link_lib_c();

    const check = exe.check_object();
    check.check_in_symtab();
    check.check_extract("{addr1} {size1} {shndx1} FUNC LOCAL DEFAULT hello");
    check.check_in_symtab();
    check.check_extract("{addr2} {size2} {shndx2} FUNC LOCAL DEFAULT world");
    check.check_compute_compare("addr1 16 %", .{ .op = .eq, .value = .{ .literal = 0 } });
    check.check_compute_compare("addr2 16 %", .{ .op = .eq, .value = .{ .literal = 0 } });
    test_step.depend_on(&check.step);

    const run = add_run_artifact(exe);
    run.expect_std_out_equal("Hello world");
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_large_bss(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "large-bss", opts);

    const exe = add_executable(b, opts, .{ .name = "main" });
    add_csource_bytes(exe,
        \\char arr[0x100000000];
        \\int main() {
        \\  return arr[2000];
        \\}
    , &.{});
    exe.link_lib_c();

    const run = add_run_artifact(exe);
    run.expect_exit_code(0);
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_link_order(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "link-order", opts);

    const obj = add_object(b, opts, .{
        .name = "obj",
        .c_source_bytes = "void foo() {}",
        .pic = true,
    });

    const dso = add_shared_library(b, opts, .{ .name = "a" });
    dso.add_object(obj);

    const lib = add_static_library(b, opts, .{ .name = "b" });
    lib.add_object(obj);

    const main_o = add_object(b, opts, .{
        .name = "main",
        .c_source_bytes =
        \\void foo();
        \\int main() {
        \\  foo();
        \\}
        ,
    });

    // https://github.com/ziglang/zig/issues/17450
    // {
    //     const exe = add_executable(b, opts, .{ .name = "main1"});
    //     exe.add_object(main_o);
    //     exe.link_system_library2("a", .{});
    //     exe.add_library_path(dso.get_emitted_bin_directory());
    //     exe.add_rpath(dso.get_emitted_bin_directory());
    //     exe.link_system_library2("b", .{});
    //     exe.add_library_path(lib.get_emitted_bin_directory());
    //     exe.add_rpath(lib.get_emitted_bin_directory());
    //     exe.link_lib_c();

    //     const check = exe.check_object();
    //     check.check_in_dynamic_section();
    //     check.check_contains("libb.so");
    //     test_step.depend_on(&check.step);
    // }

    {
        const exe = add_executable(b, opts, .{ .name = "main2" });
        exe.add_object(main_o);
        exe.link_system_library2("b", .{});
        exe.add_library_path(lib.get_emitted_bin_directory());
        exe.add_rpath(lib.get_emitted_bin_directory());
        exe.link_system_library2("a", .{});
        exe.add_library_path(dso.get_emitted_bin_directory());
        exe.add_rpath(dso.get_emitted_bin_directory());
        exe.link_lib_c();

        const check = exe.check_object();
        check.check_in_dynamic_section();
        check.check_not_present("libb.so");
        test_step.depend_on(&check.step);
    }

    return test_step;
}

fn test_ld_script(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "ld-script", opts);

    const dso = add_shared_library(b, opts, .{ .name = "bar" });
    add_csource_bytes(dso, "int foo() { return 42; }", &.{});

    const scripts = WriteFile.create(b);
    _ = scripts.add("liba.so", "INPUT(libfoo.so)");
    _ = scripts.add("libfoo.so", "GROUP(AS_NEEDED(-lbar))");

    const exe = add_executable(b, opts, .{ .name = "main" });
    add_csource_bytes(exe,
        \\int foo();
        \\int main() {
        \\  return foo() - 42;
        \\}
    , &.{});
    exe.link_system_library2("a", .{});
    exe.add_library_path(scripts.get_directory());
    exe.add_library_path(dso.get_emitted_bin_directory());
    exe.add_rpath(dso.get_emitted_bin_directory());
    exe.link_lib_c();

    const run = add_run_artifact(exe);
    run.expect_exit_code(0);
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_ld_script_path_error(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "ld-script-path-error", opts);

    const scripts = WriteFile.create(b);
    _ = scripts.add("liba.so", "INPUT(libfoo.so)");

    const exe = add_executable(b, opts, .{ .name = "main" });
    add_csource_bytes(exe, "int main() { return 0; }", &.{});
    exe.link_system_library2("a", .{});
    exe.add_library_path(scripts.get_directory());
    exe.link_lib_c();

    expect_link_errors(
        exe,
        test_step,
        .{
            .contains = "error: missing library dependency: GNU ld script '/?/liba.so' requires 'libfoo.so', but file not found",
        },
    );

    return test_step;
}

fn test_ld_script_allow_undefined_version(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "ld-script-allow-undefined-version", opts);

    const so = add_shared_library(b, opts, .{
        .name = "add",
        .zig_source_bytes =
        \\export fn add(a: i32, b: i32) i32 {
        \\    return a + b;
        \\}
        ,
    });
    const ld = b.add_write_files().add("add.ld", "VERSION { ADD_1.0 { global: add; sub; local: *; }; }");
    so.set_linker_script(ld);
    so.linker_allow_undefined_version = true;

    const exe = add_executable(b, opts, .{
        .name = "main",
        .zig_source_bytes =
        \\const std = @import("std");
        \\extern fn add(a: i32, b: i32) i32;
        \\pub fn main() void {
        \\    std.debug.print("{d}\n", .{add(1, 2)});
        \\}
        ,
    });
    exe.link_library(so);
    exe.link_lib_c();

    const run = add_run_artifact(exe);
    run.expect_std_err_equal("3\n");
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_ld_script_disallow_undefined_version(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "ld-script-disallow-undefined-version", opts);

    const so = add_shared_library(b, opts, .{
        .name = "add",
        .zig_source_bytes =
        \\export fn add(a: i32, b: i32) i32 {
        \\    return a + b;
        \\}
        ,
    });
    const ld = b.add_write_files().add("add.ld", "VERSION { ADD_1.0 { global: add; sub; local: *; }; }");
    so.set_linker_script(ld);
    so.linker_allow_undefined_version = false;

    expect_link_errors(
        so,
        test_step,
        .{
            .contains = "error: ld.lld: version script assignment of 'ADD_1.0' to symbol 'sub' failed: symbol not defined",
        },
    );

    return test_step;
}

fn test_mismatched_cpu_architecture_error(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "mismatched-cpu-architecture-error", opts);

    const obj = add_object(b, .{
        .target = b.resolve_target_query(.{ .cpu_arch = .aarch64, .os_tag = .linux, .abi = .gnu }),
    }, .{
        .name = "a",
        .c_source_bytes = "int foo;",
        .strip = true,
    });

    const exe = add_executable(b, opts, .{ .name = "main" });
    add_csource_bytes(exe,
        \\extern int foo;
        \\int main() {
        \\  return foo;
        \\}
    , &.{});
    exe.add_object(obj);
    exe.link_lib_c();

    expect_link_errors(exe, test_step, .{ .exact = &.{
        "invalid cpu architecture: aarch64",
        "note: while parsing /?/a.o",
    } });

    return test_step;
}

fn test_linking_c(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "linking-c", opts);

    const exe = add_executable(b, opts, .{ .name = "test" });
    add_csource_bytes(exe,
        \\#include <stdio.h>
        \\int main() {
        \\  printf("Hello World!\n");
        \\  return 0;
        \\}
    , &.{});
    exe.link_lib_c();

    const run = add_run_artifact(exe);
    run.expect_std_out_equal("Hello World!\n");
    test_step.depend_on(&run.step);

    const check = exe.check_object();
    check.check_in_headers();
    check.check_exact("header");
    check.check_exact("type EXEC");
    check.check_in_headers();
    check.check_exact("section headers");
    check.check_not_present("name .dynamic");
    test_step.depend_on(&check.step);

    return test_step;
}

fn test_linking_cpp(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "linking-cpp", opts);

    const exe = add_executable(b, opts, .{ .name = "test" });
    add_cpp_source_bytes(exe,
        \\#include <iostream>
        \\int main() {
        \\  std::cout << "Hello World!" << std::endl;
        \\  return 0;
        \\}
    , &.{});
    exe.link_lib_c();
    exe.link_lib_cpp();

    const run = add_run_artifact(exe);
    run.expect_std_out_equal("Hello World!\n");
    test_step.depend_on(&run.step);

    const check = exe.check_object();
    check.check_in_headers();
    check.check_exact("header");
    check.check_exact("type EXEC");
    check.check_in_headers();
    check.check_exact("section headers");
    check.check_not_present("name .dynamic");
    test_step.depend_on(&check.step);

    return test_step;
}

fn test_linking_obj(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "linking-obj", opts);

    const obj = add_object(b, opts, .{
        .name = "aobj",
        .zig_source_bytes =
        \\extern var mod: usize;
        \\export fn call_me() usize {
        \\    return me * mod;
        \\}
        \\var me: usize = 42;
        ,
    });

    const exe = add_executable(b, opts, .{
        .name = "testobj",
        .zig_source_bytes =
        \\const std = @import("std");
        \\extern fn call_me() usize;
        \\export var mod: usize = 2;
        \\pub fn main() void {
        \\    std.debug.print("{d}\n", .{call_me()});
        \\}
        ,
    });
    exe.add_object(obj);

    const run = add_run_artifact(exe);
    run.expect_std_err_equal("84\n");
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_linking_static_lib(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "linking-static-lib", opts);

    const obj = add_object(b, opts, .{
        .name = "bobj",
        .zig_source_bytes = "export var bar: i32 = -42;",
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

fn test_linking_zig(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "linking-zig-static", opts);

    const exe = add_executable(b, opts, .{
        .name = "test",
        .zig_source_bytes =
        \\pub fn main() void {
        \\    @import("std").debug.print("Hello World!\n", .{});
        \\}
        ,
    });

    const run = add_run_artifact(exe);
    run.expect_std_err_equal("Hello World!\n");
    test_step.depend_on(&run.step);

    const check = exe.check_object();
    check.check_in_headers();
    check.check_exact("header");
    check.check_exact("type EXEC");
    check.check_in_headers();
    check.check_exact("section headers");
    check.check_not_present("name .dynamic");
    test_step.depend_on(&check.step);

    return test_step;
}

// Adapted from https://github.com/rui314/mold/blob/main/test/elf/mergeable-strings.sh
fn test_merge_strings(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "merge-strings", opts);

    const obj1 = add_object(b, opts, .{ .name = "a.o" });
    add_csource_bytes(obj1,
        \\#include <uchar.h>
        \\#include <wchar.h>
        \\char *cstr1 = "foo";
        \\wchar_t *wide1 = L"foo";
        \\char16_t *utf16_1 = u"foo";
        \\char32_t *utf32_1 = U"foo";
    , &.{"-O2"});
    obj1.link_lib_c();

    const obj2 = add_object(b, opts, .{ .name = "b.o" });
    add_csource_bytes(obj2,
        \\#include <stdio.h>
        \\#include <assert.h>
        \\#include <uchar.h>
        \\#include <wchar.h>
        \\extern char *cstr1;
        \\extern wchar_t *wide1;
        \\extern char16_t *utf16_1;
        \\extern char32_t *utf32_1;
        \\char *cstr2 = "foo";
        \\wchar_t *wide2 = L"foo";
        \\char16_t *utf16_2 = u"foo";
        \\char32_t *utf32_2 = U"foo";
        \\int main() {
        \\ printf("%p %p %p %p %p %p %p %p\n",
        \\ cstr1, cstr2, wide1, wide2, utf16_1, utf16_2, utf32_1, utf32_2);
        \\  assert((void*)cstr1 ==   (void*)cstr2);
        \\  assert((void*)wide1 ==   (void*)wide2);
        \\  assert((void*)utf16_1 == (void*)utf16_2);
        \\  assert((void*)utf32_1 == (void*)utf32_2);
        \\  assert((void*)wide1 ==   (void*)utf32_1);
        \\  assert((void*)cstr1 !=   (void*)wide1);
        \\  assert((void*)cstr1 !=   (void*)utf32_1);
        \\  assert((void*)wide1 !=   (void*)utf16_1);
        \\}
    , &.{"-O2"});
    obj2.link_lib_c();

    const exe = add_executable(b, opts, .{ .name = "main" });
    exe.add_object(obj1);
    exe.add_object(obj2);
    exe.link_lib_c();

    const run = add_run_artifact(exe);
    run.expect_exit_code(0);
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_merge_strings2(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "merge-strings2", opts);

    const obj1 = add_object(b, opts, .{ .name = "a", .zig_source_bytes = 
    \\const std = @import("std");
    \\export fn foo() void {
    \\    var arr: [5:0]u16 = [_:0]u16{ 1, 2, 3, 4, 5 };
    \\    const slice = std.mem.slice_to(&arr, 3);
    \\    std.testing.expect_equal_slices(u16, arr[0..2], slice) catch unreachable;
    \\}
    });

    const obj2 = add_object(b, opts, .{ .name = "b", .zig_source_bytes = 
    \\const std = @import("std");
    \\extern fn foo() void;
    \\pub fn main() void {
    \\    foo();
    \\    var arr: [5:0]u16 = [_:0]u16{ 5, 4, 3, 2, 1 };
    \\    const slice = std.mem.slice_to(&arr, 3);
    \\    std.testing.expect_equal_slices(u16, arr[0..2], slice) catch unreachable;
    \\}
    });

    {
        const exe = add_executable(b, opts, .{ .name = "main1" });
        exe.add_object(obj1);
        exe.add_object(obj2);

        const run = add_run_artifact(exe);
        run.expect_exit_code(0);
        test_step.depend_on(&run.step);

        const check = exe.check_object();
        check.dump_section(".rodata.str");
        check.check_contains("\x01\x00\x02\x00\x03\x00\x04\x00\x05\x00\x00\x00");
        check.dump_section(".rodata.str");
        check.check_contains("\x05\x00\x04\x00\x03\x00\x02\x00\x01\x00\x00\x00");
        test_step.depend_on(&check.step);
    }

    {
        const obj3 = add_object(b, opts, .{ .name = "c" });
        obj3.add_object(obj1);
        obj3.add_object(obj2);

        const exe = add_executable(b, opts, .{ .name = "main2" });
        exe.add_object(obj3);

        const run = add_run_artifact(exe);
        run.expect_exit_code(0);
        test_step.depend_on(&run.step);

        const check = exe.check_object();
        check.dump_section(".rodata.str");
        check.check_contains("\x01\x00\x02\x00\x03\x00\x04\x00\x05\x00\x00\x00");
        check.dump_section(".rodata.str");
        check.check_contains("\x05\x00\x04\x00\x03\x00\x02\x00\x01\x00\x00\x00");
        test_step.depend_on(&check.step);
    }

    return test_step;
}

fn test_no_eh_frame_hdr(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "no-eh-frame-hdr", opts);

    const exe = add_executable(b, opts, .{ .name = "main" });
    add_csource_bytes(exe, "int main() { return 0; }", &.{});
    exe.link_eh_frame_hdr = false;
    exe.link_lib_c();

    const check = exe.check_object();
    check.check_in_headers();
    check.check_exact("section headers");
    check.check_not_present("name .eh_frame_hdr");
    test_step.depend_on(&check.step);

    return test_step;
}

fn test_pie(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "hello-pie", opts);

    const exe = add_executable(b, opts, .{ .name = "main" });
    add_csource_bytes(exe,
        \\#include <stdio.h>
        \\int main() {
        \\  printf("Hello!\n");
        \\  return 0;
        \\}
    , &.{});
    exe.link_lib_c();
    exe.root_module.pic = true;
    exe.pie = true;

    const run = add_run_artifact(exe);
    run.expect_std_out_equal("Hello!\n");
    test_step.depend_on(&run.step);

    const check = exe.check_object();
    check.check_in_headers();
    check.check_exact("header");
    check.check_exact("type DYN");
    check.check_in_headers();
    check.check_exact("section headers");
    check.check_exact("name .dynamic");
    test_step.depend_on(&check.step);

    return test_step;
}

fn test_plt_got(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "plt-got", opts);

    const dso = add_shared_library(b, opts, .{ .name = "a" });
    add_csource_bytes(dso,
        \\#include <stdio.h>
        \\void ignore(void *foo) {}
        \\void hello() {
        \\  printf("Hello world\n");
        \\}
    , &.{});
    dso.link_lib_c();

    const exe = add_executable(b, opts, .{ .name = "main" });
    add_csource_bytes(exe,
        \\void ignore(void *);
        \\int hello();
        \\void foo() { ignore(hello); }
        \\int main() { hello(); }
    , &.{});
    exe.link_library(dso);
    exe.root_module.pic = true;
    exe.link_lib_c();

    const run = add_run_artifact(exe);
    run.expect_std_out_equal("Hello world\n");
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_preinit_array(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "preinit-array", opts);

    {
        const obj = add_object(b, opts, .{
            .name = "obj",
            .c_source_bytes = "void _start() {}",
        });

        const exe = add_executable(b, opts, .{ .name = "main1" });
        exe.add_object(obj);

        const check = exe.check_object();
        check.check_in_dynamic_section();
        check.check_not_present("PREINIT_ARRAY");
    }

    {
        const exe = add_executable(b, opts, .{ .name = "main2" });
        add_csource_bytes(exe,
            \\void preinit_fn() {}
            \\int main() {}
            \\__attribute__((section(".preinit_array")))
            \\void *preinit[] = { preinit_fn };
        , &.{});
        exe.link_lib_c();

        const check = exe.check_object();
        check.check_in_dynamic_section();
        check.check_contains("PREINIT_ARRAY");
    }

    return test_step;
}

fn test_relocatable_archive(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "relocatable-archive", opts);

    const obj1 = add_object(b, opts, .{
        .name = "obj1",
        .c_source_bytes =
        \\void bar();
        \\void foo() {
        \\  bar();
        \\}
        ,
    });

    const obj2 = add_object(b, opts, .{
        .name = "obj2",
        .c_source_bytes =
        \\void bar() {}
        ,
    });

    const obj3 = add_object(b, opts, .{
        .name = "obj3",
        .c_source_bytes =
        \\void baz();
        ,
    });

    const obj4 = add_object(b, opts, .{
        .name = "obj4",
        .c_source_bytes =
        \\void foo();
        \\int main() {
        \\  foo();
        \\}
        ,
    });

    const lib = add_static_library(b, opts, .{ .name = "lib" });
    lib.add_object(obj1);
    lib.add_object(obj2);
    lib.add_object(obj3);

    const obj5 = add_object(b, opts, .{
        .name = "obj5",
    });
    obj5.add_object(obj4);
    obj5.link_library(lib);

    const check = obj5.check_object();
    check.check_in_symtab();
    check.check_contains("foo");
    check.check_in_symtab();
    check.check_contains("bar");
    check.check_in_symtab();
    check.check_not_present("baz");
    test_step.depend_on(&check.step);

    return test_step;
}

fn test_relocatable_eh_frame(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "relocatable-eh-frame", opts);

    {
        const obj = add_object(b, opts, .{
            .name = "obj1",
            .cpp_source_bytes =
            \\#include <stdexcept>
            \\int try_me() {
            \\  throw std::runtime_error("Oh no!");
            \\}
            ,
        });
        add_cpp_source_bytes(obj,
            \\extern int try_me();
            \\int try_again() {
            \\  return try_me();
            \\}
        , &.{});
        obj.link_lib_cpp();

        const exe = add_executable(b, opts, .{ .name = "test1" });
        add_cpp_source_bytes(exe,
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
        , &.{});
        exe.add_object(obj);
        exe.link_lib_cpp();

        const run = add_run_artifact(exe);
        run.expect_std_out_equal("exception=Oh no!");
        test_step.depend_on(&run.step);
    }

    {
        // Let's make the object file COMDAT group heavy!
        const obj = add_object(b, opts, .{
            .name = "obj2",
            .cpp_source_bytes =
            \\#include <stdexcept>
            \\int try_me() {
            \\  throw std::runtime_error("Oh no!");
            \\}
            ,
        });
        add_cpp_source_bytes(obj,
            \\extern int try_me();
            \\int try_again() {
            \\  return try_me();
            \\}
        , &.{});
        add_cpp_source_bytes(obj,
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
        , &.{});
        obj.link_lib_cpp();

        const exe = add_executable(b, opts, .{ .name = "test2" });
        exe.add_object(obj);
        exe.link_lib_cpp();

        const run = add_run_artifact(exe);
        run.expect_std_out_equal("exception=Oh no!");
        test_step.depend_on(&run.step);
    }

    return test_step;
}

// Adapted from https://github.com/rui314/mold/blob/main/test/elf/relocatable-mergeable-sections.sh
fn test_relocatable_merge_strings(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "relocatable-merge-strings", opts);

    const obj1 = add_object(b, opts, .{ .name = "a", .asm_source_bytes = 
    \\.section .rodata.str1.1,"aMS",@progbits,1
    \\val1:
    \\.ascii "Hello \0"
    \\.section .rodata.str1.1,"aMS",@progbits,1
    \\val5:
    \\.ascii "World \0"
    \\.section .rodata.str1.1,"aMS",@progbits,1
    \\val7:
    \\.ascii "Hello \0"
    });

    const obj2 = add_object(b, opts, .{ .name = "b" });
    obj2.add_object(obj1);

    const check = obj2.check_object();
    check.dump_section(".rodata.str1.1");
    check.check_exact("Hello \x00World \x00");
    test_step.depend_on(&check.step);

    return test_step;
}

fn test_relocatable_no_eh_frame(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "relocatable-no-eh-frame", opts);

    const obj1 = add_object(b, opts, .{
        .name = "obj1",
        .c_source_bytes = "int bar() { return 42; }",
        .c_source_flags = &.{
            "-fno-unwind-tables",
            "-fno-asynchronous-unwind-tables",
        },
    });

    const obj2 = add_object(b, opts, .{
        .name = "obj2",
    });
    obj2.add_object(obj1);

    const check1 = obj1.check_object();
    check1.check_in_headers();
    check1.check_exact("section headers");
    check1.check_not_present(".eh_frame");
    test_step.depend_on(&check1.step);

    const check2 = obj2.check_object();
    check2.check_in_headers();
    check2.check_exact("section headers");
    check2.check_not_present(".eh_frame");
    test_step.depend_on(&check2.step);

    return test_step;
}

fn test_shared_abs_symbol(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "shared-abs-symbol", opts);

    const dso = add_shared_library(b, opts, .{ .name = "a" });
    add_asm_source_bytes(dso,
        \\.globl foo
        \\foo = 3;
    );

    const obj = add_object(b, opts, .{
        .name = "obj",
        .c_source_bytes =
        \\#include <stdio.h>
        \\extern char foo;
        \\int main() { printf("foo=%p\n", &foo); }
        ,
        .pic = true,
    });
    obj.link_lib_c();

    {
        const exe = add_executable(b, opts, .{ .name = "main1" });
        exe.add_object(obj);
        exe.link_library(dso);
        exe.pie = true;

        const run = add_run_artifact(exe);
        run.expect_std_out_equal("foo=0x3\n");
        test_step.depend_on(&run.step);

        const check = exe.check_object();
        check.check_in_headers();
        check.check_exact("header");
        check.check_exact("type DYN");
        // TODO fix/improve in CheckObject
        // check.check_in_symtab();
        // check.check_not_present("foo");
        test_step.depend_on(&check.step);
    }

    // https://github.com/ziglang/zig/issues/17430
    // {
    //     const exe = add_executable(b, opts, .{ .name = "main2"});
    //     exe.add_object(obj);
    //     exe.link_library(dso);
    //     exe.pie = false;

    //     const run = add_run_artifact(exe);
    //     run.expect_std_out_equal("foo=0x3\n");
    //     test_step.depend_on(&run.step);

    //     const check = exe.check_object();
    //     check.check_in_headers();
    //     check.check_exact("header");
    //     check.check_exact("type EXEC");
    //     // TODO fix/improve in CheckObject
    //     // check.check_in_symtab();
    //     // check.check_not_present("foo");
    //     test_step.depend_on(&check.step);
    // }

    return test_step;
}

fn test_strip(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "strip", opts);

    const obj = add_object(b, opts, .{
        .name = "obj",
        .c_source_bytes =
        \\#include <stdio.h>
        \\int main() {
        \\  printf("Hello!\n");
        \\  return 0;
        \\}
        ,
    });
    obj.link_lib_c();

    {
        const exe = add_executable(b, opts, .{ .name = "main1" });
        exe.add_object(obj);
        exe.root_module.strip = false;
        exe.link_lib_c();

        const check = exe.check_object();
        check.check_in_headers();
        check.check_exact("section headers");
        check.check_exact("name .debug_info");
        test_step.depend_on(&check.step);
    }

    {
        const exe = add_executable(b, opts, .{ .name = "main2" });
        exe.add_object(obj);
        exe.root_module.strip = true;
        exe.link_lib_c();

        const check = exe.check_object();
        check.check_in_headers();
        check.check_exact("section headers");
        check.check_not_present("name .debug_info");
        test_step.depend_on(&check.step);
    }

    return test_step;
}

fn test_thunks(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "thunks", opts);

    const src =
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
    ;

    {
        const exe = add_executable(b, opts, .{ .name = "main", .c_source_bytes = src });
        exe.link_function_sections = true;
        exe.link_lib_c();

        const run = add_run_artifact(exe);
        run.expect_std_out_equal("bar=42, foo=0, foobar=42");
        run.expect_exit_code(0);
        test_step.depend_on(&run.step);
    }

    {
        const exe = add_executable(b, opts, .{ .name = "main2", .c_source_bytes = src });
        exe.link_lib_c();

        const run = add_run_artifact(exe);
        run.expect_std_out_equal("bar=42, foo=0, foobar=42");
        run.expect_exit_code(0);
        test_step.depend_on(&run.step);
    }

    return test_step;
}

fn test_tls_df_static_tls(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "tls-df-static-tls", opts);

    const obj = add_object(b, opts, .{
        .name = "obj",
        .c_source_bytes =
        \\static _Thread_local int foo = 5;
        \\void mutate() { ++foo; }
        \\int bar() { return foo; }
        ,
        .c_source_flags = &.{"-ftls-model=initial-exec"},
        .pic = true,
    });

    {
        const dso = add_shared_library(b, opts, .{ .name = "a" });
        dso.add_object(obj);
        // dso.link_relax = true;

        const check = dso.check_object();
        check.check_in_dynamic_section();
        check.check_contains("STATIC_TLS");
        test_step.depend_on(&check.step);
    }

    // TODO add -Wl,--no-relax
    // {
    //     const dso = add_shared_library(b, opts, .{ .name = "a"});
    //     dso.add_object(obj);
    //     dso.link_relax = false;

    //     const check = dso.check_object();
    //     check.check_in_dynamic_section();
    //     check.check_contains("STATIC_TLS");
    //     test_step.depend_on(&check.step);
    // }

    return test_step;
}

fn test_tls_dso(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "tls-dso", opts);

    const dso = add_shared_library(b, opts, .{ .name = "a" });
    add_csource_bytes(dso,
        \\extern _Thread_local int foo;
        \\_Thread_local int bar;
        \\int get_foo1() { return foo; }
        \\int get_bar1() { return bar; }
    , &.{});

    const exe = add_executable(b, opts, .{ .name = "main" });
    add_csource_bytes(exe,
        \\#include <stdio.h>
        \\_Thread_local int foo;
        \\extern _Thread_local int bar;
        \\int get_foo1();
        \\int get_bar1();
        \\int get_foo2() { return foo; }
        \\int get_bar2() { return bar; }
        \\int main() {
        \\  foo = 5;
        \\  bar = 3;
        \\  printf("%d %d %d %d %d %d\n",
        \\         foo, bar,
        \\         get_foo1(), get_bar1(),
        \\         get_foo2(), get_bar2());
        \\  return 0;
        \\}
    , &.{});
    exe.link_library(dso);
    exe.link_lib_c();

    const run = add_run_artifact(exe);
    run.expect_std_out_equal("5 3 5 3 5 3\n");
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_tls_gd(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "tls-gd", opts);

    const main_o = add_object(b, opts, .{
        .name = "main",
        .c_source_bytes =
        \\#include <stdio.h>
        \\__attribute__((tls_model("global-dynamic"))) static _Thread_local int x1 = 1;
        \\__attribute__((tls_model("global-dynamic"))) static _Thread_local int x2;
        \\__attribute__((tls_model("global-dynamic"))) extern _Thread_local int x3;
        \\__attribute__((tls_model("global-dynamic"))) extern _Thread_local int x4;
        \\int get_x5();
        \\int get_x6();
        \\int main() {
        \\  x2 = 2;
        \\  printf("%d %d %d %d %d %d\n", x1, x2, x3, x4, get_x5(), get_x6());
        \\  return 0;
        \\}
        ,
        .pic = true,
    });
    main_o.link_lib_c();

    const a_o = add_object(b, opts, .{
        .name = "a",
        .c_source_bytes =
        \\__attribute__((tls_model("global-dynamic"))) _Thread_local int x3 = 3;
        \\__attribute__((tls_model("global-dynamic"))) static _Thread_local int x5 = 5;
        \\int get_x5() { return x5; }
        ,
        .pic = true,
    });

    const b_o = add_object(b, opts, .{
        .name = "b",
        .c_source_bytes =
        \\__attribute__((tls_model("global-dynamic"))) _Thread_local int x4 = 4;
        \\__attribute__((tls_model("global-dynamic"))) static _Thread_local int x6 = 6;
        \\int get_x6() { return x6; }
        ,
        .pic = true,
    });

    const exp_stdout = "1 2 3 4 5 6\n";

    const dso1 = add_shared_library(b, opts, .{ .name = "a" });
    dso1.add_object(a_o);

    const dso2 = add_shared_library(b, opts, .{ .name = "b" });
    dso2.add_object(b_o);
    // dso2.link_relax = false; // TODO

    {
        const exe = add_executable(b, opts, .{ .name = "main1" });
        exe.add_object(main_o);
        exe.link_library(dso1);
        exe.link_library(dso2);

        const run = add_run_artifact(exe);
        run.expect_std_out_equal(exp_stdout);
        test_step.depend_on(&run.step);
    }

    {
        const exe = add_executable(b, opts, .{ .name = "main2" });
        exe.add_object(main_o);
        // exe.link_relax = false; // TODO
        exe.link_library(dso1);
        exe.link_library(dso2);

        const run = add_run_artifact(exe);
        run.expect_std_out_equal(exp_stdout);
        test_step.depend_on(&run.step);
    }

    // https://github.com/ziglang/zig/issues/17430 ??
    // {
    //     const exe = add_executable(b, opts, .{ .name = "main3"});
    //     exe.add_object(main_o);
    //     exe.link_library(dso1);
    //     exe.link_library(dso2);
    //     exe.linkage = .static;

    //     const run = add_run_artifact(exe);
    //     run.expect_std_out_equal(exp_stdout);
    //     test_step.depend_on(&run.step);
    // }

    // {
    //     const exe = add_executable(b, opts, .{ .name = "main4"});
    //     exe.add_object(main_o);
    //     // exe.link_relax = false; // TODO
    //     exe.link_library(dso1);
    //     exe.link_library(dso2);
    //     exe.linkage = .static;

    //     const run = add_run_artifact(exe);
    //     run.expect_std_out_equal(exp_stdout);
    //     test_step.depend_on(&run.step);
    // }

    return test_step;
}

fn test_tls_gd_no_plt(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "tls-gd-no-plt", opts);

    const obj = add_object(b, opts, .{
        .name = "obj",
        .c_source_bytes =
        \\#include <stdio.h>
        \\__attribute__((tls_model("global-dynamic"))) static _Thread_local int x1 = 1;
        \\__attribute__((tls_model("global-dynamic"))) static _Thread_local int x2;
        \\__attribute__((tls_model("global-dynamic"))) extern _Thread_local int x3;
        \\__attribute__((tls_model("global-dynamic"))) extern _Thread_local int x4;
        \\int get_x5();
        \\int get_x6();
        \\int main() {
        \\  x2 = 2;
        \\
        \\  printf("%d %d %d %d %d %d\n", x1, x2, x3, x4, get_x5(), get_x6());
        \\  return 0;
        \\}
        ,
        .c_source_flags = &.{"-fno-plt"},
        .pic = true,
    });
    obj.link_lib_c();

    const a_so = add_shared_library(b, opts, .{ .name = "a" });
    add_csource_bytes(a_so,
        \\__attribute__((tls_model("global-dynamic"))) _Thread_local int x3 = 3;
        \\__attribute__((tls_model("global-dynamic"))) static _Thread_local int x5 = 5;
        \\int get_x5() { return x5; }
    , &.{"-fno-plt"});

    const b_so = add_shared_library(b, opts, .{ .name = "b" });
    add_csource_bytes(b_so,
        \\__attribute__((tls_model("global-dynamic"))) _Thread_local int x4 = 4;
        \\__attribute__((tls_model("global-dynamic"))) static _Thread_local int x6 = 6;
        \\int get_x6() { return x6; }
    , &.{"-fno-plt"});
    // b_so.link_relax = false; // TODO

    {
        const exe = add_executable(b, opts, .{ .name = "main1" });
        exe.add_object(obj);
        exe.link_library(a_so);
        exe.link_library(b_so);
        exe.link_lib_c();

        const run = add_run_artifact(exe);
        run.expect_std_out_equal("1 2 3 4 5 6\n");
        test_step.depend_on(&run.step);
    }

    {
        const exe = add_executable(b, opts, .{ .name = "main2" });
        exe.add_object(obj);
        exe.link_library(a_so);
        exe.link_library(b_so);
        exe.link_lib_c();
        // exe.link_relax = false; // TODO

        const run = add_run_artifact(exe);
        run.expect_std_out_equal("1 2 3 4 5 6\n");
        test_step.depend_on(&run.step);
    }

    return test_step;
}

fn test_tls_gd_to_ie(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "tls-gd-to-ie", opts);

    const a_o = add_object(b, opts, .{
        .name = "a",
        .c_source_bytes =
        \\#include <stdio.h>
        \\__attribute__((tls_model("global-dynamic"))) static _Thread_local int x1 = 1;
        \\__attribute__((tls_model("global-dynamic"))) _Thread_local int x2 = 2;
        \\__attribute__((tls_model("global-dynamic"))) _Thread_local int x3;
        \\int foo() {
        \\  x3 = 3;
        \\
        \\  printf("%d %d %d\n", x1, x2, x3);
        \\  return 0;
        \\}
        ,
        .pic = true,
    });
    a_o.link_lib_c();

    const b_o = add_object(b, opts, .{
        .name = "b",
        .c_source_bytes =
        \\int foo();
        \\int main() { foo(); }
        ,
        .pic = true,
    });

    {
        const dso = add_shared_library(b, opts, .{ .name = "a1" });
        dso.add_object(a_o);

        const exe = add_executable(b, opts, .{ .name = "main1" });
        exe.add_object(b_o);
        exe.link_library(dso);
        exe.link_lib_c();

        const run = add_run_artifact(exe);
        run.expect_std_out_equal("1 2 3\n");
        test_step.depend_on(&run.step);
    }

    {
        const dso = add_shared_library(b, opts, .{ .name = "a2" });
        dso.add_object(a_o);
        // dso.link_relax = false; // TODO

        const exe = add_executable(b, opts, .{ .name = "main2" });
        exe.add_object(b_o);
        exe.link_library(dso);
        exe.link_lib_c();

        const run = add_run_artifact(exe);
        run.expect_std_out_equal("1 2 3\n");
        test_step.depend_on(&run.step);
    }

    // {
    //     const dso = add_shared_library(b, opts, .{ .name = "a"});
    //     dso.add_object(a_o);
    //     dso.link_z_nodlopen = true;

    //     const exe = add_executable(b, opts, .{ .name = "main"});
    //     exe.add_object(b_o);
    //     exe.link_library(dso);

    //     const run = add_run_artifact(exe);
    //     run.expect_std_out_equal("1 2 3\n");
    //     test_step.depend_on(&run.step);
    // }

    // {
    //     const dso = add_shared_library(b, opts, .{ .name = "a"});
    //     dso.add_object(a_o);
    //     dso.link_relax = false;
    //     dso.link_z_nodlopen = true;

    //     const exe = add_executable(b, opts, .{ .name = "main"});
    //     exe.add_object(b_o);
    //     exe.link_library(dso);

    //     const run = add_run_artifact(exe);
    //     run.expect_std_out_equal("1 2 3\n");
    //     test_step.depend_on(&run.step);
    // }

    return test_step;
}

fn test_tls_ie(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "tls-ie", opts);

    const dso = add_shared_library(b, opts, .{ .name = "a" });
    add_csource_bytes(dso,
        \\#include <stdio.h>
        \\__attribute__((tls_model("initial-exec"))) static _Thread_local int foo;
        \\__attribute__((tls_model("initial-exec"))) static _Thread_local int bar;
        \\void set() {
        \\  foo = 3;
        \\  bar = 5;
        \\}
        \\void print() {
        \\  printf("%d %d ", foo, bar);
        \\}
    , &.{});
    dso.link_lib_c();

    const main_o = add_object(b, opts, .{
        .name = "main",
        .c_source_bytes =
        \\#include <stdio.h>
        \\_Thread_local int baz;
        \\void set();
        \\void print();
        \\int main() {
        \\  baz = 7;
        \\  print();
        \\  set();
        \\  print();
        \\  printf("%d\n", baz);
        \\}
        ,
    });
    main_o.link_lib_c();

    const exp_stdout = "0 0 3 5 7\n";

    {
        const exe = add_executable(b, opts, .{ .name = "main1" });
        exe.add_object(main_o);
        exe.link_library(dso);
        exe.link_lib_c();

        const run = add_run_artifact(exe);
        run.expect_std_out_equal(exp_stdout);
        test_step.depend_on(&run.step);
    }

    {
        const exe = add_executable(b, opts, .{ .name = "main2" });
        exe.add_object(main_o);
        exe.link_library(dso);
        exe.link_lib_c();
        // exe.link_relax = false; // TODO

        const run = add_run_artifact(exe);
        run.expect_std_out_equal(exp_stdout);
        test_step.depend_on(&run.step);
    }

    return test_step;
}

fn test_tls_large_alignment(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "tls-large-alignment", opts);

    const a_o = add_object(b, opts, .{
        .name = "a",
        .c_source_bytes =
        \\__attribute__((section(".tdata1")))
        \\_Thread_local int x = 42;
        ,
        .c_source_flags = &.{"-std=c11"},
        .pic = true,
    });

    const b_o = add_object(b, opts, .{
        .name = "b",
        .c_source_bytes =
        \\__attribute__((section(".tdata2")))
        \\_Alignas(256) _Thread_local int y[] = { 1, 2, 3 };
        ,
        .c_source_flags = &.{"-std=c11"},
        .pic = true,
    });

    const c_o = add_object(b, opts, .{
        .name = "c",
        .c_source_bytes =
        \\#include <stdio.h>
        \\extern _Thread_local int x;
        \\extern _Thread_local int y[];
        \\int main() {
        \\  printf("%d %d %d %d\n", x, y[0], y[1], y[2]);
        \\}
        ,
        .pic = true,
    });
    c_o.link_lib_c();

    {
        const dso = add_shared_library(b, opts, .{ .name = "a" });
        dso.add_object(a_o);
        dso.add_object(b_o);

        const exe = add_executable(b, opts, .{ .name = "main" });
        exe.add_object(c_o);
        exe.link_library(dso);
        exe.link_lib_c();

        const run = add_run_artifact(exe);
        run.expect_std_out_equal("42 1 2 3\n");
        test_step.depend_on(&run.step);
    }

    {
        const exe = add_executable(b, opts, .{ .name = "main" });
        exe.add_object(a_o);
        exe.add_object(b_o);
        exe.add_object(c_o);
        exe.link_lib_c();

        const run = add_run_artifact(exe);
        run.expect_std_out_equal("42 1 2 3\n");
        test_step.depend_on(&run.step);
    }

    return test_step;
}

fn test_tls_large_tbss(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "tls-large-tbss", opts);

    const exe = add_executable(b, opts, .{ .name = "main" });
    add_asm_source_bytes(exe,
        \\.globl x, y
        \\.section .tbss,"awT",@nobits
        \\x:
        \\.zero 1024
        \\.section .tcommon,"awT",@nobits
        \\y:
        \\.zero 1024
    );
    add_csource_bytes(exe,
        \\#include <stdio.h>
        \\extern _Thread_local char x[1024000];
        \\extern _Thread_local char y[1024000];
        \\int main() {
        \\  x[0] = 3;
        \\  x[1023] = 5;
        \\  printf("%d %d %d %d %d %d\n", x[0], x[1], x[1023], y[0], y[1], y[1023]);
        \\}
    , &.{});
    exe.link_lib_c();

    const run = add_run_artifact(exe);
    run.expect_std_out_equal("3 0 5 0 0 0\n");
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_tls_large_static_image(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "tls-large-static-image", opts);

    const exe = add_executable(b, opts, .{ .name = "main" });
    add_csource_bytes(exe, "_Thread_local int x[] = { 1, 2, 3, [10000] = 5 };", &.{});
    add_csource_bytes(exe,
        \\#include <stdio.h>
        \\extern _Thread_local int x[];
        \\int main() {
        \\  printf("%d %d %d %d %d\n", x[0], x[1], x[2], x[3], x[10000]);
        \\}
    , &.{});
    exe.root_module.pic = true;
    exe.link_lib_c();

    const run = add_run_artifact(exe);
    run.expect_std_out_equal("1 2 3 0 5\n");
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_tls_ld(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "tls-ld", opts);

    const main_o = add_object(b, opts, .{
        .name = "main",
        .c_source_bytes =
        \\#include <stdio.h>
        \\extern _Thread_local int foo;
        \\static _Thread_local int bar;
        \\int *get_foo_addr() { return &foo; }
        \\int *get_bar_addr() { return &bar; }
        \\int main() {
        \\  bar = 5;
        \\  printf("%d %d %d %d\n", *get_foo_addr(), *get_bar_addr(), foo, bar);
        \\  return 0;
        \\}
        ,
        .c_source_flags = &.{"-ftls-model=local-dynamic"},
        .pic = true,
    });
    main_o.link_lib_c();

    const a_o = add_object(b, opts, .{
        .name = "a",
        .c_source_bytes = "_Thread_local int foo = 3;",
        .c_source_flags = &.{"-ftls-model=local-dynamic"},
        .pic = true,
    });

    const exp_stdout = "3 5 3 5\n";

    {
        const exe = add_executable(b, opts, .{ .name = "main1" });
        exe.add_object(main_o);
        exe.add_object(a_o);
        exe.link_lib_c();

        const run = add_run_artifact(exe);
        run.expect_std_out_equal(exp_stdout);
        test_step.depend_on(&run.step);
    }

    {
        const exe = add_executable(b, opts, .{ .name = "main2" });
        exe.add_object(main_o);
        exe.add_object(a_o);
        exe.link_lib_c();
        // exe.link_relax = false; // TODO

        const run = add_run_artifact(exe);
        run.expect_std_out_equal(exp_stdout);
        test_step.depend_on(&run.step);
    }

    return test_step;
}

fn test_tls_ld_dso(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "tls-ld-dso", opts);

    const dso = add_shared_library(b, opts, .{ .name = "a" });
    add_csource_bytes(dso,
        \\static _Thread_local int def, def1;
        \\int f0() { return ++def; }
        \\int f1() { return ++def1 + def; }
    , &.{"-ftls-model=local-dynamic"});

    const exe = add_executable(b, opts, .{ .name = "main" });
    add_csource_bytes(exe,
        \\#include <stdio.h>
        \\extern int f0();
        \\extern int f1();
        \\int main() {
        \\  int x = f0();
        \\  int y = f1();
        \\  printf("%d %d\n", x, y);
        \\  return 0;
        \\}
    , &.{});
    exe.link_library(dso);
    exe.link_lib_c();

    const run = add_run_artifact(exe);
    run.expect_std_out_equal("1 2\n");
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_tls_ld_no_plt(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "tls-ld-no-plt", opts);

    const a_o = add_object(b, opts, .{
        .name = "a",
        .c_source_bytes =
        \\#include <stdio.h>
        \\extern _Thread_local int foo;
        \\static _Thread_local int bar;
        \\int *get_foo_addr() { return &foo; }
        \\int *get_bar_addr() { return &bar; }
        \\int main() {
        \\  bar = 5;
        \\
        \\  printf("%d %d %d %d\n", *get_foo_addr(), *get_bar_addr(), foo, bar);
        \\  return 0;
        \\}
        ,
        .c_source_flags = &.{ "-ftls-model=local-dynamic", "-fno-plt" },
        .pic = true,
    });
    a_o.link_lib_c();

    const b_o = add_object(b, opts, .{
        .name = "b",
        .c_source_bytes = "_Thread_local int foo = 3;",
        .c_source_flags = &.{ "-ftls-model=local-dynamic", "-fno-plt" },
        .pic = true,
    });

    {
        const exe = add_executable(b, opts, .{ .name = "main1" });
        exe.add_object(a_o);
        exe.add_object(b_o);
        exe.link_lib_c();

        const run = add_run_artifact(exe);
        run.expect_std_out_equal("3 5 3 5\n");
        test_step.depend_on(&run.step);
    }

    {
        const exe = add_executable(b, opts, .{ .name = "main2" });
        exe.add_object(a_o);
        exe.add_object(b_o);
        exe.link_lib_c();
        // exe.link_relax = false; // TODO

        const run = add_run_artifact(exe);
        run.expect_std_out_equal("3 5 3 5\n");
        test_step.depend_on(&run.step);
    }

    return test_step;
}

fn test_tls_no_pic(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "tls-no-pic", opts);

    const exe = add_executable(b, opts, .{ .name = "main" });
    add_csource_bytes(exe,
        \\#include <stdio.h>
        \\__attribute__((tls_model("global-dynamic"))) extern _Thread_local int foo;
        \\__attribute__((tls_model("global-dynamic"))) static _Thread_local int bar;
        \\int *get_foo_addr() { return &foo; }
        \\int *get_bar_addr() { return &bar; }
        \\int main() {
        \\  foo = 3;
        \\  bar = 5;
        \\
        \\  printf("%d %d %d %d\n", *get_foo_addr(), *get_bar_addr(), foo, bar);
        \\  return 0;
        \\}
    , .{});
    add_csource_bytes(exe,
        \\__attribute__((tls_model("global-dynamic"))) _Thread_local int foo;
    , &.{});
    exe.root_module.pic = false;
    exe.link_lib_c();

    const run = add_run_artifact(exe);
    run.expect_std_out_equal("3 5 3 5\n");
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_tls_offset_alignment(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "tls-offset-alignment", opts);

    const dso = add_shared_library(b, opts, .{ .name = "a" });
    add_csource_bytes(dso,
        \\#include <assert.h>
        \\#include <stdlib.h>
        \\
        \\// .tdata
        \\_Thread_local int x = 42;
        \\// .tbss
        \\__attribute__ ((aligned(64)))
        \\_Thread_local int y = 0;
        \\
        \\void *verify(void *unused) {
        \\  assert((unsigned long)(&y) % 64 == 0);
        \\  return NULL;
        \\}
    , &.{});
    dso.link_lib_c();

    const exe = add_executable(b, opts, .{ .name = "main" });
    add_csource_bytes(exe,
        \\#include <pthread.h>
        \\#include <dlfcn.h>
        \\#include <assert.h>
        \\void *(*verify)(void *);
        \\
        \\int main() {
        \\  void *handle = dlopen("liba.so", RTLD_NOW);
        \\  assert(handle);
        \\  *(void**)(&verify) = dlsym(handle, "verify");
        \\  assert(verify);
        \\
        \\  pthread_t thread;
        \\
        \\  verify(NULL);
        \\
        \\  pthread_create(&thread, NULL, verify, NULL);
        \\  pthread_join(thread, NULL);
        \\}
    , &.{});
    exe.add_rpath(dso.get_emitted_bin_directory());
    exe.link_lib_c();
    exe.root_module.pic = true;

    const run = add_run_artifact(exe);
    run.expect_exit_code(0);
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_tls_pic(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "tls-pic", opts);

    const obj = add_object(b, opts, .{
        .name = "obj",
        .c_source_bytes =
        \\#include <stdio.h>
        \\__attribute__((tls_model("global-dynamic"))) extern _Thread_local int foo;
        \\__attribute__((tls_model("global-dynamic"))) static _Thread_local int bar;
        \\int *get_foo_addr() { return &foo; }
        \\int *get_bar_addr() { return &bar; }
        \\int main() {
        \\  bar = 5;
        \\
        \\  printf("%d %d %d %d\n", *get_foo_addr(), *get_bar_addr(), foo, bar);
        \\  return 0;
        \\}
        ,
        .pic = true,
    });
    obj.link_lib_c();

    const exe = add_executable(b, opts, .{ .name = "main" });
    add_csource_bytes(exe,
        \\__attribute__((tls_model("global-dynamic"))) _Thread_local int foo = 3;
    , &.{});
    exe.add_object(obj);
    exe.link_lib_c();

    const run = add_run_artifact(exe);
    run.expect_std_out_equal("3 5 3 5\n");
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_tls_small_alignment(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "tls-small-alignment", opts);

    const a_o = add_object(b, opts, .{
        .name = "a",
        .asm_source_bytes =
        \\.text
        \\.byte 0
        \\
        ,
        .pic = true,
    });

    const b_o = add_object(b, opts, .{
        .name = "b",
        .c_source_bytes = "_Thread_local char x = 42;",
        .c_source_flags = &.{"-std=c11"},
        .pic = true,
    });

    const c_o = add_object(b, opts, .{
        .name = "c",
        .c_source_bytes =
        \\#include <stdio.h>
        \\extern _Thread_local char x;
        \\int main() {
        \\  printf("%d\n", x);
        \\}
        ,
        .pic = true,
    });
    c_o.link_lib_c();

    {
        const exe = add_executable(b, opts, .{ .name = "main" });
        exe.add_object(a_o);
        exe.add_object(b_o);
        exe.add_object(c_o);
        exe.link_lib_c();

        const run = add_run_artifact(exe);
        run.expect_std_out_equal("42\n");
        test_step.depend_on(&run.step);
    }

    {
        const dso = add_shared_library(b, opts, .{ .name = "a" });
        dso.add_object(a_o);
        dso.add_object(b_o);

        const exe = add_executable(b, opts, .{ .name = "main" });
        exe.add_object(c_o);
        exe.link_library(dso);
        exe.link_lib_c();

        const run = add_run_artifact(exe);
        run.expect_std_out_equal("42\n");
        test_step.depend_on(&run.step);
    }

    return test_step;
}

fn test_tls_static(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "tls-static", opts);

    const exe = add_executable(b, opts, .{ .name = "test" });
    add_csource_bytes(exe,
        \\#include <stdio.h>
        \\_Thread_local int a = 10;
        \\_Thread_local int b;
        \\_Thread_local char c = 'a';
        \\int main(int argc, char* argv[]) {
        \\  printf("%d %d %c\n", a, b, c);
        \\  a += 1;
        \\  b += 1;
        \\  c += 1;
        \\  printf("%d %d %c\n", a, b, c);
        \\  return 0;
        \\}
    , &.{});
    exe.link_lib_c();

    const run = add_run_artifact(exe);
    run.expect_std_out_equal(
        \\10 0 a
        \\11 1 b
        \\
    );
    test_step.depend_on(&run.step);

    return test_step;
}

fn test_unknown_file_type_error(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "unknown-file-type-error", opts);

    const dylib = add_shared_library(b, .{
        .target = b.resolve_target_query(.{ .cpu_arch = .x86_64, .os_tag = .macos }),
    }, .{
        .name = "a",
        .zig_source_bytes = "export var foo: i32 = 0;",
    });

    const exe = add_executable(b, opts, .{ .name = "main" });
    add_csource_bytes(exe,
        \\extern int foo;
        \\int main() {
        \\  return foo;
        \\}
    , &.{});
    exe.link_library(dylib);
    exe.link_lib_c();

    // TODO: improve the test harness to be able to selectively match lines in error output
    // while avoiding jankiness
    // expect_link_errors(exe, test_step, .{ .exact = &.{
    //     "error: invalid token in LD script: '\\x00\\x00\\x00\\x0c\\x00\\x00\\x00/usr/lib/dyld\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x0d' (0:989)",
    //     "note: while parsing /?/liba.dylib",
    //     "error: unexpected error: parsing input file failed with error InvalidLdScript",
    //     "note: while parsing /?/liba.dylib",
    // } });
    expect_link_errors(exe, test_step, .{
        .contains = "error: unexpected error: parsing input file failed with error InvalidLdScript",
    });

    return test_step;
}

fn test_unresolved_error(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "unresolved-error", opts);

    const obj1 = add_object(b, opts, .{
        .name = "a",
        .c_source_bytes =
        \\#include <stdio.h>
        \\int foo();
        \\int bar() {
        \\  return foo() + 1;
        \\}
        ,
        .c_source_flags = &.{"-ffunction-sections"},
    });
    obj1.link_lib_c();

    const obj2 = add_object(b, opts, .{
        .name = "b",
        .c_source_bytes =
        \\#include <stdio.h>
        \\int foo();
        \\int bar();
        \\int main() {
        \\  return foo() + bar();
        \\}
        ,
        .c_source_flags = &.{"-ffunction-sections"},
    });
    obj2.link_lib_c();

    const exe = add_executable(b, opts, .{ .name = "main" });
    exe.add_object(obj1);
    exe.add_object(obj2);
    exe.link_lib_c();

    expect_link_errors(exe, test_step, .{ .exact = &.{
        "error: undefined symbol: foo",
        "note: referenced by /?/a.o:.text.bar",
        "note: referenced by /?/b.o:.text.main",
    } });

    return test_step;
}

fn test_weak_exports(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "weak-exports", opts);

    const obj = add_object(b, opts, .{
        .name = "obj",
        .c_source_bytes =
        \\#include <stdio.h>
        \\__attribute__((weak)) int foo();
        \\int main() {
        \\  printf("%d\n", foo ? foo() : 3);
        \\}
        ,
        .pic = true,
    });
    obj.link_lib_c();

    {
        const dso = add_shared_library(b, opts, .{ .name = "a" });
        dso.add_object(obj);
        dso.link_lib_c();

        const check = dso.check_object();
        check.check_in_dynamic_symtab();
        check.check_contains("UND NOTYPE WEAK DEFAULT foo");
        test_step.depend_on(&check.step);
    }

    {
        const exe = add_executable(b, opts, .{ .name = "main" });
        exe.add_object(obj);
        exe.link_lib_c();

        const check = exe.check_object();
        check.check_in_dynamic_symtab();
        check.check_not_present("UND NOTYPE WEAK DEFAULT foo");
        test_step.depend_on(&check.step);

        const run = add_run_artifact(exe);
        run.expect_std_out_equal("3\n");
        test_step.depend_on(&run.step);
    }

    return test_step;
}

fn test_weak_undefs_dso(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "weak-undef-dso", opts);

    const dso = add_shared_library(b, opts, .{ .name = "a" });
    add_csource_bytes(dso,
        \\__attribute__((weak)) int foo();
        \\int bar() { return foo ? foo() : -1; }
    , &.{});

    {
        const exe = add_executable(b, opts, .{ .name = "main" });
        add_csource_bytes(exe,
            \\#include <stdio.h>
            \\int bar();
            \\int main() { printf("bar=%d\n", bar()); }
        , &.{});
        exe.link_library(dso);
        exe.link_lib_c();

        const run = add_run_artifact(exe);
        run.expect_std_out_equal("bar=-1\n");
        test_step.depend_on(&run.step);
    }

    {
        const exe = add_executable(b, opts, .{ .name = "main" });
        add_csource_bytes(exe,
            \\#include <stdio.h>
            \\int foo() { return 5; }
            \\int bar();
            \\int main() { printf("bar=%d\n", bar()); }
        , &.{});
        exe.link_library(dso);
        exe.link_lib_c();

        const run = add_run_artifact(exe);
        run.expect_std_out_equal("bar=5\n");
        test_step.depend_on(&run.step);
    }

    return test_step;
}

fn test_znow(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "z-now", opts);

    const obj = add_object(b, opts, .{
        .name = "obj",
        .c_source_bytes = "int main() { return 0; }",
        .pic = true,
    });

    {
        const dso = add_shared_library(b, opts, .{ .name = "a" });
        dso.add_object(obj);

        const check = dso.check_object();
        check.check_in_dynamic_section();
        check.check_contains("NOW");
        test_step.depend_on(&check.step);
    }

    {
        const dso = add_shared_library(b, opts, .{ .name = "a" });
        dso.add_object(obj);
        dso.link_z_lazy = true;

        const check = dso.check_object();
        check.check_in_dynamic_section();
        check.check_not_present("NOW");
        test_step.depend_on(&check.step);
    }

    return test_step;
}

fn test_zstack_size(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "z-stack-size", opts);

    const exe = add_executable(b, opts, .{ .name = "main" });
    add_csource_bytes(exe, "int main() { return 0; }", &.{});
    exe.stack_size = 0x800000;
    exe.link_lib_c();

    const check = exe.check_object();
    check.check_in_headers();
    check.check_exact("program headers");
    check.check_exact("type GNU_STACK");
    check.check_exact("memsz 800000");
    test_step.depend_on(&check.step);

    return test_step;
}

fn test_ztext(b: *Build, opts: Options) *Step {
    const test_step = add_test_step(b, "z-text", opts);

    // Previously, following mold, this test tested text relocs present in a PIE executable.
    // However, as we want to cover musl AND glibc, it is now modified to test presence of
    // text relocs in a DSO which is then linked with an executable.
    // According to Rich and this thread https://www.openwall.com/lists/musl/2020/09/25/4
    // musl supports only a very limited number of text relocations and only in DSOs (and
    // rightly so!).

    const a_o = add_object(b, opts, .{
        .name = "a",
        .asm_source_bytes =
        \\.globl fn1
        \\fn1:
        \\  sub $8, %rsp
        \\  movabs ptr, %rax
        \\  call *%rax
        \\  add $8, %rsp
        \\  ret
        \\
        ,
    });

    const b_o = add_object(b, opts, .{
        .name = "b",
        .c_source_bytes =
        \\int fn1();
        \\int fn2() {
        \\  return 3;
        \\}
        \\void *ptr = fn2;
        \\int fnn() {
        \\  return fn1();
        \\}
        ,
        .pic = true,
    });

    const dso = add_shared_library(b, opts, .{ .name = "a" });
    dso.add_object(a_o);
    dso.add_object(b_o);
    dso.link_z_notext = true;

    const exe = add_executable(b, opts, .{ .name = "main" });
    add_csource_bytes(exe,
        \\#include <stdio.h>
        \\int fnn();
        \\int main() {
        \\  printf("%d\n", fnn());
        \\}
    , &.{});
    exe.link_library(dso);
    exe.link_lib_c();

    const run = add_run_artifact(exe);
    run.expect_std_out_equal("3\n");
    test_step.depend_on(&run.step);

    // Check for DT_TEXTREL in a DSO
    const check = dso.check_object();
    check.check_in_dynamic_section();
    // check.check_exact("TEXTREL 0"); // TODO fix in CheckObject parser
    check.check_contains("FLAGS TEXTREL");
    test_step.depend_on(&check.step);

    return test_step;
}

fn add_test_step(b: *Build, comptime prefix: []const u8, opts: Options) *Step {
    return link.add_test_step(b, "elf-" ++ prefix, opts);
}

const add_asm_source_bytes = link.add_asm_source_bytes;
const add_csource_bytes = link.add_csource_bytes;
const add_cpp_source_bytes = link.add_cpp_source_bytes;
const add_executable = link.add_executable;
const add_object = link.add_object;
const add_run_artifact = link.add_run_artifact;
const add_shared_library = link.add_shared_library;
const add_static_library = link.add_static_library;
const expect_link_errors = link.expect_link_errors;
const link = @import("link.zig");
const std = @import("std");

const Build = std.Build;
const BuildOptions = link.BuildOptions;
const Options = link.Options;
const Step = Build.Step;
const WriteFile = Step.WriteFile;
