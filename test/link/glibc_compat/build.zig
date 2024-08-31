const std = @import("std");
const builtin = @import("builtin");

// To run executables linked against a specific glibc version, the
// run-time glibc version needs to be new enough.  Check the host's glibc
// version.  Note that this does not allow for translation/vm/emulation
// services to run these tests.
const running_glibc_ver: ?std.SemanticVersion = switch (builtin.os.tag) {
    .linux => builtin.os.version_range.linux.glibc,
    else => null,
};

pub fn build(b: *std.Build) void {
    const test_step = b.step("test", "Test");
    b.default_step = test_step;

    for ([_][]const u8{ "aarch64-linux-gnu.2.27", "aarch64-linux-gnu.2.34" }) |t| {
        const exe = b.add_executable(.{
            .name = t,
            .target = b.resolve_target_query(std.Target.Query.parse(
                .{ .arch_os_abi = t },
            ) catch unreachable),
        });
        exe.add_csource_file(.{ .file = b.path("main.c") });
        exe.link_lib_c();
        // TODO: actually test the output
        _ = exe.get_emitted_bin();
        test_step.depend_on(&exe.step);
    }

    // Build & run against a sampling of supported glibc versions
    for ([_][]const u8{
        "native-linux-gnu.2.17", // Currently oldest supported, see #17769
        "native-linux-gnu.2.23",
        "native-linux-gnu.2.28",
        "native-linux-gnu.2.33",
        "native-linux-gnu.2.38",
        "native-linux-gnu",
    }) |t| {
        const target = b.resolve_target_query(std.Target.Query.parse(
            .{ .arch_os_abi = t },
        ) catch unreachable);

        const glibc_ver = target.result.os.version_range.linux.glibc;

        const exe = b.add_executable(.{
            .name = t,
            .root_source_file = b.path("glibc_runtime_check.zig"),
            .target = target,
        });
        exe.link_lib_c();

        // Only try running the test if the host glibc is known to be good enough.  Ideally, the Zig
        // test runner would be able to check this, but see https://github.com/ziglang/zig/pull/17702#issuecomment-1831310453
        if (running_glibc_ver) |running_ver| {
            if (glibc_ver.order(running_ver) == .lt) {
                const run_cmd = b.add_run_artifact(exe);
                run_cmd.skip_foreign_checks = true;
                run_cmd.expect_exit_code(0);

                test_step.depend_on(&run_cmd.step);
            }
        }
        const check = exe.check_object();

        // __errno_location is always a dynamically linked symbol
        check.check_in_dynamic_symtab();
        check.check_exact("0 0 UND FUNC GLOBAL DEFAULT __errno_location");

        // before v2.32 fstatat redirects through __fxstatat, afterwards its a
        // normal dynamic symbol
        if (glibc_ver.order(.{ .major = 2, .minor = 32, .patch = 0 }) == .lt) {
            check.check_in_dynamic_symtab();
            check.check_exact("0 0 UND FUNC GLOBAL DEFAULT __fxstatat");

            check.check_in_symtab();
            check.check_contains("FUNC LOCAL HIDDEN fstatat");
        } else {
            check.check_in_dynamic_symtab();
            check.check_exact("0 0 UND FUNC GLOBAL DEFAULT fstatat");

            check.check_in_symtab();
            check.check_not_present("FUNC LOCAL HIDDEN fstatat");
        }

        // before v2.26 reallocarray is not supported
        if (glibc_ver.order(.{ .major = 2, .minor = 26, .patch = 0 }) == .lt) {
            check.check_in_dynamic_symtab();
            check.check_not_present("reallocarray");
        } else {
            check.check_in_dynamic_symtab();
            check.check_exact("0 0 UND FUNC GLOBAL DEFAULT reallocarray");
        }

        // before v2.38 strlcpy is not supported
        if (glibc_ver.order(.{ .major = 2, .minor = 38, .patch = 0 }) == .lt) {
            check.check_in_dynamic_symtab();
            check.check_not_present("strlcpy");
        } else {
            check.check_in_dynamic_symtab();
            check.check_exact("0 0 UND FUNC GLOBAL DEFAULT strlcpy");
        }

        // v2.16 introduced getauxval(), so always present
        check.check_in_dynamic_symtab();
        check.check_exact("0 0 UND FUNC GLOBAL DEFAULT getauxval");

        // Always have a dynamic "exit" reference
        check.check_in_dynamic_symtab();
        check.check_exact("0 0 UND FUNC GLOBAL DEFAULT exit");

        // An atexit local symbol is defined, and depends on undefined dynamic
        // __cxa_atexit.
        check.check_in_symtab();
        check.check_contains("FUNC LOCAL HIDDEN atexit");
        check.check_in_dynamic_symtab();
        check.check_exact("0 0 UND FUNC GLOBAL DEFAULT __cxa_atexit");

        test_step.depend_on(&check.step);
    }
}
