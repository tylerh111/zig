// A zig test case that exercises some glibc symbols that have uncovered
// problems in the past.  This test must be compiled against a glibc.
//
// The build.zig tests the binary built from this source to see that
// symbols are statically or dynamically linked, as expected.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;

const c_malloc = @c_import(
    @cInclude("malloc.h"), // for reallocarray
);

const c_stdlib = @c_import(
    @cInclude("stdlib.h"), // for atexit
);

const c_string = @c_import(
    @cInclude("string.h"), // for strlcpy
);

// Version of glibc this test is being built to run against
const glibc_ver = builtin.target.os.version_range.linux.glibc;

// PR #17034 - fstat moved between libc_nonshared and libc
fn check_stat() !void {
    const cwdFd = std.fs.cwd().fd;

    var stat = std.mem.zeroes(std.c.Stat);
    var result = std.c.fstatat(cwdFd, "a_file_that_definitely_does_not_exist", &stat, 0);
    assert(result == -1);
    assert(std.posix.errno(result) == .NOENT);

    result = std.c.stat("a_file_that_definitely_does_not_exist", &stat);
    assert(result == -1);
    assert(std.posix.errno(result) == .NOENT);
}

// PR #17607 - reallocarray not visible in headers
fn check_reallocarray() !void {
    // reallocarray was introduced in v2.26
    if (comptime glibc_ver.order(.{ .major = 2, .minor = 26, .patch = 0 }) == .lt) {
        if (@hasDecl(c_malloc, "reallocarray")) {
            @compile_error("Before v2.26 'malloc.h' does not define 'reallocarray'");
        }
    } else {
        return try check_reallocarray_v2_26();
    }
}

fn check_reallocarray_v2_26() !void {
    const size = 16;
    const tenX = c_malloc.reallocarray(c_malloc.NULL, 10, size);
    const elevenX = c_malloc.reallocarray(tenX, 11, size);

    assert(tenX != c_malloc.NULL);
    assert(elevenX != c_malloc.NULL);
}

// getauxval introduced in v2.16
fn check_get_aux_val() !void {
    if (comptime glibc_ver.order(.{ .major = 2, .minor = 16, .patch = 0 }) == .lt) {
        if (@hasDecl(std.c, "getauxval")) {
            @compile_error("Before v2.16 glibc does not define 'getauxval'");
        }
    } else {
        try check_get_aux_val_v2_16();
    }
}

fn check_get_aux_val_v2_16() !void {
    const base = std.c.getauxval(std.elf.AT_BASE);
    const pgsz = std.c.getauxval(std.elf.AT_PAGESZ);

    assert(base != 0);
    assert(pgsz != 0);
}

// strlcpy introduced in v2.38, which is newer than many installed glibcs
fn check_strlcpy() !void {
    if (comptime glibc_ver.order(.{ .major = 2, .minor = 38, .patch = 0 }) == .lt) {
        if (@hasDecl(c_string, "strlcpy")) {
            @compile_error("Before v2.38 glibc does not define 'strlcpy'");
        }
    } else {
        try check_strlcpy_v2_38();
    }
}

fn check_strlcpy_v2_38() !void {
    var buf: [99]u8 = undefined;
    const used = c_string.strlcpy(&buf, "strlcpy works!", buf.len);
    assert(used == 14);
}

// atexit is part of libc_nonshared, so ensure its linked in correctly
fn force_exit0_callback() callconv(.C) void {
    std.c.exit(0); // Override the main() exit code
}

fn check_at_exit() !void {
    const result = c_stdlib.atexit(force_exit0_callback);
    assert(result == 0);
}

pub fn main() !u8 {
    try check_stat();
    try check_reallocarray();
    try check_strlcpy();

    try check_get_aux_val();
    try check_at_exit();

    std.c.exit(1); // overridden by atexit() callback
}
