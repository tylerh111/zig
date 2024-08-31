//! POSIX paths are arbitrary sequences of `u8` with no particular encoding.
//!
//! Windows paths are arbitrary sequences of `u16` (WTF-16).
//! For cross-platform APIs that deal with sequences of `u8`, Windows
//! paths are encoded by Zig as [WTF-8](https://simonsapin.github.io/wtf-8/).
//! WTF-8 is a superset of UTF-8 that allows encoding surrogate codepoints,
//! which enables lossless roundtripping when converting to/from WTF-16
//! (as long as the WTF-8 encoded surrogate codepoints do not form a pair).
//!
//! WASI paths are sequences of valid Unicode scalar values,
//! which means that WASI is unable to handle paths that cannot be
//! encoded as well-formed UTF-8/UTF-16.
//! https://github.com/WebAssembly/wasi-filesystem/issues/17#issuecomment-1430639353

const builtin = @import("builtin");
const std = @import("../std.zig");
const debug = std.debug;
const assert = debug.assert;
const testing = std.testing;
const mem = std.mem;
const fmt = std.fmt;
const ascii = std.ascii;
const Allocator = mem.Allocator;
const math = std.math;
const windows = std.os.windows;
const os = std.os;
const fs = std.fs;
const process = std.process;
const native_os = builtin.target.os.tag;

pub const sep_windows = '\\';
pub const sep_posix = '/';
pub const sep = switch (native_os) {
    .windows, .uefi => sep_windows,
    else => sep_posix,
};

pub const sep_str_windows = "\\";
pub const sep_str_posix = "/";
pub const sep_str = switch (native_os) {
    .windows, .uefi => sep_str_windows,
    else => sep_str_posix,
};

pub const delimiter_windows = ';';
pub const delimiter_posix = ':';
pub const delimiter = if (native_os == .windows) delimiter_windows else delimiter_posix;

/// Returns if the given byte is a valid path separator
pub fn is_sep(byte: u8) bool {
    return switch (native_os) {
        .windows => byte == '/' or byte == '\\',
        .uefi => byte == '\\',
        else => byte == '/',
    };
}

pub const PathType = enum {
    windows,
    uefi,
    posix,

    /// Returns true if `c` is a valid path separator for the `path_type`.
    pub inline fn is_sep(comptime path_type: PathType, comptime T: type, c: T) bool {
        return switch (path_type) {
            .windows => c == '/' or c == '\\',
            .posix => c == '/',
            .uefi => c == '\\',
        };
    }
};

/// This is different from mem.join in that the separator will not be repeated if
/// it is found at the end or beginning of a pair of consecutive paths.
fn join_sep_maybe_z(allocator: Allocator, separator: u8, comptime sepPredicate: fn (u8) bool, paths: []const []const u8, zero: bool) ![]u8 {
    if (paths.len == 0) return if (zero) try allocator.dupe(u8, &[1]u8{0}) else &[0]u8{};

    // Find first non-empty path index.
    const first_path_index = blk: {
        for (paths, 0..) |path, index| {
            if (path.len == 0) continue else break :blk index;
        }

        // All paths provided were empty, so return early.
        return if (zero) try allocator.dupe(u8, &[1]u8{0}) else &[0]u8{};
    };

    // Calculate length needed for resulting joined path buffer.
    const total_len = blk: {
        var sum: usize = paths[first_path_index].len;
        var prev_path = paths[first_path_index];
        assert(prev_path.len > 0);
        var i: usize = first_path_index + 1;
        while (i < paths.len) : (i += 1) {
            const this_path = paths[i];
            if (this_path.len == 0) continue;
            const prev_sep = sepPredicate(prev_path[prev_path.len - 1]);
            const this_sep = sepPredicate(this_path[0]);
            sum += @int_from_bool(!prev_sep and !this_sep);
            sum += if (prev_sep and this_sep) this_path.len - 1 else this_path.len;
            prev_path = this_path;
        }

        if (zero) sum += 1;
        break :blk sum;
    };

    const buf = try allocator.alloc(u8, total_len);
    errdefer allocator.free(buf);

    @memcpy(buf[0..paths[first_path_index].len], paths[first_path_index]);
    var buf_index: usize = paths[first_path_index].len;
    var prev_path = paths[first_path_index];
    assert(prev_path.len > 0);
    var i: usize = first_path_index + 1;
    while (i < paths.len) : (i += 1) {
        const this_path = paths[i];
        if (this_path.len == 0) continue;
        const prev_sep = sepPredicate(prev_path[prev_path.len - 1]);
        const this_sep = sepPredicate(this_path[0]);
        if (!prev_sep and !this_sep) {
            buf[buf_index] = separator;
            buf_index += 1;
        }
        const adjusted_path = if (prev_sep and this_sep) this_path[1..] else this_path;
        @memcpy(buf[buf_index..][0..adjusted_path.len], adjusted_path);
        buf_index += adjusted_path.len;
        prev_path = this_path;
    }

    if (zero) buf[buf.len - 1] = 0;

    // No need for shrink since buf is exactly the correct size.
    return buf;
}

/// Naively combines a series of paths with the native path separator.
/// Allocates memory for the result, which must be freed by the caller.
pub fn join(allocator: Allocator, paths: []const []const u8) ![]u8 {
    return join_sep_maybe_z(allocator, sep, is_sep, paths, false);
}

/// Naively combines a series of paths with the native path separator and null terminator.
/// Allocates memory for the result, which must be freed by the caller.
pub fn join_z(allocator: Allocator, paths: []const []const u8) ![:0]u8 {
    const out = try join_sep_maybe_z(allocator, sep, is_sep, paths, true);
    return out[0 .. out.len - 1 :0];
}

fn test_join_maybe_zuefi(paths: []const []const u8, expected: []const u8, zero: bool) !void {
    const uefiIsSep = struct {
        fn is_sep(byte: u8) bool {
            return byte == '\\';
        }
    }.is_sep;
    const actual = try join_sep_maybe_z(testing.allocator, sep_windows, uefiIsSep, paths, zero);
    defer testing.allocator.free(actual);
    try testing.expect_equal_slices(u8, expected, if (zero) actual[0 .. actual.len - 1 :0] else actual);
}

fn test_join_maybe_zwindows(paths: []const []const u8, expected: []const u8, zero: bool) !void {
    const windowsIsSep = struct {
        fn is_sep(byte: u8) bool {
            return byte == '/' or byte == '\\';
        }
    }.is_sep;
    const actual = try join_sep_maybe_z(testing.allocator, sep_windows, windowsIsSep, paths, zero);
    defer testing.allocator.free(actual);
    try testing.expect_equal_slices(u8, expected, if (zero) actual[0 .. actual.len - 1 :0] else actual);
}

fn test_join_maybe_zposix(paths: []const []const u8, expected: []const u8, zero: bool) !void {
    const posixIsSep = struct {
        fn is_sep(byte: u8) bool {
            return byte == '/';
        }
    }.is_sep;
    const actual = try join_sep_maybe_z(testing.allocator, sep_posix, posixIsSep, paths, zero);
    defer testing.allocator.free(actual);
    try testing.expect_equal_slices(u8, expected, if (zero) actual[0 .. actual.len - 1 :0] else actual);
}

test join {
    {
        const actual: []u8 = try join(testing.allocator, &[_][]const u8{});
        defer testing.allocator.free(actual);
        try testing.expect_equal_slices(u8, "", actual);
    }
    {
        const actual: [:0]u8 = try join_z(testing.allocator, &[_][]const u8{});
        defer testing.allocator.free(actual);
        try testing.expect_equal_slices(u8, "", actual);
    }
    for (&[_]bool{ false, true }) |zero| {
        try test_join_maybe_zwindows(&[_][]const u8{}, "", zero);
        try test_join_maybe_zwindows(&[_][]const u8{ "c:\\a\\b", "c" }, "c:\\a\\b\\c", zero);
        try test_join_maybe_zwindows(&[_][]const u8{ "c:\\a\\b", "c" }, "c:\\a\\b\\c", zero);
        try test_join_maybe_zwindows(&[_][]const u8{ "c:\\a\\b\\", "c" }, "c:\\a\\b\\c", zero);

        try test_join_maybe_zwindows(&[_][]const u8{ "c:\\", "a", "b\\", "c" }, "c:\\a\\b\\c", zero);
        try test_join_maybe_zwindows(&[_][]const u8{ "c:\\a\\", "b\\", "c" }, "c:\\a\\b\\c", zero);

        try test_join_maybe_zwindows(
            &[_][]const u8{ "c:\\home\\andy\\dev\\zig\\build\\lib\\zig\\std", "io.zig" },
            "c:\\home\\andy\\dev\\zig\\build\\lib\\zig\\std\\io.zig",
            zero,
        );

        try test_join_maybe_zuefi(&[_][]const u8{ "EFI", "Boot", "bootx64.efi" }, "EFI\\Boot\\bootx64.efi", zero);
        try test_join_maybe_zuefi(&[_][]const u8{ "EFI\\Boot", "bootx64.efi" }, "EFI\\Boot\\bootx64.efi", zero);
        try test_join_maybe_zuefi(&[_][]const u8{ "EFI\\", "\\Boot", "bootx64.efi" }, "EFI\\Boot\\bootx64.efi", zero);
        try test_join_maybe_zuefi(&[_][]const u8{ "EFI\\", "\\Boot\\", "\\bootx64.efi" }, "EFI\\Boot\\bootx64.efi", zero);

        try test_join_maybe_zwindows(&[_][]const u8{ "c:\\", "a", "b/", "c" }, "c:\\a\\b/c", zero);
        try test_join_maybe_zwindows(&[_][]const u8{ "c:\\a/", "b\\", "/c" }, "c:\\a/b\\c", zero);

        try test_join_maybe_zwindows(&[_][]const u8{ "", "c:\\", "", "", "a", "b\\", "c", "" }, "c:\\a\\b\\c", zero);
        try test_join_maybe_zwindows(&[_][]const u8{ "c:\\a/", "", "b\\", "", "/c" }, "c:\\a/b\\c", zero);
        try test_join_maybe_zwindows(&[_][]const u8{ "", "" }, "", zero);

        try test_join_maybe_zposix(&[_][]const u8{}, "", zero);
        try test_join_maybe_zposix(&[_][]const u8{ "/a/b", "c" }, "/a/b/c", zero);
        try test_join_maybe_zposix(&[_][]const u8{ "/a/b/", "c" }, "/a/b/c", zero);

        try test_join_maybe_zposix(&[_][]const u8{ "/", "a", "b/", "c" }, "/a/b/c", zero);
        try test_join_maybe_zposix(&[_][]const u8{ "/a/", "b/", "c" }, "/a/b/c", zero);

        try test_join_maybe_zposix(
            &[_][]const u8{ "/home/andy/dev/zig/build/lib/zig/std", "io.zig" },
            "/home/andy/dev/zig/build/lib/zig/std/io.zig",
            zero,
        );

        try test_join_maybe_zposix(&[_][]const u8{ "a", "/c" }, "a/c", zero);
        try test_join_maybe_zposix(&[_][]const u8{ "a/", "/c" }, "a/c", zero);

        try test_join_maybe_zposix(&[_][]const u8{ "", "/", "a", "", "b/", "c", "" }, "/a/b/c", zero);
        try test_join_maybe_zposix(&[_][]const u8{ "/a/", "", "", "b/", "c" }, "/a/b/c", zero);
        try test_join_maybe_zposix(&[_][]const u8{ "", "" }, "", zero);
    }
}

pub fn is_absolute_z(path_c: [*:0]const u8) bool {
    if (native_os == .windows) {
        return is_absolute_windows_z(path_c);
    } else {
        return is_absolute_posix_z(path_c);
    }
}

pub fn is_absolute(path: []const u8) bool {
    if (native_os == .windows) {
        return is_absolute_windows(path);
    } else {
        return is_absolute_posix(path);
    }
}

fn is_absolute_windows_impl(comptime T: type, path: []const T) bool {
    if (path.len < 1)
        return false;

    if (path[0] == '/')
        return true;

    if (path[0] == '\\')
        return true;

    if (path.len < 3)
        return false;

    if (path[1] == ':') {
        if (path[2] == '/')
            return true;
        if (path[2] == '\\')
            return true;
    }

    return false;
}

pub fn is_absolute_windows(path: []const u8) bool {
    return is_absolute_windows_impl(u8, path);
}

pub fn is_absolute_windows_w(path_w: [*:0]const u16) bool {
    return is_absolute_windows_impl(u16, mem.slice_to(path_w, 0));
}

pub fn is_absolute_windows_wtf16(path: []const u16) bool {
    return is_absolute_windows_impl(u16, path);
}

pub fn is_absolute_windows_z(path_c: [*:0]const u8) bool {
    return is_absolute_windows_impl(u8, mem.slice_to(path_c, 0));
}

pub fn is_absolute_posix(path: []const u8) bool {
    return path.len > 0 and path[0] == sep_posix;
}

pub fn is_absolute_posix_z(path_c: [*:0]const u8) bool {
    return is_absolute_posix(mem.slice_to(path_c, 0));
}

test is_absolute_windows {
    try test_is_absolute_windows("", false);
    try test_is_absolute_windows("/", true);
    try test_is_absolute_windows("//", true);
    try test_is_absolute_windows("//server", true);
    try test_is_absolute_windows("//server/file", true);
    try test_is_absolute_windows("\\\\server\\file", true);
    try test_is_absolute_windows("\\\\server", true);
    try test_is_absolute_windows("\\\\", true);
    try test_is_absolute_windows("c", false);
    try test_is_absolute_windows("c:", false);
    try test_is_absolute_windows("c:\\", true);
    try test_is_absolute_windows("c:/", true);
    try test_is_absolute_windows("c://", true);
    try test_is_absolute_windows("C:/Users/", true);
    try test_is_absolute_windows("C:\\Users\\", true);
    try test_is_absolute_windows("C:cwd/another", false);
    try test_is_absolute_windows("C:cwd\\another", false);
    try test_is_absolute_windows("directory/directory", false);
    try test_is_absolute_windows("directory\\directory", false);
    try test_is_absolute_windows("/usr/local", true);
}

test is_absolute_posix {
    try test_is_absolute_posix("", false);
    try test_is_absolute_posix("/home/foo", true);
    try test_is_absolute_posix("/home/foo/..", true);
    try test_is_absolute_posix("bar/", false);
    try test_is_absolute_posix("./baz", false);
}

fn test_is_absolute_windows(path: []const u8, expected_result: bool) !void {
    try testing.expect_equal(expected_result, is_absolute_windows(path));
}

fn test_is_absolute_posix(path: []const u8, expected_result: bool) !void {
    try testing.expect_equal(expected_result, is_absolute_posix(path));
}

pub const WindowsPath = struct {
    is_abs: bool,
    kind: Kind,
    disk_designator: []const u8,

    pub const Kind = enum {
        None,
        Drive,
        NetworkShare,
    };
};

pub fn windows_parse_path(path: []const u8) WindowsPath {
    if (path.len >= 2 and path[1] == ':') {
        return WindowsPath{
            .is_abs = is_absolute_windows(path),
            .kind = WindowsPath.Kind.Drive,
            .disk_designator = path[0..2],
        };
    }
    if (path.len >= 1 and (path[0] == '/' or path[0] == '\\') and
        (path.len == 1 or (path[1] != '/' and path[1] != '\\')))
    {
        return WindowsPath{
            .is_abs = true,
            .kind = WindowsPath.Kind.None,
            .disk_designator = path[0..0],
        };
    }
    const relative_path = WindowsPath{
        .kind = WindowsPath.Kind.None,
        .disk_designator = &[_]u8{},
        .is_abs = false,
    };
    if (path.len < "//a/b".len) {
        return relative_path;
    }

    inline for ("/\\") |this_sep| {
        const two_sep = [_]u8{ this_sep, this_sep };
        if (mem.starts_with(u8, path, &two_sep)) {
            if (path[2] == this_sep) {
                return relative_path;
            }

            var it = mem.tokenize_scalar(u8, path, this_sep);
            _ = (it.next() orelse return relative_path);
            _ = (it.next() orelse return relative_path);
            return WindowsPath{
                .is_abs = is_absolute_windows(path),
                .kind = WindowsPath.Kind.NetworkShare,
                .disk_designator = path[0..it.index],
            };
        }
    }
    return relative_path;
}

test windows_parse_path {
    {
        const parsed = windows_parse_path("//a/b");
        try testing.expect(parsed.is_abs);
        try testing.expect(parsed.kind == WindowsPath.Kind.NetworkShare);
        try testing.expect(mem.eql(u8, parsed.disk_designator, "//a/b"));
    }
    {
        const parsed = windows_parse_path("\\\\a\\b");
        try testing.expect(parsed.is_abs);
        try testing.expect(parsed.kind == WindowsPath.Kind.NetworkShare);
        try testing.expect(mem.eql(u8, parsed.disk_designator, "\\\\a\\b"));
    }
    {
        const parsed = windows_parse_path("\\\\a\\");
        try testing.expect(!parsed.is_abs);
        try testing.expect(parsed.kind == WindowsPath.Kind.None);
        try testing.expect(mem.eql(u8, parsed.disk_designator, ""));
    }
    {
        const parsed = windows_parse_path("/usr/local");
        try testing.expect(parsed.is_abs);
        try testing.expect(parsed.kind == WindowsPath.Kind.None);
        try testing.expect(mem.eql(u8, parsed.disk_designator, ""));
    }
    {
        const parsed = windows_parse_path("c:../");
        try testing.expect(!parsed.is_abs);
        try testing.expect(parsed.kind == WindowsPath.Kind.Drive);
        try testing.expect(mem.eql(u8, parsed.disk_designator, "c:"));
    }
}

pub fn disk_designator(path: []const u8) []const u8 {
    if (native_os == .windows) {
        return disk_designator_windows(path);
    } else {
        return "";
    }
}

pub fn disk_designator_windows(path: []const u8) []const u8 {
    return windows_parse_path(path).disk_designator;
}

fn network_share_servers_eql(ns1: []const u8, ns2: []const u8) bool {
    const sep1 = ns1[0];
    const sep2 = ns2[0];

    var it1 = mem.tokenize_scalar(u8, ns1, sep1);
    var it2 = mem.tokenize_scalar(u8, ns2, sep2);

    return windows.eql_ignore_case_wtf8(it1.next().?, it2.next().?);
}

fn compare_disk_designators(kind: WindowsPath.Kind, p1: []const u8, p2: []const u8) bool {
    switch (kind) {
        WindowsPath.Kind.None => {
            assert(p1.len == 0);
            assert(p2.len == 0);
            return true;
        },
        WindowsPath.Kind.Drive => {
            return ascii.to_upper(p1[0]) == ascii.to_upper(p2[0]);
        },
        WindowsPath.Kind.NetworkShare => {
            const sep1 = p1[0];
            const sep2 = p2[0];

            var it1 = mem.tokenize_scalar(u8, p1, sep1);
            var it2 = mem.tokenize_scalar(u8, p2, sep2);

            return windows.eql_ignore_case_wtf8(it1.next().?, it2.next().?) and windows.eql_ignore_case_wtf8(it1.next().?, it2.next().?);
        },
    }
}

/// On Windows, this calls `resolve_windows` and on POSIX it calls `resolve_posix`.
pub fn resolve(allocator: Allocator, paths: []const []const u8) ![]u8 {
    if (native_os == .windows) {
        return resolve_windows(allocator, paths);
    } else {
        return resolve_posix(allocator, paths);
    }
}

/// This function is like a series of `cd` statements executed one after another.
/// It resolves "." and "..", but will not convert relative path to absolute path, use std.fs.Dir.realpath instead.
/// The result does not have a trailing path separator.
/// Each drive has its own current working directory.
/// Path separators are canonicalized to '\\' and drives are canonicalized to capital letters.
/// Note: all usage of this function should be audited due to the existence of symlinks.
/// Without performing actual syscalls, resolving `..` could be incorrect.
/// This API may break in the future: https://github.com/ziglang/zig/issues/13613
pub fn resolve_windows(allocator: Allocator, paths: []const []const u8) ![]u8 {
    assert(paths.len > 0);

    // determine which disk designator we will result with, if any
    var result_drive_buf = "_:".*;
    var disk_designator: []const u8 = "";
    var drive_kind = WindowsPath.Kind.None;
    var have_abs_path = false;
    var first_index: usize = 0;
    for (paths, 0..) |p, i| {
        const parsed = windows_parse_path(p);
        if (parsed.is_abs) {
            have_abs_path = true;
            first_index = i;
        }
        switch (parsed.kind) {
            .Drive => {
                result_drive_buf[0] = ascii.to_upper(parsed.disk_designator[0]);
                disk_designator = result_drive_buf[0..];
                drive_kind = WindowsPath.Kind.Drive;
            },
            .NetworkShare => {
                disk_designator = parsed.disk_designator;
                drive_kind = WindowsPath.Kind.NetworkShare;
            },
            .None => {},
        }
    }

    // if we will result with a disk designator, loop again to determine
    // which is the last time the disk designator is absolutely specified, if any
    // and count up the max bytes for paths related to this disk designator
    if (drive_kind != WindowsPath.Kind.None) {
        have_abs_path = false;
        first_index = 0;
        var correct_disk_designator = false;

        for (paths, 0..) |p, i| {
            const parsed = windows_parse_path(p);
            if (parsed.kind != WindowsPath.Kind.None) {
                if (parsed.kind == drive_kind) {
                    correct_disk_designator = compare_disk_designators(drive_kind, disk_designator, parsed.disk_designator);
                } else {
                    continue;
                }
            }
            if (!correct_disk_designator) {
                continue;
            }
            if (parsed.is_abs) {
                first_index = i;
                have_abs_path = true;
            }
        }
    }

    // Allocate result and fill in the disk designator.
    var result = std.ArrayList(u8).init(allocator);
    defer result.deinit();

    const disk_designator_len: usize = l: {
        if (!have_abs_path) break :l 0;
        switch (drive_kind) {
            .Drive => {
                try result.append_slice(disk_designator);
                break :l disk_designator.len;
            },
            .NetworkShare => {
                var it = mem.tokenize_any(u8, paths[first_index], "/\\");
                const server_name = it.next().?;
                const other_name = it.next().?;

                try result.ensure_unused_capacity(2 + 1 + server_name.len + other_name.len);
                result.append_slice_assume_capacity("\\\\");
                result.append_slice_assume_capacity(server_name);
                result.append_assume_capacity('\\');
                result.append_slice_assume_capacity(other_name);

                break :l result.items.len;
            },
            .None => {
                break :l 1;
            },
        }
    };

    var correct_disk_designator = true;
    var negative_count: usize = 0;

    for (paths[first_index..]) |p| {
        const parsed = windows_parse_path(p);

        if (parsed.kind != .None) {
            if (parsed.kind == drive_kind) {
                const dd = result.items[0..disk_designator_len];
                correct_disk_designator = compare_disk_designators(drive_kind, dd, parsed.disk_designator);
            } else {
                continue;
            }
        }
        if (!correct_disk_designator) {
            continue;
        }
        var it = mem.tokenize_any(u8, p[parsed.disk_designator.len..], "/\\");
        while (it.next()) |component| {
            if (mem.eql(u8, component, ".")) {
                continue;
            } else if (mem.eql(u8, component, "..")) {
                if (result.items.len == 0) {
                    negative_count += 1;
                    continue;
                }
                while (true) {
                    if (result.items.len == disk_designator_len) {
                        break;
                    }
                    const end_with_sep = switch (result.items[result.items.len - 1]) {
                        '\\', '/' => true,
                        else => false,
                    };
                    result.items.len -= 1;
                    if (end_with_sep or result.items.len == 0) break;
                }
            } else if (!have_abs_path and result.items.len == 0) {
                try result.append_slice(component);
            } else {
                try result.ensure_unused_capacity(1 + component.len);
                result.append_assume_capacity('\\');
                result.append_slice_assume_capacity(component);
            }
        }
    }

    if (disk_designator_len != 0 and result.items.len == disk_designator_len) {
        try result.append('\\');
        return result.to_owned_slice();
    }

    if (result.items.len == 0) {
        if (negative_count == 0) {
            return allocator.dupe(u8, ".");
        } else {
            const real_result = try allocator.alloc(u8, 3 * negative_count - 1);
            var count = negative_count - 1;
            var i: usize = 0;
            while (count > 0) : (count -= 1) {
                real_result[i..][0..3].* = "..\\".*;
                i += 3;
            }
            real_result[i..][0..2].* = "..".*;
            return real_result;
        }
    }

    if (negative_count == 0) {
        return result.to_owned_slice();
    } else {
        const real_result = try allocator.alloc(u8, 3 * negative_count + result.items.len);
        var count = negative_count;
        var i: usize = 0;
        while (count > 0) : (count -= 1) {
            real_result[i..][0..3].* = "..\\".*;
            i += 3;
        }
        @memcpy(real_result[i..][0..result.items.len], result.items);
        return real_result;
    }
}

/// This function is like a series of `cd` statements executed one after another.
/// It resolves "." and "..", but will not convert relative path to absolute path, use std.fs.Dir.realpath instead.
/// The result does not have a trailing path separator.
/// This function does not perform any syscalls. Executing this series of path
/// lookups on the actual filesystem may produce different results due to
/// symlinks.
pub fn resolve_posix(allocator: Allocator, paths: []const []const u8) Allocator.Error![]u8 {
    assert(paths.len > 0);

    var result = std.ArrayList(u8).init(allocator);
    defer result.deinit();

    var negative_count: usize = 0;
    var is_abs = false;

    for (paths) |p| {
        if (is_absolute_posix(p)) {
            is_abs = true;
            negative_count = 0;
            result.clear_retaining_capacity();
        }
        var it = mem.tokenize_scalar(u8, p, '/');
        while (it.next()) |component| {
            if (mem.eql(u8, component, ".")) {
                continue;
            } else if (mem.eql(u8, component, "..")) {
                if (result.items.len == 0) {
                    negative_count += @int_from_bool(!is_abs);
                    continue;
                }
                while (true) {
                    const ends_with_slash = result.items[result.items.len - 1] == '/';
                    result.items.len -= 1;
                    if (ends_with_slash or result.items.len == 0) break;
                }
            } else if (result.items.len > 0 or is_abs) {
                try result.ensure_unused_capacity(1 + component.len);
                result.append_assume_capacity('/');
                result.append_slice_assume_capacity(component);
            } else {
                try result.append_slice(component);
            }
        }
    }

    if (result.items.len == 0) {
        if (is_abs) {
            return allocator.dupe(u8, "/");
        }
        if (negative_count == 0) {
            return allocator.dupe(u8, ".");
        } else {
            const real_result = try allocator.alloc(u8, 3 * negative_count - 1);
            var count = negative_count - 1;
            var i: usize = 0;
            while (count > 0) : (count -= 1) {
                real_result[i..][0..3].* = "../".*;
                i += 3;
            }
            real_result[i..][0..2].* = "..".*;
            return real_result;
        }
    }

    if (negative_count == 0) {
        return result.to_owned_slice();
    } else {
        const real_result = try allocator.alloc(u8, 3 * negative_count + result.items.len);
        var count = negative_count;
        var i: usize = 0;
        while (count > 0) : (count -= 1) {
            real_result[i..][0..3].* = "../".*;
            i += 3;
        }
        @memcpy(real_result[i..][0..result.items.len], result.items);
        return real_result;
    }
}

test resolve {
    try test_resolve_windows(&[_][]const u8{ "a\\b\\c\\", "..\\..\\.." }, ".");
    try test_resolve_windows(&[_][]const u8{"."}, ".");
    try test_resolve_windows(&[_][]const u8{""}, ".");

    try test_resolve_posix(&[_][]const u8{ "a/b/c/", "../../.." }, ".");
    try test_resolve_posix(&[_][]const u8{"."}, ".");
    try test_resolve_posix(&[_][]const u8{""}, ".");
}

test resolve_windows {
    try test_resolve_windows(
        &[_][]const u8{ "Z:\\", "/usr/local", "lib\\zig\\std\\array_list.zig" },
        "Z:\\usr\\local\\lib\\zig\\std\\array_list.zig",
    );
    try test_resolve_windows(
        &[_][]const u8{ "z:\\", "usr/local", "lib\\zig" },
        "Z:\\usr\\local\\lib\\zig",
    );

    try test_resolve_windows(&[_][]const u8{ "c:\\a\\b\\c", "/hi", "ok" }, "C:\\hi\\ok");
    try test_resolve_windows(&[_][]const u8{ "c:/blah\\blah", "d:/games", "c:../a" }, "C:\\blah\\a");
    try test_resolve_windows(&[_][]const u8{ "c:/blah\\blah", "d:/games", "C:../a" }, "C:\\blah\\a");
    try test_resolve_windows(&[_][]const u8{ "c:/ignore", "d:\\a/b\\c/d", "\\e.exe" }, "D:\\e.exe");
    try test_resolve_windows(&[_][]const u8{ "c:/ignore", "c:/some/file" }, "C:\\some\\file");
    try test_resolve_windows(&[_][]const u8{ "d:/ignore", "d:some/dir//" }, "D:\\ignore\\some\\dir");
    try test_resolve_windows(&[_][]const u8{ "//server/share", "..", "relative\\" }, "\\\\server\\share\\relative");
    try test_resolve_windows(&[_][]const u8{ "c:/", "//" }, "C:\\");
    try test_resolve_windows(&[_][]const u8{ "c:/", "//dir" }, "C:\\dir");
    try test_resolve_windows(&[_][]const u8{ "c:/", "//server/share" }, "\\\\server\\share\\");
    try test_resolve_windows(&[_][]const u8{ "c:/", "//server//share" }, "\\\\server\\share\\");
    try test_resolve_windows(&[_][]const u8{ "c:/", "///some//dir" }, "C:\\some\\dir");
    try test_resolve_windows(&[_][]const u8{ "C:\\foo\\tmp.3\\", "..\\tmp.3\\cycles\\root.js" }, "C:\\foo\\tmp.3\\cycles\\root.js");

    // Keep relative paths relative.
    try test_resolve_windows(&[_][]const u8{"a/b"}, "a\\b");
}

test resolve_posix {
    try test_resolve_posix(&.{ "/a/b", "c" }, "/a/b/c");
    try test_resolve_posix(&.{ "/a/b", "c", "//d", "e///" }, "/d/e");
    try test_resolve_posix(&.{ "/a/b/c", "..", "../" }, "/a");
    try test_resolve_posix(&.{ "/", "..", ".." }, "/");
    try test_resolve_posix(&.{"/a/b/c/"}, "/a/b/c");

    try test_resolve_posix(&.{ "/var/lib", "../", "file/" }, "/var/file");
    try test_resolve_posix(&.{ "/var/lib", "/../", "file/" }, "/file");
    try test_resolve_posix(&.{ "/some/dir", ".", "/absolute/" }, "/absolute");
    try test_resolve_posix(&.{ "/foo/tmp.3/", "../tmp.3/cycles/root.js" }, "/foo/tmp.3/cycles/root.js");

    // Keep relative paths relative.
    try test_resolve_posix(&.{"a/b"}, "a/b");
    try test_resolve_posix(&.{"."}, ".");
    try test_resolve_posix(&.{ ".", "src/test.zig", "..", "../test/cases.zig" }, "test/cases.zig");
}

fn test_resolve_windows(paths: []const []const u8, expected: []const u8) !void {
    const actual = try resolve_windows(testing.allocator, paths);
    defer testing.allocator.free(actual);
    try testing.expect_equal_strings(expected, actual);
}

fn test_resolve_posix(paths: []const []const u8, expected: []const u8) !void {
    const actual = try resolve_posix(testing.allocator, paths);
    defer testing.allocator.free(actual);
    try testing.expect_equal_strings(expected, actual);
}

/// Strip the last component from a file path.
///
/// If the path is a file in the current directory (no directory component)
/// then returns null.
///
/// If the path is the root directory, returns null.
pub fn dirname(path: []const u8) ?[]const u8 {
    if (native_os == .windows) {
        return dirname_windows(path);
    } else {
        return dirname_posix(path);
    }
}

pub fn dirname_windows(path: []const u8) ?[]const u8 {
    if (path.len == 0)
        return null;

    const root_slice = disk_designator_windows(path);
    if (path.len == root_slice.len)
        return null;

    const have_root_slash = path.len > root_slice.len and (path[root_slice.len] == '/' or path[root_slice.len] == '\\');

    var end_index: usize = path.len - 1;

    while (path[end_index] == '/' or path[end_index] == '\\') {
        if (end_index == 0)
            return null;
        end_index -= 1;
    }

    while (path[end_index] != '/' and path[end_index] != '\\') {
        if (end_index == 0)
            return null;
        end_index -= 1;
    }

    if (have_root_slash and end_index == root_slice.len) {
        end_index += 1;
    }

    if (end_index == 0)
        return null;

    return path[0..end_index];
}

pub fn dirname_posix(path: []const u8) ?[]const u8 {
    if (path.len == 0)
        return null;

    var end_index: usize = path.len - 1;
    while (path[end_index] == '/') {
        if (end_index == 0)
            return null;
        end_index -= 1;
    }

    while (path[end_index] != '/') {
        if (end_index == 0)
            return null;
        end_index -= 1;
    }

    if (end_index == 0 and path[0] == '/')
        return path[0..1];

    if (end_index == 0)
        return null;

    return path[0..end_index];
}

test dirname_posix {
    try test_dirname_posix("/a/b/c", "/a/b");
    try test_dirname_posix("/a/b/c///", "/a/b");
    try test_dirname_posix("/a", "/");
    try test_dirname_posix("/", null);
    try test_dirname_posix("//", null);
    try test_dirname_posix("///", null);
    try test_dirname_posix("////", null);
    try test_dirname_posix("", null);
    try test_dirname_posix("a", null);
    try test_dirname_posix("a/", null);
    try test_dirname_posix("a//", null);
}

test dirname_windows {
    try test_dirname_windows("c:\\", null);
    try test_dirname_windows("c:\\foo", "c:\\");
    try test_dirname_windows("c:\\foo\\", "c:\\");
    try test_dirname_windows("c:\\foo\\bar", "c:\\foo");
    try test_dirname_windows("c:\\foo\\bar\\", "c:\\foo");
    try test_dirname_windows("c:\\foo\\bar\\baz", "c:\\foo\\bar");
    try test_dirname_windows("\\", null);
    try test_dirname_windows("\\foo", "\\");
    try test_dirname_windows("\\foo\\", "\\");
    try test_dirname_windows("\\foo\\bar", "\\foo");
    try test_dirname_windows("\\foo\\bar\\", "\\foo");
    try test_dirname_windows("\\foo\\bar\\baz", "\\foo\\bar");
    try test_dirname_windows("c:", null);
    try test_dirname_windows("c:foo", null);
    try test_dirname_windows("c:foo\\", null);
    try test_dirname_windows("c:foo\\bar", "c:foo");
    try test_dirname_windows("c:foo\\bar\\", "c:foo");
    try test_dirname_windows("c:foo\\bar\\baz", "c:foo\\bar");
    try test_dirname_windows("file:stream", null);
    try test_dirname_windows("dir\\file:stream", "dir");
    try test_dirname_windows("\\\\unc\\share", null);
    try test_dirname_windows("\\\\unc\\share\\foo", "\\\\unc\\share\\");
    try test_dirname_windows("\\\\unc\\share\\foo\\", "\\\\unc\\share\\");
    try test_dirname_windows("\\\\unc\\share\\foo\\bar", "\\\\unc\\share\\foo");
    try test_dirname_windows("\\\\unc\\share\\foo\\bar\\", "\\\\unc\\share\\foo");
    try test_dirname_windows("\\\\unc\\share\\foo\\bar\\baz", "\\\\unc\\share\\foo\\bar");
    try test_dirname_windows("/a/b/", "/a");
    try test_dirname_windows("/a/b", "/a");
    try test_dirname_windows("/a", "/");
    try test_dirname_windows("", null);
    try test_dirname_windows("/", null);
    try test_dirname_windows("////", null);
    try test_dirname_windows("foo", null);
}

fn test_dirname_posix(input: []const u8, expected_output: ?[]const u8) !void {
    if (dirname_posix(input)) |output| {
        try testing.expect(mem.eql(u8, output, expected_output.?));
    } else {
        try testing.expect(expected_output == null);
    }
}

fn test_dirname_windows(input: []const u8, expected_output: ?[]const u8) !void {
    if (dirname_windows(input)) |output| {
        try testing.expect(mem.eql(u8, output, expected_output.?));
    } else {
        try testing.expect(expected_output == null);
    }
}

pub fn basename(path: []const u8) []const u8 {
    if (native_os == .windows) {
        return basename_windows(path);
    } else {
        return basename_posix(path);
    }
}

pub fn basename_posix(path: []const u8) []const u8 {
    if (path.len == 0)
        return &[_]u8{};

    var end_index: usize = path.len - 1;
    while (path[end_index] == '/') {
        if (end_index == 0)
            return &[_]u8{};
        end_index -= 1;
    }
    var start_index: usize = end_index;
    end_index += 1;
    while (path[start_index] != '/') {
        if (start_index == 0)
            return path[0..end_index];
        start_index -= 1;
    }

    return path[start_index + 1 .. end_index];
}

pub fn basename_windows(path: []const u8) []const u8 {
    if (path.len == 0)
        return &[_]u8{};

    var end_index: usize = path.len - 1;
    while (true) {
        const byte = path[end_index];
        if (byte == '/' or byte == '\\') {
            if (end_index == 0)
                return &[_]u8{};
            end_index -= 1;
            continue;
        }
        if (byte == ':' and end_index == 1) {
            return &[_]u8{};
        }
        break;
    }

    var start_index: usize = end_index;
    end_index += 1;
    while (path[start_index] != '/' and path[start_index] != '\\' and
        !(path[start_index] == ':' and start_index == 1))
    {
        if (start_index == 0)
            return path[0..end_index];
        start_index -= 1;
    }

    return path[start_index + 1 .. end_index];
}

test basename {
    try test_basename("", "");
    try test_basename("/", "");
    try test_basename("/dir/basename.ext", "basename.ext");
    try test_basename("/basename.ext", "basename.ext");
    try test_basename("basename.ext", "basename.ext");
    try test_basename("basename.ext/", "basename.ext");
    try test_basename("basename.ext//", "basename.ext");
    try test_basename("/aaa/bbb", "bbb");
    try test_basename("/aaa/", "aaa");
    try test_basename("/aaa/b", "b");
    try test_basename("/a/b", "b");
    try test_basename("//a", "a");

    try test_basename_posix("\\dir\\basename.ext", "\\dir\\basename.ext");
    try test_basename_posix("\\basename.ext", "\\basename.ext");
    try test_basename_posix("basename.ext", "basename.ext");
    try test_basename_posix("basename.ext\\", "basename.ext\\");
    try test_basename_posix("basename.ext\\\\", "basename.ext\\\\");
    try test_basename_posix("foo", "foo");

    try test_basename_windows("\\dir\\basename.ext", "basename.ext");
    try test_basename_windows("\\basename.ext", "basename.ext");
    try test_basename_windows("basename.ext", "basename.ext");
    try test_basename_windows("basename.ext\\", "basename.ext");
    try test_basename_windows("basename.ext\\\\", "basename.ext");
    try test_basename_windows("foo", "foo");
    try test_basename_windows("C:", "");
    try test_basename_windows("C:.", ".");
    try test_basename_windows("C:\\", "");
    try test_basename_windows("C:\\dir\\base.ext", "base.ext");
    try test_basename_windows("C:\\basename.ext", "basename.ext");
    try test_basename_windows("C:basename.ext", "basename.ext");
    try test_basename_windows("C:basename.ext\\", "basename.ext");
    try test_basename_windows("C:basename.ext\\\\", "basename.ext");
    try test_basename_windows("C:foo", "foo");
    try test_basename_windows("file:stream", "file:stream");
}

fn test_basename(input: []const u8, expected_output: []const u8) !void {
    try testing.expect_equal_slices(u8, expected_output, basename(input));
}

fn test_basename_posix(input: []const u8, expected_output: []const u8) !void {
    try testing.expect_equal_slices(u8, expected_output, basename_posix(input));
}

fn test_basename_windows(input: []const u8, expected_output: []const u8) !void {
    try testing.expect_equal_slices(u8, expected_output, basename_windows(input));
}

/// Returns the relative path from `from` to `to`. If `from` and `to` each
/// resolve to the same path (after calling `resolve` on each), a zero-length
/// string is returned.
/// On Windows this canonicalizes the drive to a capital letter and paths to `\\`.
pub fn relative(allocator: Allocator, from: []const u8, to: []const u8) ![]u8 {
    if (native_os == .windows) {
        return relative_windows(allocator, from, to);
    } else {
        return relative_posix(allocator, from, to);
    }
}

pub fn relative_windows(allocator: Allocator, from: []const u8, to: []const u8) ![]u8 {
    const cwd = try process.get_cwd_alloc(allocator);
    defer allocator.free(cwd);
    const resolved_from = try resolve_windows(allocator, &[_][]const u8{ cwd, from });
    defer allocator.free(resolved_from);

    var clean_up_resolved_to = true;
    const resolved_to = try resolve_windows(allocator, &[_][]const u8{ cwd, to });
    defer if (clean_up_resolved_to) allocator.free(resolved_to);

    const parsed_from = windows_parse_path(resolved_from);
    const parsed_to = windows_parse_path(resolved_to);
    const result_is_to = x: {
        if (parsed_from.kind != parsed_to.kind) {
            break :x true;
        } else switch (parsed_from.kind) {
            .NetworkShare => {
                break :x !network_share_servers_eql(parsed_to.disk_designator, parsed_from.disk_designator);
            },
            .Drive => {
                break :x ascii.to_upper(parsed_from.disk_designator[0]) != ascii.to_upper(parsed_to.disk_designator[0]);
            },
            .None => {
                break :x false;
            },
        }
    };

    if (result_is_to) {
        clean_up_resolved_to = false;
        return resolved_to;
    }

    var from_it = mem.tokenize_any(u8, resolved_from, "/\\");
    var to_it = mem.tokenize_any(u8, resolved_to, "/\\");
    while (true) {
        const from_component = from_it.next() orelse return allocator.dupe(u8, to_it.rest());
        const to_rest = to_it.rest();
        if (to_it.next()) |to_component| {
            if (windows.eql_ignore_case_wtf8(from_component, to_component))
                continue;
        }
        var up_index_end = "..".len;
        while (from_it.next()) |_| {
            up_index_end += "\\..".len;
        }
        const result = try allocator.alloc(u8, up_index_end + @int_from_bool(to_rest.len > 0) + to_rest.len);
        errdefer allocator.free(result);

        result[0..2].* = "..".*;
        var result_index: usize = 2;
        while (result_index < up_index_end) {
            result[result_index..][0..3].* = "\\..".*;
            result_index += 3;
        }

        var rest_it = mem.tokenize_any(u8, to_rest, "/\\");
        while (rest_it.next()) |to_component| {
            result[result_index] = '\\';
            result_index += 1;
            @memcpy(result[result_index..][0..to_component.len], to_component);
            result_index += to_component.len;
        }

        return allocator.realloc(result, result_index);
    }

    return [_]u8{};
}

pub fn relative_posix(allocator: Allocator, from: []const u8, to: []const u8) ![]u8 {
    const cwd = try process.get_cwd_alloc(allocator);
    defer allocator.free(cwd);
    const resolved_from = try resolve_posix(allocator, &[_][]const u8{ cwd, from });
    defer allocator.free(resolved_from);
    const resolved_to = try resolve_posix(allocator, &[_][]const u8{ cwd, to });
    defer allocator.free(resolved_to);

    var from_it = mem.tokenize_scalar(u8, resolved_from, '/');
    var to_it = mem.tokenize_scalar(u8, resolved_to, '/');
    while (true) {
        const from_component = from_it.next() orelse return allocator.dupe(u8, to_it.rest());
        const to_rest = to_it.rest();
        if (to_it.next()) |to_component| {
            if (mem.eql(u8, from_component, to_component))
                continue;
        }
        var up_count: usize = 1;
        while (from_it.next()) |_| {
            up_count += 1;
        }
        const up_index_end = up_count * "../".len;
        const result = try allocator.alloc(u8, up_index_end + to_rest.len);
        errdefer allocator.free(result);

        var result_index: usize = 0;
        while (result_index < up_index_end) {
            result[result_index..][0..3].* = "../".*;
            result_index += 3;
        }
        if (to_rest.len == 0) {
            // shave off the trailing slash
            return allocator.realloc(result, result_index - 1);
        }

        @memcpy(result[result_index..][0..to_rest.len], to_rest);
        return result;
    }

    return [_]u8{};
}

test relative {
    try test_relative_windows("c:/blah\\blah", "d:/games", "D:\\games");
    try test_relative_windows("c:/aaaa/bbbb", "c:/aaaa", "..");
    try test_relative_windows("c:/aaaa/bbbb", "c:/cccc", "..\\..\\cccc");
    try test_relative_windows("c:/aaaa/bbbb", "C:/aaaa/bbbb", "");
    try test_relative_windows("c:/aaaa/bbbb", "c:/aaaa/cccc", "..\\cccc");
    try test_relative_windows("c:/aaaa/", "c:/aaaa/cccc", "cccc");
    try test_relative_windows("c:/", "c:\\aaaa\\bbbb", "aaaa\\bbbb");
    try test_relative_windows("c:/aaaa/bbbb", "d:\\", "D:\\");
    try test_relative_windows("c:/AaAa/bbbb", "c:/aaaa/bbbb", "");
    try test_relative_windows("c:/aaaaa/", "c:/aaaa/cccc", "..\\aaaa\\cccc");
    try test_relative_windows("C:\\foo\\bar\\baz\\quux", "C:\\", "..\\..\\..\\..");
    try test_relative_windows("C:\\foo\\test", "C:\\foo\\test\\bar\\package.json", "bar\\package.json");
    try test_relative_windows("C:\\foo\\bar\\baz-quux", "C:\\foo\\bar\\baz", "..\\baz");
    try test_relative_windows("C:\\foo\\bar\\baz", "C:\\foo\\bar\\baz-quux", "..\\baz-quux");
    try test_relative_windows("\\\\foo\\bar", "\\\\foo\\bar\\baz", "baz");
    try test_relative_windows("\\\\foo\\bar\\baz", "\\\\foo\\bar", "..");
    try test_relative_windows("\\\\foo\\bar\\baz-quux", "\\\\foo\\bar\\baz", "..\\baz");
    try test_relative_windows("\\\\foo\\bar\\baz", "\\\\foo\\bar\\baz-quux", "..\\baz-quux");
    try test_relative_windows("C:\\baz-quux", "C:\\baz", "..\\baz");
    try test_relative_windows("C:\\baz", "C:\\baz-quux", "..\\baz-quux");
    try test_relative_windows("\\\\foo\\baz-quux", "\\\\foo\\baz", "..\\baz");
    try test_relative_windows("\\\\foo\\baz", "\\\\foo\\baz-quux", "..\\baz-quux");
    try test_relative_windows("C:\\baz", "\\\\foo\\bar\\baz", "\\\\foo\\bar\\baz");
    try test_relative_windows("\\\\foo\\bar\\baz", "C:\\baz", "C:\\baz");

    try test_relative_windows("a/b/c", "a\\b", "..");
    try test_relative_windows("a/b/c", "a", "..\\..");
    try test_relative_windows("a/b/c", "a\\b\\c\\d", "d");

    try test_relative_windows("\\\\FOO\\bar\\baz", "\\\\foo\\BAR\\BAZ", "");
    // Unicode-aware case-insensitive path comparison
    try test_relative_windows("\\\\кириллица\\ελληνικά\\português", "\\\\КИРИЛЛИЦА\\ΕΛΛΗΝΙΚΆ\\PORTUGUÊS", "");

    try test_relative_posix("/var/lib", "/var", "..");
    try test_relative_posix("/var/lib", "/bin", "../../bin");
    try test_relative_posix("/var/lib", "/var/lib", "");
    try test_relative_posix("/var/lib", "/var/apache", "../apache");
    try test_relative_posix("/var/", "/var/lib", "lib");
    try test_relative_posix("/", "/var/lib", "var/lib");
    try test_relative_posix("/foo/test", "/foo/test/bar/package.json", "bar/package.json");
    try test_relative_posix("/Users/a/web/b/test/mails", "/Users/a/web/b", "../..");
    try test_relative_posix("/foo/bar/baz-quux", "/foo/bar/baz", "../baz");
    try test_relative_posix("/foo/bar/baz", "/foo/bar/baz-quux", "../baz-quux");
    try test_relative_posix("/baz-quux", "/baz", "../baz");
    try test_relative_posix("/baz", "/baz-quux", "../baz-quux");
}

fn test_relative_posix(from: []const u8, to: []const u8, expected_output: []const u8) !void {
    const result = try relative_posix(testing.allocator, from, to);
    defer testing.allocator.free(result);
    try testing.expect_equal_strings(expected_output, result);
}

fn test_relative_windows(from: []const u8, to: []const u8, expected_output: []const u8) !void {
    const result = try relative_windows(testing.allocator, from, to);
    defer testing.allocator.free(result);
    try testing.expect_equal_strings(expected_output, result);
}

/// Searches for a file extension separated by a `.` and returns the string after that `.`.
/// Files that end or start with `.` and have no other `.` in their name
/// are considered to have no extension, in which case this returns "".
/// Examples:
/// - `"main.zig"`      ⇒ `".zig"`
/// - `"src/main.zig"`  ⇒ `".zig"`
/// - `".gitignore"`    ⇒ `""`
/// - `".image.png"`    ⇒ `".png"`
/// - `"keep."`         ⇒ `"."`
/// - `"src.keep.me"`   ⇒ `".me"`
/// - `"/src/keep.me"`  ⇒ `".me"`
/// - `"/src/keep.me/"` ⇒ `".me"`
/// The returned slice is guaranteed to have its pointer within the start and end
/// pointer address range of `path`, even if it is length zero.
pub fn extension(path: []const u8) []const u8 {
    const filename = basename(path);
    const index = mem.last_index_of_scalar(u8, filename, '.') orelse return path[path.len..];
    if (index == 0) return path[path.len..];
    return filename[index..];
}

fn test_extension(path: []const u8, expected: []const u8) !void {
    try testing.expect_equal_strings(expected, extension(path));
}

test extension {
    try test_extension("", "");
    try test_extension(".", "");
    try test_extension("a.", ".");
    try test_extension("abc.", ".");
    try test_extension(".a", "");
    try test_extension(".file", "");
    try test_extension(".gitignore", "");
    try test_extension(".image.png", ".png");
    try test_extension("file.ext", ".ext");
    try test_extension("file.ext.", ".");
    try test_extension("very-long-file.bruh", ".bruh");
    try test_extension("a.b.c", ".c");
    try test_extension("a.b.c/", ".c");

    try test_extension("/", "");
    try test_extension("/.", "");
    try test_extension("/a.", ".");
    try test_extension("/abc.", ".");
    try test_extension("/.a", "");
    try test_extension("/.file", "");
    try test_extension("/.gitignore", "");
    try test_extension("/file.ext", ".ext");
    try test_extension("/file.ext.", ".");
    try test_extension("/very-long-file.bruh", ".bruh");
    try test_extension("/a.b.c", ".c");
    try test_extension("/a.b.c/", ".c");

    try test_extension("/foo/bar/bam/", "");
    try test_extension("/foo/bar/bam/.", "");
    try test_extension("/foo/bar/bam/a.", ".");
    try test_extension("/foo/bar/bam/abc.", ".");
    try test_extension("/foo/bar/bam/.a", "");
    try test_extension("/foo/bar/bam/.file", "");
    try test_extension("/foo/bar/bam/.gitignore", "");
    try test_extension("/foo/bar/bam/file.ext", ".ext");
    try test_extension("/foo/bar/bam/file.ext.", ".");
    try test_extension("/foo/bar/bam/very-long-file.bruh", ".bruh");
    try test_extension("/foo/bar/bam/a.b.c", ".c");
    try test_extension("/foo/bar/bam/a.b.c/", ".c");
}

/// Returns the last component of this path without its extension (if any):
/// - "hello/world/lib.tar.gz" ⇒ "lib.tar"
/// - "hello/world/lib.tar"    ⇒ "lib"
/// - "hello/world/lib"        ⇒ "lib"
pub fn stem(path: []const u8) []const u8 {
    const filename = basename(path);
    const index = mem.last_index_of_scalar(u8, filename, '.') orelse return filename[0..];
    if (index == 0) return path;
    return filename[0..index];
}

fn test_stem(path: []const u8, expected: []const u8) !void {
    try testing.expect_equal_strings(expected, stem(path));
}

test stem {
    try test_stem("hello/world/lib.tar.gz", "lib.tar");
    try test_stem("hello/world/lib.tar", "lib");
    try test_stem("hello/world/lib", "lib");
    try test_stem("hello/lib/", "lib");
    try test_stem("hello...", "hello..");
    try test_stem("hello.", "hello");
    try test_stem("/hello.", "hello");
    try test_stem(".gitignore", ".gitignore");
    try test_stem(".image.png", ".image");
    try test_stem("file.ext", "file");
    try test_stem("file.ext.", "file.ext");
    try test_stem("a.b.c", "a.b");
    try test_stem("a.b.c/", "a.b");
    try test_stem(".a", ".a");
    try test_stem("///", "");
    try test_stem("..", ".");
    try test_stem(".", ".");
    try test_stem(" ", " ");
    try test_stem("", "");
}

/// A path component iterator that can move forwards and backwards.
/// The 'root' of the path (`/` for POSIX, things like `C:\`, `\\server\share\`, etc
/// for Windows) is treated specially and will never be returned by any of the
/// `first`, `last`, `next`, or `previous` functions.
/// Multiple consecutive path separators are skipped (treated as a single separator)
/// when iterating.
/// All returned component names/paths are slices of the original path.
/// There is no normalization of paths performed while iterating.
pub fn ComponentIterator(comptime path_type: PathType, comptime T: type) type {
    return struct {
        path: []const T,
        root_end_index: usize = 0,
        start_index: usize = 0,
        end_index: usize = 0,

        const Self = @This();

        pub const Component = struct {
            /// The current component's path name, e.g. 'b'.
            /// This will never contain path separators.
            name: []const T,
            /// The full path up to and including the current component, e.g. '/a/b'
            /// This will never contain trailing path separators.
            path: []const T,
        };

        const InitError = switch (path_type) {
            .windows => error{BadPathName},
            else => error{},
        };

        /// After `init`, `next` will return the first component after the root
        /// (there is no need to call `first` after `init`).
        /// To iterate backwards (from the end of the path to the beginning), call `last`
        /// after `init` and then iterate via `previous` calls.
        /// For Windows paths, `error.BadPathName` is returned if the `path` has an explicit
        /// namespace prefix (`\\.\`, `\\?\`, or `\??\`) or if it is a UNC path with more
        /// than two path separators at the beginning.
        pub fn init(path: []const T) InitError!Self {
            const root_end_index: usize = switch (path_type) {
                .posix, .uefi => posix: {
                    // Root on UEFI and POSIX only differs by the path separator
                    var root_end_index: usize = 0;
                    while (true) : (root_end_index += 1) {
                        if (root_end_index >= path.len or !path_type.is_sep(T, path[root_end_index])) {
                            break;
                        }
                    }
                    break :posix root_end_index;
                },
                .windows => windows: {
                    // Namespaces other than the Win32 file namespace are tricky
                    // and basically impossible to determine a 'root' for, since it's
                    // possible to construct an effectively arbitrarily long 'root',
                    // e.g. `\\.\GLOBALROOT\??\UNC\localhost\C$\foo` is a
                    // possible path that would be effectively equivalent to
                    // `C:\foo`, and the `GLOBALROOT\??\` part can also be recursive,
                    // so `GLOBALROOT\??\GLOBALROOT\??\...` would work for any number
                    // of repetitions. Therefore, paths with an explicit namespace prefix
                    // (\\.\, \??\, \\?\) are not allowed here.
                    if (std.os.windows.get_namespace_prefix(T, path) != .none) {
                        return error.BadPathName;
                    }
                    const windows_path_type = std.os.windows.get_unprefixed_path_type(T, path);
                    break :windows switch (windows_path_type) {
                        .relative => 0,
                        .root_local_device => path.len,
                        .rooted => 1,
                        .unc_absolute => unc: {
                            var end_index: usize = 2;
                            // Any extra separators between the first two and the server name are not allowed
                            // and will always lead to STATUS_OBJECT_PATH_INVALID if it is attempted
                            // to be used.
                            if (end_index < path.len and path_type.is_sep(T, path[end_index])) {
                                return error.BadPathName;
                            }
                            // Server
                            while (end_index < path.len and !path_type.is_sep(T, path[end_index])) {
                                end_index += 1;
                            }
                            // Slash(es) after server
                            while (end_index < path.len and path_type.is_sep(T, path[end_index])) {
                                end_index += 1;
                            }
                            // Share
                            while (end_index < path.len and !path_type.is_sep(T, path[end_index])) {
                                end_index += 1;
                            }
                            // Slash(es) after share
                            while (end_index < path.len and path_type.is_sep(T, path[end_index])) {
                                end_index += 1;
                            }
                            break :unc end_index;
                        },
                        .drive_absolute => drive: {
                            var end_index: usize = 3;
                            while (end_index < path.len and path_type.is_sep(T, path[end_index])) {
                                end_index += 1;
                            }
                            break :drive end_index;
                        },
                        .drive_relative => 2,
                    };
                },
            };
            return .{
                .path = path,
                .root_end_index = root_end_index,
                .start_index = root_end_index,
                .end_index = root_end_index,
            };
        }

        /// Returns the root of the path if it is an absolute path, or null otherwise.
        /// For POSIX paths, this will be `/`.
        /// For Windows paths, this will be something like `C:\`, `\\server\share\`, etc.
        /// For UEFI paths, this will be `\`.
        pub fn root(self: Self) ?[]const T {
            if (self.root_end_index == 0) return null;
            return self.path[0..self.root_end_index];
        }

        /// Returns the first component (from the beginning of the path).
        /// For example, if the path is `/a/b/c` then this will return the `a` component.
        /// After calling `first`, `previous` will always return `null`, and `next` will return
        /// the component to the right of the one returned by `first`, if any exist.
        pub fn first(self: *Self) ?Component {
            self.start_index = self.root_end_index;
            self.end_index = self.start_index;
            while (self.end_index < self.path.len and !path_type.is_sep(T, self.path[self.end_index])) {
                self.end_index += 1;
            }
            if (self.end_index == self.start_index) return null;
            return .{
                .name = self.path[self.start_index..self.end_index],
                .path = self.path[0..self.end_index],
            };
        }

        /// Returns the last component (from the end of the path).
        /// For example, if the path is `/a/b/c` then this will return the `c` component.
        /// After calling `last`, `next` will always return `null`, and `previous` will return
        /// the component to the left of the one returned by `last`, if any exist.
        pub fn last(self: *Self) ?Component {
            self.end_index = self.path.len;
            while (true) {
                if (self.end_index == self.root_end_index) {
                    self.start_index = self.end_index;
                    return null;
                }
                if (!path_type.is_sep(T, self.path[self.end_index - 1])) break;
                self.end_index -= 1;
            }
            self.start_index = self.end_index;
            while (true) {
                if (self.start_index == self.root_end_index) break;
                if (path_type.is_sep(T, self.path[self.start_index - 1])) break;
                self.start_index -= 1;
            }
            if (self.start_index == self.end_index) return null;
            return .{
                .name = self.path[self.start_index..self.end_index],
                .path = self.path[0..self.end_index],
            };
        }

        /// Returns the next component (the component to the right of the most recently
        /// returned component), or null if no such component exists.
        /// For example, if the path is `/a/b/c` and the most recently returned component
        /// is `b`, then this will return the `c` component.
        pub fn next(self: *Self) ?Component {
            const peek_result = self.peek_next() orelse return null;
            self.start_index = peek_result.path.len - peek_result.name.len;
            self.end_index = peek_result.path.len;
            return peek_result;
        }

        /// Like `next`, but does not modify the iterator state.
        pub fn peek_next(self: Self) ?Component {
            var start_index = self.end_index;
            while (start_index < self.path.len and path_type.is_sep(T, self.path[start_index])) {
                start_index += 1;
            }
            var end_index = start_index;
            while (end_index < self.path.len and !path_type.is_sep(T, self.path[end_index])) {
                end_index += 1;
            }
            if (start_index == end_index) return null;
            return .{
                .name = self.path[start_index..end_index],
                .path = self.path[0..end_index],
            };
        }

        /// Returns the previous component (the component to the left of the most recently
        /// returned component), or null if no such component exists.
        /// For example, if the path is `/a/b/c` and the most recently returned component
        /// is `b`, then this will return the `a` component.
        pub fn previous(self: *Self) ?Component {
            const peek_result = self.peek_previous() orelse return null;
            self.start_index = peek_result.path.len - peek_result.name.len;
            self.end_index = peek_result.path.len;
            return peek_result;
        }

        /// Like `previous`, but does not modify the iterator state.
        pub fn peek_previous(self: Self) ?Component {
            var end_index = self.start_index;
            while (true) {
                if (end_index == self.root_end_index) return null;
                if (!path_type.is_sep(T, self.path[end_index - 1])) break;
                end_index -= 1;
            }
            var start_index = end_index;
            while (true) {
                if (start_index == self.root_end_index) break;
                if (path_type.is_sep(T, self.path[start_index - 1])) break;
                start_index -= 1;
            }
            if (start_index == end_index) return null;
            return .{
                .name = self.path[start_index..end_index],
                .path = self.path[0..end_index],
            };
        }
    };
}

pub const NativeComponentIterator = ComponentIterator(switch (native_os) {
    .windows => .windows,
    .uefi => .uefi,
    else => .posix,
}, u8);

pub fn component_iterator(path: []const u8) !NativeComponentIterator {
    return NativeComponentIterator.init(path);
}

test "ComponentIterator posix" {
    const PosixComponentIterator = ComponentIterator(.posix, u8);
    {
        const path = "a/b/c/";
        var it = try PosixComponentIterator.init(path);
        try std.testing.expect_equal(@as(usize, 0), it.root_end_index);
        try std.testing.expect(null == it.root());
        {
            try std.testing.expect(null == it.previous());

            const first_via_next = it.next().?;
            try std.testing.expect_equal_strings("a", first_via_next.name);
            try std.testing.expect_equal_strings("a", first_via_next.path);

            const first = it.first().?;
            try std.testing.expect_equal_strings("a", first.name);
            try std.testing.expect_equal_strings("a", first.path);

            try std.testing.expect(null == it.previous());

            const second = it.next().?;
            try std.testing.expect_equal_strings("b", second.name);
            try std.testing.expect_equal_strings("a/b", second.path);

            const third = it.next().?;
            try std.testing.expect_equal_strings("c", third.name);
            try std.testing.expect_equal_strings("a/b/c", third.path);

            try std.testing.expect(null == it.next());
        }
        {
            const last = it.last().?;
            try std.testing.expect_equal_strings("c", last.name);
            try std.testing.expect_equal_strings("a/b/c", last.path);

            try std.testing.expect(null == it.next());

            const second_to_last = it.previous().?;
            try std.testing.expect_equal_strings("b", second_to_last.name);
            try std.testing.expect_equal_strings("a/b", second_to_last.path);

            const third_to_last = it.previous().?;
            try std.testing.expect_equal_strings("a", third_to_last.name);
            try std.testing.expect_equal_strings("a", third_to_last.path);

            try std.testing.expect(null == it.previous());
        }
    }

    {
        const path = "/a/b/c/";
        var it = try PosixComponentIterator.init(path);
        try std.testing.expect_equal(@as(usize, 1), it.root_end_index);
        try std.testing.expect_equal_strings("/", it.root().?);
        {
            try std.testing.expect(null == it.previous());

            const first_via_next = it.next().?;
            try std.testing.expect_equal_strings("a", first_via_next.name);
            try std.testing.expect_equal_strings("/a", first_via_next.path);

            const first = it.first().?;
            try std.testing.expect_equal_strings("a", first.name);
            try std.testing.expect_equal_strings("/a", first.path);

            try std.testing.expect(null == it.previous());

            const second = it.next().?;
            try std.testing.expect_equal_strings("b", second.name);
            try std.testing.expect_equal_strings("/a/b", second.path);

            const third = it.next().?;
            try std.testing.expect_equal_strings("c", third.name);
            try std.testing.expect_equal_strings("/a/b/c", third.path);

            try std.testing.expect(null == it.next());
        }
        {
            const last = it.last().?;
            try std.testing.expect_equal_strings("c", last.name);
            try std.testing.expect_equal_strings("/a/b/c", last.path);

            try std.testing.expect(null == it.next());

            const second_to_last = it.previous().?;
            try std.testing.expect_equal_strings("b", second_to_last.name);
            try std.testing.expect_equal_strings("/a/b", second_to_last.path);

            const third_to_last = it.previous().?;
            try std.testing.expect_equal_strings("a", third_to_last.name);
            try std.testing.expect_equal_strings("/a", third_to_last.path);

            try std.testing.expect(null == it.previous());
        }
    }

    {
        const path = "/";
        var it = try PosixComponentIterator.init(path);
        try std.testing.expect_equal(@as(usize, 1), it.root_end_index);
        try std.testing.expect_equal_strings("/", it.root().?);

        try std.testing.expect(null == it.first());
        try std.testing.expect(null == it.previous());
        try std.testing.expect(null == it.first());
        try std.testing.expect(null == it.next());

        try std.testing.expect(null == it.last());
        try std.testing.expect(null == it.previous());
        try std.testing.expect(null == it.last());
        try std.testing.expect(null == it.next());
    }

    {
        const path = "";
        var it = try PosixComponentIterator.init(path);
        try std.testing.expect_equal(@as(usize, 0), it.root_end_index);
        try std.testing.expect(null == it.root());

        try std.testing.expect(null == it.first());
        try std.testing.expect(null == it.previous());
        try std.testing.expect(null == it.first());
        try std.testing.expect(null == it.next());

        try std.testing.expect(null == it.last());
        try std.testing.expect(null == it.previous());
        try std.testing.expect(null == it.last());
        try std.testing.expect(null == it.next());
    }
}

test "ComponentIterator windows" {
    const WindowsComponentIterator = ComponentIterator(.windows, u8);
    {
        const path = "a/b\\c//";
        var it = try WindowsComponentIterator.init(path);
        try std.testing.expect_equal(@as(usize, 0), it.root_end_index);
        try std.testing.expect(null == it.root());
        {
            try std.testing.expect(null == it.previous());

            const first_via_next = it.next().?;
            try std.testing.expect_equal_strings("a", first_via_next.name);
            try std.testing.expect_equal_strings("a", first_via_next.path);

            const first = it.first().?;
            try std.testing.expect_equal_strings("a", first.name);
            try std.testing.expect_equal_strings("a", first.path);

            try std.testing.expect(null == it.previous());

            const second = it.next().?;
            try std.testing.expect_equal_strings("b", second.name);
            try std.testing.expect_equal_strings("a/b", second.path);

            const third = it.next().?;
            try std.testing.expect_equal_strings("c", third.name);
            try std.testing.expect_equal_strings("a/b\\c", third.path);

            try std.testing.expect(null == it.next());
        }
        {
            const last = it.last().?;
            try std.testing.expect_equal_strings("c", last.name);
            try std.testing.expect_equal_strings("a/b\\c", last.path);

            try std.testing.expect(null == it.next());

            const second_to_last = it.previous().?;
            try std.testing.expect_equal_strings("b", second_to_last.name);
            try std.testing.expect_equal_strings("a/b", second_to_last.path);

            const third_to_last = it.previous().?;
            try std.testing.expect_equal_strings("a", third_to_last.name);
            try std.testing.expect_equal_strings("a", third_to_last.path);

            try std.testing.expect(null == it.previous());
        }
    }

    {
        const path = "C:\\a/b/c/";
        var it = try WindowsComponentIterator.init(path);
        try std.testing.expect_equal(@as(usize, 3), it.root_end_index);
        try std.testing.expect_equal_strings("C:\\", it.root().?);
        {
            const first = it.first().?;
            try std.testing.expect_equal_strings("a", first.name);
            try std.testing.expect_equal_strings("C:\\a", first.path);

            const second = it.next().?;
            try std.testing.expect_equal_strings("b", second.name);
            try std.testing.expect_equal_strings("C:\\a/b", second.path);

            const third = it.next().?;
            try std.testing.expect_equal_strings("c", third.name);
            try std.testing.expect_equal_strings("C:\\a/b/c", third.path);

            try std.testing.expect(null == it.next());
        }
        {
            const last = it.last().?;
            try std.testing.expect_equal_strings("c", last.name);
            try std.testing.expect_equal_strings("C:\\a/b/c", last.path);

            const second_to_last = it.previous().?;
            try std.testing.expect_equal_strings("b", second_to_last.name);
            try std.testing.expect_equal_strings("C:\\a/b", second_to_last.path);

            const third_to_last = it.previous().?;
            try std.testing.expect_equal_strings("a", third_to_last.name);
            try std.testing.expect_equal_strings("C:\\a", third_to_last.path);

            try std.testing.expect(null == it.previous());
        }
    }

    {
        const path = "/";
        var it = try WindowsComponentIterator.init(path);
        try std.testing.expect_equal(@as(usize, 1), it.root_end_index);
        try std.testing.expect_equal_strings("/", it.root().?);

        try std.testing.expect(null == it.first());
        try std.testing.expect(null == it.previous());
        try std.testing.expect(null == it.first());
        try std.testing.expect(null == it.next());

        try std.testing.expect(null == it.last());
        try std.testing.expect(null == it.previous());
        try std.testing.expect(null == it.last());
        try std.testing.expect(null == it.next());
    }

    {
        const path = "";
        var it = try WindowsComponentIterator.init(path);
        try std.testing.expect_equal(@as(usize, 0), it.root_end_index);
        try std.testing.expect(null == it.root());

        try std.testing.expect(null == it.first());
        try std.testing.expect(null == it.previous());
        try std.testing.expect(null == it.first());
        try std.testing.expect(null == it.next());

        try std.testing.expect(null == it.last());
        try std.testing.expect(null == it.previous());
        try std.testing.expect(null == it.last());
        try std.testing.expect(null == it.next());
    }
}

test "ComponentIterator windows WTF-16" {
    // TODO: Fix on big endian architectures
    if (builtin.cpu.arch.endian() != .little) {
        return error.SkipZigTest;
    }

    const WindowsComponentIterator = ComponentIterator(.windows, u16);
    const L = std.unicode.utf8_to_utf16_le_string_literal;

    const path = L("C:\\a/b/c/");
    var it = try WindowsComponentIterator.init(path);
    try std.testing.expect_equal(@as(usize, 3), it.root_end_index);
    try std.testing.expect_equal_slices(u16, L("C:\\"), it.root().?);
    {
        const first = it.first().?;
        try std.testing.expect_equal_slices(u16, L("a"), first.name);
        try std.testing.expect_equal_slices(u16, L("C:\\a"), first.path);

        const second = it.next().?;
        try std.testing.expect_equal_slices(u16, L("b"), second.name);
        try std.testing.expect_equal_slices(u16, L("C:\\a/b"), second.path);

        const third = it.next().?;
        try std.testing.expect_equal_slices(u16, L("c"), third.name);
        try std.testing.expect_equal_slices(u16, L("C:\\a/b/c"), third.path);

        try std.testing.expect(null == it.next());
    }
    {
        const last = it.last().?;
        try std.testing.expect_equal_slices(u16, L("c"), last.name);
        try std.testing.expect_equal_slices(u16, L("C:\\a/b/c"), last.path);

        const second_to_last = it.previous().?;
        try std.testing.expect_equal_slices(u16, L("b"), second_to_last.name);
        try std.testing.expect_equal_slices(u16, L("C:\\a/b"), second_to_last.path);

        const third_to_last = it.previous().?;
        try std.testing.expect_equal_slices(u16, L("a"), third_to_last.name);
        try std.testing.expect_equal_slices(u16, L("C:\\a"), third_to_last.path);

        try std.testing.expect(null == it.previous());
    }
}

test "ComponentIterator roots" {
    // UEFI
    {
        var it = try ComponentIterator(.uefi, u8).init("\\\\a");
        try std.testing.expect_equal_strings("\\\\", it.root().?);

        it = try ComponentIterator(.uefi, u8).init("//a");
        try std.testing.expect(null == it.root());
    }
    // POSIX
    {
        var it = try ComponentIterator(.posix, u8).init("//a");
        try std.testing.expect_equal_strings("//", it.root().?);

        it = try ComponentIterator(.posix, u8).init("\\\\a");
        try std.testing.expect(null == it.root());
    }
    // Windows
    {
        // Drive relative
        var it = try ComponentIterator(.windows, u8).init("C:a");
        try std.testing.expect_equal_strings("C:", it.root().?);

        // Drive absolute
        it = try ComponentIterator(.windows, u8).init("C://a");
        try std.testing.expect_equal_strings("C://", it.root().?);
        it = try ComponentIterator(.windows, u8).init("C:\\a");
        try std.testing.expect_equal_strings("C:\\", it.root().?);

        // Rooted
        it = try ComponentIterator(.windows, u8).init("\\a");
        try std.testing.expect_equal_strings("\\", it.root().?);
        it = try ComponentIterator(.windows, u8).init("/a");
        try std.testing.expect_equal_strings("/", it.root().?);

        // Root local device
        it = try ComponentIterator(.windows, u8).init("\\\\.");
        try std.testing.expect_equal_strings("\\\\.", it.root().?);
        it = try ComponentIterator(.windows, u8).init("//?");
        try std.testing.expect_equal_strings("//?", it.root().?);

        // UNC absolute
        it = try ComponentIterator(.windows, u8).init("//");
        try std.testing.expect_equal_strings("//", it.root().?);
        it = try ComponentIterator(.windows, u8).init("\\\\a");
        try std.testing.expect_equal_strings("\\\\a", it.root().?);
        it = try ComponentIterator(.windows, u8).init("\\\\a\\b\\\\c");
        try std.testing.expect_equal_strings("\\\\a\\b\\\\", it.root().?);
        it = try ComponentIterator(.windows, u8).init("//a");
        try std.testing.expect_equal_strings("//a", it.root().?);
        it = try ComponentIterator(.windows, u8).init("//a/b//c");
        try std.testing.expect_equal_strings("//a/b//", it.root().?);
    }
}

/// Format a path encoded as bytes for display as UTF-8.
/// Returns a Formatter for the given path. The path will be converted to valid UTF-8
/// during formatting. This is a lossy conversion if the path contains any ill-formed UTF-8.
/// Ill-formed UTF-8 byte sequences are replaced by the replacement character (U+FFFD)
/// according to "U+FFFD Substitution of Maximal Subparts" from Chapter 3 of
/// the Unicode standard, and as specified by https://encoding.spec.whatwg.org/#utf-8-decoder
pub const fmtAsUtf8Lossy = std.unicode.fmt_utf8;

/// Format a path encoded as WTF-16 LE for display as UTF-8.
/// Return a Formatter for a (potentially ill-formed) UTF-16 LE path.
/// The path will be converted to valid UTF-8 during formatting. This is
/// a lossy conversion if the path contains any unpaired surrogates.
/// Unpaired surrogates are replaced by the replacement character (U+FFFD).
pub const fmtWtf16LeAsUtf8Lossy = std.unicode.fmt_utf16_le;
