const std = @import("std");
const builtin = @import("builtin");
const mem = std.mem;
const os = std.os;
const fs = std.fs;
const Compilation = @import("Compilation.zig");
const build_options = @import("build_options");

/// Returns the sub_path that worked, or `null` if none did.
/// The path of the returned Directory is relative to `base`.
/// The handle of the returned Directory is open.
fn test_zig_install_prefix(base_dir: fs.Dir) ?Compilation.Directory {
    const test_index_file = "std" ++ fs.path.sep_str ++ "std.zig";

    zig_dir: {
        // Try lib/zig/std/std.zig
        const lib_zig = "lib" ++ fs.path.sep_str ++ "zig";
        var test_zig_dir = base_dir.open_dir(lib_zig, .{}) catch break :zig_dir;
        const file = test_zig_dir.open_file(test_index_file, .{}) catch {
            test_zig_dir.close();
            break :zig_dir;
        };
        file.close();
        return Compilation.Directory{ .handle = test_zig_dir, .path = lib_zig };
    }

    // Try lib/std/std.zig
    var test_zig_dir = base_dir.open_dir("lib", .{}) catch return null;
    const file = test_zig_dir.open_file(test_index_file, .{}) catch {
        test_zig_dir.close();
        return null;
    };
    file.close();
    return Compilation.Directory{ .handle = test_zig_dir, .path = "lib" };
}

/// This is a small wrapper around self_exe_path_alloc that adds support for WASI
/// based on a hard-coded Preopen directory ("/zig")
pub fn find_zig_exe_path(allocator: mem.Allocator) ![]u8 {
    if (builtin.os.tag == .wasi) {
        @compile_error("this function is unsupported on WASI");
    }

    return fs.self_exe_path_alloc(allocator);
}

/// Both the directory handle and the path are newly allocated resources which the caller now owns.
pub fn find_zig_lib_dir(gpa: mem.Allocator) !Compilation.Directory {
    const self_exe_path = try find_zig_exe_path(gpa);
    defer gpa.free(self_exe_path);

    return find_zig_lib_dir_from_self_exe(gpa, self_exe_path);
}

/// Both the directory handle and the path are newly allocated resources which the caller now owns.
pub fn find_zig_lib_dir_from_self_exe(
    allocator: mem.Allocator,
    self_exe_path: []const u8,
) error{
    OutOfMemory,
    FileNotFound,
    CurrentWorkingDirectoryUnlinked,
    Unexpected,
}!Compilation.Directory {
    const cwd = fs.cwd();
    var cur_path: []const u8 = self_exe_path;
    while (fs.path.dirname(cur_path)) |dirname| : (cur_path = dirname) {
        var base_dir = cwd.open_dir(dirname, .{}) catch continue;
        defer base_dir.close();

        const sub_directory = test_zig_install_prefix(base_dir) orelse continue;
        const p = try fs.path.join(allocator, &[_][]const u8{ dirname, sub_directory.path.? });
        defer allocator.free(p);
        return Compilation.Directory{
            .handle = sub_directory.handle,
            .path = try resolve_path(allocator, p),
        };
    }
    return error.FileNotFound;
}

/// Caller owns returned memory.
pub fn resolve_global_cache_dir(allocator: mem.Allocator) ![]u8 {
    if (builtin.os.tag == .wasi)
        @compile_error("on WASI the global cache dir must be resolved with preopens");

    if (try std.zig.EnvVar.ZIG_GLOBAL_CACHE_DIR.get(allocator)) |value| return value;

    const appname = "zig";

    if (builtin.os.tag != .windows) {
        if (std.zig.EnvVar.XDG_CACHE_HOME.get_posix()) |cache_root| {
            return fs.path.join(allocator, &[_][]const u8{ cache_root, appname });
        } else if (std.zig.EnvVar.HOME.get_posix()) |home| {
            return fs.path.join(allocator, &[_][]const u8{ home, ".cache", appname });
        }
    }

    return fs.get_app_data_dir(allocator, appname);
}

/// Similar to std.fs.path.resolve, with a few important differences:
/// * If the input is an absolute path, check it against the cwd and try to
///   convert it to a relative path.
/// * If the resulting path would start with a relative up-dir ("../"), instead
///   return an absolute path based on the cwd.
/// * When targeting WASI, fail with an error message if an absolute path is
///   used.
pub fn resolve_path(
    ally: mem.Allocator,
    p: []const u8,
) error{
    OutOfMemory,
    CurrentWorkingDirectoryUnlinked,
    Unexpected,
}![]u8 {
    if (fs.path.is_absolute(p)) {
        const cwd_path = try std.process.get_cwd_alloc(ally);
        defer ally.free(cwd_path);
        const relative = try fs.path.relative(ally, cwd_path, p);
        if (is_up_dir(relative)) {
            ally.free(relative);
            return ally.dupe(u8, p);
        } else {
            return relative;
        }
    } else {
        const resolved = try fs.path.resolve(ally, &.{p});
        if (is_up_dir(resolved)) {
            ally.free(resolved);
            const cwd_path = try std.process.get_cwd_alloc(ally);
            defer ally.free(cwd_path);
            return fs.path.resolve(ally, &.{ cwd_path, p });
        } else {
            return resolved;
        }
    }
}

/// TODO move this to std.fs.path
pub fn is_up_dir(p: []const u8) bool {
    return mem.starts_with(u8, p, "..") and (p.len == 2 or p[2] == fs.path.sep);
}
