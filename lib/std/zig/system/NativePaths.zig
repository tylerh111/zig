const std = @import("../../std.zig");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const process = std.process;
const mem = std.mem;

const NativePaths = @This();

arena: Allocator,
include_dirs: std.ArrayListUnmanaged([]const u8) = .{},
lib_dirs: std.ArrayListUnmanaged([]const u8) = .{},
framework_dirs: std.ArrayListUnmanaged([]const u8) = .{},
rpaths: std.ArrayListUnmanaged([]const u8) = .{},
warnings: std.ArrayListUnmanaged([]const u8) = .{},

pub fn detect(arena: Allocator, native_target: std.Target) !NativePaths {
    var self: NativePaths = .{ .arena = arena };
    var is_nix = false;
    if (process.get_env_var_owned(arena, "NIX_CFLAGS_COMPILE")) |nix_cflags_compile| {
        is_nix = true;
        var it = mem.tokenize_scalar(u8, nix_cflags_compile, ' ');
        while (true) {
            const word = it.next() orelse break;
            if (mem.eql(u8, word, "-isystem")) {
                const include_path = it.next() orelse {
                    try self.add_warning("Expected argument after -isystem in NIX_CFLAGS_COMPILE");
                    break;
                };
                try self.add_include_dir(include_path);
            } else if (mem.eql(u8, word, "-iframework")) {
                const framework_path = it.next() orelse {
                    try self.add_warning("Expected argument after -iframework in NIX_CFLAGS_COMPILE");
                    break;
                };
                try self.add_framework_dir(framework_path);
            } else {
                if (mem.starts_with(u8, word, "-frandom-seed=")) {
                    continue;
                }
                try self.add_warning_fmt("Unrecognized C flag from NIX_CFLAGS_COMPILE: {s}", .{word});
            }
        }
    } else |err| switch (err) {
        error.InvalidWtf8 => unreachable,
        error.EnvironmentVariableNotFound => {},
        error.OutOfMemory => |e| return e,
    }
    if (process.get_env_var_owned(arena, "NIX_LDFLAGS")) |nix_ldflags| {
        is_nix = true;
        var it = mem.tokenize_scalar(u8, nix_ldflags, ' ');
        while (true) {
            const word = it.next() orelse break;
            if (mem.eql(u8, word, "-rpath")) {
                const rpath = it.next() orelse {
                    try self.add_warning("Expected argument after -rpath in NIX_LDFLAGS");
                    break;
                };
                try self.add_rpath(rpath);
            } else if (mem.eql(u8, word, "-L") or mem.eql(u8, word, "-l")) {
                _ = it.next() orelse {
                    try self.add_warning("Expected argument after -L or -l in NIX_LDFLAGS");
                    break;
                };
            } else if (mem.starts_with(u8, word, "-L")) {
                const lib_path = word[2..];
                try self.add_lib_dir(lib_path);
                try self.add_rpath(lib_path);
            } else if (mem.starts_with(u8, word, "-l")) {
                // Ignore this argument.
            } else {
                try self.add_warning_fmt("Unrecognized C flag from NIX_LDFLAGS: {s}", .{word});
                break;
            }
        }
    } else |err| switch (err) {
        error.InvalidWtf8 => unreachable,
        error.EnvironmentVariableNotFound => {},
        error.OutOfMemory => |e| return e,
    }
    if (is_nix) {
        return self;
    }

    // TODO: consider also adding homebrew paths
    // TODO: consider also adding macports paths
    if (comptime builtin.target.is_darwin()) {
        if (std.zig.system.darwin.is_sdk_installed(arena)) sdk: {
            const sdk = std.zig.system.darwin.get_sdk(arena, native_target) orelse break :sdk;
            try self.add_lib_dir(try std.fs.path.join(arena, &.{ sdk, "usr/lib" }));
            try self.add_framework_dir(try std.fs.path.join(arena, &.{ sdk, "System/Library/Frameworks" }));
            try self.add_include_dir(try std.fs.path.join(arena, &.{ sdk, "usr/include" }));
            return self;
        }
        return self;
    }

    if (builtin.os.tag.is_solarish()) {
        try self.add_lib_dir("/usr/lib/64");
        try self.add_lib_dir("/usr/local/lib/64");
        try self.add_lib_dir("/lib/64");

        try self.add_include_dir("/usr/include");
        try self.add_include_dir("/usr/local/include");

        return self;
    }

    if (builtin.os.tag == .haiku) {
        try self.add_lib_dir("/system/non-packaged/lib");
        try self.add_lib_dir("/system/develop/lib");
        try self.add_lib_dir("/system/lib");
        return self;
    }

    if (builtin.os.tag != .windows and builtin.os.tag != .wasi) {
        const triple = try native_target.linux_triple(arena);

        const qual = native_target.ptr_bit_width();

        // TODO: $ ld --verbose | grep SEARCH_DIR
        // the output contains some paths that end with lib64, maybe include them too?
        // TODO: what is the best possible order of things?
        // TODO: some of these are suspect and should only be added on some systems. audit needed.

        try self.add_include_dir("/usr/local/include");
        try self.add_lib_dir_fmt("/usr/local/lib{d}", .{qual});
        try self.add_lib_dir("/usr/local/lib");

        try self.add_include_dir_fmt("/usr/include/{s}", .{triple});
        try self.add_lib_dir_fmt("/usr/lib/{s}", .{triple});

        try self.add_include_dir("/usr/include");
        try self.add_lib_dir_fmt("/lib{d}", .{qual});
        try self.add_lib_dir("/lib");
        try self.add_lib_dir_fmt("/usr/lib{d}", .{qual});
        try self.add_lib_dir("/usr/lib");

        // example: on a 64-bit debian-based linux distro, with zlib installed from apt:
        // zlib.h is in /usr/include (added above)
        // libz.so.1 is in /lib/x86_64-linux-gnu (added here)
        try self.add_lib_dir_fmt("/lib/{s}", .{triple});

        // Distros like guix don't use FHS, so they rely on environment
        // variables to search for headers and libraries.
        // We use os.getenv here since this part won't be executed on
        // windows, to get rid of unnecessary error handling.
        if (std.posix.getenv("C_INCLUDE_PATH")) |c_include_path| {
            var it = mem.tokenize_scalar(u8, c_include_path, ':');
            while (it.next()) |dir| {
                try self.add_include_dir(dir);
            }
        }

        if (std.posix.getenv("CPLUS_INCLUDE_PATH")) |cplus_include_path| {
            var it = mem.tokenize_scalar(u8, cplus_include_path, ':');
            while (it.next()) |dir| {
                try self.add_include_dir(dir);
            }
        }

        if (std.posix.getenv("LIBRARY_PATH")) |library_path| {
            var it = mem.tokenize_scalar(u8, library_path, ':');
            while (it.next()) |dir| {
                try self.add_lib_dir(dir);
            }
        }
    }

    return self;
}

pub fn add_include_dir(self: *NativePaths, s: []const u8) !void {
    return self.include_dirs.append(self.arena, s);
}

pub fn add_include_dir_fmt(self: *NativePaths, comptime fmt: []const u8, args: anytype) !void {
    const item = try std.fmt.alloc_print(self.arena, fmt, args);
    try self.include_dirs.append(self.arena, item);
}

pub fn add_lib_dir(self: *NativePaths, s: []const u8) !void {
    try self.lib_dirs.append(self.arena, s);
}

pub fn add_lib_dir_fmt(self: *NativePaths, comptime fmt: []const u8, args: anytype) !void {
    const item = try std.fmt.alloc_print(self.arena, fmt, args);
    try self.lib_dirs.append(self.arena, item);
}

pub fn add_warning(self: *NativePaths, s: []const u8) !void {
    return self.warnings.append(self.arena, s);
}

pub fn add_framework_dir(self: *NativePaths, s: []const u8) !void {
    return self.framework_dirs.append(self.arena, s);
}

pub fn add_framework_dir_fmt(self: *NativePaths, comptime fmt: []const u8, args: anytype) !void {
    const item = try std.fmt.alloc_print(self.arena, fmt, args);
    try self.framework_dirs.append(self.arena, item);
}

pub fn add_warning_fmt(self: *NativePaths, comptime fmt: []const u8, args: anytype) !void {
    const item = try std.fmt.alloc_print(self.arena, fmt, args);
    try self.warnings.append(self.arena, item);
}

pub fn add_rpath(self: *NativePaths, s: []const u8) !void {
    try self.rpaths.append(self.arena, s);
}
