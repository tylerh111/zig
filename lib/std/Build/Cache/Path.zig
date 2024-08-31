root_dir: Cache.Directory,
/// The path, relative to the root dir, that this `Path` represents.
/// Empty string means the root_dir is the path.
sub_path: []const u8 = "",

pub fn clone(p: Path, arena: Allocator) Allocator.Error!Path {
    return .{
        .root_dir = try p.root_dir.clone(arena),
        .sub_path = try arena.dupe(u8, p.sub_path),
    };
}

pub fn cwd() Path {
    return .{ .root_dir = Cache.Directory.cwd() };
}

pub fn join(p: Path, arena: Allocator, sub_path: []const u8) Allocator.Error!Path {
    if (sub_path.len == 0) return p;
    const parts: []const []const u8 =
        if (p.sub_path.len == 0) &.{sub_path} else &.{ p.sub_path, sub_path };
    return .{
        .root_dir = p.root_dir,
        .sub_path = try fs.path.join(arena, parts),
    };
}

pub fn resolve_posix(p: Path, arena: Allocator, sub_path: []const u8) Allocator.Error!Path {
    if (sub_path.len == 0) return p;
    return .{
        .root_dir = p.root_dir,
        .sub_path = try fs.path.resolve_posix(arena, &.{ p.sub_path, sub_path }),
    };
}

pub fn join_string(p: Path, allocator: Allocator, sub_path: []const u8) Allocator.Error![]u8 {
    const parts: []const []const u8 =
        if (p.sub_path.len == 0) &.{sub_path} else &.{ p.sub_path, sub_path };
    return p.root_dir.join(allocator, parts);
}

pub fn join_string_z(p: Path, allocator: Allocator, sub_path: []const u8) Allocator.Error![:0]u8 {
    const parts: []const []const u8 =
        if (p.sub_path.len == 0) &.{sub_path} else &.{ p.sub_path, sub_path };
    return p.root_dir.join_z(allocator, parts);
}

pub fn open_file(
    p: Path,
    sub_path: []const u8,
    flags: fs.File.OpenFlags,
) !fs.File {
    var buf: [fs.MAX_PATH_BYTES]u8 = undefined;
    const joined_path = if (p.sub_path.len == 0) sub_path else p: {
        break :p std.fmt.buf_print(&buf, "{s}" ++ fs.path.sep_str ++ "{s}", .{
            p.sub_path, sub_path,
        }) catch return error.NameTooLong;
    };
    return p.root_dir.handle.open_file(joined_path, flags);
}

pub fn make_open_path(p: Path, sub_path: []const u8, opts: fs.OpenDirOptions) !fs.Dir {
    var buf: [fs.MAX_PATH_BYTES]u8 = undefined;
    const joined_path = if (p.sub_path.len == 0) sub_path else p: {
        break :p std.fmt.buf_print(&buf, "{s}" ++ fs.path.sep_str ++ "{s}", .{
            p.sub_path, sub_path,
        }) catch return error.NameTooLong;
    };
    return p.root_dir.handle.make_open_path(joined_path, opts);
}

pub fn stat_file(p: Path, sub_path: []const u8) !fs.Dir.Stat {
    var buf: [fs.MAX_PATH_BYTES]u8 = undefined;
    const joined_path = if (p.sub_path.len == 0) sub_path else p: {
        break :p std.fmt.buf_print(&buf, "{s}" ++ fs.path.sep_str ++ "{s}", .{
            p.sub_path, sub_path,
        }) catch return error.NameTooLong;
    };
    return p.root_dir.handle.stat_file(joined_path);
}

pub fn atomic_file(
    p: Path,
    sub_path: []const u8,
    options: fs.Dir.AtomicFileOptions,
    buf: *[fs.MAX_PATH_BYTES]u8,
) !fs.AtomicFile {
    const joined_path = if (p.sub_path.len == 0) sub_path else p: {
        break :p std.fmt.buf_print(buf, "{s}" ++ fs.path.sep_str ++ "{s}", .{
            p.sub_path, sub_path,
        }) catch return error.NameTooLong;
    };
    return p.root_dir.handle.atomic_file(joined_path, options);
}

pub fn access(p: Path, sub_path: []const u8, flags: fs.File.OpenFlags) !void {
    var buf: [fs.MAX_PATH_BYTES]u8 = undefined;
    const joined_path = if (p.sub_path.len == 0) sub_path else p: {
        break :p std.fmt.buf_print(&buf, "{s}" ++ fs.path.sep_str ++ "{s}", .{
            p.sub_path, sub_path,
        }) catch return error.NameTooLong;
    };
    return p.root_dir.handle.access(joined_path, flags);
}

pub fn make_path(p: Path, sub_path: []const u8) !void {
    var buf: [fs.MAX_PATH_BYTES]u8 = undefined;
    const joined_path = if (p.sub_path.len == 0) sub_path else p: {
        break :p std.fmt.buf_print(&buf, "{s}" ++ fs.path.sep_str ++ "{s}", .{
            p.sub_path, sub_path,
        }) catch return error.NameTooLong;
    };
    return p.root_dir.handle.make_path(joined_path);
}

pub fn format(
    self: Path,
    comptime fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    if (fmt_string.len == 1) {
        // Quote-escape the string.
        const string_escape = std.zig.string_escape;
        const f = switch (fmt_string[0]) {
            'q' => "",
            '\'' => '\'',
            else => @compile_error("unsupported format string: " ++ fmt_string),
        };
        if (self.root_dir.path) |p| {
            try string_escape(p, f, options, writer);
            if (self.sub_path.len > 0) try string_escape(fs.path.sep_str, f, options, writer);
        }
        if (self.sub_path.len > 0) {
            try string_escape(self.sub_path, f, options, writer);
        }
        return;
    }
    if (fmt_string.len > 0)
        std.fmt.invalid_fmt_error(fmt_string, self);
    if (self.root_dir.path) |p| {
        try writer.write_all(p);
        try writer.write_all(fs.path.sep_str);
    }
    if (self.sub_path.len > 0) {
        try writer.write_all(self.sub_path);
        try writer.write_all(fs.path.sep_str);
    }
}

const Path = @This();
const std = @import("../../std.zig");
const fs = std.fs;
const Allocator = std.mem.Allocator;
const Cache = std.Build.Cache;
