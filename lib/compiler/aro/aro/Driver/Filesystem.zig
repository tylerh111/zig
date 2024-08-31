const std = @import("std");
const mem = std.mem;
const builtin = @import("builtin");
const is_windows = builtin.os.tag == .windows;

fn read_file_fake(entries: []const Filesystem.Entry, path: []const u8, buf: []u8) ?[]const u8 {
    @setCold(true);
    for (entries) |entry| {
        if (mem.eql(u8, entry.path, path)) {
            const len = @min(entry.contents.len, buf.len);
            @memcpy(buf[0..len], entry.contents[0..len]);
            return buf[0..len];
        }
    }
    return null;
}

fn find_program_by_name_fake(entries: []const Filesystem.Entry, name: []const u8, path: ?[]const u8, buf: []u8) ?[]const u8 {
    @setCold(true);
    if (mem.index_of_scalar(u8, name, '/') != null) {
        @memcpy(buf[0..name.len], name);
        return buf[0..name.len];
    }
    const path_env = path orelse return null;
    var fib = std.heap.FixedBufferAllocator.init(buf);

    var it = mem.tokenize_scalar(u8, path_env, std.fs.path.delimiter);
    while (it.next()) |path_dir| {
        defer fib.reset();
        const full_path = std.fs.path.join(fib.allocator(), &.{ path_dir, name }) catch continue;
        if (can_execute_fake(entries, full_path)) return full_path;
    }

    return null;
}

fn can_execute_fake(entries: []const Filesystem.Entry, path: []const u8) bool {
    @setCold(true);
    for (entries) |entry| {
        if (mem.eql(u8, entry.path, path)) {
            return entry.executable;
        }
    }
    return false;
}

fn exists_fake(entries: []const Filesystem.Entry, path: []const u8) bool {
    @setCold(true);
    var buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    var fib = std.heap.FixedBufferAllocator.init(&buf);
    const resolved = std.fs.path.resolve_posix(fib.allocator(), &.{path}) catch return false;
    for (entries) |entry| {
        if (mem.eql(u8, entry.path, resolved)) return true;
    }
    return false;
}

fn can_execute_posix(path: []const u8) bool {
    std.os.access(path, std.os.X_OK) catch return false;
    // Todo: ensure path is not a directory
    return true;
}

/// TODO
fn can_execute_windows(path: []const u8) bool {
    _ = path;
    return true;
}

/// TODO
fn find_program_by_name_windows(allocator: std.mem.Allocator, name: []const u8, path: ?[]const u8, buf: []u8) ?[]const u8 {
    _ = path;
    _ = buf;
    _ = name;
    _ = allocator;
    return null;
}

/// TODO: does WASI need special handling?
fn find_program_by_name_posix(name: []const u8, path: ?[]const u8, buf: []u8) ?[]const u8 {
    if (mem.index_of_scalar(u8, name, '/') != null) {
        @memcpy(buf[0..name.len], name);
        return buf[0..name.len];
    }
    const path_env = path orelse return null;
    var fib = std.heap.FixedBufferAllocator.init(buf);

    var it = mem.tokenize_scalar(u8, path_env, std.fs.path.delimiter);
    while (it.next()) |path_dir| {
        defer fib.reset();
        const full_path = std.fs.path.join(fib.allocator(), &.{ path_dir, name }) catch continue;
        if (can_execute_posix(full_path)) return full_path;
    }

    return null;
}

pub const Filesystem = union(enum) {
    real: void,
    fake: []const Entry,

    const Entry = struct {
        path: []const u8,
        contents: []const u8 = "",
        executable: bool = false,
    };

    const FakeDir = struct {
        entries: []const Entry,
        path: []const u8,

        fn iterate(self: FakeDir) FakeDir.Iterator {
            return .{
                .entries = self.entries,
                .base = self.path,
            };
        }

        const Iterator = struct {
            entries: []const Entry,
            base: []const u8,
            i: usize = 0,

            fn next(self: *@This()) !?std.fs.Dir.Entry {
                while (self.i < self.entries.len) {
                    const entry = self.entries[self.i];
                    self.i += 1;
                    if (entry.path.len == self.base.len) continue;
                    if (std.mem.starts_with(u8, entry.path, self.base)) {
                        const remaining = entry.path[self.base.len + 1 ..];
                        if (std.mem.index_of_scalar(u8, remaining, std.fs.path.sep) != null) continue;
                        const extension = std.fs.path.extension(remaining);
                        const kind: std.fs.Dir.Entry.Kind = if (extension.len == 0) .directory else .file;
                        return .{ .name = remaining, .kind = kind };
                    }
                }
                return null;
            }
        };
    };

    const Dir = union(enum) {
        dir: std.fs.Dir,
        fake: FakeDir,

        pub fn iterate(self: Dir) Iterator {
            return switch (self) {
                .dir => |dir| .{ .iterator = dir.iterate() },
                .fake => |fake| .{ .fake = fake.iterate() },
            };
        }

        pub fn close(self: *Dir) void {
            switch (self.*) {
                .dir => |*d| d.close(),
                .fake => {},
            }
        }
    };

    const Iterator = union(enum) {
        iterator: std.fs.Dir.Iterator,
        fake: FakeDir.Iterator,

        pub fn next(self: *Iterator) std.fs.Dir.Iterator.Error!?std.fs.Dir.Entry {
            return switch (self.*) {
                .iterator => |*it| it.next(),
                .fake => |*it| it.next(),
            };
        }
    };

    pub fn exists(fs: Filesystem, path: []const u8) bool {
        switch (fs) {
            .real => {
                std.os.access(path, std.os.F_OK) catch return false;
                return true;
            },
            .fake => |paths| return exists_fake(paths, path),
        }
    }

    pub fn joined_exists(fs: Filesystem, parts: []const []const u8) bool {
        var buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
        var fib = std.heap.FixedBufferAllocator.init(&buf);
        const joined = std.fs.path.join(fib.allocator(), parts) catch return false;
        return fs.exists(joined);
    }

    pub fn can_execute(fs: Filesystem, path: []const u8) bool {
        return switch (fs) {
            .real => if (is_windows) can_execute_windows(path) else can_execute_posix(path),
            .fake => |entries| can_execute_fake(entries, path),
        };
    }

    /// Search for an executable named `name` using platform-specific logic
    /// If it's found, write the full path to `buf` and return a slice of it
    /// Otherwise retun null
    pub fn find_program_by_name(fs: Filesystem, allocator: std.mem.Allocator, name: []const u8, path: ?[]const u8, buf: []u8) ?[]const u8 {
        std.debug.assert(name.len > 0);
        return switch (fs) {
            .real => if (is_windows) find_program_by_name_windows(allocator, name, path, buf) else find_program_by_name_posix(name, path, buf),
            .fake => |entries| find_program_by_name_fake(entries, name, path, buf),
        };
    }

    /// Read the file at `path` into `buf`.
    /// Returns null if any errors are encountered
    /// Otherwise returns a slice of `buf`. If the file is larger than `buf` partial contents are returned
    pub fn read_file(fs: Filesystem, path: []const u8, buf: []u8) ?[]const u8 {
        return switch (fs) {
            .real => {
                const file = std.fs.cwd().open_file(path, .{}) catch return null;
                defer file.close();

                const bytes_read = file.read_all(buf) catch return null;
                return buf[0..bytes_read];
            },
            .fake => |entries| read_file_fake(entries, path, buf),
        };
    }

    pub fn open_dir(fs: Filesystem, dir_name: []const u8) std.fs.Dir.OpenError!Dir {
        return switch (fs) {
            .real => .{ .dir = try std.fs.cwd().open_dir(dir_name, .{ .access_sub_paths = false, .iterate = true }) },
            .fake => |entries| .{ .fake = .{ .entries = entries, .path = dir_name } },
        };
    }
};

test "Fake filesystem" {
    const fs: Filesystem = .{ .fake = &.{
        .{ .path = "/usr/bin" },
    } };
    try std.testing.expect(fs.exists("/usr/bin"));
    try std.testing.expect(fs.exists("/usr/bin/foo/.."));
    try std.testing.expect(!fs.exists("/usr/bin/bar"));
}
