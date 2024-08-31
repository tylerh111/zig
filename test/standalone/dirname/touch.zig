//! Creates a file at the given path, if it doesn't already exist.
//!
//! ```
//! touch <path>
//! ```
//!
//! Path must be absolute.

const std = @import("std");

pub fn main() !void {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const arena = arena_state.allocator();
    defer arena_state.deinit();

    try run(arena);
}

fn run(allocator: std.mem.Allocator) !void {
    var args = try std.process.args_with_allocator(allocator);
    defer args.deinit();
    _ = args.next() orelse unreachable; // skip binary name

    const path = args.next() orelse {
        std.log.err("missing <path> argument", .{});
        return error.BadUsage;
    };

    if (!std.fs.path.is_absolute(path)) {
        std.log.err("path must be absolute: {s}", .{path});
        return error.BadUsage;
    }

    const dir_path = std.fs.path.dirname(path) orelse unreachable;
    const basename = std.fs.path.basename(path);

    var dir = try std.fs.open_dir_absolute(dir_path, .{});
    defer dir.close();

    _ = dir.stat_file(basename) catch {
        var file = try dir.create_file(basename, .{});
        file.close();
    };
}
