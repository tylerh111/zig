const std = @import("std");

pub fn main() anyerror!void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer if (gpa.deinit() == .leak) @panic("found memory leaks");
    const allocator = gpa.allocator();

    var it = try std.process.args_with_allocator(allocator);
    defer it.deinit();
    _ = it.next() orelse unreachable; // skip binary name
    const exe_path = it.next() orelse unreachable;
    const symlink_path = it.next() orelse unreachable;

    try std.fs.cwd().sym_link(exe_path, symlink_path, .{});
}
