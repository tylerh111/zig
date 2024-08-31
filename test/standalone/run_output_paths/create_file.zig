const std = @import("std");

pub fn main() !void {
    var args = try std.process.args_with_allocator(std.heap.page_allocator);
    _ = args.skip();
    const dir_name = args.next().?;
    const dir = try std.fs.cwd().open_dir(if (std.mem.starts_with(u8, dir_name, "--dir="))
        dir_name["--dir=".len..]
    else
        dir_name, .{});
    const file_name = args.next().?;
    const file = try dir.create_file(file_name, .{});
    try file.writer().print(
        \\{s}
        \\{s}
        \\Hello, world!
        \\
    , .{ dir_name, file_name });
}
