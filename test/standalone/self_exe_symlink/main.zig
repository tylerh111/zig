const std = @import("std");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer std.debug.assert(gpa.deinit() == .ok);
    const allocator = gpa.allocator();

    const self_path = try std.fs.self_exe_path_alloc(allocator);
    defer allocator.free(self_path);

    var self_exe = try std.fs.open_self_exe(.{});
    defer self_exe.close();
    var buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    const self_exe_path = try std.os.get_fd_path(self_exe.handle, &buf);

    try std.testing.expect_equal_strings(self_exe_path, self_path);
}
