const std = @import("std");

pub fn main() !void {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const stdout = std.io.get_std_out().writer();
    var args = try std.process.args_alloc(arena);
    for (args[1..], 1..) |arg, i| {
        try stdout.write_all(arg);
        if (i != args.len - 1) try stdout.write_byte('\x00');
    }
}
