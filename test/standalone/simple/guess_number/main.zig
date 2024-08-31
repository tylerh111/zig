const builtin = @import("builtin");
const std = @import("std");
const io = std.io;
const fmt = std.fmt;

pub fn main() !void {
    const stdout = io.get_std_out().writer();
    const stdin = io.get_std_in();

    try stdout.print("Welcome to the Guess Number Game in Zig.\n", .{});

    const answer = std.crypto.random.int_range_less_than(u8, 0, 100) + 1;

    while (true) {
        try stdout.print("\nGuess a number between 1 and 100: ", .{});
        var line_buf: [20]u8 = undefined;

        const amt = try stdin.read(&line_buf);
        if (amt == line_buf.len) {
            try stdout.print("Input too long.\n", .{});
            continue;
        }
        const line = std.mem.trim_right(u8, line_buf[0..amt], "\r\n");

        const guess = fmt.parse_unsigned(u8, line, 10) catch {
            try stdout.print("Invalid number.\n", .{});
            continue;
        };
        if (guess > answer) {
            try stdout.print("Guess lower.\n", .{});
        } else if (guess < answer) {
            try stdout.print("Guess higher.\n", .{});
        } else {
            try stdout.print("You win!\n", .{});
            return;
        }
    }
}
