const std = @import("std");

pub fn main() void {
    const number = get_number_or_fail() catch unreachable;
    std.debug.print("value: {}\n", .{number});
}

fn get_number_or_fail() !i32 {
    return error.UnableToReturnNumber;
}

// exe=fail
