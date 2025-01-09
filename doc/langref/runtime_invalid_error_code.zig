const std = @import("std");

pub fn main() void {
    const err = error.AnError;
    var number = @intfromerror(err) + 500;
    _ = &number;
    const invalid_err = @errorfromint(number);
    std.debug.print("value: {}\n", .{invalid_err});
}

// exe=fail
