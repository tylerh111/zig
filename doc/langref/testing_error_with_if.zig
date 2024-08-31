const print = @import("std").debug.print;

pub fn main() void {
    const result = get_number_or_fail();

    if (result) |number| {
        print("got number: {}\n", .{number});
    } else |err| {
        print("got error: {s}\n", .{@errorName(err)});
    }
}

fn get_number_or_fail() !i32 {
    return error.UnableToReturnNumber;
}

// exe=succeed
