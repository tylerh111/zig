const expect = @import("std").testing.expect;

test "inline for loop" {
    const nums = [_]i32{ 2, 4, 6 };
    var sum: usize = 0;
    inline for (nums) |i| {
        const T = switch (i) {
            2 => f32,
            4 => i8,
            6 => bool,
            else => unreachable,
        };
        sum += type_name_length(T);
    }
    try expect(sum == 9);
}

fn type_name_length(comptime T: type) usize {
    return @type_name(T).len;
}

// test
