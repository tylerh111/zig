const expect = @import("std").testing.expect;

test "inline while loop" {
    comptime var i = 0;
    var sum: usize = 0;
    inline while (i < 3) : (i += 1) {
        const T = switch (i) {
            0 => f32,
            1 => i8,
            2 => bool,
            else => unreachable,
        };
        sum += typenameLength(T);
    }
    try expect(sum == 9);
}

fn typenameLength(comptime T: type) usize {
    return @typename(T).len;
}

// test
