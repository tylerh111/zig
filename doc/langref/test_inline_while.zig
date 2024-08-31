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
        sum += type_name_length(T);
    }
    try expect(sum == 9);
}

fn type_name_length(comptime T: type) usize {
    return @type_name(T).len;
}

// test
