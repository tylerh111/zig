const std = @import("std");
const math = std.math;
const testing = std.testing;

test "fn reflection" {
    try testing.expect(@typeinfo(@TypeOf(testing.expect)).Fn.params[0].type.? == bool);
    try testing.expect(@typeinfo(@TypeOf(testing.tmpDir)).Fn.return_type.? == testing.TmpDir);

    try testing.expect(@typeinfo(@TypeOf(math.Log2Int)).Fn.is_generic);
}

// test
