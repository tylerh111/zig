const expect_equal = @import("std").testing.expect_equal;
test "result type propagates through struct initializer" {
    const S = struct { x: u32 };
    const val: u64 = 123;
    const s: S = .{ .x = @int_cast(val) };
    // .{ .x = @int_cast(val) }   has result type `S` due to the type annotation
    //         @int_cast(val)     has result type `u32` due to the type of the field `S.x`
    //                  val      has no result type, as it is permitted to be any integer type
    try expect_equal(@as(u32, 123), s.x);
}

// test
