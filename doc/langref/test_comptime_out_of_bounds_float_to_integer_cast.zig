comptime {
    const float: f32 = 4294967296;
    const int: i32 = @intfromfloat(float);
    _ = int;
}

// test_error=float value '4294967296' cannot be stored in integer type 'i32'
