export fn entry() void {
    const x: f32 = @floatfromint(1.1);
    _ = x;
}

// error
// backend=stage2
// target=native
//
// :2:34: error: expected integer type, found 'comptime_float'
