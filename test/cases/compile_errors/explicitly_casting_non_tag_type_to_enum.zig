const Small = enum(u2) {
    One,
    Two,
    Three,
    Four,
};

export fn entry() void {
    var y = @as(f32, 3);
    const x: Small = @enumfromint((&y).*);
    _ = x;
}

// error
// backend=stage2
// target=native
//
// :10:39: error: expected integer type, found 'f32'
