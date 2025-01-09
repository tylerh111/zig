export fn foo() void {
    var a: u32 = 2;
    _ = &a;
    _ = @as(comptime_int, @intcast(a));
}
export fn bar() void {
    var a: u32 = 2;
    _ = &a;
    _ = @as(u32, @floatfromint(a));
}
export fn baz() void {
    var a: u32 = 2;
    _ = &a;
    _ = @as(u32, @intfromfloat(a));
}
export fn qux() void {
    var a: f32 = 2;
    _ = &a;
    _ = @as(u32, @intcast(a));
}

// error
// backend=stage2
// target=native
//
// :4:36: error: unable to cast runtime value to 'comptime_int'
// :9:18: error: expected float type, found 'u32'
// :14:32: error: expected float type, found 'u32'
// :19:27: error: expected integer or vector, found 'f32'
