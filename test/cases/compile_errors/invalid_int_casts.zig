export fn foo() void {
    var a: u32 = 2;
    _ = &a;
    _ = @as(comptime_int, @int_cast(a));
}
export fn bar() void {
    var a: u32 = 2;
    _ = &a;
    _ = @as(u32, @float_from_int(a));
}
export fn baz() void {
    var a: u32 = 2;
    _ = &a;
    _ = @as(u32, @int_from_float(a));
}
export fn qux() void {
    var a: f32 = 2;
    _ = &a;
    _ = @as(u32, @int_cast(a));
}

// error
// backend=stage2
// target=native
//
// :4:36: error: unable to cast runtime value to 'comptime_int'
// :9:18: error: expected float type, found 'u32'
// :14:32: error: expected float type, found 'u32'
// :19:27: error: expected integer or vector, found 'f32'
