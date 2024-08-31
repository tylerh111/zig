export fn foo() void {
    var a: f32 = 2;
    _ = &a;
    _ = @as(comptime_int, @int_from_float(a));
}
export fn bar() void {
    var a: u32 = 2;
    _ = &a;
    _ = @as(comptime_float, @float_from_int(a));
}

// error
// backend=stage2
// target=native
//
// :4:41: error: unable to resolve comptime value
// :4:41: note: value being casted to 'comptime_int' must be comptime-known
// :9:43: error: unable to resolve comptime value
// :9:43: note: value being casted to 'comptime_float' must be comptime-known
