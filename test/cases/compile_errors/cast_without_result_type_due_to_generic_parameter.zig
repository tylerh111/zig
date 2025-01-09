export fn a() void {
    bar(@ptrfromint(123));
}
export fn b() void {
    bar(@ptrcast(@aligncast(@as(*u8, undefined))));
}
export fn c() void {
    bar(@intcast(@as(u64, 123)));
}
export fn d() void {
    bar(@floatfromint(123));
}
export fn f() void {
    bar(.{
        .x = @intcast(123),
    });
}

fn bar(_: anytype) void {}

// error
// backend=stage2
// target=native
//
// :2:9: error: @ptrfromint must have a known result type
// :2:8: note: result type is unknown due to anytype parameter
// :2:9: note: use @as to provide explicit result type
// :5:9: error: @ptrcast must have a known result type
// :5:8: note: result type is unknown due to anytype parameter
// :5:9: note: use @as to provide explicit result type
// :8:9: error: @intcast must have a known result type
// :8:8: note: result type is unknown due to anytype parameter
// :8:9: note: use @as to provide explicit result type
// :11:9: error: @floatfromint must have a known result type
// :11:8: note: result type is unknown due to anytype parameter
// :11:9: note: use @as to provide explicit result type
// :15:14: error: @intcast must have a known result type
// :14:8: note: result type is unknown due to anytype parameter
// :15:14: note: use @as to provide explicit result type
