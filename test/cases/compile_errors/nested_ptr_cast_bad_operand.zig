const p: ?*const u8 = null;
export fn a() void {
    _ = @as(*const u32, @ptr_cast(@align_cast(p)));
}
export fn b() void {
    _ = @constCast(@volatileCast(123));
}
export fn c() void {
    const x: ?*f32 = @constCast(@ptr_cast(@addrSpaceCast(@volatileCast(p))));
    _ = x;
}

// error
// backend=stage2
// target=native
//
// :3:45: error: null pointer casted to type '*const u32'
// :6:34: error: expected pointer type, found 'comptime_int'
// :9:22: error: @ptr_cast increases pointer alignment
// :9:71: note: '?*const u8' has alignment '1'
// :9:22: note: '?*f32' has alignment '4'
// :9:22: note: use @align_cast to assert pointer alignment
