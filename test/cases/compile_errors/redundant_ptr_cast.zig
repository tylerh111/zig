const p: *anyopaque = undefined;
export fn a() void {
    _ = @ptr_cast(@ptr_cast(p));
}
export fn b() void {
    const ptr1: *u32 = @align_cast(@ptr_cast(@align_cast(p)));
    _ = ptr1;
}
export fn c() void {
    _ = @constCast(@align_cast(@ptr_cast(@constCast(@volatileCast(p)))));
}

// error
// backend=stage2
// target=native
//
// :3:18: error: redundant @ptr_cast
// :6:44: error: redundant @align_cast
// :10:40: error: redundant @constCast
