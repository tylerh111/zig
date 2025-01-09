const p: *anyopaque = undefined;
export fn a() void {
    _ = @ptrcast(@ptrcast(p));
}
export fn b() void {
    const ptr1: *u32 = @aligncast(@ptrcast(@aligncast(p)));
    _ = ptr1;
}
export fn c() void {
    _ = @constcast(@aligncast(@ptrcast(@constcast(@volatilecast(p)))));
}

// error
// backend=stage2
// target=native
//
// :3:18: error: redundant @ptrcast
// :6:44: error: redundant @aligncast
// :10:40: error: redundant @constcast
