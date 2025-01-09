export fn entry() void {
    const x: i32 = 1234;
    const y: *i32 = @ptrcast(&x);
    _ = y;
}

// error
// backend=stage2
// target=native
//
// :3:21: error: @ptrcast discards const qualifier
// :3:21: note: use @constcast to discard const qualifier
