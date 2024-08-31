export fn foo1() void {
    var bytes = [_]u8{ 1, 2 };
    const word: u16 = @bit_cast(bytes[0..]);
    _ = word;
}
export fn foo2() void {
    const bytes: []const u8 = &[_]u8{ 1, 2 };
    const word: u16 = @bit_cast(bytes);
    _ = word;
}

// error
// backend=stage2
// target=native
//
// :3:37: error: cannot @bit_cast from '*[2]u8'
// :3:37: note: use @int_from_ptr to cast to 'u16'
// :8:32: error: cannot @bit_cast from '[]const u8'
// :8:32: note: use @int_from_ptr to cast to 'u16'
