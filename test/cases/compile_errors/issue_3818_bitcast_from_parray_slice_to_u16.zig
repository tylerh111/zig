export fn foo1() void {
    var bytes = [_]u8{ 1, 2 };
    const word: u16 = @bitcast(bytes[0..]);
    _ = word;
}
export fn foo2() void {
    const bytes: []const u8 = &[_]u8{ 1, 2 };
    const word: u16 = @bitcast(bytes);
    _ = word;
}

// error
// backend=stage2
// target=native
//
// :3:37: error: cannot @bitcast from '*[2]u8'
// :3:37: note: use @intfromptr to cast to 'u16'
// :8:32: error: cannot @bitcast from '[]const u8'
// :8:32: note: use @intfromptr to cast to 'u16'
