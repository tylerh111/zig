export fn entry() void {
    const E = enum(u32) { a, b };
    const y: E = @bitcast(@as(u32, 3));
    _ = y;
}

// error
// backend=stage2
// target=native
//
// :3:18: error: cannot @bitcast to 'tmp.entry.E'
// :3:18: note: use @enumfromint to cast from 'u32'
