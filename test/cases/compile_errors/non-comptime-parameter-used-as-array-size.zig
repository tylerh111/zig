export fn entry() void {
    const llamas1 = make_llamas(5);
    const llamas2 = make_llamas(5);
    _ = llamas1;
    _ = llamas2;
}

fn make_llamas(count: usize) [count]u8 {}

// error
// target=native
//
// :8:30: error: unable to resolve comptime value
// :8:30: note: array length must be comptime-known
