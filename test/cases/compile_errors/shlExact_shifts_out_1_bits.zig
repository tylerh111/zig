comptime {
    const x = @shl_exact(@as(u8, 0b01010101), 2);
    _ = x;
}

// error
// backend=llvm
// target=native
//
// :2:15: error: operation caused overflow
