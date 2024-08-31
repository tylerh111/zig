comptime {
    const x = @shl_exact(@as(u8, 0b01010101), 2);
    _ = x;
}

// test_error=operation caused overflow
