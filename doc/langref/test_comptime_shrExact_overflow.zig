comptime {
    const x = @shrexact(@as(u8, 0b10101010), 2);
    _ = x;
}

// test_error=exact shift shifted out 1 bits
