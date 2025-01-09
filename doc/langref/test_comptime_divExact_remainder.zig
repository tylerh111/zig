comptime {
    const a: u32 = 10;
    const b: u32 = 3;
    const c = @divexact(a, b);
    _ = c;
}

// test_error=exact division produced remainder
