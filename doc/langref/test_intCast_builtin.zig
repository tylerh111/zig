test "integer cast panic" {
    var a: u16 = 0xabcd; // runtime-known
    _ = &a;
    const b: u8 = @int_cast(a);
    _ = b;
}

// test_error=cast truncated bits
