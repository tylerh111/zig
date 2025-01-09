comptime {
    const ptr: *align(1) i32 = @ptrfromint(0x1);
    const aligned: *align(4) i32 = @aligncast(ptr);
    _ = aligned;
}

// test_error=pointer address 0x1 is not aligned to 4 bytes
