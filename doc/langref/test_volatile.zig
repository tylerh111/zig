const expect = @import("std").testing.expect;

test "volatile" {
    const mmio_ptr: *volatile u8 = @ptrfromint(0x12345678);
    try expect(@TypeOf(mmio_ptr) == *volatile u8);
}

// test
