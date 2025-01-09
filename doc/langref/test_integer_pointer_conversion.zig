const expect = @import("std").testing.expect;

test "@intfromptr and @ptrfromint" {
    const ptr: *i32 = @ptrfromint(0xdeadbee0);
    const addr = @intfromptr(ptr);
    try expect(@TypeOf(addr) == usize);
    try expect(addr == 0xdeadbee0);
}

// test
