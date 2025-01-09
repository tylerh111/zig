const expect = @import("std").testing.expect;

test "comptime @ptrfromint" {
    comptime {
        // Zig is able to do this at compile-time, as long as
        // ptr is never dereferenced.
        const ptr: *i32 = @ptrfromint(0xdeadbee0);
        const addr = @intfromptr(ptr);
        try expect(@TypeOf(addr) == usize);
        try expect(addr == 0xdeadbee0);
    }
}

// test
