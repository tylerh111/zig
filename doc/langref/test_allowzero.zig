const std = @import("std");
const expect = std.testing.expect;

test "allowzero" {
    var zero: usize = 0; // var to make to runtime-known
    _ = &zero; // suppress 'var is never mutated' error
    const ptr: *allowzero i32 = @ptrfromint(zero);
    try expect(@intfromptr(ptr) == 0);
}

// test
