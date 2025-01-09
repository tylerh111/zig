const std = @import("std");
const native_arch = @import("builtin").target.cpu.arch;
const expect = std.testing.expect;

test "@wasmmemorygrow" {
    if (native_arch != .wasm32) return error.SkipZigTest;

    const prev = @wasmmemorysize(0);
    try expect(prev == @wasmmemorygrow(0, 1));
    try expect(prev + 1 == @wasmmemorysize(0));
}

// test
