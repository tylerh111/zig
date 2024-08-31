const std = @import("std");
const expect = std.testing.expect;

test "@src" {
    try do_the_test();
}

fn do_the_test() !void {
    const src = @src();

    try expect(src.line == 9);
    try expect(src.column == 17);
    try expect(std.mem.ends_with(u8, src.fn_name, "do_the_test"));
    try expect(std.mem.ends_with(u8, src.file, "test_src_builtin.zig"));
}

// test
