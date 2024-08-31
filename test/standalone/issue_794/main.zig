const c = @c_import(@cInclude("foo.h"));
const std = @import("std");
const testing = std.testing;

test "c import" {
    try comptime testing.expect(c.NUMBER == 1234);
}
