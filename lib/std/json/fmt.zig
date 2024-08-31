const std = @import("std");

const stringify = @import("stringify.zig").stringify;
const StringifyOptions = @import("stringify.zig").StringifyOptions;

/// Returns a formatter that formats the given value using stringify.
pub fn fmt(value: anytype, options: StringifyOptions) Formatter(@TypeOf(value)) {
    return Formatter(@TypeOf(value)){ .value = value, .options = options };
}

/// Formats the given value using stringify.
pub fn Formatter(comptime T: type) type {
    return struct {
        value: T,
        options: StringifyOptions,

        pub fn format(
            self: @This(),
            comptime fmt_spec: []const u8,
            options: std.fmt.FormatOptions,
            writer: anytype,
        ) !void {
            _ = fmt_spec;
            _ = options;
            try stringify(self.value, self.options, writer);
        }
    };
}

test fmt {
    const expect_fmt = std.testing.expect_fmt;
    try expect_fmt("123", "{}", .{fmt(@as(u32, 123), .{})});
    try expect_fmt(
        \\{"num":927,"msg":"hello","sub":{"mybool":true}}
    , "{}", .{fmt(struct {
        num: u32,
        msg: []const u8,
        sub: struct {
            mybool: bool,
        },
    }{
        .num = 927,
        .msg = "hello",
        .sub = .{ .mybool = true },
    }, .{})});
}
