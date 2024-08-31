const std = @import("std");
const mem = std.mem;
const testing = std.testing;

const ObjectMap = @import("dynamic.zig").ObjectMap;
const Value = @import("dynamic.zig").Value;

const StringifyOptions = @import("stringify.zig").StringifyOptions;
const stringify = @import("stringify.zig").stringify;
const stringify_max_depth = @import("stringify.zig").stringify_max_depth;
const stringify_arbitrary_depth = @import("stringify.zig").stringify_arbitrary_depth;
const stringify_alloc = @import("stringify.zig").stringify_alloc;
const write_stream = @import("stringify.zig").write_stream;
const write_stream_max_depth = @import("stringify.zig").write_stream_max_depth;
const write_stream_arbitrary_depth = @import("stringify.zig").write_stream_arbitrary_depth;

test "json write stream" {
    var out_buf: [1024]u8 = undefined;
    var slice_stream = std.io.fixed_buffer_stream(&out_buf);
    const out = slice_stream.writer();

    {
        var w = write_stream(out, .{ .whitespace = .indent_2 });
        try test_basic_write_stream(&w, &slice_stream);
    }

    {
        var w = write_stream_max_depth(out, .{ .whitespace = .indent_2 }, 8);
        try test_basic_write_stream(&w, &slice_stream);
    }

    {
        var w = write_stream_max_depth(out, .{ .whitespace = .indent_2 }, null);
        try test_basic_write_stream(&w, &slice_stream);
    }

    {
        var w = write_stream_arbitrary_depth(testing.allocator, out, .{ .whitespace = .indent_2 });
        defer w.deinit();
        try test_basic_write_stream(&w, &slice_stream);
    }
}

fn test_basic_write_stream(w: anytype, slice_stream: anytype) !void {
    slice_stream.reset();

    try w.begin_object();

    try w.object_field("object");
    var arena_allocator = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_allocator.deinit();
    try w.write(try get_json_object(arena_allocator.allocator()));

    try w.object_field_raw("\"string\"");
    try w.write("This is a string");

    try w.object_field("array");
    try w.begin_array();
    try w.write("Another string");
    try w.write(@as(i32, 1));
    try w.write(@as(f32, 3.5));
    try w.end_array();

    try w.object_field("int");
    try w.write(@as(i32, 10));

    try w.object_field("float");
    try w.write(@as(f32, 3.5));

    try w.end_object();

    const result = slice_stream.get_written();
    const expected =
        \\{
        \\  "object": {
        \\    "one": 1,
        \\    "two": 2e0
        \\  },
        \\  "string": "This is a string",
        \\  "array": [
        \\    "Another string",
        \\    1,
        \\    3.5e0
        \\  ],
        \\  "int": 10,
        \\  "float": 3.5e0
        \\}
    ;
    try std.testing.expect_equal_strings(expected, result);
}

fn get_json_object(allocator: std.mem.Allocator) !Value {
    var value = Value{ .object = ObjectMap.init(allocator) };
    try value.object.put("one", Value{ .integer = @as(i64, @int_cast(1)) });
    try value.object.put("two", Value{ .float = 2.0 });
    return value;
}

test "stringify null optional fields" {
    const MyStruct = struct {
        optional: ?[]const u8 = null,
        required: []const u8 = "something",
        another_optional: ?[]const u8 = null,
        another_required: []const u8 = "something else",
    };
    try test_stringify(
        \\{"optional":null,"required":"something","another_optional":null,"another_required":"something else"}
    ,
        MyStruct{},
        .{},
    );
    try test_stringify(
        \\{"required":"something","another_required":"something else"}
    ,
        MyStruct{},
        .{ .emit_null_optional_fields = false },
    );
}

test "stringify basic types" {
    try test_stringify("false", false, .{});
    try test_stringify("true", true, .{});
    try test_stringify("null", @as(?u8, null), .{});
    try test_stringify("null", @as(?*u32, null), .{});
    try test_stringify("42", 42, .{});
    try test_stringify("4.2e1", 42.0, .{});
    try test_stringify("42", @as(u8, 42), .{});
    try test_stringify("42", @as(u128, 42), .{});
    try test_stringify("9999999999999999", 9999999999999999, .{});
    try test_stringify("4.2e1", @as(f32, 42), .{});
    try test_stringify("4.2e1", @as(f64, 42), .{});
    try test_stringify("\"ItBroke\"", @as(anyerror, error.ItBroke), .{});
    try test_stringify("\"ItBroke\"", error.ItBroke, .{});
}

test "stringify string" {
    try test_stringify("\"hello\"", "hello", .{});
    try test_stringify("\"with\\nescapes\\r\"", "with\nescapes\r", .{});
    try test_stringify("\"with\\nescapes\\r\"", "with\nescapes\r", .{ .escape_unicode = true });
    try test_stringify("\"with unicode\\u0001\"", "with unicode\u{1}", .{});
    try test_stringify("\"with unicode\\u0001\"", "with unicode\u{1}", .{ .escape_unicode = true });
    try test_stringify("\"with unicode\u{80}\"", "with unicode\u{80}", .{});
    try test_stringify("\"with unicode\\u0080\"", "with unicode\u{80}", .{ .escape_unicode = true });
    try test_stringify("\"with unicode\u{FF}\"", "with unicode\u{FF}", .{});
    try test_stringify("\"with unicode\\u00ff\"", "with unicode\u{FF}", .{ .escape_unicode = true });
    try test_stringify("\"with unicode\u{100}\"", "with unicode\u{100}", .{});
    try test_stringify("\"with unicode\\u0100\"", "with unicode\u{100}", .{ .escape_unicode = true });
    try test_stringify("\"with unicode\u{800}\"", "with unicode\u{800}", .{});
    try test_stringify("\"with unicode\\u0800\"", "with unicode\u{800}", .{ .escape_unicode = true });
    try test_stringify("\"with unicode\u{8000}\"", "with unicode\u{8000}", .{});
    try test_stringify("\"with unicode\\u8000\"", "with unicode\u{8000}", .{ .escape_unicode = true });
    try test_stringify("\"with unicode\u{D799}\"", "with unicode\u{D799}", .{});
    try test_stringify("\"with unicode\\ud799\"", "with unicode\u{D799}", .{ .escape_unicode = true });
    try test_stringify("\"with unicode\u{10000}\"", "with unicode\u{10000}", .{});
    try test_stringify("\"with unicode\\ud800\\udc00\"", "with unicode\u{10000}", .{ .escape_unicode = true });
    try test_stringify("\"with unicode\u{10FFFF}\"", "with unicode\u{10FFFF}", .{});
    try test_stringify("\"with unicode\\udbff\\udfff\"", "with unicode\u{10FFFF}", .{ .escape_unicode = true });
}

test "stringify many-item sentinel-terminated string" {
    try test_stringify("\"hello\"", @as([*:0]const u8, "hello"), .{});
    try test_stringify("\"with\\nescapes\\r\"", @as([*:0]const u8, "with\nescapes\r"), .{ .escape_unicode = true });
    try test_stringify("\"with unicode\\u0001\"", @as([*:0]const u8, "with unicode\u{1}"), .{ .escape_unicode = true });
}

test "stringify enums" {
    const E = enum {
        foo,
        bar,
    };
    try test_stringify("\"foo\"", E.foo, .{});
    try test_stringify("\"bar\"", E.bar, .{});
}

test "stringify enum literals" {
    try test_stringify("\"foo\"", .foo, .{});
    try test_stringify("\"bar\"", .bar, .{});
}

test "stringify tagged unions" {
    const T = union(enum) {
        nothing,
        foo: u32,
        bar: bool,
    };
    try test_stringify("{\"nothing\":{}}", T{ .nothing = {} }, .{});
    try test_stringify("{\"foo\":42}", T{ .foo = 42 }, .{});
    try test_stringify("{\"bar\":true}", T{ .bar = true }, .{});
}

test "stringify struct" {
    try test_stringify("{\"foo\":42}", struct {
        foo: u32,
    }{ .foo = 42 }, .{});
}

test "emit_strings_as_arrays" {
    // Should only affect string values, not object keys.
    try test_stringify("{\"foo\":\"bar\"}", .{ .foo = "bar" }, .{});
    try test_stringify("{\"foo\":[98,97,114]}", .{ .foo = "bar" }, .{ .emit_strings_as_arrays = true });
    // Should *not* affect these types:
    try test_stringify("\"foo\"", @as(enum { foo, bar }, .foo), .{ .emit_strings_as_arrays = true });
    try test_stringify("\"ItBroke\"", error.ItBroke, .{ .emit_strings_as_arrays = true });
    // Should work on these:
    try test_stringify("\"bar\"", @Vector(3, u8){ 'b', 'a', 'r' }, .{});
    try test_stringify("[98,97,114]", @Vector(3, u8){ 'b', 'a', 'r' }, .{ .emit_strings_as_arrays = true });
    try test_stringify("\"bar\"", [3]u8{ 'b', 'a', 'r' }, .{});
    try test_stringify("[98,97,114]", [3]u8{ 'b', 'a', 'r' }, .{ .emit_strings_as_arrays = true });
}

test "stringify struct with indentation" {
    try test_stringify(
        \\{
        \\    "foo": 42,
        \\    "bar": [
        \\        1,
        \\        2,
        \\        3
        \\    ]
        \\}
    ,
        struct {
            foo: u32,
            bar: [3]u32,
        }{
            .foo = 42,
            .bar = .{ 1, 2, 3 },
        },
        .{ .whitespace = .indent_4 },
    );
    try test_stringify(
        "{\n\t\"foo\": 42,\n\t\"bar\": [\n\t\t1,\n\t\t2,\n\t\t3\n\t]\n}",
        struct {
            foo: u32,
            bar: [3]u32,
        }{
            .foo = 42,
            .bar = .{ 1, 2, 3 },
        },
        .{ .whitespace = .indent_tab },
    );
    try test_stringify(
        \\{"foo":42,"bar":[1,2,3]}
    ,
        struct {
            foo: u32,
            bar: [3]u32,
        }{
            .foo = 42,
            .bar = .{ 1, 2, 3 },
        },
        .{ .whitespace = .minified },
    );
}

test "stringify struct with void field" {
    try test_stringify("{\"foo\":42}", struct {
        foo: u32,
        bar: void = {},
    }{ .foo = 42 }, .{});
}

test "stringify array of structs" {
    const MyStruct = struct {
        foo: u32,
    };
    try test_stringify("[{\"foo\":42},{\"foo\":100},{\"foo\":1000}]", [_]MyStruct{
        MyStruct{ .foo = 42 },
        MyStruct{ .foo = 100 },
        MyStruct{ .foo = 1000 },
    }, .{});
}

test "stringify struct with custom stringifier" {
    try test_stringify("[\"something special\",42]", struct {
        foo: u32,
        const Self = @This();
        pub fn json_stringify(value: @This(), jws: anytype) !void {
            _ = value;
            try jws.begin_array();
            try jws.write("something special");
            try jws.write(42);
            try jws.end_array();
        }
    }{ .foo = 42 }, .{});
}

test "stringify vector" {
    try test_stringify("[1,1]", @as(@Vector(2, u32), @splat(1)), .{});
    try test_stringify("\"AA\"", @as(@Vector(2, u8), @splat('A')), .{});
    try test_stringify("[65,65]", @as(@Vector(2, u8), @splat('A')), .{ .emit_strings_as_arrays = true });
}

test "stringify tuple" {
    try test_stringify("[\"foo\",42]", std.meta.Tuple(&.{ []const u8, usize }){ "foo", 42 }, .{});
}

fn test_stringify(expected: []const u8, value: anytype, options: StringifyOptions) !void {
    const ValidationWriter = struct {
        const Self = @This();
        pub const Writer = std.io.Writer(*Self, Error, write);
        pub const Error = error{
            TooMuchData,
            DifferentData,
        };

        expected_remaining: []const u8,

        fn init(exp: []const u8) Self {
            return .{ .expected_remaining = exp };
        }

        pub fn writer(self: *Self) Writer {
            return .{ .context = self };
        }

        fn write(self: *Self, bytes: []const u8) Error!usize {
            if (self.expected_remaining.len < bytes.len) {
                std.debug.print(
                    \\====== expected this output: =========
                    \\{s}
                    \\======== instead found this: =========
                    \\{s}
                    \\======================================
                , .{
                    self.expected_remaining,
                    bytes,
                });
                return error.TooMuchData;
            }
            if (!mem.eql(u8, self.expected_remaining[0..bytes.len], bytes)) {
                std.debug.print(
                    \\====== expected this output: =========
                    \\{s}
                    \\======== instead found this: =========
                    \\{s}
                    \\======================================
                , .{
                    self.expected_remaining[0..bytes.len],
                    bytes,
                });
                return error.DifferentData;
            }
            self.expected_remaining = self.expected_remaining[bytes.len..];
            return bytes.len;
        }
    };

    var vos = ValidationWriter.init(expected);
    try stringify_arbitrary_depth(testing.allocator, value, options, vos.writer());
    if (vos.expected_remaining.len > 0) return error.NotEnoughData;

    // Also test with safety disabled.
    try test_stringify_max_depth(expected, value, options, null);
    try test_stringify_arbitrary_depth(expected, value, options);
}

fn test_stringify_max_depth(expected: []const u8, value: anytype, options: StringifyOptions, comptime max_depth: ?usize) !void {
    var out_buf: [1024]u8 = undefined;
    var slice_stream = std.io.fixed_buffer_stream(&out_buf);
    const out = slice_stream.writer();

    try stringify_max_depth(value, options, out, max_depth);
    const got = slice_stream.get_written();

    try testing.expect_equal_strings(expected, got);
}

fn test_stringify_arbitrary_depth(expected: []const u8, value: anytype, options: StringifyOptions) !void {
    var out_buf: [1024]u8 = undefined;
    var slice_stream = std.io.fixed_buffer_stream(&out_buf);
    const out = slice_stream.writer();

    try stringify_arbitrary_depth(testing.allocator, value, options, out);
    const got = slice_stream.get_written();

    try testing.expect_equal_strings(expected, got);
}

test "stringify alloc" {
    const allocator = std.testing.allocator;
    const expected =
        \\{"foo":"bar","answer":42,"my_friend":"sammy"}
    ;
    const actual = try stringify_alloc(allocator, .{ .foo = "bar", .answer = 42, .my_friend = "sammy" }, .{});
    defer allocator.free(actual);

    try std.testing.expect_equal_strings(expected, actual);
}

test "comptime stringify" {
    comptime test_stringify_max_depth("false", false, .{}, null) catch unreachable;
    comptime test_stringify_max_depth("false", false, .{}, 0) catch unreachable;
    comptime test_stringify_arbitrary_depth("false", false, .{}) catch unreachable;

    const MyStruct = struct {
        foo: u32,
    };
    comptime test_stringify_max_depth("[{\"foo\":42},{\"foo\":100},{\"foo\":1000}]", [_]MyStruct{
        MyStruct{ .foo = 42 },
        MyStruct{ .foo = 100 },
        MyStruct{ .foo = 1000 },
    }, .{}, null) catch unreachable;
    comptime test_stringify_max_depth("[{\"foo\":42},{\"foo\":100},{\"foo\":1000}]", [_]MyStruct{
        MyStruct{ .foo = 42 },
        MyStruct{ .foo = 100 },
        MyStruct{ .foo = 1000 },
    }, .{}, 8) catch unreachable;
}

test "print" {
    var out_buf: [1024]u8 = undefined;
    var slice_stream = std.io.fixed_buffer_stream(&out_buf);
    const out = slice_stream.writer();

    var w = write_stream(out, .{ .whitespace = .indent_2 });
    defer w.deinit();

    try w.begin_object();
    try w.object_field("a");
    try w.print("[  ]", .{});
    try w.object_field("b");
    try w.begin_array();
    try w.print("[{s}] ", .{"[]"});
    try w.print("  {}", .{12345});
    try w.end_array();
    try w.end_object();

    const result = slice_stream.get_written();
    const expected =
        \\{
        \\  "a": [  ],
        \\  "b": [
        \\    [[]] ,
        \\      12345
        \\  ]
        \\}
    ;
    try std.testing.expect_equal_strings(expected, result);
}

test "nonportable numbers" {
    try test_stringify("9999999999999999", 9999999999999999, .{});
    try test_stringify("\"9999999999999999\"", 9999999999999999, .{ .emit_nonportable_numbers_as_strings = true });
}
