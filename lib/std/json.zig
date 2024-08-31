//! JSON parsing and stringification conforming to RFC 8259. https://datatracker.ietf.org/doc/html/rfc8259
//!
//! The low-level `Scanner` API produces `Token`s from an input slice or successive slices of inputs,
//! The `Reader` API connects a `std.io.Reader` to a `Scanner`.
//!
//! The high-level `parse_from_slice` and `parse_from_token_source` deserialize a JSON document into a Zig type.
//! Parse into a dynamically-typed `Value` to load any JSON value for runtime inspection.
//!
//! The low-level `write_stream` emits syntax-conformant JSON tokens to a `std.io.Writer`.
//! The high-level `stringify` serializes a Zig or `Value` type into JSON.

const builtin = @import("builtin");
const testing = @import("std").testing;
const ArrayList = @import("std").ArrayList;

test Scanner {
    var scanner = Scanner.init_complete_input(testing.allocator, "{\"foo\": 123}\n");
    defer scanner.deinit();
    try testing.expect_equal(Token.object_begin, try scanner.next());
    try testing.expect_equal_slices(u8, "foo", (try scanner.next()).string);
    try testing.expect_equal_slices(u8, "123", (try scanner.next()).number);
    try testing.expect_equal(Token.object_end, try scanner.next());
    try testing.expect_equal(Token.end_of_document, try scanner.next());
}

test parse_from_slice {
    var parsed_str = try parse_from_slice([]const u8, testing.allocator, "\"a\\u0020b\"", .{});
    defer parsed_str.deinit();
    try testing.expect_equal_slices(u8, "a b", parsed_str.value);

    const T = struct { a: i32 = -1, b: [2]u8 };
    var parsed_struct = try parse_from_slice(T, testing.allocator, "{\"b\":\"xy\"}", .{});
    defer parsed_struct.deinit();
    try testing.expect_equal(@as(i32, -1), parsed_struct.value.a); // default value
    try testing.expect_equal_slices(u8, "xy", parsed_struct.value.b[0..]);
}

test Value {
    var parsed = try parse_from_slice(Value, testing.allocator, "{\"anything\": \"goes\"}", .{});
    defer parsed.deinit();
    try testing.expect_equal_slices(u8, "goes", parsed.value.object.get("anything").?.string);
}

test write_stream {
    var out = ArrayList(u8).init(testing.allocator);
    defer out.deinit();
    var write_stream = write_stream(out.writer(), .{ .whitespace = .indent_2 });
    defer write_stream.deinit();
    try write_stream.begin_object();
    try write_stream.object_field("foo");
    try write_stream.write(123);
    try write_stream.end_object();
    const expected =
        \\{
        \\  "foo": 123
        \\}
    ;
    try testing.expect_equal_slices(u8, expected, out.items);
}

test stringify {
    var out = ArrayList(u8).init(testing.allocator);
    defer out.deinit();

    const T = struct { a: i32, b: []const u8 };
    try stringify(T{ .a = 123, .b = "xy" }, .{}, out.writer());
    try testing.expect_equal_slices(u8, "{\"a\":123,\"b\":\"xy\"}", out.items);
}

pub const ObjectMap = @import("json/dynamic.zig").ObjectMap;
pub const Array = @import("json/dynamic.zig").Array;
pub const Value = @import("json/dynamic.zig").Value;

pub const ArrayHashMap = @import("json/hashmap.zig").ArrayHashMap;

pub const validate = @import("json/scanner.zig").validate;
pub const Error = @import("json/scanner.zig").Error;
pub const reader = @import("json/scanner.zig").reader;
pub const default_buffer_size = @import("json/scanner.zig").default_buffer_size;
pub const Token = @import("json/scanner.zig").Token;
pub const TokenType = @import("json/scanner.zig").TokenType;
pub const Diagnostics = @import("json/scanner.zig").Diagnostics;
pub const AllocWhen = @import("json/scanner.zig").AllocWhen;
pub const default_max_value_len = @import("json/scanner.zig").default_max_value_len;
pub const Reader = @import("json/scanner.zig").Reader;
pub const Scanner = @import("json/scanner.zig").Scanner;
pub const is_number_formatted_like_an_integer = @import("json/scanner.zig").is_number_formatted_like_an_integer;

pub const ParseOptions = @import("json/static.zig").ParseOptions;
pub const Parsed = @import("json/static.zig").Parsed;
pub const parse_from_slice = @import("json/static.zig").parse_from_slice;
pub const parse_from_slice_leaky = @import("json/static.zig").parse_from_slice_leaky;
pub const parse_from_token_source = @import("json/static.zig").parse_from_token_source;
pub const parse_from_token_source_leaky = @import("json/static.zig").parse_from_token_source_leaky;
pub const inner_parse = @import("json/static.zig").inner_parse;
pub const parse_from_value = @import("json/static.zig").parse_from_value;
pub const parse_from_value_leaky = @import("json/static.zig").parse_from_value_leaky;
pub const inner_parse_from_value = @import("json/static.zig").inner_parse_from_value;
pub const ParseError = @import("json/static.zig").ParseError;
pub const ParseFromValueError = @import("json/static.zig").ParseFromValueError;

pub const StringifyOptions = @import("json/stringify.zig").StringifyOptions;
pub const stringify = @import("json/stringify.zig").stringify;
pub const stringify_max_depth = @import("json/stringify.zig").stringify_max_depth;
pub const stringify_arbitrary_depth = @import("json/stringify.zig").stringify_arbitrary_depth;
pub const stringify_alloc = @import("json/stringify.zig").stringify_alloc;
pub const write_stream = @import("json/stringify.zig").write_stream;
pub const write_stream_max_depth = @import("json/stringify.zig").write_stream_max_depth;
pub const write_stream_arbitrary_depth = @import("json/stringify.zig").write_stream_arbitrary_depth;
pub const WriteStream = @import("json/stringify.zig").WriteStream;
pub const encode_json_string = @import("json/stringify.zig").encode_json_string;
pub const encode_json_string_chars = @import("json/stringify.zig").encode_json_string_chars;

pub const Formatter = @import("json/fmt.zig").Formatter;
pub const fmt = @import("json/fmt.zig").fmt;

test {
    _ = @import("json/test.zig");
    _ = @import("json/scanner.zig");
    _ = @import("json/dynamic.zig");
    _ = @import("json/hashmap.zig");
    _ = @import("json/static.zig");
    _ = @import("json/stringify.zig");
    _ = @import("json/JSONTestSuite_test.zig");
}
