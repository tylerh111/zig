const std = @import("std");
const testing = std.testing;

const ArrayHashMap = @import("hashmap.zig").ArrayHashMap;

const parse_from_slice = @import("static.zig").parse_from_slice;
const parse_from_slice_leaky = @import("static.zig").parse_from_slice_leaky;
const parse_from_token_source = @import("static.zig").parse_from_token_source;
const parse_from_value = @import("static.zig").parse_from_value;
const stringify_alloc = @import("stringify.zig").stringify_alloc;
const Value = @import("dynamic.zig").Value;

const jsonReader = @import("./scanner.zig").reader;

const T = struct {
    i: i32,
    s: []const u8,
};

test "parse json hashmap" {
    const doc =
        \\{
        \\  "abc": {"i": 0, "s": "d"},
        \\  "xyz": {"i": 1, "s": "w"}
        \\}
    ;
    const parsed = try parse_from_slice(ArrayHashMap(T), testing.allocator, doc, .{});
    defer parsed.deinit();

    try testing.expect_equal(@as(usize, 2), parsed.value.map.count());
    try testing.expect_equal_strings("d", parsed.value.map.get("abc").?.s);
    try testing.expect_equal(@as(i32, 1), parsed.value.map.get("xyz").?.i);
}

test "parse json hashmap while streaming" {
    const doc =
        \\{
        \\  "abc": {"i": 0, "s": "d"},
        \\  "xyz": {"i": 1, "s": "w"}
        \\}
    ;
    var stream = std.io.fixed_buffer_stream(doc);
    var json_reader = jsonReader(testing.allocator, stream.reader());

    var parsed = try parse_from_token_source(
        ArrayHashMap(T),
        testing.allocator,
        &json_reader,
        .{},
    );
    defer parsed.deinit();
    // Deinit our reader to invalidate its buffer
    json_reader.deinit();

    try testing.expect_equal(@as(usize, 2), parsed.value.map.count());
    try testing.expect_equal_strings("d", parsed.value.map.get("abc").?.s);
    try testing.expect_equal(@as(i32, 1), parsed.value.map.get("xyz").?.i);
}

test "parse json hashmap duplicate fields" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const doc =
        \\{
        \\  "abc": {"i": 0, "s": "d"},
        \\  "abc": {"i": 1, "s": "w"}
        \\}
    ;

    try testing.expect_error(error.DuplicateField, parse_from_slice_leaky(ArrayHashMap(T), arena.allocator(), doc, .{
        .duplicate_field_behavior = .@"error",
    }));

    const first = try parse_from_slice_leaky(ArrayHashMap(T), arena.allocator(), doc, .{
        .duplicate_field_behavior = .use_first,
    });
    try testing.expect_equal(@as(usize, 1), first.map.count());
    try testing.expect_equal(@as(i32, 0), first.map.get("abc").?.i);

    const last = try parse_from_slice_leaky(ArrayHashMap(T), arena.allocator(), doc, .{
        .duplicate_field_behavior = .use_last,
    });
    try testing.expect_equal(@as(usize, 1), last.map.count());
    try testing.expect_equal(@as(i32, 1), last.map.get("abc").?.i);
}

test "stringify json hashmap" {
    var value = ArrayHashMap(T){};
    defer value.deinit(testing.allocator);
    {
        const doc = try stringify_alloc(testing.allocator, value, .{});
        defer testing.allocator.free(doc);
        try testing.expect_equal_strings("{}", doc);
    }

    try value.map.put(testing.allocator, "abc", .{ .i = 0, .s = "d" });
    try value.map.put(testing.allocator, "xyz", .{ .i = 1, .s = "w" });

    {
        const doc = try stringify_alloc(testing.allocator, value, .{});
        defer testing.allocator.free(doc);
        try testing.expect_equal_strings(
            \\{"abc":{"i":0,"s":"d"},"xyz":{"i":1,"s":"w"}}
        , doc);
    }

    try testing.expect(value.map.swap_remove("abc"));
    {
        const doc = try stringify_alloc(testing.allocator, value, .{});
        defer testing.allocator.free(doc);
        try testing.expect_equal_strings(
            \\{"xyz":{"i":1,"s":"w"}}
        , doc);
    }

    try testing.expect(value.map.swap_remove("xyz"));
    {
        const doc = try stringify_alloc(testing.allocator, value, .{});
        defer testing.allocator.free(doc);
        try testing.expect_equal_strings("{}", doc);
    }
}

test "stringify json hashmap whitespace" {
    var value = ArrayHashMap(T){};
    defer value.deinit(testing.allocator);
    try value.map.put(testing.allocator, "abc", .{ .i = 0, .s = "d" });
    try value.map.put(testing.allocator, "xyz", .{ .i = 1, .s = "w" });

    {
        const doc = try stringify_alloc(testing.allocator, value, .{ .whitespace = .indent_2 });
        defer testing.allocator.free(doc);
        try testing.expect_equal_strings(
            \\{
            \\  "abc": {
            \\    "i": 0,
            \\    "s": "d"
            \\  },
            \\  "xyz": {
            \\    "i": 1,
            \\    "s": "w"
            \\  }
            \\}
        , doc);
    }
}

test "json parse from value hashmap" {
    const doc =
        \\{
        \\  "abc": {"i": 0, "s": "d"},
        \\  "xyz": {"i": 1, "s": "w"}
        \\}
    ;
    const parsed1 = try parse_from_slice(Value, testing.allocator, doc, .{});
    defer parsed1.deinit();

    const parsed2 = try parse_from_value(ArrayHashMap(T), testing.allocator, parsed1.value, .{});
    defer parsed2.deinit();

    try testing.expect_equal_strings("d", parsed2.value.map.get("abc").?.s);
}
