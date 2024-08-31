const std = @import("../../std.zig");
const testing = std.testing;

test "Reader" {
    var buf = "a\x02".*;
    var fis = std.io.fixed_buffer_stream(&buf);
    const reader = fis.reader();
    try testing.expect((try reader.read_byte()) == 'a');
    try testing.expect((try reader.read_enum(enum(u8) {
        a = 0,
        b = 99,
        c = 2,
        d = 3,
    }, undefined)) == .c);
    try testing.expect_error(error.EndOfStream, reader.read_byte());
}

test "is_bytes" {
    var fis = std.io.fixed_buffer_stream("foobar");
    const reader = fis.reader();
    try testing.expect_equal(true, try reader.is_bytes("foo"));
    try testing.expect_equal(false, try reader.is_bytes("qux"));
}

test "skip_bytes" {
    var fis = std.io.fixed_buffer_stream("foobar");
    const reader = fis.reader();
    try reader.skip_bytes(3, .{});
    try testing.expect(try reader.is_bytes("bar"));
    try reader.skip_bytes(0, .{});
    try testing.expect_error(error.EndOfStream, reader.skip_bytes(1, .{}));
}

test "read_until_delimiter_array_list returns ArrayLists with bytes read until the delimiter, then EndOfStream" {
    const a = std.testing.allocator;
    var list = std.ArrayList(u8).init(a);
    defer list.deinit();

    var fis = std.io.fixed_buffer_stream("0000\n1234\n");
    const reader = fis.reader();

    try reader.read_until_delimiter_array_list(&list, '\n', 5);
    try std.testing.expect_equal_strings("0000", list.items);
    try reader.read_until_delimiter_array_list(&list, '\n', 5);
    try std.testing.expect_equal_strings("1234", list.items);
    try std.testing.expect_error(error.EndOfStream, reader.read_until_delimiter_array_list(&list, '\n', 5));
}

test "read_until_delimiter_array_list returns an empty ArrayList" {
    const a = std.testing.allocator;
    var list = std.ArrayList(u8).init(a);
    defer list.deinit();

    var fis = std.io.fixed_buffer_stream("\n");
    const reader = fis.reader();

    try reader.read_until_delimiter_array_list(&list, '\n', 5);
    try std.testing.expect_equal_strings("", list.items);
}

test "read_until_delimiter_array_list returns StreamTooLong, then an ArrayList with bytes read until the delimiter" {
    const a = std.testing.allocator;
    var list = std.ArrayList(u8).init(a);
    defer list.deinit();

    var fis = std.io.fixed_buffer_stream("1234567\n");
    const reader = fis.reader();

    try std.testing.expect_error(error.StreamTooLong, reader.read_until_delimiter_array_list(&list, '\n', 5));
    try std.testing.expect_equal_strings("12345", list.items);
    try reader.read_until_delimiter_array_list(&list, '\n', 5);
    try std.testing.expect_equal_strings("67", list.items);
}

test "read_until_delimiter_array_list returns EndOfStream" {
    const a = std.testing.allocator;
    var list = std.ArrayList(u8).init(a);
    defer list.deinit();

    var fis = std.io.fixed_buffer_stream("1234");
    const reader = fis.reader();

    try std.testing.expect_error(error.EndOfStream, reader.read_until_delimiter_array_list(&list, '\n', 5));
    try std.testing.expect_equal_strings("1234", list.items);
}

test "read_until_delimiter_alloc returns ArrayLists with bytes read until the delimiter, then EndOfStream" {
    const a = std.testing.allocator;

    var fis = std.io.fixed_buffer_stream("0000\n1234\n");
    const reader = fis.reader();

    {
        const result = try reader.read_until_delimiter_alloc(a, '\n', 5);
        defer a.free(result);
        try std.testing.expect_equal_strings("0000", result);
    }

    {
        const result = try reader.read_until_delimiter_alloc(a, '\n', 5);
        defer a.free(result);
        try std.testing.expect_equal_strings("1234", result);
    }

    try std.testing.expect_error(error.EndOfStream, reader.read_until_delimiter_alloc(a, '\n', 5));
}

test "read_until_delimiter_alloc returns an empty ArrayList" {
    const a = std.testing.allocator;

    var fis = std.io.fixed_buffer_stream("\n");
    const reader = fis.reader();

    {
        const result = try reader.read_until_delimiter_alloc(a, '\n', 5);
        defer a.free(result);
        try std.testing.expect_equal_strings("", result);
    }
}

test "read_until_delimiter_alloc returns StreamTooLong, then an ArrayList with bytes read until the delimiter" {
    const a = std.testing.allocator;

    var fis = std.io.fixed_buffer_stream("1234567\n");
    const reader = fis.reader();

    try std.testing.expect_error(error.StreamTooLong, reader.read_until_delimiter_alloc(a, '\n', 5));

    const result = try reader.read_until_delimiter_alloc(a, '\n', 5);
    defer a.free(result);
    try std.testing.expect_equal_strings("67", result);
}

test "read_until_delimiter_alloc returns EndOfStream" {
    const a = std.testing.allocator;

    var fis = std.io.fixed_buffer_stream("1234");
    const reader = fis.reader();

    try std.testing.expect_error(error.EndOfStream, reader.read_until_delimiter_alloc(a, '\n', 5));
}

test "read_until_delimiter returns bytes read until the delimiter" {
    var buf: [5]u8 = undefined;
    var fis = std.io.fixed_buffer_stream("0000\n1234\n");
    const reader = fis.reader();
    try std.testing.expect_equal_strings("0000", try reader.read_until_delimiter(&buf, '\n'));
    try std.testing.expect_equal_strings("1234", try reader.read_until_delimiter(&buf, '\n'));
}

test "read_until_delimiter returns an empty string" {
    var buf: [5]u8 = undefined;
    var fis = std.io.fixed_buffer_stream("\n");
    const reader = fis.reader();
    try std.testing.expect_equal_strings("", try reader.read_until_delimiter(&buf, '\n'));
}

test "read_until_delimiter returns StreamTooLong, then an empty string" {
    var buf: [5]u8 = undefined;
    var fis = std.io.fixed_buffer_stream("12345\n");
    const reader = fis.reader();
    try std.testing.expect_error(error.StreamTooLong, reader.read_until_delimiter(&buf, '\n'));
    try std.testing.expect_equal_strings("", try reader.read_until_delimiter(&buf, '\n'));
}

test "read_until_delimiter returns StreamTooLong, then bytes read until the delimiter" {
    var buf: [5]u8 = undefined;
    var fis = std.io.fixed_buffer_stream("1234567\n");
    const reader = fis.reader();
    try std.testing.expect_error(error.StreamTooLong, reader.read_until_delimiter(&buf, '\n'));
    try std.testing.expect_equal_strings("67", try reader.read_until_delimiter(&buf, '\n'));
}

test "read_until_delimiter returns EndOfStream" {
    {
        var buf: [5]u8 = undefined;
        var fis = std.io.fixed_buffer_stream("");
        const reader = fis.reader();
        try std.testing.expect_error(error.EndOfStream, reader.read_until_delimiter(&buf, '\n'));
    }
    {
        var buf: [5]u8 = undefined;
        var fis = std.io.fixed_buffer_stream("1234");
        const reader = fis.reader();
        try std.testing.expect_error(error.EndOfStream, reader.read_until_delimiter(&buf, '\n'));
    }
}

test "read_until_delimiter returns bytes read until delimiter, then EndOfStream" {
    var buf: [5]u8 = undefined;
    var fis = std.io.fixed_buffer_stream("1234\n");
    const reader = fis.reader();
    try std.testing.expect_equal_strings("1234", try reader.read_until_delimiter(&buf, '\n'));
    try std.testing.expect_error(error.EndOfStream, reader.read_until_delimiter(&buf, '\n'));
}

test "read_until_delimiter returns StreamTooLong, then EndOfStream" {
    var buf: [5]u8 = undefined;
    var fis = std.io.fixed_buffer_stream("12345");
    const reader = fis.reader();
    try std.testing.expect_error(error.StreamTooLong, reader.read_until_delimiter(&buf, '\n'));
    try std.testing.expect_error(error.EndOfStream, reader.read_until_delimiter(&buf, '\n'));
}

test "read_until_delimiter writes all bytes read to the output buffer" {
    var buf: [5]u8 = undefined;
    var fis = std.io.fixed_buffer_stream("0000\n12345");
    const reader = fis.reader();
    _ = try reader.read_until_delimiter(&buf, '\n');
    try std.testing.expect_equal_strings("0000\n", &buf);
    try std.testing.expect_error(error.StreamTooLong, reader.read_until_delimiter(&buf, '\n'));
    try std.testing.expect_equal_strings("12345", &buf);
}

test "read_until_delimiter_or_eof_alloc returns ArrayLists with bytes read until the delimiter, then EndOfStream" {
    const a = std.testing.allocator;

    var fis = std.io.fixed_buffer_stream("0000\n1234\n");
    const reader = fis.reader();

    {
        const result = (try reader.read_until_delimiter_or_eof_alloc(a, '\n', 5)).?;
        defer a.free(result);
        try std.testing.expect_equal_strings("0000", result);
    }

    {
        const result = (try reader.read_until_delimiter_or_eof_alloc(a, '\n', 5)).?;
        defer a.free(result);
        try std.testing.expect_equal_strings("1234", result);
    }

    try std.testing.expect((try reader.read_until_delimiter_or_eof_alloc(a, '\n', 5)) == null);
}

test "read_until_delimiter_or_eof_alloc returns an empty ArrayList" {
    const a = std.testing.allocator;

    var fis = std.io.fixed_buffer_stream("\n");
    const reader = fis.reader();

    {
        const result = (try reader.read_until_delimiter_or_eof_alloc(a, '\n', 5)).?;
        defer a.free(result);
        try std.testing.expect_equal_strings("", result);
    }
}

test "read_until_delimiter_or_eof_alloc returns StreamTooLong, then an ArrayList with bytes read until the delimiter" {
    const a = std.testing.allocator;

    var fis = std.io.fixed_buffer_stream("1234567\n");
    const reader = fis.reader();

    try std.testing.expect_error(error.StreamTooLong, reader.read_until_delimiter_or_eof_alloc(a, '\n', 5));

    const result = (try reader.read_until_delimiter_or_eof_alloc(a, '\n', 5)).?;
    defer a.free(result);
    try std.testing.expect_equal_strings("67", result);
}

test "read_until_delimiter_or_eof returns bytes read until the delimiter" {
    var buf: [5]u8 = undefined;
    var fis = std.io.fixed_buffer_stream("0000\n1234\n");
    const reader = fis.reader();
    try std.testing.expect_equal_strings("0000", (try reader.read_until_delimiter_or_eof(&buf, '\n')).?);
    try std.testing.expect_equal_strings("1234", (try reader.read_until_delimiter_or_eof(&buf, '\n')).?);
}

test "read_until_delimiter_or_eof returns an empty string" {
    var buf: [5]u8 = undefined;
    var fis = std.io.fixed_buffer_stream("\n");
    const reader = fis.reader();
    try std.testing.expect_equal_strings("", (try reader.read_until_delimiter_or_eof(&buf, '\n')).?);
}

test "read_until_delimiter_or_eof returns StreamTooLong, then an empty string" {
    var buf: [5]u8 = undefined;
    var fis = std.io.fixed_buffer_stream("12345\n");
    const reader = fis.reader();
    try std.testing.expect_error(error.StreamTooLong, reader.read_until_delimiter_or_eof(&buf, '\n'));
    try std.testing.expect_equal_strings("", (try reader.read_until_delimiter_or_eof(&buf, '\n')).?);
}

test "read_until_delimiter_or_eof returns StreamTooLong, then bytes read until the delimiter" {
    var buf: [5]u8 = undefined;
    var fis = std.io.fixed_buffer_stream("1234567\n");
    const reader = fis.reader();
    try std.testing.expect_error(error.StreamTooLong, reader.read_until_delimiter_or_eof(&buf, '\n'));
    try std.testing.expect_equal_strings("67", (try reader.read_until_delimiter_or_eof(&buf, '\n')).?);
}

test "read_until_delimiter_or_eof returns null" {
    var buf: [5]u8 = undefined;
    var fis = std.io.fixed_buffer_stream("");
    const reader = fis.reader();
    try std.testing.expect((try reader.read_until_delimiter_or_eof(&buf, '\n')) == null);
}

test "read_until_delimiter_or_eof returns bytes read until delimiter, then null" {
    var buf: [5]u8 = undefined;
    var fis = std.io.fixed_buffer_stream("1234\n");
    const reader = fis.reader();
    try std.testing.expect_equal_strings("1234", (try reader.read_until_delimiter_or_eof(&buf, '\n')).?);
    try std.testing.expect((try reader.read_until_delimiter_or_eof(&buf, '\n')) == null);
}

test "read_until_delimiter_or_eof returns bytes read until end-of-stream" {
    var buf: [5]u8 = undefined;
    var fis = std.io.fixed_buffer_stream("1234");
    const reader = fis.reader();
    try std.testing.expect_equal_strings("1234", (try reader.read_until_delimiter_or_eof(&buf, '\n')).?);
}

test "read_until_delimiter_or_eof returns StreamTooLong, then bytes read until end-of-stream" {
    var buf: [5]u8 = undefined;
    var fis = std.io.fixed_buffer_stream("1234567");
    const reader = fis.reader();
    try std.testing.expect_error(error.StreamTooLong, reader.read_until_delimiter_or_eof(&buf, '\n'));
    try std.testing.expect_equal_strings("67", (try reader.read_until_delimiter_or_eof(&buf, '\n')).?);
}

test "read_until_delimiter_or_eof writes all bytes read to the output buffer" {
    var buf: [5]u8 = undefined;
    var fis = std.io.fixed_buffer_stream("0000\n12345");
    const reader = fis.reader();
    _ = try reader.read_until_delimiter_or_eof(&buf, '\n');
    try std.testing.expect_equal_strings("0000\n", &buf);
    try std.testing.expect_error(error.StreamTooLong, reader.read_until_delimiter_or_eof(&buf, '\n'));
    try std.testing.expect_equal_strings("12345", &buf);
}

test "stream_until_delimiter writes all bytes without delimiter to the output" {
    const input_string = "some_string_with_delimiter!";
    var input_fbs = std.io.fixed_buffer_stream(input_string);
    const reader = input_fbs.reader();

    var output: [input_string.len]u8 = undefined;
    var output_fbs = std.io.fixed_buffer_stream(&output);
    const writer = output_fbs.writer();

    try reader.stream_until_delimiter(writer, '!', input_fbs.buffer.len);
    try std.testing.expect_equal_strings("some_string_with_delimiter", output_fbs.get_written());
    try std.testing.expect_error(error.EndOfStream, reader.stream_until_delimiter(writer, '!', input_fbs.buffer.len));

    input_fbs.reset();
    output_fbs.reset();

    try std.testing.expect_error(error.StreamTooLong, reader.stream_until_delimiter(writer, '!', 5));
}

test "read_bounded_bytes correctly reads into a new bounded array" {
    const test_string = "abcdefg";
    var fis = std.io.fixed_buffer_stream(test_string);
    const reader = fis.reader();

    var array = try reader.read_bounded_bytes(10000);
    try testing.expect_equal_strings(array.slice(), test_string);
}

test "read_into_bounded_bytes correctly reads into a provided bounded array" {
    const test_string = "abcdefg";
    var fis = std.io.fixed_buffer_stream(test_string);
    const reader = fis.reader();

    var bounded_array = std.BoundedArray(u8, 10000){};

    // compile time error if the size is not the same at the provided `bounded.capacity()`
    try reader.read_into_bounded_bytes(10000, &bounded_array);
    try testing.expect_equal_strings(bounded_array.slice(), test_string);
}
