const std = @import("std");
const JsonScanner = @import("./scanner.zig").Scanner;
const jsonReader = @import("./scanner.zig").reader;
const JsonReader = @import("./scanner.zig").Reader;
const Token = @import("./scanner.zig").Token;
const TokenType = @import("./scanner.zig").TokenType;
const Diagnostics = @import("./scanner.zig").Diagnostics;
const Error = @import("./scanner.zig").Error;
const validate = @import("./scanner.zig").validate;
const is_number_formatted_like_an_integer = @import("./scanner.zig").is_number_formatted_like_an_integer;

const example_document_str =
    \\{
    \\  "Image": {
    \\      "Width":  800,
    \\      "Height": 600,
    \\      "Title":  "View from 15th Floor",
    \\      "Thumbnail": {
    \\          "Url":    "http://www.example.com/image/481989943",
    \\          "Height": 125,
    \\          "Width":  100
    \\      },
    \\      "Animated" : false,
    \\      "IDs": [116, 943, 234, 38793]
    \\    }
    \\}
;

fn expect_next(scanner_or_reader: anytype, expected_token: Token) !void {
    return expect_equal_tokens(expected_token, try scanner_or_reader.next());
}

fn expect_peek_next(scanner_or_reader: anytype, expected_token_type: TokenType, expected_token: Token) !void {
    try std.testing.expect_equal(expected_token_type, try scanner_or_reader.peek_next_token_type());
    try expect_equal_tokens(expected_token, try scanner_or_reader.next());
}

test "token" {
    var scanner = JsonScanner.init_complete_input(std.testing.allocator, example_document_str);
    defer scanner.deinit();

    try expect_next(&scanner, .object_begin);
    try expect_next(&scanner, Token{ .string = "Image" });
    try expect_next(&scanner, .object_begin);
    try expect_next(&scanner, Token{ .string = "Width" });
    try expect_next(&scanner, Token{ .number = "800" });
    try expect_next(&scanner, Token{ .string = "Height" });
    try expect_next(&scanner, Token{ .number = "600" });
    try expect_next(&scanner, Token{ .string = "Title" });
    try expect_next(&scanner, Token{ .string = "View from 15th Floor" });
    try expect_next(&scanner, Token{ .string = "Thumbnail" });
    try expect_next(&scanner, .object_begin);
    try expect_next(&scanner, Token{ .string = "Url" });
    try expect_next(&scanner, Token{ .string = "http://www.example.com/image/481989943" });
    try expect_next(&scanner, Token{ .string = "Height" });
    try expect_next(&scanner, Token{ .number = "125" });
    try expect_next(&scanner, Token{ .string = "Width" });
    try expect_next(&scanner, Token{ .number = "100" });
    try expect_next(&scanner, .object_end);
    try expect_next(&scanner, Token{ .string = "Animated" });
    try expect_next(&scanner, .false);
    try expect_next(&scanner, Token{ .string = "IDs" });
    try expect_next(&scanner, .array_begin);
    try expect_next(&scanner, Token{ .number = "116" });
    try expect_next(&scanner, Token{ .number = "943" });
    try expect_next(&scanner, Token{ .number = "234" });
    try expect_next(&scanner, Token{ .number = "38793" });
    try expect_next(&scanner, .array_end);
    try expect_next(&scanner, .object_end);
    try expect_next(&scanner, .object_end);
    try expect_next(&scanner, .end_of_document);
}

const all_types_test_case =
    \\[
    \\  "", "a\nb",
    \\  0, 0.0, -1.1e-1,
    \\  true, false, null,
    \\  {"a": {}},
    \\  []
    \\]
;

fn test_all_types(source: anytype, large_buffer: bool) !void {
    try expect_peek_next(source, .array_begin, .array_begin);
    try expect_peek_next(source, .string, Token{ .string = "" });
    try expect_peek_next(source, .string, Token{ .partial_string = "a" });
    try expect_peek_next(source, .string, Token{ .partial_string_escaped_1 = "\n".* });
    if (large_buffer) {
        try expect_peek_next(source, .string, Token{ .string = "b" });
    } else {
        try expect_peek_next(source, .string, Token{ .partial_string = "b" });
        try expect_peek_next(source, .string, Token{ .string = "" });
    }
    if (large_buffer) {
        try expect_peek_next(source, .number, Token{ .number = "0" });
    } else {
        try expect_peek_next(source, .number, Token{ .partial_number = "0" });
        try expect_peek_next(source, .number, Token{ .number = "" });
    }
    if (large_buffer) {
        try expect_peek_next(source, .number, Token{ .number = "0.0" });
    } else {
        try expect_peek_next(source, .number, Token{ .partial_number = "0" });
        try expect_peek_next(source, .number, Token{ .partial_number = "." });
        try expect_peek_next(source, .number, Token{ .partial_number = "0" });
        try expect_peek_next(source, .number, Token{ .number = "" });
    }
    if (large_buffer) {
        try expect_peek_next(source, .number, Token{ .number = "-1.1e-1" });
    } else {
        try expect_peek_next(source, .number, Token{ .partial_number = "-" });
        try expect_peek_next(source, .number, Token{ .partial_number = "1" });
        try expect_peek_next(source, .number, Token{ .partial_number = "." });
        try expect_peek_next(source, .number, Token{ .partial_number = "1" });
        try expect_peek_next(source, .number, Token{ .partial_number = "e" });
        try expect_peek_next(source, .number, Token{ .partial_number = "-" });
        try expect_peek_next(source, .number, Token{ .partial_number = "1" });
        try expect_peek_next(source, .number, Token{ .number = "" });
    }
    try expect_peek_next(source, .true, .true);
    try expect_peek_next(source, .false, .false);
    try expect_peek_next(source, .null, .null);
    try expect_peek_next(source, .object_begin, .object_begin);
    if (large_buffer) {
        try expect_peek_next(source, .string, Token{ .string = "a" });
    } else {
        try expect_peek_next(source, .string, Token{ .partial_string = "a" });
        try expect_peek_next(source, .string, Token{ .string = "" });
    }
    try expect_peek_next(source, .object_begin, .object_begin);
    try expect_peek_next(source, .object_end, .object_end);
    try expect_peek_next(source, .object_end, .object_end);
    try expect_peek_next(source, .array_begin, .array_begin);
    try expect_peek_next(source, .array_end, .array_end);
    try expect_peek_next(source, .array_end, .array_end);
    try expect_peek_next(source, .end_of_document, .end_of_document);
}

test "peek all types" {
    var scanner = JsonScanner.init_complete_input(std.testing.allocator, all_types_test_case);
    defer scanner.deinit();
    try test_all_types(&scanner, true);

    var stream = std.io.fixed_buffer_stream(all_types_test_case);
    var json_reader = jsonReader(std.testing.allocator, stream.reader());
    defer json_reader.deinit();
    try test_all_types(&json_reader, true);

    var tiny_stream = std.io.fixed_buffer_stream(all_types_test_case);
    var tiny_json_reader = JsonReader(1, @TypeOf(tiny_stream.reader())).init(std.testing.allocator, tiny_stream.reader());
    defer tiny_json_reader.deinit();
    try test_all_types(&tiny_json_reader, false);
}

test "token mismatched close" {
    var scanner = JsonScanner.init_complete_input(std.testing.allocator, "[102, 111, 111 }");
    defer scanner.deinit();
    try expect_next(&scanner, .array_begin);
    try expect_next(&scanner, Token{ .number = "102" });
    try expect_next(&scanner, Token{ .number = "111" });
    try expect_next(&scanner, Token{ .number = "111" });
    try std.testing.expect_error(error.SyntaxError, scanner.next());
}

test "token premature object close" {
    var scanner = JsonScanner.init_complete_input(std.testing.allocator, "{ \"key\": }");
    defer scanner.deinit();
    try expect_next(&scanner, .object_begin);
    try expect_next(&scanner, Token{ .string = "key" });
    try std.testing.expect_error(error.SyntaxError, scanner.next());
}

test "JsonScanner basic" {
    var scanner = JsonScanner.init_complete_input(std.testing.allocator, example_document_str);
    defer scanner.deinit();

    while (true) {
        const token = try scanner.next();
        if (token == .end_of_document) break;
    }
}

test "JsonReader basic" {
    var stream = std.io.fixed_buffer_stream(example_document_str);

    var json_reader = jsonReader(std.testing.allocator, stream.reader());
    defer json_reader.deinit();

    while (true) {
        const token = try json_reader.next();
        if (token == .end_of_document) break;
    }
}

const number_test_stems = .{
    .{ "", "-" },
    .{ "0", "1", "10", "9999999999999999999999999" },
    .{ "", ".0", ".999999999999999999999999" },
    .{ "", "e0", "E0", "e+0", "e-0", "e9999999999999999999999999999" },
};
const number_test_items = blk: {
    var ret: []const []const u8 = &[_][]const u8{};
    for (number_test_stems[0]) |s0| {
        for (number_test_stems[1]) |s1| {
            for (number_test_stems[2]) |s2| {
                for (number_test_stems[3]) |s3| {
                    ret = ret ++ &[_][]const u8{s0 ++ s1 ++ s2 ++ s3};
                }
            }
        }
    }
    break :blk ret;
};

test "numbers" {
    for (number_test_items) |number_str| {
        var scanner = JsonScanner.init_complete_input(std.testing.allocator, number_str);
        defer scanner.deinit();

        const token = try scanner.next();
        const value = token.number; // assert this is a number
        try std.testing.expect_equal_strings(number_str, value);

        try std.testing.expect_equal(Token.end_of_document, try scanner.next());
    }
}

const string_test_cases = .{
    // The left is JSON without the "quotes".
    // The right is the expected unescaped content.
    .{ "", "" },
    .{ "\\\\", "\\" },
    .{ "a\\\\b", "a\\b" },
    .{ "a\\\"b", "a\"b" },
    .{ "\\n", "\n" },
    .{ "\\u000a", "\n" },
    .{ "𝄞", "\u{1D11E}" },
    .{ "\\uD834\\uDD1E", "\u{1D11E}" },
    .{ "\\uD87F\\uDFFE", "\u{2FFFE}" },
    .{ "\\uff20", "＠" },
};

test "strings" {
    inline for (string_test_cases) |tuple| {
        var stream = std.io.fixed_buffer_stream("\"" ++ tuple[0] ++ "\"");
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        var json_reader = jsonReader(std.testing.allocator, stream.reader());
        defer json_reader.deinit();

        const token = try json_reader.next_alloc(arena.allocator(), .alloc_if_needed);
        const value = switch (token) {
            .string => |value| value,
            .allocated_string => |value| value,
            else => return error.ExpectedString,
        };
        try std.testing.expect_equal_strings(tuple[1], value);

        try std.testing.expect_equal(Token.end_of_document, try json_reader.next());
    }
}

const nesting_test_cases = .{
    .{ null, "[]" },
    .{ null, "{}" },
    .{ error.SyntaxError, "[}" },
    .{ error.SyntaxError, "{]" },
    .{ null, "[" ** 1000 ++ "]" ** 1000 },
    .{ null, "{\"\":" ** 1000 ++ "0" ++ "}" ** 1000 },
    .{ error.SyntaxError, "[" ** 1000 ++ "]" ** 999 ++ "}" },
    .{ error.SyntaxError, "{\"\":" ** 1000 ++ "0" ++ "}" ** 999 ++ "]" },
    .{ error.SyntaxError, "[" ** 1000 ++ "]" ** 1001 },
    .{ error.SyntaxError, "{\"\":" ** 1000 ++ "0" ++ "}" ** 1001 },
    .{ error.UnexpectedEndOfInput, "[" ** 1000 ++ "]" ** 999 },
    .{ error.UnexpectedEndOfInput, "{\"\":" ** 1000 ++ "0" ++ "}" ** 999 },
};

test "nesting" {
    inline for (nesting_test_cases) |tuple| {
        const maybe_error = tuple[0];
        const document_str = tuple[1];

        expect_maybe_error(document_str, maybe_error) catch |err| {
            std.debug.print("in json document: {s}\n", .{document_str});
            return err;
        };
    }
}

fn expect_maybe_error(document_str: []const u8, maybe_error: ?Error) !void {
    var scanner = JsonScanner.init_complete_input(std.testing.allocator, document_str);
    defer scanner.deinit();

    while (true) {
        const token = scanner.next() catch |err| {
            if (maybe_error) |expected_err| {
                if (err == expected_err) return;
            }
            return err;
        };
        if (token == .end_of_document) break;
    }
    if (maybe_error != null) return error.ExpectedError;
}

fn expect_equal_tokens(expected_token: Token, actual_token: Token) !void {
    try std.testing.expect_equal(std.meta.active_tag(expected_token), std.meta.active_tag(actual_token));
    switch (expected_token) {
        .number => |expected_value| {
            try std.testing.expect_equal_strings(expected_value, actual_token.number);
        },
        .string => |expected_value| {
            try std.testing.expect_equal_strings(expected_value, actual_token.string);
        },
        else => {},
    }
}

fn test_tiny_buffer_size(document_str: []const u8) !void {
    var tiny_stream = std.io.fixed_buffer_stream(document_str);
    var normal_stream = std.io.fixed_buffer_stream(document_str);

    var tiny_json_reader = JsonReader(1, @TypeOf(tiny_stream.reader())).init(std.testing.allocator, tiny_stream.reader());
    defer tiny_json_reader.deinit();
    var normal_json_reader = JsonReader(0x1000, @TypeOf(normal_stream.reader())).init(std.testing.allocator, normal_stream.reader());
    defer normal_json_reader.deinit();

    expect_equal_stream_of_tokens(&normal_json_reader, &tiny_json_reader) catch |err| {
        std.debug.print("in json document: {s}\n", .{document_str});
        return err;
    };
}
fn expect_equal_stream_of_tokens(control_json_reader: anytype, test_json_reader: anytype) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    while (true) {
        const control_token = try control_json_reader.next_alloc(arena.allocator(), .alloc_always);
        const test_token = try test_json_reader.next_alloc(arena.allocator(), .alloc_always);
        try expect_equal_tokens(control_token, test_token);
        if (control_token == .end_of_document) break;
        _ = arena.reset(.retain_capacity);
    }
}

test "BufferUnderrun" {
    try test_tiny_buffer_size(example_document_str);
    for (number_test_items) |number_str| {
        try test_tiny_buffer_size(number_str);
    }
    inline for (string_test_cases) |tuple| {
        try test_tiny_buffer_size("\"" ++ tuple[0] ++ "\"");
    }
}

test "validate" {
    try std.testing.expect_equal(true, try validate(std.testing.allocator, "{}"));
    try std.testing.expect_equal(true, try validate(std.testing.allocator, "[]"));
    try std.testing.expect_equal(false, try validate(std.testing.allocator, "[{[[[[{}]]]]}]"));
    try std.testing.expect_equal(false, try validate(std.testing.allocator, "{]"));
    try std.testing.expect_equal(false, try validate(std.testing.allocator, "[}"));
    try std.testing.expect_equal(false, try validate(std.testing.allocator, "{{{{[]}}}]"));
}

fn test_skip_value(s: []const u8) !void {
    var scanner = JsonScanner.init_complete_input(std.testing.allocator, s);
    defer scanner.deinit();
    try scanner.skip_value();
    try expect_equal_tokens(.end_of_document, try scanner.next());

    var stream = std.io.fixed_buffer_stream(s);
    var json_reader = jsonReader(std.testing.allocator, stream.reader());
    defer json_reader.deinit();
    try json_reader.skip_value();
    try expect_equal_tokens(.end_of_document, try json_reader.next());
}

test "skip_value" {
    try test_skip_value("false");
    try test_skip_value("true");
    try test_skip_value("null");
    try test_skip_value("42");
    try test_skip_value("42.0");
    try test_skip_value("\"foo\"");
    try test_skip_value("[101, 111, 121]");
    try test_skip_value("{}");
    try test_skip_value("{\"foo\": \"bar\\nbaz\"}");

    // An absurd number of nestings
    const nestings = 1000;
    try test_skip_value("[" ** nestings ++ "]" ** nestings);

    // Would a number token cause problems in a deeply-nested array?
    try test_skip_value("[" ** nestings ++ "0.118, 999, 881.99, 911.9, 725, 3" ++ "]" ** nestings);

    // Mismatched brace/square bracket
    try std.testing.expect_error(error.SyntaxError, test_skip_value("[102, 111, 111}"));
}

fn test_ensure_stack_capacity(do_ensure: bool) !void {
    var fail_alloc = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 1 });
    const failing_allocator = fail_alloc.allocator();

    const nestings = 999; // intentionally not a power of 2.
    var scanner = JsonScanner.init_complete_input(failing_allocator, "[" ** nestings ++ "]" ** nestings);
    defer scanner.deinit();

    if (do_ensure) {
        try scanner.ensure_total_stack_capacity(nestings);
    }

    try scanner.skip_value();
    try std.testing.expect_equal(Token.end_of_document, try scanner.next());
}
test "ensure_total_stack_capacity" {
    // Once to demonstrate failure.
    try std.testing.expect_error(error.OutOfMemory, test_ensure_stack_capacity(false));
    // Then to demonstrate it works.
    try test_ensure_stack_capacity(true);
}

fn test_diagnostics_from_source(expected_error: ?anyerror, line: u64, col: u64, byte_offset: u64, source: anytype) !void {
    var diagnostics = Diagnostics{};
    source.enable_diagnostics(&diagnostics);

    if (expected_error) |expected_err| {
        try std.testing.expect_error(expected_err, source.skip_value());
    } else {
        try source.skip_value();
        try std.testing.expect_equal(Token.end_of_document, try source.next());
    }
    try std.testing.expect_equal(line, diagnostics.get_line());
    try std.testing.expect_equal(col, diagnostics.get_column());
    try std.testing.expect_equal(byte_offset, diagnostics.get_byte_offset());
}
fn test_diagnostics(expected_error: ?anyerror, line: u64, col: u64, byte_offset: u64, s: []const u8) !void {
    var scanner = JsonScanner.init_complete_input(std.testing.allocator, s);
    defer scanner.deinit();
    try test_diagnostics_from_source(expected_error, line, col, byte_offset, &scanner);

    var tiny_stream = std.io.fixed_buffer_stream(s);
    var tiny_json_reader = JsonReader(1, @TypeOf(tiny_stream.reader())).init(std.testing.allocator, tiny_stream.reader());
    defer tiny_json_reader.deinit();
    try test_diagnostics_from_source(expected_error, line, col, byte_offset, &tiny_json_reader);

    var medium_stream = std.io.fixed_buffer_stream(s);
    var medium_json_reader = JsonReader(5, @TypeOf(medium_stream.reader())).init(std.testing.allocator, medium_stream.reader());
    defer medium_json_reader.deinit();
    try test_diagnostics_from_source(expected_error, line, col, byte_offset, &medium_json_reader);
}
test "enable_diagnostics" {
    try test_diagnostics(error.UnexpectedEndOfInput, 1, 1, 0, "");
    try test_diagnostics(null, 1, 3, 2, "[]");
    try test_diagnostics(null, 2, 2, 3, "[\n]");
    try test_diagnostics(null, 14, 2, example_document_str.len, example_document_str);

    try test_diagnostics(error.SyntaxError, 3, 1, 25,
        \\{
        \\  "common": "mistake",
        \\}
    );

    inline for ([_]comptime_int{ 5, 6, 7, 99 }) |reps| {
        // The error happens 1 byte before the end.
        const s = "[" ** reps ++ "}";
        try test_diagnostics(error.SyntaxError, 1, s.len, s.len - 1, s);
    }
}

test is_number_formatted_like_an_integer {
    try std.testing.expect(is_number_formatted_like_an_integer("0"));
    try std.testing.expect(is_number_formatted_like_an_integer("1"));
    try std.testing.expect(is_number_formatted_like_an_integer("123"));
    try std.testing.expect(!is_number_formatted_like_an_integer("-0"));
    try std.testing.expect(!is_number_formatted_like_an_integer("0.0"));
    try std.testing.expect(!is_number_formatted_like_an_integer("1.0"));
    try std.testing.expect(!is_number_formatted_like_an_integer("1.23"));
    try std.testing.expect(!is_number_formatted_like_an_integer("1e10"));
    try std.testing.expect(!is_number_formatted_like_an_integer("1E10"));
}
