const std = @import("../std.zig");
const assert = std.debug.assert;
const utf8_decode = std.unicode.utf8_decode;
const utf8_encode = std.unicode.utf8_encode;

pub const ParseError = error{
    OutOfMemory,
    InvalidLiteral,
};

pub const ParsedCharLiteral = union(enum) {
    success: u21,
    failure: Error,
};

pub const Result = union(enum) {
    success,
    failure: Error,
};

pub const Error = union(enum) {
    /// The character after backslash is missing or not recognized.
    invalid_escape_character: usize,
    /// Expected hex digit at this index.
    expected_hex_digit: usize,
    /// Unicode escape sequence had no digits with rbrace at this index.
    empty_unicode_escape_sequence: usize,
    /// Expected hex digit or '}' at this index.
    expected_hex_digit_or_rbrace: usize,
    /// Invalid unicode codepoint at this index.
    invalid_unicode_codepoint: usize,
    /// Expected '{' at this index.
    expected_lbrace: usize,
    /// Expected '}' at this index.
    expected_rbrace: usize,
    /// Expected '\'' at this index.
    expected_single_quote: usize,
    /// The character at this index cannot be represented without an escape sequence.
    invalid_character: usize,
};

/// Only validates escape sequence characters.
/// Slice must be valid utf8 starting and ending with "'" and exactly one codepoint in between.
pub fn parse_char_literal(slice: []const u8) ParsedCharLiteral {
    assert(slice.len >= 3 and slice[0] == '\'' and slice[slice.len - 1] == '\'');

    switch (slice[1]) {
        '\\' => {
            var offset: usize = 1;
            const result = parse_escape_sequence(slice, &offset);
            if (result == .success and (offset + 1 != slice.len or slice[offset] != '\''))
                return .{ .failure = .{ .expected_single_quote = offset } };

            return result;
        },
        0 => return .{ .failure = .{ .invalid_character = 1 } },
        else => {
            const codepoint = utf8_decode(slice[1 .. slice.len - 1]) catch unreachable;
            return .{ .success = codepoint };
        },
    }
}

/// Parse an escape sequence from `slice[offset..]`. If parsing is successful,
/// offset is updated to reflect the characters consumed.
pub fn parse_escape_sequence(slice: []const u8, offset: *usize) ParsedCharLiteral {
    assert(slice.len > offset.*);
    assert(slice[offset.*] == '\\');

    if (slice.len == offset.* + 1)
        return .{ .failure = .{ .invalid_escape_character = offset.* + 1 } };

    offset.* += 2;
    switch (slice[offset.* - 1]) {
        'n' => return .{ .success = '\n' },
        'r' => return .{ .success = '\r' },
        '\\' => return .{ .success = '\\' },
        't' => return .{ .success = '\t' },
        '\'' => return .{ .success = '\'' },
        '"' => return .{ .success = '"' },
        'x' => {
            var value: u8 = 0;
            var i: usize = offset.*;
            while (i < offset.* + 2) : (i += 1) {
                if (i == slice.len) return .{ .failure = .{ .expected_hex_digit = i } };

                const c = slice[i];
                switch (c) {
                    '0'...'9' => {
                        value *= 16;
                        value += c - '0';
                    },
                    'a'...'f' => {
                        value *= 16;
                        value += c - 'a' + 10;
                    },
                    'A'...'F' => {
                        value *= 16;
                        value += c - 'A' + 10;
                    },
                    else => {
                        return .{ .failure = .{ .expected_hex_digit = i } };
                    },
                }
            }
            offset.* = i;
            return .{ .success = value };
        },
        'u' => {
            var i: usize = offset.*;
            if (i >= slice.len or slice[i] != '{') return .{ .failure = .{ .expected_lbrace = i } };
            i += 1;
            if (i >= slice.len) return .{ .failure = .{ .expected_hex_digit_or_rbrace = i } };
            if (slice[i] == '}') return .{ .failure = .{ .empty_unicode_escape_sequence = i } };

            var value: u32 = 0;
            while (i < slice.len) : (i += 1) {
                const c = slice[i];
                switch (c) {
                    '0'...'9' => {
                        value *= 16;
                        value += c - '0';
                    },
                    'a'...'f' => {
                        value *= 16;
                        value += c - 'a' + 10;
                    },
                    'A'...'F' => {
                        value *= 16;
                        value += c - 'A' + 10;
                    },
                    '}' => {
                        i += 1;
                        break;
                    },
                    else => return .{ .failure = .{ .expected_hex_digit_or_rbrace = i } },
                }
                if (value > 0x10ffff) {
                    return .{ .failure = .{ .invalid_unicode_codepoint = i } };
                }
            } else {
                return .{ .failure = .{ .expected_rbrace = i } };
            }
            offset.* = i;
            return .{ .success = @as(u21, @int_cast(value)) };
        },
        else => return .{ .failure = .{ .invalid_escape_character = offset.* - 1 } },
    }
}

test parse_char_literal {
    try std.testing.expect_equal(
        ParsedCharLiteral{ .success = 'a' },
        parse_char_literal("'a'"),
    );
    try std.testing.expect_equal(
        ParsedCharLiteral{ .success = 'ä' },
        parse_char_literal("'ä'"),
    );
    try std.testing.expect_equal(
        ParsedCharLiteral{ .success = 0 },
        parse_char_literal("'\\x00'"),
    );
    try std.testing.expect_equal(
        ParsedCharLiteral{ .success = 0x4f },
        parse_char_literal("'\\x4f'"),
    );
    try std.testing.expect_equal(
        ParsedCharLiteral{ .success = 0x4f },
        parse_char_literal("'\\x4F'"),
    );
    try std.testing.expect_equal(
        ParsedCharLiteral{ .success = 0x3041 },
        parse_char_literal("'ぁ'"),
    );
    try std.testing.expect_equal(
        ParsedCharLiteral{ .success = 0 },
        parse_char_literal("'\\u{0}'"),
    );
    try std.testing.expect_equal(
        ParsedCharLiteral{ .success = 0x3041 },
        parse_char_literal("'\\u{3041}'"),
    );
    try std.testing.expect_equal(
        ParsedCharLiteral{ .success = 0x7f },
        parse_char_literal("'\\u{7f}'"),
    );
    try std.testing.expect_equal(
        ParsedCharLiteral{ .success = 0x7fff },
        parse_char_literal("'\\u{7FFF}'"),
    );
    try std.testing.expect_equal(
        ParsedCharLiteral{ .failure = .{ .expected_hex_digit = 4 } },
        parse_char_literal("'\\x0'"),
    );
    try std.testing.expect_equal(
        ParsedCharLiteral{ .failure = .{ .expected_single_quote = 5 } },
        parse_char_literal("'\\x000'"),
    );
    try std.testing.expect_equal(
        ParsedCharLiteral{ .failure = .{ .invalid_escape_character = 2 } },
        parse_char_literal("'\\y'"),
    );
    try std.testing.expect_equal(
        ParsedCharLiteral{ .failure = .{ .expected_lbrace = 3 } },
        parse_char_literal("'\\u'"),
    );
    try std.testing.expect_equal(
        ParsedCharLiteral{ .failure = .{ .expected_lbrace = 3 } },
        parse_char_literal("'\\uFFFF'"),
    );
    try std.testing.expect_equal(
        ParsedCharLiteral{ .failure = .{ .empty_unicode_escape_sequence = 4 } },
        parse_char_literal("'\\u{}'"),
    );
    try std.testing.expect_equal(
        ParsedCharLiteral{ .failure = .{ .invalid_unicode_codepoint = 9 } },
        parse_char_literal("'\\u{FFFFFF}'"),
    );
    try std.testing.expect_equal(
        ParsedCharLiteral{ .failure = .{ .expected_hex_digit_or_rbrace = 8 } },
        parse_char_literal("'\\u{FFFF'"),
    );
    try std.testing.expect_equal(
        ParsedCharLiteral{ .failure = .{ .expected_single_quote = 9 } },
        parse_char_literal("'\\u{FFFF}x'"),
    );
    try std.testing.expect_equal(
        ParsedCharLiteral{ .failure = .{ .invalid_character = 1 } },
        parse_char_literal("'\x00'"),
    );
}

/// Parses `bytes` as a Zig string literal and writes the result to the std.io.Writer type.
/// Asserts `bytes` has '"' at beginning and end.
pub fn parse_write(writer: anytype, bytes: []const u8) error{OutOfMemory}!Result {
    assert(bytes.len >= 2 and bytes[0] == '"' and bytes[bytes.len - 1] == '"');

    var index: usize = 1;
    while (true) {
        const b = bytes[index];

        switch (b) {
            '\\' => {
                const escape_char_index = index + 1;
                const result = parse_escape_sequence(bytes, &index);
                switch (result) {
                    .success => |codepoint| {
                        if (bytes[escape_char_index] == 'u') {
                            var buf: [4]u8 = undefined;
                            const len = utf8_encode(codepoint, &buf) catch {
                                return Result{ .failure = .{ .invalid_unicode_codepoint = escape_char_index + 1 } };
                            };
                            try writer.write_all(buf[0..len]);
                        } else {
                            try writer.write_byte(@as(u8, @int_cast(codepoint)));
                        }
                    },
                    .failure => |err| return Result{ .failure = err },
                }
            },
            '\n' => return Result{ .failure = .{ .invalid_character = index } },
            '"' => return Result.success,
            else => {
                try writer.write_byte(b);
                index += 1;
            },
        }
    }
}

/// Higher level API. Does not return extra info about parse errors.
/// Caller owns returned memory.
pub fn parse_alloc(allocator: std.mem.Allocator, bytes: []const u8) ParseError![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();

    switch (try parse_write(buf.writer(), bytes)) {
        .success => return buf.to_owned_slice(),
        .failure => return error.InvalidLiteral,
    }
}

test parse_alloc {
    const expect = std.testing.expect;
    const expect_error = std.testing.expect_error;
    const eql = std.mem.eql;

    var fixed_buf_mem: [64]u8 = undefined;
    var fixed_buf_alloc = std.heap.FixedBufferAllocator.init(&fixed_buf_mem);
    const alloc = fixed_buf_alloc.allocator();

    try expect_error(error.InvalidLiteral, parse_alloc(alloc, "\"\\x6\""));
    try expect(eql(u8, "foo\nbar", try parse_alloc(alloc, "\"foo\\nbar\"")));
    try expect(eql(u8, "\x12foo", try parse_alloc(alloc, "\"\\x12foo\"")));
    try expect(eql(u8, "bytes\u{1234}foo", try parse_alloc(alloc, "\"bytes\\u{1234}foo\"")));
    try expect(eql(u8, "foo", try parse_alloc(alloc, "\"foo\"")));
    try expect(eql(u8, "foo", try parse_alloc(alloc, "\"f\x6f\x6f\"")));
    try expect(eql(u8, "f💯", try parse_alloc(alloc, "\"f\u{1f4af}\"")));
}
