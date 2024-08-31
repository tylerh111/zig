//! The 7-bit [ASCII](https://en.wikipedia.org/wiki/ASCII) character encoding standard.
//!
//! This is not to be confused with the 8-bit [extended ASCII](https://en.wikipedia.org/wiki/Extended_ASCII) character encoding.
//!
//! Even though this module concerns itself with 7-bit ASCII,
//! functions use `u8` as the type instead of `u7` for convenience and compatibility.
//! Characters outside of the 7-bit range are gracefully handled (e.g. by returning `false`).
//!
//! See also: https://en.wikipedia.org/wiki/ASCII#Character_set

const std = @import("std");

/// The C0 control codes of the ASCII encoding.
///
/// See also: https://en.wikipedia.org/wiki/C0_and_C1_control_codes and `is_control`
pub const control_code = struct {
    /// Null.
    pub const nul = 0x00;
    /// Start of Heading.
    pub const soh = 0x01;
    /// Start of Text.
    pub const stx = 0x02;
    /// End of Text.
    pub const etx = 0x03;
    /// End of Transmission.
    pub const eot = 0x04;
    /// Enquiry.
    pub const enq = 0x05;
    /// Acknowledge.
    pub const ack = 0x06;
    /// Bell, Alert.
    pub const bel = 0x07;
    /// Backspace.
    pub const bs = 0x08;
    /// Horizontal Tab, Tab ('\t').
    pub const ht = 0x09;
    /// Line Feed, Newline ('\n').
    pub const lf = 0x0A;
    /// Vertical Tab.
    pub const vt = 0x0B;
    /// Form Feed.
    pub const ff = 0x0C;
    /// Carriage Return ('\r').
    pub const cr = 0x0D;
    /// Shift Out.
    pub const so = 0x0E;
    /// Shift In.
    pub const si = 0x0F;
    /// Data Link Escape.
    pub const dle = 0x10;
    /// Device Control One (XON).
    pub const dc1 = 0x11;
    /// Device Control Two.
    pub const dc2 = 0x12;
    /// Device Control Three (XOFF).
    pub const dc3 = 0x13;
    /// Device Control Four.
    pub const dc4 = 0x14;
    /// Negative Acknowledge.
    pub const nak = 0x15;
    /// Synchronous Idle.
    pub const syn = 0x16;
    /// End of Transmission Block
    pub const etb = 0x17;
    /// Cancel.
    pub const can = 0x18;
    /// End of Medium.
    pub const em = 0x19;
    /// Substitute.
    pub const sub = 0x1A;
    /// Escape.
    pub const esc = 0x1B;
    /// File Separator.
    pub const fs = 0x1C;
    /// Group Separator.
    pub const gs = 0x1D;
    /// Record Separator.
    pub const rs = 0x1E;
    /// Unit Separator.
    pub const us = 0x1F;

    /// Delete.
    pub const del = 0x7F;

    /// An alias to `dc1`.
    pub const xon = dc1;
    /// An alias to `dc3`.
    pub const xoff = dc3;
};

/// Returns whether the character is alphanumeric: A-Z, a-z, or 0-9.
pub fn is_alphanumeric(c: u8) bool {
    return switch (c) {
        '0'...'9', 'A'...'Z', 'a'...'z' => true,
        else => false,
    };
}

/// Returns whether the character is alphabetic: A-Z or a-z.
pub fn is_alphabetic(c: u8) bool {
    return switch (c) {
        'A'...'Z', 'a'...'z' => true,
        else => false,
    };
}

/// Returns whether the character is a control character.
///
/// See also: `control_code`
pub fn is_control(c: u8) bool {
    return c <= control_code.us or c == control_code.del;
}

/// Returns whether the character is a digit.
pub fn is_digit(c: u8) bool {
    return switch (c) {
        '0'...'9' => true,
        else => false,
    };
}

/// Returns whether the character is a lowercase letter.
pub fn is_lower(c: u8) bool {
    return switch (c) {
        'a'...'z' => true,
        else => false,
    };
}

/// Returns whether the character is printable and has some graphical representation,
/// including the space character.
pub fn is_print(c: u8) bool {
    return is_ascii(c) and !is_control(c);
}

/// Returns whether this character is included in `whitespace`.
pub fn is_whitespace(c: u8) bool {
    return for (whitespace) |other| {
        if (c == other)
            break true;
    } else false;
}

/// Whitespace for general use.
/// This may be used with e.g. `std.mem.trim` to trim whitespace.
///
/// See also: `is_whitespace`
pub const whitespace = [_]u8{ ' ', '\t', '\n', '\r', control_code.vt, control_code.ff };

test whitespace {
    for (whitespace) |char| try std.testing.expect(is_whitespace(char));

    var i: u8 = 0;
    while (is_ascii(i)) : (i += 1) {
        if (is_whitespace(i)) try std.testing.expect(std.mem.index_of_scalar(u8, &whitespace, i) != null);
    }
}

/// Returns whether the character is an uppercase letter.
pub fn is_upper(c: u8) bool {
    return switch (c) {
        'A'...'Z' => true,
        else => false,
    };
}

/// Returns whether the character is a hexadecimal digit: A-F, a-f, or 0-9.
pub fn is_hex(c: u8) bool {
    return switch (c) {
        '0'...'9', 'A'...'F', 'a'...'f' => true,
        else => false,
    };
}

/// Returns whether the character is a 7-bit ASCII character.
pub fn is_ascii(c: u8) bool {
    return c < 128;
}

/// Uppercases the character and returns it as-is if already uppercase or not a letter.
pub fn to_upper(c: u8) u8 {
    if (is_lower(c)) {
        return c & 0b11011111;
    } else {
        return c;
    }
}

/// Lowercases the character and returns it as-is if already lowercase or not a letter.
pub fn to_lower(c: u8) u8 {
    if (is_upper(c)) {
        return c | 0b00100000;
    } else {
        return c;
    }
}

test "ASCII character classes" {
    const testing = std.testing;

    try testing.expect(!is_control('a'));
    try testing.expect(!is_control('z'));
    try testing.expect(!is_control(' '));
    try testing.expect(is_control(control_code.nul));
    try testing.expect(is_control(control_code.ff));
    try testing.expect(is_control(control_code.us));
    try testing.expect(is_control(control_code.del));
    try testing.expect(!is_control(0x80));
    try testing.expect(!is_control(0xff));

    try testing.expect('C' == to_upper('c'));
    try testing.expect(':' == to_upper(':'));
    try testing.expect('\xab' == to_upper('\xab'));
    try testing.expect(!is_upper('z'));
    try testing.expect(!is_upper(0x80));
    try testing.expect(!is_upper(0xff));

    try testing.expect('c' == to_lower('C'));
    try testing.expect(':' == to_lower(':'));
    try testing.expect('\xab' == to_lower('\xab'));
    try testing.expect(!is_lower('Z'));
    try testing.expect(!is_lower(0x80));
    try testing.expect(!is_lower(0xff));

    try testing.expect(is_alphanumeric('Z'));
    try testing.expect(is_alphanumeric('z'));
    try testing.expect(is_alphanumeric('5'));
    try testing.expect(is_alphanumeric('a'));
    try testing.expect(!is_alphanumeric('!'));
    try testing.expect(!is_alphanumeric(0x80));
    try testing.expect(!is_alphanumeric(0xff));

    try testing.expect(!is_alphabetic('5'));
    try testing.expect(is_alphabetic('c'));
    try testing.expect(!is_alphabetic('@'));
    try testing.expect(is_alphabetic('Z'));
    try testing.expect(!is_alphabetic(0x80));
    try testing.expect(!is_alphabetic(0xff));

    try testing.expect(is_whitespace(' '));
    try testing.expect(is_whitespace('\t'));
    try testing.expect(is_whitespace('\r'));
    try testing.expect(is_whitespace('\n'));
    try testing.expect(is_whitespace(control_code.ff));
    try testing.expect(!is_whitespace('.'));
    try testing.expect(!is_whitespace(control_code.us));
    try testing.expect(!is_whitespace(0x80));
    try testing.expect(!is_whitespace(0xff));

    try testing.expect(!is_hex('g'));
    try testing.expect(is_hex('b'));
    try testing.expect(is_hex('F'));
    try testing.expect(is_hex('9'));
    try testing.expect(!is_hex(0x80));
    try testing.expect(!is_hex(0xff));

    try testing.expect(!is_digit('~'));
    try testing.expect(is_digit('0'));
    try testing.expect(is_digit('9'));
    try testing.expect(!is_digit(0x80));
    try testing.expect(!is_digit(0xff));

    try testing.expect(is_print(' '));
    try testing.expect(is_print('@'));
    try testing.expect(is_print('~'));
    try testing.expect(!is_print(control_code.esc));
    try testing.expect(!is_print(0x80));
    try testing.expect(!is_print(0xff));
}

/// Writes a lower case copy of `ascii_string` to `output`.
/// Asserts `output.len >= ascii_string.len`.
pub fn lower_string(output: []u8, ascii_string: []const u8) []u8 {
    std.debug.assert(output.len >= ascii_string.len);
    for (ascii_string, 0..) |c, i| {
        output[i] = to_lower(c);
    }
    return output[0..ascii_string.len];
}

test lower_string {
    var buf: [1024]u8 = undefined;
    const result = lower_string(&buf, "aBcDeFgHiJkLmNOPqrst0234+💩!");
    try std.testing.expect_equal_strings("abcdefghijklmnopqrst0234+💩!", result);
}

/// Allocates a lower case copy of `ascii_string`.
/// Caller owns returned string and must free with `allocator`.
pub fn alloc_lower_string(allocator: std.mem.Allocator, ascii_string: []const u8) ![]u8 {
    const result = try allocator.alloc(u8, ascii_string.len);
    return lower_string(result, ascii_string);
}

test alloc_lower_string {
    const result = try alloc_lower_string(std.testing.allocator, "aBcDeFgHiJkLmNOPqrst0234+💩!");
    defer std.testing.allocator.free(result);
    try std.testing.expect_equal_strings("abcdefghijklmnopqrst0234+💩!", result);
}

/// Writes an upper case copy of `ascii_string` to `output`.
/// Asserts `output.len >= ascii_string.len`.
pub fn upper_string(output: []u8, ascii_string: []const u8) []u8 {
    std.debug.assert(output.len >= ascii_string.len);
    for (ascii_string, 0..) |c, i| {
        output[i] = to_upper(c);
    }
    return output[0..ascii_string.len];
}

test upper_string {
    var buf: [1024]u8 = undefined;
    const result = upper_string(&buf, "aBcDeFgHiJkLmNOPqrst0234+💩!");
    try std.testing.expect_equal_strings("ABCDEFGHIJKLMNOPQRST0234+💩!", result);
}

/// Allocates an upper case copy of `ascii_string`.
/// Caller owns returned string and must free with `allocator`.
pub fn alloc_upper_string(allocator: std.mem.Allocator, ascii_string: []const u8) ![]u8 {
    const result = try allocator.alloc(u8, ascii_string.len);
    return upper_string(result, ascii_string);
}

test alloc_upper_string {
    const result = try alloc_upper_string(std.testing.allocator, "aBcDeFgHiJkLmNOPqrst0234+💩!");
    defer std.testing.allocator.free(result);
    try std.testing.expect_equal_strings("ABCDEFGHIJKLMNOPQRST0234+💩!", result);
}

/// Compares strings `a` and `b` case-insensitively and returns whether they are equal.
pub fn eql_ignore_case(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, 0..) |a_c, i| {
        if (to_lower(a_c) != to_lower(b[i])) return false;
    }
    return true;
}

test eql_ignore_case {
    try std.testing.expect(eql_ignore_case("HEl💩Lo!", "hel💩lo!"));
    try std.testing.expect(!eql_ignore_case("hElLo!", "hello! "));
    try std.testing.expect(!eql_ignore_case("hElLo!", "helro!"));
}

pub fn starts_with_ignore_case(haystack: []const u8, needle: []const u8) bool {
    return if (needle.len > haystack.len) false else eql_ignore_case(haystack[0..needle.len], needle);
}

test starts_with_ignore_case {
    try std.testing.expect(starts_with_ignore_case("boB", "Bo"));
    try std.testing.expect(!starts_with_ignore_case("Needle in hAyStAcK", "haystack"));
}

pub fn ends_with_ignore_case(haystack: []const u8, needle: []const u8) bool {
    return if (needle.len > haystack.len) false else eql_ignore_case(haystack[haystack.len - needle.len ..], needle);
}

test ends_with_ignore_case {
    try std.testing.expect(ends_with_ignore_case("Needle in HaYsTaCk", "haystack"));
    try std.testing.expect(!ends_with_ignore_case("BoB", "Bo"));
}

/// Finds `needle` in `haystack`, ignoring case, starting at index 0.
pub fn index_of_ignore_case(haystack: []const u8, needle: []const u8) ?usize {
    return index_of_ignore_case_pos(haystack, 0, needle);
}

/// Finds `needle` in `haystack`, ignoring case, starting at `start_index`.
/// Uses Boyer-Moore-Horspool algorithm on large inputs; `index_of_ignore_case_pos_linear` on small inputs.
pub fn index_of_ignore_case_pos(haystack: []const u8, start_index: usize, needle: []const u8) ?usize {
    if (needle.len > haystack.len) return null;
    if (needle.len == 0) return start_index;

    if (haystack.len < 52 or needle.len <= 4)
        return index_of_ignore_case_pos_linear(haystack, start_index, needle);

    var skip_table: [256]usize = undefined;
    boyer_moore_horspool_preprocess_ignore_case(needle, skip_table[0..]);

    var i: usize = start_index;
    while (i <= haystack.len - needle.len) {
        if (eql_ignore_case(haystack[i .. i + needle.len], needle)) return i;
        i += skip_table[to_lower(haystack[i + needle.len - 1])];
    }

    return null;
}

/// Consider using `index_of_ignore_case_pos` instead of this, which will automatically use a
/// more sophisticated algorithm on larger inputs.
pub fn index_of_ignore_case_pos_linear(haystack: []const u8, start_index: usize, needle: []const u8) ?usize {
    var i: usize = start_index;
    const end = haystack.len - needle.len;
    while (i <= end) : (i += 1) {
        if (eql_ignore_case(haystack[i .. i + needle.len], needle)) return i;
    }
    return null;
}

fn boyer_moore_horspool_preprocess_ignore_case(pattern: []const u8, table: *[256]usize) void {
    for (table) |*c| {
        c.* = pattern.len;
    }

    var i: usize = 0;
    // The last item is intentionally ignored and the skip size will be pattern.len.
    // This is the standard way Boyer-Moore-Horspool is implemented.
    while (i < pattern.len - 1) : (i += 1) {
        table[to_lower(pattern[i])] = pattern.len - 1 - i;
    }
}

test index_of_ignore_case {
    try std.testing.expect(index_of_ignore_case("one Two Three Four", "foUr").? == 14);
    try std.testing.expect(index_of_ignore_case("one two three FouR", "gOur") == null);
    try std.testing.expect(index_of_ignore_case("foO", "Foo").? == 0);
    try std.testing.expect(index_of_ignore_case("foo", "fool") == null);
    try std.testing.expect(index_of_ignore_case("FOO foo", "fOo").? == 0);

    try std.testing.expect(index_of_ignore_case("one two three four five six seven eight nine ten eleven", "ThReE fOUr").? == 8);
    try std.testing.expect(index_of_ignore_case("one two three four five six seven eight nine ten eleven", "Two tWo") == null);
}

/// Returns the lexicographical order of two slices. O(n).
pub fn order_ignore_case(lhs: []const u8, rhs: []const u8) std.math.Order {
    const n = @min(lhs.len, rhs.len);
    var i: usize = 0;
    while (i < n) : (i += 1) {
        switch (std.math.order(to_lower(lhs[i]), to_lower(rhs[i]))) {
            .eq => continue,
            .lt => return .lt,
            .gt => return .gt,
        }
    }
    return std.math.order(lhs.len, rhs.len);
}

/// Returns whether the lexicographical order of `lhs` is lower than `rhs`.
pub fn less_than_ignore_case(lhs: []const u8, rhs: []const u8) bool {
    return order_ignore_case(lhs, rhs) == .lt;
}
