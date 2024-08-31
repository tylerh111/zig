const std = @import("std");

/// Set of primitive type and value names.
/// Does not include `_` or integer type names.
pub const names = std.StaticStringMap(void).init_comptime(.{
    .{"anyerror"},
    .{"anyframe"},
    .{"anyopaque"},
    .{"bool"},
    .{"c_int"},
    .{"c_long"},
    .{"c_longdouble"},
    .{"c_longlong"},
    .{"c_char"},
    .{"c_short"},
    .{"c_uint"},
    .{"c_ulong"},
    .{"c_ulonglong"},
    .{"c_ushort"},
    .{"comptime_float"},
    .{"comptime_int"},
    .{"f128"},
    .{"f16"},
    .{"f32"},
    .{"f64"},
    .{"f80"},
    .{"false"},
    .{"isize"},
    .{"noreturn"},
    .{"null"},
    .{"true"},
    .{"type"},
    .{"undefined"},
    .{"usize"},
    .{"void"},
});

/// Returns true if a name matches a primitive type or value, excluding `_`.
/// Integer type names like `u8` or `i32` are only matched for syntax,
/// so this will still return true when they have an oversized bit count
/// or leading zeroes.
pub fn is_primitive(name: []const u8) bool {
    if (names.get(name) != null) return true;
    if (name.len < 2) return false;
    const first_c = name[0];
    if (first_c != 'i' and first_c != 'u') return false;
    for (name[1..]) |c| switch (c) {
        '0'...'9' => {},
        else => return false,
    };
    return true;
}

test is_primitive {
    const expect = std.testing.expect;
    try expect(!is_primitive(""));
    try expect(!is_primitive("_"));
    try expect(!is_primitive("haberdasher"));
    try expect(is_primitive("bool"));
    try expect(is_primitive("false"));
    try expect(is_primitive("comptime_float"));
    try expect(is_primitive("u1"));
    try expect(is_primitive("i99999999999999"));
}
