const std = @import("std");
const expect = std.testing.expect;
const mem = std.mem;

test "peer resolve int widening" {
    const a: i8 = 12;
    const b: i16 = 34;
    const c = a + b;
    try expect(c == 46);
    try expect(@TypeOf(c) == i16);
}

test "peer resolve arrays of different size to const slice" {
    try expect(mem.eql(u8, bool_to_str(true), "true"));
    try expect(mem.eql(u8, bool_to_str(false), "false"));
    try comptime expect(mem.eql(u8, bool_to_str(true), "true"));
    try comptime expect(mem.eql(u8, bool_to_str(false), "false"));
}
fn bool_to_str(b: bool) []const u8 {
    return if (b) "true" else "false";
}

test "peer resolve array and const slice" {
    try test_peer_resolve_array_const_slice(true);
    try comptime test_peer_resolve_array_const_slice(true);
}
fn test_peer_resolve_array_const_slice(b: bool) !void {
    const value1 = if (b) "aoeu" else @as([]const u8, "zz");
    const value2 = if (b) @as([]const u8, "zz") else "aoeu";
    try expect(mem.eql(u8, value1, "aoeu"));
    try expect(mem.eql(u8, value2, "zz"));
}

test "peer type resolution: ?T and T" {
    try expect(peer_type_tand_optional_t(true, false).? == 0);
    try expect(peer_type_tand_optional_t(false, false).? == 3);
    comptime {
        try expect(peer_type_tand_optional_t(true, false).? == 0);
        try expect(peer_type_tand_optional_t(false, false).? == 3);
    }
}
fn peer_type_tand_optional_t(c: bool, b: bool) ?usize {
    if (c) {
        return if (b) null else @as(usize, 0);
    }

    return @as(usize, 3);
}

test "peer type resolution: *[0]u8 and []const u8" {
    try expect(peer_type_empty_array_and_slice(true, "hi").len == 0);
    try expect(peer_type_empty_array_and_slice(false, "hi").len == 1);
    comptime {
        try expect(peer_type_empty_array_and_slice(true, "hi").len == 0);
        try expect(peer_type_empty_array_and_slice(false, "hi").len == 1);
    }
}
fn peer_type_empty_array_and_slice(a: bool, slice: []const u8) []const u8 {
    if (a) {
        return &[_]u8{};
    }

    return slice[0..1];
}
test "peer type resolution: *[0]u8, []const u8, and anyerror![]u8" {
    {
        var data = "hi".*;
        const slice = data[0..];
        try expect((try peer_type_empty_array_and_slice_and_error(true, slice)).len == 0);
        try expect((try peer_type_empty_array_and_slice_and_error(false, slice)).len == 1);
    }
    comptime {
        var data = "hi".*;
        const slice = data[0..];
        try expect((try peer_type_empty_array_and_slice_and_error(true, slice)).len == 0);
        try expect((try peer_type_empty_array_and_slice_and_error(false, slice)).len == 1);
    }
}
fn peer_type_empty_array_and_slice_and_error(a: bool, slice: []u8) anyerror![]u8 {
    if (a) {
        return &[_]u8{};
    }

    return slice[0..1];
}

test "peer type resolution: *const T and ?*T" {
    const a: *const usize = @ptrFromInt(0x123456780);
    const b: ?*usize = @ptrFromInt(0x123456780);
    try expect(a == b);
    try expect(b == a);
}

test "peer type resolution: error union switch" {
    // The non-error and error cases are only peers if the error case is just a switch expression;
    // the pattern `if (x) {...} else |err| blk: { switch (err) {...} }` does not consider the
    // non-error and error case to be peers.
    var a: error{ A, B, C }!u32 = 0;
    _ = &a;
    const b = if (a) |x|
        x + 3
    else |err| switch (err) {
        error.A => 0,
        error.B => 1,
        error.C => null,
    };
    try expect(@TypeOf(b) == ?u32);

    // The non-error and error cases are only peers if the error case is just a switch expression;
    // the pattern `x catch |err| blk: { switch (err) {...} }` does not consider the unwrapped `x`
    // and error case to be peers.
    const c = a catch |err| switch (err) {
        error.A => 0,
        error.B => 1,
        error.C => null,
    };
    try expect(@TypeOf(c) == ?u32);
}

// test
