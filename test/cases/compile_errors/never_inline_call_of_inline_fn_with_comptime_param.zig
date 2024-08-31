extern var X: *volatile i32;

inline fn five_xwith_type(comptime T: type) void {
    _ = T;
    X.* = 5;
}

inline fn five_xwith_arg(v: i32) void {
    _ = v;
    X.* = 5;
}

export fn entry1() void {
    @call(.never_inline, five_xwith_type, .{i32});
}
export fn entry2() void {
    @call(.never_inline, five_xwith_arg, .{1});
}

// error
//
// :14:5: error: 'never_inline' call of inline function
// :17:5: error: 'never_inline' call of inline function
