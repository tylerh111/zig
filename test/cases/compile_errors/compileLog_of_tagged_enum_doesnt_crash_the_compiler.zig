const Bar = union(enum(u32)) {
    X: i32 = 1,
};

fn test_compile_log(x: Bar) void {
    @compileLog(x);
}

pub export fn entry() void {
    comptime test_compile_log(Bar{ .X = 123 });
    _ = &test_compile_log;
}

// error
// backend=stage2
// target=native
//
// :6:5: error: found compile log statement
//
// Compile Log Output:
// @as(tmp.Bar, .{ .X = 123 })
// @as(tmp.Bar, [runtime value])
