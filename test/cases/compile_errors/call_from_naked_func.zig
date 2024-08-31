export fn runtime_call() callconv(.Naked) void {
    f();
}

export fn runtime_builtin_call() callconv(.Naked) void {
    @call(.auto, f, .{});
}

export fn comptime_call() callconv(.Naked) void {
    comptime f();
}

export fn comptime_builtin_call() callconv(.Naked) void {
    @call(.compile_time, f, .{});
}

fn f() void {}

// error
// backend=llvm
// target=native
//
// :2:6: error: runtime call not allowed in naked function
// :6:5: error: runtime @call not allowed in naked function
