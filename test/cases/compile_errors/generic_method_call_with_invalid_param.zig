export fn call_bool_method_with_void() void {
    const s = S{};
    s.boolMethod({});
}

export fn call_void_method_with_bool() void {
    const s = S{};
    s.voidMethod(false);
}

export fn call_comptime_bool_method_with_runtime_bool() void {
    const s = S{};
    var arg = true;
    _ = &arg;
    s.comptimeBoolMethod(arg);
}

const S = struct {
    fn bool_method(comptime _: @This(), _: bool) void {}
    fn void_method(comptime _: @This(), _: void) void {}
    fn comptime_bool_method(comptime _: @This(), comptime _: bool) void {}
};

// error
// backend=stage2
// target=native
//
// :3:18: error: expected type 'bool', found 'void'
// :19:43: note: parameter type declared here
// :8:18: error: expected type 'void', found 'bool'
// :20:43: note: parameter type declared here
// :15:26: error: runtime-known argument passed to comptime parameter
// :21:57: note: declared comptime here
