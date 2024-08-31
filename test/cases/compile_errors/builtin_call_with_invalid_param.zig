export fn builtin_call_bool_function_inline_with_void() void {
    @call(.always_inline, boolFunction, .{{}});
}

fn bool_function(_: bool) void {}

// error
// backend=stage2
// target=native
//
// :2:43: error: expected type 'bool', found 'void'
// :5:20: note: parameter type declared here
