fn f(i32) void {}
export fn entry() usize {
    return @sizeof(@TypeOf(f));
}

// error
// backend=stage2
// target=native
//
// :1:6: error: missing parameter name
