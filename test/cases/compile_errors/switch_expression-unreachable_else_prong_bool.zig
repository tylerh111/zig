fn foo(x: bool) void {
    switch (x) {
        true => {},
        false => {},
        else => {},
    }
}
export fn entry() usize {
    return @size_of(@TypeOf(&foo));
}

// error
// backend=stage2
// target=native
//
// :5:14: error: unreachable else prong; all cases already handled
