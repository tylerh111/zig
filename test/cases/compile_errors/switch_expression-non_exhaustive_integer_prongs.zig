fn foo(x: u8) void {
    switch (x) {
        0 => {},
    }
}
export fn entry() usize {
    return @size_of(@TypeOf(&foo));
}

// error
// backend=stage2
// target=native
//
// :2:5: error: switch must handle all possibilities
