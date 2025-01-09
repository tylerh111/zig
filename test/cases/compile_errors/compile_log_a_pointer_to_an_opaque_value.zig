export fn entry() void {
    @compilelog(@as(*const anyopaque, @ptrcast(&entry)));
}

// error
// backend=stage2
// target=native
//
// :2:5: error: found compile log statement
//
// Compile Log Output:
// @as(*const anyopaque, @as(*const anyopaque, @ptrcast(tmp.entry)))
