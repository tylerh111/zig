export fn a() void {
    const E = enum {};
    var e: E = undefined;
    _ = &e;
    _ = @intfromenum(e);
}

// error
// backend=stage2
// target=native
//
// :5:22: error: cannot use @intfromenum on empty enum 'tmp.a.E'
// :2:15: note: enum declared here
