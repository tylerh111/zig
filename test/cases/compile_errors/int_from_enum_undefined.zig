export fn a() void {
    const E = enum {};
    var e: E = undefined;
    _ = &e;
    _ = @int_from_enum(e);
}

// error
// backend=stage2
// target=native
//
// :5:22: error: cannot use @int_from_enum on empty enum 'tmp.a.E'
// :2:15: note: enum declared here
