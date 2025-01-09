export fn entry() void {
    const E = enum(u8) {
        a,
        b,
        c,
        d,
    };
    var x: E = .a;
    _ = @atomicrmw(E, &x, .Add, .b, .seq_cst);
}

// error
// backend=stage2
// target=native
//
// :9:28: error: @atomicrmw with enum only allowed with .Xchg
