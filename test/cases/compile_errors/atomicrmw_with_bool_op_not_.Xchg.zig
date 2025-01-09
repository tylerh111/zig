export fn entry() void {
    var x = false;
    _ = @atomicrmw(bool, &x, .Add, true, .seq_cst);
}

// error
// backend=stage2
// target=native
//
// :3:31: error: @atomicrmw with bool only allowed with .Xchg
