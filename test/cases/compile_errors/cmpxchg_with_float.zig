export fn entry() void {
    var x: f32 = 0;
    _ = @cmpxchg_weak(f32, &x, 1, 2, .seq_cst, .seq_cst);
}

// error
// backend=stage2
// target=native
//
// :3:22: error: expected bool, integer, enum, or pointer type; found 'f32'
