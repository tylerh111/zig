pub fn main() void {
    var x: u32 = undefined;
    const maybe_x = by_ptr(&x);
    assert(maybe_x == null);
}

fn by_ptr(x: *u32) ?*u32 {
    _ = x;
    return null;
}

fn assert(ok: bool) void {
    if (!ok) unreachable;
}

// run
//
