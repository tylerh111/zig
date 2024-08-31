pub fn main() void {
    var x: i8 = undefined;
    const maybe_x = by_ptr(&x);
    assert(maybe_x != null);
    maybe_x.?.* = -1;
    assert(x == -1);
}

fn by_ptr(x: *i8) ?*i8 {
    return x;
}

fn assert(ok: bool) void {
    if (!ok) unreachable;
}

// run
//
