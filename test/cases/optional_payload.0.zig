pub fn main() void {
    var x: u32 = undefined;
    const maybe_x = by_ptr(&x);
    assert(maybe_x != null);
    maybe_x.?.* = 123;
    assert(x == 123);
}

fn by_ptr(x: *u32) ?*u32 {
    return x;
}

fn assert(ok: bool) void {
    if (!ok) unreachable;
}

// run
// target=x86_64-linux,x86_64-macos
//
