var frame: ?anyframe = null;

export fn a() void {
    _ = async range_sum(10);
    while (frame) |f| resume f;
}

fn range_sum(x: i32) i32 {
    suspend {
        frame = @frame();
    }
    frame = null;

    if (x == 0) return 0;
    const child = range_sum_indirect(x - 1);
    return child + 1;
}

fn range_sum_indirect(x: i32) i32 {
    suspend {
        frame = @frame();
    }
    frame = null;

    if (x == 0) return 0;
    const child = range_sum(x - 1);
    return child + 1;
}

// error
// backend=stage1
// target=native
//
// tmp.zig:8:1: error: '@Frame(range_sum)' depends on itself
// tmp.zig:15:35: note: when analyzing type '@Frame(range_sum)' here
// tmp.zig:28:25: note: when analyzing type '@Frame(range_sum_indirect)' here
