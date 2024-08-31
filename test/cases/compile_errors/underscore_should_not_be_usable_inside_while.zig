export fn returns() void {
    while (optional_return()) |_| {
        while (optional_return()) |_| {
            return _;
        }
    }
}
fn optional_return() ?u32 {
    return 1;
}

// error
// backend=stage2
// target=native
//
// :4:20: error: '_' used as an identifier without @"_" syntax
