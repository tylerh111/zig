export fn returns() void {
    while (optional_return_error()) |_| {
        while (optional_return_error()) |_| {
            return;
        } else |_| {
            if (_ == error.optional_return_error) return;
        }
    }
}
fn optional_return_error() !?u32 {
    return error.optional_return_error;
}

// error
// backend=stage2
// target=native
//
// :6:17: error: '_' used as an identifier without @"_" syntax
