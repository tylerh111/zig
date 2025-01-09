pub fn main() void {
    var opt_ptr: ?*i32 = null;
    _ = &opt_ptr;
    const ptr: *i32 = @ptrcast(opt_ptr);
    _ = ptr;
}

// exe=fail
