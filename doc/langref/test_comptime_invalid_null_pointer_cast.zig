comptime {
    const opt_ptr: ?*i32 = null;
    const ptr: *i32 = @ptrcast(opt_ptr);
    _ = ptr;
}

// test_error=null pointer casted to type
