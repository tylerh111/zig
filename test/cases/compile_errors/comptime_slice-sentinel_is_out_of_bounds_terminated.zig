export fn foo_array() void {
    comptime {
        var target = [_:0]u8{ 'a', 'b', 'c', 'd' } ++ [_]u8{undefined} ** 10;
        const slice = target[0..15 :1];
        _ = slice;
    }
}
export fn foo_ptr_array() void {
    comptime {
        var buf = [_:0]u8{ 'a', 'b', 'c', 'd' } ++ [_]u8{undefined} ** 10;
        var target = &buf;
        const slice = target[0..15 :0];
        _ = slice;
    }
}
export fn foo_vector_const_ptr_special_base_array() void {
    comptime {
        var buf = [_:0]u8{ 'a', 'b', 'c', 'd' } ++ [_]u8{undefined} ** 10;
        var target: [*]u8 = &buf;
        const slice = target[0..15 :0];
        _ = slice;
    }
}
export fn foo_vector_const_ptr_special_ref() void {
    comptime {
        var buf = [_:0]u8{ 'a', 'b', 'c', 'd' } ++ [_]u8{undefined} ** 10;
        var target: [*]u8 = @ptr_cast(&buf);
        const slice = target[0..15 :0];
        _ = slice;
    }
}
export fn foo_cvector_const_ptr_special_base_array() void {
    comptime {
        var buf = [_:0]u8{ 'a', 'b', 'c', 'd' } ++ [_]u8{undefined} ** 10;
        var target: [*c]u8 = &buf;
        const slice = target[0..15 :0];
        _ = slice;
    }
}
export fn foo_cvector_const_ptr_special_ref() void {
    comptime {
        var buf = [_:0]u8{ 'a', 'b', 'c', 'd' } ++ [_]u8{undefined} ** 10;
        var target: [*c]u8 = @ptr_cast(&buf);
        const slice = target[0..15 :0];
        _ = slice;
    }
}
export fn foo_slice() void {
    comptime {
        var buf = [_:0]u8{ 'a', 'b', 'c', 'd' } ++ [_]u8{undefined} ** 10;
        var target: []u8 = &buf;
        const slice = target[0..15 :0];
        _ = slice;
    }
}

// error
// backend=stage2
// target=native
//
// :4:33: error: slice end index 15 exceeds bounds of containing decl of type '[14:0]u8'
// :12:33: error: slice end index 15 exceeds bounds of containing decl of type '[14:0]u8'
// :20:33: error: slice end index 15 exceeds bounds of containing decl of type '[14:0]u8'
// :28:33: error: slice end index 15 exceeds bounds of containing decl of type '[14:0]u8'
// :36:33: error: slice end index 15 exceeds bounds of containing decl of type '[14:0]u8'
// :44:33: error: slice end index 15 exceeds bounds of containing decl of type '[14:0]u8'
// :52:33: error: end index 15 out of bounds for slice of length 14
