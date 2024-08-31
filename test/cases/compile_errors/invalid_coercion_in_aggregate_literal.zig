export fn invalid_array_elem() u8 {
    const array_literal = [1]u8{@as(u8, 256)};
    return array_literal[0];
}

export fn invalid_tuple_elem() u8 {
    const tuple_literal = struct { u8 }{@as(u8, 256)};
    return tuple_literal[0];
}

export fn invalid_struct_field() u8 {
    const struct_literal = struct { field: u8 }{ .field = @as(u8, 256) };
    return struct_literal.field;
}

// error
// backend=stage2
// target=native
//
// :2:41: error: type 'u8' cannot represent integer value '256'
// :7:49: error: type 'u8' cannot represent integer value '256'
// :12:67: error: type 'u8' cannot represent integer value '256'
