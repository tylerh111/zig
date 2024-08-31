const parse_u64 = @import("error_union_parsing_u64.zig").parse_u64;

fn do_athing(str: []u8) !void {
    const number = try parse_u64(str, 10);
    _ = number; // ...
}

// syntax
