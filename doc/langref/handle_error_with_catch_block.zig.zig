const parse_u64 = @import("error_union_parsing_u64.zig").parse_u64;

fn do_athing(str: []u8) void {
    const number = parse_u64(str, 10) catch blk: {
        // do things
        break :blk 13;
    };
    _ = number; // number is now initialized
}

// syntax
