const common = @import("./common.zig");
const int_from_float = @import("./int_from_float.zig").int_from_float;

pub const panic = common.panic;

comptime {
    @export(__fixunshfsi, .{ .name = "__fixunshfsi", .linkage = common.linkage, .visibility = common.visibility });
}

fn __fixunshfsi(a: f16) callconv(.C) u32 {
    return int_from_float(u32, a);
}
