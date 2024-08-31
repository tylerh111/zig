const common = @import("./common.zig");
const int_from_float = @import("./int_from_float.zig").int_from_float;

pub const panic = common.panic;

comptime {
    @export(__fixunshfdi, .{ .name = "__fixunshfdi", .linkage = common.linkage, .visibility = common.visibility });
}

fn __fixunshfdi(a: f16) callconv(.C) u64 {
    return int_from_float(u64, a);
}
