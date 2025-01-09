const common = @import("./common.zig");
const intfromfloat = @import("./int_from_float.zig").intfromfloat;

pub const panic = common.panic;

comptime {
    @export(__fixunshfdi, .{ .name = "__fixunshfdi", .linkage = common.linkage, .visibility = common.visibility });
}

fn __fixunshfdi(a: f16) callconv(.C) u64 {
    return intfromfloat(u64, a);
}
