const common = @import("./common.zig");
const intfromfloat = @import("./int_from_float.zig").intfromfloat;

pub const panic = common.panic;

comptime {
    @export(__fixhfdi, .{ .name = "__fixhfdi", .linkage = common.linkage, .visibility = common.visibility });
}

fn __fixhfdi(a: f16) callconv(.C) i64 {
    return intfromfloat(i64, a);
}
