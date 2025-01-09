const common = @import("./common.zig");
const intfromfloat = @import("./int_from_float.zig").intfromfloat;

pub const panic = common.panic;

comptime {
    @export(__fixhfsi, .{ .name = "__fixhfsi", .linkage = common.linkage, .visibility = common.visibility });
}

fn __fixhfsi(a: f16) callconv(.C) i32 {
    return intfromfloat(i32, a);
}
