const common = @import("./common.zig");
const intfromfloat = @import("./int_from_float.zig").intfromfloat;

pub const panic = common.panic;

comptime {
    @export(__fixxfsi, .{ .name = "__fixxfsi", .linkage = common.linkage, .visibility = common.visibility });
}

fn __fixxfsi(a: f80) callconv(.C) i32 {
    return intfromfloat(i32, a);
}
