const common = @import("./common.zig");
const intfromfloat = @import("./int_from_float.zig").intfromfloat;

pub const panic = common.panic;

comptime {
    @export(__fixxfdi, .{ .name = "__fixxfdi", .linkage = common.linkage, .visibility = common.visibility });
}

fn __fixxfdi(a: f80) callconv(.C) i64 {
    return intfromfloat(i64, a);
}
