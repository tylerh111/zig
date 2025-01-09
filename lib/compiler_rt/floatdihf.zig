const common = @import("./common.zig");
const floatfromint = @import("./float_from_int.zig").floatfromint;

pub const panic = common.panic;

comptime {
    @export(__floatdihf, .{ .name = "__floatdihf", .linkage = common.linkage, .visibility = common.visibility });
}

fn __floatdihf(a: i64) callconv(.C) f16 {
    return floatfromint(f16, a);
}
