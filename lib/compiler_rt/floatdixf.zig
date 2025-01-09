const common = @import("./common.zig");
const floatfromint = @import("./float_from_int.zig").floatfromint;

pub const panic = common.panic;

comptime {
    @export(__floatdixf, .{ .name = "__floatdixf", .linkage = common.linkage, .visibility = common.visibility });
}

fn __floatdixf(a: i64) callconv(.C) f80 {
    return floatfromint(f80, a);
}
