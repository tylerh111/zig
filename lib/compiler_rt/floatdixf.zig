const common = @import("./common.zig");
const float_from_int = @import("./float_from_int.zig").float_from_int;

pub const panic = common.panic;

comptime {
    @export(__floatdixf, .{ .name = "__floatdixf", .linkage = common.linkage, .visibility = common.visibility });
}

fn __floatdixf(a: i64) callconv(.C) f80 {
    return float_from_int(f80, a);
}
