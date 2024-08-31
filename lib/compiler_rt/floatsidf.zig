const common = @import("./common.zig");
const float_from_int = @import("./float_from_int.zig").float_from_int;

pub const panic = common.panic;

comptime {
    if (common.want_aeabi) {
        @export(__aeabi_i2d, .{ .name = "__aeabi_i2d", .linkage = common.linkage, .visibility = common.visibility });
    } else {
        @export(__floatsidf, .{ .name = "__floatsidf", .linkage = common.linkage, .visibility = common.visibility });
    }
}

pub fn __floatsidf(a: i32) callconv(.C) f64 {
    return float_from_int(f64, a);
}

fn __aeabi_i2d(a: i32) callconv(.AAPCS) f64 {
    return float_from_int(f64, a);
}
