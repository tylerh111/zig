const common = @import("./common.zig");
const float_from_int = @import("./float_from_int.zig").float_from_int;

pub const panic = common.panic;

comptime {
    if (common.want_aeabi) {
        @export(__aeabi_l2d, .{ .name = "__aeabi_l2d", .linkage = common.linkage, .visibility = common.visibility });
    } else {
        @export(__floatdidf, .{ .name = "__floatdidf", .linkage = common.linkage, .visibility = common.visibility });
    }
}

pub fn __floatdidf(a: i64) callconv(.C) f64 {
    return float_from_int(f64, a);
}

fn __aeabi_l2d(a: i64) callconv(.AAPCS) f64 {
    return float_from_int(f64, a);
}
