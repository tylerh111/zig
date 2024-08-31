const common = @import("./common.zig");
const float_from_int = @import("./float_from_int.zig").float_from_int;

pub const panic = common.panic;

comptime {
    if (common.want_aeabi) {
        @export(__aeabi_ul2d, .{ .name = "__aeabi_ul2d", .linkage = common.linkage, .visibility = common.visibility });
    } else {
        @export(__floatundidf, .{ .name = "__floatundidf", .linkage = common.linkage, .visibility = common.visibility });
    }
}

pub fn __floatundidf(a: u64) callconv(.C) f64 {
    return float_from_int(f64, a);
}

fn __aeabi_ul2d(a: u64) callconv(.AAPCS) f64 {
    return float_from_int(f64, a);
}
