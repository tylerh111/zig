const common = @import("./common.zig");
const float_from_int = @import("./float_from_int.zig").float_from_int;

pub const panic = common.panic;

comptime {
    if (common.want_ppc_abi) {
        @export(__floatditf, .{ .name = "__floatdikf", .linkage = common.linkage, .visibility = common.visibility });
    } else if (common.want_sparc_abi) {
        @export(_Qp_xtoq, .{ .name = "_Qp_xtoq", .linkage = common.linkage, .visibility = common.visibility });
    }
    @export(__floatditf, .{ .name = "__floatditf", .linkage = common.linkage, .visibility = common.visibility });
}

pub fn __floatditf(a: i64) callconv(.C) f128 {
    return float_from_int(f128, a);
}

fn _Qp_xtoq(c: *f128, a: i64) callconv(.C) void {
    c.* = float_from_int(f128, a);
}
