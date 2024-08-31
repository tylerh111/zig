const common = @import("./common.zig");
const float_from_int = @import("./float_from_int.zig").float_from_int;

pub const panic = common.panic;

comptime {
    if (common.want_ppc_abi) {
        @export(__floatunsitf, .{ .name = "__floatunsikf", .linkage = common.linkage, .visibility = common.visibility });
    } else if (common.want_sparc_abi) {
        @export(_Qp_uitoq, .{ .name = "_Qp_uitoq", .linkage = common.linkage, .visibility = common.visibility });
    }
    @export(__floatunsitf, .{ .name = "__floatunsitf", .linkage = common.linkage, .visibility = common.visibility });
}

pub fn __floatunsitf(a: u32) callconv(.C) f128 {
    return float_from_int(f128, a);
}

fn _Qp_uitoq(c: *f128, a: u32) callconv(.C) void {
    c.* = float_from_int(f128, a);
}
