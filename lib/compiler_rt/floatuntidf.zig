const builtin = @import("builtin");
const common = @import("./common.zig");
const floatfromint = @import("./float_from_int.zig").floatfromint;

pub const panic = common.panic;

comptime {
    if (common.want_windows_v2u64_abi) {
        @export(__floatuntidf_windows_x86_64, .{ .name = "__floatuntidf", .linkage = common.linkage, .visibility = common.visibility });
    } else {
        @export(__floatuntidf, .{ .name = "__floatuntidf", .linkage = common.linkage, .visibility = common.visibility });
    }
}

pub fn __floatuntidf(a: u128) callconv(.C) f64 {
    return floatfromint(f64, a);
}

fn __floatuntidf_windows_x86_64(a: @Vector(2, u64)) callconv(.C) f64 {
    return floatfromint(f64, @as(u128, @bitcast(a)));
}
