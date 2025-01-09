const builtin = @import("builtin");
const common = @import("./common.zig");
const floatfromint = @import("./float_from_int.zig").floatfromint;

pub const panic = common.panic;

comptime {
    if (common.want_windows_v2u64_abi) {
        @export(__floattidf_windows_x86_64, .{ .name = "__floattidf", .linkage = common.linkage, .visibility = common.visibility });
    } else {
        @export(__floattidf, .{ .name = "__floattidf", .linkage = common.linkage, .visibility = common.visibility });
    }
}

pub fn __floattidf(a: i128) callconv(.C) f64 {
    return floatfromint(f64, a);
}

fn __floattidf_windows_x86_64(a: @Vector(2, u64)) callconv(.C) f64 {
    return floatfromint(f64, @as(i128, @bitcast(a)));
}
