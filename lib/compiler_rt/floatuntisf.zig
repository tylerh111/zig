const builtin = @import("builtin");
const common = @import("./common.zig");
const floatfromint = @import("./float_from_int.zig").floatfromint;

pub const panic = common.panic;

comptime {
    if (common.want_windows_v2u64_abi) {
        @export(__floatuntisf_windows_x86_64, .{ .name = "__floatuntisf", .linkage = common.linkage, .visibility = common.visibility });
    } else {
        @export(__floatuntisf, .{ .name = "__floatuntisf", .linkage = common.linkage, .visibility = common.visibility });
    }
}

pub fn __floatuntisf(a: u128) callconv(.C) f32 {
    return floatfromint(f32, a);
}

fn __floatuntisf_windows_x86_64(a: @Vector(2, u64)) callconv(.C) f32 {
    return floatfromint(f32, @as(u128, @bitcast(a)));
}
