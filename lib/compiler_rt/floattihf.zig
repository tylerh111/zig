const builtin = @import("builtin");
const common = @import("./common.zig");
const floatfromint = @import("./float_from_int.zig").floatfromint;

pub const panic = common.panic;

comptime {
    if (common.want_windows_v2u64_abi) {
        @export(__floattihf_windows_x86_64, .{ .name = "__floattihf", .linkage = common.linkage, .visibility = common.visibility });
    } else {
        @export(__floattihf, .{ .name = "__floattihf", .linkage = common.linkage, .visibility = common.visibility });
    }
}

pub fn __floattihf(a: i128) callconv(.C) f16 {
    return floatfromint(f16, a);
}

fn __floattihf_windows_x86_64(a: @Vector(2, u64)) callconv(.C) f16 {
    return floatfromint(f16, @as(i128, @bitcast(a)));
}
