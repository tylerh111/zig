const builtin = @import("builtin");
const common = @import("./common.zig");
const float_from_int = @import("./float_from_int.zig").float_from_int;

pub const panic = common.panic;

comptime {
    if (common.want_windows_v2u64_abi) {
        @export(__floatuntixf_windows_x86_64, .{ .name = "__floatuntixf", .linkage = common.linkage, .visibility = common.visibility });
    } else {
        @export(__floatuntixf, .{ .name = "__floatuntixf", .linkage = common.linkage, .visibility = common.visibility });
    }
}

pub fn __floatuntixf(a: u128) callconv(.C) f80 {
    return float_from_int(f80, a);
}

fn __floatuntixf_windows_x86_64(a: @Vector(2, u64)) callconv(.C) f80 {
    return float_from_int(f80, @as(u128, @bit_cast(a)));
}
