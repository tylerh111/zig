const builtin = @import("builtin");
const common = @import("./common.zig");
const int_from_float = @import("./int_from_float.zig").int_from_float;

pub const panic = common.panic;

comptime {
    if (common.want_windows_v2u64_abi) {
        @export(__fixxfti_windows_x86_64, .{ .name = "__fixxfti", .linkage = common.linkage, .visibility = common.visibility });
    } else {
        @export(__fixxfti, .{ .name = "__fixxfti", .linkage = common.linkage, .visibility = common.visibility });
    }
}

pub fn __fixxfti(a: f80) callconv(.C) i128 {
    return int_from_float(i128, a);
}

const v2u64 = @Vector(2, u64);

fn __fixxfti_windows_x86_64(a: f80) callconv(.C) v2u64 {
    return @bit_cast(int_from_float(i128, a));
}
