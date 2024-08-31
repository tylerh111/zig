const builtin = @import("builtin");
const common = @import("./common.zig");
const int_from_float = @import("./int_from_float.zig").int_from_float;

pub const panic = common.panic;

comptime {
    if (common.want_windows_v2u64_abi) {
        @export(__fixtfti_windows_x86_64, .{ .name = "__fixtfti", .linkage = common.linkage, .visibility = common.visibility });
    } else {
        if (common.want_ppc_abi)
            @export(__fixtfti, .{ .name = "__fixkfti", .linkage = common.linkage, .visibility = common.visibility });
        @export(__fixtfti, .{ .name = "__fixtfti", .linkage = common.linkage, .visibility = common.visibility });
    }
}

pub fn __fixtfti(a: f128) callconv(.C) i128 {
    return int_from_float(i128, a);
}

const v2u64 = @Vector(2, u64);

fn __fixtfti_windows_x86_64(a: f128) callconv(.C) v2u64 {
    return @bit_cast(int_from_float(i128, a));
}
