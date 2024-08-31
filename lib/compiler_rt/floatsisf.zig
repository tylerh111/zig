const common = @import("./common.zig");
const float_from_int = @import("./float_from_int.zig").float_from_int;

pub const panic = common.panic;

comptime {
    if (common.want_aeabi) {
        @export(__aeabi_i2f, .{ .name = "__aeabi_i2f", .linkage = common.linkage, .visibility = common.visibility });
    } else {
        @export(__floatsisf, .{ .name = "__floatsisf", .linkage = common.linkage, .visibility = common.visibility });
    }
}

pub fn __floatsisf(a: i32) callconv(.C) f32 {
    return float_from_int(f32, a);
}

fn __aeabi_i2f(a: i32) callconv(.AAPCS) f32 {
    return float_from_int(f32, a);
}
