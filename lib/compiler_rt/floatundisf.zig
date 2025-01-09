const common = @import("./common.zig");
const floatfromint = @import("./float_from_int.zig").floatfromint;

pub const panic = common.panic;

comptime {
    if (common.want_aeabi) {
        @export(__aeabi_ul2f, .{ .name = "__aeabi_ul2f", .linkage = common.linkage, .visibility = common.visibility });
    } else {
        @export(__floatundisf, .{ .name = "__floatundisf", .linkage = common.linkage, .visibility = common.visibility });
    }
}

pub fn __floatundisf(a: u64) callconv(.C) f32 {
    return floatfromint(f32, a);
}

fn __aeabi_ul2f(a: u64) callconv(.AAPCS) f32 {
    return floatfromint(f32, a);
}
