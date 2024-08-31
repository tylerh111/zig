const common = @import("./common.zig");
const float_from_int = @import("./float_from_int.zig").float_from_int;

pub const panic = common.panic;

comptime {
    if (common.want_aeabi) {
        @export(__aeabi_ui2f, .{ .name = "__aeabi_ui2f", .linkage = common.linkage, .visibility = common.visibility });
    } else {
        @export(__floatunsisf, .{ .name = "__floatunsisf", .linkage = common.linkage, .visibility = common.visibility });
    }
}

pub fn __floatunsisf(a: u32) callconv(.C) f32 {
    return float_from_int(f32, a);
}

fn __aeabi_ui2f(a: u32) callconv(.AAPCS) f32 {
    return float_from_int(f32, a);
}
