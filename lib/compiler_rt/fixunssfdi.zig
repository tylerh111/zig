const common = @import("./common.zig");
const int_from_float = @import("./int_from_float.zig").int_from_float;

pub const panic = common.panic;

comptime {
    if (common.want_aeabi) {
        @export(__aeabi_f2ulz, .{ .name = "__aeabi_f2ulz", .linkage = common.linkage, .visibility = common.visibility });
    } else {
        @export(__fixunssfdi, .{ .name = "__fixunssfdi", .linkage = common.linkage, .visibility = common.visibility });
    }
}

pub fn __fixunssfdi(a: f32) callconv(.C) u64 {
    return int_from_float(u64, a);
}

fn __aeabi_f2ulz(a: f32) callconv(.AAPCS) u64 {
    return int_from_float(u64, a);
}
