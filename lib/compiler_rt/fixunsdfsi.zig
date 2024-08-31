const common = @import("./common.zig");
const int_from_float = @import("./int_from_float.zig").int_from_float;

pub const panic = common.panic;

comptime {
    if (common.want_aeabi) {
        @export(__aeabi_d2uiz, .{ .name = "__aeabi_d2uiz", .linkage = common.linkage, .visibility = common.visibility });
    } else {
        @export(__fixunsdfsi, .{ .name = "__fixunsdfsi", .linkage = common.linkage, .visibility = common.visibility });
    }
}

pub fn __fixunsdfsi(a: f64) callconv(.C) u32 {
    return int_from_float(u32, a);
}

fn __aeabi_d2uiz(a: f64) callconv(.AAPCS) u32 {
    return int_from_float(u32, a);
}
