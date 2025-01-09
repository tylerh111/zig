const common = @import("./common.zig");
const floatfromint = @import("./float_from_int.zig").floatfromint;

pub const panic = common.panic;

comptime {
    @export(__floatunsixf, .{ .name = "__floatunsixf", .linkage = common.linkage, .visibility = common.visibility });
}

fn __floatunsixf(a: u32) callconv(.C) f80 {
    return floatfromint(f80, a);
}
