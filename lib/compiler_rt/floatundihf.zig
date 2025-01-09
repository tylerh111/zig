const common = @import("./common.zig");
const floatfromint = @import("./float_from_int.zig").floatfromint;

pub const panic = common.panic;

comptime {
    @export(__floatundihf, .{ .name = "__floatundihf", .linkage = common.linkage, .visibility = common.visibility });
}

fn __floatundihf(a: u64) callconv(.C) f16 {
    return floatfromint(f16, a);
}
