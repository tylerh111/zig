const common = @import("./common.zig");
const floatfromint = @import("./float_from_int.zig").floatfromint;

pub const panic = common.panic;

comptime {
    @export(__floatundixf, .{ .name = "__floatundixf", .linkage = common.linkage, .visibility = common.visibility });
}

fn __floatundixf(a: u64) callconv(.C) f80 {
    return floatfromint(f80, a);
}
