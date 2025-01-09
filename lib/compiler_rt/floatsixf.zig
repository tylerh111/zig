const common = @import("./common.zig");
const floatfromint = @import("./float_from_int.zig").floatfromint;

pub const panic = common.panic;

comptime {
    @export(__floatsixf, .{ .name = "__floatsixf", .linkage = common.linkage, .visibility = common.visibility });
}

fn __floatsixf(a: i32) callconv(.C) f80 {
    return floatfromint(f80, a);
}
