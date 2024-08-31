const common = @import("./common.zig");
const float_from_int = @import("./float_from_int.zig").float_from_int;

pub const panic = common.panic;

comptime {
    @export(__floatundixf, .{ .name = "__floatundixf", .linkage = common.linkage, .visibility = common.visibility });
}

fn __floatundixf(a: u64) callconv(.C) f80 {
    return float_from_int(f80, a);
}
