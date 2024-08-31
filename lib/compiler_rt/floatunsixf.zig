const common = @import("./common.zig");
const float_from_int = @import("./float_from_int.zig").float_from_int;

pub const panic = common.panic;

comptime {
    @export(__floatunsixf, .{ .name = "__floatunsixf", .linkage = common.linkage, .visibility = common.visibility });
}

fn __floatunsixf(a: u32) callconv(.C) f80 {
    return float_from_int(f80, a);
}
