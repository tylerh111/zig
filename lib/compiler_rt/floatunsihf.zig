const common = @import("./common.zig");
const float_from_int = @import("./float_from_int.zig").float_from_int;

pub const panic = common.panic;

comptime {
    @export(__floatunsihf, .{ .name = "__floatunsihf", .linkage = common.linkage, .visibility = common.visibility });
}

pub fn __floatunsihf(a: u32) callconv(.C) f16 {
    return float_from_int(f16, a);
}
