const common = @import("./common.zig");
const int_from_float = @import("./int_from_float.zig").int_from_float;

pub const panic = common.panic;

comptime {
    @export(__fixxfsi, .{ .name = "__fixxfsi", .linkage = common.linkage, .visibility = common.visibility });
}

fn __fixxfsi(a: f80) callconv(.C) i32 {
    return int_from_float(i32, a);
}
