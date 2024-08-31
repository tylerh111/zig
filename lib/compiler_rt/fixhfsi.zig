const common = @import("./common.zig");
const int_from_float = @import("./int_from_float.zig").int_from_float;

pub const panic = common.panic;

comptime {
    @export(__fixhfsi, .{ .name = "__fixhfsi", .linkage = common.linkage, .visibility = common.visibility });
}

fn __fixhfsi(a: f16) callconv(.C) i32 {
    return int_from_float(i32, a);
}
