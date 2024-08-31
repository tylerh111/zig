const common = @import("./common.zig");
const int_from_float = @import("./int_from_float.zig").int_from_float;

pub const panic = common.panic;

comptime {
    @export(__fixhfdi, .{ .name = "__fixhfdi", .linkage = common.linkage, .visibility = common.visibility });
}

fn __fixhfdi(a: f16) callconv(.C) i64 {
    return int_from_float(i64, a);
}
