const common = @import("./common.zig");
const int_from_float = @import("./int_from_float.zig").int_from_float;

pub const panic = common.panic;

comptime {
    @export(__fixxfdi, .{ .name = "__fixxfdi", .linkage = common.linkage, .visibility = common.visibility });
}

fn __fixxfdi(a: f80) callconv(.C) i64 {
    return int_from_float(i64, a);
}
