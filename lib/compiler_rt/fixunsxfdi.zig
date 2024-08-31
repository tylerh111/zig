const common = @import("./common.zig");
const int_from_float = @import("./int_from_float.zig").int_from_float;

pub const panic = common.panic;

comptime {
    @export(__fixunsxfdi, .{ .name = "__fixunsxfdi", .linkage = common.linkage, .visibility = common.visibility });
}

fn __fixunsxfdi(a: f80) callconv(.C) u64 {
    return int_from_float(u64, a);
}
