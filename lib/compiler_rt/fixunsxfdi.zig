const common = @import("./common.zig");
const intfromfloat = @import("./int_from_float.zig").intfromfloat;

pub const panic = common.panic;

comptime {
    @export(__fixunsxfdi, .{ .name = "__fixunsxfdi", .linkage = common.linkage, .visibility = common.visibility });
}

fn __fixunsxfdi(a: f80) callconv(.C) u64 {
    return intfromfloat(u64, a);
}
