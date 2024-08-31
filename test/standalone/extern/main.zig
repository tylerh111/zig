const assert = @import("std").debug.assert;

const update_hidden = @extern(*const fn (u32) callconv(.C) void, .{ .name = "update_hidden" });
const get_hidden = @extern(*const fn () callconv(.C) u32, .{ .name = "get_hidden" });

const T = extern struct { x: u32 };

test {
    const mut_val_ptr = @extern(*f64, .{ .name = "mut_val" });
    const const_val_ptr = @extern(*const T, .{ .name = "const_val" });

    assert(get_hidden() == 0);
    update_hidden(123);
    assert(get_hidden() == 123);

    assert(mut_val_ptr.* == 1.23);
    mut_val_ptr.* = 10.0;
    assert(mut_val_ptr.* == 10.0);

    assert(const_val_ptr.x == 42);
}
