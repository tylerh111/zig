const std = @import("std");

extern var foo: i32;
extern var bar: i32;

test {
    try std.testing.expect(@int_from_ptr(&foo) % 4 == 0);
    try std.testing.expect(@int_from_ptr(&bar) % 4096 == 0);
}
