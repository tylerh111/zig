const std = @import("std");

extern var foo: i32;
extern var bar: i32;

test {
    try std.testing.expect(@intfromptr(&foo) % 4 == 0);
    try std.testing.expect(@intfromptr(&bar) % 4096 == 0);
}
