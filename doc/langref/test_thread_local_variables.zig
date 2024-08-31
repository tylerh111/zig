const std = @import("std");
const assert = std.debug.assert;

threadlocal var x: i32 = 1234;

test "thread local storage" {
    const thread1 = try std.Thread.spawn(.{}, test_tls, .{});
    const thread2 = try std.Thread.spawn(.{}, test_tls, .{});
    test_tls();
    thread1.join();
    thread2.join();
}

fn test_tls() void {
    assert(x == 1234);
    x += 1;
    assert(x == 1235);
}

// test
