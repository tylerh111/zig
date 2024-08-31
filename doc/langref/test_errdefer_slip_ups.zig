const std = @import("std");
const Allocator = std.mem.Allocator;

const Foo = struct {
    data: u32,
};

fn try_to_allocate_foo(allocator: Allocator) !*Foo {
    return allocator.create(Foo);
}

fn deallocate_foo(allocator: Allocator, foo: *Foo) void {
    allocator.destroy(foo);
}

fn get_foo_data() !u32 {
    return 666;
}

fn create_foo(allocator: Allocator, param: i32) !*Foo {
    const foo = get_foo: {
        var foo = try try_to_allocate_foo(allocator);
        errdefer deallocate_foo(allocator, foo); // Only lasts until the end of get_foo

        // Calls deallocate_foo on error
        foo.data = try get_foo_data();

        break :get_foo foo;
    };

    // Outside of the scope of the errdefer, so
    // deallocate_foo will not be called here
    if (param > 1337) return error.InvalidParam;

    return foo;
}

test "create_foo" {
    try std.testing.expect_error(error.InvalidParam, create_foo(std.testing.allocator, 2468));
}

// test_error=1 tests leaked memory
