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
    const foo = getFoo: {
        var foo = try tryToAllocateFoo(allocator);
        errdefer deallocateFoo(allocator, foo); // Only lasts until the end of getFoo

        // Calls deallocateFoo on error
        foo.data = try getFooData();

        break :getFoo foo;
    };

    // Outside of the scope of the errdefer, so
    // deallocateFoo will not be called here
    if (param > 1337) return error.InvalidParam;

    return foo;
}

test "createFoo" {
    try std.testing.expectError(error.InvalidParam, createFoo(std.testing.allocator, 2468));
}

// test_error=1 tests leaked memory
