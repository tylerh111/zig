const Foo = struct {};
fn do_something_with_foo(foo: *Foo) void {
    _ = foo;
}

fn do_athing(optional_foo: ?*Foo) void {
    // do some stuff

    if (optional_foo) |foo| {
        do_something_with_foo(foo);
    }

    // do some stuff
}

// syntax
