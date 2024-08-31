test "void is ignored" {
    returns_void();
}

test "explicitly ignoring expression value" {
    _ = foo();
}

fn returns_void() void {}

fn foo() i32 {
    return 1234;
}

// test
