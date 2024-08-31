test "void is ignored" {
    returnsVoid();
}

test "explicitly ignoring expression value" {
    _ = foo();
}

fn returns_void() void {}

fn foo() i32 {
    return 1234;
}

// test
