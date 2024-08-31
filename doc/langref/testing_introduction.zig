const std = @import("std");

test "expect add_one adds one to 41" {

    // The Standard Library contains useful functions to help create tests.
    // `expect` is a function that verifies its argument is true.
    // It will return an error if its argument is false to indicate a failure.
    // `try` is used to return an error to the test runner to notify it that the test failed.
    try std.testing.expect(add_one(41) == 42);
}

test add_one {
    // A test name can also be written using an identifier.
    // This is a doctest, and serves as documentation for `add_one`.
    try std.testing.expect(add_one(41) == 42);
}

/// The function `add_one` adds one to the number given as its argument.
fn add_one(number: i32) i32 {
    return number + 1;
}

// test
