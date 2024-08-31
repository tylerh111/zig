const std = @import("std");

test "expect_equal demo" {
    const expected: i32 = 42;
    const actual = 42;

    // The first argument to `expect_equal` is the known, expected, result.
    // The second argument is the result of some expression.
    // The actual's type is casted to the type of expected.
    try std.testing.expect_equal(expected, actual);
}

test "expect_error demo" {
    const expected_error = error.DemoError;
    const actual_error_union: anyerror!void = error.DemoError;

    // `expect_error` will fail when the actual error is different than
    // the expected error.
    try std.testing.expect_error(expected_error, actual_error_union);
}

// test
