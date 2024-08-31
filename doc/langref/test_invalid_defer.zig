fn defer_invalid_example() !void {
    defer {
        return error.DeferError;
    }

    return error.DeferError;
}

// test_error=cannot return from defer expression
