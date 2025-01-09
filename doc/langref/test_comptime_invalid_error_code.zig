comptime {
    const err = error.AnError;
    const number = @intfromerror(err) + 10;
    const invalid_err = @errorfromint(number);
    _ = invalid_err;
}

// test_error=integer value '11' represents no error
