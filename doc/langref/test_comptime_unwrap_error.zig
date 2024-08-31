comptime {
    const number = get_number_or_fail() catch unreachable;
    _ = number;
}

fn get_number_or_fail() !i32 {
    return error.UnableToReturnNumber;
}

// test_error=caught unexpected error 'UnableToReturnNumber'
