pub fn test_tricky_defer() !void {
    defer can_fail() catch {};

    defer try can_fail();

    const a = maybe_int() orelse return;
}

fn can_fail() anyerror!void {}

pub fn maybe_int() ?i32 {
    return 0;
}

export fn entry() usize {
    return @size_of(@TypeOf(test_tricky_defer));
}

// error
// backend=stage2
// target=native
//
// :4:11: error: 'try' not allowed inside defer expression
// :4:5: note: defer expression here
