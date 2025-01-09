comptime {
    const undef: i64 = undefined;
    const not_undef: i64 = 32;

    // If either of the operands are zero, the result is zero.
    @compilelog(undef *% 0);
    @compilelog(not_undef *% 0);
    @compilelog(0 *% undef);
    @compilelog(0 *% not_undef);

    // If either of the operands are one, result is the other operand.
    @compilelog(undef *% 1);
    @compilelog(not_undef *% 1);
    @compilelog(1 *% undef);
    @compilelog(1 *% not_undef);

    // If either of the operands are undefined, result is undefined.
    @compilelog(undef *% 2);
    @compilelog(2 *% undef);
}

// error
// backend=stage2
// target=native
//
// :6:5: error: found compile log statement
//
// Compile Log Output:
// @as(i64, 0)
// @as(i64, 0)
// @as(i64, 0)
// @as(i64, 0)
// @as(i64, undefined)
// @as(i64, 32)
// @as(i64, undefined)
// @as(i64, 32)
// @as(i64, undefined)
// @as(i64, undefined)
