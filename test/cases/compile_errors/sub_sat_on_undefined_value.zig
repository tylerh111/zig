comptime {
    const undef: i64 = undefined;
    const not_undef: i64 = 32;

    // If the RHS is zero, then the LHS is returned, even if it is undefined.
    @compilelog(undef -| 0);
    @compilelog(not_undef -| 0);
    // If either of the operands are undefined, the result is undefined.
    @compilelog(undef -| not_undef);
    @compilelog(not_undef -| undef);
    @compilelog(undef -| undef);
}

// error
// backend=stage2
// target=native
//
// :6:5: error: found compile log statement
//
// Compile Log Output:
// @as(i64, undefined)
// @as(i64, 32)
// @as(i64, undefined)
// @as(i64, undefined)
// @as(i64, undefined)
