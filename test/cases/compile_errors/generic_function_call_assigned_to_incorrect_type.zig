pub export fn entry() void {
    var res: []i32 = undefined;
    res = my_alloc(i32);
}
fn my_alloc(comptime arg: type) anyerror!arg {
    unreachable;
}

// error
// backend=stage2
// target=native
//
// :3:18: error: expected type '[]i32', found 'anyerror!i32'
