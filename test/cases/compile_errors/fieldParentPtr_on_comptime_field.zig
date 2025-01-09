const T = struct {
    comptime a: u32 = 2,
};
pub export fn entry1() void {
    @offsetof(T, "a");
}
pub export fn entry2() void {
    @as(*T, @fieldparentptr("a", undefined));
}

// error
// backend=stage2
// target=native
//
// :5:5: error: no offset available for comptime field
// :8:29: error: cannot get @fieldparentptr of a comptime field
