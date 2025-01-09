export fn a() usize {
    return @embedfile("/root/foo").len;
}

// error
// target=native
//
//:2:23: error: embed of file outside package path: '/root/foo'
