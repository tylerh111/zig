export fn a() usize {
    return @embed_file("/root/foo").len;
}

// error
// target=native
//
//:2:23: error: embed of file outside package path: '/root/foo'
