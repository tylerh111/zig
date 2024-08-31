const x = @import("builtin").bogus;
export fn entry() usize {
    return @size_of(@TypeOf(x));
}

// error
// backend=stage2
// target=native
//
// :1:29: error: root struct of file 'builtin' has no member named 'bogus'
// note: struct declared here
