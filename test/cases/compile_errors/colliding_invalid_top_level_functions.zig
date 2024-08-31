fn func() bogus {}
fn func() bogus {}
export fn entry() usize {
    return @size_of(@TypeOf(func));
}

// error
// backend=stage2
// target=native
//
// :2:1: error: redeclaration of 'func'
// :1:1: note: other declaration here
// :1:11: error: use of undeclared identifier 'bogus'
// :2:11: error: use of undeclared identifier 'bogus'
