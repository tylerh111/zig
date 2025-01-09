export fn entry() usize {
    return @alignof(noreturn);
}

// error
// backend=stage2
// target=native
//
// :2:21: error: no align available for type 'noreturn'
