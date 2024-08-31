export fn entry(x: i32) usize {
    return @int_from_ptr(x);
}

// error
// backend=stage2
// target=native
//
// :2:24: error: expected pointer, found 'i32'
