export fn entry(x: i32) usize {
    return @intfromptr(x);
}

// error
// backend=stage2
// target=native
//
// :2:24: error: expected pointer, found 'i32'
