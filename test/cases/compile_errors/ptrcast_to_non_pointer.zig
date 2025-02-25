export fn entry(a: *i32) usize {
    return @ptrcast(a);
}

// error
// backend=llvm
// target=native
//
// :2:12: error: expected pointer type, found 'usize'
