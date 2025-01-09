export fn entry() bool {
    return @hasfield(i32, "hi");
}

// error
// backend=stage2
// target=native
//
// :2:22: error: type 'i32' does not support '@hasfield'
