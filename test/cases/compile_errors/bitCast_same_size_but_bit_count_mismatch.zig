export fn entry(byte: u8) void {
    const oops: u7 = @bitcast(byte);
    _ = oops;
}

// error
// backend=stage2
// target=native
//
// :2:22: error: @bitcast size mismatch: destination type 'u7' has 7 bits but source type 'u8' has 8 bits
