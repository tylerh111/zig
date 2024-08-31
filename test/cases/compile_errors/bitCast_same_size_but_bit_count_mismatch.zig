export fn entry(byte: u8) void {
    const oops: u7 = @bit_cast(byte);
    _ = oops;
}

// error
// backend=stage2
// target=native
//
// :2:22: error: @bit_cast size mismatch: destination type 'u7' has 7 bits but source type 'u8' has 8 bits
