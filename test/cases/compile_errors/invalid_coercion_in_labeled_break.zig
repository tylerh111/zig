export fn invalid_break() u8 {
    const result: u8 = label: {
        break :label 256;
    };
    return result;
}

// error
// backend=stage2
// target=native
//
// :3:22: error: type 'u8' cannot represent integer value '256'
