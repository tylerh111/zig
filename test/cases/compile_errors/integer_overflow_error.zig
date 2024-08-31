const x: u8 = 300;
export fn entry() usize {
    return @size_of(@TypeOf(x));
}

// error
// backend=stage2
// target=native
//
// :1:15: error: type 'u8' cannot represent integer value '300'
