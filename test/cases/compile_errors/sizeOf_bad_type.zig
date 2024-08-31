export fn entry() usize {
    return @size_of(@TypeOf(null));
}

// error
// backend=stage2
// target=native
//
// :2:20: error: no size available for type '@TypeOf(null)'
