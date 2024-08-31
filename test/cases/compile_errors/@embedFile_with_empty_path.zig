const resource = @embed_file("");

export fn entry() usize {
    return @size_of(@TypeOf(resource));
}

// error
// backend=stage2
// target=native
//
// :1:29: error: file path name cannot be empty
