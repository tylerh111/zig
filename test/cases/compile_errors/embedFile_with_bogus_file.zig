const resource = @embed_file("bogus.txt");

export fn entry() usize {
    return @size_of(@TypeOf(resource));
}

// error
// backend=stage2
// target=native
//
// :1:29: error: unable to open 'bogus.txt': FileNotFound
