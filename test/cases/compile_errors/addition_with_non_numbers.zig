const Foo = struct {
    field: i32,
};
const x = Foo{ .field = 1 } + Foo{ .field = 2 };

export fn entry() usize {
    return @size_of(@TypeOf(x));
}

// error
// backend=llvm
// target=native
//
// :4:29: error: invalid operands to binary expression: 'Struct' and 'Struct'
