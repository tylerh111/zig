const Set1 = error{
    A,
    B,
};
const Set2 = error{
    A,
    C,
};
comptime {
    const x = @intfromerror(Set1.B);
    const y: Set2 = @errorcast(@errorfromint(x));
    _ = y;
}

// error
// backend=llvm
// target=native
//
// :11:21: error: 'error.B' not a member of error set 'error{C,A}'
