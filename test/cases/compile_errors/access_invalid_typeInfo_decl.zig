const A = B;
test "Crash" {
    _ = @typeinfo(@This()).Struct.decls[0];
}

// error
// backend=stage2
// target=native
// is_test=true
//
// :1:11: error: use of undeclared identifier 'B'
