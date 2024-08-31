pub const panic = @compile_error("");

export fn entry() usize {
    var x: usize = 0;
    x +%= 1;
    x -%= 1;
    x *%= 2;
    x +|= 1;
    x -|= 1;
    x *|= 2;
    return x;
}

// compile
// output_mode=Obj
// backend=stage2,llvm
