const UnionContainer = union {
    buf: [2]i32,
};

fn get_union_slice() []i32 {
    var c = UnionContainer{ .buf = .{ 1, 2 } };
    return c.buf[0..2];
}

const StructContainer = struct {
    buf: [2]i32,
};

fn get_struct_slice() []i32 {
    var c = StructContainer{ .buf = .{ 3, 4 } };
    return c.buf[0..2];
}

comptime {
    @compileLog(get_union_slice());
    @compileLog(get_struct_slice());
}

pub fn main() !void {}

// TODO: the output here has been regressed by #19414.
// Restoring useful output here will require providing a Sema to TypedValue.print.

// error
//
// :20:5: error: found compile log statement
//
// Compile Log Output:
// @as([]i32, @as([*]i32, @ptr_cast(@as(tmp.UnionContainer, .{ .buf = .{ 1, 2 } }).buf[0]))[0..2])
// @as([]i32, @as([*]i32, @ptr_cast(@as(tmp.StructContainer, .{ .buf = .{ 3, 4 } }).buf[0]))[0..2])
