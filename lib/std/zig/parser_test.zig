test "zig fmt: remove extra whitespace at start and end of file with comment between" {
    try test_transform(
        \\
        \\
        \\// hello
        \\
        \\
    ,
        \\// hello
        \\
    );
}

test "zig fmt: tuple struct" {
    try test_canonical(
        \\const T = struct {
        \\    /// doc comment on tuple field
        \\    comptime comptime u32,
        \\    /// another doc comment on tuple field
        \\    *u32 = 1,
        \\    // needs to be wrapped in parentheses to not be parsed as a function decl
        \\    (fn () void) align(1),
        \\};
        \\
    );
}

test "zig fmt: preserves clobbers in inline asm with stray comma" {
    try test_canonical(
        \\fn foo() void {
        \\    asm volatile (""
        \\        : [_] "" (-> type),
        \\        :
        \\        : "clobber"
        \\    );
        \\    asm volatile (""
        \\        :
        \\        : [_] "" (type),
        \\        : "clobber"
        \\    );
        \\}
        \\
    );
}

test "zig fmt: remove trailing comma at the end of assembly clobber" {
    try test_transform(
        \\fn foo() void {
        \\    asm volatile (""
        \\        : [_] "" (-> type),
        \\        :
        \\        : "clobber1", "clobber2",
        \\    );
        \\}
        \\
    ,
        \\fn foo() void {
        \\    asm volatile (""
        \\        : [_] "" (-> type),
        \\        :
        \\        : "clobber1", "clobber2"
        \\    );
        \\}
        \\
    );
}

test "zig fmt: respect line breaks in struct field value declaration" {
    try test_canonical(
        \\const Foo = struct {
        \\    bar: u32 =
        \\        42,
        \\    bar: u32 =
        \\        // a comment
        \\        42,
        \\    bar: u32 =
        \\        42,
        \\    // a comment
        \\    bar: []const u8 =
        \\        \\ foo
        \\        \\ bar
        \\        \\ baz
        \\    ,
        \\    bar: u32 =
        \\        blk: {
        \\            break :blk 42;
        \\        },
        \\};
        \\
    );
}

test "zig fmt: respect line breaks before functions" {
    try test_canonical(
        \\const std = @import("std");
        \\
        \\inline fn foo() void {}
        \\
        \\noinline fn foo() void {}
        \\
        \\export fn foo() void {}
        \\
        \\extern fn foo() void;
        \\
        \\extern "foo" fn foo() void;
        \\
    );
}

test "zig fmt: rewrite callconv(.Inline) to the inline keyword" {
    try test_transform(
        \\fn foo() callconv(.Inline) void {}
        \\const bar = .Inline;
        \\fn foo() callconv(bar) void {}
        \\
    ,
        \\inline fn foo() void {}
        \\const bar = .Inline;
        \\fn foo() callconv(bar) void {}
        \\
    );
}

test "zig fmt: simple top level comptime block" {
    try test_canonical(
        \\// line comment
        \\comptime {}
        \\
    );
}

test "zig fmt: two spaced line comments before decl" {
    try test_canonical(
        \\// line comment
        \\
        \\// another
        \\comptime {}
        \\
    );
}

test "zig fmt: respect line breaks after var declarations" {
    try test_canonical(
        \\const crc =
        \\    lookup_tables[0][p[7]] ^
        \\    lookup_tables[1][p[6]] ^
        \\    lookup_tables[2][p[5]] ^
        \\    lookup_tables[3][p[4]] ^
        \\    lookup_tables[4][@as(u8, self.crc >> 24)] ^
        \\    lookup_tables[5][@as(u8, self.crc >> 16)] ^
        \\    lookup_tables[6][@as(u8, self.crc >> 8)] ^
        \\    lookup_tables[7][@as(u8, self.crc >> 0)];
        \\
    );
}

test "zig fmt: multiline string mixed with comments" {
    try test_canonical(
        \\const s1 =
        \\    //\\one
        \\    \\two)
        \\    \\three
        \\;
        \\const s2 =
        \\    \\one
        \\    \\two)
        \\    //\\three
        \\;
        \\const s3 =
        \\    \\one
        \\    //\\two)
        \\    \\three
        \\;
        \\const s4 =
        \\    \\one
        \\    //\\two
        \\    \\three
        \\    //\\four
        \\    \\five
        \\;
        \\const a =
        \\    1;
        \\
    );
}

test "zig fmt: empty file" {
    try test_canonical(
        \\
    );
}

test "zig fmt: file ends in comment" {
    try test_transform(
        \\     //foobar
    ,
        \\//foobar
        \\
    );
}

test "zig fmt: file ends in multi line comment" {
    try test_transform(
        \\     \\foobar
    ,
        \\\\foobar
        \\
    );
}

test "zig fmt: file ends in comment after var decl" {
    try test_transform(
        \\const x = 42;
        \\     //foobar
    ,
        \\const x = 42;
        \\//foobar
        \\
    );
}

test "zig fmt: if statement" {
    try test_canonical(
        \\test "" {
        \\    if (optional()) |some|
        \\        bar = some.foo();
        \\}
        \\
    );
}

test "zig fmt: top-level fields" {
    try test_canonical(
        \\a: did_you_know,
        \\b: all_files_are,
        \\structs: ?x,
        \\
    );
}

test "zig fmt: top-level tuple function call type" {
    try test_canonical(
        \\foo()
        \\
    );
}

test "zig fmt: top-level enum missing 'const name ='" {
    try test_error(
        \\enum(u32)
        \\
    , &[_]Error{.expected_token});
}

test "zig fmt: top-level for/while loop" {
    try test_canonical(
        \\for (foo) |_| foo
        \\
    );
    try test_canonical(
        \\while (foo) |_| foo
        \\
    );
}

test "zig fmt: top-level bare asterisk+identifier" {
    try test_canonical(
        \\*x
        \\
    );
}

test "zig fmt: top-level bare asterisk+asterisk+identifier" {
    try test_canonical(
        \\**x
        \\
    );
}

test "zig fmt: C style containers" {
    try test_error(
        \\struct Foo {
        \\    a: u32,
        \\};
    , &[_]Error{
        .c_style_container,
        .zig_style_container,
    });
    try test_error(
        \\test {
        \\    struct Foo {
        \\        a: u32,
        \\    };
        \\}
    , &[_]Error{
        .c_style_container,
        .zig_style_container,
    });
}

test "zig fmt: decl between fields" {
    try test_error(
        \\const S = struct {
        \\    const foo = 2;
        \\    const bar = 2;
        \\    const baz = 2;
        \\    a: usize,
        \\    const foo1 = 2;
        \\    const bar1 = 2;
        \\    const baz1 = 2;
        \\    b: usize,
        \\};
    , &[_]Error{
        .decl_between_fields,
        .previous_field,
        .next_field,
    });
}

test "zig fmt: errdefer with payload" {
    try test_canonical(
        \\pub fn main() anyerror!void {
        \\    errdefer |a| x += 1;
        \\    errdefer |a| {}
        \\    errdefer |a| {
        \\        x += 1;
        \\    }
        \\}
        \\
    );
}

test "zig fmt: nosuspend block" {
    try test_canonical(
        \\pub fn main() anyerror!void {
        \\    nosuspend {
        \\        var foo: Foo = .{ .bar = 42 };
        \\    }
        \\}
        \\
    );
}

test "zig fmt: nosuspend await" {
    try test_canonical(
        \\fn foo() void {
        \\    x = nosuspend await y;
        \\}
        \\
    );
}

test "zig fmt: container declaration, single line" {
    try test_canonical(
        \\const X = struct { foo: i32 };
        \\const X = struct { foo: i32, bar: i32 };
        \\const X = struct { foo: i32 = 1, bar: i32 = 2 };
        \\const X = struct { foo: i32 align(4), bar: i32 align(4) };
        \\const X = struct { foo: i32 align(4) = 1, bar: i32 align(4) = 2 };
        \\
    );
}

test "zig fmt: container declaration, one item, multi line trailing comma" {
    try test_canonical(
        \\test "" {
        \\    comptime {
        \\        const X = struct {
        \\            x: i32,
        \\        };
        \\    }
        \\}
        \\
    );
}

test "zig fmt: container declaration, no trailing comma on separate line" {
    try test_transform(
        \\test "" {
        \\    comptime {
        \\        const X = struct {
        \\            x: i32
        \\        };
        \\    }
        \\}
        \\
    ,
        \\test "" {
        \\    comptime {
        \\        const X = struct { x: i32 };
        \\    }
        \\}
        \\
    );
}

test "zig fmt: container declaration, line break, no trailing comma" {
    try test_transform(
        \\const X = struct {
        \\    foo: i32, bar: i8 };
    ,
        \\const X = struct { foo: i32, bar: i8 };
        \\
    );
}

test "zig fmt: container declaration, transform trailing comma" {
    try test_transform(
        \\const X = struct {
        \\    foo: i32, bar: i8, };
    ,
        \\const X = struct {
        \\    foo: i32,
        \\    bar: i8,
        \\};
        \\
    );
}

test "zig fmt: container declaration, comment, add trailing comma" {
    try test_transform(
        \\const X = struct {
        \\    foo: i32, // foo
        \\    bar: i8
        \\};
    ,
        \\const X = struct {
        \\    foo: i32, // foo
        \\    bar: i8,
        \\};
        \\
    );
    try test_transform(
        \\const X = struct {
        \\    foo: i32 // foo
        \\};
    ,
        \\const X = struct {
        \\    foo: i32, // foo
        \\};
        \\
    );
}

test "zig fmt: container declaration, multiline string, add trailing comma" {
    try test_transform(
        \\const X = struct {
        \\    foo: []const u8 =
        \\        \\ foo
        \\    ,
        \\    bar: i8
        \\};
    ,
        \\const X = struct {
        \\    foo: []const u8 =
        \\        \\ foo
        \\    ,
        \\    bar: i8,
        \\};
        \\
    );
}

test "zig fmt: container declaration, doc comment on member, add trailing comma" {
    try test_transform(
        \\pub const Pos = struct {
        \\    /// X-axis.
        \\    x: u32,
        \\    /// Y-axis.
        \\    y: u32
        \\};
    ,
        \\pub const Pos = struct {
        \\    /// X-axis.
        \\    x: u32,
        \\    /// Y-axis.
        \\    y: u32,
        \\};
        \\
    );
}

test "zig fmt: remove empty lines at start/end of container decl" {
    try test_transform(
        \\const X = struct {
        \\
        \\    foo: i32,
        \\
        \\    bar: i8,
        \\
        \\};
        \\
    ,
        \\const X = struct {
        \\    foo: i32,
        \\
        \\    bar: i8,
        \\};
        \\
    );
}

test "zig fmt: remove empty lines at start/end of block" {
    try test_transform(
        \\test {
        \\
        \\    if (foo) {
        \\        foo();
        \\    }
        \\
        \\}
        \\
    ,
        \\test {
        \\    if (foo) {
        \\        foo();
        \\    }
        \\}
        \\
    );
}

test "zig fmt: allow empty line before comment at start of block" {
    try test_canonical(
        \\test {
        \\
        \\    // foo
        \\    const x = 42;
        \\}
        \\
    );
}

test "zig fmt: trailing comma in fn parameter list" {
    try test_canonical(
        \\pub fn f(
        \\    a: i32,
        \\    b: i32,
        \\) i32 {}
        \\pub fn f(
        \\    a: i32,
        \\    b: i32,
        \\) align(8) i32 {}
        \\pub fn f(
        \\    a: i32,
        \\    b: i32,
        \\) addrspace(.generic) i32 {}
        \\pub fn f(
        \\    a: i32,
        \\    b: i32,
        \\) linksection(".text") i32 {}
        \\pub fn f(
        \\    a: i32,
        \\    b: i32,
        \\) callconv(.C) i32 {}
        \\pub fn f(
        \\    a: i32,
        \\    b: i32,
        \\) align(8) linksection(".text") i32 {}
        \\pub fn f(
        \\    a: i32,
        \\    b: i32,
        \\) align(8) callconv(.C) i32 {}
        \\pub fn f(
        \\    a: i32,
        \\    b: i32,
        \\) align(8) linksection(".text") callconv(.C) i32 {}
        \\pub fn f(
        \\    a: i32,
        \\    b: i32,
        \\) linksection(".text") callconv(.C) i32 {}
        \\
    );
}

test "zig fmt: comptime struct field" {
    try test_canonical(
        \\const Foo = struct {
        \\    a: i32,
        \\    comptime b: i32 = 1234,
        \\};
        \\
    );
}

test "zig fmt: break from block" {
    try test_canonical(
        \\const a = blk: {
        \\    break :blk 42;
        \\};
        \\const b = blk: {
        \\    break :blk;
        \\};
        \\const c = {
        \\    break 42;
        \\};
        \\const d = {
        \\    break;
        \\};
        \\
    );
}

test "zig fmt: grouped expressions (parentheses)" {
    try test_canonical(
        \\const r = (x + y) * (a + b);
        \\
    );
}

test "zig fmt: c pointer type" {
    try test_canonical(
        \\pub extern fn repro() [*c]const u8;
        \\
    );
}

test "zig fmt: builtin call with trailing comma" {
    try test_canonical(
        \\pub fn main() void {
        \\    @breakpoint();
        \\    _ = @int_from_bool(a);
        \\    _ = @call(
        \\        a,
        \\        b,
        \\        c,
        \\    );
        \\}
        \\
    );
}

test "zig fmt: asm expression with comptime content" {
    try test_canonical(
        \\comptime {
        \\    asm ("foo" ++ "bar");
        \\}
        \\pub fn main() void {
        \\    asm volatile ("foo" ++ "bar");
        \\    asm volatile ("foo" ++ "bar"
        \\        : [_] "" (x),
        \\    );
        \\    asm volatile ("foo" ++ "bar"
        \\        : [_] "" (x),
        \\        : [_] "" (y),
        \\    );
        \\    asm volatile ("foo" ++ "bar"
        \\        : [_] "" (x),
        \\        : [_] "" (y),
        \\        : "h", "e", "l", "l", "o"
        \\    );
        \\}
        \\
    );
}

test "zig fmt: array types last token" {
    try test_canonical(
        \\test {
        \\    const x = [40]u32;
        \\}
        \\
        \\test {
        \\    const x = [40:0]u32;
        \\}
        \\
    );
}

test "zig fmt: sentinel-terminated array type" {
    try test_canonical(
        \\pub fn c_str_to_prefixed_file_w(s: [*:0]const u8) ![PATH_MAX_WIDE:0]u16 {
        \\    return slice_to_prefixed_file_w(mem.toSliceConst(u8, s));
        \\}
        \\
    );
}

test "zig fmt: sentinel-terminated slice type" {
    try test_canonical(
        \\pub fn to_slice(self: Buffer) [:0]u8 {
        \\    return self.list.to_slice()[0..self.len()];
        \\}
        \\
    );
}

test "zig fmt: pointer-to-one with modifiers" {
    try test_canonical(
        \\const x: *u32 = undefined;
        \\const y: *allowzero align(8) addrspace(.generic) const volatile u32 = undefined;
        \\const z: *allowzero align(8:4:2) addrspace(.generic) const volatile u32 = undefined;
        \\
    );
}

test "zig fmt: pointer-to-many with modifiers" {
    try test_canonical(
        \\const x: [*]u32 = undefined;
        \\const y: [*]allowzero align(8) addrspace(.generic) const volatile u32 = undefined;
        \\const z: [*]allowzero align(8:4:2) addrspace(.generic) const volatile u32 = undefined;
        \\
    );
}

test "zig fmt: sentinel pointer with modifiers" {
    try test_canonical(
        \\const x: [*:42]u32 = undefined;
        \\const y: [*:42]allowzero align(8) addrspace(.generic) const volatile u32 = undefined;
        \\const y: [*:42]allowzero align(8:4:2) addrspace(.generic) const volatile u32 = undefined;
        \\
    );
}

test "zig fmt: c pointer with modifiers" {
    try test_canonical(
        \\const x: [*c]u32 = undefined;
        \\const y: [*c]allowzero align(8) addrspace(.generic) const volatile u32 = undefined;
        \\const z: [*c]allowzero align(8:4:2) addrspace(.generic) const volatile u32 = undefined;
        \\
    );
}

test "zig fmt: slice with modifiers" {
    try test_canonical(
        \\const x: []u32 = undefined;
        \\const y: []allowzero align(8) addrspace(.generic) const volatile u32 = undefined;
        \\
    );
}

test "zig fmt: sentinel slice with modifiers" {
    try test_canonical(
        \\const x: [:42]u32 = undefined;
        \\const y: [:42]allowzero align(8) addrspace(.generic) const volatile u32 = undefined;
        \\
    );
}

test "zig fmt: anon literal in array" {
    try test_canonical(
        \\var arr: [2]Foo = .{
        \\    .{ .a = 2 },
        \\    .{ .b = 3 },
        \\};
        \\
    );
}

test "zig fmt: alignment in anonymous literal" {
    try test_transform(
        \\const a = .{
        \\    "U",     "L",     "F",
        \\    "U'",
        \\    "L'",
        \\    "F'",
        \\};
        \\
    ,
        \\const a = .{
        \\    "U",  "L",  "F",
        \\    "U'", "L'", "F'",
        \\};
        \\
    );
}

test "zig fmt: anon struct literal 0 element" {
    try test_canonical(
        \\test {
        \\    const x = .{};
        \\}
        \\
    );
}

test "zig fmt: anon struct literal 1 element" {
    try test_canonical(
        \\test {
        \\    const x = .{ .a = b };
        \\}
        \\
    );
}

test "zig fmt: anon struct literal 1 element comma" {
    try test_canonical(
        \\test {
        \\    const x = .{
        \\        .a = b,
        \\    };
        \\}
        \\
    );
}

test "zig fmt: anon struct literal 2 element" {
    try test_canonical(
        \\test {
        \\    const x = .{ .a = b, .c = d };
        \\}
        \\
    );
}

test "zig fmt: anon struct literal 2 element comma" {
    try test_canonical(
        \\test {
        \\    const x = .{
        \\        .a = b,
        \\        .c = d,
        \\    };
        \\}
        \\
    );
}

test "zig fmt: anon struct literal 3 element" {
    try test_canonical(
        \\test {
        \\    const x = .{ .a = b, .c = d, .e = f };
        \\}
        \\
    );
}

test "zig fmt: anon struct literal 3 element comma" {
    try test_canonical(
        \\test {
        \\    const x = .{
        \\        .a = b,
        \\        .c = d,
        \\        .e = f,
        \\    };
        \\}
        \\
    );
}

test "zig fmt: struct literal 0 element" {
    try test_canonical(
        \\test {
        \\    const x = X{};
        \\}
        \\
    );
}

test "zig fmt: struct literal 1 element" {
    try test_canonical(
        \\test {
        \\    const x = X{ .a = b };
        \\}
        \\
    );
}

test "zig fmt: Unicode code point literal larger than u8" {
    try test_canonical(
        \\test {
        \\    const x = X{
        \\        .a = b,
        \\    };
        \\}
        \\
    );
}

test "zig fmt: struct literal 2 element" {
    try test_canonical(
        \\test {
        \\    const x = X{ .a = b, .c = d };
        \\}
        \\
    );
}

test "zig fmt: struct literal 2 element comma" {
    try test_canonical(
        \\test {
        \\    const x = X{
        \\        .a = b,
        \\        .c = d,
        \\    };
        \\}
        \\
    );
}

test "zig fmt: struct literal 3 element" {
    try test_canonical(
        \\test {
        \\    const x = X{ .a = b, .c = d, .e = f };
        \\}
        \\
    );
}

test "zig fmt: struct literal 3 element comma" {
    try test_canonical(
        \\test {
        \\    const x = X{
        \\        .a = b,
        \\        .c = d,
        \\        .e = f,
        \\    };
        \\}
        \\
    );
}

test "zig fmt: anon list literal 1 element" {
    try test_canonical(
        \\test {
        \\    const x = .{a};
        \\}
        \\
    );
}

test "zig fmt: anon list literal 1 element comma" {
    try test_canonical(
        \\test {
        \\    const x = .{
        \\        a,
        \\    };
        \\}
        \\
    );
}

test "zig fmt: anon list literal 2 element" {
    try test_canonical(
        \\test {
        \\    const x = .{ a, b };
        \\}
        \\
    );
}

test "zig fmt: anon list literal 2 element comma" {
    try test_canonical(
        \\test {
        \\    const x = .{
        \\        a,
        \\        b,
        \\    };
        \\}
        \\
    );
}

test "zig fmt: anon list literal 3 element" {
    try test_canonical(
        \\test {
        \\    const x = .{ a, b, c };
        \\}
        \\
    );
}

test "zig fmt: anon list literal 3 element comma" {
    try test_canonical(
        \\test {
        \\    const x = .{
        \\        a,
        \\        // foo
        \\        b,
        \\
        \\        c,
        \\    };
        \\}
        \\
    );
}

test "zig fmt: array literal 0 element" {
    try test_canonical(
        \\test {
        \\    const x = [_]u32{};
        \\}
        \\
    );
}

test "zig fmt: array literal 1 element" {
    try test_canonical(
        \\test {
        \\    const x = [_]u32{a};
        \\}
        \\
    );
}

test "zig fmt: array literal 1 element comma" {
    try test_canonical(
        \\test {
        \\    const x = [1]u32{
        \\        a,
        \\    };
        \\}
        \\
    );
}

test "zig fmt: array literal 2 element" {
    try test_canonical(
        \\test {
        \\    const x = [_]u32{ a, b };
        \\}
        \\
    );
}

test "zig fmt: array literal 2 element comma" {
    try test_canonical(
        \\test {
        \\    const x = [2]u32{
        \\        a,
        \\        b,
        \\    };
        \\}
        \\
    );
}

test "zig fmt: array literal 3 element" {
    try test_canonical(
        \\test {
        \\    const x = [_]u32{ a, b, c };
        \\}
        \\
    );
}

test "zig fmt: array literal 3 element comma" {
    try test_canonical(
        \\test {
        \\    const x = [3]u32{
        \\        a,
        \\        b,
        \\        c,
        \\    };
        \\}
        \\
    );
}

test "zig fmt: sentinel array literal 1 element" {
    try test_canonical(
        \\test {
        \\    const x = [_:9000]u32{a};
        \\}
        \\
    );
}

test "zig fmt: slices" {
    try test_canonical(
        \\const a = b[0..];
        \\const c = d[0..1];
        \\const d = f[0.. :0];
        \\const e = f[0..1 :0];
        \\
    );
}

test "zig fmt: slices with spaces in bounds" {
    try test_canonical(
        \\const a = b[0 + 0 ..];
        \\const c = d[0 + 0 .. 1];
        \\const c = d[0 + 0 .. :0];
        \\const e = f[0 .. 1 + 1 :0];
        \\
    );
}

test "zig fmt: block in slice expression" {
    try test_canonical(
        \\const a = b[{
        \\    _ = x;
        \\}..];
        \\const c = d[0..{
        \\    _ = x;
        \\    _ = y;
        \\}];
        \\const e = f[0..1 :{
        \\    _ = x;
        \\    _ = y;
        \\    _ = z;
        \\}];
        \\
    );
}

test "zig fmt: async function" {
    try test_canonical(
        \\pub const Server = struct {
        \\    handleRequestFn: fn (*Server, *const std.net.Address, File) callconv(.Async) void,
        \\};
        \\test "hi" {
        \\    var ptr: fn (i32) callconv(.Async) void = @ptr_cast(other);
        \\}
        \\
    );
}

test "zig fmt: whitespace fixes" {
    try test_transform("test \"\" {\r\n\tconst hi = x;\r\n}\n// zig fmt: off\ntest \"\"{\r\n\tconst a  = b;}\r\n",
        \\test "" {
        \\    const hi = x;
        \\}
        \\// zig fmt: off
        \\test ""{
        \\    const a  = b;}
        \\
    );
}

test "zig fmt: while else err prong with no block" {
    try test_canonical(
        \\test "" {
        \\    const result = while (return_error()) |value| {
        \\        break value;
        \\    } else |err| @as(i32, 2);
        \\    try expect(result == 2);
        \\}
        \\
    );
}

test "zig fmt: tagged union with enum values" {
    try test_canonical(
        \\const MultipleChoice2 = union(enum(u32)) {
        \\    Unspecified1: i32,
        \\    A: f32 = 20,
        \\    Unspecified2: void,
        \\    B: bool = 40,
        \\    Unspecified3: i32,
        \\    C: i8 = 60,
        \\    Unspecified4: void,
        \\    D: void = 1000,
        \\    Unspecified5: i32,
        \\};
        \\
    );
}

test "zig fmt: tagged union enum tag last token" {
    try test_canonical(
        \\test {
        \\    const U = union(enum(u32)) {};
        \\}
        \\
        \\test {
        \\    const U = union(enum(u32)) { foo };
        \\}
        \\
        \\test {
        \\    const U = union(enum(u32)) {
        \\        foo,
        \\    };
        \\}
        \\
    );
}

test "zig fmt: allowzero pointer" {
    try test_canonical(
        \\const T = [*]allowzero const u8;
        \\
    );
}

test "zig fmt: empty enum decls" {
    try test_canonical(
        \\const A = enum {};
        \\const B = enum(u32) {};
        \\const C = extern enum(c_int) {};
        \\const D = packed enum(u8) {};
        \\
    );
}

test "zig fmt: empty union decls" {
    try test_canonical(
        \\const A = union {};
        \\const B = union(enum) {};
        \\const C = union(Foo) {};
        \\const D = extern union {};
        \\const E = packed union {};
        \\
    );
}

test "zig fmt: enum literal" {
    try test_canonical(
        \\const x = .hi;
        \\
    );
}

test "zig fmt: enum literal inside array literal" {
    try test_canonical(
        \\test "enums in arrays" {
        \\    var colors = []Color{.Green};
        \\    colors = []Colors{ .Green, .Cyan };
        \\    colors = []Colors{
        \\        .Grey,
        \\        .Green,
        \\        .Cyan,
        \\    };
        \\}
        \\
    );
}

test "zig fmt: character literal larger than u8" {
    try test_canonical(
        \\const x = '\u{01f4a9}';
        \\
    );
}

test "zig fmt: infix operator and then multiline string literal" {
    try test_canonical(
        \\const x = "" ++
        \\    \\ hi
        \\;
        \\
    );
}

test "zig fmt: infix operator and then multiline string literal over multiple lines" {
    try test_canonical(
        \\const x = "" ++
        \\    \\ hi0
        \\    \\ hi1
        \\    \\ hi2
        \\;
        \\
    );
}

test "zig fmt: C pointers" {
    try test_canonical(
        \\const Ptr = [*c]i32;
        \\
    );
}

test "zig fmt: threadlocal" {
    try test_canonical(
        \\threadlocal var x: i32 = 1234;
        \\
    );
}

test "zig fmt: linksection" {
    try test_canonical(
        \\export var aoeu: u64 linksection(".text.derp") = 1234;
        \\export fn _start() linksection(".text.boot") callconv(.Naked) noreturn {}
        \\
    );
}

test "zig fmt: addrspace" {
    try test_canonical(
        \\export var python_length: u64 align(1) addrspace(.generic);
        \\export var python_color: Color addrspace(.generic) = .green;
        \\export var python_legs: u0 align(8) addrspace(.generic) linksection(".python") = 0;
        \\export fn python_hiss() align(8) addrspace(.generic) linksection(".python") void;
        \\
    );
}

test "zig fmt: correctly space struct fields with doc comments" {
    try test_transform(
        \\pub const S = struct {
        \\    /// A
        \\    a: u8,
        \\    /// B
        \\    /// B (cont)
        \\    b: u8,
        \\
        \\
        \\    /// C
        \\    c: u8,
        \\};
        \\
    ,
        \\pub const S = struct {
        \\    /// A
        \\    a: u8,
        \\    /// B
        \\    /// B (cont)
        \\    b: u8,
        \\
        \\    /// C
        \\    c: u8,
        \\};
        \\
    );
}

test "zig fmt: doc comments on param decl" {
    try test_canonical(
        \\pub const Allocator = struct {
        \\    shrinkFn: fn (
        \\        self: Allocator,
        \\        /// Guaranteed to be the same as what was returned from most recent call to
        \\        /// `alloc_fn`, `reallocFn`, or `shrinkFn`.
        \\        old_mem: []u8,
        \\        /// Guaranteed to be the same as what was returned from most recent call to
        \\        /// `alloc_fn`, `reallocFn`, or `shrinkFn`.
        \\        old_alignment: u29,
        \\        /// Guaranteed to be less than or equal to `old_mem.len`.
        \\        new_byte_count: usize,
        \\        /// Guaranteed to be less than or equal to `old_alignment`.
        \\        new_alignment: u29,
        \\    ) []u8,
        \\};
        \\
    );
}

test "zig fmt: aligned struct field" {
    try test_canonical(
        \\pub const S = struct {
        \\    f: i32 align(32),
        \\};
        \\
    );
    try test_canonical(
        \\pub const S = struct {
        \\    f: i32 align(32) = 1,
        \\};
        \\
    );
}

test "zig fmt: comment to disable/enable zig fmt first" {
    try test_canonical(
        \\// Test trailing comma syntax
        \\// zig fmt: off
        \\
        \\const struct_trailing_comma = struct { x: i32, y: i32, };
    );
}

test "zig fmt: 'zig fmt: (off|on)' can be surrounded by arbitrary whitespace" {
    try test_transform(
        \\// Test trailing comma syntax
        \\//     zig fmt: off
        \\
        \\const struct_trailing_comma = struct { x: i32, y: i32, };
        \\
        \\//   zig fmt: on
    ,
        \\// Test trailing comma syntax
        \\// zig fmt: off
        \\
        \\const struct_trailing_comma = struct { x: i32, y: i32, };
        \\
        \\// zig fmt: on
        \\
    );
}

test "zig fmt: comment to disable/enable zig fmt" {
    try test_transform(
        \\const  a  =  b;
        \\// zig fmt: off
        \\const  c  =  d;
        \\// zig fmt: on
        \\const  e  =  f;
    ,
        \\const a = b;
        \\// zig fmt: off
        \\const  c  =  d;
        \\// zig fmt: on
        \\const e = f;
        \\
    );
}

test "zig fmt: line comment following 'zig fmt: off'" {
    try test_canonical(
        \\// zig fmt: off
        \\// Test
        \\const  e  =  f;
    );
}

test "zig fmt: doc comment following 'zig fmt: off'" {
    try test_canonical(
        \\// zig fmt: off
        \\/// test
        \\const  e  =  f;
    );
}

test "zig fmt: line and doc comment following 'zig fmt: off'" {
    try test_canonical(
        \\// zig fmt: off
        \\// test 1
        \\/// test 2
        \\const  e  =  f;
    );
}

test "zig fmt: doc and line comment following 'zig fmt: off'" {
    try test_canonical(
        \\// zig fmt: off
        \\/// test 1
        \\// test 2
        \\const  e  =  f;
    );
}

test "zig fmt: alternating 'zig fmt: off' and 'zig fmt: on'" {
    try test_canonical(
        \\// zig fmt: off
        \\// zig fmt: on
        \\// zig fmt: off
        \\const  e  =  f;
        \\// zig fmt: off
        \\// zig fmt: on
        \\// zig fmt: off
        \\const  a  =  b;
        \\// zig fmt: on
        \\const c = d;
        \\// zig fmt: on
        \\
    );
}

test "zig fmt: line comment following 'zig fmt: on'" {
    try test_canonical(
        \\// zig fmt: off
        \\const  e  =  f;
        \\// zig fmt: on
        \\// test
        \\const e = f;
        \\
    );
}

test "zig fmt: doc comment following 'zig fmt: on'" {
    try test_canonical(
        \\// zig fmt: off
        \\const  e  =  f;
        \\// zig fmt: on
        \\/// test
        \\const e = f;
        \\
    );
}

test "zig fmt: line and doc comment following 'zig fmt: on'" {
    try test_canonical(
        \\// zig fmt: off
        \\const  e  =  f;
        \\// zig fmt: on
        \\// test1
        \\/// test2
        \\const e = f;
        \\
    );
}

test "zig fmt: doc and line comment following 'zig fmt: on'" {
    try test_canonical(
        \\// zig fmt: off
        \\const  e  =  f;
        \\// zig fmt: on
        \\/// test1
        \\// test2
        \\const e = f;
        \\
    );
}

test "zig fmt: 'zig fmt: (off|on)' works in the middle of code" {
    try test_transform(
        \\test "" {
        \\    const x = 42;
        \\
        \\    if (foobar) |y| {
        \\    // zig fmt: off
        \\            }// zig fmt: on
        \\
        \\    const  z  = 420;
        \\}
        \\
    ,
        \\test "" {
        \\    const x = 42;
        \\
        \\    if (foobar) |y| {
        \\        // zig fmt: off
        \\            }// zig fmt: on
        \\
        \\    const z = 420;
        \\}
        \\
    );
}

test "zig fmt: 'zig fmt: on' indentation is unchanged" {
    try test_canonical(
        \\fn init_options_and_layouts(output: *Output, context: *Context) !void {
        \\    // zig fmt: off
        \\    try output.main_amount.init(output, "main_amount"); errdefer optput.main_amount.deinit();
        \\    try output.main_factor.init(output, "main_factor"); errdefer optput.main_factor.deinit();
        \\    try output.view_padding.init(output, "view_padding"); errdefer optput.view_padding.deinit();
        \\    try output.outer_padding.init(output, "outer_padding"); errdefer optput.outer_padding.deinit();
        \\    // zig fmt: on
        \\
        \\    // zig fmt: off
        \\    try output.top.init(output, .top); errdefer optput.top.deinit();
        \\    try output.right.init(output, .right); errdefer optput.right.deinit();
        \\    try output.bottom.init(output, .bottom); errdefer optput.bottom.deinit();
        \\    try output.left.init(output, .left); errdefer optput.left.deinit();
        \\        // zig fmt: on
        \\}
        \\
    );
}

test "zig fmt: pointer of unknown length" {
    try test_canonical(
        \\fn foo(ptr: [*]u8) void {}
        \\
    );
}

test "zig fmt: spaces around slice operator" {
    try test_canonical(
        \\var a = b[c..d];
        \\var a = b[c..d :0];
        \\var a = b[c + 1 .. d];
        \\var a = b[c + 1 ..];
        \\var a = b[c .. d + 1];
        \\var a = b[c .. d + 1 :0];
        \\var a = b[c.a..d.e];
        \\var a = b[c.a..d.e :0];
        \\
    );
}

test "zig fmt: async call in if condition" {
    try test_canonical(
        \\comptime {
        \\    if (async b()) {
        \\        a();
        \\    }
        \\}
        \\
    );
}

test "zig fmt: 2nd arg multiline string" {
    try test_canonical(
        \\comptime {
        \\    cases.add_asm("hello world linux x86_64",
        \\        \\.text
        \\    , "Hello, world!\n");
        \\}
        \\
    );
    try test_transform(
        \\comptime {
        \\    cases.add_asm("hello world linux x86_64",
        \\        \\.text
        \\    , "Hello, world!\n",);
        \\}
    ,
        \\comptime {
        \\    cases.add_asm(
        \\        "hello world linux x86_64",
        \\        \\.text
        \\    ,
        \\        "Hello, world!\n",
        \\    );
        \\}
        \\
    );
}

test "zig fmt: 2nd arg multiline string many args" {
    try test_canonical(
        \\comptime {
        \\    cases.add_asm("hello world linux x86_64",
        \\        \\.text
        \\    , "Hello, world!\n", "Hello, world!\n");
        \\}
        \\
    );
}

test "zig fmt: final arg multiline string" {
    try test_canonical(
        \\comptime {
        \\    cases.add_asm("hello world linux x86_64", "Hello, world!\n",
        \\        \\.text
        \\    );
        \\}
        \\
    );
}

test "zig fmt: if condition wraps" {
    try test_transform(
        \\comptime {
        \\    if (cond and
        \\        cond) {
        \\        return x;
        \\    }
        \\    while (cond and
        \\        cond) {
        \\        return x;
        \\    }
        \\    if (a == b and
        \\        c) {
        \\        a = b;
        \\    }
        \\    while (a == b and
        \\        c) {
        \\        a = b;
        \\    }
        \\    if ((cond and
        \\        cond)) {
        \\        return x;
        \\    }
        \\    while ((cond and
        \\        cond)) {
        \\        return x;
        \\    }
        \\    var a = if (a) |*f| x: {
        \\        break :x &a.b;
        \\    } else |err| err;
        \\    var a = if (cond and
        \\                cond) |*f|
        \\    x: {
        \\        break :x &a.b;
        \\    } else |err| err;
        \\}
    ,
        \\comptime {
        \\    if (cond and
        \\        cond)
        \\    {
        \\        return x;
        \\    }
        \\    while (cond and
        \\        cond)
        \\    {
        \\        return x;
        \\    }
        \\    if (a == b and
        \\        c)
        \\    {
        \\        a = b;
        \\    }
        \\    while (a == b and
        \\        c)
        \\    {
        \\        a = b;
        \\    }
        \\    if ((cond and
        \\        cond))
        \\    {
        \\        return x;
        \\    }
        \\    while ((cond and
        \\        cond))
        \\    {
        \\        return x;
        \\    }
        \\    var a = if (a) |*f| x: {
        \\        break :x &a.b;
        \\    } else |err| err;
        \\    var a = if (cond and
        \\        cond) |*f|
        \\    x: {
        \\        break :x &a.b;
        \\    } else |err| err;
        \\}
        \\
    );
}

test "zig fmt: if condition has line break but must not wrap" {
    try test_canonical(
        \\comptime {
        \\    if (self.user_input_options.put(
        \\        name,
        \\        UserInputOption{
        \\            .name = name,
        \\            .used = false,
        \\        },
        \\    ) catch unreachable) |*prev_value| {
        \\        foo();
        \\        bar();
        \\    }
        \\    if (put(
        \\        a,
        \\        b,
        \\    )) {
        \\        foo();
        \\    }
        \\}
        \\
    );
}

test "zig fmt: if condition has line break but must not wrap (no fn call comma)" {
    try test_canonical(
        \\comptime {
        \\    if (self.user_input_options.put(name, UserInputOption{
        \\        .name = name,
        \\        .used = false,
        \\    }) catch unreachable) |*prev_value| {
        \\        foo();
        \\        bar();
        \\    }
        \\    if (put(
        \\        a,
        \\        b,
        \\    )) {
        \\        foo();
        \\    }
        \\}
        \\
    );
}

test "zig fmt: function call with multiline argument" {
    try test_canonical(
        \\comptime {
        \\    self.user_input_options.put(name, UserInputOption{
        \\        .name = name,
        \\        .used = false,
        \\    });
        \\}
        \\
    );
}

test "zig fmt: if-else with comment before else" {
    try test_canonical(
        \\comptime {
        \\    // cexp(finite|nan +- i inf|nan) = nan + i nan
        \\    if ((hx & 0x7fffffff) != 0x7f800000) {
        \\        return Complex(f32).init(y - y, y - y);
        \\    } // cexp(-inf +- i inf|nan) = 0 + i0
        \\    else if (hx & 0x80000000 != 0) {
        \\        return Complex(f32).init(0, 0);
        \\    } // cexp(+inf +- i inf|nan) = inf + i nan
        \\    else {
        \\        return Complex(f32).init(x, y - y);
        \\    }
        \\}
        \\
    );
}

test "zig fmt: if nested" {
    try test_canonical(
        \\pub fn foo() void {
        \\    return if ((aInt & bInt) >= 0)
        \\        if (aInt < bInt)
        \\            GE_LESS
        \\        else if (aInt == bInt)
        \\            GE_EQUAL
        \\        else
        \\            GE_GREATER
        \\        // comment
        \\    else if (aInt > bInt)
        \\        GE_LESS
        \\    else if (aInt == bInt)
        \\        GE_EQUAL
        \\    else
        \\        GE_GREATER;
        \\    // comment
        \\}
        \\
    );
}

test "zig fmt: respect line breaks in if-else" {
    try test_canonical(
        \\comptime {
        \\    return if (cond) a else b;
        \\    return if (cond)
        \\        a
        \\    else
        \\        b;
        \\    return if (cond)
        \\        a
        \\    else if (cond)
        \\        b
        \\    else
        \\        c;
        \\}
        \\
    );
}

test "zig fmt: respect line breaks after infix operators" {
    try test_canonical(
        \\comptime {
        \\    self.crc =
        \\        lookup_tables[0][p[7]] ^
        \\        lookup_tables[1][p[6]] ^
        \\        lookup_tables[2][p[5]] ^
        \\        lookup_tables[3][p[4]] ^
        \\        lookup_tables[4][@as(u8, self.crc >> 24)] ^
        \\        lookup_tables[5][@as(u8, self.crc >> 16)] ^
        \\        lookup_tables[6][@as(u8, self.crc >> 8)] ^
        \\        lookup_tables[7][@as(u8, self.crc >> 0)];
        \\}
        \\
    );
}

test "zig fmt: fn decl with trailing comma" {
    try test_transform(
        \\fn foo(a: i32, b: i32,) void {}
    ,
        \\fn foo(
        \\    a: i32,
        \\    b: i32,
        \\) void {}
        \\
    );
}

test "zig fmt: enum decl with no trailing comma" {
    try test_transform(
        \\const StrLitKind = enum {Normal, C};
    ,
        \\const StrLitKind = enum { Normal, C };
        \\
    );
}

test "zig fmt: switch comment before prong" {
    try test_canonical(
        \\comptime {
        \\    switch (a) {
        \\        // hi
        \\        0 => {},
        \\    }
        \\}
        \\
    );
}

test "zig fmt: switch comment after prong" {
    try test_canonical(
        \\comptime {
        \\    switch (a) {
        \\        0,
        \\        // hi
        \\        => {},
        \\    }
        \\}
        \\
    );
}

test "zig fmt: struct literal no trailing comma" {
    try test_transform(
        \\const a = foo{ .x = 1, .y = 2 };
        \\const a = foo{ .x = 1,
        \\    .y = 2 };
        \\const a = foo{ .x = 1,
        \\    .y = 2, };
    ,
        \\const a = foo{ .x = 1, .y = 2 };
        \\const a = foo{ .x = 1, .y = 2 };
        \\const a = foo{
        \\    .x = 1,
        \\    .y = 2,
        \\};
        \\
    );
}

test "zig fmt: struct literal containing a multiline expression" {
    try test_transform(
        \\const a = A{ .x = if (f1()) 10 else 20 };
        \\const a = A{ .x = if (f1()) 10 else 20, };
        \\const a = A{ .x = if (f1())
        \\    10 else 20 };
        \\const a = A{ .x = if (f1())
        \\    10 else 20,};
        \\const a = A{ .x = if (f1()) 10 else 20, .y = f2() + 100 };
        \\const a = A{ .x = if (f1()) 10 else 20, .y = f2() + 100, };
        \\const a = A{ .x = if (f1())
        \\    10 else 20};
        \\const a = A{ .x = if (f1())
        \\    10 else 20,};
        \\const a = A{ .x = switch(g) {0 => "ok", else => "no"} };
        \\const a = A{ .x = switch(g) {0 => "ok", else => "no"}, };
        \\
    ,
        \\const a = A{ .x = if (f1()) 10 else 20 };
        \\const a = A{
        \\    .x = if (f1()) 10 else 20,
        \\};
        \\const a = A{ .x = if (f1())
        \\    10
        \\else
        \\    20 };
        \\const a = A{
        \\    .x = if (f1())
        \\        10
        \\    else
        \\        20,
        \\};
        \\const a = A{ .x = if (f1()) 10 else 20, .y = f2() + 100 };
        \\const a = A{
        \\    .x = if (f1()) 10 else 20,
        \\    .y = f2() + 100,
        \\};
        \\const a = A{ .x = if (f1())
        \\    10
        \\else
        \\    20 };
        \\const a = A{
        \\    .x = if (f1())
        \\        10
        \\    else
        \\        20,
        \\};
        \\const a = A{ .x = switch (g) {
        \\    0 => "ok",
        \\    else => "no",
        \\} };
        \\const a = A{
        \\    .x = switch (g) {
        \\        0 => "ok",
        \\        else => "no",
        \\    },
        \\};
        \\
    );
}

test "zig fmt: array literal with hint" {
    try test_transform(
        \\const a = []u8{
        \\    1, 2, //
        \\    3,
        \\    4,
        \\    5,
        \\    6,
        \\    7 };
        \\const a = []u8{
        \\    1, 2, //
        \\    3,
        \\    4,
        \\    5,
        \\    6,
        \\    7, 8 };
        \\const a = []u8{
        \\    1, 2, //
        \\    3,
        \\    4,
        \\    5,
        \\    6, // blah
        \\    7, 8 };
        \\const a = []u8{
        \\    1, 2, //
        \\    3, //
        \\    4,
        \\    5,
        \\    6,
        \\    7 };
        \\const a = []u8{
        \\    1,
        \\    2,
        \\    3, 4, //
        \\    5, 6, //
        \\    7, 8, //
        \\};
    ,
        \\const a = []u8{
        \\    1, 2, //
        \\    3, 4,
        \\    5, 6,
        \\    7,
        \\};
        \\const a = []u8{
        \\    1, 2, //
        \\    3, 4,
        \\    5, 6,
        \\    7, 8,
        \\};
        \\const a = []u8{
        \\    1, 2, //
        \\    3, 4,
        \\    5,
        \\    6, // blah
        \\    7,
        \\    8,
        \\};
        \\const a = []u8{
        \\    1, 2, //
        \\    3, //
        \\    4,
        \\    5,
        \\    6,
        \\    7,
        \\};
        \\const a = []u8{
        \\    1,
        \\    2,
        \\    3, 4, //
        \\    5, 6, //
        \\    7, 8, //
        \\};
        \\
    );
}

test "zig fmt: array literal vertical column alignment" {
    try test_transform(
        \\const a = []u8{
        \\    1000, 200,
        \\    30, 4,
        \\    50000, 60,
        \\};
        \\const a = []u8{0,   1, 2, 3, 40,
        \\    4,5,600,7,
        \\           80,
        \\    9, 10, 11, 0, 13, 14, 15,};
        \\const a = [12]u8{
        \\    31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
        \\const a = [12]u8{
        \\    31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31, };
        \\
    ,
        \\const a = []u8{
        \\    1000,  200,
        \\    30,    4,
        \\    50000, 60,
        \\};
        \\const a = []u8{
        \\    0,  1,  2,   3, 40,
        \\    4,  5,  600, 7, 80,
        \\    9,  10, 11,  0, 13,
        \\    14, 15,
        \\};
        \\const a = [12]u8{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
        \\const a = [12]u8{
        \\    31,
        \\    28,
        \\    31,
        \\    30,
        \\    31,
        \\    30,
        \\    31,
        \\    31,
        \\    30,
        \\    31,
        \\    30,
        \\    31,
        \\};
        \\
    );
}

test "zig fmt: multiline string with backslash at end of line" {
    try test_canonical(
        \\comptime {
        \\    err(
        \\        \\\
        \\    );
        \\}
        \\
    );
}

test "zig fmt: multiline string parameter in fn call with trailing comma" {
    try test_canonical(
        \\fn foo() void {
        \\    try stdout.print(
        \\        \\ZIG_CMAKE_BINARY_DIR {s}
        \\        \\ZIG_C_HEADER_FILES   {s}
        \\        \\ZIG_DIA_GUIDS_LIB    {s}
        \\        \\
        \\    ,
        \\        std.mem.slice_to(c.ZIG_CMAKE_BINARY_DIR, 0),
        \\        std.mem.slice_to(c.ZIG_CXX_COMPILER, 0),
        \\        std.mem.slice_to(c.ZIG_DIA_GUIDS_LIB, 0),
        \\    );
        \\}
        \\
    );
}

test "zig fmt: trailing comma on fn call" {
    try test_canonical(
        \\comptime {
        \\    var module = try Module.create(
        \\        allocator,
        \\        zig_lib_dir,
        \\        full_cache_dir,
        \\    );
        \\}
        \\
    );
}

test "zig fmt: multi line arguments without last comma" {
    try test_transform(
        \\pub fn foo(
        \\    a: usize,
        \\    b: usize,
        \\    c: usize,
        \\    d: usize
        \\) usize {
        \\    return a + b + c + d;
        \\}
        \\
    ,
        \\pub fn foo(a: usize, b: usize, c: usize, d: usize) usize {
        \\    return a + b + c + d;
        \\}
        \\
    );
}

test "zig fmt: empty block with only comment" {
    try test_canonical(
        \\comptime {
        \\    {
        \\        // comment
        \\    }
        \\}
        \\
    );
}

test "zig fmt: trailing commas on struct decl" {
    try test_transform(
        \\const RoundParam = struct {
        \\    k: usize, s: u32, t: u32
        \\};
        \\const RoundParam = struct {
        \\    k: usize, s: u32, t: u32,
        \\};
    ,
        \\const RoundParam = struct { k: usize, s: u32, t: u32 };
        \\const RoundParam = struct {
        \\    k: usize,
        \\    s: u32,
        \\    t: u32,
        \\};
        \\
    );
}

test "zig fmt: extra newlines at the end" {
    try test_transform(
        \\const a = b;
        \\
        \\
        \\
    ,
        \\const a = b;
        \\
    );
}

test "zig fmt: simple asm" {
    try test_transform(
        \\comptime {
        \\    asm volatile (
        \\        \\.globl aoeu;
        \\        \\.type aoeu, @function;
        \\        \\.set aoeu, derp;
        \\    );
        \\
        \\    asm ("not real assembly"
        \\        :[a] "x" (x),);
        \\    asm ("not real assembly"
        \\        :[a] "x" (->i32),:[a] "x" (1),);
        \\    asm ("still not real assembly"
        \\        :::"a","b",);
        \\}
    ,
        \\comptime {
        \\    asm volatile (
        \\        \\.globl aoeu;
        \\        \\.type aoeu, @function;
        \\        \\.set aoeu, derp;
        \\    );
        \\
        \\    asm ("not real assembly"
        \\        : [a] "x" (x),
        \\    );
        \\    asm ("not real assembly"
        \\        : [a] "x" (-> i32),
        \\        : [a] "x" (1),
        \\    );
        \\    asm ("still not real assembly" ::: "a", "b");
        \\}
        \\
    );
}

test "zig fmt: nested struct literal with one item" {
    try test_canonical(
        \\const a = foo{
        \\    .item = bar{ .a = b },
        \\};
        \\
    );
}

test "zig fmt: switch cases trailing comma" {
    try test_transform(
        \\test "switch cases trailing comma"{
        \\    switch (x) {
        \\        1,2,3 => {},
        \\        4,5, => {},
        \\        6... 8, => {},
        \\        9 ...
        \\        10 => {},
        \\        11 => {},
        \\        12, => {},
        \\        else => {},
        \\    }
        \\}
    ,
        \\test "switch cases trailing comma" {
        \\    switch (x) {
        \\        1, 2, 3 => {},
        \\        4,
        \\        5,
        \\        => {},
        \\        6...8,
        \\        => {},
        \\        9...10 => {},
        \\        11 => {},
        \\        12,
        \\        => {},
        \\        else => {},
        \\    }
        \\}
        \\
    );
}

test "zig fmt: slice align" {
    try test_canonical(
        \\const A = struct {
        \\    items: []align(A) T,
        \\};
        \\
    );
}

test "zig fmt: add trailing comma to array literal" {
    try test_transform(
        \\comptime {
        \\    return []u16{'m', 's', 'y', 's', '-' // hi
        \\   };
        \\    return []u16{'m', 's', 'y', 's',
        \\      '-'};
        \\    return []u16{'m', 's', 'y', 's', '-'};
        \\}
    ,
        \\comptime {
        \\    return []u16{
        \\        'm', 's', 'y', 's', '-', // hi
        \\    };
        \\    return []u16{ 'm', 's', 'y', 's', '-' };
        \\    return []u16{ 'm', 's', 'y', 's', '-' };
        \\}
        \\
    );
}

test "zig fmt: first thing in file is line comment" {
    try test_canonical(
        \\// Introspection and determination of system libraries needed by zig.
        \\
        \\// Introspection and determination of system libraries needed by zig.
        \\
        \\const std = @import("std");
        \\
    );
}

test "zig fmt: line comment after doc comment" {
    try test_canonical(
        \\/// doc comment
        \\// line comment
        \\fn foo() void {}
        \\
    );
}

test "zig fmt: bit field alignment" {
    try test_canonical(
        \\test {
        \\    assert(@TypeOf(&blah.b) == *align(1:3:6) const u3);
        \\}
        \\
    );
}

test "zig fmt: nested switch" {
    try test_canonical(
        \\test {
        \\    switch (state) {
        \\        TermState.Start => switch (c) {
        \\            '\x1b' => state = TermState.Escape,
        \\            else => try out.write_byte(c),
        \\        },
        \\    }
        \\}
        \\
    );
}

test "zig fmt: float literal with exponent" {
    try test_canonical(
        \\pub const f64_true_min = 4.94065645841246544177e-324;
        \\const threshold = 0x1.a827999fcef32p+1022;
        \\
    );
}

test "zig fmt: if-else end of comptime" {
    try test_canonical(
        \\comptime {
        \\    if (a) {
        \\        b();
        \\    } else {
        \\        b();
        \\    }
        \\}
        \\
    );
}

test "zig fmt: nested blocks" {
    try test_canonical(
        \\comptime {
        \\    {
        \\        {
        \\            {
        \\                a();
        \\            }
        \\        }
        \\    }
        \\}
        \\
    );
}

test "zig fmt: block with same line comment after end brace" {
    try test_canonical(
        \\comptime {
        \\    {
        \\        b();
        \\    } // comment
        \\}
        \\
    );
}

test "zig fmt: statements with comment between" {
    try test_canonical(
        \\comptime {
        \\    a = b;
        \\    // comment
        \\    a = b;
        \\}
        \\
    );
}

test "zig fmt: statements with empty line between" {
    try test_canonical(
        \\comptime {
        \\    a = b;
        \\
        \\    a = b;
        \\}
        \\
    );
}

test "zig fmt: ptr deref operator and unwrap optional operator" {
    try test_canonical(
        \\const a = b.*;
        \\const a = b.?;
        \\
    );
}

test "zig fmt: comment after if before another if" {
    try test_canonical(
        \\test "aoeu" {
        \\    // comment
        \\    if (x) {
        \\        bar();
        \\    }
        \\}
        \\
        \\test "aoeu" {
        \\    if (x) {
        \\        foo();
        \\    }
        \\    // comment
        \\    if (x) {
        \\        bar();
        \\    }
        \\}
        \\
    );
}

test "zig fmt: line comment between if block and else keyword" {
    try test_canonical(
        \\test "aoeu" {
        \\    // cexp(finite|nan +- i inf|nan) = nan + i nan
        \\    if ((hx & 0x7fffffff) != 0x7f800000) {
        \\        return Complex(f32).init(y - y, y - y);
        \\    }
        \\    // cexp(-inf +- i inf|nan) = 0 + i0
        \\    else if (hx & 0x80000000 != 0) {
        \\        return Complex(f32).init(0, 0);
        \\    }
        \\    // cexp(+inf +- i inf|nan) = inf + i nan
        \\    // another comment
        \\    else {
        \\        return Complex(f32).init(x, y - y);
        \\    }
        \\}
        \\
    );
}

test "zig fmt: same line comments in expression" {
    try test_canonical(
        \\test "aoeu" {
        \\    const x = ( // a
        \\        0 // b
        \\    ); // c
        \\}
        \\
    );
}

test "zig fmt: add comma on last switch prong" {
    try test_transform(
        \\test "aoeu" {
        \\switch (self.init_arg_expr) {
        \\    InitArg.Type => |t| { },
        \\    InitArg.None,
        \\    InitArg.Enum => { }
        \\}
        \\ switch (self.init_arg_expr) {
        \\     InitArg.Type => |t| { },
        \\     InitArg.None,
        \\     InitArg.Enum => { }//line comment
        \\ }
        \\}
    ,
        \\test "aoeu" {
        \\    switch (self.init_arg_expr) {
        \\        InitArg.Type => |t| {},
        \\        InitArg.None, InitArg.Enum => {},
        \\    }
        \\    switch (self.init_arg_expr) {
        \\        InitArg.Type => |t| {},
        \\        InitArg.None, InitArg.Enum => {}, //line comment
        \\    }
        \\}
        \\
    );
}

test "zig fmt: same-line comment after a statement" {
    try test_canonical(
        \\test "" {
        \\    a = b;
        \\    debug.assert(H.digest_size <= H.block_size); // HMAC makes this assumption
        \\    a = b;
        \\}
        \\
    );
}

test "zig fmt: same-line comment after var decl in struct" {
    try test_canonical(
        \\pub const vfs_cap_data = extern struct {
        \\    const Data = struct {}; // when on disk.
        \\};
        \\
    );
}

test "zig fmt: same-line comment after field decl" {
    try test_canonical(
        \\pub const dirent = extern struct {
        \\    d_name: u8,
        \\    d_name: u8, // comment 1
        \\    d_name: u8,
        \\    d_name: u8, // comment 2
        \\    d_name: u8,
        \\};
        \\
    );
}

test "zig fmt: same-line comment after switch prong" {
    try test_canonical(
        \\test "" {
        \\    switch (err) {
        \\        error.PathAlreadyExists => {}, // comment 2
        \\        else => return err, // comment 1
        \\    }
        \\}
        \\
    );
}

test "zig fmt: same-line comment after non-block if expression" {
    try test_canonical(
        \\comptime {
        \\    if (sr > n_uword_bits - 1) // d > r
        \\        return 0;
        \\}
        \\
    );
}

test "zig fmt: same-line comment on comptime expression" {
    try test_canonical(
        \\test "" {
        \\    comptime assert(@typeInfo(T) == .Int); // must pass an integer to absInt
        \\}
        \\
    );
}

test "zig fmt: switch with empty body" {
    try test_canonical(
        \\test "" {
        \\    foo() catch |err| switch (err) {};
        \\}
        \\
    );
}

test "zig fmt: line comments in struct initializer" {
    try test_canonical(
        \\fn foo() void {
        \\    return Self{
        \\        .a = b,
        \\
        \\        // Initialize these two fields to buffer_size so that
        \\        // in `read_fn` we treat the state as being able to read
        \\        .start_index = buffer_size,
        \\        .end_index = buffer_size,
        \\
        \\        // middle
        \\
        \\        .a = b,
        \\
        \\        // end
        \\    };
        \\}
        \\
    );
}

test "zig fmt: first line comment in struct initializer" {
    try test_canonical(
        \\pub fn acquire(self: *Self) HeldLock {
        \\    return HeldLock{
        \\        // guaranteed allocation elision
        \\        .held = self.lock.acquire(),
        \\        .value = &self.private_data,
        \\    };
        \\}
        \\
    );
}

test "zig fmt: doc comments before struct field" {
    try test_canonical(
        \\pub const Allocator = struct {
        \\    /// Allocate byte_count bytes and return them in a slice, with the
        \\    /// slice's pointer aligned at least to alignment bytes.
        \\    alloc_fn: fn () void,
        \\};
        \\
    );
}

test "zig fmt: error set declaration" {
    try test_canonical(
        \\const E = error{
        \\    A,
        \\    B,
        \\
        \\    C,
        \\};
        \\
        \\const Error = error{
        \\    /// no more memory
        \\    OutOfMemory,
        \\};
        \\
        \\const Error = error{
        \\    /// no more memory
        \\    OutOfMemory,
        \\
        \\    /// another
        \\    Another,
        \\
        \\    // end
        \\};
        \\
        \\const Error = error{OutOfMemory};
        \\const Error = error{};
        \\
        \\const Error = error{ OutOfMemory, OutOfTime };
        \\
    );
}

test "zig fmt: union(enum(u32)) with assigned enum values" {
    try test_canonical(
        \\const MultipleChoice = union(enum(u32)) {
        \\    A = 20,
        \\    B = 40,
        \\    C = 60,
        \\    D = 1000,
        \\};
        \\
    );
}

test "zig fmt: resume from suspend block" {
    try test_canonical(
        \\fn foo() void {
        \\    suspend {
        \\        resume @frame();
        \\    }
        \\}
        \\
    );
}

test "zig fmt: comments before error set decl" {
    try test_canonical(
        \\const UnexpectedError = error{
        \\    /// The Operating System returned an undocumented error code.
        \\    Unexpected,
        \\    // another
        \\    Another,
        \\
        \\    // in between
        \\
        \\    // at end
        \\};
        \\
    );
}

test "zig fmt: comments before switch prong" {
    try test_canonical(
        \\test "" {
        \\    switch (err) {
        \\        error.PathAlreadyExists => continue,
        \\
        \\        // comment 1
        \\
        \\        // comment 2
        \\        else => return err,
        \\        // at end
        \\    }
        \\}
        \\
    );
}

test "zig fmt: comments before var decl in struct" {
    try test_canonical(
        \\pub const vfs_cap_data = extern struct {
        \\    // All of these are mandated as little endian
        \\    // when on disk.
        \\    const Data = struct {
        \\        permitted: u32,
        \\        inheritable: u32,
        \\    };
        \\
        \\    // in between
        \\
        \\    /// All of these are mandated as little endian
        \\    /// when on disk.
        \\    const Data = struct {
        \\        permitted: u32,
        \\        inheritable: u32,
        \\    };
        \\
        \\    // at end
        \\};
        \\
    );
}

test "zig fmt: array literal with 1 item on 1 line" {
    try test_canonical(
        \\var s = []const u64{0} ** 25;
        \\
    );
}

test "zig fmt: comments before global variables" {
    try test_canonical(
        \\/// Foo copies keys and values before they go into the map, and
        \\/// frees them when they get removed.
        \\pub const Foo = struct {};
        \\
    );
}

test "zig fmt: comments in statements" {
    try test_canonical(
        \\test "std" {
        \\    // statement comment
        \\    _ = @import("foo/bar.zig");
        \\
        \\    // middle
        \\    // middle2
        \\
        \\    // end
        \\}
        \\
    );
}

test "zig fmt: comments before test decl" {
    try test_canonical(
        \\// top level normal comment
        \\test "hi" {}
        \\
        \\// middle
        \\
        \\// end
        \\
    );
}

test "zig fmt: preserve spacing" {
    try test_canonical(
        \\const std = @import("std");
        \\
        \\pub fn main() !void {
        \\    var stdout_file = std.io.get_std_out;
        \\    var stdout_file = std.io.get_std_out;
        \\
        \\    var stdout_file = std.io.get_std_out;
        \\    var stdout_file = std.io.get_std_out;
        \\}
        \\
    );
}

test "zig fmt: return types" {
    try test_canonical(
        \\pub fn main() !void {}
        \\pub fn main() FooBar {}
        \\pub fn main() i32 {}
        \\
    );
}

test "zig fmt: imports" {
    try test_canonical(
        \\const std = @import("std");
        \\const std = @import();
        \\
    );
}

test "zig fmt: global declarations" {
    try test_canonical(
        \\const a = b;
        \\pub const a = b;
        \\var a = b;
        \\pub var a = b;
        \\const a: i32 = b;
        \\pub const a: i32 = b;
        \\var a: i32 = b;
        \\pub var a: i32 = b;
        \\extern const a: i32 = b;
        \\pub extern const a: i32 = b;
        \\extern var a: i32 = b;
        \\pub extern var a: i32 = b;
        \\extern "a" const a: i32 = b;
        \\pub extern "a" const a: i32 = b;
        \\extern "a" var a: i32 = b;
        \\pub extern "a" var a: i32 = b;
        \\
    );
}

test "zig fmt: extern declaration" {
    try test_canonical(
        \\extern var foo: c_int;
        \\
    );
}

test "zig fmt: alignment" {
    try test_canonical(
        \\var foo: c_int align(1);
        \\
    );
}

test "zig fmt: C main" {
    try test_canonical(
        \\fn main(argc: c_int, argv: **u8) c_int {
        \\    const a = b;
        \\}
        \\
    );
}

test "zig fmt: return" {
    try test_canonical(
        \\fn foo(argc: c_int, argv: **u8) c_int {
        \\    return 0;
        \\}
        \\
        \\fn bar() void {
        \\    return;
        \\}
        \\
    );
}

test "zig fmt: function attributes" {
    try test_canonical(
        \\export fn foo() void {}
        \\pub export fn foo() void {}
        \\extern fn foo() void;
        \\pub extern fn foo() void;
        \\extern "c" fn foo() void;
        \\pub extern "c" fn foo() void;
        \\noinline fn foo() void {}
        \\pub noinline fn foo() void {}
        \\
    );
}

test "zig fmt: nested pointers with ** tokens" {
    try test_canonical(
        \\const x: *u32 = undefined;
        \\const x: **u32 = undefined;
        \\const x: ***u32 = undefined;
        \\const x: ****u32 = undefined;
        \\const x: *****u32 = undefined;
        \\const x: ******u32 = undefined;
        \\const x: *******u32 = undefined;
        \\
    );
}

test "zig fmt: pointer attributes" {
    try test_canonical(
        \\extern fn f1(s: *align(*u8) u8) c_int;
        \\extern fn f2(s: **align(1) *const *volatile u8) c_int;
        \\extern fn f3(s: *align(1) const *align(1) volatile *const volatile u8) c_int;
        \\extern fn f4(s: *align(1) const volatile u8) c_int;
        \\extern fn f5(s: [*:0]align(1) const volatile u8) c_int;
        \\
    );
}

test "zig fmt: slice attributes" {
    try test_canonical(
        \\extern fn f1(s: []align(*u8) u8) c_int;
        \\extern fn f2(s: []align(1) []const []volatile u8) c_int;
        \\extern fn f3(s: []align(1) const [:0]align(1) volatile []const volatile u8) c_int;
        \\extern fn f4(s: []align(1) const volatile u8) c_int;
        \\extern fn f5(s: [:0]align(1) const volatile u8) c_int;
        \\
    );
}

test "zig fmt: test declaration" {
    try test_canonical(
        \\test "test name" {
        \\    const a = 1;
        \\    var b = 1;
        \\}
        \\
    );
}

test "zig fmt: destructure" {
    try test_canonical(
        \\comptime {
        \\    var w: u8, var x: u8 = .{ 1, 2 };
        \\    w, var y: u8 = .{ 3, 4 };
        \\    var z: u8, x = .{ 5, 6 };
        \\    y, z = .{ 7, 8 };
        \\}
        \\
        \\comptime {
        \\    comptime var w, var x = .{ 1, 2 };
        \\    comptime w, var y = .{ 3, 4 };
        \\    comptime var z, x = .{ 5, 6 };
        \\    comptime y, z = .{ 7, 8 };
        \\}
        \\
    );
}

test "zig fmt: infix operators" {
    try test_canonical(
        \\test {
        \\    var i = undefined;
        \\    i = 2;
        \\    i *= 2;
        \\    i |= 2;
        \\    i ^= 2;
        \\    i <<= 2;
        \\    i >>= 2;
        \\    i &= 2;
        \\    i *= 2;
        \\    i *%= 2;
        \\    i -= 2;
        \\    i -%= 2;
        \\    i += 2;
        \\    i +%= 2;
        \\    i /= 2;
        \\    i %= 2;
        \\    _ = i == i;
        \\    _ = i != i;
        \\    _ = i != i;
        \\    _ = i.i;
        \\    _ = i || i;
        \\    _ = i!i;
        \\    _ = i ** i;
        \\    _ = i ++ i;
        \\    _ = i orelse i;
        \\    _ = i % i;
        \\    _ = i / i;
        \\    _ = i *% i;
        \\    _ = i * i;
        \\    _ = i -% i;
        \\    _ = i - i;
        \\    _ = i +% i;
        \\    _ = i + i;
        \\    _ = i << i;
        \\    _ = i >> i;
        \\    _ = i & i;
        \\    _ = i ^ i;
        \\    _ = i | i;
        \\    _ = i >= i;
        \\    _ = i <= i;
        \\    _ = i > i;
        \\    _ = i < i;
        \\    _ = i and i;
        \\    _ = i or i;
        \\}
        \\
    );
}

test "zig fmt: precedence" {
    try test_canonical(
        \\test "precedence" {
        \\    a!b();
        \\    (a!b)();
        \\    !a!b;
        \\    !(a!b);
        \\    !a{};
        \\    !(a{});
        \\    a + b{};
        \\    (a + b){};
        \\    a << b + c;
        \\    (a << b) + c;
        \\    a & b << c;
        \\    (a & b) << c;
        \\    a ^ b & c;
        \\    (a ^ b) & c;
        \\    a | b ^ c;
        \\    (a | b) ^ c;
        \\    a == b | c;
        \\    (a == b) | c;
        \\    a and b == c;
        \\    (a and b) == c;
        \\    a or b and c;
        \\    (a or b) and c;
        \\    (a or b) and c;
        \\    a == b and c == d;
        \\}
        \\
    );
}

test "zig fmt: prefix operators" {
    try test_canonical(
        \\test "prefix operators" {
        \\    try return --%~!&0;
        \\}
        \\
    );
}

test "zig fmt: call expression" {
    try test_canonical(
        \\test "test calls" {
        \\    a();
        \\    a(1);
        \\    a(1, 2);
        \\    a(1, 2) + a(1, 2);
        \\}
        \\
    );
}

test "zig fmt: anytype type" {
    try test_canonical(
        \\fn print(args: anytype) @This() {}
        \\
    );
}

test "zig fmt: functions" {
    try test_canonical(
        \\extern fn puts(s: *const u8) c_int;
        \\extern "c" fn puts(s: *const u8) c_int;
        \\export fn puts(s: *const u8) c_int;
        \\inline fn puts(s: *const u8) c_int;
        \\noinline fn puts(s: *const u8) c_int;
        \\pub extern fn puts(s: *const u8) c_int;
        \\pub extern "c" fn puts(s: *const u8) c_int;
        \\pub export fn puts(s: *const u8) c_int;
        \\pub inline fn puts(s: *const u8) c_int;
        \\pub noinline fn puts(s: *const u8) c_int;
        \\pub extern fn puts(s: *const u8) align(2 + 2) c_int;
        \\pub extern "c" fn puts(s: *const u8) align(2 + 2) c_int;
        \\pub export fn puts(s: *const u8) align(2 + 2) c_int;
        \\pub inline fn puts(s: *const u8) align(2 + 2) c_int;
        \\pub noinline fn puts(s: *const u8) align(2 + 2) c_int;
        \\pub fn call_inline_fn(func: fn () callconv(.Inline) void) void {
        \\    func();
        \\}
        \\
    );
}

test "zig fmt: multiline string" {
    try test_canonical(
        \\test "" {
        \\    const s1 =
        \\        \\one
        \\        \\two)
        \\        \\three
        \\    ;
        \\    const s3 = // hi
        \\        \\one
        \\        \\two)
        \\        \\three
        \\    ;
        \\}
        \\
    );
}

test "zig fmt: values" {
    try test_canonical(
        \\test "values" {
        \\    1;
        \\    1.0;
        \\    "string";
        \\    'c';
        \\    true;
        \\    false;
        \\    null;
        \\    undefined;
        \\    anyerror;
        \\    this;
        \\    unreachable;
        \\}
        \\
    );
}

test "zig fmt: indexing" {
    try test_canonical(
        \\test "test index" {
        \\    a[0];
        \\    a[0 + 5];
        \\    a[0..];
        \\    a[0..5];
        \\    a[a[0]];
        \\    a[a[0..]];
        \\    a[a[0..5]];
        \\    a[a[0]..];
        \\    a[a[0..5]..];
        \\    a[a[0]..a[0]];
        \\    a[a[0..5]..a[0]];
        \\    a[a[0..5]..a[0..5]];
        \\}
        \\
    );
}

test "zig fmt: struct declaration" {
    try test_canonical(
        \\const S = struct {
        \\    const Self = @This();
        \\    f1: u8,
        \\    f3: u8,
        \\
        \\    f2: u8,
        \\
        \\    fn method(self: *Self) Self {
        \\        return self.*;
        \\    }
        \\};
        \\
        \\const Ps = packed struct {
        \\    a: u8,
        \\    b: u8,
        \\
        \\    c: u8,
        \\};
        \\
        \\const Ps = packed struct(u32) {
        \\    a: u1,
        \\    b: u2,
        \\
        \\    c: u29,
        \\};
        \\
        \\const Es = extern struct {
        \\    a: u8,
        \\    b: u8,
        \\
        \\    c: u8,
        \\};
        \\
    );
}

test "zig fmt: enum declaration" {
    try test_canonical(
        \\const E = enum {
        \\    Ok,
        \\    SomethingElse = 0,
        \\};
        \\
        \\const E2 = enum(u8) {
        \\    Ok,
        \\    SomethingElse = 255,
        \\    SomethingThird,
        \\};
        \\
        \\const Ee = extern enum {
        \\    Ok,
        \\    SomethingElse,
        \\    SomethingThird,
        \\};
        \\
        \\const Ep = packed enum {
        \\    Ok,
        \\    SomethingElse,
        \\    SomethingThird,
        \\};
        \\
    );
}

test "zig fmt: union declaration" {
    try test_canonical(
        \\const U = union {
        \\    Int: u8,
        \\    Float: f32,
        \\    None,
        \\    Bool: bool,
        \\};
        \\
        \\const Ue = union(enum) {
        \\    Int: u8,
        \\    Float: f32,
        \\    None,
        \\    Bool: bool,
        \\};
        \\
        \\const E = enum {
        \\    Int,
        \\    Float,
        \\    None,
        \\    Bool,
        \\};
        \\
        \\const Ue2 = union(E) {
        \\    Int: u8,
        \\    Float: f32,
        \\    None,
        \\    Bool: bool,
        \\};
        \\
        \\const Eu = extern union {
        \\    Int: u8,
        \\    Float: f32,
        \\    None,
        \\    Bool: bool,
        \\};
        \\
    );
}

test "zig fmt: arrays" {
    try test_canonical(
        \\test "test array" {
        \\    const a: [2]u8 = [2]u8{
        \\        1,
        \\        2,
        \\    };
        \\    const a: [2]u8 = []u8{
        \\        1,
        \\        2,
        \\    };
        \\    const a: [0]u8 = []u8{};
        \\    const x: [4:0]u8 = undefined;
        \\}
        \\
    );
}

test "zig fmt: container initializers" {
    try test_canonical(
        \\const a0 = []u8{};
        \\const a1 = []u8{1};
        \\const a2 = []u8{
        \\    1,
        \\    2,
        \\    3,
        \\    4,
        \\};
        \\const s0 = S{};
        \\const s1 = S{ .a = 1 };
        \\const s2 = S{
        \\    .a = 1,
        \\    .b = 2,
        \\};
        \\
    );
}

test "zig fmt: catch" {
    try test_canonical(
        \\test "catch" {
        \\    const a: anyerror!u8 = 0;
        \\    _ = a catch return;
        \\    _ = a catch
        \\        return;
        \\    _ = a catch |err| return;
        \\    _ = a catch |err|
        \\        return;
        \\}
        \\
    );
}

test "zig fmt: blocks" {
    try test_canonical(
        \\test "blocks" {
        \\    {
        \\        const a = 0;
        \\        const b = 0;
        \\    }
        \\
        \\    blk: {
        \\        const a = 0;
        \\        const b = 0;
        \\    }
        \\
        \\    const r = blk: {
        \\        const a = 0;
        \\        const b = 0;
        \\    };
        \\}
        \\
    );
}

test "zig fmt: switch" {
    try test_canonical(
        \\test "switch" {
        \\    switch (0) {
        \\        0 => {},
        \\        1 => unreachable,
        \\        2, 3 => {},
        \\        4...7 => {},
        \\        1 + 4 * 3 + 22 => {},
        \\        else => {
        \\            const a = 1;
        \\            const b = a;
        \\        },
        \\    }
        \\
        \\    const res = switch (0) {
        \\        0 => 0,
        \\        1 => 2,
        \\        1 => a = 4,
        \\        else => 4,
        \\    };
        \\
        \\    const Union = union(enum) {
        \\        Int: i64,
        \\        Float: f64,
        \\    };
        \\
        \\    switch (u) {
        \\        Union.Int => |int| {},
        \\        Union.Float => |*float| unreachable,
        \\        1 => |a, b| unreachable,
        \\        2 => |*a, b| unreachable,
        \\    }
        \\}
        \\
    );

    try test_transform(
        \\test {
        \\    switch (x) {
        \\        foo =>
        \\            "bar",
        \\    }
        \\}
        \\
    ,
        \\test {
        \\    switch (x) {
        \\        foo => "bar",
        \\    }
        \\}
        \\
    );
}

test "zig fmt: switch multiline string" {
    try test_canonical(
        \\test "switch multiline string" {
        \\    const x: u32 = 0;
        \\    const str = switch (x) {
        \\        1 => "one",
        \\        2 =>
        \\        \\ Comma after the multiline string
        \\        \\ is needed
        \\        ,
        \\        3 => "three",
        \\        else => "else",
        \\    };
        \\
        \\    const Union = union(enum) {
        \\        Int: i64,
        \\        Float: f64,
        \\    };
        \\
        \\    const str = switch (u) {
        \\        Union.Int => |int|
        \\        \\ Comma after the multiline string
        \\        \\ is needed
        \\        ,
        \\        Union.Float => |*float| unreachable,
        \\    };
        \\}
        \\
    );
}

test "zig fmt: while" {
    try test_canonical(
        \\test "while" {
        \\    while (10 < 1) unreachable;
        \\
        \\    while (10 < 1) unreachable else unreachable;
        \\
        \\    while (10 < 1) {
        \\        unreachable;
        \\    }
        \\
        \\    while (10 < 1)
        \\        unreachable;
        \\
        \\    var i: usize = 0;
        \\    while (i < 10) : (i += 1) {
        \\        continue;
        \\    }
        \\
        \\    i = 0;
        \\    while (i < 10) : (i += 1)
        \\        continue;
        \\
        \\    i = 0;
        \\    var j: usize = 0;
        \\    while (i < 10) : ({
        \\        i += 1;
        \\        j += 1;
        \\    }) continue;
        \\
        \\    while (i < 10) : ({
        \\        i += 1;
        \\        j += 1;
        \\    }) {
        \\        continue;
        \\    }
        \\
        \\    var a: ?u8 = 2;
        \\    while (a) |v| : (a = null) {
        \\        continue;
        \\    }
        \\
        \\    while (a) |v| : (a = null)
        \\        unreachable;
        \\
        \\    label: while (10 < 0) {
        \\        unreachable;
        \\    }
        \\
        \\    const res = while (0 < 10) {
        \\        break 7;
        \\    } else {
        \\        unreachable;
        \\    };
        \\
        \\    const res = while (0 < 10)
        \\        break 7
        \\    else
        \\        unreachable;
        \\
        \\    var a: anyerror!u8 = 0;
        \\    while (a) |v| {
        \\        a = error.Err;
        \\    } else |err| {
        \\        i = 1;
        \\    }
        \\
        \\    comptime var k: usize = 0;
        \\    inline while (i < 10) : (i += 1)
        \\        j += 2;
        \\}
        \\
    );
}

test "zig fmt: for" {
    try test_canonical(
        \\test "for" {
        \\    for (a) |v| {
        \\        continue;
        \\    }
        \\
        \\    for (a) |v| continue;
        \\
        \\    for (a) |v| continue else return;
        \\
        \\    for (a) |v| {
        \\        continue;
        \\    } else return;
        \\
        \\    for (a) |v| continue else {
        \\        return;
        \\    }
        \\
        \\    for (a) |v|
        \\        continue
        \\    else
        \\        return;
        \\
        \\    for (a) |v|
        \\        continue;
        \\
        \\    for (a) |*v|
        \\        continue;
        \\
        \\    for (a, 0..) |v, i| {
        \\        continue;
        \\    }
        \\
        \\    for (a, 0..) |v, i|
        \\        continue;
        \\
        \\    for (a) |b| switch (b) {
        \\        c => {},
        \\        d => {},
        \\    };
        \\
        \\    const res = for (a, 0..) |v, i| {
        \\        break v;
        \\    } else {
        \\        unreachable;
        \\    };
        \\
        \\    var num: usize = 0;
        \\    inline for (a, 0..1) |v, i| {
        \\        num += v;
        \\        num += i;
        \\    }
        \\
        \\    for (a, b) |
        \\        long_name,
        \\        another_long_name,
        \\    | {
        \\        continue;
        \\    }
        \\}
        \\
    );

    try test_transform(
        \\test "fix for" {
        \\    for (a) |x|
        \\        f(x) else continue;
        \\}
        \\
    ,
        \\test "fix for" {
        \\    for (a) |x|
        \\        f(x)
        \\    else
        \\        continue;
        \\}
        \\
    );

    try test_transform(
        \\test "fix for" {
        \\    for (a, b, c,) |long, another, third,| {}
        \\}
        \\
    ,
        \\test "fix for" {
        \\    for (
        \\        a,
        \\        b,
        \\        c,
        \\    ) |
        \\        long,
        \\        another,
        \\        third,
        \\    | {}
        \\}
        \\
    );
}

test "zig fmt: for if" {
    try test_canonical(
        \\test {
        \\    for (a) |x| if (x) f(x);
        \\
        \\    for (a) |x| if (x)
        \\        f(x);
        \\
        \\    for (a) |x| if (x) {
        \\        f(x);
        \\    };
        \\
        \\    for (a) |x|
        \\        if (x)
        \\            f(x);
        \\
        \\    for (a) |x|
        \\        if (x) {
        \\            f(x);
        \\        };
        \\}
        \\
    );
}

test "zig fmt: if for" {
    try test_canonical(
        \\test {
        \\    if (a) for (x) |x| f(x);
        \\
        \\    if (a) for (x) |x|
        \\        f(x);
        \\
        \\    if (a) for (x) |x| {
        \\        f(x);
        \\    };
        \\
        \\    if (a)
        \\        for (x) |x|
        \\            f(x);
        \\
        \\    if (a)
        \\        for (x) |x| {
        \\            f(x);
        \\        };
        \\}
        \\
    );
}

test "zig fmt: while if" {
    try test_canonical(
        \\test {
        \\    while (a) if (x) f(x);
        \\
        \\    while (a) if (x)
        \\        f(x);
        \\
        \\    while (a) if (x) {
        \\        f(x);
        \\    };
        \\
        \\    while (a)
        \\        if (x)
        \\            f(x);
        \\
        \\    while (a)
        \\        if (x) {
        \\            f(x);
        \\        };
        \\}
        \\
    );
}

test "zig fmt: if while" {
    try test_canonical(
        \\test {
        \\    if (a) while (x) : (cont) f(x);
        \\
        \\    if (a) while (x) : (cont)
        \\        f(x);
        \\
        \\    if (a) while (x) : (cont) {
        \\        f(x);
        \\    };
        \\
        \\    if (a)
        \\        while (x) : (cont)
        \\            f(x);
        \\
        \\    if (a)
        \\        while (x) : (cont) {
        \\            f(x);
        \\        };
        \\}
        \\
    );
}

test "zig fmt: while for" {
    try test_canonical(
        \\test {
        \\    while (a) for (x) |x| f(x);
        \\
        \\    while (a) for (x) |x|
        \\        f(x);
        \\
        \\    while (a) for (x) |x| {
        \\        f(x);
        \\    };
        \\
        \\    while (a)
        \\        for (x) |x|
        \\            f(x);
        \\
        \\    while (a)
        \\        for (x) |x| {
        \\            f(x);
        \\        };
        \\}
        \\
    );
}

test "zig fmt: for while" {
    try test_canonical(
        \\test {
        \\    for (a) |a| while (x) |x| f(x);
        \\
        \\    for (a) |a| while (x) |x|
        \\        f(x);
        \\
        \\    for (a) |a| while (x) |x| {
        \\        f(x);
        \\    };
        \\
        \\    for (a) |a|
        \\        while (x) |x|
        \\            f(x);
        \\
        \\    for (a) |a|
        \\        while (x) |x| {
        \\            f(x);
        \\        };
        \\}
        \\
    );
}

test "zig fmt: if" {
    try test_canonical(
        \\test "if" {
        \\    if (10 < 0) {
        \\        unreachable;
        \\    }
        \\
        \\    if (10 < 0) unreachable;
        \\
        \\    if (10 < 0) {
        \\        unreachable;
        \\    } else {
        \\        const a = 20;
        \\    }
        \\
        \\    if (10 < 0) {
        \\        unreachable;
        \\    } else if (5 < 0) {
        \\        unreachable;
        \\    } else {
        \\        const a = 20;
        \\    }
        \\
        \\    const is_world_broken = if (10 < 0) true else false;
        \\    const some_number = 1 + if (10 < 0) 2 else 3;
        \\
        \\    const a: ?u8 = 10;
        \\    const b: ?u8 = null;
        \\    if (a) |v| {
        \\        const some = v;
        \\    } else if (b) |*v| {
        \\        unreachable;
        \\    } else {
        \\        const some = 10;
        \\    }
        \\
        \\    const non_null_a = if (a) |v| v else 0;
        \\
        \\    const a_err: anyerror!u8 = 0;
        \\    if (a_err) |v| {
        \\        const p = v;
        \\    } else |err| {
        \\        unreachable;
        \\    }
        \\}
        \\
    );
}

test "zig fmt: fix single statement if/for/while line breaks" {
    try test_transform(
        \\test {
        \\    if (cond) a
        \\    else b;
        \\
        \\    if (cond)
        \\        a
        \\    else b;
        \\
        \\    for (xs) |x| foo()
        \\    else bar();
        \\
        \\    for (xs) |x|
        \\        foo()
        \\    else bar();
        \\
        \\    while (a) : (b) foo()
        \\    else bar();
        \\
        \\    while (a) : (b)
        \\        foo()
        \\    else bar();
        \\}
        \\
    ,
        \\test {
        \\    if (cond) a else b;
        \\
        \\    if (cond)
        \\        a
        \\    else
        \\        b;
        \\
        \\    for (xs) |x| foo() else bar();
        \\
        \\    for (xs) |x|
        \\        foo()
        \\    else
        \\        bar();
        \\
        \\    while (a) : (b) foo() else bar();
        \\
        \\    while (a) : (b)
        \\        foo()
        \\    else
        \\        bar();
        \\}
        \\
    );
}

test "zig fmt: anon struct/array literal in if" {
    try test_canonical(
        \\test {
        \\    const a = if (cond) .{
        \\        1, 2,
        \\        3, 4,
        \\    } else .{
        \\        1,
        \\        2,
        \\        3,
        \\    };
        \\
        \\    const rl_and_tag: struct { rl: ResultLoc, tag: zir.Inst.Tag } = if (any_payload_is_ref) .{
        \\        .rl = .ref,
        \\        .tag = .switchbr_ref,
        \\    } else .{
        \\        .rl = .none,
        \\        .tag = .switchbr,
        \\    };
        \\}
        \\
    );
}

test "zig fmt: defer" {
    try test_canonical(
        \\test "defer" {
        \\    var i: usize = 0;
        \\    defer i = 1;
        \\    defer {
        \\        i += 2;
        \\        i *= i;
        \\    }
        \\
        \\    errdefer i += 3;
        \\    errdefer {
        \\        i += 2;
        \\        i /= i;
        \\    }
        \\}
        \\
    );
}

test "zig fmt: comptime" {
    try test_canonical(
        \\fn a() u8 {
        \\    return 5;
        \\}
        \\
        \\fn b(comptime i: u8) u8 {
        \\    return i;
        \\}
        \\
        \\const av = comptime a();
        \\const av2 = comptime blk: {
        \\    var res = a();
        \\    res *= b(2);
        \\    break :blk res;
        \\};
        \\
        \\comptime {
        \\    _ = a();
        \\}
        \\
        \\test "comptime" {
        \\    const av3 = comptime a();
        \\    const av4 = comptime blk: {
        \\        var res = a();
        \\        res *= a();
        \\        break :blk res;
        \\    };
        \\
        \\    comptime var i = 0;
        \\    comptime {
        \\        i = a();
        \\        i += b(i);
        \\    }
        \\}
        \\
    );
}

test "zig fmt: fn type" {
    try test_canonical(
        \\fn a(i: u8) u8 {
        \\    return i + 1;
        \\}
        \\
        \\const a: fn (u8) u8 = undefined;
        \\const b: fn (u8) callconv(.Naked) u8 = undefined;
        \\const ap: fn (u8) u8 = a;
        \\
    );
}

test "zig fmt: inline asm" {
    try test_canonical(
        \\pub fn syscall1(number: usize, arg1: usize) usize {
        \\    return asm volatile ("syscall"
        \\        : [ret] "={rax}" (-> usize),
        \\        : [number] "{rax}" (number),
        \\          [arg1] "{rdi}" (arg1),
        \\        : "rcx", "r11"
        \\    );
        \\}
        \\
    );
}

test "zig fmt: async functions" {
    try test_canonical(
        \\fn simple_async_fn() void {
        \\    const a = async a.b();
        \\    x += 1;
        \\    suspend {}
        \\    x += 1;
        \\    suspend {}
        \\    const p: anyframe->void = async simple_async_fn() catch unreachable;
        \\    await p;
        \\}
        \\
        \\test "suspend, resume, await" {
        \\    const p: anyframe = async test_async_seq();
        \\    resume p;
        \\    await p;
        \\}
        \\
    );
}

test "zig fmt: nosuspend" {
    try test_canonical(
        \\const a = nosuspend foo();
        \\
    );
}

test "zig fmt: Block after if" {
    try test_canonical(
        \\test {
        \\    if (true) {
        \\        const a = 0;
        \\    }
        \\
        \\    {
        \\        const a = 0;
        \\    }
        \\}
        \\
    );
}

test "zig fmt: usingnamespace" {
    try test_canonical(
        \\usingnamespace @import("std");
        \\pub usingnamespace @import("std");
        \\
    );
}

test "zig fmt: string identifier" {
    try test_canonical(
        \\const @"a b" = @"c d".@"e f";
        \\fn @"g h"() void {}
        \\
    );
}

test "zig fmt: error return" {
    try test_canonical(
        \\fn err() anyerror {
        \\    call();
        \\    return error.InvalidArgs;
        \\}
        \\
    );
}

test "zig fmt: comptime block in container" {
    try test_canonical(
        \\pub fn container() type {
        \\    return struct {
        \\        comptime {
        \\            if (false) {
        \\                unreachable;
        \\            }
        \\        }
        \\    };
        \\}
        \\
    );
}

test "zig fmt: inline asm parameter alignment" {
    try test_canonical(
        \\pub fn main() void {
        \\    asm volatile (
        \\        \\ foo
        \\        \\ bar
        \\    );
        \\    asm volatile (
        \\        \\ foo
        \\        \\ bar
        \\        : [_] "" (-> usize),
        \\          [_] "" (-> usize),
        \\    );
        \\    asm volatile (
        \\        \\ foo
        \\        \\ bar
        \\        :
        \\        : [_] "" (0),
        \\          [_] "" (0),
        \\    );
        \\    asm volatile (
        \\        \\ foo
        \\        \\ bar
        \\        ::: "", "");
        \\    asm volatile (
        \\        \\ foo
        \\        \\ bar
        \\        : [_] "" (-> usize),
        \\          [_] "" (-> usize),
        \\        : [_] "" (0),
        \\          [_] "" (0),
        \\        : "", ""
        \\    );
        \\}
        \\
    );
}

test "zig fmt: multiline string in array" {
    try test_canonical(
        \\const Foo = [][]const u8{
        \\    \\aaa
        \\    ,
        \\    \\bbb
        \\};
        \\
        \\fn bar() void {
        \\    const Foo = [][]const u8{
        \\        \\aaa
        \\        ,
        \\        \\bbb
        \\    };
        \\    const Bar = [][]const u8{ // comment here
        \\        \\aaa
        \\        \\
        \\        , // and another comment can go here
        \\        \\bbb
        \\    };
        \\}
        \\
    );
}

test "zig fmt: if type expr" {
    try test_canonical(
        \\const mycond = true;
        \\pub fn foo() if (mycond) i32 else void {
        \\    if (mycond) {
        \\        return 42;
        \\    }
        \\}
        \\
    );
}
test "zig fmt: file ends with struct field" {
    try test_canonical(
        \\a: bool
        \\
    );
}

test "zig fmt: comment after empty comment" {
    try test_canonical(
        \\const x = true; //
        \\//
        \\//
        \\//a
        \\
    );
}

test "zig fmt: line comment in array" {
    try test_transform(
        \\test "a" {
        \\    var arr = [_]u32{
        \\        0
        \\        // 1,
        \\        // 2,
        \\    };
        \\}
        \\
    ,
        \\test "a" {
        \\    var arr = [_]u32{
        \\        0,
        \\        // 1,
        \\        // 2,
        \\    };
        \\}
        \\
    );
    try test_canonical(
        \\test "a" {
        \\    var arr = [_]u32{
        \\        0,
        \\        // 1,
        \\        // 2,
        \\    };
        \\}
        \\
    );
}

test "zig fmt: comment after params" {
    try test_transform(
        \\fn a(
        \\    b: u32
        \\    // c: u32,
        \\    // d: u32,
        \\) void {}
        \\
    ,
        \\fn a(
        \\    b: u32,
        \\    // c: u32,
        \\    // d: u32,
        \\) void {}
        \\
    );
    try test_canonical(
        \\fn a(
        \\    b: u32,
        \\    // c: u32,
        \\    // d: u32,
        \\) void {}
        \\
    );
}

test "zig fmt: comment in array initializer/access" {
    try test_canonical(
        \\test "a" {
        \\    var a = x{ //aa
        \\        //bb
        \\    };
        \\    var a = []x{ //aa
        \\        //bb
        \\    };
        \\    var b = [ //aa
        \\        _
        \\    ]x{ //aa
        \\        //bb
        \\        9,
        \\    };
        \\    var c = b[ //aa
        \\        0
        \\    ];
        \\    var d = [
        \\        _
        \\        //aa
        \\        :
        \\        0
        \\    ]x{ //aa
        \\        //bb
        \\        9,
        \\    };
        \\    var e = d[
        \\        0
        \\        //aa
        \\    ];
        \\}
        \\
    );
}

test "zig fmt: comments at several places in struct init" {
    try test_transform(
        \\var bar = Bar{
        \\    .x = 10, // test
        \\    .y = "test"
        \\    // test
        \\};
        \\
    ,
        \\var bar = Bar{
        \\    .x = 10, // test
        \\    .y = "test",
        \\    // test
        \\};
        \\
    );

    try test_canonical(
        \\var bar = Bar{ // test
        \\    .x = 10, // test
        \\    .y = "test",
        \\    // test
        \\};
        \\
    );
}

test "zig fmt: container doc comments" {
    try test_canonical(
        \\//! tld 1
        \\//! tld 2
        \\//! tld 3
        \\
        \\// comment
        \\
        \\/// A doc
        \\const A = struct {
        \\    //! A tld 1
        \\    //! A tld 2
        \\    //! A tld 3
        \\};
        \\
        \\/// B doc
        \\const B = struct {
        \\    //! B tld 1
        \\    //! B tld 2
        \\    //! B tld 3
        \\
        \\    /// B doc
        \\    b: u32,
        \\};
        \\
        \\/// C doc
        \\const C = union(enum) { // comment
        \\    //! C tld 1
        \\    //! C tld 2
        \\    //! C tld 3
        \\};
        \\
        \\/// D doc
        \\const D = union(Foo) {
        \\    //! D tld 1
        \\    //! D tld 2
        \\    //! D tld 3
        \\
        \\    /// D doc
        \\    b: u32,
        \\};
        \\
    );
    try test_canonical(
        \\//! Top-level documentation.
        \\
        \\/// This is A
        \\pub const A = usize;
        \\
    );
    try test_canonical(
        \\//! Nothing here
        \\
    );
}

test "zig fmt: remove newlines surrounding doc comment" {
    try test_transform(
        \\
        \\
        \\
        \\/// doc comment
        \\
        \\fn foo() void {}
        \\
    ,
        \\/// doc comment
        \\fn foo() void {}
        \\
    );
}

test "zig fmt: remove newlines surrounding doc comment between members" {
    try test_transform(
        \\f1: i32,
        \\
        \\
        \\/// doc comment
        \\
        \\f2: i32,
        \\
    ,
        \\f1: i32,
        \\
        \\/// doc comment
        \\f2: i32,
        \\
    );
}

test "zig fmt: remove newlines surrounding doc comment between members within container decl (1)" {
    try test_transform(
        \\const Foo = struct {
        \\    fn foo() void {}
        \\
        \\
        \\    /// doc comment
        \\
        \\
        \\    fn bar() void {}
        \\};
        \\
    ,
        \\const Foo = struct {
        \\    fn foo() void {}
        \\
        \\    /// doc comment
        \\    fn bar() void {}
        \\};
        \\
    );
}

test "zig fmt: remove newlines surrounding doc comment between members within container decl (2)" {
    try test_transform(
        \\const Foo = struct {
        \\    fn foo() void {}
        \\    /// doc comment 1
        \\
        \\    /// doc comment 2
        \\
        \\    fn bar() void {}
        \\};
        \\
    ,
        \\const Foo = struct {
        \\    fn foo() void {}
        \\    /// doc comment 1
        \\    /// doc comment 2
        \\    fn bar() void {}
        \\};
        \\
    );
}

test "zig fmt: remove newlines surrounding doc comment within container decl" {
    try test_transform(
        \\const Foo = struct {
        \\
        \\
        \\    /// doc comment
        \\
        \\    fn foo() void {}
        \\};
        \\
    ,
        \\const Foo = struct {
        \\    /// doc comment
        \\    fn foo() void {}
        \\};
        \\
    );
}

test "zig fmt: comptime before comptime field" {
    try test_error(
        \\const Foo = struct {
        \\    a: i32,
        \\    comptime comptime b: i32 = 1234,
        \\};
        \\
    , &[_]Error{
        .expected_comma_after_field,
    });
}

test "zig fmt: invalid doc comments on comptime and test blocks" {
    try test_error(
        \\/// This is a doc comment for a comptime block.
        \\comptime {}
        \\/// This is a doc comment for a test
        \\test "This is my test" {}
    , &[_]Error{
        .comptime_doc_comment,
        .test_doc_comment,
    });
}

test "zig fmt: else comptime expr" {
    try test_canonical(
        \\comptime {
        \\    if (true) {} else comptime foo();
        \\}
        \\comptime {
        \\    while (true) {} else comptime foo();
        \\}
        \\comptime {
        \\    for ("") |_| {} else comptime foo();
        \\}
        \\
    );
}

test "zig fmt: invalid else branch statement" {
    try test_error(
        \\comptime {
        \\    if (true) {} else var a = 0;
        \\    if (true) {} else defer {}
        \\}
        \\comptime {
        \\    while (true) {} else var a = 0;
        \\    while (true) {} else defer {}
        \\}
        \\comptime {
        \\    for ("") |_| {} else var a = 0;
        \\    for ("") |_| {} else defer {}
        \\}
    , &[_]Error{
        .expected_expr_or_assignment,
        .expected_expr_or_assignment,
        .expected_expr_or_assignment,
        .expected_expr_or_assignment,
        .expected_expr_or_assignment,
        .expected_expr_or_assignment,
    });
}

test "zig fmt: anytype struct field" {
    try test_error(
        \\pub const Pointer = struct {
        \\    sentinel: anytype,
        \\};
        \\
    , &[_]Error{
        .expected_type_expr,
    });
}

test "zig fmt: extern without container keyword returns error" {
    try test_error(
        \\const container = extern {};
        \\
    , &[_]Error{
        .expected_container,
    });
}

test "zig fmt: same line doc comment returns error" {
    try test_error(
        \\const Foo = struct{
        \\    bar: u32, /// comment
        \\    foo: u32, /// comment
        \\    /// comment
        \\};
        \\
        \\const a = 42; /// comment
        \\
        \\extern fn foo() void; /// comment
        \\
        \\/// comment
        \\
    , &[_]Error{
        .same_line_doc_comment,
        .same_line_doc_comment,
        .unattached_doc_comment,
        .same_line_doc_comment,
        .same_line_doc_comment,
        .unattached_doc_comment,
    });
}

test "zig fmt: integer literals with underscore separators" {
    try test_transform(
        \\const
        \\ x     =
        \\ 1_234_567
        \\ + (0b0_1-0o7_0+0xff_FF ) +  1_0;
    ,
        \\const x =
        \\    1_234_567 + (0b0_1 - 0o7_0 + 0xff_FF) + 1_0;
        \\
    );
}

test "zig fmt: hex literals with underscore separators" {
    try test_transform(
        \\pub fn or_mask(a: [ 1_000 ]u64, b: [  1_000]  u64) [1_000]u64 {
        \\    var c: [1_000]u64 =  [1]u64{ 0xFFFF_FFFF_FFFF_FFFF}**1_000;
        \\    for (c [ 1_0 .. ], 0..) |_, i| {
        \\        c[i] = (a[i] | b[i]) & 0xCCAA_CCAA_CCAA_CCAA;
        \\    }
        \\    return c;
        \\}
        \\
        \\
    ,
        \\pub fn or_mask(a: [1_000]u64, b: [1_000]u64) [1_000]u64 {
        \\    var c: [1_000]u64 = [1]u64{0xFFFF_FFFF_FFFF_FFFF} ** 1_000;
        \\    for (c[1_0..], 0..) |_, i| {
        \\        c[i] = (a[i] | b[i]) & 0xCCAA_CCAA_CCAA_CCAA;
        \\    }
        \\    return c;
        \\}
        \\
    );
}

test "zig fmt: decimal float literals with underscore separators" {
    try test_transform(
        \\pub fn main() void {
        \\    const a:f64=(10.0e-0+(10.0e+0))+10_00.00_00e-2+20_00.00_10e+4;
        \\    const b:f64=1_0.0--10_10.0+1_0_0.0_0+1e2;
        \\    std.debug.warn("a: {}, b: {} -> a+b: {}\n", .{ a, b, a + b });
        \\}
    ,
        \\pub fn main() void {
        \\    const a: f64 = (10.0e-0 + (10.0e+0)) + 10_00.00_00e-2 + 20_00.00_10e+4;
        \\    const b: f64 = 1_0.0 - -10_10.0 + 1_0_0.0_0 + 1e2;
        \\    std.debug.warn("a: {}, b: {} -> a+b: {}\n", .{ a, b, a + b });
        \\}
        \\
    );
}

test "zig fmt: hexadeciaml float literals with underscore separators" {
    try test_transform(
        \\pub fn main() void {
        \\    const a: f64 = (0x10.0p-0+(0x10.0p+0))+0x10_00.00_00p-8+0x00_00.00_10p+16;
        \\    const b: f64 = 0x0010.0--0x00_10.0+0x10.00+0x1p4;
        \\    std.debug.warn("a: {}, b: {} -> a+b: {}\n", .{ a, b, a + b });
        \\}
    ,
        \\pub fn main() void {
        \\    const a: f64 = (0x10.0p-0 + (0x10.0p+0)) + 0x10_00.00_00p-8 + 0x00_00.00_10p+16;
        \\    const b: f64 = 0x0010.0 - -0x00_10.0 + 0x10.00 + 0x1p4;
        \\    std.debug.warn("a: {}, b: {} -> a+b: {}\n", .{ a, b, a + b });
        \\}
        \\
    );
}

test "zig fmt: C var args" {
    try test_canonical(
        \\pub extern "c" fn printf(format: [*:0]const u8, ...) c_int;
        \\
    );
}

test "zig fmt: Only indent multiline string literals in function calls" {
    try test_canonical(
        \\test "zig fmt:" {
        \\    try test_transform(
        \\        \\const X = struct {
        \\        \\    foo: i32, bar: i8 };
        \\    ,
        \\        \\const X = struct {
        \\        \\    foo: i32, bar: i8
        \\        \\};
        \\        \\
        \\    );
        \\}
        \\
    );
}

test "zig fmt: Don't add extra newline after if" {
    try test_canonical(
        \\pub fn atomic_sym_link(allocator: Allocator, existing_path: []const u8, new_path: []const u8) !void {
        \\    if (cwd().sym_link(existing_path, new_path, .{})) {
        \\        return;
        \\    }
        \\}
        \\
    );
}

test "zig fmt: comments in ternary ifs" {
    try test_canonical(
        \\const x = if (true) {
        \\    1;
        \\} else if (false)
        \\    // Comment
        \\    0;
        \\const y = if (true)
        \\    // Comment
        \\    1
        \\else
        \\    // Comment
        \\    0;
        \\
        \\pub extern "c" fn printf(format: [*:0]const u8, ...) c_int;
        \\
    );
}

test "zig fmt: while statement in blockless if" {
    try test_canonical(
        \\pub fn main() void {
        \\    const zoom_node = if (focused_node == layout_first)
        \\        while (it.next()) |node| {
        \\            if (!node.view.pending.float and !node.view.pending.fullscreen) break node;
        \\        } else null
        \\    else
        \\        focused_node;
        \\}
        \\
    );
}

test "zig fmt: test comments in field access chain" {
    try test_canonical(
        \\pub const str = struct {
        \\    pub const Thing = more.more //
        \\        .more() //
        \\        .more().more() //
        \\        .more() //
        \\    // .more() //
        \\        .more() //
        \\        .more();
        \\    data: Data,
        \\};
        \\
        \\pub const str = struct {
        \\    pub const Thing = more.more //
        \\        .more() //
        \\    // .more() //
        \\    // .more() //
        \\    // .more() //
        \\        .more() //
        \\        .more();
        \\    data: Data,
        \\};
        \\
        \\pub const str = struct {
        \\    pub const Thing = more //
        \\        .more //
        \\        .more() //
        \\        .more();
        \\    data: Data,
        \\};
        \\
    );
}

test "zig fmt: allow line break before field access" {
    try test_canonical(
        \\test {
        \\    const w = foo.bar().zippy(zag).iguessthisisok();
        \\
        \\    const x = foo
        \\        .bar()
        \\        . // comment
        \\    // comment
        \\        swooop().zippy(zag)
        \\        .iguessthisisok();
        \\
        \\    const y = view.output.root.server.input_manager.default_seat.wlr_seat.name;
        \\
        \\    const z = view.output.root.server
        \\        .input_manager //
        \\        .default_seat
        \\        . // comment
        \\    // another comment
        \\        wlr_seat.name;
        \\}
        \\
    );
    try test_transform(
        \\test {
        \\    const x = foo.
        \\        bar()
        \\        .zippy(zag).iguessthisisok();
        \\
        \\    const z = view.output.root.server.
        \\        input_manager.
        \\        default_seat.wlr_seat.name;
        \\}
        \\
    ,
        \\test {
        \\    const x = foo
        \\        .bar()
        \\        .zippy(zag).iguessthisisok();
        \\
        \\    const z = view.output.root.server
        \\        .input_manager
        \\        .default_seat.wlr_seat.name;
        \\}
        \\
    );
}

test "zig fmt: Indent comma correctly after multiline string literals in arg list (trailing comma)" {
    try test_canonical(
        \\fn foo() void {
        \\    z.display_message_dialog(
        \\        *const [323:0]u8,
        \\        \\Message Text
        \\        \\------------
        \\        \\xxxxxxxxxxxx
        \\        \\xxxxxxxxxxxx
        \\    ,
        \\        g.GtkMessageType.GTK_MESSAGE_WARNING,
        \\        null,
        \\    );
        \\
        \\    z.display_message_dialog(*const [323:0]u8,
        \\        \\Message Text
        \\        \\------------
        \\        \\xxxxxxxxxxxx
        \\        \\xxxxxxxxxxxx
        \\    , g.GtkMessageType.GTK_MESSAGE_WARNING, null);
        \\}
        \\
    );
}

test "zig fmt: Control flow statement as body of blockless if" {
    try test_canonical(
        \\pub fn main() void {
        \\    const zoom_node = if (focused_node == layout_first)
        \\        if (it.next()) {
        \\            if (!node.view.pending.float and !node.view.pending.fullscreen) break node;
        \\        } else null
        \\    else
        \\        focused_node;
        \\
        \\    const zoom_node = if (focused_node == layout_first) while (it.next()) |node| {
        \\        if (!node.view.pending.float and !node.view.pending.fullscreen) break node;
        \\    } else null else focused_node;
        \\
        \\    const zoom_node = if (focused_node == layout_first)
        \\        if (it.next()) {
        \\            if (!node.view.pending.float and !node.view.pending.fullscreen) break node;
        \\        } else null;
        \\
        \\    const zoom_node = if (focused_node == layout_first) while (it.next()) |node| {
        \\        if (!node.view.pending.float and !node.view.pending.fullscreen) break node;
        \\    };
        \\
        \\    const zoom_node = if (focused_node == layout_first) for (nodes) |node| {
        \\        break node;
        \\    };
        \\
        \\    const zoom_node = if (focused_node == layout_first) switch (nodes) {
        \\        0 => 0,
        \\    } else focused_node;
        \\}
        \\
    );
}

test "zig fmt: regression test for #5722" {
    try test_canonical(
        \\pub fn send_view_tags(self: Self) void {
        \\    var it = ViewStack(View).iterator(self.output.views.first, std.math.max_int(u32));
        \\    while (it.next()) |node|
        \\        view_tags.append(node.view.current_tags) catch {
        \\            c.wl_resource_post_no_memory(self.wl_resource);
        \\            log.err(.river_status, "out of memory", .{});
        \\            return;
        \\        };
        \\}
        \\
    );
}

test "zig fmt: regression test for #8974" {
    try test_canonical(
        \\pub const VARIABLE;
        \\
    );
}

test "zig fmt: allow trailing line comments to do manual array formatting" {
    try test_canonical(
        \\fn foo() void {
        \\    self.code.append_slice_assume_capacity(&[_]u8{
        \\        0x55, // push rbp
        \\        0x48, 0x89, 0xe5, // mov rbp, rsp
        \\        0x48, 0x81, 0xec, // sub rsp, imm32 (with reloc)
        \\    });
        \\
        \\    di_buf.append_assume_capacity(&[_]u8{
        \\        1, DW.TAG_compile_unit, DW.CHILDREN_no, // header
        \\        DW.AT_stmt_list, DW_FORM_data4, // form value pairs
        \\        DW.AT_low_pc,    DW_FORM_addr,
        \\        DW.AT_high_pc,   DW_FORM_addr,
        \\        DW.AT_name,      DW_FORM_strp,
        \\        DW.AT_comp_dir,  DW_FORM_strp,
        \\        DW.AT_producer,  DW_FORM_strp,
        \\        DW.AT_language,  DW_FORM_data2,
        \\        0, 0, // sentinel
        \\    });
        \\
        \\    self.code.append_slice_assume_capacity(&[_]u8{
        \\        0x55, // push rbp
        \\        0x48, 0x89, 0xe5, // mov rbp, rsp
        \\        // How do we handle this?
        \\        //0x48, 0x81, 0xec, // sub rsp, imm32 (with reloc)
        \\        // Here's a blank line, should that be allowed?
        \\
        \\        0x48, 0x89, 0xe5,
        \\        0x33, 0x45,
        \\        // Now the comment breaks a single line -- how do we handle this?
        \\        0x88,
        \\    });
        \\}
        \\
    );
}

test "zig fmt: multiline string literals should play nice with array initializers" {
    try test_canonical(
        \\fn main() void {
        \\    var a = .{.{.{.{.{.{.{.{
        \\        0,
        \\    }}}}}}}};
        \\    myFunc(.{
        \\        "aaaaaaa",                           "bbbbbb", "ccccc",
        \\        "dddd",                              ("eee"),  ("fff"),
        \\        ("gggg"),
        \\        // Line comment
        \\        \\Multiline String Literals can be quite long
        \\        ,
        \\        \\Multiline String Literals can be quite long
        \\        \\Multiline String Literals can be quite long
        \\        ,
        \\        \\Multiline String Literals can be quite long
        \\        \\Multiline String Literals can be quite long
        \\        \\Multiline String Literals can be quite long
        \\        \\Multiline String Literals can be quite long
        \\        ,
        \\        (
        \\            \\Multiline String Literals can be quite long
        \\        ),
        \\        .{
        \\            \\xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
        \\            \\xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
        \\            \\xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
        \\        },
        \\        .{(
        \\            \\xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
        \\        )},
        \\        .{
        \\            "xxxxxxx", "xxx",
        \\            (
        \\                \\ xxx
        \\            ),
        \\            "xxx",
        \\            "xxx",
        \\        },
        \\        .{ "xxxxxxx", "xxx", "xxx", "xxx" },
        \\        .{ "xxxxxxx", "xxx", "xxx", "xxx" },
        \\        "aaaaaaa", "bbbbbb", "ccccc", // -
        \\        "dddd",    ("eee"),  ("fff"),
        \\        .{
        \\            "xxx",            "xxx",
        \\            (
        \\                \\ xxx
        \\            ),
        \\            "xxxxxxxxxxxxxx",
        \\            "xxx",
        \\        },
        \\        .{
        \\            (
        \\                \\xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
        \\            ),
        \\            \\xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
        \\        },
        \\        \\xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
        \\        \\xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
        \\    });
        \\}
        \\
    );
}

test "zig fmt: use of comments and multiline string literals may force the parameters over multiple lines" {
    try test_canonical(
        \\pub fn make_mem_undefined(qzz: []u8) i1 {
        \\    cases.add( // fixed bug foo
        \\        "compile diagnostic string for top level decl type",
        \\        \\export fn entry() void {
        \\        \\    var foo: u32 = @This(){};
        \\        \\}
        \\    , &[_][]const u8{
        \\        "tmp.zig:2:27: error: type 'u32' does not support array initialization",
        \\    });
        \\    @compile_error(
        \\        \\ unknown-length pointers and C pointers cannot be hashed deeply.
        \\        \\ Consider providing your own hash function.
        \\        \\ unknown-length pointers and C pointers cannot be hashed deeply.
        \\        \\ Consider providing your own hash function.
        \\    );
        \\    return @int_cast(do_mem_check_client_request_expr(0, // default return
        \\        .MakeMemUndefined, @int_from_ptr(qzz.ptr), qzz.len, 0, 0, 0));
        \\}
        \\
        \\// This looks like garbage don't do this
        \\const rparen = tree.prevToken(
        \\// the first token for the annotation expressions is the left
        \\// parenthesis, hence the need for two prevToken
        \\if (fn_proto.getAlignExpr()) |align_expr|
        \\    tree.prevToken(tree.prevToken(align_expr.first_token()))
        \\else if (fn_proto.getSectionExpr()) |section_expr|
        \\    tree.prevToken(tree.prevToken(section_expr.first_token()))
        \\else if (fn_proto.getCallconvExpr()) |callconv_expr|
        \\    tree.prevToken(tree.prevToken(callconv_expr.first_token()))
        \\else switch (fn_proto.return_type) {
        \\    .Explicit => |node| node.first_token(),
        \\    .InferErrorSet => |node| tree.prevToken(node.first_token()),
        \\    .Invalid => unreachable,
        \\});
        \\
    );
}

test "zig fmt: single argument trailing commas in @builtins()" {
    try test_canonical(
        \\pub fn foo(qzz: []u8) i1 {
        \\    @panic(
        \\        foo,
        \\    );
        \\    panic(
        \\        foo,
        \\    );
        \\    @panic(
        \\        foo,
        \\        bar,
        \\    );
        \\}
        \\
    );
}

test "zig fmt: trailing comma should force multiline 1 column" {
    try test_transform(
        \\pub const UUID_NULL: uuid_t = [16]u8{0,0,0,0,};
        \\
    ,
        \\pub const UUID_NULL: uuid_t = [16]u8{
        \\    0,
        \\    0,
        \\    0,
        \\    0,
        \\};
        \\
    );
}

test "zig fmt: function params should align nicely" {
    try test_canonical(
        \\pub fn foo() void {
        \\    cases.add_runtime_safety("slicing operator with sentinel",
        \\        \\const std = @import("std");
        \\    ++ check_panic_msg ++
        \\        \\pub fn main() void {
        \\        \\    var buf = [4]u8{'a','b','c',0};
        \\        \\    const slice = buf[0..:0];
        \\        \\}
        \\    );
        \\}
        \\
    );
}

test "zig fmt: fn proto end with anytype and comma" {
    try test_canonical(
        \\pub fn format(
        \\    out_stream: anytype,
        \\) !void {}
        \\
    );
}

test "zig fmt: space after top level doc comment" {
    try test_canonical(
        \\//! top level doc comment
        \\
        \\field: i32,
        \\
    );
}

test "zig fmt: remove trailing whitespace after container doc comment" {
    try test_transform(
        \\//! top level doc comment 
        \\
    ,
        \\//! top level doc comment
        \\
    );
}

test "zig fmt: remove trailing whitespace after doc comment" {
    try test_transform(
        \\/// doc comment 
        \\a = 0,
        \\
    ,
        \\/// doc comment
        \\a = 0,
        \\
    );
}

test "zig fmt: for loop with ptr payload and index" {
    try test_canonical(
        \\test {
        \\    for (self.entries.items, 0..) |*item, i| {}
        \\    for (self.entries.items, 0..) |*item, i|
        \\        a = b;
        \\    for (self.entries.items, 0..) |*item, i| a = b;
        \\}
        \\
    );
}

test "zig fmt: proper indent line comment after multi-line single expr while loop" {
    try test_canonical(
        \\test {
        \\    while (a) : (b)
        \\        foo();
        \\
        \\    // bar
        \\    baz();
        \\}
        \\
    );
}

test "zig fmt: function with labeled block as return type" {
    try test_canonical(
        \\fn foo() t: {
        \\    break :t bar;
        \\} {
        \\    baz();
        \\}
        \\
    );
}

test "zig fmt: extern function with missing param name" {
    try test_canonical(
        \\extern fn a(
        \\    *b,
        \\    c: *d,
        \\) e;
        \\extern fn f(*g, h: *i) j;
        \\
    );
}

test "zig fmt: line comment after multiline single expr if statement with multiline string" {
    try test_canonical(
        \\test {
        \\    if (foo)
        \\        x =
        \\            \\hello
        \\            \\hello
        \\            \\
        \\        ;
        \\
        \\    // bar
        \\    baz();
        \\
        \\    if (foo)
        \\        x =
        \\            \\hello
        \\            \\hello
        \\            \\
        \\    else
        \\        y =
        \\            \\hello
        \\            \\hello
        \\            \\
        \\        ;
        \\
        \\    // bar
        \\    baz();
        \\}
        \\
    );
}

test "zig fmt: respect extra newline between fn and pub usingnamespace" {
    try test_canonical(
        \\fn foo() void {
        \\    bar();
        \\}
        \\
        \\pub usingnamespace baz;
        \\
    );
}

test "zig fmt: respect extra newline between switch items" {
    try test_canonical(
        \\const a = switch (b) {
        \\    .c => {},
        \\
        \\    .d,
        \\    .e,
        \\    => f,
        \\};
        \\
    );
}

test "zig fmt: assignment with inline for and inline while" {
    try test_canonical(
        \\const tmp = inline for (items) |item| {};
        \\
    );

    try test_canonical(
        \\const tmp2 = inline while (true) {};
        \\
    );
}

test "zig fmt: saturating arithmetic" {
    try test_canonical(
        \\test {
        \\    const actual = switch (op) {
        \\        .add => a +| b,
        \\        .sub => a -| b,
        \\        .mul => a *| b,
        \\        .shl => a <<| b,
        \\    };
        \\    switch (op) {
        \\        .add => actual +|= b,
        \\        .sub => actual -|= b,
        \\        .mul => actual *|= b,
        \\        .shl => actual <<|= b,
        \\    }
        \\}
        \\
    );
}

test "zig fmt: insert trailing comma if there are comments between switch values" {
    try test_transform(
        \\const a = switch (b) {
        \\    .c => {},
        \\
        \\    .d, // foobar
        \\    .e
        \\    => f,
        \\
        \\    .g, .h
        \\    // comment
        \\    => i,
        \\};
        \\
    ,
        \\const a = switch (b) {
        \\    .c => {},
        \\
        \\    .d, // foobar
        \\    .e,
        \\    => f,
        \\
        \\    .g,
        \\    .h,
        \\    // comment
        \\    => i,
        \\};
        \\
    );
}

test "zig fmt: insert trailing comma if comments in array init" {
    try test_transform(
        \\var a = .{
        \\    "foo", //
        \\    "bar"
        \\};
        \\var a = .{
        \\    "foo",
        \\    "bar" //
        \\};
        \\var a = .{
        \\    "foo",
        \\    "//"
        \\};
        \\var a = .{
        \\    "foo",
        \\    "//" //
        \\};
        \\
    ,
        \\var a = .{
        \\    "foo", //
        \\    "bar",
        \\};
        \\var a = .{
        \\    "foo",
        \\    "bar", //
        \\};
        \\var a = .{ "foo", "//" };
        \\var a = .{
        \\    "foo",
        \\    "//", //
        \\};
        \\
    );
}

test "zig fmt: make single-line if no trailing comma" {
    try test_transform(
        \\test "function call no trailing comma" {
        \\    foo(
        \\        1,
        \\        2
        \\    );
        \\}
        \\
    ,
        \\test "function call no trailing comma" {
        \\    foo(1, 2);
        \\}
        \\
    );

    try test_transform(
        \\test "struct no trailing comma" {
        \\    const a = .{
        \\        .foo = 1,
        \\        .bar = 2
        \\    };
        \\}
        \\
    ,
        \\test "struct no trailing comma" {
        \\    const a = .{ .foo = 1, .bar = 2 };
        \\}
        \\
    );

    try test_transform(
        \\test "array no trailing comma" {
        \\    var stream = multiOutStream(.{
        \\        fbs1.outStream(),
        \\        fbs2.outStream()
        \\    });
        \\}
        \\
    ,
        \\test "array no trailing comma" {
        \\    var stream = multiOutStream(.{ fbs1.outStream(), fbs2.outStream() });
        \\}
        \\
    );
}

test "zig fmt: preserve container doc comment in container without trailing comma" {
    try test_transform(
        \\const A = enum(u32) {
        \\//! comment
        \\_ };
        \\
    ,
        \\const A = enum(u32) {
        \\    //! comment
        \\    _,
        \\};
        \\
    );
}

test "zig fmt: make single-line if no trailing comma, fmt: off" {
    try test_canonical(
        \\// Test trailing comma syntax
        \\// zig fmt: off
        \\
        \\extern var a: c_int;
        \\extern "c" var b: c_int;
        \\export var c: c_int = 0;
        \\threadlocal var d: c_int = 0;
        \\extern threadlocal var e: c_int;
        \\extern "c" threadlocal var f: c_int;
        \\export threadlocal var g: c_int = 0;
        \\
        \\const struct_trailing_comma = struct { x: i32, y: i32, };
        \\const struct_no_comma = struct { x: i32, y: i32 };
        \\const struct_fn_no_comma = struct { fn m() void {} y: i32 };
        \\
        \\const enum_no_comma = enum { A, B };
        \\
        \\fn container_init() void {
        \\    const S = struct { x: i32, y: i32 };
        \\    _ = S { .x = 1, .y = 2 };
        \\    _ = S { .x = 1, .y = 2, };
        \\}
        \\
        \\fn type_expr_return1() if (true) A {}
        \\fn type_expr_return2() for (true) |_| A {}
        \\fn type_expr_return3() while (true) A {}
        \\
        \\fn switch_cases(x: i32) void {
        \\    switch (x) {
        \\        1,2,3 => {},
        \\        4,5, => {},
        \\        6...8, => {},
        \\        else => {},
        \\    }
        \\}
        \\
        \\fn switch_prongs(x: i32) void {
        \\    switch (x) {
        \\        0 => {},
        \\        else => {},
        \\    }
        \\    switch (x) {
        \\        0 => {},
        \\        else => {}
        \\    }
        \\}
        \\
        \\const fn_no_comma = fn (i32, i32) void;
        \\const fn_trailing_comma = fn (i32, i32,) void;
        \\
        \\fn fn_calls() void {
        \\    fn add(x: i32, y: i32,) i32 { x + y };
        \\    _ = add(1, 2);
        \\    _ = add(1, 2,);
        \\}
        \\
        \\fn asm_lists() void {
        \\    if (false) { // Build AST but don't analyze
        \\        asm ("not real assembly"
        \\            :[a] "x" (x),);
        \\        asm ("not real assembly"
        \\            :[a] "x" (->i32),:[a] "x" (1),);
        \\        asm volatile ("still not real assembly"
        \\            :::"a","b",);
        \\    }
        \\}
    );
}

test "zig fmt: variable initialized with ==" {
    try test_error(
        \\comptime {
        \\    var z: u32 == 12 + 1;
        \\}
    , &.{.wrong_equal_var_decl});
}

test "zig fmt: missing const/var before local variable in comptime block" {
    try test_error(
        \\comptime {
        \\    z: u32;
        \\}
        \\comptime {
        \\    z: u32 align(1);
        \\}
        \\comptime {
        \\    z: u32 addrspace(.generic);
        \\}
        \\comptime {
        \\    z: u32 linksection("foo");
        \\}
        \\comptime {
        \\    z: u32 = 1;
        \\}
    , &.{
        .expected_labelable,
        .expected_var_const,
        .expected_var_const,
        .expected_var_const,
        .expected_var_const,
    });
}

test "zig fmt: missing const/var before local variable" {
    try test_error(
        \\std = foo,
        \\std = foo;
        \\*u32 = foo;
    , &.{
        .expected_comma_after_field,
        .var_const_decl,
        .expected_comma_after_field,
    });
}

test "zig fmt: while continue expr" {
    try test_canonical(
        \\test {
        \\    while (i > 0)
        \\        (i * 2);
        \\}
        \\
    );
    try test_error(
        \\test {
        \\    while (i > 0) (i -= 1) {
        \\        print("test123", .{});
        \\    }
        \\}
    , &[_]Error{
        .expected_continue_expr,
    });
}

test "zig fmt: canonicalize symbols (simple)" {
    try test_transform(
        \\const val_normal: Normal = .{};
        \\const @"val_unesc_me": @"UnescMe" = .{};
        \\const @"val_esc!": @"Esc!" = .{};
        \\
        \\fn fn_normal() void {}
        \\fn @"fn_unesc_me"() void {}
        \\fn @"fnEsc!"() void {}
        \\
        \\extern fn proto_normal() void;
        \\extern fn @"proto_unesc_me"() void;
        \\extern fn @"protoEsc!"() void;
        \\
        \\fn fn_with_args(normal: Normal, @"unesc_me": @"UnescMe", @"esc!": @"Esc!") void {
        \\    _ = normal;
        \\    _ = @"unesc_me";
        \\    _ = @"esc!";
        \\}
        \\
        \\const Normal = struct {};
        \\const @"UnescMe" = struct {
        \\    @"x": @"X",
        \\    const X = union(@"EnumUnesc") {
        \\        normal,
        \\        @"unesc_me",
        \\        @"esc!",
        \\    };
        \\    const @"EnumUnesc" = enum {
        \\        normal,
        \\        @"unesc_me",
        \\        @"esc!",
        \\    };
        \\};
        \\const @"Esc!" = struct {
        \\    normal: bool = false,
        \\    @"unesc_me": bool = false,
        \\    @"esc!": bool = false,
        \\};
        \\
        \\pub fn main() void {
        \\    _ = val_normal;
        \\    _ = @"val_normal";
        \\    _ = val_unesc_me;
        \\    _ = @"val_unesc_me";
        \\    _ = @"val_esc!";
        \\
        \\    fn_normal();
        \\    @"fn_normal"();
        \\    fn_unesc_me();
        \\    @"fn_unesc_me"();
        \\    @"fnEsc!"();
        \\
        \\    fn_with_args(1, Normal{}, UnescMe{}, @"Esc!"{});
        \\    fn_with_args(1, @"Normal"{}, @"UnescMe"{}, @"Esc!"{});
        \\    fn_with_args(1, @"Normal"{}, @"Normal"{}, @"Esc!"{});
        \\
        \\    const local_val1: @"Normal" = .{};
        \\    const @"local_val2": UnescMe = .{
        \\        .@"x" = .@"unesc_me",
        \\    };
        \\    fn_with_args(@"local_val1", @"local_val2", .{ .@"normal" = true, .@"unesc_me" = true, .@"esc!" = true });
        \\    fn_with_args(local_val1, local_val2, .{ .normal = true, .unesc_me = true, .@"esc!" = true });
        \\
        \\    var x: u8 = 'x';
        \\    switch (@"x") {
        \\        @"x" => {},
        \\    }
        \\
        \\    _ = @import("std"); // Don't mess with @builtins
        \\    // @"comment"
        \\}
        \\
    ,
        \\const val_normal: Normal = .{};
        \\const val_unesc_me: UnescMe = .{};
        \\const @"val_esc!": @"Esc!" = .{};
        \\
        \\fn fn_normal() void {}
        \\fn fn_unesc_me() void {}
        \\fn @"fnEsc!"() void {}
        \\
        \\extern fn proto_normal() void;
        \\extern fn proto_unesc_me() void;
        \\extern fn @"protoEsc!"() void;
        \\
        \\fn fn_with_args(normal: Normal, unesc_me: UnescMe, @"esc!": @"Esc!") void {
        \\    _ = normal;
        \\    _ = unesc_me;
        \\    _ = @"esc!";
        \\}
        \\
        \\const Normal = struct {};
        \\const UnescMe = struct {
        \\    x: X,
        \\    const X = union(EnumUnesc) {
        \\        normal,
        \\        unesc_me,
        \\        @"esc!",
        \\    };
        \\    const EnumUnesc = enum {
        \\        normal,
        \\        unesc_me,
        \\        @"esc!",
        \\    };
        \\};
        \\const @"Esc!" = struct {
        \\    normal: bool = false,
        \\    unesc_me: bool = false,
        \\    @"esc!": bool = false,
        \\};
        \\
        \\pub fn main() void {
        \\    _ = val_normal;
        \\    _ = val_normal;
        \\    _ = val_unesc_me;
        \\    _ = val_unesc_me;
        \\    _ = @"val_esc!";
        \\
        \\    fn_normal();
        \\    fn_normal();
        \\    fn_unesc_me();
        \\    fn_unesc_me();
        \\    @"fnEsc!"();
        \\
        \\    fn_with_args(1, Normal{}, UnescMe{}, @"Esc!"{});
        \\    fn_with_args(1, Normal{}, UnescMe{}, @"Esc!"{});
        \\    fn_with_args(1, Normal{}, Normal{}, @"Esc!"{});
        \\
        \\    const local_val1: Normal = .{};
        \\    const local_val2: UnescMe = .{
        \\        .x = .unesc_me,
        \\    };
        \\    fn_with_args(local_val1, local_val2, .{ .normal = true, .unesc_me = true, .@"esc!" = true });
        \\    fn_with_args(local_val1, local_val2, .{ .normal = true, .unesc_me = true, .@"esc!" = true });
        \\
        \\    var x: u8 = 'x';
        \\    switch (x) {
        \\        x => {},
        \\    }
        \\
        \\    _ = @import("std"); // Don't mess with @builtins
        \\    // @"comment"
        \\}
        \\
    );
}

// Contextually unescape when shadowing primitive types and values.
test "zig fmt: canonicalize symbols (primitive types)" {
    try test_transform(
        \\const @"anyopaque" = struct {
        \\    @"u8": @"type" = true,
        \\    @"_": @"false" = @"true",
        \\    const @"type" = bool;
        \\    const @"false" = bool;
        \\    const @"true" = false;
        \\};
        \\
        \\const U = union(@"null") {
        \\    @"type",
        \\    const @"null" = enum {
        \\        @"type",
        \\    };
        \\};
        \\
        \\test {
        \\    const E = enum { @"anyopaque" };
        \\    _ = U{ .@"type" = {} };
        \\    _ = U.@"type";
        \\    _ = E.@"anyopaque";
        \\}
        \\
        \\fn @"i10"(@"void": @"anyopaque", @"type": @"anyopaque".@"type") error{@"null"}!void {
        \\    var @"f32" = @"void";
        \\    @"f32".@"u8" = false;
        \\    _ = @"type";
        \\    _ = type;
        \\    if (@"f32".@"u8") {
        \\        return @"i10"(.{ .@"u8" = true, .@"_" = false }, false);
        \\    } else {
        \\        return error.@"null";
        \\    }
        \\}
        \\
        \\test @"i10" {
        \\    try @"i10"(.{}, true);
        \\    _ = @"void": while (null) |@"u3"| {
        \\        break :@"void" @"u3";
        \\    };
        \\    _ = @"void": {
        \\        break :@"void";
        \\    };
        \\    for ("hi", 0..) |@"u3", @"i4"| {
        \\        _ = @"u3";
        \\        _ = @"i4";
        \\    }
        \\    if (false) {} else |@"bool"| {
        \\        _ = @"bool";
        \\    }
        \\}
        \\
    ,
        \\const @"anyopaque" = struct {
        \\    u8: @"type" = true,
        \\    _: @"false" = @"true",
        \\    const @"type" = bool;
        \\    const @"false" = bool;
        \\    const @"true" = false;
        \\};
        \\
        \\const U = union(@"null") {
        \\    type,
        \\    const @"null" = enum {
        \\        type,
        \\    };
        \\};
        \\
        \\test {
        \\    const E = enum { anyopaque };
        \\    _ = U{ .type = {} };
        \\    _ = U.type;
        \\    _ = E.anyopaque;
        \\}
        \\
        \\fn @"i10"(@"void": @"anyopaque", @"type": @"anyopaque".type) error{null}!void {
        \\    var @"f32" = @"void";
        \\    @"f32".u8 = false;
        \\    _ = @"type";
        \\    _ = type;
        \\    if (@"f32".u8) {
        \\        return @"i10"(.{ .u8 = true, ._ = false }, false);
        \\    } else {
        \\        return error.null;
        \\    }
        \\}
        \\
        \\test @"i10" {
        \\    try @"i10"(.{}, true);
        \\    _ = void: while (null) |@"u3"| {
        \\        break :void @"u3";
        \\    };
        \\    _ = void: {
        \\        break :void;
        \\    };
        \\    for ("hi", 0..) |@"u3", @"i4"| {
        \\        _ = @"u3";
        \\        _ = @"i4";
        \\    }
        \\    if (false) {} else |@"bool"| {
        \\        _ = @"bool";
        \\    }
        \\}
        \\
    );
}

// Never unescape names spelled like keywords.
test "zig fmt: canonicalize symbols (keywords)" {
    try test_canonical(
        \\const @"enum" = struct {
        \\    @"error": @"struct" = true,
        \\    const @"struct" = bool;
        \\};
        \\
        \\fn @"usingnamespace"(@"union": @"enum") error{@"try"}!void {
        \\    var @"struct" = @"union";
        \\    @"struct".@"error" = false;
        \\    if (@"struct".@"error") {
        \\        return @"usingnamespace"(.{ .@"error" = false });
        \\    } else {
        \\        return error.@"try";
        \\    }
        \\}
        \\
        \\test @"usingnamespace" {
        \\    try @"usingnamespace"(.{});
        \\    _ = @"return": {
        \\        break :@"return" 4;
        \\    };
        \\}
        \\
    );
}

test "zig fmt: no space before newline before multiline string" {
    try test_canonical(
        \\const S = struct {
        \\    text: []const u8,
        \\    comment: []const u8,
        \\};
        \\
        \\test {
        \\    const s1 = .{
        \\        .text =
        \\        \\hello
        \\        \\world
        \\        ,
        \\        .comment = "test",
        \\    };
        \\    _ = s1;
        \\    const s2 = .{
        \\        .comment = "test",
        \\        .text =
        \\        \\hello
        \\        \\world
        \\        ,
        \\    };
        \\    _ = s2;
        \\}
        \\
    );
}

// Normalize \xNN and \u{NN} escapes and unicode inside @"" escapes.
test "zig fmt: canonicalize symbols (character escapes)" {
    try test_transform(
        \\const @"\x46\x6f\x6f\x64" = struct {
        \\    @"\x62\x61\x72\x6E": @"\x43\x72\x61\x62" = false,
        \\    @"\u{67}\u{6C}o\u{70}\xFF": @"Cra\x62" = false,
        \\    @"\x65\x72\x72\x6F\x72": Crab = true,
        \\    @"\x74\x72\x79": Crab = true,
        \\    @"\u{74}\u{79}\u{70}\u{65}": @"any\u{6F}\u{70}\u{61}\u{71}\u{75}\u{65}",
        \\
        \\    const @"\x43\x72\x61\x62" = bool;
        \\    const @"\x61\x6E\x79\x6F\x70\x61que" = void;
        \\};
        \\
        \\test "unicode" {
        \\    const @"cąbbäge ⚡" = 2;
        \\    _ = @"cąbbäge ⚡";
        \\    const @"\u{01f422} friend\u{f6}" = 4;
        \\    _ = @"🐢 friendö";
        \\}
        \\
    ,
        \\const Food = struct {
        \\    barn: Crab = false,
        \\    @"glop\xFF": Crab = false,
        \\    @"error": Crab = true,
        \\    @"try": Crab = true,
        \\    type: @"anyopaque",
        \\
        \\    const Crab = bool;
        \\    const @"anyopaque" = void;
        \\};
        \\
        \\test "unicode" {
        \\    const @"cąbbäge ⚡" = 2;
        \\    _ = @"cąbbäge ⚡";
        \\    const @"\u{01f422} friend\u{f6}" = 4;
        \\    _ = @"🐢 friendö";
        \\}
        \\
    );
}

test "zig fmt: canonicalize symbols (asm)" {
    try test_transform(
        \\test "asm" {
        \\    const @"null" = usize;
        \\    const @"try": usize = 808;
        \\    const arg: usize = 2;
        \\    _ = asm volatile ("syscall"
        \\        : [@"void"] "={rax}" (-> @"null"),
        \\        : [@"error"] "{rax}" (@"try"),
        \\          [@"arg1"] "{rdi}" (arg),
        \\          [arg2] "{rsi}" (arg),
        \\          [arg3] "{rdx}" (arg),
        \\        : "rcx", "r11"
        \\    );
        \\
        \\    const @"false": usize = 10;
        \\    const @"true" = "explode";
        \\    _ = asm volatile (@"true"
        \\        : [one] "={rax}" (@"false"),
        \\        : [two] "{rax}" (@"false"),
        \\    );
        \\}
        \\
    ,
        \\test "asm" {
        \\    const @"null" = usize;
        \\    const @"try": usize = 808;
        \\    const arg: usize = 2;
        \\    _ = asm volatile ("syscall"
        \\        : [void] "={rax}" (-> @"null"),
        \\        : [@"error"] "{rax}" (@"try"),
        \\          [arg1] "{rdi}" (arg),
        \\          [arg2] "{rsi}" (arg),
        \\          [arg3] "{rdx}" (arg),
        \\        : "rcx", "r11"
        \\    );
        \\
        \\    const @"false": usize = 10;
        \\    const @"true" = "explode";
        \\    _ = asm volatile (@"true"
        \\        : [one] "={rax}" (false),
        \\        : [two] "{rax}" (@"false"),
        \\    );
        \\}
        \\
    );
}

test "zig fmt: don't canonicalize _ in enums" {
    try test_transform(
        \\const A = enum {
        \\    first,
        \\    second,
        \\    third,
        \\    _,
        \\};
        \\const B = enum {
        \\    @"_",
        \\    @"__",
        \\    @"___",
        \\    @"____",
        \\};
        \\const C = struct {
        \\    @"_": u8,
        \\    @"__": u8,
        \\    @"___": u8,
        \\    @"____": u8,
        \\};
        \\const D = union {
        \\    @"_": u8,
        \\    @"__": u8,
        \\    @"___": u8,
        \\    @"____": u8,
        \\};
        \\
    ,
        \\const A = enum {
        \\    first,
        \\    second,
        \\    third,
        \\    _,
        \\};
        \\const B = enum {
        \\    @"_",
        \\    __,
        \\    ___,
        \\    ____,
        \\};
        \\const C = struct {
        \\    _: u8,
        \\    __: u8,
        \\    ___: u8,
        \\    ____: u8,
        \\};
        \\const D = union {
        \\    _: u8,
        \\    __: u8,
        \\    ___: u8,
        \\    ____: u8,
        \\};
        \\
    );
}

test "zig fmt: error for missing sentinel value in sentinel slice" {
    try test_error(
        \\const foo = foo[0..:];
    , &[_]Error{
        .expected_expr,
    });
}

test "zig fmt: error for invalid bit range" {
    try test_error(
        \\var x: []align(0:0:0)u8 = bar;
    , &[_]Error{
        .invalid_bit_range,
    });
}

test "zig fmt: error for ptr mod on array child type" {
    try test_error(
        \\var a: [10]align(10) u8 = e;
        \\var b: [10]const u8 = f;
        \\var c: [10]volatile u8 = g;
        \\var d: [10]allowzero u8 = h;
    , &[_]Error{
        .ptr_mod_on_array_child_type,
        .ptr_mod_on_array_child_type,
        .ptr_mod_on_array_child_type,
        .ptr_mod_on_array_child_type,
    });
}

test "recovery: top level" {
    try test_error(
        \\test "" {inline}
        \\test "" {inline}
    , &[_]Error{
        .expected_inlinable,
        .expected_inlinable,
    });
}

test "recovery: block statements" {
    try test_error(
        \\test "" {
        \\    foo + +;
        \\    inline;
        \\}
    , &[_]Error{
        .expected_expr,
        .expected_semi_after_stmt,
        .expected_statement,
        .expected_inlinable,
    });
}

test "recovery: missing comma" {
    try test_error(
        \\test "" {
        \\    switch (foo) {
        \\        2 => {}
        \\        3 => {}
        \\        else => {
        \\            foo & bar +;
        \\        }
        \\    }
        \\}
    , &[_]Error{
        .expected_comma_after_switch_prong,
        .expected_comma_after_switch_prong,
        .expected_expr,
    });
}

test "recovery: non-associative operators" {
    try test_error(
        \\const x = a == b == c;
        \\const x = a == b != c;
    , &[_]Error{
        .chained_comparison_operators,
        .chained_comparison_operators,
    });
}

test "recovery: extra qualifier" {
    try test_error(
        \\const a: *const const u8;
        \\test ""
    , &[_]Error{
        .extra_const_qualifier,
        .expected_block,
    });
}

test "recovery: missing return type" {
    try test_error(
        \\fn foo() {
        \\    a & b;
        \\}
        \\test ""
    , &[_]Error{
        .expected_return_type,
        .expected_block,
    });
}

test "recovery: continue after invalid decl" {
    try test_error(
        \\fn foo {
        \\    inline;
        \\}
        \\pub test "" {
        \\    async a & b;
        \\}
    , &[_]Error{
        .expected_token,
        .expected_pub_item,
        .expected_param_list,
    });
    try test_error(
        \\threadlocal test "" {
        \\    @a & b;
        \\}
    , &[_]Error{
        .expected_var_decl,
        .expected_param_list,
    });
}

test "recovery: invalid extern/inline" {
    try test_error(
        \\inline test "" { a & b; }
    , &[_]Error{
        .expected_fn,
    });
    try test_error(
        \\extern "" test "" { a & b; }
    , &[_]Error{
        .expected_var_decl_or_fn,
    });
}

test "recovery: missing semicolon" {
    try test_error(
        \\test "" {
        \\    comptime a & b
        \\    c & d
        \\    @foo
        \\}
    , &[_]Error{
        .expected_semi_after_stmt,
        .expected_semi_after_stmt,
        .expected_param_list,
        .expected_semi_after_stmt,
    });
}

test "recovery: invalid container members" {
    try test_error(
        \\usingnamespace;
        \\@foo()+
        \\@bar()@,
        \\while (a == 2) { test "" {}}
        \\test "" {
        \\    a & b
        \\}
    , &[_]Error{
        .expected_expr,
        .expected_comma_after_field,
        .expected_type_expr,
        .expected_semi_after_stmt,
    });
}

// TODO after https://github.com/ziglang/zig/issues/35 is implemented,
// we should be able to recover from this *at any indentation level*,
// reporting a parse error and yet also parsing all the decls even
// inside structs.
test "recovery: extra '}' at top level" {
    try test_error(
        \\}}}
        \\test "" {
        \\    a & b;
        \\}
    , &[_]Error{
        .expected_token,
    });
}

test "recovery: mismatched bracket at top level" {
    try test_error(
        \\const S = struct {
        \\    arr: 128]?G
        \\};
    , &[_]Error{
        .expected_comma_after_field,
    });
}

test "recovery: invalid global error set access" {
    try test_error(
        \\test "" {
        \\    error & foo;
        \\}
    , &[_]Error{
        .expected_token,
        .expected_token,
    });
}

test "recovery: invalid asterisk after pointer dereference" {
    try test_error(
        \\test "" {
        \\    var sequence = "repeat".*** 10;
        \\}
    , &[_]Error{
        .asterisk_after_ptr_deref,
        .mismatched_binary_op_whitespace,
    });
    try test_error(
        \\test "" {
        \\    var sequence = "repeat".** 10&a;
        \\}
    , &[_]Error{
        .asterisk_after_ptr_deref,
        .mismatched_binary_op_whitespace,
    });
}

test "recovery: missing semicolon after if, for, while stmt" {
    try test_error(
        \\test "" {
        \\    if (foo) bar
        \\    for (foo) |a| bar
        \\    while (foo) bar
        \\    a & b;
        \\}
    , &[_]Error{
        .expected_semi_or_else,
        .expected_semi_or_else,
        .expected_semi_or_else,
    });
}

test "recovery: invalid comptime" {
    try test_error(
        \\comptime
    , &[_]Error{
        .expected_type_expr,
    });
}

test "recovery: missing block after suspend" {
    try test_error(
        \\fn foo() void {
        \\    suspend;
        \\    nosuspend;
        \\}
    , &[_]Error{
        .expected_block_or_expr,
        .expected_block_or_expr,
    });
}

test "recovery: missing block after for/while loops" {
    try test_error(
        \\test "" { while (foo) }
    , &[_]Error{
        .expected_block_or_assignment,
    });
    try test_error(
        \\test "" { for (foo) |bar| }
    , &[_]Error{
        .expected_block_or_assignment,
    });
}

test "recovery: missing for payload" {
    try test_error(
        \\comptime {
        \\    const a = for(a) {};
        \\    const a: for(a) blk: {} = {};
        \\    for(a) {}
        \\}
    , &[_]Error{
        .expected_loop_payload,
        .expected_loop_payload,
        .expected_loop_payload,
    });
}

test "recovery: missing comma in params" {
    try test_error(
        \\fn foo(comptime bool what what) void { }
        \\fn bar(a: i32, b: i32 c) void { }
        \\
    , &[_]Error{
        .expected_comma_after_param,
        .expected_comma_after_param,
        .expected_comma_after_param,
    });
}

test "recovery: missing while rbrace" {
    try test_error(
        \\fn a() b {
        \\    while (d) {
        \\}
    , &[_]Error{
        .expected_statement,
    });
}

test "recovery: nonfinal varargs" {
    try test_error(
        \\extern fn f(a: u32, ..., b: u32) void;
        \\extern fn g(a: u32, ..., b: anytype) void;
        \\extern fn h(a: u32, ..., ...) void;
    , &[_]Error{
        .varargs_nonfinal,
        .varargs_nonfinal,
        .varargs_nonfinal,
    });
}

test "recovery: eof in c pointer" {
    try test_error(
        \\const Ptr = [*c
    , &[_]Error{
        .expected_token,
    });
}

test "matching whitespace on minus op" {
    try test_error(
        \\ _ = 2 -1, 
        \\ _ = 2- 1, 
        \\ _ = 2-
        \\     2,
        \\ _ = 2
        \\     -2,
    , &[_]Error{
        .mismatched_binary_op_whitespace,
        .mismatched_binary_op_whitespace,
        .mismatched_binary_op_whitespace,
        .mismatched_binary_op_whitespace,
    });

    try test_error(
        \\ _ = - 1,
        \\ _ = -1,
        \\ _ = 2 - -1,
        \\ _ = 2 - 1,
        \\ _ = 2-1, 
        \\ _ = 2 -
        \\1,
        \\ _ = 2
        \\     - 1,
    , &[_]Error{});
}

test "ampersand" {
    try test_error(
        \\ _ = bar && foo,
        \\ _ = bar&&foo, 
        \\ _ = bar& & foo, 
        \\ _ = bar& &foo,
    , &.{
        .invalid_ampersand_ampersand,
        .invalid_ampersand_ampersand,
        .mismatched_binary_op_whitespace,
        .mismatched_binary_op_whitespace,
    });

    try test_error(
        \\ _ = bar & &foo, 
        \\ _ = bar & &&foo, 
        \\ _ = &&foo, 
    , &.{});
}

const std = @import("std");
const mem = std.mem;
const print = std.debug.print;
const io = std.io;
const max_int = std.math.max_int;

var fixed_buffer_mem: [100 * 1024]u8 = undefined;

fn test_parse(source: [:0]const u8, allocator: mem.Allocator, anything_changed: *bool) ![]u8 {
    const stderr = io.get_std_err().writer();

    var tree = try std.zig.Ast.parse(allocator, source, .zig);
    defer tree.deinit(allocator);

    for (tree.errors) |parse_error| {
        const loc = tree.token_location(0, parse_error.token);
        try stderr.print("(memory buffer):{d}:{d}: error: ", .{ loc.line + 1, loc.column + 1 });
        try tree.render_error(parse_error, stderr);
        try stderr.print("\n{s}\n", .{source[loc.line_start..loc.line_end]});
        {
            var i: usize = 0;
            while (i < loc.column) : (i += 1) {
                try stderr.write_all(" ");
            }
            try stderr.write_all("^");
        }
        try stderr.write_all("\n");
    }
    if (tree.errors.len != 0) {
        return error.ParseError;
    }

    const formatted = try tree.render(allocator);
    anything_changed.* = !mem.eql(u8, formatted, source);
    return formatted;
}
fn test_transform_impl(allocator: mem.Allocator, fba: *std.heap.FixedBufferAllocator, source: [:0]const u8, expected_source: []const u8) !void {
    // reset the fixed buffer allocator each run so that it can be re-used for each
    // iteration of the failing index
    fba.reset();
    var anything_changed: bool = undefined;
    const result_source = try test_parse(source, allocator, &anything_changed);
    try std.testing.expect_equal_strings(expected_source, result_source);
    const changes_expected = source.ptr != expected_source.ptr;
    if (anything_changed != changes_expected) {
        print("std.zig.render returned {} instead of {}\n", .{ anything_changed, changes_expected });
        return error.TestFailed;
    }
    try std.testing.expect(anything_changed == changes_expected);
    allocator.free(result_source);
}
fn test_transform(source: [:0]const u8, expected_source: []const u8) !void {
    var fixed_allocator = std.heap.FixedBufferAllocator.init(fixed_buffer_mem[0..]);
    return std.testing.check_all_allocation_failures(fixed_allocator.allocator(), test_transform_impl, .{ &fixed_allocator, source, expected_source });
}
fn test_canonical(source: [:0]const u8) !void {
    return test_transform(source, source);
}

const Error = std.zig.Ast.Error.Tag;

fn test_error(source: [:0]const u8, expected_errors: []const Error) !void {
    var tree = try std.zig.Ast.parse(std.testing.allocator, source, .zig);
    defer tree.deinit(std.testing.allocator);

    std.testing.expect_equal(expected_errors.len, tree.errors.len) catch |err| {
        std.debug.print("errors found: {any}\n", .{tree.errors});
        return err;
    };
    for (expected_errors, 0..) |expected, i| {
        try std.testing.expect_equal(expected, tree.errors[i].tag);
    }
}
