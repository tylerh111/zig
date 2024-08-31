const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;
const expect = testing.expect;
const expect_equal = testing.expect_equal;

test "one param, explicit comptime" {
    var x: usize = 0;
    x += check_size(i32);
    x += check_size(bool);
    x += check_size(bool);
    try expect(x == 6);
}

fn check_size(comptime T: type) usize {
    return @size_of(T);
}

test "simple generic fn" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    try expect(max(i32, 3, -1) == 3);
    try expect(max(u8, 1, 100) == 100);
    try expect(max(f32, 0.123, 0.456) == 0.456);
    try expect(add(2, 3) == 5);
}

fn max(comptime T: type, a: T, b: T) T {
    return if (a > b) a else b;
}

fn add(comptime a: i32, b: i32) i32 {
    return (comptime a) + b;
}

const the_max = max(u32, 1234, 5678);
test "compile time generic eval" {
    try expect(the_max == 5678);
}

fn gimme_the_big_one(a: u32, b: u32) u32 {
    return max(u32, a, b);
}

fn should_call_same_instance(a: u32, b: u32) u32 {
    return max(u32, a, b);
}

fn same_but_with_floats(a: f64, b: f64) f64 {
    return max(f64, a, b);
}

test "fn with comptime args" {
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    try expect(gimme_the_big_one(1234, 5678) == 5678);
    try expect(should_call_same_instance(34, 12) == 34);
    try expect(same_but_with_floats(0.43, 0.49) == 0.49);
}

test "anytype params" {
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    try expect(max_i32(12, 34) == 34);
    try expect(max_f64(1.2, 3.4) == 3.4);
    comptime {
        try expect(max_i32(12, 34) == 34);
        try expect(max_f64(1.2, 3.4) == 3.4);
    }
}

fn max_anytype(a: anytype, b: anytype) @TypeOf(a, b) {
    return if (a > b) a else b;
}

fn max_i32(a: i32, b: i32) i32 {
    return max_anytype(a, b);
}

fn max_f64(a: f64, b: f64) f64 {
    return max_anytype(a, b);
}

test "type constructed by comptime function call" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    var l: SimpleList(10) = undefined;
    l.array[0] = 10;
    l.array[1] = 11;
    l.array[2] = 12;
    const ptr = @as([*]u8, @ptr_cast(&l.array));
    try expect(ptr[0] == 10);
    try expect(ptr[1] == 11);
    try expect(ptr[2] == 12);
}

fn SimpleList(comptime L: usize) type {
    var mutable_T = u8;
    _ = &mutable_T;
    const T = mutable_T;
    return struct {
        array: [L]T,
    };
}

test "function with return type type" {
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    var list: List(i32) = undefined;
    var list2: List(i32) = undefined;
    list.length = 10;
    list2.length = 10;
    try expect(list.prealloc_items.len == 8);
    try expect(list2.prealloc_items.len == 8);
}

pub fn List(comptime T: type) type {
    return SmallList(T, 8);
}

pub fn SmallList(comptime T: type, comptime STATIC_SIZE: usize) type {
    return struct {
        items: []T,
        length: usize,
        prealloc_items: [STATIC_SIZE]T,
    };
}

test "const decls in struct" {
    try expect(GenericDataThing(3).count_plus_one == 4);
}
fn GenericDataThing(comptime count: isize) type {
    return struct {
        const count_plus_one = count + 1;
    };
}

test "use generic param in generic param" {
    try expect(a_generic_fn(i32, 3, 4) == 7);
}
fn a_generic_fn(comptime T: type, comptime a: T, b: T) T {
    return a + b;
}

test "generic fn with implicit cast" {
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    try expect(get_first_byte(u8, &[_]u8{13}) == 13);
    try expect(get_first_byte(u16, &[_]u16{
        0,
        13,
    }) == 0);
}
fn get_byte(ptr: ?*const u8) u8 {
    return ptr.?.*;
}
fn get_first_byte(comptime T: type, mem: []const T) u8 {
    return get_byte(@as(*const u8, @ptr_cast(&mem[0])));
}

test "generic fn keeps non-generic parameter types" {
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const A = 128;

    const S = struct {
        fn f(comptime T: type, s: []T) !void {
            try expect(A != @typeInfo(@TypeOf(s)).Pointer.alignment);
        }
    };

    // The compiler monomorphizes `S.f` for `T=u8` on its first use, check that
    // `x` type not affect `s` parameter type.
    var x: [16]u8 align(A) = undefined;
    try S.f(u8, &x);
}

test "array of generic fns" {
    try expect(foos[0](true));
    try expect(!foos[1](true));
}

const foos = [_]fn (anytype) bool{
    foo1,
    foo2,
};

fn foo1(arg: anytype) bool {
    return arg;
}
fn foo2(arg: anytype) bool {
    return !arg;
}

test "generic struct" {
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO

    var a1 = GenNode(i32){
        .value = 13,
        .next = null,
    };
    var b1 = GenNode(bool){
        .value = true,
        .next = null,
    };
    try expect(a1.value == 13);
    try expect(a1.value == a1.get_val());
    try expect(b1.get_val());
}
fn GenNode(comptime T: type) type {
    return struct {
        value: T,
        next: ?*GenNode(T),
        fn get_val(n: *const GenNode(T)) T {
            return n.value;
        }
    };
}

test "function parameter is generic" {
    const S = struct {
        pub fn init(pointer: anytype, comptime fillFn: fn (ptr: *@TypeOf(pointer)) void) void {
            _ = fillFn;
        }
        pub fn fill(self: *u32) void {
            _ = self;
        }
    };
    var rng: u32 = 2;
    _ = &rng;
    S.init(rng, S.fill);
}

test "generic function instantiation turns into comptime call" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO

    const S = struct {
        fn do_the_test() !void {
            const E1 = enum { A };
            const e1f = field_info(E1, .A);
            try expect(std.mem.eql(u8, e1f.name, "A"));
        }

        pub fn field_info(comptime T: type, comptime field: FieldEnum(T)) switch (@typeInfo(T)) {
            .Enum => std.builtin.Type.EnumField,
            else => void,
        } {
            return @typeInfo(T).Enum.fields[@int_from_enum(field)];
        }

        pub fn FieldEnum(comptime T: type) type {
            _ = T;
            var enum_fields: [1]std.builtin.Type.EnumField = .{.{ .name = "A", .value = 0 }};
            return @Type(.{
                .Enum = .{
                    .tag_type = u0,
                    .fields = &enum_fields,
                    .decls = &.{},
                    .is_exhaustive = true,
                },
            });
        }
    };
    try S.do_the_test();
}

test "generic function with void and comptime parameter" {
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const S = struct { x: i32 };
    const namespace = struct {
        fn foo(v: void, s: *S, comptime T: type) !void {
            _ = @as(void, v);
            try expect(s.x == 1234);
            try expect(T == u8);
        }
    };
    var s: S = .{ .x = 1234 };
    try namespace.foo({}, &s, u8);
}

test "anonymous struct return type referencing comptime parameter" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const S = struct {
        pub fn extra_data(comptime T: type, index: usize) struct { data: T, end: usize } {
            return .{
                .data = 1234,
                .end = index,
            };
        }
    };
    const s = S.extra_data(i32, 5678);
    try expect(s.data == 1234);
    try expect(s.end == 5678);
}

test "generic function instantiation non-duplicates" {
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;
    if (builtin.os.tag == .wasi) return error.SkipZigTest;

    const S = struct {
        fn copy(comptime T: type, dest: []T, source: []const T) void {
            @export(foo, .{ .name = "test_generic_instantiation_non_dupe" });
            for (source, 0..) |s, i| dest[i] = s;
        }

        fn foo() callconv(.C) void {}
    };
    var buffer: [100]u8 = undefined;
    S.copy(u8, &buffer, "hello");
    S.copy(u8, &buffer, "hello2");
}

test "generic instantiation of tagged union with only one field" {
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.os.tag == .wasi) return error.SkipZigTest;

    const S = struct {
        const U = union(enum) {
            s: []const u8,
        };

        fn foo(comptime u: U) usize {
            return u.s.len;
        }
    };

    try expect(S.foo(.{ .s = "a" }) == 1);
    try expect(S.foo(.{ .s = "ab" }) == 2);
}

test "nested generic function" {
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;

    const S = struct {
        fn foo(comptime T: type, callback: *const fn (user_data: T) anyerror!void, data: T) anyerror!void {
            try callback(data);
        }
        fn bar(a: u32) anyerror!void {
            try expect(a == 123);
        }

        fn g(_: *const fn (anytype) void) void {}
    };
    try expect(@typeInfo(@TypeOf(S.g)).Fn.is_generic);
    try S.foo(u32, S.bar, 123);
}

test "extern function used as generic parameter" {
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;

    const S = struct {
        extern fn used_as_generic_parameter_foo() void;
        extern fn used_as_generic_parameter_bar() void;
        inline fn used_as_generic_parameter_baz(comptime token: anytype) type {
            return struct {
                comptime {
                    _ = token;
                }
            };
        }
    };
    try expect(S.used_as_generic_parameter_baz(S.used_as_generic_parameter_foo) !=
        S.used_as_generic_parameter_baz(S.used_as_generic_parameter_bar));
}

test "generic struct as parameter type" {
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const S = struct {
        fn do_the_test(comptime Int: type, thing: struct { int: Int }) !void {
            try expect(thing.int == 123);
        }
        fn do_the_test2(comptime Int: type, comptime thing: struct { int: Int }) !void {
            try expect(thing.int == 456);
        }
    };
    try S.do_the_test(u32, .{ .int = 123 });
    try S.do_the_test2(i32, .{ .int = 456 });
}

test "slice as parameter type" {
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const S = struct {
        fn intern_comptime_string(comptime str: []const u8) *const []const u8 {
            return &struct {
                const intern: []const u8 = str;
            }.intern;
        }
    };

    const source_a = "this is a string";
    try expect(S.intern_comptime_string(source_a[1..2]) == S.intern_comptime_string(source_a[1..2]));
    try expect(S.intern_comptime_string(source_a[2..4]) != S.intern_comptime_string(source_a[5..7]));
}

test "null sentinel pointer passed as generic argument" {
    const S = struct {
        fn do_the_test(a: anytype) !void {
            try std.testing.expect(@int_from_ptr(a) == 8);
        }
    };
    try S.do_the_test((@as([*:null]const [*c]const u8, @ptrFromInt(8))));
}

test "generic function passed as comptime argument" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const S = struct {
        fn do_math(comptime f: fn (type, i32, i32) error{Overflow}!i32, a: i32, b: i32) !void {
            const result = try f(i32, a, b);
            try expect(result == 11);
        }
    };
    try S.do_math(std.math.add, 5, 6);
}

test "return type of generic function is function pointer" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const S = struct {
        fn b(comptime T: type) ?*const fn () error{}!T {
            return null;
        }
    };

    try expect(null == S.b(void));
}

test "coerced function body has inequal value with its uncoerced body" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const S = struct {
        const A = B(i32, c);
        fn c() !i32 {
            return 1234;
        }
        fn B(comptime T: type, comptime d: ?fn () anyerror!T) type {
            return struct {
                fn do() T {
                    return d.?() catch @panic("fail");
                }
            };
        }
    };
    try expect(S.A.do() == 1234);
}

test "generic function returns value from callconv(.C) function" {
    const S = struct {
        fn get_u8() callconv(.C) u8 {
            return 123;
        }

        fn get_generic(comptime T: type, supplier: fn () callconv(.C) T) T {
            return supplier();
        }
    };

    try testing.expect(S.get_generic(u8, S.get_u8) == 123);
}

test "union in struct captures argument" {
    const S = struct {
        fn BuildType(comptime T: type) type {
            return struct {
                val: union {
                    b: T,
                },
            };
        }
    };
    const TestStruct = S.BuildType(u32);
    const c = TestStruct{ .val = .{ .b = 10 } };
    try expect(c.val.b == 10);
}

test "function argument tuple used as struct field" {
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const S = struct {
        fn DeleagateWithContext(comptime Function: type) type {
            const ArgArgs = std.meta.ArgsTuple(Function);
            return struct {
                t: ArgArgs,
            };
        }

        const OnConfirm = DeleagateWithContext(fn (bool) void);
        const CustomDraw = DeleagateWithContext(fn (?OnConfirm) void);
    };

    var c: S.CustomDraw = undefined;
    c.t[0] = null;
    try expect(c.t[0] == null);
}

test "comptime callconv(.C) function ptr uses comptime type argument" {
    const S = struct {
        fn A(
            comptime T: type,
            comptime destroycb: ?*const fn (?*T) callconv(.C) void,
        ) !void {
            try expect(destroycb == null);
        }
    };
    try S.A(u32, null);
}

test "call generic function with from function called by the generic function" {
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_llvm and
        builtin.cpu.arch == .aarch64 and builtin.os.tag == .windows) return error.SkipZigTest;

    const GET = struct {
        key: []const u8,
        const GET = @This();
        const Redis = struct {
            const Command = struct {
                fn serialize(self: GET, comptime RootSerializer: type) void {
                    return RootSerializer.serialize_command(.{ "GET", self.key });
                }
            };
        };
    };
    const ArgSerializer = struct {
        fn is_command(comptime T: type) bool {
            const tid = @typeInfo(T);
            return (tid == .Struct or tid == .Enum or tid == .Union) and
                @hasDecl(T, "Redis") and @hasDecl(T.Redis, "Command");
        }
        fn serialize_command(command: anytype) void {
            const CmdT = @TypeOf(command);

            if (comptime is_command(CmdT)) {
                return CmdT.Redis.Command.serialize(command, @This());
            }
        }
    };

    ArgSerializer.serialize_command(GET{ .key = "banana" });
}

fn StructCapture(comptime T: type) type {
    return struct {
        pub fn foo(comptime x: usize) struct { T } {
            return .{x};
        }
    };
}

test "call generic function that uses capture from function declaration's scope" {
    if (builtin.zig_backend == .stage2_x86_64 and builtin.target.ofmt != .elf and builtin.target.ofmt != .macho) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const S = StructCapture(f64);
    const s = S.foo(123);
    try expect_equal(123.0, s[0]);
}

comptime {
    // The same function parameter instruction being analyzed multiple times
    // should override the result of the previous analysis.
    for (0..2) |_| _ = fn (void) void;
}
