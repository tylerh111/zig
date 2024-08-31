const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;
const math = std.math;
const mem = std.mem;

/// Given a type and value, cast the value to the type as c would.
pub fn cast(comptime DestType: type, target: anytype) DestType {
    // this function should behave like trans_ccast in translate-c, except it's for macros
    const SourceType = @TypeOf(target);
    switch (@typeInfo(DestType)) {
        .Fn => return cast_to_ptr(*const DestType, SourceType, target),
        .Pointer => return cast_to_ptr(DestType, SourceType, target),
        .Optional => |dest_opt| {
            if (@typeInfo(dest_opt.child) == .Pointer) {
                return cast_to_ptr(DestType, SourceType, target);
            } else if (@typeInfo(dest_opt.child) == .Fn) {
                return cast_to_ptr(?*const dest_opt.child, SourceType, target);
            }
        },
        .Int => {
            switch (@typeInfo(SourceType)) {
                .Pointer => {
                    return cast_int(DestType, @int_from_ptr(target));
                },
                .Optional => |opt| {
                    if (@typeInfo(opt.child) == .Pointer) {
                        return cast_int(DestType, @int_from_ptr(target));
                    }
                },
                .Int => {
                    return cast_int(DestType, target);
                },
                .Fn => {
                    return cast_int(DestType, @int_from_ptr(&target));
                },
                .Bool => {
                    return @int_from_bool(target);
                },
                else => {},
            }
        },
        .Float => {
            switch (@typeInfo(SourceType)) {
                .Int => return @as(DestType, @float_from_int(target)),
                .Float => return @as(DestType, @float_cast(target)),
                .Bool => return @as(DestType, @float_from_int(@int_from_bool(target))),
                else => {},
            }
        },
        .Union => |info| {
            inline for (info.fields) |field| {
                if (field.type == SourceType) return @union_init(DestType, field.name, target);
            }
            @compile_error("cast to union type '" ++ @type_name(DestType) ++ "' from type '" ++ @type_name(SourceType) ++ "' which is not present in union");
        },
        .Bool => return cast(usize, target) != 0,
        else => {},
    }
    return @as(DestType, target);
}

fn cast_int(comptime DestType: type, target: anytype) DestType {
    const dest = @typeInfo(DestType).Int;
    const source = @typeInfo(@TypeOf(target)).Int;

    if (dest.bits < source.bits)
        return @as(DestType, @bit_cast(@as(std.meta.Int(source.signedness, dest.bits), @truncate(target))))
    else
        return @as(DestType, @bit_cast(@as(std.meta.Int(source.signedness, dest.bits), target)));
}

fn cast_ptr(comptime DestType: type, target: anytype) DestType {
    return @constCast(@volatileCast(@align_cast(@ptr_cast(target))));
}

fn cast_to_ptr(comptime DestType: type, comptime SourceType: type, target: anytype) DestType {
    switch (@typeInfo(SourceType)) {
        .Int => {
            return @as(DestType, @ptrFromInt(cast_int(usize, target)));
        },
        .ComptimeInt => {
            if (target < 0)
                return @as(DestType, @ptrFromInt(@as(usize, @bit_cast(@as(isize, @int_cast(target))))))
            else
                return @as(DestType, @ptrFromInt(@as(usize, @int_cast(target))));
        },
        .Pointer => {
            return cast_ptr(DestType, target);
        },
        .Optional => |target_opt| {
            if (@typeInfo(target_opt.child) == .Pointer) {
                return cast_ptr(DestType, target);
            }
        },
        else => {},
    }
    return @as(DestType, target);
}

fn ptr_info(comptime PtrType: type) std.builtin.Type.Pointer {
    return switch (@typeInfo(PtrType)) {
        .Optional => |opt_info| @typeInfo(opt_info.child).Pointer,
        .Pointer => |ptr_info| ptr_info,
        else => unreachable,
    };
}

test "cast" {
    var i = @as(i64, 10);

    try testing.expect(cast(*u8, 16) == @as(*u8, @ptrFromInt(16)));
    try testing.expect(cast(*u64, &i).* == @as(u64, 10));
    try testing.expect(cast(*i64, @as(?*align(1) i64, &i)) == &i);

    try testing.expect(cast(?*u8, 2) == @as(*u8, @ptrFromInt(2)));
    try testing.expect(cast(?*i64, @as(*align(1) i64, &i)) == &i);
    try testing.expect(cast(?*i64, @as(?*align(1) i64, &i)) == &i);

    try testing.expect_equal(@as(u32, 4), cast(u32, @as(*u32, @ptrFromInt(4))));
    try testing.expect_equal(@as(u32, 4), cast(u32, @as(?*u32, @ptrFromInt(4))));
    try testing.expect_equal(@as(u32, 10), cast(u32, @as(u64, 10)));

    try testing.expect_equal(@as(i32, @bit_cast(@as(u32, 0x8000_0000))), cast(i32, @as(u32, 0x8000_0000)));

    try testing.expect_equal(@as(*u8, @ptrFromInt(2)), cast(*u8, @as(*const u8, @ptrFromInt(2))));
    try testing.expect_equal(@as(*u8, @ptrFromInt(2)), cast(*u8, @as(*volatile u8, @ptrFromInt(2))));

    try testing.expect_equal(@as(?*anyopaque, @ptrFromInt(2)), cast(?*anyopaque, @as(*u8, @ptrFromInt(2))));

    var foo: c_int = -1;
    _ = &foo;
    try testing.expect(cast(*anyopaque, -1) == @as(*anyopaque, @ptrFromInt(@as(usize, @bit_cast(@as(isize, -1))))));
    try testing.expect(cast(*anyopaque, foo) == @as(*anyopaque, @ptrFromInt(@as(usize, @bit_cast(@as(isize, -1))))));
    try testing.expect(cast(?*anyopaque, -1) == @as(?*anyopaque, @ptrFromInt(@as(usize, @bit_cast(@as(isize, -1))))));
    try testing.expect(cast(?*anyopaque, foo) == @as(?*anyopaque, @ptrFromInt(@as(usize, @bit_cast(@as(isize, -1))))));

    const FnPtr = ?*align(1) const fn (*anyopaque) void;
    try testing.expect(cast(FnPtr, 0) == @as(FnPtr, @ptrFromInt(@as(usize, 0))));
    try testing.expect(cast(FnPtr, foo) == @as(FnPtr, @ptrFromInt(@as(usize, @bit_cast(@as(isize, -1))))));
}

/// Given a value returns its size as C's sizeof operator would.
pub fn sizeof(target: anytype) usize {
    const T: type = if (@TypeOf(target) == type) target else @TypeOf(target);
    switch (@typeInfo(T)) {
        .Float, .Int, .Struct, .Union, .Array, .Bool, .Vector => return @size_of(T),
        .Fn => {
            // sizeof(main) in C returns 1
            return 1;
        },
        .Null => return @size_of(*anyopaque),
        .Void => {
            // Note: sizeof(void) is 1 on clang/gcc and 0 on MSVC.
            return 1;
        },
        .Opaque => {
            if (T == anyopaque) {
                // Note: sizeof(void) is 1 on clang/gcc and 0 on MSVC.
                return 1;
            } else {
                @compile_error("Cannot use C sizeof on opaque type " ++ @type_name(T));
            }
        },
        .Optional => |opt| {
            if (@typeInfo(opt.child) == .Pointer) {
                return sizeof(opt.child);
            } else {
                @compile_error("Cannot use C sizeof on non-pointer optional " ++ @type_name(T));
            }
        },
        .Pointer => |ptr| {
            if (ptr.size == .Slice) {
                @compile_error("Cannot use C sizeof on slice type " ++ @type_name(T));
            }
            // for strings, sizeof("a") returns 2.
            // normal pointer decay scenarios from C are handled
            // in the .Array case above, but strings remain literals
            // and are therefore always pointers, so they need to be
            // specially handled here.
            if (ptr.size == .One and ptr.is_const and @typeInfo(ptr.child) == .Array) {
                const array_info = @typeInfo(ptr.child).Array;
                if ((array_info.child == u8 or array_info.child == u16) and
                    array_info.sentinel != null and
                    @as(*align(1) const array_info.child, @ptr_cast(array_info.sentinel.?)).* == 0)
                {
                    // length of the string plus one for the null terminator.
                    return (array_info.len + 1) * @size_of(array_info.child);
                }
            }
            // When zero sized pointers are removed, this case will no
            // longer be reachable and can be deleted.
            if (@size_of(T) == 0) {
                return @size_of(*anyopaque);
            }
            return @size_of(T);
        },
        .ComptimeFloat => return @size_of(f64), // TODO c_double #3999
        .ComptimeInt => {
            // TODO to get the correct result we have to translate
            // `1073741824 * 4` as `int(1073741824) *% int(4)` since
            // sizeof(1073741824 * 4) != sizeof(4294967296).

            // TODO test if target fits in int, long or long long
            return @size_of(c_int);
        },
        else => @compile_error("std.meta.sizeof does not support type " ++ @type_name(T)),
    }
}

test "sizeof" {
    const S = extern struct { a: u32 };

    const ptr_size = @size_of(*anyopaque);

    try testing.expect(sizeof(u32) == 4);
    try testing.expect(sizeof(@as(u32, 2)) == 4);
    try testing.expect(sizeof(2) == @size_of(c_int));

    try testing.expect(sizeof(2.0) == @size_of(f64));

    try testing.expect(sizeof(S) == 4);

    try testing.expect(sizeof([_]u32{ 4, 5, 6 }) == 12);
    try testing.expect(sizeof([3]u32) == 12);
    try testing.expect(sizeof([3:0]u32) == 16);
    try testing.expect(sizeof(&[_]u32{ 4, 5, 6 }) == ptr_size);

    try testing.expect(sizeof(*u32) == ptr_size);
    try testing.expect(sizeof([*]u32) == ptr_size);
    try testing.expect(sizeof([*c]u32) == ptr_size);
    try testing.expect(sizeof(?*u32) == ptr_size);
    try testing.expect(sizeof(?[*]u32) == ptr_size);
    try testing.expect(sizeof(*anyopaque) == ptr_size);
    try testing.expect(sizeof(*void) == ptr_size);
    try testing.expect(sizeof(null) == ptr_size);

    try testing.expect(sizeof("foobar") == 7);
    try testing.expect(sizeof(&[_:0]u16{ 'f', 'o', 'o', 'b', 'a', 'r' }) == 14);
    try testing.expect(sizeof(*const [4:0]u8) == 5);
    try testing.expect(sizeof(*[4:0]u8) == ptr_size);
    try testing.expect(sizeof([*]const [4:0]u8) == ptr_size);
    try testing.expect(sizeof(*const *const [4:0]u8) == ptr_size);
    try testing.expect(sizeof(*const [4]u8) == ptr_size);

    if (false) { // TODO
        try testing.expect(sizeof(&sizeof) == @size_of(@TypeOf(&sizeof)));
        try testing.expect(sizeof(sizeof) == 1);
    }

    try testing.expect(sizeof(void) == 1);
    try testing.expect(sizeof(anyopaque) == 1);
}

pub const CIntLiteralBase = enum { decimal, octal, hex };

/// Deprecated: use `CIntLiteralBase`
pub const CIntLiteralRadix = CIntLiteralBase;

fn PromoteIntLiteralReturnType(comptime SuffixType: type, comptime number: comptime_int, comptime base: CIntLiteralBase) type {
    const signed_decimal = [_]type{ c_int, c_long, c_longlong, c_ulonglong };
    const signed_oct_hex = [_]type{ c_int, c_uint, c_long, c_ulong, c_longlong, c_ulonglong };
    const unsigned = [_]type{ c_uint, c_ulong, c_ulonglong };

    const list: []const type = if (@typeInfo(SuffixType).Int.signedness == .unsigned)
        &unsigned
    else if (base == .decimal)
        &signed_decimal
    else
        &signed_oct_hex;

    var pos = mem.index_of_scalar(type, list, SuffixType).?;

    while (pos < list.len) : (pos += 1) {
        if (number >= math.min_int(list[pos]) and number <= math.max_int(list[pos])) {
            return list[pos];
        }
    }
    @compile_error("Integer literal is too large");
}

/// Promote the type of an integer literal until it fits as C would.
pub fn promote_int_literal(
    comptime SuffixType: type,
    comptime number: comptime_int,
    comptime base: CIntLiteralBase,
) PromoteIntLiteralReturnType(SuffixType, number, base) {
    return number;
}

test "promote_int_literal" {
    const signed_hex = promote_int_literal(c_int, math.max_int(c_int) + 1, .hex);
    try testing.expect_equal(c_uint, @TypeOf(signed_hex));

    if (math.max_int(c_longlong) == math.max_int(c_int)) return;

    const signed_decimal = promote_int_literal(c_int, math.max_int(c_int) + 1, .decimal);
    const unsigned = promote_int_literal(c_uint, math.max_int(c_uint) + 1, .hex);

    if (math.max_int(c_long) > math.max_int(c_int)) {
        try testing.expect_equal(c_long, @TypeOf(signed_decimal));
        try testing.expect_equal(c_ulong, @TypeOf(unsigned));
    } else {
        try testing.expect_equal(c_longlong, @TypeOf(signed_decimal));
        try testing.expect_equal(c_ulonglong, @TypeOf(unsigned));
    }
}

/// Convert from clang __builtin_shufflevector index to Zig @shuffle index
/// clang requires __builtin_shufflevector index arguments to be integer constants.
/// negative values for `this_index` indicate "don't care".
/// clang enforces that `this_index` is less than the total number of vector elements
/// See https://ziglang.org/documentation/master/#shuffle
/// See https://clang.llvm.org/docs/LanguageExtensions.html#langext-builtin-shufflevector
pub fn shuffle_vector_index(comptime this_index: c_int, comptime source_vector_len: usize) i32 {
    const positive_index = std.math.cast(usize, this_index) orelse return undefined;
    if (positive_index < source_vector_len) return @as(i32, @int_cast(this_index));
    const b_index = positive_index - source_vector_len;
    return ~@as(i32, @int_cast(b_index));
}

test "shuffle_vector_index" {
    const vector_len: usize = 4;

    _ = shuffle_vector_index(-1, vector_len);

    try testing.expect(shuffle_vector_index(0, vector_len) == 0);
    try testing.expect(shuffle_vector_index(1, vector_len) == 1);
    try testing.expect(shuffle_vector_index(2, vector_len) == 2);
    try testing.expect(shuffle_vector_index(3, vector_len) == 3);

    try testing.expect(shuffle_vector_index(4, vector_len) == -1);
    try testing.expect(shuffle_vector_index(5, vector_len) == -2);
    try testing.expect(shuffle_vector_index(6, vector_len) == -3);
    try testing.expect(shuffle_vector_index(7, vector_len) == -4);
}

/// Constructs a [*c] pointer with the const and volatile annotations
/// from SelfType for pointing to a C flexible array of ElementType.
pub fn FlexibleArrayType(comptime SelfType: type, comptime ElementType: type) type {
    switch (@typeInfo(SelfType)) {
        .Pointer => |ptr| {
            return @Type(.{ .Pointer = .{
                .size = .C,
                .is_const = ptr.is_const,
                .is_volatile = ptr.is_volatile,
                .alignment = @alignOf(ElementType),
                .address_space = .generic,
                .child = ElementType,
                .is_allowzero = true,
                .sentinel = null,
            } });
        },
        else => |info| @compile_error("Invalid self type \"" ++ @tag_name(info) ++ "\" for flexible array getter: " ++ @type_name(SelfType)),
    }
}

test "Flexible Array Type" {
    const Container = extern struct {
        size: usize,
    };

    try testing.expect_equal(FlexibleArrayType(*Container, c_int), [*c]c_int);
    try testing.expect_equal(FlexibleArrayType(*const Container, c_int), [*c]const c_int);
    try testing.expect_equal(FlexibleArrayType(*volatile Container, c_int), [*c]volatile c_int);
    try testing.expect_equal(FlexibleArrayType(*const volatile Container, c_int), [*c]const volatile c_int);
}

/// C `%` operator for signed integers
/// C standard states: "If the quotient a/b is representable, the expression (a/b)*b + a%b shall equal a"
/// The quotient is not representable if denominator is zero, or if numerator is the minimum integer for
/// the type and denominator is -1. C has undefined behavior for those two cases; this function has safety
/// checked undefined behavior
pub fn signed_remainder(numerator: anytype, denominator: anytype) @TypeOf(numerator, denominator) {
    std.debug.assert(@typeInfo(@TypeOf(numerator, denominator)).Int.signedness == .signed);
    if (denominator > 0) return @rem(numerator, denominator);
    return numerator - @div_trunc(numerator, denominator) * denominator;
}

pub const Macros = struct {
    pub fn U_SUFFIX(comptime n: comptime_int) @TypeOf(promote_int_literal(c_uint, n, .decimal)) {
        return promote_int_literal(c_uint, n, .decimal);
    }

    fn L_SUFFIX_ReturnType(comptime number: anytype) type {
        switch (@typeInfo(@TypeOf(number))) {
            .Int, .ComptimeInt => return @TypeOf(promote_int_literal(c_long, number, .decimal)),
            .Float, .ComptimeFloat => return c_longdouble,
            else => @compile_error("Invalid value for L suffix"),
        }
    }
    pub fn L_SUFFIX(comptime number: anytype) L_SUFFIX_ReturnType(number) {
        switch (@typeInfo(@TypeOf(number))) {
            .Int, .ComptimeInt => return promote_int_literal(c_long, number, .decimal),
            .Float, .ComptimeFloat => @compile_error("TODO: c_longdouble initialization from comptime_float not supported"),
            else => @compile_error("Invalid value for L suffix"),
        }
    }

    pub fn UL_SUFFIX(comptime n: comptime_int) @TypeOf(promote_int_literal(c_ulong, n, .decimal)) {
        return promote_int_literal(c_ulong, n, .decimal);
    }

    pub fn LL_SUFFIX(comptime n: comptime_int) @TypeOf(promote_int_literal(c_longlong, n, .decimal)) {
        return promote_int_literal(c_longlong, n, .decimal);
    }

    pub fn ULL_SUFFIX(comptime n: comptime_int) @TypeOf(promote_int_literal(c_ulonglong, n, .decimal)) {
        return promote_int_literal(c_ulonglong, n, .decimal);
    }

    pub fn F_SUFFIX(comptime f: comptime_float) f32 {
        return @as(f32, f);
    }

    pub fn WL_CONTAINER_OF(ptr: anytype, sample: anytype, comptime member: []const u8) @TypeOf(sample) {
        return @fieldParentPtr(member, ptr);
    }

    /// A 2-argument function-like macro defined as #define FOO(A, B) (A)(B)
    /// could be either: cast B to A, or call A with the value B.
    pub fn CAST_OR_CALL(a: anytype, b: anytype) switch (@typeInfo(@TypeOf(a))) {
        .Type => a,
        .Fn => |fn_info| fn_info.return_type orelse void,
        else => |info| @compile_error("Unexpected argument type: " ++ @tag_name(info)),
    } {
        switch (@typeInfo(@TypeOf(a))) {
            .Type => return cast(a, b),
            .Fn => return a(b),
            else => unreachable, // return type will be a compile error otherwise
        }
    }

    pub inline fn DISCARD(x: anytype) void {
        _ = x;
    }
};

/// Integer promotion described in C11 6.3.1.1.2
fn PromotedIntType(comptime T: type) type {
    return switch (T) {
        bool, u8, i8, c_short => c_int,
        c_ushort => if (@size_of(c_ushort) == @size_of(c_int)) c_uint else c_int,
        c_int, c_uint, c_long, c_ulong, c_longlong, c_ulonglong => T,
        else => if (T == comptime_int) {
            @compile_error("Cannot promote `" ++ @type_name(T) ++ "`; a fixed-size number type is required");
        } else if (@typeInfo(T) == .Int) {
            @compile_error("Cannot promote `" ++ @type_name(T) ++ "`; a C ABI type is required");
        } else {
            @compile_error("Attempted to promote invalid type `" ++ @type_name(T) ++ "`");
        },
    };
}

/// C11 6.3.1.1.1
fn integer_rank(comptime T: type) u8 {
    return switch (T) {
        bool => 0,
        u8, i8 => 1,
        c_short, c_ushort => 2,
        c_int, c_uint => 3,
        c_long, c_ulong => 4,
        c_longlong, c_ulonglong => 5,
        else => @compile_error("integer rank not supported for `" ++ @type_name(T) ++ "`"),
    };
}

fn ToUnsigned(comptime T: type) type {
    return switch (T) {
        c_int => c_uint,
        c_long => c_ulong,
        c_longlong => c_ulonglong,
        else => @compile_error("Cannot convert `" ++ @type_name(T) ++ "` to unsigned"),
    };
}

/// "Usual arithmetic conversions" from C11 standard 6.3.1.8
fn ArithmeticConversion(comptime A: type, comptime B: type) type {
    if (A == c_longdouble or B == c_longdouble) return c_longdouble;
    if (A == f80 or B == f80) return f80;
    if (A == f64 or B == f64) return f64;
    if (A == f32 or B == f32) return f32;

    const A_Promoted = PromotedIntType(A);
    const B_Promoted = PromotedIntType(B);
    comptime {
        std.debug.assert(integer_rank(A_Promoted) >= integer_rank(c_int));
        std.debug.assert(integer_rank(B_Promoted) >= integer_rank(c_int));
    }

    if (A_Promoted == B_Promoted) return A_Promoted;

    const a_signed = @typeInfo(A_Promoted).Int.signedness == .signed;
    const b_signed = @typeInfo(B_Promoted).Int.signedness == .signed;

    if (a_signed == b_signed) {
        return if (integer_rank(A_Promoted) > integer_rank(B_Promoted)) A_Promoted else B_Promoted;
    }

    const SignedType = if (a_signed) A_Promoted else B_Promoted;
    const UnsignedType = if (!a_signed) A_Promoted else B_Promoted;

    if (integer_rank(UnsignedType) >= integer_rank(SignedType)) return UnsignedType;

    if (std.math.max_int(SignedType) >= std.math.max_int(UnsignedType)) return SignedType;

    return ToUnsigned(SignedType);
}

test "ArithmeticConversion" {
    // Promotions not necessarily the same for other platforms
    if (builtin.target.cpu.arch != .x86_64 or builtin.target.os.tag != .linux) return error.SkipZigTest;

    const Test = struct {
        /// Order of operands should not matter for arithmetic conversions
        fn check_promotion(comptime A: type, comptime B: type, comptime Expected: type) !void {
            try std.testing.expect(ArithmeticConversion(A, B) == Expected);
            try std.testing.expect(ArithmeticConversion(B, A) == Expected);
        }
    };

    try Test.check_promotion(c_longdouble, c_int, c_longdouble);
    try Test.check_promotion(c_int, f64, f64);
    try Test.check_promotion(f32, bool, f32);

    try Test.check_promotion(bool, c_short, c_int);
    try Test.check_promotion(c_int, c_int, c_int);
    try Test.check_promotion(c_short, c_int, c_int);

    try Test.check_promotion(c_int, c_long, c_long);

    try Test.check_promotion(c_ulonglong, c_uint, c_ulonglong);

    try Test.check_promotion(c_uint, c_int, c_uint);

    try Test.check_promotion(c_uint, c_long, c_long);

    try Test.check_promotion(c_ulong, c_longlong, c_ulonglong);
}

pub const MacroArithmetic = struct {
    pub fn div(a: anytype, b: anytype) ArithmeticConversion(@TypeOf(a), @TypeOf(b)) {
        const ResType = ArithmeticConversion(@TypeOf(a), @TypeOf(b));
        const a_casted = cast(ResType, a);
        const b_casted = cast(ResType, b);
        switch (@typeInfo(ResType)) {
            .Float => return a_casted / b_casted,
            .Int => return @div_trunc(a_casted, b_casted),
            else => unreachable,
        }
    }

    pub fn rem(a: anytype, b: anytype) ArithmeticConversion(@TypeOf(a), @TypeOf(b)) {
        const ResType = ArithmeticConversion(@TypeOf(a), @TypeOf(b));
        const a_casted = cast(ResType, a);
        const b_casted = cast(ResType, b);
        switch (@typeInfo(ResType)) {
            .Int => {
                if (@typeInfo(ResType).Int.signedness == .signed) {
                    return signed_remainder(a_casted, b_casted);
                } else {
                    return a_casted % b_casted;
                }
            },
            else => unreachable,
        }
    }
};

test "Macro suffix functions" {
    try testing.expect(@TypeOf(Macros.F_SUFFIX(1)) == f32);

    try testing.expect(@TypeOf(Macros.U_SUFFIX(1)) == c_uint);
    if (math.max_int(c_ulong) > math.max_int(c_uint)) {
        try testing.expect(@TypeOf(Macros.U_SUFFIX(math.max_int(c_uint) + 1)) == c_ulong);
    }
    if (math.max_int(c_ulonglong) > math.max_int(c_ulong)) {
        try testing.expect(@TypeOf(Macros.U_SUFFIX(math.max_int(c_ulong) + 1)) == c_ulonglong);
    }

    try testing.expect(@TypeOf(Macros.L_SUFFIX(1)) == c_long);
    if (math.max_int(c_long) > math.max_int(c_int)) {
        try testing.expect(@TypeOf(Macros.L_SUFFIX(math.max_int(c_int) + 1)) == c_long);
    }
    if (math.max_int(c_longlong) > math.max_int(c_long)) {
        try testing.expect(@TypeOf(Macros.L_SUFFIX(math.max_int(c_long) + 1)) == c_longlong);
    }

    try testing.expect(@TypeOf(Macros.UL_SUFFIX(1)) == c_ulong);
    if (math.max_int(c_ulonglong) > math.max_int(c_ulong)) {
        try testing.expect(@TypeOf(Macros.UL_SUFFIX(math.max_int(c_ulong) + 1)) == c_ulonglong);
    }

    try testing.expect(@TypeOf(Macros.LL_SUFFIX(1)) == c_longlong);
    try testing.expect(@TypeOf(Macros.ULL_SUFFIX(1)) == c_ulonglong);
}

test "WL_CONTAINER_OF" {
    const S = struct {
        a: u32 = 0,
        b: u32 = 0,
    };
    const x = S{};
    const y = S{};
    const ptr = Macros.WL_CONTAINER_OF(&x.b, &y, "b");
    try testing.expect_equal(&x, ptr);
}

test "CAST_OR_CALL casting" {
    const arg: c_int = 1000;
    const casted = Macros.CAST_OR_CALL(u8, arg);
    try testing.expect_equal(cast(u8, arg), casted);

    const S = struct {
        x: u32 = 0,
    };
    var s: S = .{};
    const casted_ptr = Macros.CAST_OR_CALL(*u8, &s);
    try testing.expect_equal(cast(*u8, &s), casted_ptr);
}

test "CAST_OR_CALL calling" {
    const Helper = struct {
        var last_val: bool = false;
        fn returns_void(val: bool) void {
            last_val = val;
        }
        fn returns_bool(f: f32) bool {
            return f > 0;
        }
        fn identity(self: c_uint) c_uint {
            return self;
        }
    };

    Macros.CAST_OR_CALL(Helper.returns_void, true);
    try testing.expect_equal(true, Helper.last_val);
    Macros.CAST_OR_CALL(Helper.returns_void, false);
    try testing.expect_equal(false, Helper.last_val);

    try testing.expect_equal(Helper.returns_bool(1), Macros.CAST_OR_CALL(Helper.returns_bool, @as(f32, 1)));
    try testing.expect_equal(Helper.returns_bool(-1), Macros.CAST_OR_CALL(Helper.returns_bool, @as(f32, -1)));

    try testing.expect_equal(Helper.identity(@as(c_uint, 100)), Macros.CAST_OR_CALL(Helper.identity, @as(c_uint, 100)));
}

test "Extended C ABI casting" {
    if (math.max_int(c_long) > math.max_int(c_char)) {
        try testing.expect(@TypeOf(Macros.L_SUFFIX(@as(c_char, math.max_int(c_char) - 1))) == c_long); // c_char
    }
    if (math.max_int(c_long) > math.max_int(c_short)) {
        try testing.expect(@TypeOf(Macros.L_SUFFIX(@as(c_short, math.max_int(c_short) - 1))) == c_long); // c_short
    }

    if (math.max_int(c_long) > math.max_int(c_ushort)) {
        try testing.expect(@TypeOf(Macros.L_SUFFIX(@as(c_ushort, math.max_int(c_ushort) - 1))) == c_long); //c_ushort
    }

    if (math.max_int(c_long) > math.max_int(c_int)) {
        try testing.expect(@TypeOf(Macros.L_SUFFIX(@as(c_int, math.max_int(c_int) - 1))) == c_long); // c_int
    }

    if (math.max_int(c_long) > math.max_int(c_uint)) {
        try testing.expect(@TypeOf(Macros.L_SUFFIX(@as(c_uint, math.max_int(c_uint) - 1))) == c_long); // c_uint
        try testing.expect(@TypeOf(Macros.L_SUFFIX(math.max_int(c_uint) + 1)) == c_long); // comptime_int -> c_long
    }

    if (math.max_int(c_longlong) > math.max_int(c_long)) {
        try testing.expect(@TypeOf(Macros.L_SUFFIX(@as(c_long, math.max_int(c_long) - 1))) == c_long); // c_long
        try testing.expect(@TypeOf(Macros.L_SUFFIX(math.max_int(c_long) + 1)) == c_longlong); // comptime_int -> c_longlong
    }
}
