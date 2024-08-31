const std = @import("std");
const builtin = @import("builtin");
const endian = builtin.cpu.arch.endian();
const testing = @import("std").testing;
const ptr_size = @size_of(usize);

test "type pun signed and unsigned as single pointer" {
    comptime {
        var x: u32 = 0;
        const y = @as(*i32, @ptr_cast(&x));
        y.* = -1;
        try testing.expect_equal(@as(u32, 0xFFFFFFFF), x);
    }
}

test "type pun signed and unsigned as many pointer" {
    comptime {
        var x: u32 = 0;
        const y = @as([*]i32, @ptr_cast(&x));
        y[0] = -1;
        try testing.expect_equal(@as(u32, 0xFFFFFFFF), x);
    }
}

test "type pun signed and unsigned as array pointer" {
    comptime {
        var x: u32 = 0;
        const y = @as(*[1]i32, @ptr_cast(&x));
        y[0] = -1;
        try testing.expect_equal(@as(u32, 0xFFFFFFFF), x);
    }
}

test "type pun signed and unsigned as offset many pointer" {
    comptime {
        var x: [11]u32 = undefined;
        var y: [*]i32 = @ptr_cast(&x[10]);
        y -= 10;
        y[10] = -1;
        try testing.expect_equal(@as(u32, 0xFFFFFFFF), x[10]);
    }
}

test "type pun signed and unsigned as array pointer with pointer arithemtic" {
    comptime {
        var x: [11]u32 = undefined;
        const y = @as([*]i32, @ptr_cast(&x[10])) - 10;
        const z: *[15]i32 = y[0..15];
        z[10] = -1;
        try testing.expect_equal(@as(u32, 0xFFFFFFFF), x[10]);
    }
}

test "type pun value and struct" {
    comptime {
        const StructOfU32 = extern struct { x: u32 };
        var inst: StructOfU32 = .{ .x = 0 };
        @as(*i32, @ptr_cast(&inst.x)).* = -1;
        try testing.expect_equal(@as(u32, 0xFFFFFFFF), inst.x);
        @as(*i32, @ptr_cast(&inst)).* = -2;
        try testing.expect_equal(@as(u32, 0xFFFFFFFE), inst.x);
    }
}

fn big_to_native_endian(comptime T: type, v: T) T {
    return if (endian == .big) v else @byte_swap(v);
}
test "type pun endianness" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO

    comptime {
        const StructOfBytes = extern struct { x: [4]u8 };
        var inst: StructOfBytes = .{ .x = [4]u8{ 0, 0, 0, 0 } };
        const structPtr = @as(*align(1) u32, @ptr_cast(&inst));
        const arrayPtr = @as(*align(1) u32, @ptr_cast(&inst.x));
        inst.x[0] = 0xFE;
        inst.x[2] = 0xBE;
        try testing.expect_equal(big_to_native_endian(u32, 0xFE00BE00), structPtr.*);
        try testing.expect_equal(big_to_native_endian(u32, 0xFE00BE00), arrayPtr.*);
        structPtr.* = big_to_native_endian(u32, 0xDEADF00D);
        try testing.expect_equal(big_to_native_endian(u32, 0xDEADF00D), structPtr.*);
        try testing.expect_equal(big_to_native_endian(u32, 0xDEADF00D), arrayPtr.*);
        try testing.expect_equal(@as(u8, 0xDE), inst.x[0]);
        try testing.expect_equal(@as(u8, 0xAD), inst.x[1]);
        try testing.expect_equal(@as(u8, 0xF0), inst.x[2]);
        try testing.expect_equal(@as(u8, 0x0D), inst.x[3]);
    }
}

const Bits = packed struct {
    // Note: This struct has only single byte words so it
    // doesn't need to be byte swapped.
    p0: u1,
    p1: u4,
    p2: u3,
    p3: u2,
    p4: u6,
    p5: u8,
    p6: u7,
    p7: u1,
};
const ShuffledBits = packed struct {
    p1: u4,
    p3: u2,
    p7: u1,
    p0: u1,
    p5: u8,
    p2: u3,
    p6: u7,
    p4: u6,
};
fn shuffle(ptr: usize, comptime From: type, comptime To: type) usize {
    if (@size_of(From) != @size_of(To))
        @compile_error("Mismatched sizes! " ++ @type_name(From) ++ " and " ++ @type_name(To) ++ " must have the same size!");
    const array_len = @div_exact(ptr_size, @size_of(From));
    var result: usize = 0;
    const pSource = @as(*align(1) const [array_len]From, @ptr_cast(&ptr));
    const pResult = @as(*align(1) [array_len]To, @ptr_cast(&result));
    var i: usize = 0;
    while (i < array_len) : (i += 1) {
        inline for (@typeInfo(To).Struct.fields) |f| {
            @field(pResult[i], f.name) = @field(pSource[i], f.name);
        }
    }
    return result;
}

fn do_type_pun_bits_test(as_bits: *Bits) !void {
    const as_u32 = @as(*align(1) u32, @ptr_cast(as_bits));
    const as_bytes = @as(*[4]u8, @ptr_cast(as_bits));
    as_u32.* = big_to_native_endian(u32, 0xB0A7DEED);
    try testing.expect_equal(@as(u1, 0x00), as_bits.p0);
    try testing.expect_equal(@as(u4, 0x08), as_bits.p1);
    try testing.expect_equal(@as(u3, 0x05), as_bits.p2);
    try testing.expect_equal(@as(u2, 0x03), as_bits.p3);
    try testing.expect_equal(@as(u6, 0x29), as_bits.p4);
    try testing.expect_equal(@as(u8, 0xDE), as_bits.p5);
    try testing.expect_equal(@as(u7, 0x6D), as_bits.p6);
    try testing.expect_equal(@as(u1, 0x01), as_bits.p7);

    as_bits.p6 = 0x2D;
    as_bits.p1 = 0x0F;
    try testing.expect_equal(big_to_native_endian(u32, 0xBEA7DEAD), as_u32.*);

    // clobbering one bit doesn't clobber the word
    as_bits.p7 = undefined;
    try testing.expect_equal(@as(u7, 0x2D), as_bits.p6);
    // even when read as a whole
    const u = as_u32.*;
    _ = u; // u is undefined
    try testing.expect_equal(@as(u7, 0x2D), as_bits.p6);
    // or if a field which shares the byte is modified
    as_bits.p6 = 0x6D;
    try testing.expect_equal(@as(u7, 0x6D), as_bits.p6);

    // but overwriting the undefined will clear it
    as_bytes[3] = 0xAF;
    try testing.expect_equal(big_to_native_endian(u32, 0xBEA7DEAF), as_u32.*);
}

test "type pun bits" {
    if (true) {
        // TODO: currently, marking one bit of `Bits` as `undefined` does
        // mark the whole value as `undefined`, since the pointer interpretation
        // logic reads it back in as a `u32`, which is partially-undef and thus
        // has value `undefined`. We need an improved comptime memory representation
        // to make this work.
        return error.SkipZigTest;
    }
    comptime {
        var v: u32 = undefined;
        try do_type_pun_bits_test(@as(*Bits, @ptr_cast(&v)));
    }
}

const imports = struct {
    var global_u32: u32 = 0;
};

// Make sure lazy values work on their own, before getting into more complex tests
test "basic pointer preservation" {
    if (true) {
        // TODO https://github.com/ziglang/zig/issues/9646
        return error.SkipZigTest;
    }

    comptime {
        const lazy_address = @int_from_ptr(&imports.global_u32);
        try testing.expect_equal(@int_from_ptr(&imports.global_u32), lazy_address);
        try testing.expect_equal(&imports.global_u32, @as(*u32, @ptrFromInt(lazy_address)));
    }
}

test "byte copy preserves linker value" {
    if (true) {
        // TODO https://github.com/ziglang/zig/issues/9646
        return error.SkipZigTest;
    }

    const ct_value = comptime blk: {
        const lazy = &imports.global_u32;
        var result: *u32 = undefined;
        const pSource = @as(*const [ptr_size]u8, @ptr_cast(&lazy));
        const pResult = @as(*[ptr_size]u8, @ptr_cast(&result));
        var i: usize = 0;
        while (i < ptr_size) : (i += 1) {
            pResult[i] = pSource[i];
            try testing.expect_equal(pSource[i], pResult[i]);
        }
        try testing.expect_equal(&imports.global_u32, result);
        break :blk result;
    };

    try testing.expect_equal(&imports.global_u32, ct_value);
}

test "unordered byte copy preserves linker value" {
    if (true) {
        // TODO https://github.com/ziglang/zig/issues/9646
        return error.SkipZigTest;
    }

    const ct_value = comptime blk: {
        const lazy = &imports.global_u32;
        var result: *u32 = undefined;
        const pSource = @as(*const [ptr_size]u8, @ptr_cast(&lazy));
        const pResult = @as(*[ptr_size]u8, @ptr_cast(&result));
        if (ptr_size > 8) @compile_error("This array needs to be expanded for platform with very big pointers");
        const shuffled_indices = [_]usize{ 4, 5, 2, 6, 1, 3, 0, 7 };
        for (shuffled_indices) |i| {
            pResult[i] = pSource[i];
            try testing.expect_equal(pSource[i], pResult[i]);
        }
        try testing.expect_equal(&imports.global_u32, result);
        break :blk result;
    };

    try testing.expect_equal(&imports.global_u32, ct_value);
}

test "shuffle chunks of linker value" {
    if (true) {
        // TODO https://github.com/ziglang/zig/issues/9646
        return error.SkipZigTest;
    }

    const lazy_address = @int_from_ptr(&imports.global_u32);
    const shuffled1_rt = shuffle(lazy_address, Bits, ShuffledBits);
    const unshuffled1_rt = shuffle(shuffled1_rt, ShuffledBits, Bits);
    try testing.expect_equal(lazy_address, unshuffled1_rt);
    const shuffled1_ct = comptime shuffle(lazy_address, Bits, ShuffledBits);
    const shuffled1_ct_2 = comptime shuffle(lazy_address, Bits, ShuffledBits);
    try comptime testing.expect_equal(shuffled1_ct, shuffled1_ct_2);
    const unshuffled1_ct = comptime shuffle(shuffled1_ct, ShuffledBits, Bits);
    try comptime testing.expect_equal(lazy_address, unshuffled1_ct);
    try testing.expect_equal(shuffled1_ct, shuffled1_rt);
}

test "dance on linker values" {
    if (true) {
        // TODO https://github.com/ziglang/zig/issues/9646
        return error.SkipZigTest;
    }

    comptime {
        var arr: [2]usize = undefined;
        arr[0] = @int_from_ptr(&imports.global_u32);
        arr[1] = @int_from_ptr(&imports.global_u32);

        const weird_ptr = @as([*]Bits, @ptr_cast(@as([*]u8, @ptr_cast(&arr)) + @size_of(usize) - 3));
        try do_type_pun_bits_test(&weird_ptr[0]);
        if (ptr_size > @size_of(Bits))
            try do_type_pun_bits_test(&weird_ptr[1]);

        const arr_bytes: *[2][ptr_size]u8 = @ptr_cast(&arr);

        var rebuilt_bytes: [ptr_size]u8 = undefined;
        var i: usize = 0;
        while (i < ptr_size - 3) : (i += 1) {
            rebuilt_bytes[i] = arr_bytes[0][i];
        }
        while (i < ptr_size) : (i += 1) {
            rebuilt_bytes[i] = arr_bytes[1][i];
        }

        try testing.expect_equal(&imports.global_u32, @as(*u32, @ptrFromInt(@as(usize, @bit_cast(rebuilt_bytes)))));
    }
}

test "offset array ptr by element size" {
    comptime {
        const VirtualStruct = struct { x: u32 };
        var arr: [4]VirtualStruct = .{
            .{ .x = big_to_native_endian(u32, 0x0004080c) },
            .{ .x = big_to_native_endian(u32, 0x0105090d) },
            .{ .x = big_to_native_endian(u32, 0x02060a0e) },
            .{ .x = big_to_native_endian(u32, 0x03070b0f) },
        };

        const buf: [*]align(@alignOf(VirtualStruct)) u8 = @ptr_cast(&arr);

        const second_element: *VirtualStruct = @ptr_cast(buf + 2 * @size_of(VirtualStruct));
        try testing.expect_equal(big_to_native_endian(u32, 0x02060a0e), second_element.x);
    }
}

test "offset instance by field size" {
    if (true) {
        // TODO https://github.com/ziglang/zig/issues/9646
        return error.SkipZigTest;
    }

    comptime {
        const VirtualStruct = struct { x: u32, y: u32, z: u32, w: u32 };
        var inst = VirtualStruct{ .x = 0, .y = 1, .z = 2, .w = 3 };

        var ptr = @int_from_ptr(&inst);
        ptr -= 4;
        ptr += @offset_of(VirtualStruct, "x");
        try testing.expect_equal(@as(u32, 0), @as([*]u32, @ptrFromInt(ptr))[1]);
        ptr -= @offset_of(VirtualStruct, "x");
        ptr += @offset_of(VirtualStruct, "y");
        try testing.expect_equal(@as(u32, 1), @as([*]u32, @ptrFromInt(ptr))[1]);
        ptr = ptr - @offset_of(VirtualStruct, "y") + @offset_of(VirtualStruct, "z");
        try testing.expect_equal(@as(u32, 2), @as([*]u32, @ptrFromInt(ptr))[1]);
        ptr = @int_from_ptr(&inst.z) - 4 - @offset_of(VirtualStruct, "z");
        ptr += @offset_of(VirtualStruct, "w");
        try testing.expect_equal(@as(u32, 3), @as(*u32, @ptrFromInt(ptr + 4)).*);
    }
}

test "offset field ptr by enclosing array element size" {
    if (true) {
        // TODO https://github.com/ziglang/zig/issues/9646
        return error.SkipZigTest;
    }

    comptime {
        const VirtualStruct = struct { x: u32 };
        var arr: [4]VirtualStruct = .{
            .{ .x = big_to_native_endian(u32, 0x0004080c) },
            .{ .x = big_to_native_endian(u32, 0x0105090d) },
            .{ .x = big_to_native_endian(u32, 0x02060a0e) },
            .{ .x = big_to_native_endian(u32, 0x03070b0f) },
        };

        var i: usize = 0;
        while (i < 4) : (i += 1) {
            var ptr: [*]u8 = @ptr_cast(&arr[0]);
            ptr += i;
            ptr += @offset_of(VirtualStruct, "x");
            var j: usize = 0;
            while (j < 4) : (j += 1) {
                const base = ptr + j * @size_of(VirtualStruct);
                try testing.expect_equal(@as(u8, @int_cast(i * 4 + j)), base[0]);
            }
        }
    }
}

test "accessing reinterpreted memory of parent object" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO

    const S = extern struct {
        a: f32,
        b: [4]u8,
        c: f32,
    };
    const expected = if (endian == .little) 102 else 38;

    comptime {
        const x = S{
            .a = 1.5,
            .b = [_]u8{ 1, 2, 3, 4 },
            .c = 2.6,
        };
        const ptr = &x.b[0];
        const b = @as([*c]const u8, @ptr_cast(ptr))[5];
        try testing.expect(b == expected);
    }
}

test "bitcast packed union to integer" {
    const U = packed union {
        x: i2,
        y: u2,
    };

    comptime {
        const a: U = .{ .x = -1 };
        const b: U = .{ .y = 2 };
        const cast_a: u2 = @bit_cast(a);
        const cast_b: u2 = @bit_cast(b);

        try testing.expect_equal(@as(u2, 3), cast_a);
        try testing.expect_equal(@as(u2, 2), cast_b);
    }
}

test "mutate entire slice at comptime" {
    comptime {
        var buf: [3]u8 = undefined;
        const x: [2]u8 = .{ 1, 2 }; // Avoid RLS
        buf[1..3].* = x;
    }
}

test "dereference undefined pointer to zero-bit type" {
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const p0: *void = undefined;
    try testing.expect_equal({}, p0.*);

    const p1: *[0]u32 = undefined;
    try testing.expect(p1.*.len == 0);
}

test "type pun extern struct" {
    const S = extern struct { f: u8 };
    comptime var s = S{ .f = 123 };
    @as(*u8, @ptr_cast(&s)).* = 72;
    try testing.expect_equal(@as(u8, 72), s.f);
}

test "type pun @ptrFromInt" {
    const p: *u8 = @ptrFromInt(42);
    // note that expect_equal hides the bug
    try testing.expect(@as(*const [*]u8, @ptr_cast(&p)).* == @as([*]u8, @ptrFromInt(42)));
}

test "type pun null pointer-like optional" {
    const p: ?*u8 = null;
    // note that expect_equal hides the bug
    try testing.expect(@as(*const ?*i8, @ptr_cast(&p)).* == null);
}

test "write empty array to end" {
    comptime var array: [5]u8 = "hello".*;
    array[5..5].* = .{};
    array[5..5].* = [0]u8{};
    array[5..5].* = [_]u8{};
    comptime std.debug.assert(std.mem.eql(u8, "hello", &array));
}

fn double_ptr_test() !void {
    var a: u32 = 0;
    const ptr = &a;
    const double_ptr = &ptr;
    set_double_ptr(double_ptr, 1);
    set_double_ptr(double_ptr, 2);
    set_double_ptr(double_ptr, 1);
    try std.testing.expect(a == 1);
}
fn set_double_ptr(ptr: *const *const u32, value: u32) void {
    set_ptr(ptr.*, value);
}
fn set_ptr(ptr: *const u32, value: u32) void {
    const mut_ptr: *u32 = @constCast(ptr);
    mut_ptr.* = value;
}
test "double pointer can mutate comptime state" {
    try comptime double_ptr_test();
}

fn GenericIntApplier(
    comptime Context: type,
    comptime applyFn: fn (context: Context, arg: u32) void,
) type {
    return struct {
        context: Context,

        const Self = @This();

        inline fn any(self: *const Self) IntApplier {
            return .{
                .context = @ptr_cast(&self.context),
                .applyFn = type_erased_apply_fn,
            };
        }

        fn type_erased_apply_fn(context: *const anyopaque, arg: u32) void {
            const ptr: *const Context = @align_cast(@ptr_cast(context));
            applyFn(ptr.*, arg);
        }
    };
}
const IntApplier = struct {
    context: *const anyopaque,
    applyFn: *const fn (context: *const anyopaque, arg: u32) void,

    fn apply(ia: IntApplier, arg: u32) void {
        ia.applyFn(ia.context, arg);
    }
};
const Accumulator = struct {
    value: u32,

    const Applier = GenericIntApplier(*u32, add);

    fn applier(a: *Accumulator) Applier {
        return .{ .context = &a.value };
    }

    fn add(context: *u32, arg: u32) void {
        context.* += arg;
    }
};
fn field_ptr_test() u32 {
    var a: Accumulator = .{ .value = 0 };
    const applier = a.applier();
    applier.any().apply(1);
    applier.any().apply(1);
    return a.value;
}
test "pointer in aggregate field can mutate comptime state" {
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    try comptime std.testing.expect(field_ptr_test() == 2);
}
