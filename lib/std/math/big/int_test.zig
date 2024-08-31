const std = @import("../../std.zig");
const builtin = @import("builtin");
const mem = std.mem;
const testing = std.testing;
const Managed = std.math.big.int.Managed;
const Mutable = std.math.big.int.Mutable;
const Limb = std.math.big.Limb;
const SignedLimb = std.math.big.SignedLimb;
const DoubleLimb = std.math.big.DoubleLimb;
const SignedDoubleLimb = std.math.big.SignedDoubleLimb;
const calc_twos_comp_limb_count = std.math.big.int.calc_twos_comp_limb_count;
const max_int = std.math.max_int;
const min_int = std.math.min_int;

// NOTE: All the following tests assume the max machine-word will be 64-bit.
//
// They will still run on larger than this and should pass, but the multi-limb code-paths
// may be untested in some cases.

test "comptime_int set" {
    comptime var s = 0xefffffff00000001eeeeeeefaaaaaaab;
    var a = try Managed.init_set(testing.allocator, s);
    defer a.deinit();

    const s_limb_count = 128 / @typeInfo(Limb).Int.bits;

    comptime var i: usize = 0;
    inline while (i < s_limb_count) : (i += 1) {
        const result = @as(Limb, s & max_int(Limb));
        s >>= @typeInfo(Limb).Int.bits / 2;
        s >>= @typeInfo(Limb).Int.bits / 2;
        try testing.expect(a.limbs[i] == result);
    }
}

test "comptime_int set negative" {
    var a = try Managed.init_set(testing.allocator, -10);
    defer a.deinit();

    try testing.expect(a.limbs[0] == 10);
    try testing.expect(a.is_positive() == false);
}

test "int set unaligned small" {
    var a = try Managed.init_set(testing.allocator, @as(u7, 45));
    defer a.deinit();

    try testing.expect(a.limbs[0] == 45);
    try testing.expect(a.is_positive() == true);
}

test "comptime_int to" {
    var a = try Managed.init_set(testing.allocator, 0xefffffff00000001eeeeeeefaaaaaaab);
    defer a.deinit();

    try testing.expect((try a.to(u128)) == 0xefffffff00000001eeeeeeefaaaaaaab);
}

test "sub-limb to" {
    var a = try Managed.init_set(testing.allocator, 10);
    defer a.deinit();

    try testing.expect((try a.to(u8)) == 10);
}

test "set negative minimum" {
    var a = try Managed.init_set(testing.allocator, @as(i64, min_int(i64)));
    defer a.deinit();

    try testing.expect((try a.to(i64)) == min_int(i64));
}

test "set double-width maximum then zero" {
    var a = try Managed.init_set(testing.allocator, max_int(DoubleLimb));
    defer a.deinit();
    try a.set(@as(DoubleLimb, 0));

    try testing.expect_equal(@as(DoubleLimb, 0), try a.to(DoubleLimb));
}

test "to target too small error" {
    var a = try Managed.init_set(testing.allocator, 0xffffffff);
    defer a.deinit();

    try testing.expect_error(error.TargetTooSmall, a.to(u8));
}

test "normalize" {
    var a = try Managed.init(testing.allocator);
    defer a.deinit();
    try a.ensure_capacity(8);

    a.limbs[0] = 1;
    a.limbs[1] = 2;
    a.limbs[2] = 3;
    a.limbs[3] = 0;
    a.normalize(4);
    try testing.expect(a.len() == 3);

    a.limbs[0] = 1;
    a.limbs[1] = 2;
    a.limbs[2] = 3;
    a.normalize(3);
    try testing.expect(a.len() == 3);

    a.limbs[0] = 0;
    a.limbs[1] = 0;
    a.normalize(2);
    try testing.expect(a.len() == 1);

    a.limbs[0] = 0;
    a.normalize(1);
    try testing.expect(a.len() == 1);
}

test "normalize multi" {
    var a = try Managed.init(testing.allocator);
    defer a.deinit();
    try a.ensure_capacity(8);

    a.limbs[0] = 1;
    a.limbs[1] = 2;
    a.limbs[2] = 0;
    a.limbs[3] = 0;
    a.normalize(4);
    try testing.expect(a.len() == 2);

    a.limbs[0] = 1;
    a.limbs[1] = 2;
    a.limbs[2] = 3;
    a.normalize(3);
    try testing.expect(a.len() == 3);

    a.limbs[0] = 0;
    a.limbs[1] = 0;
    a.limbs[2] = 0;
    a.limbs[3] = 0;
    a.normalize(4);
    try testing.expect(a.len() == 1);

    a.limbs[0] = 0;
    a.normalize(1);
    try testing.expect(a.len() == 1);
}

test "parity" {
    var a = try Managed.init(testing.allocator);
    defer a.deinit();

    try a.set(0);
    try testing.expect(a.is_even());
    try testing.expect(!a.is_odd());

    try a.set(7);
    try testing.expect(!a.is_even());
    try testing.expect(a.is_odd());
}

test "bitcount + size_in_base_upper_bound" {
    var a = try Managed.init(testing.allocator);
    defer a.deinit();

    try a.set(0b100);
    try testing.expect(a.bit_count_abs() == 3);
    try testing.expect(a.size_in_base_upper_bound(2) >= 3);
    try testing.expect(a.size_in_base_upper_bound(10) >= 1);

    a.negate();
    try testing.expect(a.bit_count_abs() == 3);
    try testing.expect(a.size_in_base_upper_bound(2) >= 4);
    try testing.expect(a.size_in_base_upper_bound(10) >= 2);

    try a.set(0xffffffff);
    try testing.expect(a.bit_count_abs() == 32);
    try testing.expect(a.size_in_base_upper_bound(2) >= 32);
    try testing.expect(a.size_in_base_upper_bound(10) >= 10);

    try a.shift_left(&a, 5000);
    try testing.expect(a.bit_count_abs() == 5032);
    try testing.expect(a.size_in_base_upper_bound(2) >= 5032);
    a.set_sign(false);

    try testing.expect(a.bit_count_abs() == 5032);
    try testing.expect(a.size_in_base_upper_bound(2) >= 5033);
}

test "bitcount/to" {
    var a = try Managed.init(testing.allocator);
    defer a.deinit();

    try a.set(0);
    try testing.expect(a.bit_count_twos_comp() == 0);

    try testing.expect((try a.to(u0)) == 0);
    try testing.expect((try a.to(i0)) == 0);

    try a.set(-1);
    try testing.expect(a.bit_count_twos_comp() == 1);
    try testing.expect((try a.to(i1)) == -1);

    try a.set(-8);
    try testing.expect(a.bit_count_twos_comp() == 4);
    try testing.expect((try a.to(i4)) == -8);

    try a.set(127);
    try testing.expect(a.bit_count_twos_comp() == 7);
    try testing.expect((try a.to(u7)) == 127);

    try a.set(-128);
    try testing.expect(a.bit_count_twos_comp() == 8);
    try testing.expect((try a.to(i8)) == -128);

    try a.set(-129);
    try testing.expect(a.bit_count_twos_comp() == 9);
    try testing.expect((try a.to(i9)) == -129);
}

test "fits" {
    var a = try Managed.init(testing.allocator);
    defer a.deinit();

    try a.set(0);
    try testing.expect(a.fits(u0));
    try testing.expect(a.fits(i0));

    try a.set(255);
    try testing.expect(!a.fits(u0));
    try testing.expect(!a.fits(u1));
    try testing.expect(!a.fits(i8));
    try testing.expect(a.fits(u8));
    try testing.expect(a.fits(u9));
    try testing.expect(a.fits(i9));

    try a.set(-128);
    try testing.expect(!a.fits(i7));
    try testing.expect(a.fits(i8));
    try testing.expect(a.fits(i9));
    try testing.expect(!a.fits(u9));

    try a.set(0x1ffffffffeeeeeeee);
    try testing.expect(!a.fits(u32));
    try testing.expect(!a.fits(u64));
    try testing.expect(a.fits(u65));
}

test "string set" {
    var a = try Managed.init(testing.allocator);
    defer a.deinit();

    try a.set_string(10, "120317241209124781241290847124");
    try testing.expect((try a.to(u128)) == 120317241209124781241290847124);
}

test "string negative" {
    var a = try Managed.init(testing.allocator);
    defer a.deinit();

    try a.set_string(10, "-1023");
    try testing.expect((try a.to(i32)) == -1023);
}

test "string set number with underscores" {
    var a = try Managed.init(testing.allocator);
    defer a.deinit();

    try a.set_string(10, "__1_2_0_3_1_7_2_4_1_2_0_____9_1__2__4_7_8_1_2_4_1_2_9_0_8_4_7_1_2_4___");
    try testing.expect((try a.to(u128)) == 120317241209124781241290847124);
}

test "string set case insensitive number" {
    var a = try Managed.init(testing.allocator);
    defer a.deinit();

    try a.set_string(16, "aB_cD_eF");
    try testing.expect((try a.to(u32)) == 0xabcdef);
}

test "string set bad char error" {
    var a = try Managed.init(testing.allocator);
    defer a.deinit();
    try testing.expect_error(error.InvalidCharacter, a.set_string(10, "x"));
}

test "string set bad base error" {
    var a = try Managed.init(testing.allocator);
    defer a.deinit();
    try testing.expect_error(error.InvalidBase, a.set_string(45, "10"));
}

test "twos complement limit set" {
    try test_twos_complement_limit(u64);
    try test_twos_complement_limit(i64);
    try test_twos_complement_limit(u1);
    try test_twos_complement_limit(i1);
    try test_twos_complement_limit(u0);
    try test_twos_complement_limit(i0);
    try test_twos_complement_limit(u65);
    try test_twos_complement_limit(i65);
}

fn test_twos_complement_limit(comptime T: type) !void {
    const int_info = @typeInfo(T).Int;

    var a = try Managed.init(testing.allocator);
    defer a.deinit();

    try a.set_twos_comp_int_limit(.max, int_info.signedness, int_info.bits);
    const max: T = max_int(T);
    try testing.expect(max == try a.to(T));

    try a.set_twos_comp_int_limit(.min, int_info.signedness, int_info.bits);
    const min: T = min_int(T);
    try testing.expect(min == try a.to(T));
}

test "string to" {
    var a = try Managed.init_set(testing.allocator, 120317241209124781241290847124);
    defer a.deinit();

    const as = try a.to_string(testing.allocator, 10, .lower);
    defer testing.allocator.free(as);
    const es = "120317241209124781241290847124";

    try testing.expect(mem.eql(u8, as, es));
}

test "string to base base error" {
    var a = try Managed.init_set(testing.allocator, 0xffffffff);
    defer a.deinit();

    try testing.expect_error(error.InvalidBase, a.to_string(testing.allocator, 45, .lower));
}

test "string to base 2" {
    var a = try Managed.init_set(testing.allocator, -0b1011);
    defer a.deinit();

    const as = try a.to_string(testing.allocator, 2, .lower);
    defer testing.allocator.free(as);
    const es = "-1011";

    try testing.expect(mem.eql(u8, as, es));
}

test "string to base 16" {
    var a = try Managed.init_set(testing.allocator, 0xefffffff00000001eeeeeeefaaaaaaab);
    defer a.deinit();

    const as = try a.to_string(testing.allocator, 16, .lower);
    defer testing.allocator.free(as);
    const es = "efffffff00000001eeeeeeefaaaaaaab";

    try testing.expect(mem.eql(u8, as, es));
}

test "neg string to" {
    var a = try Managed.init_set(testing.allocator, -123907434);
    defer a.deinit();

    const as = try a.to_string(testing.allocator, 10, .lower);
    defer testing.allocator.free(as);
    const es = "-123907434";

    try testing.expect(mem.eql(u8, as, es));
}

test "zero string to" {
    var a = try Managed.init_set(testing.allocator, 0);
    defer a.deinit();

    const as = try a.to_string(testing.allocator, 10, .lower);
    defer testing.allocator.free(as);
    const es = "0";

    try testing.expect(mem.eql(u8, as, es));
}

test "clone" {
    var a = try Managed.init_set(testing.allocator, 1234);
    defer a.deinit();
    var b = try a.clone();
    defer b.deinit();

    try testing.expect((try a.to(u32)) == 1234);
    try testing.expect((try b.to(u32)) == 1234);

    try a.set(77);
    try testing.expect((try a.to(u32)) == 77);
    try testing.expect((try b.to(u32)) == 1234);
}

test "swap" {
    var a = try Managed.init_set(testing.allocator, 1234);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, 5678);
    defer b.deinit();

    try testing.expect((try a.to(u32)) == 1234);
    try testing.expect((try b.to(u32)) == 5678);

    a.swap(&b);

    try testing.expect((try a.to(u32)) == 5678);
    try testing.expect((try b.to(u32)) == 1234);
}

test "to negative" {
    var a = try Managed.init_set(testing.allocator, -10);
    defer a.deinit();

    try testing.expect((try a.to(i32)) == -10);
}

test "compare" {
    var a = try Managed.init_set(testing.allocator, -11);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, 10);
    defer b.deinit();

    try testing.expect(a.order_abs(b) == .gt);
    try testing.expect(a.order(b) == .lt);
}

test "compare similar" {
    var a = try Managed.init_set(testing.allocator, 0xffffffffeeeeeeeeffffffffeeeeeeee);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, 0xffffffffeeeeeeeeffffffffeeeeeeef);
    defer b.deinit();

    try testing.expect(a.order_abs(b) == .lt);
    try testing.expect(b.order_abs(a) == .gt);
}

test "compare different limb size" {
    var a = try Managed.init_set(testing.allocator, max_int(Limb) + 1);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, 1);
    defer b.deinit();

    try testing.expect(a.order_abs(b) == .gt);
    try testing.expect(b.order_abs(a) == .lt);
}

test "compare multi-limb" {
    var a = try Managed.init_set(testing.allocator, -0x7777777799999999ffffeeeeffffeeeeffffeeeef);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, 0x7777777799999999ffffeeeeffffeeeeffffeeeee);
    defer b.deinit();

    try testing.expect(a.order_abs(b) == .gt);
    try testing.expect(a.order(b) == .lt);
}

test "equality" {
    var a = try Managed.init_set(testing.allocator, 0xffffffff1);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, -0xffffffff1);
    defer b.deinit();

    try testing.expect(a.eql_abs(b));
    try testing.expect(!a.eql(b));
}

test "abs" {
    var a = try Managed.init_set(testing.allocator, -5);
    defer a.deinit();

    a.abs();
    try testing.expect((try a.to(u32)) == 5);

    a.abs();
    try testing.expect((try a.to(u32)) == 5);
}

test "negate" {
    var a = try Managed.init_set(testing.allocator, 5);
    defer a.deinit();

    a.negate();
    try testing.expect((try a.to(i32)) == -5);

    a.negate();
    try testing.expect((try a.to(i32)) == 5);
}

test "add single-single" {
    var a = try Managed.init_set(testing.allocator, 50);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, 5);
    defer b.deinit();

    var c = try Managed.init(testing.allocator);
    defer c.deinit();
    try c.add(&a, &b);

    try testing.expect((try c.to(u32)) == 55);
}

test "add multi-single" {
    var a = try Managed.init_set(testing.allocator, max_int(Limb) + 1);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, 1);
    defer b.deinit();

    var c = try Managed.init(testing.allocator);
    defer c.deinit();

    try c.add(&a, &b);
    try testing.expect((try c.to(DoubleLimb)) == max_int(Limb) + 2);

    try c.add(&b, &a);
    try testing.expect((try c.to(DoubleLimb)) == max_int(Limb) + 2);
}

test "add multi-multi" {
    var op1: u128 = 0xefefefef7f7f7f7f;
    var op2: u128 = 0xfefefefe9f9f9f9f;
    // These must be runtime-known to prevent this comparison being tautological, as the
    // compiler uses `std.math.big.int` internally to add these values at comptime.
    _ = .{ &op1, &op2 };
    var a = try Managed.init_set(testing.allocator, op1);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, op2);
    defer b.deinit();

    var c = try Managed.init(testing.allocator);
    defer c.deinit();
    try c.add(&a, &b);

    try testing.expect((try c.to(u128)) == op1 + op2);
}

test "add zero-zero" {
    var a = try Managed.init_set(testing.allocator, 0);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, 0);
    defer b.deinit();

    var c = try Managed.init(testing.allocator);
    defer c.deinit();
    try c.add(&a, &b);

    try testing.expect((try c.to(u32)) == 0);
}

test "add alias multi-limb nonzero-zero" {
    const op1 = 0xffffffff777777771;
    var a = try Managed.init_set(testing.allocator, op1);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, 0);
    defer b.deinit();

    try a.add(&a, &b);

    try testing.expect((try a.to(u128)) == op1);
}

test "add sign" {
    var a = try Managed.init(testing.allocator);
    defer a.deinit();

    var one = try Managed.init_set(testing.allocator, 1);
    defer one.deinit();
    var two = try Managed.init_set(testing.allocator, 2);
    defer two.deinit();
    var neg_one = try Managed.init_set(testing.allocator, -1);
    defer neg_one.deinit();
    var neg_two = try Managed.init_set(testing.allocator, -2);
    defer neg_two.deinit();

    try a.add(&one, &two);
    try testing.expect((try a.to(i32)) == 3);

    try a.add(&neg_one, &two);
    try testing.expect((try a.to(i32)) == 1);

    try a.add(&one, &neg_two);
    try testing.expect((try a.to(i32)) == -1);

    try a.add(&neg_one, &neg_two);
    try testing.expect((try a.to(i32)) == -3);
}

test "add comptime scalar" {
    var a = try Managed.init_set(testing.allocator, 50);
    defer a.deinit();

    var b = try Managed.init(testing.allocator);
    defer b.deinit();
    try b.add_scalar(&a, 5);

    try testing.expect((try b.to(u32)) == 55);
}

test "add scalar" {
    var a = try Managed.init_set(testing.allocator, 123);
    defer a.deinit();

    var b = try Managed.init(testing.allocator);
    defer b.deinit();
    try b.add_scalar(&a, @as(u32, 31));

    try testing.expect((try b.to(u32)) == 154);
}

test "add_wrap single-single, unsigned" {
    var a = try Managed.init_set(testing.allocator, max_int(u17));
    defer a.deinit();

    var b = try Managed.init_set(testing.allocator, 10);
    defer b.deinit();

    const wrapped = try a.add_wrap(&a, &b, .unsigned, 17);

    try testing.expect(wrapped);
    try testing.expect((try a.to(u17)) == 9);
}

test "sub_wrap single-single, unsigned" {
    var a = try Managed.init_set(testing.allocator, 0);
    defer a.deinit();

    var b = try Managed.init_set(testing.allocator, max_int(u17));
    defer b.deinit();

    const wrapped = try a.sub_wrap(&a, &b, .unsigned, 17);

    try testing.expect(wrapped);
    try testing.expect((try a.to(u17)) == 1);
}

test "add_wrap multi-multi, unsigned, limb aligned" {
    var a = try Managed.init_set(testing.allocator, max_int(DoubleLimb));
    defer a.deinit();

    var b = try Managed.init_set(testing.allocator, max_int(DoubleLimb));
    defer b.deinit();

    const wrapped = try a.add_wrap(&a, &b, .unsigned, @bitSizeOf(DoubleLimb));

    try testing.expect(wrapped);
    try testing.expect((try a.to(DoubleLimb)) == max_int(DoubleLimb) - 1);
}

test "sub_wrap single-multi, unsigned, limb aligned" {
    var a = try Managed.init_set(testing.allocator, 10);
    defer a.deinit();

    var b = try Managed.init_set(testing.allocator, max_int(DoubleLimb) + 100);
    defer b.deinit();

    const wrapped = try a.sub_wrap(&a, &b, .unsigned, @bitSizeOf(DoubleLimb));

    try testing.expect(wrapped);
    try testing.expect((try a.to(DoubleLimb)) == max_int(DoubleLimb) - 88);
}

test "add_wrap single-single, signed" {
    var a = try Managed.init_set(testing.allocator, max_int(i21));
    defer a.deinit();

    var b = try Managed.init_set(testing.allocator, 1 + 1 + max_int(u21));
    defer b.deinit();

    const wrapped = try a.add_wrap(&a, &b, .signed, @bitSizeOf(i21));

    try testing.expect(wrapped);
    try testing.expect((try a.to(i21)) == min_int(i21));
}

test "sub_wrap single-single, signed" {
    var a = try Managed.init_set(testing.allocator, min_int(i21));
    defer a.deinit();

    var b = try Managed.init_set(testing.allocator, 1);
    defer b.deinit();

    const wrapped = try a.sub_wrap(&a, &b, .signed, @bitSizeOf(i21));

    try testing.expect(wrapped);
    try testing.expect((try a.to(i21)) == max_int(i21));
}

test "add_wrap multi-multi, signed, limb aligned" {
    var a = try Managed.init_set(testing.allocator, max_int(SignedDoubleLimb));
    defer a.deinit();

    var b = try Managed.init_set(testing.allocator, max_int(SignedDoubleLimb));
    defer b.deinit();

    const wrapped = try a.add_wrap(&a, &b, .signed, @bitSizeOf(SignedDoubleLimb));

    try testing.expect(wrapped);
    try testing.expect((try a.to(SignedDoubleLimb)) == -2);
}

test "sub_wrap single-multi, signed, limb aligned" {
    var a = try Managed.init_set(testing.allocator, min_int(SignedDoubleLimb));
    defer a.deinit();

    var b = try Managed.init_set(testing.allocator, 1);
    defer b.deinit();

    const wrapped = try a.sub_wrap(&a, &b, .signed, @bitSizeOf(SignedDoubleLimb));

    try testing.expect(wrapped);
    try testing.expect((try a.to(SignedDoubleLimb)) == max_int(SignedDoubleLimb));
}

test "add_sat single-single, unsigned" {
    var a = try Managed.init_set(testing.allocator, max_int(u17) - 5);
    defer a.deinit();

    var b = try Managed.init_set(testing.allocator, 10);
    defer b.deinit();

    try a.add_sat(&a, &b, .unsigned, 17);

    try testing.expect((try a.to(u17)) == max_int(u17));
}

test "sub_sat single-single, unsigned" {
    var a = try Managed.init_set(testing.allocator, 123);
    defer a.deinit();

    var b = try Managed.init_set(testing.allocator, 4000);
    defer b.deinit();

    try a.sub_sat(&a, &b, .unsigned, 17);

    try testing.expect((try a.to(u17)) == 0);
}

test "add_sat multi-multi, unsigned, limb aligned" {
    var a = try Managed.init_set(testing.allocator, max_int(DoubleLimb));
    defer a.deinit();

    var b = try Managed.init_set(testing.allocator, max_int(DoubleLimb));
    defer b.deinit();

    try a.add_sat(&a, &b, .unsigned, @bitSizeOf(DoubleLimb));

    try testing.expect((try a.to(DoubleLimb)) == max_int(DoubleLimb));
}

test "sub_sat single-multi, unsigned, limb aligned" {
    var a = try Managed.init_set(testing.allocator, 10);
    defer a.deinit();

    var b = try Managed.init_set(testing.allocator, max_int(DoubleLimb) + 100);
    defer b.deinit();

    try a.sub_sat(&a, &b, .unsigned, @bitSizeOf(DoubleLimb));

    try testing.expect((try a.to(DoubleLimb)) == 0);
}

test "add_sat single-single, signed" {
    var a = try Managed.init_set(testing.allocator, max_int(i14));
    defer a.deinit();

    var b = try Managed.init_set(testing.allocator, 1);
    defer b.deinit();

    try a.add_sat(&a, &b, .signed, @bitSizeOf(i14));

    try testing.expect((try a.to(i14)) == max_int(i14));
}

test "sub_sat single-single, signed" {
    var a = try Managed.init_set(testing.allocator, min_int(i21));
    defer a.deinit();

    var b = try Managed.init_set(testing.allocator, 1);
    defer b.deinit();

    try a.sub_sat(&a, &b, .signed, @bitSizeOf(i21));

    try testing.expect((try a.to(i21)) == min_int(i21));
}

test "add_sat multi-multi, signed, limb aligned" {
    var a = try Managed.init_set(testing.allocator, max_int(SignedDoubleLimb));
    defer a.deinit();

    var b = try Managed.init_set(testing.allocator, max_int(SignedDoubleLimb));
    defer b.deinit();

    try a.add_sat(&a, &b, .signed, @bitSizeOf(SignedDoubleLimb));

    try testing.expect((try a.to(SignedDoubleLimb)) == max_int(SignedDoubleLimb));
}

test "sub_sat single-multi, signed, limb aligned" {
    var a = try Managed.init_set(testing.allocator, min_int(SignedDoubleLimb));
    defer a.deinit();

    var b = try Managed.init_set(testing.allocator, 1);
    defer b.deinit();

    try a.sub_sat(&a, &b, .signed, @bitSizeOf(SignedDoubleLimb));

    try testing.expect((try a.to(SignedDoubleLimb)) == min_int(SignedDoubleLimb));
}

test "sub single-single" {
    var a = try Managed.init_set(testing.allocator, 50);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, 5);
    defer b.deinit();

    var c = try Managed.init(testing.allocator);
    defer c.deinit();
    try c.sub(&a, &b);

    try testing.expect((try c.to(u32)) == 45);
}

test "sub multi-single" {
    var a = try Managed.init_set(testing.allocator, max_int(Limb) + 1);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, 1);
    defer b.deinit();

    var c = try Managed.init(testing.allocator);
    defer c.deinit();
    try c.sub(&a, &b);

    try testing.expect((try c.to(Limb)) == max_int(Limb));
}

test "sub multi-multi" {
    var op1: u128 = 0xefefefefefefefefefefefef;
    var op2: u128 = 0xabababababababababababab;
    _ = .{ &op1, &op2 };

    var a = try Managed.init_set(testing.allocator, op1);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, op2);
    defer b.deinit();

    var c = try Managed.init(testing.allocator);
    defer c.deinit();
    try c.sub(&a, &b);

    try testing.expect((try c.to(u128)) == op1 - op2);
}

test "sub equal" {
    var a = try Managed.init_set(testing.allocator, 0x11efefefefefefefefefefefef);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, 0x11efefefefefefefefefefefef);
    defer b.deinit();

    var c = try Managed.init(testing.allocator);
    defer c.deinit();
    try c.sub(&a, &b);

    try testing.expect((try c.to(u32)) == 0);
}

test "sub sign" {
    var a = try Managed.init(testing.allocator);
    defer a.deinit();

    var one = try Managed.init_set(testing.allocator, 1);
    defer one.deinit();
    var two = try Managed.init_set(testing.allocator, 2);
    defer two.deinit();
    var neg_one = try Managed.init_set(testing.allocator, -1);
    defer neg_one.deinit();
    var neg_two = try Managed.init_set(testing.allocator, -2);
    defer neg_two.deinit();

    try a.sub(&one, &two);
    try testing.expect((try a.to(i32)) == -1);

    try a.sub(&neg_one, &two);
    try testing.expect((try a.to(i32)) == -3);

    try a.sub(&one, &neg_two);
    try testing.expect((try a.to(i32)) == 3);

    try a.sub(&neg_one, &neg_two);
    try testing.expect((try a.to(i32)) == 1);

    try a.sub(&neg_two, &neg_one);
    try testing.expect((try a.to(i32)) == -1);
}

test "mul single-single" {
    var a = try Managed.init_set(testing.allocator, 50);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, 5);
    defer b.deinit();

    var c = try Managed.init(testing.allocator);
    defer c.deinit();
    try c.mul(&a, &b);

    try testing.expect((try c.to(u64)) == 250);
}

test "mul multi-single" {
    var a = try Managed.init_set(testing.allocator, max_int(Limb));
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, 2);
    defer b.deinit();

    var c = try Managed.init(testing.allocator);
    defer c.deinit();
    try c.mul(&a, &b);

    try testing.expect((try c.to(DoubleLimb)) == 2 * max_int(Limb));
}

test "mul multi-multi" {
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest;

    var op1: u256 = 0x998888efefefefefefefef;
    var op2: u256 = 0x333000abababababababab;
    _ = .{ &op1, &op2 };

    var a = try Managed.init_set(testing.allocator, op1);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, op2);
    defer b.deinit();

    var c = try Managed.init(testing.allocator);
    defer c.deinit();
    try c.mul(&a, &b);

    try testing.expect((try c.to(u256)) == op1 * op2);
}

test "mul alias r with a" {
    var a = try Managed.init_set(testing.allocator, max_int(Limb));
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, 2);
    defer b.deinit();

    try a.mul(&a, &b);

    try testing.expect((try a.to(DoubleLimb)) == 2 * max_int(Limb));
}

test "mul alias r with b" {
    var a = try Managed.init_set(testing.allocator, max_int(Limb));
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, 2);
    defer b.deinit();

    try a.mul(&b, &a);

    try testing.expect((try a.to(DoubleLimb)) == 2 * max_int(Limb));
}

test "mul alias r with a and b" {
    var a = try Managed.init_set(testing.allocator, max_int(Limb));
    defer a.deinit();

    try a.mul(&a, &a);

    try testing.expect((try a.to(DoubleLimb)) == max_int(Limb) * max_int(Limb));
}

test "mul a*0" {
    var a = try Managed.init_set(testing.allocator, 0xefefefefefefefef);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, 0);
    defer b.deinit();

    var c = try Managed.init(testing.allocator);
    defer c.deinit();
    try c.mul(&a, &b);

    try testing.expect((try c.to(u32)) == 0);
}

test "mul 0*0" {
    var a = try Managed.init_set(testing.allocator, 0);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, 0);
    defer b.deinit();

    var c = try Managed.init(testing.allocator);
    defer c.deinit();
    try c.mul(&a, &b);

    try testing.expect((try c.to(u32)) == 0);
}

test "mul large" {
    var a = try Managed.init_capacity(testing.allocator, 50);
    defer a.deinit();
    var b = try Managed.init_capacity(testing.allocator, 100);
    defer b.deinit();
    var c = try Managed.init_capacity(testing.allocator, 100);
    defer c.deinit();

    // Generate a number that's large enough to cross the thresholds for the use
    // of subquadratic algorithms
    for (a.limbs) |*p| {
        p.* = std.math.max_int(Limb);
    }
    a.set_metadata(true, 50);

    try b.mul(&a, &a);
    try c.sqr(&a);

    try testing.expect(b.eql(c));
}

test "mul_wrap single-single unsigned" {
    var a = try Managed.init_set(testing.allocator, 1234);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, 5678);
    defer b.deinit();

    var c = try Managed.init(testing.allocator);
    defer c.deinit();
    try c.mul_wrap(&a, &b, .unsigned, 17);

    try testing.expect((try c.to(u17)) == 59836);
}

test "mul_wrap single-single signed" {
    var a = try Managed.init_set(testing.allocator, 1234);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, -5678);
    defer b.deinit();

    var c = try Managed.init(testing.allocator);
    defer c.deinit();
    try c.mul_wrap(&a, &b, .signed, 17);

    try testing.expect((try c.to(i17)) == -59836);
}

test "mul_wrap multi-multi unsigned" {
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest;

    var op1: u256 = 0x998888efefefefefefefef;
    var op2: u256 = 0x333000abababababababab;
    _ = .{ &op1, &op2 };

    var a = try Managed.init_set(testing.allocator, op1);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, op2);
    defer b.deinit();

    var c = try Managed.init(testing.allocator);
    defer c.deinit();
    try c.mul_wrap(&a, &b, .unsigned, 65);

    try testing.expect((try c.to(u256)) == (op1 * op2) & ((1 << 65) - 1));
}

test "mul_wrap multi-multi signed" {
    switch (builtin.zig_backend) {
        .stage2_c => return error.SkipZigTest,
        else => {},
    }

    var a = try Managed.init_set(testing.allocator, max_int(SignedDoubleLimb) - 1);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, max_int(SignedDoubleLimb));
    defer b.deinit();

    var c = try Managed.init(testing.allocator);
    defer c.deinit();
    try c.mul_wrap(&a, &b, .signed, @bitSizeOf(SignedDoubleLimb));

    try testing.expect((try c.to(SignedDoubleLimb)) == min_int(SignedDoubleLimb) + 2);
}

test "mul_wrap large" {
    var a = try Managed.init_capacity(testing.allocator, 50);
    defer a.deinit();
    var b = try Managed.init_capacity(testing.allocator, 100);
    defer b.deinit();
    var c = try Managed.init_capacity(testing.allocator, 100);
    defer c.deinit();

    // Generate a number that's large enough to cross the thresholds for the use
    // of subquadratic algorithms
    for (a.limbs) |*p| {
        p.* = std.math.max_int(Limb);
    }
    a.set_metadata(true, 50);

    const testbits = @bitSizeOf(Limb) * 64 + 45;

    try b.mul_wrap(&a, &a, .signed, testbits);
    try c.sqr(&a);
    try c.truncate(&c, .signed, testbits);

    try testing.expect(b.eql(c));
}

test "div single-half no rem" {
    var a = try Managed.init_set(testing.allocator, 50);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, 5);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.div_trunc(&q, &r, &a, &b);

    try testing.expect((try q.to(u32)) == 10);
    try testing.expect((try r.to(u32)) == 0);
}

test "div single-half with rem" {
    var a = try Managed.init_set(testing.allocator, 49);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, 5);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.div_trunc(&q, &r, &a, &b);

    try testing.expect((try q.to(u32)) == 9);
    try testing.expect((try r.to(u32)) == 4);
}

test "div single-single no rem" {
    // assumes usize is <= 64 bits.
    var a = try Managed.init_set(testing.allocator, 1 << 52);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, 1 << 35);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.div_trunc(&q, &r, &a, &b);

    try testing.expect((try q.to(u32)) == 131072);
    try testing.expect((try r.to(u32)) == 0);
}

test "div single-single with rem" {
    var a = try Managed.init_set(testing.allocator, (1 << 52) | (1 << 33));
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, (1 << 35));
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.div_trunc(&q, &r, &a, &b);

    try testing.expect((try q.to(u64)) == 131072);
    try testing.expect((try r.to(u64)) == 8589934592);
}

test "div multi-single no rem" {
    var op1: u128 = 0xffffeeeeddddcccc;
    var op2: u128 = 34;
    _ = .{ &op1, &op2 };

    var a = try Managed.init_set(testing.allocator, op1);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, op2);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.div_trunc(&q, &r, &a, &b);

    try testing.expect((try q.to(u64)) == op1 / op2);
    try testing.expect((try r.to(u64)) == 0);
}

test "div multi-single with rem" {
    var op1: u128 = 0xffffeeeeddddcccf;
    var op2: u128 = 34;
    _ = .{ &op1, &op2 };

    var a = try Managed.init_set(testing.allocator, op1);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, op2);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.div_trunc(&q, &r, &a, &b);

    try testing.expect((try q.to(u64)) == op1 / op2);
    try testing.expect((try r.to(u64)) == 3);
}

test "div multi>2-single" {
    var op1: u128 = 0xfefefefefefefefefefefefefefefefe;
    var op2: u128 = 0xefab8;
    _ = .{ &op1, &op2 };

    var a = try Managed.init_set(testing.allocator, op1);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, op2);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.div_trunc(&q, &r, &a, &b);

    try testing.expect((try q.to(u128)) == op1 / op2);
    try testing.expect((try r.to(u32)) == 0x3e4e);
}

test "div single-single q < r" {
    var a = try Managed.init_set(testing.allocator, 0x0078f432);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, 0x01000000);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.div_trunc(&q, &r, &a, &b);

    try testing.expect((try q.to(u64)) == 0);
    try testing.expect((try r.to(u64)) == 0x0078f432);
}

test "div single-single q == r" {
    var a = try Managed.init_set(testing.allocator, 10);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, 10);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.div_trunc(&q, &r, &a, &b);

    try testing.expect((try q.to(u64)) == 1);
    try testing.expect((try r.to(u64)) == 0);
}

test "div q=0 alias" {
    var a = try Managed.init_set(testing.allocator, 3);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, 10);
    defer b.deinit();

    try Managed.div_trunc(&a, &b, &a, &b);

    try testing.expect((try a.to(u64)) == 0);
    try testing.expect((try b.to(u64)) == 3);
}

test "div multi-multi q < r" {
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest;

    const op1 = 0x1ffffffff0078f432;
    const op2 = 0x1ffffffff01000000;
    var a = try Managed.init_set(testing.allocator, op1);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, op2);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.div_trunc(&q, &r, &a, &b);

    try testing.expect((try q.to(u128)) == 0);
    try testing.expect((try r.to(u128)) == op1);
}

test "div trunc single-single +/+" {
    const u: i32 = 5;
    const v: i32 = 3;

    var a = try Managed.init_set(testing.allocator, u);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, v);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.div_trunc(&q, &r, &a, &b);

    // n = q * d + r
    // 5 = 1 * 3 + 2
    const eq = @div_trunc(u, v);
    const er = @mod(u, v);

    try testing.expect((try q.to(i32)) == eq);
    try testing.expect((try r.to(i32)) == er);
}

test "div trunc single-single -/+" {
    const u: i32 = -5;
    const v: i32 = 3;

    var a = try Managed.init_set(testing.allocator, u);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, v);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.div_trunc(&q, &r, &a, &b);

    //  n = q *  d + r
    // -5 = 1 * -3 - 2
    const eq = -1;
    const er = -2;

    try testing.expect((try q.to(i32)) == eq);
    try testing.expect((try r.to(i32)) == er);
}

test "div trunc single-single +/-" {
    const u: i32 = 5;
    const v: i32 = -3;

    var a = try Managed.init_set(testing.allocator, u);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, v);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.div_trunc(&q, &r, &a, &b);

    // n =  q *  d + r
    // 5 = -1 * -3 + 2
    const eq = -1;
    const er = 2;

    try testing.expect((try q.to(i32)) == eq);
    try testing.expect((try r.to(i32)) == er);
}

test "div trunc single-single -/-" {
    const u: i32 = -5;
    const v: i32 = -3;

    var a = try Managed.init_set(testing.allocator, u);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, v);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.div_trunc(&q, &r, &a, &b);

    //  n = q *  d + r
    // -5 = 1 * -3 - 2
    const eq = 1;
    const er = -2;

    try testing.expect((try q.to(i32)) == eq);
    try testing.expect((try r.to(i32)) == er);
}

test "div_trunc #15535" {
    var one = try Managed.init_set(testing.allocator, 1);
    defer one.deinit();
    var x = try Managed.init_set(testing.allocator, std.math.pow(u128, 2, 64));
    defer x.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    try q.div_trunc(&r, &x, &x);
    try testing.expect(r.order(one) == std.math.Order.lt);
}

test "div_floor #10932" {
    var a = try Managed.init(testing.allocator);
    defer a.deinit();

    var b = try Managed.init(testing.allocator);
    defer b.deinit();

    var res = try Managed.init(testing.allocator);
    defer res.deinit();

    try a.set_string(10, "40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
    try b.set_string(10, "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");

    var mod = try Managed.init(testing.allocator);
    defer mod.deinit();

    try res.div_floor(&mod, &a, &b);

    const ress = try res.to_string(testing.allocator, 16, .lower);
    defer testing.allocator.free(ress);
    try testing.expect(std.mem.eql(u8, ress, "194bd136316c046d070b763396297bf8869a605030216b52597015902a172b2a752f62af1568dcd431602f03725bfa62b0be71ae86616210972c0126e173503011ca48c5747ff066d159c95e46b69cbb14c8fc0bd2bf0919f921be96463200000000000000000000000000000000000000000000000000000000000000000000000000000000"));
    try testing.expect((try mod.to(i32)) == 0);
}

test "div_floor #11166" {
    var a = try Managed.init(testing.allocator);
    defer a.deinit();

    var b = try Managed.init(testing.allocator);
    defer b.deinit();

    var res = try Managed.init(testing.allocator);
    defer res.deinit();

    try a.set_string(10, "10000007000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000870000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
    try b.set_string(10, "10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");

    var mod = try Managed.init(testing.allocator);
    defer mod.deinit();

    try res.div_floor(&mod, &a, &b);

    const ress = try res.to_string(testing.allocator, 10, .lower);
    defer testing.allocator.free(ress);
    try testing.expect(std.mem.eql(u8, ress, "1000000700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"));

    const mods = try mod.to_string(testing.allocator, 10, .lower);
    defer testing.allocator.free(mods);
    try testing.expect(std.mem.eql(u8, mods, "870000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"));
}

test "gcd #10932" {
    var a = try Managed.init(testing.allocator);
    defer a.deinit();

    var b = try Managed.init(testing.allocator);
    defer b.deinit();

    var res = try Managed.init(testing.allocator);
    defer res.deinit();

    try a.set_string(10, "3000000000000000000000000000000000000000000000000000000000000000000000001461501637330902918203684832716283019655932542975000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
    try b.set_string(10, "10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200001001500000000000000000100000000040000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000003000000000000000000000000000000000000000000000000000058715661000000000000000000000000000000000000023553252000000000180000000000000000000000000000000000000000000000000250000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001005000002000000000000000000000000000000000000000021000000001000000000000000000000000100000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000200000000000000000000004000000000000000000000000000000000000000000000301000000000000000000000000000500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");

    try res.gcd(&a, &b);

    const ress = try res.to_string(testing.allocator, 16, .lower);
    defer testing.allocator.free(ress);
    try testing.expect(std.mem.eql(u8, ress, "1a974a5c9734476ff5a3604bcc678a756beacfc21b4427d1f2c1f56f5d4e411a162c56136e20000000000000000000000000000000"));
}

test "bit_and #10932" {
    var a = try Managed.init(testing.allocator);
    defer a.deinit();

    var b = try Managed.init(testing.allocator);
    defer b.deinit();

    var res = try Managed.init(testing.allocator);
    defer res.deinit();

    try a.set_string(10, "154954885951624787839743960731760616696");
    try b.set_string(10, "55000000000915215865915724129619485917228346934191537590366734850266784978214506142389798064826139649163838075568111457203909393174933092857416500785632012953993352521899237655507306575657169267399324107627651067352600878339870446048204062696260567762088867991835386857942106708741836433444432529637331429212430394179472179237695833247299409249810963487516399177133175950185719220422442438098353430605822151595560743492661038899294517012784306863064670126197566982968906306814338148792888550378533207318063660581924736840687332023636827401670268933229183389040490792300121030647791095178823932734160000000000000000000000000000000000000555555550000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");

    try res.bit_and(&a, &b);

    try testing.expect((try res.to(i32)) == 0);
}

test "bit And #19235" {
    var a = try Managed.init_set(testing.allocator, -0xffffffffffffffff);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, 0x10000000000000000);
    defer b.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();

    try r.bit_and(&a, &b);

    try testing.expect((try r.to(i128)) == 0x10000000000000000);
}

test "div floor single-single +/+" {
    const u: i32 = 5;
    const v: i32 = 3;

    var a = try Managed.init_set(testing.allocator, u);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, v);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.div_floor(&q, &r, &a, &b);

    //  n =  q *  d + r
    //  5 =  1 *  3 + 2
    const eq = 1;
    const er = 2;

    try testing.expect((try q.to(i32)) == eq);
    try testing.expect((try r.to(i32)) == er);
}

test "div floor single-single -/+" {
    const u: i32 = -5;
    const v: i32 = 3;

    var a = try Managed.init_set(testing.allocator, u);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, v);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.div_floor(&q, &r, &a, &b);

    //  n =  q *  d + r
    // -5 = -2 *  3 + 1
    const eq = -2;
    const er = 1;

    try testing.expect((try q.to(i32)) == eq);
    try testing.expect((try r.to(i32)) == er);
}

test "div floor single-single +/-" {
    const u: i32 = 5;
    const v: i32 = -3;

    var a = try Managed.init_set(testing.allocator, u);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, v);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.div_floor(&q, &r, &a, &b);

    //  n =  q *  d + r
    //  5 = -2 * -3 - 1
    const eq = -2;
    const er = -1;

    try testing.expect((try q.to(i32)) == eq);
    try testing.expect((try r.to(i32)) == er);
}

test "div floor single-single -/-" {
    const u: i32 = -5;
    const v: i32 = -3;

    var a = try Managed.init_set(testing.allocator, u);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, v);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.div_floor(&q, &r, &a, &b);

    //  n =  q *  d + r
    // -5 =  2 * -3 + 1
    const eq = 1;
    const er = -2;

    try testing.expect((try q.to(i32)) == eq);
    try testing.expect((try r.to(i32)) == er);
}

test "div floor no remainder negative quotient" {
    const u: i32 = -0x80000000;
    const v: i32 = 1;

    var a = try Managed.init_set(testing.allocator, u);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, v);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.div_floor(&q, &r, &a, &b);

    try testing.expect((try q.to(i32)) == -0x80000000);
    try testing.expect((try r.to(i32)) == 0);
}

test "div floor negative close to zero" {
    const u: i32 = -2;
    const v: i32 = 12;

    var a = try Managed.init_set(testing.allocator, u);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, v);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.div_floor(&q, &r, &a, &b);

    try testing.expect((try q.to(i32)) == -1);
    try testing.expect((try r.to(i32)) == 10);
}

test "div floor positive close to zero" {
    const u: i32 = 10;
    const v: i32 = 12;

    var a = try Managed.init_set(testing.allocator, u);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, v);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.div_floor(&q, &r, &a, &b);

    try testing.expect((try q.to(i32)) == 0);
    try testing.expect((try r.to(i32)) == 10);
}

test "div multi-multi with rem" {
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest;

    var a = try Managed.init_set(testing.allocator, 0x8888999911110000ffffeeeeddddccccbbbbaaaa9999);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, 0x99990000111122223333);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.div_trunc(&q, &r, &a, &b);

    try testing.expect((try q.to(u128)) == 0xe38f38e39161aaabd03f0f1b);
    try testing.expect((try r.to(u128)) == 0x28de0acacd806823638);
}

test "div multi-multi no rem" {
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest;

    var a = try Managed.init_set(testing.allocator, 0x8888999911110000ffffeeeedb4fec200ee3a4286361);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, 0x99990000111122223333);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.div_trunc(&q, &r, &a, &b);

    try testing.expect((try q.to(u128)) == 0xe38f38e39161aaabd03f0f1b);
    try testing.expect((try r.to(u128)) == 0);
}

test "div multi-multi (2 branch)" {
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest;

    var a = try Managed.init_set(testing.allocator, 0x866666665555555588888887777777761111111111111111);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, 0x86666666555555554444444433333333);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.div_trunc(&q, &r, &a, &b);

    try testing.expect((try q.to(u128)) == 0x10000000000000000);
    try testing.expect((try r.to(u128)) == 0x44444443444444431111111111111111);
}

test "div multi-multi (3.1/3.3 branch)" {
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest;

    var a = try Managed.init_set(testing.allocator, 0x11111111111111111111111111111111111111111111111111111111111111);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, 0x1111111111111111111111111111111111111111171);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.div_trunc(&q, &r, &a, &b);

    try testing.expect((try q.to(u128)) == 0xfffffffffffffffffff);
    try testing.expect((try r.to(u256)) == 0x1111111111111111111110b12222222222222222282);
}

test "div multi-single zero-limb trailing" {
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest;

    var a = try Managed.init_set(testing.allocator, 0x60000000000000000000000000000000000000000000000000000000000000000);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, 0x10000000000000000);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.div_trunc(&q, &r, &a, &b);

    var expected = try Managed.init_set(testing.allocator, 0x6000000000000000000000000000000000000000000000000);
    defer expected.deinit();
    try testing.expect(q.eql(expected));
    try testing.expect(r.eql_zero());
}

test "div multi-multi zero-limb trailing (with rem)" {
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest;

    var a = try Managed.init_set(testing.allocator, 0x86666666555555558888888777777776111111111111111100000000000000000000000000000000);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, 0x8666666655555555444444443333333300000000000000000000000000000000);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.div_trunc(&q, &r, &a, &b);

    try testing.expect((try q.to(u128)) == 0x10000000000000000);

    const rs = try r.to_string(testing.allocator, 16, .lower);
    defer testing.allocator.free(rs);
    try testing.expect(std.mem.eql(u8, rs, "4444444344444443111111111111111100000000000000000000000000000000"));
}

test "div multi-multi zero-limb trailing (with rem) and dividend zero-limb count > divisor zero-limb count" {
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest;

    var a = try Managed.init_set(testing.allocator, 0x8666666655555555888888877777777611111111111111110000000000000000);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, 0x8666666655555555444444443333333300000000000000000000000000000000);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.div_trunc(&q, &r, &a, &b);

    try testing.expect((try q.to(u128)) == 0x1);

    const rs = try r.to_string(testing.allocator, 16, .lower);
    defer testing.allocator.free(rs);
    try testing.expect(std.mem.eql(u8, rs, "444444434444444311111111111111110000000000000000"));
}

test "div multi-multi zero-limb trailing (with rem) and dividend zero-limb count < divisor zero-limb count" {
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest;

    var a = try Managed.init_set(testing.allocator, 0x86666666555555558888888777777776111111111111111100000000000000000000000000000000);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, 0x866666665555555544444444333333330000000000000000);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.div_trunc(&q, &r, &a, &b);

    const qs = try q.to_string(testing.allocator, 16, .lower);
    defer testing.allocator.free(qs);
    try testing.expect(std.mem.eql(u8, qs, "10000000000000000820820803105186f"));

    const rs = try r.to_string(testing.allocator, 16, .lower);
    defer testing.allocator.free(rs);
    try testing.expect(std.mem.eql(u8, rs, "4e11f2baa5896a321d463b543d0104e30000000000000000"));
}

test "div multi-multi fuzz case #1" {
    var a = try Managed.init(testing.allocator);
    defer a.deinit();
    var b = try Managed.init(testing.allocator);
    defer b.deinit();

    try a.set_string(16, "ffffffffffffffffffffffffffffc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
    try b.set_string(16, "3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0000000000000000000000000000000000001ffffffffffffffffffffffffffffffffffffffffffffffffffc000000000000000000000000000000007fffffffffff");

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.div_trunc(&q, &r, &a, &b);

    const qs = try q.to_string(testing.allocator, 16, .lower);
    defer testing.allocator.free(qs);
    try testing.expect(std.mem.eql(u8, qs, "3ffffffffffffffffffffffffffff0000000000000000000000000000000000001ffffffffffffffffffffffffffff7fffffffe000000000000000000000000000180000000000000000000003fffffbfffffffdfffffffffffffeffff800000100101000000100000000020003fffffdfbfffffe3ffffffffffffeffff7fffc00800a100000017ffe000002000400007efbfff7fe9f00000037ffff3fff7fffa004006100000009ffe00000190038200bf7d2ff7fefe80400060000f7d7f8fbf9401fe38e0403ffc0bdffffa51102c300d7be5ef9df4e5060007b0127ad3fa69f97d0f820b6605ff617ddf7f32ad7a05c0d03f2e7bc78a6000e087a8bbcdc59e07a5a079128a7861f553ddebed7e8e56701756f9ead39b48cd1b0831889ea6ec1fddf643d0565b075ff07e6caea4e2854ec9227fd635ed60a2f5eef2893052ffd54718fa08604acbf6a15e78a467c4a3c53c0278af06c4416573f925491b195e8fd79302cb1aaf7caf4ecfc9aec1254cc969786363ac729f914c6ddcc26738d6b0facd54eba026580aba2eb6482a088b0d224a8852420b91ec1"));

    const rs = try r.to_string(testing.allocator, 16, .lower);
    defer testing.allocator.free(rs);
    try testing.expect(std.mem.eql(u8, rs, "310d1d4c414426b4836c2635bad1df3a424e50cbdd167ffccb4dfff57d36b4aae0d6ca0910698220171a0f3373c1060a046c2812f0027e321f72979daa5e7973214170d49e885de0c0ecc167837d44502430674a82522e5df6a0759548052420b91ec1"));
}

test "div multi-multi fuzz case #2" {
    var a = try Managed.init(testing.allocator);
    defer a.deinit();
    var b = try Managed.init(testing.allocator);
    defer b.deinit();

    try a.set_string(16, "3ffffffffe00000000000000000000000000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffe000000000000000000000000000000000000000000000000000000000000001fffffffffffffffff800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffffffffffffffffffffc000000000000000000000000000000000000000000000000000000000000000");
    try b.set_string(16, "ffc0000000000000000000000000000000000000000000000000");

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.div_trunc(&q, &r, &a, &b);

    const qs = try q.to_string(testing.allocator, 16, .lower);
    defer testing.allocator.free(qs);
    try testing.expect(std.mem.eql(u8, qs, "40100400fe3f8fe3f8fe3f8fe3f8fe3f8fe4f93e4f93e4f93e4f93e4f93e4f93e4f93e4f93e4f93e4f93e4f93e4f91e4791e4791e4791e4791e4791e4791e4791e4791e4791e4791e4791e4791e4992649926499264991e4791e4791e4791e4791e4791e4791e4791e4791e4791e4791e4791e4791e4791e4791e4791e4791e4791e4791e4791e4791e4791e4791e4791e4792e4b92e4b92e4b92e4b92a4a92a4a92a4"));

    const rs = try r.to_string(testing.allocator, 16, .lower);
    defer testing.allocator.free(rs);
    try testing.expect(std.mem.eql(u8, rs, "a900000000000000000000000000000000000000000000000000"));
}

test "truncate single unsigned" {
    var a = try Managed.init_set(testing.allocator, max_int(u47));
    defer a.deinit();

    try a.truncate(&a, .unsigned, 17);

    try testing.expect((try a.to(u17)) == max_int(u17));
}

test "truncate single signed" {
    var a = try Managed.init_set(testing.allocator, 0x1_0000);
    defer a.deinit();

    try a.truncate(&a, .signed, 17);

    try testing.expect((try a.to(i17)) == min_int(i17));
}

test "truncate multi to single unsigned" {
    var a = try Managed.init_set(testing.allocator, (max_int(Limb) + 1) | 0x1234_5678_9ABC_DEF0);
    defer a.deinit();

    try a.truncate(&a, .unsigned, 27);

    try testing.expect((try a.to(u27)) == 0x2BC_DEF0);
}

test "truncate multi to single signed" {
    var a = try Managed.init_set(testing.allocator, max_int(Limb) << 10);
    defer a.deinit();

    try a.truncate(&a, .signed, @bitSizeOf(i11));

    try testing.expect((try a.to(i11)) == min_int(i11));
}

test "truncate multi to multi unsigned" {
    const bits = @typeInfo(SignedDoubleLimb).Int.bits;
    const Int = std.meta.Int(.unsigned, bits - 1);

    var a = try Managed.init_set(testing.allocator, max_int(SignedDoubleLimb));
    defer a.deinit();

    try a.truncate(&a, .unsigned, bits - 1);

    try testing.expect((try a.to(Int)) == max_int(Int));
}

test "truncate multi to multi signed" {
    var a = try Managed.init_set(testing.allocator, 3 << @bitSizeOf(Limb));
    defer a.deinit();

    try a.truncate(&a, .signed, @bitSizeOf(Limb) + 1);

    try testing.expect((try a.to(std.meta.Int(.signed, @bitSizeOf(Limb) + 1))) == -1 << @bitSizeOf(Limb));
}

test "truncate negative multi to single" {
    var a = try Managed.init_set(testing.allocator, -@as(SignedDoubleLimb, max_int(Limb) + 1));
    defer a.deinit();

    try a.truncate(&a, .signed, @bitSizeOf(i17));

    try testing.expect((try a.to(i17)) == 0);
}

test "truncate multi unsigned many" {
    var a = try Managed.init_set(testing.allocator, 1);
    defer a.deinit();
    try a.shift_left(&a, 1023);

    var b = try Managed.init(testing.allocator);
    defer b.deinit();
    try b.truncate(&a, .signed, @bitSizeOf(i1));

    try testing.expect((try b.to(i1)) == 0);
}

test "saturate single signed positive" {
    var a = try Managed.init_set(testing.allocator, 0xBBBB_BBBB);
    defer a.deinit();

    try a.saturate(&a, .signed, 17);

    try testing.expect((try a.to(i17)) == max_int(i17));
}

test "saturate single signed negative" {
    var a = try Managed.init_set(testing.allocator, -1_234_567);
    defer a.deinit();

    try a.saturate(&a, .signed, 17);

    try testing.expect((try a.to(i17)) == min_int(i17));
}

test "saturate single signed" {
    var a = try Managed.init_set(testing.allocator, max_int(i17) - 1);
    defer a.deinit();

    try a.saturate(&a, .signed, 17);

    try testing.expect((try a.to(i17)) == max_int(i17) - 1);
}

test "saturate multi signed" {
    var a = try Managed.init_set(testing.allocator, max_int(Limb) << @bitSizeOf(SignedDoubleLimb));
    defer a.deinit();

    try a.saturate(&a, .signed, @bitSizeOf(SignedDoubleLimb));

    try testing.expect((try a.to(SignedDoubleLimb)) == max_int(SignedDoubleLimb));
}

test "saturate single unsigned" {
    var a = try Managed.init_set(testing.allocator, 0xFEFE_FEFE);
    defer a.deinit();

    try a.saturate(&a, .unsigned, 23);

    try testing.expect((try a.to(u23)) == max_int(u23));
}

test "saturate multi unsigned zero" {
    var a = try Managed.init_set(testing.allocator, -1);
    defer a.deinit();

    try a.saturate(&a, .unsigned, @bitSizeOf(DoubleLimb));

    try testing.expect(a.eql_zero());
}

test "saturate multi unsigned" {
    var a = try Managed.init_set(testing.allocator, max_int(Limb) << @bitSizeOf(DoubleLimb));
    defer a.deinit();

    try a.saturate(&a, .unsigned, @bitSizeOf(DoubleLimb));

    try testing.expect((try a.to(DoubleLimb)) == max_int(DoubleLimb));
}

test "shift-right single" {
    var a = try Managed.init_set(testing.allocator, 0xffff0000);
    defer a.deinit();
    try a.shift_right(&a, 16);

    try testing.expect((try a.to(u32)) == 0xffff);
}

test "shift-right multi" {
    var a = try Managed.init_set(testing.allocator, 0xffff0000eeee1111dddd2222cccc3333);
    defer a.deinit();
    try a.shift_right(&a, 67);

    try testing.expect((try a.to(u64)) == 0x1fffe0001dddc222);

    try a.set(0xffff0000eeee1111dddd2222cccc3333);
    try a.shift_right(&a, 63);
    try a.shift_right(&a, 63);
    try a.shift_right(&a, 2);
    try testing.expect(a.eql_zero());

    try a.set(0xffff0000eeee1111dddd2222cccc3333000000000000000000000);
    try a.shift_right(&a, 84);
    const string = try a.to_string(
        testing.allocator,
        16,
        .lower,
    );
    defer testing.allocator.free(string);
    try std.testing.expect_equal_strings(
        string,
        "ffff0000eeee1111dddd2222cccc3333",
    );
}

test "shift-left single" {
    var a = try Managed.init_set(testing.allocator, 0xffff);
    defer a.deinit();
    try a.shift_left(&a, 16);

    try testing.expect((try a.to(u64)) == 0xffff0000);
}

test "shift-left multi" {
    var a = try Managed.init_set(testing.allocator, 0x1fffe0001dddc222);
    defer a.deinit();
    try a.shift_left(&a, 67);

    try testing.expect((try a.to(u128)) == 0xffff0000eeee11100000000000000000);
}

test "shift-right negative" {
    var a = try Managed.init(testing.allocator);
    defer a.deinit();

    var arg = try Managed.init_set(testing.allocator, -20);
    defer arg.deinit();
    try a.shift_right(&arg, 2);
    try testing.expect((try a.to(i32)) == -5); // -20 >> 2 == -5

    var arg2 = try Managed.init_set(testing.allocator, -5);
    defer arg2.deinit();
    try a.shift_right(&arg2, 10);
    try testing.expect((try a.to(i32)) == -1); // -5 >> 10 == -1

    var arg3 = try Managed.init_set(testing.allocator, -10);
    defer arg3.deinit();
    try a.shift_right(&arg3, 1232);
    try testing.expect((try a.to(i32)) == -1); // -10 >> 1232 == -1
}

test "sat shift-left simple unsigned" {
    var a = try Managed.init_set(testing.allocator, 0xffff);
    defer a.deinit();
    try a.shift_left_sat(&a, 16, .unsigned, 21);

    try testing.expect((try a.to(u64)) == 0x1fffff);
}

test "sat shift-left simple unsigned no sat" {
    var a = try Managed.init_set(testing.allocator, 1);
    defer a.deinit();
    try a.shift_left_sat(&a, 16, .unsigned, 21);

    try testing.expect((try a.to(u64)) == 0x10000);
}

test "sat shift-left multi unsigned" {
    var a = try Managed.init_set(testing.allocator, 16);
    defer a.deinit();
    try a.shift_left_sat(&a, @bitSizeOf(DoubleLimb) - 3, .unsigned, @bitSizeOf(DoubleLimb) - 1);

    try testing.expect((try a.to(DoubleLimb)) == max_int(DoubleLimb) >> 1);
}

test "sat shift-left unsigned shift > bitcount" {
    var a = try Managed.init_set(testing.allocator, 1);
    defer a.deinit();
    try a.shift_left_sat(&a, 10, .unsigned, 10);

    try testing.expect((try a.to(u10)) == max_int(u10));
}

test "sat shift-left unsigned zero" {
    var a = try Managed.init_set(testing.allocator, 0);
    defer a.deinit();
    try a.shift_left_sat(&a, 1, .unsigned, 0);

    try testing.expect((try a.to(u64)) == 0);
}

test "sat shift-left unsigned negative" {
    var a = try Managed.init_set(testing.allocator, -100);
    defer a.deinit();
    try a.shift_left_sat(&a, 0, .unsigned, 0);

    try testing.expect((try a.to(u64)) == 0);
}

test "sat shift-left signed simple negative" {
    var a = try Managed.init_set(testing.allocator, -100);
    defer a.deinit();
    try a.shift_left_sat(&a, 3, .signed, 10);

    try testing.expect((try a.to(i10)) == min_int(i10));
}

test "sat shift-left signed simple positive" {
    var a = try Managed.init_set(testing.allocator, 100);
    defer a.deinit();
    try a.shift_left_sat(&a, 3, .signed, 10);

    try testing.expect((try a.to(i10)) == max_int(i10));
}

test "sat shift-left signed multi positive" {
    if (builtin.zig_backend == .stage2_x86_64) return error.SkipZigTest;

    var x: SignedDoubleLimb = 1;
    _ = &x;

    const shift = @bitSizeOf(SignedDoubleLimb) - 1;

    var a = try Managed.init_set(testing.allocator, x);
    defer a.deinit();
    try a.shift_left_sat(&a, shift, .signed, @bitSizeOf(SignedDoubleLimb));

    try testing.expect((try a.to(SignedDoubleLimb)) == x <<| shift);
}

test "sat shift-left signed multi negative" {
    if (builtin.zig_backend == .stage2_x86_64) return error.SkipZigTest;

    var x: SignedDoubleLimb = -1;
    _ = &x;

    const shift = @bitSizeOf(SignedDoubleLimb) - 1;

    var a = try Managed.init_set(testing.allocator, x);
    defer a.deinit();
    try a.shift_left_sat(&a, shift, .signed, @bitSizeOf(SignedDoubleLimb));

    try testing.expect((try a.to(SignedDoubleLimb)) == x <<| shift);
}

test "bit_not_wrap unsigned simple" {
    var x: u10 = 123;
    _ = &x;

    var a = try Managed.init_set(testing.allocator, x);
    defer a.deinit();

    try a.bit_not_wrap(&a, .unsigned, 10);

    try testing.expect((try a.to(u10)) == ~x);
}

test "bit_not_wrap unsigned multi" {
    var a = try Managed.init_set(testing.allocator, 0);
    defer a.deinit();

    try a.bit_not_wrap(&a, .unsigned, @bitSizeOf(DoubleLimb));

    try testing.expect((try a.to(DoubleLimb)) == max_int(DoubleLimb));
}

test "bit_not_wrap signed simple" {
    var x: i11 = -456;
    _ = &x;

    var a = try Managed.init_set(testing.allocator, -456);
    defer a.deinit();

    try a.bit_not_wrap(&a, .signed, 11);

    try testing.expect((try a.to(i11)) == ~x);
}

test "bit_not_wrap signed multi" {
    var a = try Managed.init_set(testing.allocator, 0);
    defer a.deinit();

    try a.bit_not_wrap(&a, .signed, @bitSizeOf(SignedDoubleLimb));

    try testing.expect((try a.to(SignedDoubleLimb)) == -1);
}

test "bit_not_wrap more than two limbs" {
    // This test requires int sizes greater than 128 bits.
    if (builtin.zig_backend == .stage2_wasm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    // LLVM: unexpected runtime library name: __umodei4
    if (builtin.zig_backend == .stage2_llvm and comptime builtin.target.is_wasm()) return error.SkipZigTest; // TODO

    var a = try Managed.init_set(testing.allocator, max_int(Limb));
    defer a.deinit();

    var res = try Managed.init(testing.allocator);
    defer res.deinit();

    const bits = @bitSizeOf(Limb) * 4 + 2;

    try res.bit_not_wrap(&a, .unsigned, bits);
    const Unsigned = @Type(.{ .Int = .{ .signedness = .unsigned, .bits = bits } });
    try testing.expect_equal((try res.to(Unsigned)), ~@as(Unsigned, max_int(Limb)));

    try res.bit_not_wrap(&a, .signed, bits);
    const Signed = @Type(.{ .Int = .{ .signedness = .signed, .bits = bits } });
    try testing.expect_equal((try res.to(Signed)), ~@as(Signed, max_int(Limb)));
}

test "bitwise and simple" {
    var a = try Managed.init_set(testing.allocator, 0xffffffff11111111);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, 0xeeeeeeee22222222);
    defer b.deinit();

    try a.bit_and(&a, &b);

    try testing.expect((try a.to(u64)) == 0xeeeeeeee00000000);
}

test "bitwise and multi-limb" {
    var a = try Managed.init_set(testing.allocator, max_int(Limb) + 1);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, max_int(Limb));
    defer b.deinit();

    try a.bit_and(&a, &b);

    try testing.expect((try a.to(u128)) == 0);
}

test "bitwise and negative-positive simple" {
    var a = try Managed.init_set(testing.allocator, -0xffffffff11111111);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, 0xeeeeeeee22222222);
    defer b.deinit();

    try a.bit_and(&a, &b);

    try testing.expect((try a.to(u64)) == 0x22222222);
}

test "bitwise and negative-positive multi-limb" {
    var a = try Managed.init_set(testing.allocator, -max_int(Limb) - 1);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, max_int(Limb));
    defer b.deinit();

    try a.bit_and(&a, &b);

    try testing.expect(a.eql_zero());
}

test "bitwise and positive-negative simple" {
    var a = try Managed.init_set(testing.allocator, 0xffffffff11111111);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, -0xeeeeeeee22222222);
    defer b.deinit();

    try a.bit_and(&a, &b);

    try testing.expect((try a.to(u64)) == 0x1111111111111110);
}

test "bitwise and positive-negative multi-limb" {
    var a = try Managed.init_set(testing.allocator, max_int(Limb));
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, -max_int(Limb) - 1);
    defer b.deinit();

    try a.bit_and(&a, &b);

    try testing.expect(a.eql_zero());
}

test "bitwise and negative-negative simple" {
    var a = try Managed.init_set(testing.allocator, -0xffffffff11111111);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, -0xeeeeeeee22222222);
    defer b.deinit();

    try a.bit_and(&a, &b);

    try testing.expect((try a.to(i128)) == -0xffffffff33333332);
}

test "bitwise and negative-negative multi-limb" {
    var a = try Managed.init_set(testing.allocator, -max_int(Limb) - 1);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, -max_int(Limb) - 2);
    defer b.deinit();

    try a.bit_and(&a, &b);

    try testing.expect((try a.to(i128)) == -max_int(Limb) * 2 - 2);
}

test "bitwise and negative overflow" {
    var a = try Managed.init_set(testing.allocator, -max_int(Limb));
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, -2);
    defer b.deinit();

    try a.bit_and(&a, &b);

    try testing.expect((try a.to(SignedDoubleLimb)) == -max_int(Limb) - 1);
}

test "bitwise xor simple" {
    var a = try Managed.init_set(testing.allocator, 0xffffffff11111111);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, 0xeeeeeeee22222222);
    defer b.deinit();

    try a.bit_xor(&a, &b);

    try testing.expect((try a.to(u64)) == 0x1111111133333333);
}

test "bitwise xor multi-limb" {
    var x: DoubleLimb = max_int(Limb) + 1;
    var y: DoubleLimb = max_int(Limb);
    _ = .{ &x, &y };

    var a = try Managed.init_set(testing.allocator, x);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, y);
    defer b.deinit();

    try a.bit_xor(&a, &b);

    try testing.expect((try a.to(DoubleLimb)) == x ^ y);
}

test "bitwise xor single negative simple" {
    var a = try Managed.init_set(testing.allocator, 0x6b03e381328a3154);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, -0x45fd3acef9191fad);
    defer b.deinit();

    try a.bit_xor(&a, &b);

    try testing.expect((try a.to(i64)) == -0x2efed94fcb932ef9);
}

test "bitwise xor single negative multi-limb" {
    var a = try Managed.init_set(testing.allocator, -0x9849c6e7a10d66d0e4260d4846254c32);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, 0xf2194e7d1c855272a997fcde16f6d5a8);
    defer b.deinit();

    try a.bit_xor(&a, &b);

    try testing.expect((try a.to(i128)) == -0x6a50889abd8834a24db1f19650d3999a);
}

test "bitwise xor single negative overflow" {
    var a = try Managed.init_set(testing.allocator, max_int(Limb));
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, -1);
    defer b.deinit();

    try a.bit_xor(&a, &b);

    try testing.expect((try a.to(SignedDoubleLimb)) == -(max_int(Limb) + 1));
}

test "bitwise xor double negative simple" {
    var a = try Managed.init_set(testing.allocator, -0x8e48bd5f755ef1f3);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, -0x4dd4fa576f3046ac);
    defer b.deinit();

    try a.bit_xor(&a, &b);

    try testing.expect((try a.to(u64)) == 0xc39c47081a6eb759);
}

test "bitwise xor double negative multi-limb" {
    var a = try Managed.init_set(testing.allocator, -0x684e5da8f500ec8ca7204c33ccc51c9c);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, -0xcb07736a7b62289c78d967c3985eebeb);
    defer b.deinit();

    try a.bit_xor(&a, &b);

    try testing.expect((try a.to(u128)) == 0xa3492ec28e62c410dff92bf0549bf771);
}

test "bitwise or simple" {
    var a = try Managed.init_set(testing.allocator, 0xffffffff11111111);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, 0xeeeeeeee22222222);
    defer b.deinit();

    try a.bit_or(&a, &b);

    try testing.expect((try a.to(u64)) == 0xffffffff33333333);
}

test "bitwise or multi-limb" {
    var a = try Managed.init_set(testing.allocator, max_int(Limb) + 1);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, max_int(Limb));
    defer b.deinit();

    try a.bit_or(&a, &b);

    try testing.expect((try a.to(DoubleLimb)) == (max_int(Limb) + 1) + max_int(Limb));
}

test "bitwise or negative-positive simple" {
    var a = try Managed.init_set(testing.allocator, -0xffffffff11111111);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, 0xeeeeeeee22222222);
    defer b.deinit();

    try a.bit_or(&a, &b);

    try testing.expect((try a.to(i64)) == -0x1111111111111111);
}

test "bitwise or negative-positive multi-limb" {
    var a = try Managed.init_set(testing.allocator, -max_int(Limb) - 1);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, 1);
    defer b.deinit();

    try a.bit_or(&a, &b);

    try testing.expect((try a.to(SignedDoubleLimb)) == -max_int(Limb));
}

test "bitwise or positive-negative simple" {
    var a = try Managed.init_set(testing.allocator, 0xffffffff11111111);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, -0xeeeeeeee22222222);
    defer b.deinit();

    try a.bit_or(&a, &b);

    try testing.expect((try a.to(i64)) == -0x22222221);
}

test "bitwise or positive-negative multi-limb" {
    var a = try Managed.init_set(testing.allocator, max_int(Limb) + 1);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, -1);
    defer b.deinit();

    try a.bit_or(&a, &b);

    try testing.expect((try a.to(SignedDoubleLimb)) == -1);
}

test "bitwise or negative-negative simple" {
    var a = try Managed.init_set(testing.allocator, -0xffffffff11111111);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, -0xeeeeeeee22222222);
    defer b.deinit();

    try a.bit_or(&a, &b);

    try testing.expect((try a.to(i128)) == -0xeeeeeeee00000001);
}

test "bitwise or negative-negative multi-limb" {
    var a = try Managed.init_set(testing.allocator, -max_int(Limb) - 1);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, -max_int(Limb));
    defer b.deinit();

    try a.bit_or(&a, &b);

    try testing.expect((try a.to(SignedDoubleLimb)) == -max_int(Limb));
}

test "var args" {
    var a = try Managed.init_set(testing.allocator, 5);
    defer a.deinit();

    var b = try Managed.init_set(testing.allocator, 6);
    defer b.deinit();
    try a.add(&a, &b);
    try testing.expect((try a.to(u64)) == 11);

    var c = try Managed.init_set(testing.allocator, 11);
    defer c.deinit();
    try testing.expect(a.order(c) == .eq);

    var d = try Managed.init_set(testing.allocator, 14);
    defer d.deinit();
    try testing.expect(a.order(d) != .gt);
}

test "gcd non-one small" {
    var a = try Managed.init_set(testing.allocator, 17);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, 97);
    defer b.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();

    try r.gcd(&a, &b);

    try testing.expect((try r.to(u32)) == 1);
}

test "gcd non-one medium" {
    var a = try Managed.init_set(testing.allocator, 4864);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, 3458);
    defer b.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();

    try r.gcd(&a, &b);

    try testing.expect((try r.to(u32)) == 38);
}

test "gcd non-one large" {
    var a = try Managed.init_set(testing.allocator, 0xffffffffffffffff);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, 0xffffffffffffffff7777);
    defer b.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();

    try r.gcd(&a, &b);

    try testing.expect((try r.to(u32)) == 4369);
}

test "gcd large multi-limb result" {
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest;

    var a = try Managed.init_set(testing.allocator, 0x12345678123456781234567812345678123456781234567812345678);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, 0x12345671234567123456712345671234567123456712345671234567);
    defer b.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();

    try r.gcd(&a, &b);

    const answer = (try r.to(u256));
    try testing.expect(answer == 0xf000000ff00000fff0000ffff000fffff00ffffff1);
}

test "gcd one large" {
    var a = try Managed.init_set(testing.allocator, 1897056385327307);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, 2251799813685248);
    defer b.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();

    try r.gcd(&a, &b);

    try testing.expect((try r.to(u64)) == 1);
}

test "mutable to managed" {
    const allocator = testing.allocator;
    const limbs_buf = try allocator.alloc(Limb, 8);
    defer allocator.free(limbs_buf);

    var a = Mutable.init(limbs_buf, 0xdeadbeef);
    var a_managed = a.to_managed(allocator);

    try testing.expect(a.to_const().eql(a_managed.to_const()));
}

test "const to managed" {
    var a = try Managed.init_set(testing.allocator, 123423453456);
    defer a.deinit();

    var b = try a.to_const().to_managed(testing.allocator);
    defer b.deinit();

    try testing.expect(a.to_const().eql(b.to_const()));
}

test "pow" {
    {
        var a = try Managed.init_set(testing.allocator, -3);
        defer a.deinit();

        try a.pow(&a, 3);
        try testing.expect_equal(@as(i32, -27), try a.to(i32));

        try a.pow(&a, 4);
        try testing.expect_equal(@as(i32, 531441), try a.to(i32));
    }
    {
        var a = try Managed.init_set(testing.allocator, 10);
        defer a.deinit();

        var y = try Managed.init(testing.allocator);
        defer y.deinit();

        // y and a are not aliased
        try y.pow(&a, 123);
        // y and a are aliased
        try a.pow(&a, 123);

        try testing.expect(a.eql(y));

        const ys = try y.to_string(testing.allocator, 16, .lower);
        defer testing.allocator.free(ys);
        try testing.expect_equal_slices(
            u8,
            "183425a5f872f126e00a5ad62c839075cd6846c6fb0230887c7ad7a9dc530fcb" ++
                "4933f60e8000000000000000000000000000000",
            ys,
        );
    }
    // Special cases
    {
        var a = try Managed.init_set(testing.allocator, 0);
        defer a.deinit();

        try a.pow(&a, 100);
        try testing.expect_equal(@as(i32, 0), try a.to(i32));

        try a.set(1);
        try a.pow(&a, 0);
        try testing.expect_equal(@as(i32, 1), try a.to(i32));
        try a.pow(&a, 100);
        try testing.expect_equal(@as(i32, 1), try a.to(i32));
        try a.set(-1);
        try a.pow(&a, 15);
        try testing.expect_equal(@as(i32, -1), try a.to(i32));
        try a.pow(&a, 16);
        try testing.expect_equal(@as(i32, 1), try a.to(i32));
    }
}

test "sqrt" {
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    var a = try Managed.init(testing.allocator);
    defer a.deinit();

    // not aliased
    try r.set(0);
    try a.set(25);
    try r.sqrt(&a);
    try testing.expect_equal(@as(i32, 5), try r.to(i32));

    // aliased
    try a.set(25);
    try a.sqrt(&a);
    try testing.expect_equal(@as(i32, 5), try a.to(i32));

    // bottom
    try r.set(0);
    try a.set(24);
    try r.sqrt(&a);
    try testing.expect_equal(@as(i32, 4), try r.to(i32));

    // large number
    try r.set(0);
    try a.set(0x1_0000_0000_0000);
    try r.sqrt(&a);
    try testing.expect_equal(@as(i32, 0x100_0000), try r.to(i32));
}

test "regression test for 1 limb overflow with alias" {
    // Note these happen to be two consecutive Fibonacci sequence numbers, the
    // first two whose sum exceeds 2**64.
    var a = try Managed.init_set(testing.allocator, 7540113804746346429);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, 12200160415121876738);
    defer b.deinit();

    try a.ensure_add_capacity(a.to_const(), b.to_const());
    try a.add(&a, &b);

    try testing.expect(a.to_const().order_against_scalar(19740274219868223167) == .eq);
}

test "regression test for realloc with alias" {
    // Note these happen to be two consecutive Fibonacci sequence numbers, the
    // second of which is the first such number to exceed 2**192.
    var a = try Managed.init_set(testing.allocator, 5611500259351924431073312796924978741056961814867751431689);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, 9079598147510263717870894449029933369491131786514446266146);
    defer b.deinit();

    try a.ensure_add_capacity(a.to_const(), b.to_const());
    try a.add(&a, &b);

    try testing.expect(a.to_const().order_against_scalar(14691098406862188148944207245954912110548093601382197697835) == .eq);
}

test "big int popcount" {
    var a = try Managed.init(testing.allocator);
    defer a.deinit();

    try a.set(0);
    try pop_count_test(&a, 0, 0);
    try pop_count_test(&a, 567, 0);

    try a.set(1);
    try pop_count_test(&a, 1, 1);
    try pop_count_test(&a, 13, 1);
    try pop_count_test(&a, 432, 1);

    try a.set(255);
    try pop_count_test(&a, 8, 8);
    try a.set(-128);
    try pop_count_test(&a, 8, 1);

    try a.set(-2);
    try pop_count_test(&a, 16, 15);
    try pop_count_test(&a, 15, 14);

    try a.set(-2047);
    try pop_count_test(&a, 12, 2);
    try pop_count_test(&a, 24, 14);

    try a.set(max_int(u5000));
    try pop_count_test(&a, 5000, 5000);
    try a.set(min_int(i5000));
    try pop_count_test(&a, 5000, 1);

    // Check -1 at various bit counts that cross Limb size multiples.
    const limb_bits = @bitSizeOf(Limb);
    try a.set(-1);
    try pop_count_test(&a, 1, 1); // i1
    try pop_count_test(&a, 2, 2);
    try pop_count_test(&a, 16, 16);
    try pop_count_test(&a, 543, 543);
    try pop_count_test(&a, 544, 544);
    try pop_count_test(&a, limb_bits - 1, limb_bits - 1);
    try pop_count_test(&a, limb_bits, limb_bits);
    try pop_count_test(&a, limb_bits + 1, limb_bits + 1);
    try pop_count_test(&a, limb_bits * 2 - 1, limb_bits * 2 - 1);
    try pop_count_test(&a, limb_bits * 2, limb_bits * 2);
    try pop_count_test(&a, limb_bits * 2 + 1, limb_bits * 2 + 1);

    // Check very large numbers.
    try a.set_string(16, "ff00000100000100" ++ ("0000000000000000" ** 62));
    try pop_count_test(&a, 4032, 10);
    try pop_count_test(&a, 6000, 10);
    a.negate();
    try pop_count_test(&a, 4033, 48);
    try pop_count_test(&a, 4133, 148);

    // Check when most significant limb is full of 1s.
    const limb_size = @bitSizeOf(Limb);
    try a.set(max_int(Limb));
    try pop_count_test(&a, limb_size, limb_size);
    try pop_count_test(&a, limb_size + 1, limb_size);
    try pop_count_test(&a, limb_size * 10 + 2, limb_size);
    a.negate();
    try pop_count_test(&a, limb_size * 2 - 2, limb_size - 1);
    try pop_count_test(&a, limb_size * 2 - 1, limb_size);
    try pop_count_test(&a, limb_size * 2, limb_size + 1);
    try pop_count_test(&a, limb_size * 2 + 1, limb_size + 2);
    try pop_count_test(&a, limb_size * 2 + 2, limb_size + 3);
    try pop_count_test(&a, limb_size * 2 + 3, limb_size + 4);
    try pop_count_test(&a, limb_size * 2 + 4, limb_size + 5);
    try pop_count_test(&a, limb_size * 4 + 2, limb_size * 3 + 3);
}

fn pop_count_test(val: *const Managed, bit_count: usize, expected: usize) !void {
    var b = try Managed.init(testing.allocator);
    defer b.deinit();
    try b.pop_count(val, bit_count);

    try testing.expect_equal(std.math.Order.eq, b.to_const().order_against_scalar(expected));
    try testing.expect_equal(expected, val.to_const().pop_count(bit_count));
}

test "big int conversion read/write twos complement" {
    var a = try Managed.init_set(testing.allocator, (1 << 493) - 1);
    defer a.deinit();
    var b = try Managed.init_set(testing.allocator, (1 << 493) - 1);
    defer b.deinit();
    var m = b.to_mutable();

    var buffer1 = try testing.allocator.alloc(u8, 64);
    defer testing.allocator.free(buffer1);

    const endians = [_]std.builtin.Endian{ .little, .big };
    const abi_size = 64;

    for (endians) |endian| {
        // Writing to buffer and back should not change anything
        a.to_const().write_twos_complement(buffer1[0..abi_size], endian);
        m.read_twos_complement(buffer1[0..abi_size], 493, endian, .unsigned);
        try testing.expect(m.to_const().order(a.to_const()) == .eq);

        // Equivalent to @bit_cast(i493, @as(u493, intMax(u493))
        a.to_const().write_twos_complement(buffer1[0..abi_size], endian);
        m.read_twos_complement(buffer1[0..abi_size], 493, endian, .signed);
        try testing.expect(m.to_const().order_against_scalar(-1) == .eq);
    }
}

test "big int conversion read twos complement with padding" {
    var a = try Managed.init_set(testing.allocator, 0x01_02030405_06070809_0a0b0c0d);
    defer a.deinit();

    var buffer1 = try testing.allocator.alloc(u8, 16);
    defer testing.allocator.free(buffer1);
    @memset(buffer1, 0xaa);

    // write_twos_complement:
    // (1) should not write beyond buffer[0..abi_size]
    // (2) should correctly order bytes based on the provided endianness
    // (3) should sign-extend any bits from bit_count to 8 * abi_size

    var bit_count: usize = 12 * 8 + 1;
    a.to_const().write_twos_complement(buffer1[0..13], .little);
    try testing.expect(std.mem.eql(u8, buffer1, &[_]u8{ 0xd, 0xc, 0xb, 0xa, 0x9, 0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0xaa, 0xaa, 0xaa }));
    a.to_const().write_twos_complement(buffer1[0..13], .big);
    try testing.expect(std.mem.eql(u8, buffer1, &[_]u8{ 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xaa, 0xaa, 0xaa }));
    a.to_const().write_twos_complement(buffer1[0..16], .little);
    try testing.expect(std.mem.eql(u8, buffer1, &[_]u8{ 0xd, 0xc, 0xb, 0xa, 0x9, 0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0, 0x0, 0x0 }));
    a.to_const().write_twos_complement(buffer1[0..16], .big);
    try testing.expect(std.mem.eql(u8, buffer1, &[_]u8{ 0x0, 0x0, 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd }));

    @memset(buffer1, 0xaa);
    try a.set(-0x01_02030405_06070809_0a0b0c0d);
    bit_count = 12 * 8 + 2;

    a.to_const().write_twos_complement(buffer1[0..13], .little);
    try testing.expect(std.mem.eql(u8, buffer1, &[_]u8{ 0xf3, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xaa, 0xaa, 0xaa }));
    a.to_const().write_twos_complement(buffer1[0..13], .big);
    try testing.expect(std.mem.eql(u8, buffer1, &[_]u8{ 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf3, 0xaa, 0xaa, 0xaa }));
    a.to_const().write_twos_complement(buffer1[0..16], .little);
    try testing.expect(std.mem.eql(u8, buffer1, &[_]u8{ 0xf3, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff, 0xff, 0xff }));
    a.to_const().write_twos_complement(buffer1[0..16], .big);
    try testing.expect(std.mem.eql(u8, buffer1, &[_]u8{ 0xff, 0xff, 0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf3 }));
}

test "big int write twos complement +/- zero" {
    var a = try Managed.init_set(testing.allocator, 0x0);
    defer a.deinit();
    var m = a.to_mutable();

    var buffer1 = try testing.allocator.alloc(u8, 16);
    defer testing.allocator.free(buffer1);
    @memset(buffer1, 0xaa);

    // Test zero

    m.to_const().write_twos_complement(buffer1[0..13], .little);
    try testing.expect(std.mem.eql(u8, buffer1, &(([_]u8{0} ** 13) ++ ([_]u8{0xaa} ** 3))));
    m.to_const().write_twos_complement(buffer1[0..13], .big);
    try testing.expect(std.mem.eql(u8, buffer1, &(([_]u8{0} ** 13) ++ ([_]u8{0xaa} ** 3))));
    m.to_const().write_twos_complement(buffer1[0..16], .little);
    try testing.expect(std.mem.eql(u8, buffer1, &(([_]u8{0} ** 16))));
    m.to_const().write_twos_complement(buffer1[0..16], .big);
    try testing.expect(std.mem.eql(u8, buffer1, &(([_]u8{0} ** 16))));

    @memset(buffer1, 0xaa);
    m.positive = false;

    // Test negative zero

    m.to_const().write_twos_complement(buffer1[0..13], .little);
    try testing.expect(std.mem.eql(u8, buffer1, &(([_]u8{0} ** 13) ++ ([_]u8{0xaa} ** 3))));
    m.to_const().write_twos_complement(buffer1[0..13], .big);
    try testing.expect(std.mem.eql(u8, buffer1, &(([_]u8{0} ** 13) ++ ([_]u8{0xaa} ** 3))));
    m.to_const().write_twos_complement(buffer1[0..16], .little);
    try testing.expect(std.mem.eql(u8, buffer1, &(([_]u8{0} ** 16))));
    m.to_const().write_twos_complement(buffer1[0..16], .big);
    try testing.expect(std.mem.eql(u8, buffer1, &(([_]u8{0} ** 16))));
}

test "big int conversion write twos complement with padding" {
    var a = try Managed.init_set(testing.allocator, 0x01_ffffffff_ffffffff_ffffffff);
    defer a.deinit();

    var m = a.to_mutable();

    // read_twos_complement:
    // (1) should not read beyond buffer[0..abi_size]
    // (2) should correctly interpret bytes based on the provided endianness
    // (3) should ignore any bits from bit_count to 8 * abi_size

    var bit_count: usize = 12 * 8 + 1;
    var buffer: []const u8 = undefined;

    // Test 0x01_02030405_06070809_0a0b0c0d

    buffer = &[_]u8{ 0xd, 0xc, 0xb, 0xa, 0x9, 0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0xb };
    m.read_twos_complement(buffer[0..13], bit_count, .little, .unsigned);
    try testing.expect(m.to_const().order_against_scalar(0x01_02030405_06070809_0a0b0c0d) == .eq);

    buffer = &[_]u8{ 0xb, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd };
    m.read_twos_complement(buffer[0..13], bit_count, .big, .unsigned);
    try testing.expect(m.to_const().order_against_scalar(0x01_02030405_06070809_0a0b0c0d) == .eq);

    buffer = &[_]u8{ 0xd, 0xc, 0xb, 0xa, 0x9, 0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0xab, 0xaa, 0xaa, 0xaa };
    m.read_twos_complement(buffer[0..16], bit_count, .little, .unsigned);
    try testing.expect(m.to_const().order_against_scalar(0x01_02030405_06070809_0a0b0c0d) == .eq);

    buffer = &[_]u8{ 0xaa, 0xaa, 0xaa, 0xab, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd };
    m.read_twos_complement(buffer[0..16], bit_count, .big, .unsigned);
    try testing.expect(m.to_const().order_against_scalar(0x01_02030405_06070809_0a0b0c0d) == .eq);

    bit_count = @size_of(Limb) * 8;

    // Test 0x0a0a0a0a_02030405_06070809_0a0b0c0d

    buffer = &[_]u8{ 0xd, 0xc, 0xb, 0xa, 0x9, 0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0xaa };
    m.read_twos_complement(buffer[0..13], bit_count, .little, .unsigned);
    try testing.expect(m.to_const().order_against_scalar(@as(Limb, @truncate(0xaa_02030405_06070809_0a0b0c0d))) == .eq);

    buffer = &[_]u8{ 0xaa, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd };
    m.read_twos_complement(buffer[0..13], bit_count, .big, .unsigned);
    try testing.expect(m.to_const().order_against_scalar(@as(Limb, @truncate(0xaa_02030405_06070809_0a0b0c0d))) == .eq);

    buffer = &[_]u8{ 0xd, 0xc, 0xb, 0xa, 0x9, 0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0xaa, 0xaa, 0xaa, 0xaa };
    m.read_twos_complement(buffer[0..16], bit_count, .little, .unsigned);
    try testing.expect(m.to_const().order_against_scalar(@as(Limb, @truncate(0xaaaaaaaa_02030405_06070809_0a0b0c0d))) == .eq);

    buffer = &[_]u8{ 0xaa, 0xaa, 0xaa, 0xaa, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd };
    m.read_twos_complement(buffer[0..16], bit_count, .big, .unsigned);
    try testing.expect(m.to_const().order_against_scalar(@as(Limb, @truncate(0xaaaaaaaa_02030405_06070809_0a0b0c0d))) == .eq);

    bit_count = 12 * 8 + 2;

    // Test -0x01_02030405_06070809_0a0b0c0d

    buffer = &[_]u8{ 0xf3, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0x02 };
    m.read_twos_complement(buffer[0..13], bit_count, .little, .signed);
    try testing.expect(m.to_const().order_against_scalar(-0x01_02030405_06070809_0a0b0c0d) == .eq);

    buffer = &[_]u8{ 0x02, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf3 };
    m.read_twos_complement(buffer[0..13], bit_count, .big, .signed);
    try testing.expect(m.to_const().order_against_scalar(-0x01_02030405_06070809_0a0b0c0d) == .eq);

    buffer = &[_]u8{ 0xf3, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0x02, 0xaa, 0xaa, 0xaa };
    m.read_twos_complement(buffer[0..16], bit_count, .little, .signed);
    try testing.expect(m.to_const().order_against_scalar(-0x01_02030405_06070809_0a0b0c0d) == .eq);

    buffer = &[_]u8{ 0xaa, 0xaa, 0xaa, 0x02, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf3 };
    m.read_twos_complement(buffer[0..16], bit_count, .big, .signed);
    try testing.expect(m.to_const().order_against_scalar(-0x01_02030405_06070809_0a0b0c0d) == .eq);

    // Test 0

    buffer = &([_]u8{0} ** 16);
    m.read_twos_complement(buffer[0..13], bit_count, .little, .unsigned);
    try testing.expect(m.to_const().order_against_scalar(0x0) == .eq);
    m.read_twos_complement(buffer[0..13], bit_count, .big, .unsigned);
    try testing.expect(m.to_const().order_against_scalar(0x0) == .eq);
    m.read_twos_complement(buffer[0..16], bit_count, .little, .unsigned);
    try testing.expect(m.to_const().order_against_scalar(0x0) == .eq);
    m.read_twos_complement(buffer[0..16], bit_count, .big, .unsigned);
    try testing.expect(m.to_const().order_against_scalar(0x0) == .eq);

    bit_count = 0;
    buffer = &([_]u8{0xaa} ** 16);
    m.read_twos_complement(buffer[0..13], bit_count, .little, .unsigned);
    try testing.expect(m.to_const().order_against_scalar(0x0) == .eq);
    m.read_twos_complement(buffer[0..13], bit_count, .big, .unsigned);
    try testing.expect(m.to_const().order_against_scalar(0x0) == .eq);
    m.read_twos_complement(buffer[0..16], bit_count, .little, .unsigned);
    try testing.expect(m.to_const().order_against_scalar(0x0) == .eq);
    m.read_twos_complement(buffer[0..16], bit_count, .big, .unsigned);
    try testing.expect(m.to_const().order_against_scalar(0x0) == .eq);
}

test "big int conversion write twos complement zero" {
    var a = try Managed.init_set(testing.allocator, 0x01_ffffffff_ffffffff_ffffffff);
    defer a.deinit();

    var m = a.to_mutable();

    // read_twos_complement:
    // (1) should not read beyond buffer[0..abi_size]
    // (2) should correctly interpret bytes based on the provided endianness
    // (3) should ignore any bits from bit_count to 8 * abi_size

    const bit_count: usize = 12 * 8 + 1;
    var buffer: []const u8 = undefined;

    buffer = &([_]u8{0} ** 13);
    m.read_twos_complement(buffer[0..13], bit_count, .little, .unsigned);
    try testing.expect(m.to_const().order_against_scalar(0x0) == .eq);
    m.read_twos_complement(buffer[0..13], bit_count, .big, .unsigned);
    try testing.expect(m.to_const().order_against_scalar(0x0) == .eq);

    buffer = &([_]u8{0} ** 16);
    m.read_twos_complement(buffer[0..16], bit_count, .little, .unsigned);
    try testing.expect(m.to_const().order_against_scalar(0x0) == .eq);
    m.read_twos_complement(buffer[0..16], bit_count, .big, .unsigned);
    try testing.expect(m.to_const().order_against_scalar(0x0) == .eq);
}

fn bit_reverse_test(comptime T: type, comptime input: comptime_int, comptime expected_output: comptime_int) !void {
    const bit_count = @typeInfo(T).Int.bits;
    const signedness = @typeInfo(T).Int.signedness;

    var a = try Managed.init_set(testing.allocator, input);
    defer a.deinit();

    try a.ensure_capacity(calc_twos_comp_limb_count(bit_count));
    var m = a.to_mutable();
    m.bit_reverse(a.to_const(), signedness, bit_count);
    try testing.expect(m.to_const().order_against_scalar(expected_output) == .eq);
}

test "big int bit reverse" {
    var a = try Managed.init_set(testing.allocator, 0x01_ffffffff_ffffffff_ffffffff);
    defer a.deinit();

    try bit_reverse_test(u0, 0, 0);
    try bit_reverse_test(u5, 0x12, 0x09);
    try bit_reverse_test(u8, 0x12, 0x48);
    try bit_reverse_test(u16, 0x1234, 0x2c48);
    try bit_reverse_test(u24, 0x123456, 0x6a2c48);
    try bit_reverse_test(u32, 0x12345678, 0x1e6a2c48);
    try bit_reverse_test(u40, 0x123456789a, 0x591e6a2c48);
    try bit_reverse_test(u48, 0x123456789abc, 0x3d591e6a2c48);
    try bit_reverse_test(u56, 0x123456789abcde, 0x7b3d591e6a2c48);
    try bit_reverse_test(u64, 0x123456789abcdef1, 0x8f7b3d591e6a2c48);
    try bit_reverse_test(u95, 0x123456789abcdef111213141, 0x4146424447bd9eac8f351624);
    try bit_reverse_test(u96, 0x123456789abcdef111213141, 0x828c84888f7b3d591e6a2c48);
    try bit_reverse_test(u128, 0x123456789abcdef11121314151617181, 0x818e868a828c84888f7b3d591e6a2c48);

    try bit_reverse_test(i8, @as(i8, @bit_cast(@as(u8, 0x92))), @as(i8, @bit_cast(@as(u8, 0x49))));
    try bit_reverse_test(i16, @as(i16, @bit_cast(@as(u16, 0x1234))), @as(i16, @bit_cast(@as(u16, 0x2c48))));
    try bit_reverse_test(i24, @as(i24, @bit_cast(@as(u24, 0x123456))), @as(i24, @bit_cast(@as(u24, 0x6a2c48))));
    try bit_reverse_test(i24, @as(i24, @bit_cast(@as(u24, 0x12345f))), @as(i24, @bit_cast(@as(u24, 0xfa2c48))));
    try bit_reverse_test(i24, @as(i24, @bit_cast(@as(u24, 0xf23456))), @as(i24, @bit_cast(@as(u24, 0x6a2c4f))));
    try bit_reverse_test(i32, @as(i32, @bit_cast(@as(u32, 0x12345678))), @as(i32, @bit_cast(@as(u32, 0x1e6a2c48))));
    try bit_reverse_test(i32, @as(i32, @bit_cast(@as(u32, 0xf2345678))), @as(i32, @bit_cast(@as(u32, 0x1e6a2c4f))));
    try bit_reverse_test(i32, @as(i32, @bit_cast(@as(u32, 0x1234567f))), @as(i32, @bit_cast(@as(u32, 0xfe6a2c48))));
    try bit_reverse_test(i40, @as(i40, @bit_cast(@as(u40, 0x123456789a))), @as(i40, @bit_cast(@as(u40, 0x591e6a2c48))));
    try bit_reverse_test(i48, @as(i48, @bit_cast(@as(u48, 0x123456789abc))), @as(i48, @bit_cast(@as(u48, 0x3d591e6a2c48))));
    try bit_reverse_test(i56, @as(i56, @bit_cast(@as(u56, 0x123456789abcde))), @as(i56, @bit_cast(@as(u56, 0x7b3d591e6a2c48))));
    try bit_reverse_test(i64, @as(i64, @bit_cast(@as(u64, 0x123456789abcdef1))), @as(i64, @bit_cast(@as(u64, 0x8f7b3d591e6a2c48))));
    try bit_reverse_test(i96, @as(i96, @bit_cast(@as(u96, 0x123456789abcdef111213141))), @as(i96, @bit_cast(@as(u96, 0x828c84888f7b3d591e6a2c48))));
    try bit_reverse_test(i128, @as(i128, @bit_cast(@as(u128, 0x123456789abcdef11121314151617181))), @as(i128, @bit_cast(@as(u128, 0x818e868a828c84888f7b3d591e6a2c48))));
}

fn byte_swap_test(comptime T: type, comptime input: comptime_int, comptime expected_output: comptime_int) !void {
    const byte_count = @typeInfo(T).Int.bits / 8;
    const signedness = @typeInfo(T).Int.signedness;

    var a = try Managed.init_set(testing.allocator, input);
    defer a.deinit();

    try a.ensure_capacity(calc_twos_comp_limb_count(8 * byte_count));
    var m = a.to_mutable();
    m.byte_swap(a.to_const(), signedness, byte_count);
    try testing.expect(m.to_const().order_against_scalar(expected_output) == .eq);
}

test "big int byte swap" {
    var a = try Managed.init_set(testing.allocator, 0x01_ffffffff_ffffffff_ffffffff);
    defer a.deinit();

    @setEvalBranchQuota(10_000);

    try byte_swap_test(u0, 0, 0);
    try byte_swap_test(u8, 0x12, 0x12);
    try byte_swap_test(u16, 0x1234, 0x3412);
    try byte_swap_test(u24, 0x123456, 0x563412);
    try byte_swap_test(u32, 0x12345678, 0x78563412);
    try byte_swap_test(u40, 0x123456789a, 0x9a78563412);
    try byte_swap_test(u48, 0x123456789abc, 0xbc9a78563412);
    try byte_swap_test(u56, 0x123456789abcde, 0xdebc9a78563412);
    try byte_swap_test(u64, 0x123456789abcdef1, 0xf1debc9a78563412);
    try byte_swap_test(u88, 0x123456789abcdef1112131, 0x312111f1debc9a78563412);
    try byte_swap_test(u96, 0x123456789abcdef111213141, 0x41312111f1debc9a78563412);
    try byte_swap_test(u128, 0x123456789abcdef11121314151617181, 0x8171615141312111f1debc9a78563412);

    try byte_swap_test(i8, -50, -50);
    try byte_swap_test(i16, @as(i16, @bit_cast(@as(u16, 0x1234))), @as(i16, @bit_cast(@as(u16, 0x3412))));
    try byte_swap_test(i24, @as(i24, @bit_cast(@as(u24, 0x123456))), @as(i24, @bit_cast(@as(u24, 0x563412))));
    try byte_swap_test(i32, @as(i32, @bit_cast(@as(u32, 0x12345678))), @as(i32, @bit_cast(@as(u32, 0x78563412))));
    try byte_swap_test(i40, @as(i40, @bit_cast(@as(u40, 0x123456789a))), @as(i40, @bit_cast(@as(u40, 0x9a78563412))));
    try byte_swap_test(i48, @as(i48, @bit_cast(@as(u48, 0x123456789abc))), @as(i48, @bit_cast(@as(u48, 0xbc9a78563412))));
    try byte_swap_test(i56, @as(i56, @bit_cast(@as(u56, 0x123456789abcde))), @as(i56, @bit_cast(@as(u56, 0xdebc9a78563412))));
    try byte_swap_test(i64, @as(i64, @bit_cast(@as(u64, 0x123456789abcdef1))), @as(i64, @bit_cast(@as(u64, 0xf1debc9a78563412))));
    try byte_swap_test(i88, @as(i88, @bit_cast(@as(u88, 0x123456789abcdef1112131))), @as(i88, @bit_cast(@as(u88, 0x312111f1debc9a78563412))));
    try byte_swap_test(i96, @as(i96, @bit_cast(@as(u96, 0x123456789abcdef111213141))), @as(i96, @bit_cast(@as(u96, 0x41312111f1debc9a78563412))));
    try byte_swap_test(i128, @as(i128, @bit_cast(@as(u128, 0x123456789abcdef11121314151617181))), @as(i128, @bit_cast(@as(u128, 0x8171615141312111f1debc9a78563412))));

    try byte_swap_test(u512, 0x80, 1 << 511);
    try byte_swap_test(i512, 0x80, min_int(i512));
    try byte_swap_test(i512, 0x40, 1 << 510);
    try byte_swap_test(i512, -0x100, (1 << 504) - 1);
    try byte_swap_test(i400, -0x100, (1 << 392) - 1);
    try byte_swap_test(i400, -0x2, -(1 << 392) - 1);
    try byte_swap_test(i24, @as(i24, @bit_cast(@as(u24, 0xf23456))), 0x5634f2);
    try byte_swap_test(i24, 0x1234f6, @as(i24, @bit_cast(@as(u24, 0xf63412))));
    try byte_swap_test(i32, @as(i32, @bit_cast(@as(u32, 0xf2345678))), 0x785634f2);
    try byte_swap_test(i32, 0x123456f8, @as(i32, @bit_cast(@as(u32, 0xf8563412))));
    try byte_swap_test(i48, 0x123456789abc, @as(i48, @bit_cast(@as(u48, 0xbc9a78563412))));
}

test "mul multi-multi alias r with a and b" {
    var a = try Managed.init_set(testing.allocator, 2 * max_int(Limb));
    defer a.deinit();

    try a.mul(&a, &a);

    var want = try Managed.init_set(testing.allocator, 4 * max_int(Limb) * max_int(Limb));
    defer want.deinit();

    try testing.expect(a.eql(want));

    if (@typeInfo(Limb).Int.bits == 64) {
        try testing.expect_equal(@as(usize, 5), a.limbs.len);
    }
}

test "sqr multi alias r with a" {
    var a = try Managed.init_set(testing.allocator, 2 * max_int(Limb));
    defer a.deinit();

    try a.sqr(&a);

    var want = try Managed.init_set(testing.allocator, 4 * max_int(Limb) * max_int(Limb));
    defer want.deinit();

    try testing.expect(a.eql(want));

    if (@typeInfo(Limb).Int.bits == 64) {
        try testing.expect_equal(@as(usize, 5), a.limbs.len);
    }
}

test "eql zeroes #17296" {
    var zero = try Managed.init(testing.allocator);
    defer zero.deinit();
    try zero.set_string(10, "0");
    try std.testing.expect(zero.eql(zero));

    {
        var sum = try Managed.init(testing.allocator);
        defer sum.deinit();
        try sum.add(&zero, &zero);
        try std.testing.expect(zero.eql(sum));
    }

    {
        var diff = try Managed.init(testing.allocator);
        defer diff.deinit();
        try diff.sub(&zero, &zero);
        try std.testing.expect(zero.eql(diff));
    }
}

test "Const.order 0 == -0" {
    const a = std.math.big.int.Const{
        .limbs = &.{0},
        .positive = true,
    };
    const b = std.math.big.int.Const{
        .limbs = &.{0},
        .positive = false,
    };
    try std.testing.expect_equal(std.math.Order.eq, a.order(b));
}

test "Managed sqrt(0) = 0" {
    const allocator = testing.allocator;
    var a = try Managed.init_set(allocator, 1);
    defer a.deinit();

    var res = try Managed.init_set(allocator, 1);
    defer res.deinit();

    try a.set_string(10, "0");

    try res.sqrt(&a);
    try testing.expect_equal(@as(i32, 0), try res.to(i32));
}

test "Managed sqrt(-1) = error" {
    const allocator = testing.allocator;
    var a = try Managed.init_set(allocator, 1);
    defer a.deinit();

    var res = try Managed.init_set(allocator, 1);
    defer res.deinit();

    try a.set_string(10, "-1");

    try testing.expect_error(error.SqrtOfNegativeNumber, res.sqrt(&a));
}

test "Managed sqrt(n) succeed with res.bit_count_abs() >= usize bits" {
    const allocator = testing.allocator;
    var a = try Managed.init_set(allocator, 1);
    defer a.deinit();

    var res = try Managed.init_set(allocator, 1);
    defer res.deinit();

    // a.bit_count_abs() = 127 so the first attempt has 64 bits >= usize bits
    try a.set_string(10, "136036462105870278006290938611834481486");
    try res.sqrt(&a);

    var expected = try Managed.init_set(allocator, 1);
    defer expected.deinit();
    try expected.set_string(10, "11663466984815033033");
    try std.testing.expect_equal(std.math.Order.eq, expected.order(res));
}

test "(BigInt) positive" {
    var a = try Managed.init_set(testing.allocator, 2);
    defer a.deinit();

    var b = try Managed.init(testing.allocator);
    defer b.deinit();

    var c = try Managed.init_set(testing.allocator, 1);
    defer c.deinit();

    // a = pow(2, 64 * @size_of(usize) * 8), b = a - 1
    try a.pow(&a, 64 * @size_of(Limb) * 8);
    try b.sub(&a, &c);

    const a_fmt = try std.fmt.alloc_print_z(testing.allocator, "{d}", .{a});
    defer testing.allocator.free(a_fmt);

    const b_fmt = try std.fmt.alloc_print_z(testing.allocator, "{d}", .{b});
    defer testing.allocator.free(b_fmt);

    try testing.expect(mem.eql(u8, a_fmt, "(BigInt)"));
    try testing.expect(!mem.eql(u8, b_fmt, "(BigInt)"));
}

test "(BigInt) negative" {
    var a = try Managed.init_set(testing.allocator, 2);
    defer a.deinit();

    var b = try Managed.init(testing.allocator);
    defer b.deinit();

    var c = try Managed.init_set(testing.allocator, 1);
    defer c.deinit();

    // a = -pow(2, 64 * @size_of(usize) * 8), b = a + 1
    try a.pow(&a, 64 * @size_of(Limb) * 8);
    a.negate();
    try b.add(&a, &c);

    const a_fmt = try std.fmt.alloc_print_z(testing.allocator, "{d}", .{a});
    defer testing.allocator.free(a_fmt);

    const b_fmt = try std.fmt.alloc_print_z(testing.allocator, "{d}", .{b});
    defer testing.allocator.free(b_fmt);

    try testing.expect(mem.eql(u8, a_fmt, "(BigInt)"));
    try testing.expect(!mem.eql(u8, b_fmt, "(BigInt)"));
}
