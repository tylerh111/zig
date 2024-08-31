const std = @import("../../std.zig");
const builtin = @import("builtin");
const debug = std.debug;
const math = std.math;
const mem = std.mem;
const testing = std.testing;
const Allocator = mem.Allocator;

const Limb = std.math.big.Limb;
const DoubleLimb = std.math.big.DoubleLimb;
const Int = std.math.big.int.Managed;
const IntConst = std.math.big.int.Const;

/// An arbitrary-precision rational number.
///
/// Memory is allocated as needed for operations to ensure full precision is kept. The precision
/// of a Rational is only bounded by memory.
///
/// Rational's are always normalized. That is, for a Rational r = p/q where p and q are integers,
/// gcd(p, q) = 1 always.
///
/// TODO rework this to store its own allocator and use a non-managed big int, to avoid double
/// allocator storage.
pub const Rational = struct {
    /// Numerator. Determines the sign of the Rational.
    p: Int,

    /// Denominator. Sign is ignored.
    q: Int,

    /// Create a new Rational. A small amount of memory will be allocated on initialization.
    /// This will be 2 * Int.default_capacity.
    pub fn init(a: Allocator) !Rational {
        var p = try Int.init(a);
        errdefer p.deinit();
        return Rational{
            .p = p,
            .q = try Int.init_set(a, 1),
        };
    }

    /// Frees all memory associated with a Rational.
    pub fn deinit(self: *Rational) void {
        self.p.deinit();
        self.q.deinit();
    }

    /// Set a Rational from a primitive integer type.
    pub fn set_int(self: *Rational, a: anytype) !void {
        try self.p.set(a);
        try self.q.set(1);
    }

    /// Set a Rational from a string of the form `A/B` where A and B are base-10 integers.
    pub fn set_float_string(self: *Rational, str: []const u8) !void {
        // TODO: Accept a/b fractions and exponent form
        if (str.len == 0) {
            return error.InvalidFloatString;
        }

        const State = enum {
            Integer,
            Fractional,
        };

        var state = State.Integer;
        var point: ?usize = null;

        var start: usize = 0;
        if (str[0] == '-') {
            start += 1;
        }

        for (str, 0..) |c, i| {
            switch (state) {
                State.Integer => {
                    switch (c) {
                        '.' => {
                            state = State.Fractional;
                            point = i;
                        },
                        '0'...'9' => {
                            // okay
                        },
                        else => {
                            return error.InvalidFloatString;
                        },
                    }
                },
                State.Fractional => {
                    switch (c) {
                        '0'...'9' => {
                            // okay
                        },
                        else => {
                            return error.InvalidFloatString;
                        },
                    }
                },
            }
        }

        // TODO: batch the multiplies by 10
        if (point) |i| {
            try self.p.set_string(10, str[0..i]);

            const base = IntConst{ .limbs = &[_]Limb{10}, .positive = true };
            var local_buf: [@size_of(Limb) * Int.default_capacity]u8 align(@alignOf(Limb)) = undefined;
            var fba = std.heap.FixedBufferAllocator.init(&local_buf);
            const base_managed = try base.to_managed(fba.allocator());

            var j: usize = start;
            while (j < str.len - i - 1) : (j += 1) {
                try self.p.ensure_mul_capacity(self.p.to_const(), base);
                try self.p.mul(&self.p, &base_managed);
            }

            try self.q.set_string(10, str[i + 1 ..]);
            try self.p.add(&self.p, &self.q);

            try self.q.set(1);
            var k: usize = i + 1;
            while (k < str.len) : (k += 1) {
                try self.q.mul(&self.q, &base_managed);
            }

            try self.reduce();
        } else {
            try self.p.set_string(10, str[0..]);
            try self.q.set(1);
        }
    }

    /// Set a Rational from a floating-point value. The rational will have enough precision to
    /// completely represent the provided float.
    pub fn set_float(self: *Rational, comptime T: type, f: T) !void {
        // Translated from golang.go/src/math/big/rat.go.
        debug.assert(@typeInfo(T) == .Float);

        const UnsignedInt = std.meta.Int(.unsigned, @typeInfo(T).Float.bits);
        const f_bits = @as(UnsignedInt, @bit_cast(f));

        const exponent_bits = math.float_exponent_bits(T);
        const exponent_bias = (1 << (exponent_bits - 1)) - 1;
        const mantissa_bits = math.float_mantissa_bits(T);

        const exponent_mask = (1 << exponent_bits) - 1;
        const mantissa_mask = (1 << mantissa_bits) - 1;

        var exponent = @as(i16, @int_cast((f_bits >> mantissa_bits) & exponent_mask));
        var mantissa = f_bits & mantissa_mask;

        switch (exponent) {
            exponent_mask => {
                return error.NonFiniteFloat;
            },
            0 => {
                // denormal
                exponent -= exponent_bias - 1;
            },
            else => {
                // normal
                mantissa |= 1 << mantissa_bits;
                exponent -= exponent_bias;
            },
        }

        var shift: i16 = mantissa_bits - exponent;

        // factor out powers of two early from rational
        while (mantissa & 1 == 0 and shift > 0) {
            mantissa >>= 1;
            shift -= 1;
        }

        try self.p.set(mantissa);
        self.p.set_sign(f >= 0);

        try self.q.set(1);
        if (shift >= 0) {
            try self.q.shift_left(&self.q, @as(usize, @int_cast(shift)));
        } else {
            try self.p.shift_left(&self.p, @as(usize, @int_cast(-shift)));
        }

        try self.reduce();
    }

    /// Return a floating-point value that is the closest value to a Rational.
    ///
    /// The result may not be exact if the Rational is too precise or too large for the
    /// target type.
    pub fn to_float(self: Rational, comptime T: type) !T {
        // Translated from golang.go/src/math/big/rat.go.
        // TODO: Indicate whether the result is not exact.
        debug.assert(@typeInfo(T) == .Float);

        const fsize = @typeInfo(T).Float.bits;
        const BitReprType = std.meta.Int(.unsigned, fsize);

        const msize = math.float_mantissa_bits(T);
        const msize1 = msize + 1;
        const msize2 = msize1 + 1;

        const esize = math.float_exponent_bits(T);
        const ebias = (1 << (esize - 1)) - 1;
        const emin = 1 - ebias;

        if (self.p.eql_zero()) {
            return 0;
        }

        // 1. left-shift a or sub so that a/b is in [1 << msize1, 1 << (msize2 + 1)]
        var exp = @as(isize, @int_cast(self.p.bit_count_twos_comp())) - @as(isize, @int_cast(self.q.bit_count_twos_comp()));

        var a2 = try self.p.clone();
        defer a2.deinit();

        var b2 = try self.q.clone();
        defer b2.deinit();

        const shift = msize2 - exp;
        if (shift >= 0) {
            try a2.shift_left(&a2, @as(usize, @int_cast(shift)));
        } else {
            try b2.shift_left(&b2, @as(usize, @int_cast(-shift)));
        }

        // 2. compute quotient and remainder
        var q = try Int.init(self.p.allocator);
        defer q.deinit();

        // unused
        var r = try Int.init(self.p.allocator);
        defer r.deinit();

        try Int.div_trunc(&q, &r, &a2, &b2);

        var mantissa = extract_low_bits(q, BitReprType);
        var have_rem = r.len() > 0;

        // 3. q didn't fit in msize2 bits, redo division b2 << 1
        if (mantissa >> msize2 == 1) {
            if (mantissa & 1 == 1) {
                have_rem = true;
            }
            mantissa >>= 1;
            exp += 1;
        }
        if (mantissa >> msize1 != 1) {
            // NOTE: This can be hit if the limb size is small (u8/16).
            @panic("unexpected bits in result");
        }

        // 4. Rounding
        if (emin - msize <= exp and exp <= emin) {
            // denormal
            const shift1 = @as(math.Log2Int(BitReprType), @int_cast(emin - (exp - 1)));
            const lost_bits = mantissa & ((@as(BitReprType, @int_cast(1)) << shift1) - 1);
            have_rem = have_rem or lost_bits != 0;
            mantissa >>= shift1;
            exp = 2 - ebias;
        }

        // round q using round-half-to-even
        var exact = !have_rem;
        if (mantissa & 1 != 0) {
            exact = false;
            if (have_rem or (mantissa & 2 != 0)) {
                mantissa += 1;
                if (mantissa >= 1 << msize2) {
                    // 11...1 => 100...0
                    mantissa >>= 1;
                    exp += 1;
                }
            }
        }
        mantissa >>= 1;

        const f = math.scalbn(@as(T, @float_from_int(mantissa)), @as(i32, @int_cast(exp - msize1)));
        if (math.is_inf(f)) {
            exact = false;
        }

        return if (self.p.is_positive()) f else -f;
    }

    /// Set a rational from an integer ratio.
    pub fn set_ratio(self: *Rational, p: anytype, q: anytype) !void {
        try self.p.set(p);
        try self.q.set(q);

        self.p.set_sign(@int_from_bool(self.p.is_positive()) ^ @int_from_bool(self.q.is_positive()) == 0);
        self.q.set_sign(true);

        try self.reduce();

        if (self.q.eql_zero()) {
            @panic("cannot set rational with denominator = 0");
        }
    }

    /// Set a Rational directly from an Int.
    pub fn copy_int(self: *Rational, a: Int) !void {
        try self.p.copy(a.to_const());
        try self.q.set(1);
    }

    /// Set a Rational directly from a ratio of two Int's.
    pub fn copy_ratio(self: *Rational, a: Int, b: Int) !void {
        try self.p.copy(a.to_const());
        try self.q.copy(b.to_const());

        self.p.set_sign(@int_from_bool(self.p.is_positive()) ^ @int_from_bool(self.q.is_positive()) == 0);
        self.q.set_sign(true);

        try self.reduce();
    }

    /// Make a Rational positive.
    pub fn abs(r: *Rational) void {
        r.p.abs();
    }

    /// Negate the sign of a Rational.
    pub fn negate(r: *Rational) void {
        r.p.negate();
    }

    /// Efficiently swap a Rational with another. This swaps the limb pointers and a full copy is not
    /// performed. The address of the limbs field will not be the same after this function.
    pub fn swap(r: *Rational, other: *Rational) void {
        r.p.swap(&other.p);
        r.q.swap(&other.q);
    }

    /// Returns math.Order.lt, math.Order.eq, math.Order.gt if a < b, a == b or
    /// a > b respectively.
    pub fn order(a: Rational, b: Rational) !math.Order {
        return cmp_internal(a, b, false);
    }

    /// Returns math.Order.lt, math.Order.eq, math.Order.gt if |a| < |b|, |a| ==
    /// |b| or |a| > |b| respectively.
    pub fn order_abs(a: Rational, b: Rational) !math.Order {
        return cmp_internal(a, b, true);
    }

    // p/q > x/y iff p*y > x*q
    fn cmp_internal(a: Rational, b: Rational, is_abs: bool) !math.Order {
        // TODO: Would a div compare algorithm of sorts be viable and quicker? Can we avoid
        // the memory allocations here?
        var q = try Int.init(a.p.allocator);
        defer q.deinit();

        var p = try Int.init(b.p.allocator);
        defer p.deinit();

        try q.mul(&a.p, &b.q);
        try p.mul(&b.p, &a.q);

        return if (is_abs) q.order_abs(p) else q.order(p);
    }

    /// rma = a + b.
    ///
    /// rma, a and b may be aliases. However, it is more efficient if rma does not alias a or b.
    ///
    /// Returns an error if memory could not be allocated.
    pub fn add(rma: *Rational, a: Rational, b: Rational) !void {
        var r = rma;
        var aliased = rma.p.limbs.ptr == a.p.limbs.ptr or rma.p.limbs.ptr == b.p.limbs.ptr;

        var sr: Rational = undefined;
        if (aliased) {
            sr = try Rational.init(rma.p.allocator);
            r = &sr;
            aliased = true;
        }
        defer if (aliased) {
            rma.swap(r);
            r.deinit();
        };

        try r.p.mul(&a.p, &b.q);
        try r.q.mul(&b.p, &a.q);
        try r.p.add(&r.p, &r.q);

        try r.q.mul(&a.q, &b.q);
        try r.reduce();
    }

    /// rma = a - b.
    ///
    /// rma, a and b may be aliases. However, it is more efficient if rma does not alias a or b.
    ///
    /// Returns an error if memory could not be allocated.
    pub fn sub(rma: *Rational, a: Rational, b: Rational) !void {
        var r = rma;
        var aliased = rma.p.limbs.ptr == a.p.limbs.ptr or rma.p.limbs.ptr == b.p.limbs.ptr;

        var sr: Rational = undefined;
        if (aliased) {
            sr = try Rational.init(rma.p.allocator);
            r = &sr;
            aliased = true;
        }
        defer if (aliased) {
            rma.swap(r);
            r.deinit();
        };

        try r.p.mul(&a.p, &b.q);
        try r.q.mul(&b.p, &a.q);
        try r.p.sub(&r.p, &r.q);

        try r.q.mul(&a.q, &b.q);
        try r.reduce();
    }

    /// rma = a * b.
    ///
    /// rma, a and b may be aliases. However, it is more efficient if rma does not alias a or b.
    ///
    /// Returns an error if memory could not be allocated.
    pub fn mul(r: *Rational, a: Rational, b: Rational) !void {
        try r.p.mul(&a.p, &b.p);
        try r.q.mul(&a.q, &b.q);
        try r.reduce();
    }

    /// rma = a / b.
    ///
    /// rma, a and b may be aliases. However, it is more efficient if rma does not alias a or b.
    ///
    /// Returns an error if memory could not be allocated.
    pub fn div(r: *Rational, a: Rational, b: Rational) !void {
        if (b.p.eql_zero()) {
            @panic("division by zero");
        }

        try r.p.mul(&a.p, &b.q);
        try r.q.mul(&b.p, &a.q);
        try r.reduce();
    }

    /// Invert the numerator and denominator fields of a Rational. p/q => q/p.
    pub fn invert(r: *Rational) void {
        Int.swap(&r.p, &r.q);
    }

    // reduce r/q such that gcd(r, q) = 1
    fn reduce(r: *Rational) !void {
        var a = try Int.init(r.p.allocator);
        defer a.deinit();

        const sign = r.p.is_positive();
        r.p.abs();
        try a.gcd(&r.p, &r.q);
        r.p.set_sign(sign);

        const one = IntConst{ .limbs = &[_]Limb{1}, .positive = true };
        if (a.to_const().order(one) != .eq) {
            var unused = try Int.init(r.p.allocator);
            defer unused.deinit();

            // TODO: divexact would be useful here
            // TODO: don't copy r.q for div
            try Int.div_trunc(&r.p, &unused, &r.p, &a);
            try Int.div_trunc(&r.q, &unused, &r.q, &a);
        }
    }
};

fn extract_low_bits(a: Int, comptime T: type) T {
    debug.assert(@typeInfo(T) == .Int);

    const t_bits = @typeInfo(T).Int.bits;
    const limb_bits = @typeInfo(Limb).Int.bits;
    if (t_bits <= limb_bits) {
        return @as(T, @truncate(a.limbs[0]));
    } else {
        var r: T = 0;
        comptime var i: usize = 0;

        // Remainder is always 0 since if t_bits >= limb_bits -> Limb | T and both
        // are powers of two.
        inline while (i < t_bits / limb_bits) : (i += 1) {
            r |= math.shl(T, a.limbs[i], i * limb_bits);
        }

        return r;
    }
}

test extract_low_bits {
    var a = try Int.init_set(testing.allocator, 0x11112222333344441234567887654321);
    defer a.deinit();

    const a1 = extract_low_bits(a, u8);
    try testing.expect(a1 == 0x21);

    const a2 = extract_low_bits(a, u16);
    try testing.expect(a2 == 0x4321);

    const a3 = extract_low_bits(a, u32);
    try testing.expect(a3 == 0x87654321);

    const a4 = extract_low_bits(a, u64);
    try testing.expect(a4 == 0x1234567887654321);

    const a5 = extract_low_bits(a, u128);
    try testing.expect(a5 == 0x11112222333344441234567887654321);
}

test "set" {
    var a = try Rational.init(testing.allocator);
    defer a.deinit();

    try a.set_int(5);
    try testing.expect((try a.p.to(u32)) == 5);
    try testing.expect((try a.q.to(u32)) == 1);

    try a.set_ratio(7, 3);
    try testing.expect((try a.p.to(u32)) == 7);
    try testing.expect((try a.q.to(u32)) == 3);

    try a.set_ratio(9, 3);
    try testing.expect((try a.p.to(i32)) == 3);
    try testing.expect((try a.q.to(i32)) == 1);

    try a.set_ratio(-9, 3);
    try testing.expect((try a.p.to(i32)) == -3);
    try testing.expect((try a.q.to(i32)) == 1);

    try a.set_ratio(9, -3);
    try testing.expect((try a.p.to(i32)) == -3);
    try testing.expect((try a.q.to(i32)) == 1);

    try a.set_ratio(-9, -3);
    try testing.expect((try a.p.to(i32)) == 3);
    try testing.expect((try a.q.to(i32)) == 1);
}

test "set_float" {
    var a = try Rational.init(testing.allocator);
    defer a.deinit();

    try a.set_float(f64, 2.5);
    try testing.expect((try a.p.to(i32)) == 5);
    try testing.expect((try a.q.to(i32)) == 2);

    try a.set_float(f32, -2.5);
    try testing.expect((try a.p.to(i32)) == -5);
    try testing.expect((try a.q.to(i32)) == 2);

    try a.set_float(f32, 3.141593);

    //                = 3.14159297943115234375
    try testing.expect((try a.p.to(u32)) == 3294199);
    try testing.expect((try a.q.to(u32)) == 1048576);

    try a.set_float(f64, 72.141593120712409172417410926841290461290467124);

    //                = 72.1415931207124145885245525278151035308837890625
    try testing.expect((try a.p.to(u128)) == 5076513310880537);
    try testing.expect((try a.q.to(u128)) == 70368744177664);
}

test "set_float_string" {
    var a = try Rational.init(testing.allocator);
    defer a.deinit();

    try a.set_float_string("72.14159312071241458852455252781510353");

    //                  = 72.1415931207124145885245525278151035308837890625
    try testing.expect((try a.p.to(u128)) == 7214159312071241458852455252781510353);
    try testing.expect((try a.q.to(u128)) == 100000000000000000000000000000000000);
}

test "to_float" {
    var a = try Rational.init(testing.allocator);
    defer a.deinit();

    // = 3.14159297943115234375
    try a.set_ratio(3294199, 1048576);
    try testing.expect((try a.to_float(f64)) == 3.14159297943115234375);

    // = 72.1415931207124145885245525278151035308837890625
    try a.set_ratio(5076513310880537, 70368744177664);
    try testing.expect((try a.to_float(f64)) == 72.141593120712409172417410926841290461290467124);
}

test "set/to Float round-trip" {
    var a = try Rational.init(testing.allocator);
    defer a.deinit();
    var prng = std.Random.DefaultPrng.init(0x5EED);
    const random = prng.random();
    var i: usize = 0;
    while (i < 512) : (i += 1) {
        const r = random.float(f64);
        try a.set_float(f64, r);
        try testing.expect((try a.to_float(f64)) == r);
    }
}

test "copy" {
    var a = try Rational.init(testing.allocator);
    defer a.deinit();

    var b = try Int.init_set(testing.allocator, 5);
    defer b.deinit();

    try a.copy_int(b);
    try testing.expect((try a.p.to(u32)) == 5);
    try testing.expect((try a.q.to(u32)) == 1);

    var c = try Int.init_set(testing.allocator, 7);
    defer c.deinit();
    var d = try Int.init_set(testing.allocator, 3);
    defer d.deinit();

    try a.copy_ratio(c, d);
    try testing.expect((try a.p.to(u32)) == 7);
    try testing.expect((try a.q.to(u32)) == 3);

    var e = try Int.init_set(testing.allocator, 9);
    defer e.deinit();
    var f = try Int.init_set(testing.allocator, 3);
    defer f.deinit();

    try a.copy_ratio(e, f);
    try testing.expect((try a.p.to(u32)) == 3);
    try testing.expect((try a.q.to(u32)) == 1);
}

test "negate" {
    var a = try Rational.init(testing.allocator);
    defer a.deinit();

    try a.set_int(-50);
    try testing.expect((try a.p.to(i32)) == -50);
    try testing.expect((try a.q.to(i32)) == 1);

    a.negate();
    try testing.expect((try a.p.to(i32)) == 50);
    try testing.expect((try a.q.to(i32)) == 1);

    a.negate();
    try testing.expect((try a.p.to(i32)) == -50);
    try testing.expect((try a.q.to(i32)) == 1);
}

test "abs" {
    var a = try Rational.init(testing.allocator);
    defer a.deinit();

    try a.set_int(-50);
    try testing.expect((try a.p.to(i32)) == -50);
    try testing.expect((try a.q.to(i32)) == 1);

    a.abs();
    try testing.expect((try a.p.to(i32)) == 50);
    try testing.expect((try a.q.to(i32)) == 1);

    a.abs();
    try testing.expect((try a.p.to(i32)) == 50);
    try testing.expect((try a.q.to(i32)) == 1);
}

test "swap" {
    var a = try Rational.init(testing.allocator);
    defer a.deinit();
    var b = try Rational.init(testing.allocator);
    defer b.deinit();

    try a.set_ratio(50, 23);
    try b.set_ratio(17, 3);

    try testing.expect((try a.p.to(u32)) == 50);
    try testing.expect((try a.q.to(u32)) == 23);

    try testing.expect((try b.p.to(u32)) == 17);
    try testing.expect((try b.q.to(u32)) == 3);

    a.swap(&b);

    try testing.expect((try a.p.to(u32)) == 17);
    try testing.expect((try a.q.to(u32)) == 3);

    try testing.expect((try b.p.to(u32)) == 50);
    try testing.expect((try b.q.to(u32)) == 23);
}

test "order" {
    var a = try Rational.init(testing.allocator);
    defer a.deinit();
    var b = try Rational.init(testing.allocator);
    defer b.deinit();

    try a.set_ratio(500, 231);
    try b.set_ratio(18903, 8584);
    try testing.expect((try a.order(b)) == .lt);

    try a.set_ratio(890, 10);
    try b.set_ratio(89, 1);
    try testing.expect((try a.order(b)) == .eq);
}

test "order/order_abs with negative" {
    var a = try Rational.init(testing.allocator);
    defer a.deinit();
    var b = try Rational.init(testing.allocator);
    defer b.deinit();

    try a.set_ratio(1, 1);
    try b.set_ratio(-2, 1);
    try testing.expect((try a.order(b)) == .gt);
    try testing.expect((try a.order_abs(b)) == .lt);
}

test "add single-limb" {
    var a = try Rational.init(testing.allocator);
    defer a.deinit();
    var b = try Rational.init(testing.allocator);
    defer b.deinit();

    try a.set_ratio(500, 231);
    try b.set_ratio(18903, 8584);
    try testing.expect((try a.order(b)) == .lt);

    try a.set_ratio(890, 10);
    try b.set_ratio(89, 1);
    try testing.expect((try a.order(b)) == .eq);
}

test "add" {
    var a = try Rational.init(testing.allocator);
    defer a.deinit();
    var b = try Rational.init(testing.allocator);
    defer b.deinit();
    var r = try Rational.init(testing.allocator);
    defer r.deinit();

    try a.set_ratio(78923, 23341);
    try b.set_ratio(123097, 12441414);
    try a.add(a, b);

    try r.set_ratio(984786924199, 290395044174);
    try testing.expect((try a.order(r)) == .eq);
}

test "sub" {
    var a = try Rational.init(testing.allocator);
    defer a.deinit();
    var b = try Rational.init(testing.allocator);
    defer b.deinit();
    var r = try Rational.init(testing.allocator);
    defer r.deinit();

    try a.set_ratio(78923, 23341);
    try b.set_ratio(123097, 12441414);
    try a.sub(a, b);

    try r.set_ratio(979040510045, 290395044174);
    try testing.expect((try a.order(r)) == .eq);
}

test "mul" {
    var a = try Rational.init(testing.allocator);
    defer a.deinit();
    var b = try Rational.init(testing.allocator);
    defer b.deinit();
    var r = try Rational.init(testing.allocator);
    defer r.deinit();

    try a.set_ratio(78923, 23341);
    try b.set_ratio(123097, 12441414);
    try a.mul(a, b);

    try r.set_ratio(571481443, 17082061422);
    try testing.expect((try a.order(r)) == .eq);
}

test "div" {
    {
        var a = try Rational.init(testing.allocator);
        defer a.deinit();
        var b = try Rational.init(testing.allocator);
        defer b.deinit();
        var r = try Rational.init(testing.allocator);
        defer r.deinit();

        try a.set_ratio(78923, 23341);
        try b.set_ratio(123097, 12441414);
        try a.div(a, b);

        try r.set_ratio(75531824394, 221015929);
        try testing.expect((try a.order(r)) == .eq);
    }

    {
        var a = try Rational.init(testing.allocator);
        defer a.deinit();
        var r = try Rational.init(testing.allocator);
        defer r.deinit();

        try a.set_ratio(78923, 23341);
        a.invert();

        try r.set_ratio(23341, 78923);
        try testing.expect((try a.order(r)) == .eq);

        try a.set_ratio(-78923, 23341);
        a.invert();

        try r.set_ratio(-23341, 78923);
        try testing.expect((try a.order(r)) == .eq);
    }
}
