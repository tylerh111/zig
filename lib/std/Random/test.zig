const std = @import("../std.zig");
const math = std.math;
const Random = std.Random;
const DefaultPrng = Random.DefaultPrng;
const SplitMix64 = Random.SplitMix64;
const DefaultCsprng = Random.DefaultCsprng;
const expect = std.testing.expect;
const expect_equal = std.testing.expect_equal;

const SequentialPrng = struct {
    const Self = @This();
    next_value: u8,

    pub fn init() Self {
        return Self{
            .next_value = 0,
        };
    }

    pub fn random(self: *Self) Random {
        return Random.init(self, fill);
    }

    pub fn fill(self: *Self, buf: []u8) void {
        for (buf) |*b| {
            b.* = self.next_value;
        }
        self.next_value +%= 1;
    }
};

/// Do not use this PRNG! It is meant to be predictable, for the purposes of test reproducibility and coverage.
/// Its output is just a repeat of a user-specified byte pattern.
/// Name is a reference to this comic: https://dilbert.com/strip/2001-10-25
const Dilbert = struct {
    pattern: []const u8 = undefined,
    curr_idx: usize = 0,

    pub fn init(pattern: []const u8) !Dilbert {
        if (pattern.len == 0)
            return error.EmptyPattern;
        var self = Dilbert{};
        self.pattern = pattern;
        self.curr_idx = 0;
        return self;
    }

    pub fn random(self: *Dilbert) Random {
        return Random.init(self, fill);
    }

    pub fn fill(self: *Dilbert, buf: []u8) void {
        for (buf) |*byte| {
            byte.* = self.pattern[self.curr_idx];
            self.curr_idx = (self.curr_idx + 1) % self.pattern.len;
        }
    }

    test "Dilbert fill" {
        var r = try Dilbert.init("9nine");

        const seq = [_]u64{
            0x396E696E65396E69,
            0x6E65396E696E6539,
            0x6E696E65396E696E,
            0x65396E696E65396E,
            0x696E65396E696E65,
        };

        for (seq) |s| {
            var buf0: [8]u8 = undefined;
            var buf1: [8]u8 = undefined;
            std.mem.write_int(u64, &buf0, s, .big);
            r.fill(&buf1);
            try std.testing.expect(std.mem.eql(u8, buf0[0..], buf1[0..]));
        }
    }
};

test "Random int" {
    try test_random_int();
    try comptime test_random_int();
}
fn test_random_int() !void {
    var rng = SequentialPrng.init();
    const random = rng.random();

    try expect(random.int(u0) == 0);

    rng.next_value = 0;
    try expect(random.int(u1) == 0);
    try expect(random.int(u1) == 1);
    try expect(random.int(u2) == 2);
    try expect(random.int(u2) == 3);
    try expect(random.int(u2) == 0);

    rng.next_value = 0xff;
    try expect(random.int(u8) == 0xff);
    rng.next_value = 0x11;
    try expect(random.int(u8) == 0x11);

    rng.next_value = 0xff;
    try expect(random.int(u32) == 0xffffffff);
    rng.next_value = 0x11;
    try expect(random.int(u32) == 0x11111111);

    rng.next_value = 0xff;
    try expect(random.int(i32) == -1);
    rng.next_value = 0x11;
    try expect(random.int(i32) == 0x11111111);

    rng.next_value = 0xff;
    try expect(random.int(i8) == -1);
    rng.next_value = 0x11;
    try expect(random.int(i8) == 0x11);

    rng.next_value = 0xff;
    try expect(random.int(u33) == 0x1ffffffff);
    rng.next_value = 0xff;
    try expect(random.int(i1) == -1);
    rng.next_value = 0xff;
    try expect(random.int(i2) == -1);
    rng.next_value = 0xff;
    try expect(random.int(i33) == -1);
}

test "Random boolean" {
    try test_random_boolean();
    try comptime test_random_boolean();
}
fn test_random_boolean() !void {
    var rng = SequentialPrng.init();
    const random = rng.random();

    try expect(random.boolean() == false);
    try expect(random.boolean() == true);
    try expect(random.boolean() == false);
    try expect(random.boolean() == true);
}

test "Random enum" {
    try test_random_enum_value();
    try comptime test_random_enum_value();
}
fn test_random_enum_value() !void {
    const TestEnum = enum {
        First,
        Second,
        Third,
    };
    var rng = SequentialPrng.init();
    const random = rng.random();
    rng.next_value = 0;
    try expect(random.enum_value(TestEnum) == TestEnum.First);
    try expect(random.enum_value(TestEnum) == TestEnum.First);
    try expect(random.enum_value(TestEnum) == TestEnum.First);
}

test "Random intLessThan" {
    @setEvalBranchQuota(10000);
    try test_random_int_less_than();
    try comptime test_random_int_less_than();
}
fn test_random_int_less_than() !void {
    var rng = SequentialPrng.init();
    const random = rng.random();

    rng.next_value = 0xff;
    try expect(random.uint_less_than(u8, 4) == 3);
    try expect(rng.next_value == 0);
    try expect(random.uint_less_than(u8, 4) == 0);
    try expect(rng.next_value == 1);

    rng.next_value = 0;
    try expect(random.uint_less_than(u64, 32) == 0);

    // trigger the bias rejection code path
    rng.next_value = 0;
    try expect(random.uint_less_than(u8, 3) == 0);
    // verify we incremented twice
    try expect(rng.next_value == 2);

    rng.next_value = 0xff;
    try expect(random.int_range_less_than(u8, 0, 0x80) == 0x7f);
    rng.next_value = 0xff;
    try expect(random.int_range_less_than(u8, 0x7f, 0xff) == 0xfe);

    rng.next_value = 0xff;
    try expect(random.int_range_less_than(i8, 0, 0x40) == 0x3f);
    rng.next_value = 0xff;
    try expect(random.int_range_less_than(i8, -0x40, 0x40) == 0x3f);
    rng.next_value = 0xff;
    try expect(random.int_range_less_than(i8, -0x80, 0) == -1);

    rng.next_value = 0xff;
    try expect(random.int_range_less_than(i3, -4, 0) == -1);
    rng.next_value = 0xff;
    try expect(random.int_range_less_than(i3, -2, 2) == 1);
}

test "Random intAtMost" {
    @setEvalBranchQuota(10000);
    try test_random_int_at_most();
    try comptime test_random_int_at_most();
}
fn test_random_int_at_most() !void {
    var rng = SequentialPrng.init();
    const random = rng.random();

    rng.next_value = 0xff;
    try expect(random.uint_at_most(u8, 3) == 3);
    try expect(rng.next_value == 0);
    try expect(random.uint_at_most(u8, 3) == 0);

    // trigger the bias rejection code path
    rng.next_value = 0;
    try expect(random.uint_at_most(u8, 2) == 0);
    // verify we incremented twice
    try expect(rng.next_value == 2);

    rng.next_value = 0xff;
    try expect(random.int_range_at_most(u8, 0, 0x7f) == 0x7f);
    rng.next_value = 0xff;
    try expect(random.int_range_at_most(u8, 0x7f, 0xfe) == 0xfe);

    rng.next_value = 0xff;
    try expect(random.int_range_at_most(i8, 0, 0x3f) == 0x3f);
    rng.next_value = 0xff;
    try expect(random.int_range_at_most(i8, -0x40, 0x3f) == 0x3f);
    rng.next_value = 0xff;
    try expect(random.int_range_at_most(i8, -0x80, -1) == -1);

    rng.next_value = 0xff;
    try expect(random.int_range_at_most(i3, -4, -1) == -1);
    rng.next_value = 0xff;
    try expect(random.int_range_at_most(i3, -2, 1) == 1);

    try expect(random.uint_at_most(u0, 0) == 0);
}

test "Random Biased" {
    var prng = DefaultPrng.init(0);
    const random = prng.random();
    // Not thoroughly checking the logic here.
    // Just want to execute all the paths with different types.

    try expect(random.uint_less_than_biased(u1, 1) == 0);
    try expect(random.uint_less_than_biased(u32, 10) < 10);
    try expect(random.uint_less_than_biased(u64, 20) < 20);

    try expect(random.uint_at_most_biased(u0, 0) == 0);
    try expect(random.uint_at_most_biased(u1, 0) <= 0);
    try expect(random.uint_at_most_biased(u32, 10) <= 10);
    try expect(random.uint_at_most_biased(u64, 20) <= 20);

    try expect(random.int_range_less_than_biased(u1, 0, 1) == 0);
    try expect(random.int_range_less_than_biased(i1, -1, 0) == -1);
    try expect(random.int_range_less_than_biased(u32, 10, 20) >= 10);
    try expect(random.int_range_less_than_biased(i32, 10, 20) >= 10);
    try expect(random.int_range_less_than_biased(u64, 20, 40) >= 20);
    try expect(random.int_range_less_than_biased(i64, 20, 40) >= 20);

    // uncomment for broken module error:
    //expect(random.int_range_at_most_biased(u0, 0, 0) == 0);
    try expect(random.int_range_at_most_biased(u1, 0, 1) >= 0);
    try expect(random.int_range_at_most_biased(i1, -1, 0) >= -1);
    try expect(random.int_range_at_most_biased(u32, 10, 20) >= 10);
    try expect(random.int_range_at_most_biased(i32, 10, 20) >= 10);
    try expect(random.int_range_at_most_biased(u64, 20, 40) >= 20);
    try expect(random.int_range_at_most_biased(i64, 20, 40) >= 20);
}

test "splitmix64 sequence" {
    var r = SplitMix64.init(0xaeecf86f7878dd75);

    const seq = [_]u64{
        0x5dbd39db0178eb44,
        0xa9900fb66b397da3,
        0x5c1a28b1aeebcf5c,
        0x64a963238f776912,
        0xc6d4177b21d1c0ab,
        0xb2cbdbdb5ea35394,
    };

    for (seq) |s| {
        try expect(s == r.next());
    }
}

// Actual Random helper function tests, pcg engine is assumed correct.
test "Random float correctness" {
    var prng = DefaultPrng.init(0);
    const random = prng.random();

    var i: usize = 0;
    while (i < 1000) : (i += 1) {
        const val1 = random.float(f32);
        try expect(val1 >= 0.0);
        try expect(val1 < 1.0);

        const val2 = random.float(f64);
        try expect(val2 >= 0.0);
        try expect(val2 < 1.0);
    }
}

// Check the "astronomically unlikely" code paths.
test "Random float coverage" {
    var prng = try Dilbert.init(&[_]u8{0});
    const random = prng.random();

    const rand_f64 = random.float(f64);
    const rand_f32 = random.float(f32);

    try expect(rand_f32 == 0.0);
    try expect(rand_f64 == 0.0);
}

test "Random float chi-square goodness of fit" {
    const num_numbers = 100000;
    const num_buckets = 1000;

    var f32_hist = std.AutoHashMap(u32, u32).init(std.testing.allocator);
    defer f32_hist.deinit();
    var f64_hist = std.AutoHashMap(u64, u32).init(std.testing.allocator);
    defer f64_hist.deinit();

    var prng = DefaultPrng.init(0);
    const random = prng.random();

    var i: usize = 0;
    while (i < num_numbers) : (i += 1) {
        const rand_f32 = random.float(f32);
        const rand_f64 = random.float(f64);
        const f32_put = try f32_hist.get_or_put(@as(u32, @int_from_float(rand_f32 * @as(f32, @float_from_int(num_buckets)))));
        if (f32_put.found_existing) {
            f32_put.value_ptr.* += 1;
        } else {
            f32_put.value_ptr.* = 1;
        }
        const f64_put = try f64_hist.get_or_put(@as(u32, @int_from_float(rand_f64 * @as(f64, @float_from_int(num_buckets)))));
        if (f64_put.found_existing) {
            f64_put.value_ptr.* += 1;
        } else {
            f64_put.value_ptr.* = 1;
        }
    }

    var f32_total_variance: f64 = 0;
    var f64_total_variance: f64 = 0;

    {
        var j: u32 = 0;
        while (j < num_buckets) : (j += 1) {
            const count = @as(f64, @float_from_int((if (f32_hist.get(j)) |v| v else 0)));
            const expected = @as(f64, @float_from_int(num_numbers)) / @as(f64, @float_from_int(num_buckets));
            const delta = count - expected;
            const variance = (delta * delta) / expected;
            f32_total_variance += variance;
        }
    }

    {
        var j: u64 = 0;
        while (j < num_buckets) : (j += 1) {
            const count = @as(f64, @float_from_int((if (f64_hist.get(j)) |v| v else 0)));
            const expected = @as(f64, @float_from_int(num_numbers)) / @as(f64, @float_from_int(num_buckets));
            const delta = count - expected;
            const variance = (delta * delta) / expected;
            f64_total_variance += variance;
        }
    }

    // Accept p-values >= 0.05.
    // Critical value is calculated by opening a Python interpreter and running:
    // scipy.stats.chi2.isf(0.05, num_buckets - 1)
    const critical_value = 1073.6426506574246;
    try expect(f32_total_variance < critical_value);
    try expect(f64_total_variance < critical_value);
}

test "Random shuffle" {
    var prng = DefaultPrng.init(0);
    const random = prng.random();

    var seq = [_]u8{ 0, 1, 2, 3, 4 };
    var seen = [_]bool{false} ** 5;

    var i: usize = 0;
    while (i < 1000) : (i += 1) {
        random.shuffle(u8, seq[0..]);
        seen[seq[0]] = true;
        try expect(sum_array(seq[0..]) == 10);
    }

    // we should see every entry at the head at least once
    for (seen) |e| {
        try expect(e == true);
    }
}

fn sum_array(s: []const u8) u32 {
    var r: u32 = 0;
    for (s) |e|
        r += e;
    return r;
}

test "Random range" {
    var prng = DefaultPrng.init(0);
    const random = prng.random();

    try test_range(random, -4, 3);
    try test_range(random, -4, -1);
    try test_range(random, 10, 14);
    try test_range(random, -0x80, 0x7f);
}

fn test_range(r: Random, start: i8, end: i8) !void {
    try test_range_bias(r, start, end, true);
    try test_range_bias(r, start, end, false);
}
fn test_range_bias(r: Random, start: i8, end: i8, biased: bool) !void {
    const count = @as(usize, @int_cast(@as(i32, end) - @as(i32, start)));
    var values_buffer = [_]bool{false} ** 0x100;
    const values = values_buffer[0..count];
    var i: usize = 0;
    while (i < count) {
        const value: i32 = if (biased) r.int_range_less_than_biased(i8, start, end) else r.int_range_less_than(i8, start, end);
        const index = @as(usize, @int_cast(value - start));
        if (!values[index]) {
            i += 1;
            values[index] = true;
        }
    }
}

test "CSPRNG" {
    var secret_seed: [DefaultCsprng.secret_seed_length]u8 = undefined;
    std.crypto.random.bytes(&secret_seed);
    var csprng = DefaultCsprng.init(secret_seed);
    const random = csprng.random();
    const a = random.int(u64);
    const b = random.int(u64);
    const c = random.int(u64);
    try expect(a ^ b ^ c != 0);
}

test "Random weighted_index" {
    // Make sure weighted_index works for various integers and floats
    inline for (.{ u64, i4, f32, f64 }) |T| {
        var prng = DefaultPrng.init(0);
        const random = prng.random();

        const proportions = [_]T{ 2, 1, 1, 2 };
        var counts = [_]f64{ 0, 0, 0, 0 };

        const n_trials: u64 = 10_000;
        var i: usize = 0;
        while (i < n_trials) : (i += 1) {
            const pick = random.weighted_index(T, &proportions);
            counts[pick] += 1;
        }

        // We expect the first and last counts to be roughly 2x the second and third
        const approx_eq_rel = std.math.approx_eq_rel;
        // Define "roughly" to be within 10%
        const tolerance = 0.1;
        try std.testing.expect(approx_eq_rel(f64, counts[0], counts[1] * 2, tolerance));
        try std.testing.expect(approx_eq_rel(f64, counts[1], counts[2], tolerance));
        try std.testing.expect(approx_eq_rel(f64, counts[2] * 2, counts[3], tolerance));
    }
}
