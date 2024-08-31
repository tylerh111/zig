const std = @import("../std.zig");
const math = std.math;
const expect = std.testing.expect;
const is_nan = math.is_nan;
const is_inf = math.is_inf;
const inf = math.inf;
const nan = math.nan;
const float_eps_at = math.float_eps_at;
const float_eps = math.float_eps;
const float_min = math.float_min;
const float_max = math.float_max;

/// Returns sqrt(x * x + y * y), avoiding unnecessary overflow and underflow.
///
/// Special Cases:
///
/// |   x   |   y   | hypot |
/// |-------|-------|-------|
/// | +-inf |  any  | +inf  |
/// |  any  | +-inf | +inf  |
/// |  nan  |  fin  |  nan  |
/// |  fin  |  nan  |  nan  |
pub fn hypot(x: anytype, y: anytype) @TypeOf(x, y) {
    const T = @TypeOf(x, y);
    switch (@typeInfo(T)) {
        .Float => {},
        .ComptimeFloat => return @sqrt(x * x + y * y),
        else => @compile_error("hypot not implemented for " ++ @type_name(T)),
    }
    const lower = @sqrt(float_min(T));
    const upper = @sqrt(float_max(T) / 2);
    const incre = @sqrt(float_eps(T) / 2);
    const scale = float_eps_at(T, incre);
    const hypfn = if (emulate_fma(T)) hypot_unfused else hypot_fused;
    var major: T = x;
    var minor: T = y;
    if (is_inf(major) or is_inf(minor)) return inf(T);
    if (is_nan(major) or is_nan(minor)) return nan(T);
    if (T == f16) return @float_cast(@sqrt(@mul_add(f32, x, x, @as(f32, y) * y)));
    if (T == f32) return @float_cast(@sqrt(@mul_add(f64, x, x, @as(f64, y) * y)));
    major = @abs(major);
    minor = @abs(minor);
    if (minor > major) {
        const tempo = major;
        major = minor;
        minor = tempo;
    }
    if (major * incre >= minor) return major;
    if (major > upper) return hypfn(T, major * scale, minor * scale) / scale;
    if (minor < lower) return hypfn(T, major / scale, minor / scale) * scale;
    return hypfn(T, major, minor);
}

inline fn emulate_fma(comptime T: type) bool {
    // If @mul_add lowers to the software implementation,
    // hypot_unfused should be used in place of hypot_fused.
    // This takes an educated guess, but ideally we should
    // properly detect at comptime when that fallback will
    // occur.
    return (T == f128 or T == f80);
}

inline fn hypot_fused(comptime F: type, x: F, y: F) F {
    const r = @sqrt(@mul_add(F, x, x, y * y));
    const rr = r * r;
    const xx = x * x;
    const z = @mul_add(F, -y, y, rr - xx) + @mul_add(F, r, r, -rr) - @mul_add(F, x, x, -xx);
    return r - z / (2 * r);
}

inline fn hypot_unfused(comptime F: type, x: F, y: F) F {
    const r = @sqrt(x * x + y * y);
    if (r <= 2 * y) { // 30deg or steeper
        const dx = r - y;
        const z = x * (2 * dx - x) + (dx - 2 * (x - y)) * dx;
        return r - z / (2 * r);
    } else { // shallower than 30 deg
        const dy = r - x;
        const z = 2 * dy * (x - 2 * y) + (4 * dy - y) * y + dy * dy;
        return r - z / (2 * r);
    }
}

const hypot_test_cases = .{
    .{ 0.0, -1.2, 1.2 },
    .{ 0.2, -0.34, 0.3944616584663203993612799816649560759946493601889826495362 },
    .{ 0.8923, 2.636890, 2.7837722899152509525110650481670176852603253522923737962880 },
    .{ 1.5, 5.25, 5.4600824169603887033229768686452745953332522619323580787836 },
    .{ 37.45, 159.835, 164.16372840856167640478217141034363907565754072954443805164 },
    .{ 89.123, 382.028905, 392.28687638576315875933966414927490685367196874260165618371 },
    .{ 123123.234375, 529428.707813, 543556.88524707706887251269205923830745438413088753096759371 },
};

test hypot {
    try expect(hypot(0.3, 0.4) == 0.5);
}

test "hypot.correct" {
    inline for (.{ f16, f32, f64, f128 }) |T| {
        inline for (hypot_test_cases) |v| {
            const a: T, const b: T, const c: T = v;
            try expect(math.approx_eq_rel(T, hypot(a, b), c, @sqrt(float_eps(T))));
        }
    }
}

test "hypot.precise" {
    inline for (.{ f16, f32, f64 }) |T| { // f128 seems to be 5 ulp
        inline for (hypot_test_cases) |v| {
            const a: T, const b: T, const c: T = v;
            try expect(math.approx_eq_rel(T, hypot(a, b), c, float_eps(T)));
        }
    }
}

test "hypot.special" {
    inline for (.{ f16, f32, f64, f128 }) |T| {
        try expect(math.is_nan(hypot(nan(T), 0.0)));
        try expect(math.is_nan(hypot(0.0, nan(T))));

        try expect(math.is_positive_inf(hypot(inf(T), 0.0)));
        try expect(math.is_positive_inf(hypot(0.0, inf(T))));
        try expect(math.is_positive_inf(hypot(inf(T), nan(T))));
        try expect(math.is_positive_inf(hypot(nan(T), inf(T))));

        try expect(math.is_positive_inf(hypot(-inf(T), 0.0)));
        try expect(math.is_positive_inf(hypot(0.0, -inf(T))));
        try expect(math.is_positive_inf(hypot(-inf(T), nan(T))));
        try expect(math.is_positive_inf(hypot(nan(T), -inf(T))));
    }
}
