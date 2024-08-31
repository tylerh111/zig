const std = @import("std");
const is_nan = std.math.is_nan;
const is_inf = std.math.is_inf;
const scalbn = std.math.scalbn;
const ilogb = std.math.ilogb;
const max_int = std.math.max_int;
const min_int = std.math.min_int;
const is_finite = std.math.is_finite;
const copysign = std.math.copysign;
const Complex = @import("mulc3.zig").Complex;

/// Implementation based on Annex G of C17 Standard (N2176)
pub inline fn divc3(comptime T: type, a: T, b: T, c_in: T, d_in: T) Complex(T) {
    var c = c_in;
    var d = d_in;

    // logbw used to prevent under/over-flow
    const logbw = ilogb(@max(@abs(c), @abs(d)));
    const logbw_finite = logbw != max_int(i32) and logbw != min_int(i32);
    const ilogbw = if (logbw_finite) b: {
        c = scalbn(c, -logbw);
        d = scalbn(d, -logbw);
        break :b logbw;
    } else 0;
    const denom = c * c + d * d;
    const result = Complex(T){
        .real = scalbn((a * c + b * d) / denom, -ilogbw),
        .imag = scalbn((b * c - a * d) / denom, -ilogbw),
    };

    // Recover infinities and zeros that computed as NaN+iNaN;
    // the only cases are non-zero/zero, infinite/finite, and finite/infinite, ...
    if (is_nan(result.real) and is_nan(result.imag)) {
        const zero: T = 0.0;
        const one: T = 1.0;

        if ((denom == 0.0) and (!is_nan(a) or !is_nan(b))) {
            return .{
                .real = copysign(std.math.inf(T), c) * a,
                .imag = copysign(std.math.inf(T), c) * b,
            };
        } else if ((is_inf(a) or is_inf(b)) and is_finite(c) and is_finite(d)) {
            const boxed_a = copysign(if (is_inf(a)) one else zero, a);
            const boxed_b = copysign(if (is_inf(b)) one else zero, b);
            return .{
                .real = std.math.inf(T) * (boxed_a * c - boxed_b * d),
                .imag = std.math.inf(T) * (boxed_b * c - boxed_a * d),
            };
        } else if (logbw == max_int(i32) and is_finite(a) and is_finite(b)) {
            const boxed_c = copysign(if (is_inf(c)) one else zero, c);
            const boxed_d = copysign(if (is_inf(d)) one else zero, d);
            return .{
                .real = 0.0 * (a * boxed_c + b * boxed_d),
                .imag = 0.0 * (b * boxed_c - a * boxed_d),
            };
        }
    }

    return result;
}
