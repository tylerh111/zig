const std = @import("std");
const is_nan = std.math.is_nan;
const is_inf = std.math.is_inf;
const copysign = std.math.copysign;

pub fn Complex(comptime T: type) type {
    return extern struct {
        real: T,
        imag: T,
    };
}

/// Implementation based on Annex G of C17 Standard (N2176)
pub inline fn mulc3(comptime T: type, a_in: T, b_in: T, c_in: T, d_in: T) Complex(T) {
    var a = a_in;
    var b = b_in;
    var c = c_in;
    var d = d_in;

    const ac = a * c;
    const bd = b * d;
    const ad = a * d;
    const bc = b * c;

    const zero: T = 0.0;
    const one: T = 1.0;

    const z: Complex(T) = .{
        .real = ac - bd,
        .imag = ad + bc,
    };
    if (is_nan(z.real) and is_nan(z.imag)) {
        var recalc: bool = false;

        if (is_inf(a) or is_inf(b)) { // (a + ib) is infinite

            // "Box" the infinity (+/-inf goes to +/-1, all finite values go to 0)
            a = copysign(if (is_inf(a)) one else zero, a);
            b = copysign(if (is_inf(b)) one else zero, b);

            // Replace NaNs in the other factor with (signed) 0
            if (is_nan(c)) c = copysign(zero, c);
            if (is_nan(d)) d = copysign(zero, d);

            recalc = true;
        }

        if (is_inf(c) or is_inf(d)) { // (c + id) is infinite

            // "Box" the infinity (+/-inf goes to +/-1, all finite values go to 0)
            c = copysign(if (is_inf(c)) one else zero, c);
            d = copysign(if (is_inf(d)) one else zero, d);

            // Replace NaNs in the other factor with (signed) 0
            if (is_nan(a)) a = copysign(zero, a);
            if (is_nan(b)) b = copysign(zero, b);

            recalc = true;
        }

        if (!recalc and (is_inf(ac) or is_inf(bd) or is_inf(ad) or is_inf(bc))) {

            // Recover infinities from overflow by changing NaNs to 0
            if (is_nan(a)) a = copysign(zero, a);
            if (is_nan(b)) b = copysign(zero, b);
            if (is_nan(c)) c = copysign(zero, c);
            if (is_nan(d)) d = copysign(zero, d);

            recalc = true;
        }
        if (recalc) {
            return .{
                .real = std.math.inf(T) * (a * c - b * d),
                .imag = std.math.inf(T) * (a * d + b * c),
            };
        }
    }
    return z;
}
