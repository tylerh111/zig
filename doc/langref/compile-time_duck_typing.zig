fn max(comptime T: type, a: T, b: T) T {
    return if (a > b) a else b;
}
fn gimme_the_bigger_float(a: f32, b: f32) f32 {
    return max(f32, a, b);
}
fn gimme_the_bigger_integer(a: u64, b: u64) u64 {
    return max(u64, a, b);
}

// syntax
