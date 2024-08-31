const Number = enum { One, Two, Three };

pub fn main() void {
    var number1 = Number.One;
    _ = &number1;
    var number2: Number = .Two;
    _ = &number2;
    const number3: Number = @enumFromInt(2);
    assert(number1 != number2);
    assert(number2 != number3);
    assert(@int_from_enum(number1) == 0);
    assert(@int_from_enum(number2) == 1);
    assert(@int_from_enum(number3) == 2);
    var x: Number = .Two;
    _ = &x;
    assert(number2 == x);

    return;
}
fn assert(val: bool) void {
    if (!val) unreachable;
}

// run
//
