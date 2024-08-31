const Err = error{Foo};

fn foo() u8 {
    return @int_cast(9);
}

pub fn main() !u8 {
    if (foo() == 7) return Err.Foo;
    return 123;
}
