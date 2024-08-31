pub fn main() void {
    var float: f32 = 4294967296; // runtime-known
    _ = &float;
    const int: i32 = @int_from_float(float);
    _ = int;
}

// exe=fail
