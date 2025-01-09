pub fn main() void {
    var float: f32 = 4294967296; // runtime-known
    _ = &float;
    const int: i32 = @intfromfloat(float);
    _ = int;
}

// exe=fail
