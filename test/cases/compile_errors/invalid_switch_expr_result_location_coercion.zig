const Enum = enum(u8) { first, second, _ };

export fn invalid_first_prong(enum_value: Enum) u8 {
    const result: u8 = switch (enum_value) {
        .first => 256,
        .second => 0,
        else => 0,
    };
    return result;
}

export fn invalid_second_prong(enum_value: Enum) u8 {
    const result: u8 = switch (enum_value) {
        .first => 0,
        .second => 256,
        _ => 0,
    };
    return result;
}

export fn invalid_else_prong(enum_value: Enum) u8 {
    const result: u8 = switch (enum_value) {
        .first => 0,
        .second => 0,
        else => 256,
    };
    return result;
}

export fn invalid_non_exhaustive_prong(enum_value: Enum) u8 {
    const result: u8 = switch (enum_value) {
        .first => 0,
        .second => 0,
        _ => 256,
    };
    return result;
}

// error
// backend=stage2
// target=native
//
// :5:19: error: type 'u8' cannot represent integer value '256'
// :15:20: error: type 'u8' cannot represent integer value '256'
// :25:17: error: type 'u8' cannot represent integer value '256'
// :34:14: error: type 'u8' cannot represent integer value '256'
