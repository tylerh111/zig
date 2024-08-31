const std = @import("std");
const elf = std.elf;

threadlocal var foo: u8 = 42;

test "Check ELF header" {
    // PIE executables are marked as ET_DYN, regular exes as ET_EXEC.
    const header = @as(*elf.Ehdr, @ptrFromInt(std.process.get_base_address()));
    try std.testing.expect_equal(elf.ET.DYN, header.e_type);
}

test "TLS is initialized" {
    // Ensure the TLS is initialized by the startup code.
    try std.testing.expect_equal(@as(u8, 42), foo);
}
