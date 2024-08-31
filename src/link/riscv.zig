pub fn write_set_sub6(comptime op: enum { set, sub }, code: *[1]u8, addend: anytype) void {
    const mask: u8 = 0b11_000000;
    const actual: i8 = @truncate(addend);
    var value: u8 = mem.read_int(u8, code, .little);
    switch (op) {
        .set => value = (value & mask) | @as(u8, @bit_cast(actual & ~mask)),
        .sub => value = (value & mask) | (@as(u8, @bit_cast(@as(i8, @bit_cast(value)) -| actual)) & ~mask),
    }
    mem.write_int(u8, code, value, .little);
}

pub fn write_addend(
    comptime Int: type,
    comptime op: enum { add, sub },
    code: *[@typeInfo(Int).Int.bits / 8]u8,
    value: anytype,
) void {
    var V: Int = mem.read_int(Int, code, .little);
    const addend: Int = @truncate(value);
    switch (op) {
        .add => V +|= addend, // TODO: I think saturating arithmetic is correct here
        .sub => V -|= addend,
    }
    mem.write_int(Int, code, V, .little);
}

pub fn write_inst_u(code: *[4]u8, value: u32) void {
    var data = Encoding.Data{
        .U = mem.bytes_to_value(std.meta.TagPayload(
            Encoding.Data,
            Encoding.Data.U,
        ), code),
    };
    const compensated: u32 = @bit_cast(@as(i32, @bit_cast(value)) + 0x800);
    data.U.imm12_31 = bit_slice(compensated, 31, 12);
    mem.write_int(u32, code, data.to_u32(), .little);
}

pub fn write_inst_i(code: *[4]u8, value: u32) void {
    var data = Encoding.Data{
        .I = mem.bytes_to_value(std.meta.TagPayload(
            Encoding.Data,
            Encoding.Data.I,
        ), code),
    };
    data.I.imm0_11 = bit_slice(value, 11, 0);
    mem.write_int(u32, code, data.to_u32(), .little);
}

pub fn write_inst_s(code: *[4]u8, value: u32) void {
    var data = Encoding.Data{
        .S = mem.bytes_to_value(std.meta.TagPayload(
            Encoding.Data,
            Encoding.Data.S,
        ), code),
    };
    data.S.imm0_4 = bit_slice(value, 4, 0);
    data.S.imm5_11 = bit_slice(value, 11, 5);
    mem.write_int(u32, code, data.to_u32(), .little);
}

pub fn write_inst_j(code: *[4]u8, value: u32) void {
    var data = Encoding.Data{
        .J = mem.bytes_to_value(std.meta.TagPayload(
            Encoding.Data,
            Encoding.Data.J,
        ), code),
    };
    data.J.imm1_10 = bit_slice(value, 10, 1);
    data.J.imm11 = bit_slice(value, 11, 11);
    data.J.imm12_19 = bit_slice(value, 19, 12);
    data.J.imm20 = bit_slice(value, 20, 20);
    mem.write_int(u32, code, data.to_u32(), .little);
}

pub fn write_inst_b(code: *[4]u8, value: u32) void {
    var data = Encoding.Data{
        .B = mem.bytes_to_value(std.meta.TagPayload(
            Encoding.Data,
            Encoding.Data.B,
        ), code),
    };
    data.B.imm1_4 = bit_slice(value, 4, 1);
    data.B.imm5_10 = bit_slice(value, 10, 5);
    data.B.imm11 = bit_slice(value, 11, 11);
    data.B.imm12 = bit_slice(value, 12, 12);
    mem.write_int(u32, code, data.to_u32(), .little);
}

fn bit_slice(
    value: anytype,
    comptime high: comptime_int,
    comptime low: comptime_int,
) std.math.IntFittingRange(0, 1 << high - low) {
    return @truncate((value >> low) & (1 << (high - low + 1)) - 1);
}

const encoder = @import("../arch/riscv64/encoder.zig");
const Encoding = @import("../arch/riscv64/Encoding.zig");
const mem = std.mem;
const std = @import("std");

pub const Instruction = encoder.Instruction;
