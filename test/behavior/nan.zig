const builtin = @import("builtin");
const std = @import("std");
const math = std.math;
const mem = std.mem;
const testing = std.testing;

const qnan_u16: u16 = 0x7E00;
const snan_u16: u16 = 0x7D00;
const qnan_u32: u32 = 0x7FC00000;
const snan_u32: u32 = 0x7FA00000;
const qnan_u64: u64 = 0x7FF8000000000000;
const snan_u64: u64 = 0x7FF4000000000000;
const qnan_u128: u128 = 0x7FFF8000000000000000000000000000;
const snan_u128: u128 = 0x7FFF4000000000000000000000000000;
const qnan_f16: f16 = math.nan(f16);
const snan_f16: f16 = math.snan(f16);
const qnan_f32: f32 = math.nan(f32);
const snan_f32: f32 = math.snan(f32);
const qnan_f64: f64 = math.nan(f64);
const snan_f64: f64 = math.snan(f64);
const qnan_f128: f128 = math.nan(f128);
const snan_f128: f128 = math.snan(f128);

test "nan memory equality" {
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    // signaled
    try testing.expect(mem.eql(u8, mem.as_bytes(&snan_u16), mem.as_bytes(&snan_f16)));
    try testing.expect(mem.eql(u8, mem.as_bytes(&snan_u32), mem.as_bytes(&snan_f32)));
    try testing.expect(mem.eql(u8, mem.as_bytes(&snan_u64), mem.as_bytes(&snan_f64)));
    try testing.expect(mem.eql(u8, mem.as_bytes(&snan_u128), mem.as_bytes(&snan_f128)));

    // quiet
    try testing.expect(mem.eql(u8, mem.as_bytes(&qnan_u16), mem.as_bytes(&qnan_f16)));
    try testing.expect(mem.eql(u8, mem.as_bytes(&qnan_u32), mem.as_bytes(&qnan_f32)));
    try testing.expect(mem.eql(u8, mem.as_bytes(&qnan_u64), mem.as_bytes(&qnan_f64)));
    try testing.expect(mem.eql(u8, mem.as_bytes(&qnan_u128), mem.as_bytes(&qnan_f128)));
}
