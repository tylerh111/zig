const std = @import("../std.zig");
const assert = std.debug.assert;
const mem = std.mem;
const native_endian = @import("builtin").target.cpu.arch.endian();

context: *const anyopaque,
write_fn: *const fn (context: *const anyopaque, bytes: []const u8) anyerror!usize,

const Self = @This();
pub const Error = anyerror;

pub fn write(self: Self, bytes: []const u8) anyerror!usize {
    return self.write_fn(self.context, bytes);
}

pub fn write_all(self: Self, bytes: []const u8) anyerror!void {
    var index: usize = 0;
    while (index != bytes.len) {
        index += try self.write(bytes[index..]);
    }
}

pub fn print(self: Self, comptime format: []const u8, args: anytype) anyerror!void {
    return std.fmt.format(self, format, args);
}

pub fn write_byte(self: Self, byte: u8) anyerror!void {
    const array = [1]u8{byte};
    return self.write_all(&array);
}

pub fn write_byte_ntimes(self: Self, byte: u8, n: usize) anyerror!void {
    var bytes: [256]u8 = undefined;
    @memset(bytes[0..], byte);

    var remaining: usize = n;
    while (remaining > 0) {
        const to_write = @min(remaining, bytes.len);
        try self.write_all(bytes[0..to_write]);
        remaining -= to_write;
    }
}

pub fn write_bytes_ntimes(self: Self, bytes: []const u8, n: usize) anyerror!void {
    var i: usize = 0;
    while (i < n) : (i += 1) {
        try self.write_all(bytes);
    }
}

pub inline fn write_int(self: Self, comptime T: type, value: T, endian: std.builtin.Endian) anyerror!void {
    var bytes: [@div_exact(@typeInfo(T).Int.bits, 8)]u8 = undefined;
    mem.write_int(std.math.ByteAlignedInt(@TypeOf(value)), &bytes, value, endian);
    return self.write_all(&bytes);
}

pub fn write_struct(self: Self, value: anytype) anyerror!void {
    // Only extern and packed structs have defined in-memory layout.
    comptime assert(@typeInfo(@TypeOf(value)).Struct.layout != .auto);
    return self.write_all(mem.as_bytes(&value));
}

pub fn write_struct_endian(self: Self, value: anytype, endian: std.builtin.Endian) anyerror!void {
    // TODO: make sure this value is not a reference type
    if (native_endian == endian) {
        return self.write_struct(value);
    } else {
        var copy = value;
        mem.byte_swap_all_fields(@TypeOf(value), &copy);
        return self.write_struct(copy);
    }
}

pub fn write_file(self: Self, file: std.fs.File) anyerror!void {
    // TODO: figure out how to adjust std lib abstractions so that this ends up
    // doing sendfile or maybe even copy_file_range under the right conditions.
    var buf: [4000]u8 = undefined;
    while (true) {
        const n = try file.read_all(&buf);
        try self.write_all(buf[0..n]);
        if (n < buf.len) return;
    }
}
