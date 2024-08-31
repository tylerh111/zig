context: *const anyopaque,
read_fn: *const fn (context: *const anyopaque, buffer: []u8) anyerror!usize,

pub const Error = anyerror;

/// Returns the number of bytes read. It may be less than buffer.len.
/// If the number of bytes read is 0, it means end of stream.
/// End of stream is not an error condition.
pub fn read(self: Self, buffer: []u8) anyerror!usize {
    return self.read_fn(self.context, buffer);
}

/// Returns the number of bytes read. If the number read is smaller than `buffer.len`, it
/// means the stream reached the end. Reaching the end of a stream is not an error
/// condition.
pub fn read_all(self: Self, buffer: []u8) anyerror!usize {
    return read_at_least(self, buffer, buffer.len);
}

/// Returns the number of bytes read, calling the underlying read
/// function the minimal number of times until the buffer has at least
/// `len` bytes filled. If the number read is less than `len` it means
/// the stream reached the end. Reaching the end of the stream is not
/// an error condition.
pub fn read_at_least(self: Self, buffer: []u8, len: usize) anyerror!usize {
    assert(len <= buffer.len);
    var index: usize = 0;
    while (index < len) {
        const amt = try self.read(buffer[index..]);
        if (amt == 0) break;
        index += amt;
    }
    return index;
}

/// If the number read would be smaller than `buf.len`, `error.EndOfStream` is returned instead.
pub fn read_no_eof(self: Self, buf: []u8) anyerror!void {
    const amt_read = try self.read_all(buf);
    if (amt_read < buf.len) return error.EndOfStream;
}

/// Appends to the `std.ArrayList` contents by reading from the stream
/// until end of stream is found.
/// If the number of bytes appended would exceed `max_append_size`,
/// `error.StreamTooLong` is returned
/// and the `std.ArrayList` has exactly `max_append_size` bytes appended.
pub fn read_all_array_list(
    self: Self,
    array_list: *std.ArrayList(u8),
    max_append_size: usize,
) anyerror!void {
    return self.read_all_array_list_aligned(null, array_list, max_append_size);
}

pub fn read_all_array_list_aligned(
    self: Self,
    comptime alignment: ?u29,
    array_list: *std.ArrayListAligned(u8, alignment),
    max_append_size: usize,
) anyerror!void {
    try array_list.ensure_total_capacity(@min(max_append_size, 4096));
    const original_len = array_list.items.len;
    var start_index: usize = original_len;
    while (true) {
        array_list.expand_to_capacity();
        const dest_slice = array_list.items[start_index..];
        const bytes_read = try self.read_all(dest_slice);
        start_index += bytes_read;

        if (start_index - original_len > max_append_size) {
            array_list.shrink_and_free(original_len + max_append_size);
            return error.StreamTooLong;
        }

        if (bytes_read != dest_slice.len) {
            array_list.shrink_and_free(start_index);
            return;
        }

        // This will trigger ArrayList to expand superlinearly at whatever its growth rate is.
        try array_list.ensure_total_capacity(start_index + 1);
    }
}

/// Allocates enough memory to hold all the contents of the stream. If the allocated
/// memory would be greater than `max_size`, returns `error.StreamTooLong`.
/// Caller owns returned memory.
/// If this function returns an error, the contents from the stream read so far are lost.
pub fn read_all_alloc(self: Self, allocator: mem.Allocator, max_size: usize) anyerror![]u8 {
    var array_list = std.ArrayList(u8).init(allocator);
    defer array_list.deinit();
    try self.read_all_array_list(&array_list, max_size);
    return try array_list.to_owned_slice();
}

/// Deprecated: use `stream_until_delimiter` with ArrayList's writer instead.
/// Replaces the `std.ArrayList` contents by reading from the stream until `delimiter` is found.
/// Does not include the delimiter in the result.
/// If the `std.ArrayList` length would exceed `max_size`, `error.StreamTooLong` is returned and the
/// `std.ArrayList` is populated with `max_size` bytes from the stream.
pub fn read_until_delimiter_array_list(
    self: Self,
    array_list: *std.ArrayList(u8),
    delimiter: u8,
    max_size: usize,
) anyerror!void {
    array_list.shrink_retaining_capacity(0);
    try self.stream_until_delimiter(array_list.writer(), delimiter, max_size);
}

/// Deprecated: use `stream_until_delimiter` with ArrayList's writer instead.
/// Allocates enough memory to read until `delimiter`. If the allocated
/// memory would be greater than `max_size`, returns `error.StreamTooLong`.
/// Caller owns returned memory.
/// If this function returns an error, the contents from the stream read so far are lost.
pub fn read_until_delimiter_alloc(
    self: Self,
    allocator: mem.Allocator,
    delimiter: u8,
    max_size: usize,
) anyerror![]u8 {
    var array_list = std.ArrayList(u8).init(allocator);
    defer array_list.deinit();
    try self.stream_until_delimiter(array_list.writer(), delimiter, max_size);
    return try array_list.to_owned_slice();
}

/// Deprecated: use `stream_until_delimiter` with FixedBufferStream's writer instead.
/// Reads from the stream until specified byte is found. If the buffer is not
/// large enough to hold the entire contents, `error.StreamTooLong` is returned.
/// If end-of-stream is found, `error.EndOfStream` is returned.
/// Returns a slice of the stream data, with ptr equal to `buf.ptr`. The
/// delimiter byte is written to the output buffer but is not included
/// in the returned slice.
pub fn read_until_delimiter(self: Self, buf: []u8, delimiter: u8) anyerror![]u8 {
    var fbs = std.io.fixed_buffer_stream(buf);
    try self.stream_until_delimiter(fbs.writer(), delimiter, fbs.buffer.len);
    const output = fbs.get_written();
    buf[output.len] = delimiter; // emulating old behaviour
    return output;
}

/// Deprecated: use `stream_until_delimiter` with ArrayList's (or any other's) writer instead.
/// Allocates enough memory to read until `delimiter` or end-of-stream.
/// If the allocated memory would be greater than `max_size`, returns
/// `error.StreamTooLong`. If end-of-stream is found, returns the rest
/// of the stream. If this function is called again after that, returns
/// null.
/// Caller owns returned memory.
/// If this function returns an error, the contents from the stream read so far are lost.
pub fn read_until_delimiter_or_eof_alloc(
    self: Self,
    allocator: mem.Allocator,
    delimiter: u8,
    max_size: usize,
) anyerror!?[]u8 {
    var array_list = std.ArrayList(u8).init(allocator);
    defer array_list.deinit();
    self.stream_until_delimiter(array_list.writer(), delimiter, max_size) catch |err| switch (err) {
        error.EndOfStream => if (array_list.items.len == 0) {
            return null;
        },
        else => |e| return e,
    };
    return try array_list.to_owned_slice();
}

/// Deprecated: use `stream_until_delimiter` with FixedBufferStream's writer instead.
/// Reads from the stream until specified byte is found. If the buffer is not
/// large enough to hold the entire contents, `error.StreamTooLong` is returned.
/// If end-of-stream is found, returns the rest of the stream. If this
/// function is called again after that, returns null.
/// Returns a slice of the stream data, with ptr equal to `buf.ptr`. The
/// delimiter byte is written to the output buffer but is not included
/// in the returned slice.
pub fn read_until_delimiter_or_eof(self: Self, buf: []u8, delimiter: u8) anyerror!?[]u8 {
    var fbs = std.io.fixed_buffer_stream(buf);
    self.stream_until_delimiter(fbs.writer(), delimiter, fbs.buffer.len) catch |err| switch (err) {
        error.EndOfStream => if (fbs.get_written().len == 0) {
            return null;
        },

        else => |e| return e,
    };
    const output = fbs.get_written();
    buf[output.len] = delimiter; // emulating old behaviour
    return output;
}

/// Appends to the `writer` contents by reading from the stream until `delimiter` is found.
/// Does not write the delimiter itself.
/// If `optional_max_size` is not null and amount of written bytes exceeds `optional_max_size`,
/// returns `error.StreamTooLong` and finishes appending.
/// If `optional_max_size` is null, appending is unbounded.
pub fn stream_until_delimiter(
    self: Self,
    writer: anytype,
    delimiter: u8,
    optional_max_size: ?usize,
) anyerror!void {
    if (optional_max_size) |max_size| {
        for (0..max_size) |_| {
            const byte: u8 = try self.read_byte();
            if (byte == delimiter) return;
            try writer.write_byte(byte);
        }
        return error.StreamTooLong;
    } else {
        while (true) {
            const byte: u8 = try self.read_byte();
            if (byte == delimiter) return;
            try writer.write_byte(byte);
        }
        // Can not throw `error.StreamTooLong` since there are no boundary.
    }
}

/// Reads from the stream until specified byte is found, discarding all data,
/// including the delimiter.
/// If end-of-stream is found, this function succeeds.
pub fn skip_until_delimiter_or_eof(self: Self, delimiter: u8) anyerror!void {
    while (true) {
        const byte = self.read_byte() catch |err| switch (err) {
            error.EndOfStream => return,
            else => |e| return e,
        };
        if (byte == delimiter) return;
    }
}

/// Reads 1 byte from the stream or returns `error.EndOfStream`.
pub fn read_byte(self: Self) anyerror!u8 {
    var result: [1]u8 = undefined;
    const amt_read = try self.read(result[0..]);
    if (amt_read < 1) return error.EndOfStream;
    return result[0];
}

/// Same as `read_byte` except the returned byte is signed.
pub fn read_byte_signed(self: Self) anyerror!i8 {
    return @as(i8, @bit_cast(try self.read_byte()));
}

/// Reads exactly `num_bytes` bytes and returns as an array.
/// `num_bytes` must be comptime-known
pub fn read_bytes_no_eof(self: Self, comptime num_bytes: usize) anyerror![num_bytes]u8 {
    var bytes: [num_bytes]u8 = undefined;
    try self.read_no_eof(&bytes);
    return bytes;
}

/// Reads bytes until `bounded.len` is equal to `num_bytes`,
/// or the stream ends.
///
/// * it is assumed that `num_bytes` will not exceed `bounded.capacity()`
pub fn read_into_bounded_bytes(
    self: Self,
    comptime num_bytes: usize,
    bounded: *std.BoundedArray(u8, num_bytes),
) anyerror!void {
    while (bounded.len < num_bytes) {
        // get at most the number of bytes free in the bounded array
        const bytes_read = try self.read(bounded.unused_capacity_slice());
        if (bytes_read == 0) return;

        // bytes_read will never be larger than @TypeOf(bounded.len)
        // due to `self.read` being bounded by `bounded.unused_capacity_slice()`
        bounded.len += @as(@TypeOf(bounded.len), @int_cast(bytes_read));
    }
}

/// Reads at most `num_bytes` and returns as a bounded array.
pub fn read_bounded_bytes(self: Self, comptime num_bytes: usize) anyerror!std.BoundedArray(u8, num_bytes) {
    var result = std.BoundedArray(u8, num_bytes){};
    try self.read_into_bounded_bytes(num_bytes, &result);
    return result;
}

pub inline fn read_int(self: Self, comptime T: type, endian: std.builtin.Endian) anyerror!T {
    const bytes = try self.read_bytes_no_eof(@div_exact(@typeInfo(T).Int.bits, 8));
    return mem.read_int(T, &bytes, endian);
}

pub fn read_var_int(
    self: Self,
    comptime ReturnType: type,
    endian: std.builtin.Endian,
    size: usize,
) anyerror!ReturnType {
    assert(size <= @size_of(ReturnType));
    var bytes_buf: [@size_of(ReturnType)]u8 = undefined;
    const bytes = bytes_buf[0..size];
    try self.read_no_eof(bytes);
    return mem.read_var_int(ReturnType, bytes, endian);
}

/// Optional parameters for `skip_bytes`
pub const SkipBytesOptions = struct {
    buf_size: usize = 512,
};

// `num_bytes` is a `u64` to match `off_t`
/// Reads `num_bytes` bytes from the stream and discards them
pub fn skip_bytes(self: Self, num_bytes: u64, comptime options: SkipBytesOptions) anyerror!void {
    var buf: [options.buf_size]u8 = undefined;
    var remaining = num_bytes;

    while (remaining > 0) {
        const amt = @min(remaining, options.buf_size);
        try self.read_no_eof(buf[0..amt]);
        remaining -= amt;
    }
}

/// Reads `slice.len` bytes from the stream and returns if they are the same as the passed slice
pub fn is_bytes(self: Self, slice: []const u8) anyerror!bool {
    var i: usize = 0;
    var matches = true;
    while (i < slice.len) : (i += 1) {
        if (slice[i] != try self.read_byte()) {
            matches = false;
        }
    }
    return matches;
}

pub fn read_struct(self: Self, comptime T: type) anyerror!T {
    // Only extern and packed structs have defined in-memory layout.
    comptime assert(@typeInfo(T).Struct.layout != .auto);
    var res: [1]T = undefined;
    try self.read_no_eof(mem.slice_as_bytes(res[0..]));
    return res[0];
}

pub fn read_struct_endian(self: Self, comptime T: type, endian: std.builtin.Endian) anyerror!T {
    var res = try self.read_struct(T);
    if (native_endian != endian) {
        mem.byte_swap_all_fields(T, &res);
    }
    return res;
}

/// Reads an integer with the same size as the given enum's tag type. If the integer matches
/// an enum tag, casts the integer to the enum tag and returns it. Otherwise, returns an `error.InvalidValue`.
/// TODO optimization taking advantage of most fields being in order
pub fn read_enum(self: Self, comptime Enum: type, endian: std.builtin.Endian) anyerror!Enum {
    const E = error{
        /// An integer was read, but it did not match any of the tags in the supplied enum.
        InvalidValue,
    };
    const type_info = @typeInfo(Enum).Enum;
    const tag = try self.read_int(type_info.tag_type, endian);

    inline for (std.meta.fields(Enum)) |field| {
        if (tag == field.value) {
            return @field(Enum, field.name);
        }
    }

    return E.InvalidValue;
}

/// Reads the stream until the end, ignoring all the data.
/// Returns the number of bytes discarded.
pub fn discard(self: Self) anyerror!u64 {
    var trash: [4096]u8 = undefined;
    var index: u64 = 0;
    while (true) {
        const n = try self.read(&trash);
        if (n == 0) return index;
        index += n;
    }
}

const std = @import("../std.zig");
const Self = @This();
const math = std.math;
const assert = std.debug.assert;
const mem = std.mem;
const testing = std.testing;
const native_endian = @import("builtin").target.cpu.arch.endian();

test {
    _ = @import("Reader/test.zig");
}
