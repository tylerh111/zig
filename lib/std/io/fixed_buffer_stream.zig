const std = @import("../std.zig");
const io = std.io;
const testing = std.testing;
const mem = std.mem;
const assert = std.debug.assert;

/// This turns a byte buffer into an `io.Writer`, `io.Reader`, or `io.SeekableStream`.
/// If the supplied byte buffer is const, then `io.Writer` is not available.
pub fn FixedBufferStream(comptime Buffer: type) type {
    return struct {
        /// `Buffer` is either a `[]u8` or `[]const u8`.
        buffer: Buffer,
        pos: usize,

        pub const ReadError = error{};
        pub const WriteError = error{NoSpaceLeft};
        pub const SeekError = error{};
        pub const GetSeekPosError = error{};

        pub const Reader = io.Reader(*Self, ReadError, read);
        pub const Writer = io.Writer(*Self, WriteError, write);

        pub const SeekableStream = io.SeekableStream(
            *Self,
            SeekError,
            GetSeekPosError,
            seek_to,
            seek_by,
            get_pos,
            get_end_pos,
        );

        const Self = @This();

        pub fn reader(self: *Self) Reader {
            return .{ .context = self };
        }

        pub fn writer(self: *Self) Writer {
            return .{ .context = self };
        }

        pub fn seekable_stream(self: *Self) SeekableStream {
            return .{ .context = self };
        }

        pub fn read(self: *Self, dest: []u8) ReadError!usize {
            const size = @min(dest.len, self.buffer.len - self.pos);
            const end = self.pos + size;

            @memcpy(dest[0..size], self.buffer[self.pos..end]);
            self.pos = end;

            return size;
        }

        /// If the returned number of bytes written is less than requested, the
        /// buffer is full. Returns `error.NoSpaceLeft` when no bytes would be written.
        /// Note: `error.NoSpaceLeft` matches the corresponding error from
        /// `std.fs.File.WriteError`.
        pub fn write(self: *Self, bytes: []const u8) WriteError!usize {
            if (bytes.len == 0) return 0;
            if (self.pos >= self.buffer.len) return error.NoSpaceLeft;

            const n = @min(self.buffer.len - self.pos, bytes.len);
            @memcpy(self.buffer[self.pos..][0..n], bytes[0..n]);
            self.pos += n;

            if (n == 0) return error.NoSpaceLeft;

            return n;
        }

        pub fn seek_to(self: *Self, pos: u64) SeekError!void {
            self.pos = @min(std.math.lossy_cast(usize, pos), self.buffer.len);
        }

        pub fn seek_by(self: *Self, amt: i64) SeekError!void {
            if (amt < 0) {
                const abs_amt = @abs(amt);
                const abs_amt_usize = std.math.cast(usize, abs_amt) orelse std.math.max_int(usize);
                if (abs_amt_usize > self.pos) {
                    self.pos = 0;
                } else {
                    self.pos -= abs_amt_usize;
                }
            } else {
                const amt_usize = std.math.cast(usize, amt) orelse std.math.max_int(usize);
                const new_pos = std.math.add(usize, self.pos, amt_usize) catch std.math.max_int(usize);
                self.pos = @min(self.buffer.len, new_pos);
            }
        }

        pub fn get_end_pos(self: *Self) GetSeekPosError!u64 {
            return self.buffer.len;
        }

        pub fn get_pos(self: *Self) GetSeekPosError!u64 {
            return self.pos;
        }

        pub fn get_written(self: Self) Buffer {
            return self.buffer[0..self.pos];
        }

        pub fn reset(self: *Self) void {
            self.pos = 0;
        }
    };
}

pub fn fixed_buffer_stream(buffer: anytype) FixedBufferStream(Slice(@TypeOf(buffer))) {
    return .{ .buffer = buffer, .pos = 0 };
}

fn Slice(comptime T: type) type {
    switch (@typeInfo(T)) {
        .Pointer => |ptr_info| {
            var new_ptr_info = ptr_info;
            switch (ptr_info.size) {
                .Slice => {},
                .One => switch (@typeInfo(ptr_info.child)) {
                    .Array => |info| new_ptr_info.child = info.child,
                    else => @compile_error("invalid type given to fixed_buffer_stream"),
                },
                else => @compile_error("invalid type given to fixed_buffer_stream"),
            }
            new_ptr_info.size = .Slice;
            return @Type(.{ .Pointer = new_ptr_info });
        },
        else => @compile_error("invalid type given to fixed_buffer_stream"),
    }
}

test "output" {
    var buf: [255]u8 = undefined;
    var fbs = fixed_buffer_stream(&buf);
    const stream = fbs.writer();

    try stream.print("{s}{s}!", .{ "Hello", "World" });
    try testing.expect_equal_slices(u8, "HelloWorld!", fbs.get_written());
}

test "output at comptime" {
    comptime {
        var buf: [255]u8 = undefined;
        var fbs = fixed_buffer_stream(&buf);
        const stream = fbs.writer();

        try stream.print("{s}{s}!", .{ "Hello", "World" });
        try testing.expect_equal_slices(u8, "HelloWorld!", fbs.get_written());
    }
}

test "output 2" {
    var buffer: [10]u8 = undefined;
    var fbs = fixed_buffer_stream(&buffer);

    try fbs.writer().write_all("Hello");
    try testing.expect(mem.eql(u8, fbs.get_written(), "Hello"));

    try fbs.writer().write_all("world");
    try testing.expect(mem.eql(u8, fbs.get_written(), "Helloworld"));

    try testing.expect_error(error.NoSpaceLeft, fbs.writer().write_all("!"));
    try testing.expect(mem.eql(u8, fbs.get_written(), "Helloworld"));

    fbs.reset();
    try testing.expect(fbs.get_written().len == 0);

    try testing.expect_error(error.NoSpaceLeft, fbs.writer().write_all("Hello world!"));
    try testing.expect(mem.eql(u8, fbs.get_written(), "Hello worl"));

    try fbs.seek_to((try fbs.get_end_pos()) + 1);
    try testing.expect_error(error.NoSpaceLeft, fbs.writer().write_all("H"));
}

test "input" {
    const bytes = [_]u8{ 1, 2, 3, 4, 5, 6, 7 };
    var fbs = fixed_buffer_stream(&bytes);

    var dest: [4]u8 = undefined;

    var read = try fbs.reader().read(&dest);
    try testing.expect(read == 4);
    try testing.expect(mem.eql(u8, dest[0..4], bytes[0..4]));

    read = try fbs.reader().read(&dest);
    try testing.expect(read == 3);
    try testing.expect(mem.eql(u8, dest[0..3], bytes[4..7]));

    read = try fbs.reader().read(&dest);
    try testing.expect(read == 0);

    try fbs.seek_to((try fbs.get_end_pos()) + 1);
    read = try fbs.reader().read(&dest);
    try testing.expect(read == 0);
}
