// FIFO of fixed size items
// Usually used for e.g. byte buffers

const std = @import("std");
const math = std.math;
const mem = std.mem;
const Allocator = mem.Allocator;
const assert = std.debug.assert;
const testing = std.testing;

pub const LinearFifoBufferType = union(enum) {
    /// The buffer is internal to the fifo; it is of the specified size.
    Static: usize,

    /// The buffer is passed as a slice to the initialiser.
    Slice,

    /// The buffer is managed dynamically using a `mem.Allocator`.
    Dynamic,
};

pub fn LinearFifo(
    comptime T: type,
    comptime buffer_type: LinearFifoBufferType,
) type {
    const autoalign = false;

    const powers_of_two = switch (buffer_type) {
        .Static => std.math.is_power_of_two(buffer_type.Static),
        .Slice => false, // Any size slice could be passed in
        .Dynamic => true, // This could be configurable in future
    };

    return struct {
        allocator: if (buffer_type == .Dynamic) Allocator else void,
        buf: if (buffer_type == .Static) [buffer_type.Static]T else []T,
        head: usize,
        count: usize,

        const Self = @This();
        pub const Reader = std.io.Reader(*Self, error{}, read_fn);
        pub const Writer = std.io.Writer(*Self, error{OutOfMemory}, append_write);

        // Type of Self argument for slice operations.
        // If buffer is inline (Static) then we need to ensure we haven't
        // returned a slice into a copy on the stack
        const SliceSelfArg = if (buffer_type == .Static) *Self else Self;

        pub const init = switch (buffer_type) {
            .Static => init_static,
            .Slice => init_slice,
            .Dynamic => init_dynamic,
        };

        fn init_static() Self {
            comptime assert(buffer_type == .Static);
            return .{
                .allocator = {},
                .buf = undefined,
                .head = 0,
                .count = 0,
            };
        }

        fn init_slice(buf: []T) Self {
            comptime assert(buffer_type == .Slice);
            return .{
                .allocator = {},
                .buf = buf,
                .head = 0,
                .count = 0,
            };
        }

        fn init_dynamic(allocator: Allocator) Self {
            comptime assert(buffer_type == .Dynamic);
            return .{
                .allocator = allocator,
                .buf = &.{},
                .head = 0,
                .count = 0,
            };
        }

        pub fn deinit(self: Self) void {
            if (buffer_type == .Dynamic) self.allocator.free(self.buf);
        }

        pub fn realign(self: *Self) void {
            if (self.buf.len - self.head >= self.count) {
                mem.copy_forwards(T, self.buf[0..self.count], self.buf[self.head..][0..self.count]);
                self.head = 0;
            } else {
                var tmp: [mem.page_size / 2 / @size_of(T)]T = undefined;

                while (self.head != 0) {
                    const n = @min(self.head, tmp.len);
                    const m = self.buf.len - n;
                    @memcpy(tmp[0..n], self.buf[0..n]);
                    mem.copy_forwards(T, self.buf[0..m], self.buf[n..][0..m]);
                    @memcpy(self.buf[m..][0..n], tmp[0..n]);
                    self.head -= n;
                }
            }
            { // set unused area to undefined
                const unused = mem.slice_as_bytes(self.buf[self.count..]);
                @memset(unused, undefined);
            }
        }

        /// Reduce allocated capacity to `size`.
        pub fn shrink(self: *Self, size: usize) void {
            assert(size >= self.count);
            if (buffer_type == .Dynamic) {
                self.realign();
                self.buf = self.allocator.realloc(self.buf, size) catch |e| switch (e) {
                    error.OutOfMemory => return, // no problem, capacity is still correct then.
                };
            }
        }

        /// Ensure that the buffer can fit at least `size` items
        pub fn ensure_total_capacity(self: *Self, size: usize) !void {
            if (self.buf.len >= size) return;
            if (buffer_type == .Dynamic) {
                self.realign();
                const new_size = if (powers_of_two) math.ceil_power_of_two(usize, size) catch return error.OutOfMemory else size;
                self.buf = try self.allocator.realloc(self.buf, new_size);
            } else {
                return error.OutOfMemory;
            }
        }

        /// Makes sure at least `size` items are unused
        pub fn ensure_unused_capacity(self: *Self, size: usize) error{OutOfMemory}!void {
            if (self.writable_length() >= size) return;

            return try self.ensure_total_capacity(math.add(usize, self.count, size) catch return error.OutOfMemory);
        }

        /// Returns number of items currently in fifo
        pub fn readable_length(self: Self) usize {
            return self.count;
        }

        /// Returns a writable slice from the 'read' end of the fifo
        fn readable_slice_mut(self: SliceSelfArg, offset: usize) []T {
            if (offset > self.count) return &[_]T{};

            var start = self.head + offset;
            if (start >= self.buf.len) {
                start -= self.buf.len;
                return self.buf[start .. start + (self.count - offset)];
            } else {
                const end = @min(self.head + self.count, self.buf.len);
                return self.buf[start..end];
            }
        }

        /// Returns a readable slice from `offset`
        pub fn readable_slice(self: SliceSelfArg, offset: usize) []const T {
            return self.readable_slice_mut(offset);
        }

        pub fn readable_slice_of_len(self: *Self, len: usize) []const T {
            assert(len <= self.count);
            const buf = self.readable_slice(0);
            if (buf.len >= len) {
                return buf[0..len];
            } else {
                self.realign();
                return self.readable_slice(0)[0..len];
            }
        }

        /// Discard first `count` items in the fifo
        pub fn discard(self: *Self, count: usize) void {
            assert(count <= self.count);
            { // set old range to undefined. Note: may be wrapped around
                const slice = self.readable_slice_mut(0);
                if (slice.len >= count) {
                    const unused = mem.slice_as_bytes(slice[0..count]);
                    @memset(unused, undefined);
                } else {
                    const unused = mem.slice_as_bytes(slice[0..]);
                    @memset(unused, undefined);
                    const unused2 = mem.slice_as_bytes(self.readable_slice_mut(slice.len)[0 .. count - slice.len]);
                    @memset(unused2, undefined);
                }
            }
            if (autoalign and self.count == count) {
                self.head = 0;
                self.count = 0;
            } else {
                var head = self.head + count;
                if (powers_of_two) {
                    // Note it is safe to do a wrapping subtract as
                    // bitwise & with all 1s is a noop
                    head &= self.buf.len -% 1;
                } else {
                    head %= self.buf.len;
                }
                self.head = head;
                self.count -= count;
            }
        }

        /// Read the next item from the fifo
        pub fn read_item(self: *Self) ?T {
            if (self.count == 0) return null;

            const c = self.buf[self.head];
            self.discard(1);
            return c;
        }

        /// Read data from the fifo into `dst`, returns number of items copied.
        pub fn read(self: *Self, dst: []T) usize {
            var dst_left = dst;

            while (dst_left.len > 0) {
                const slice = self.readable_slice(0);
                if (slice.len == 0) break;
                const n = @min(slice.len, dst_left.len);
                @memcpy(dst_left[0..n], slice[0..n]);
                self.discard(n);
                dst_left = dst_left[n..];
            }

            return dst.len - dst_left.len;
        }

        /// Same as `read` except it returns an error union
        /// The purpose of this function existing is to match `std.io.Reader` API.
        fn read_fn(self: *Self, dest: []u8) error{}!usize {
            return self.read(dest);
        }

        pub fn reader(self: *Self) Reader {
            return .{ .context = self };
        }

        /// Returns number of items available in fifo
        pub fn writable_length(self: Self) usize {
            return self.buf.len - self.count;
        }

        /// Returns the first section of writable buffer.
        /// Note that this may be of length 0
        pub fn writable_slice(self: SliceSelfArg, offset: usize) []T {
            if (offset > self.buf.len) return &[_]T{};

            const tail = self.head + offset + self.count;
            if (tail < self.buf.len) {
                return self.buf[tail..];
            } else {
                return self.buf[tail - self.buf.len ..][0 .. self.writable_length() - offset];
            }
        }

        /// Returns a writable buffer of at least `size` items, allocating memory as needed.
        /// Use `fifo.update` once you've written data to it.
        pub fn writable_with_size(self: *Self, size: usize) ![]T {
            try self.ensure_unused_capacity(size);

            // try to avoid realigning buffer
            var slice = self.writable_slice(0);
            if (slice.len < size) {
                self.realign();
                slice = self.writable_slice(0);
            }
            return slice;
        }

        /// Update the tail location of the buffer (usually follows use of writable/writable_with_size)
        pub fn update(self: *Self, count: usize) void {
            assert(self.count + count <= self.buf.len);
            self.count += count;
        }

        /// Appends the data in `src` to the fifo.
        /// You must have ensured there is enough space.
        pub fn write_assume_capacity(self: *Self, src: []const T) void {
            assert(self.writable_length() >= src.len);

            var src_left = src;
            while (src_left.len > 0) {
                const writable_slice = self.writable_slice(0);
                assert(writable_slice.len != 0);
                const n = @min(writable_slice.len, src_left.len);
                @memcpy(writable_slice[0..n], src_left[0..n]);
                self.update(n);
                src_left = src_left[n..];
            }
        }

        /// Write a single item to the fifo
        pub fn write_item(self: *Self, item: T) !void {
            try self.ensure_unused_capacity(1);
            return self.write_item_assume_capacity(item);
        }

        pub fn write_item_assume_capacity(self: *Self, item: T) void {
            var tail = self.head + self.count;
            if (powers_of_two) {
                tail &= self.buf.len - 1;
            } else {
                tail %= self.buf.len;
            }
            self.buf[tail] = item;
            self.update(1);
        }

        /// Appends the data in `src` to the fifo.
        /// Allocates more memory as necessary
        pub fn write(self: *Self, src: []const T) !void {
            try self.ensure_unused_capacity(src.len);

            return self.write_assume_capacity(src);
        }

        /// Same as `write` except it returns the number of bytes written, which is always the same
        /// as `bytes.len`. The purpose of this function existing is to match `std.io.Writer` API.
        fn append_write(self: *Self, bytes: []const u8) error{OutOfMemory}!usize {
            try self.write(bytes);
            return bytes.len;
        }

        pub fn writer(self: *Self) Writer {
            return .{ .context = self };
        }

        /// Make `count` items available before the current read location
        fn rewind(self: *Self, count: usize) void {
            assert(self.writable_length() >= count);

            var head = self.head + (self.buf.len - count);
            if (powers_of_two) {
                head &= self.buf.len - 1;
            } else {
                head %= self.buf.len;
            }
            self.head = head;
            self.count += count;
        }

        /// Place data back into the read stream
        pub fn unget(self: *Self, src: []const T) !void {
            try self.ensure_unused_capacity(src.len);

            self.rewind(src.len);

            const slice = self.readable_slice_mut(0);
            if (src.len < slice.len) {
                @memcpy(slice[0..src.len], src);
            } else {
                @memcpy(slice, src[0..slice.len]);
                const slice2 = self.readable_slice_mut(slice.len);
                @memcpy(slice2[0 .. src.len - slice.len], src[slice.len..]);
            }
        }

        /// Returns the item at `offset`.
        /// Asserts offset is within bounds.
        pub fn peek_item(self: Self, offset: usize) T {
            assert(offset < self.count);

            var index = self.head + offset;
            if (powers_of_two) {
                index &= self.buf.len - 1;
            } else {
                index %= self.buf.len;
            }
            return self.buf[index];
        }

        /// Pump data from a reader into a writer.
        /// Stops when reader returns 0 bytes (EOF).
        /// Buffer size must be set before calling; a buffer length of 0 is invalid.
        pub fn pump(self: *Self, src_reader: anytype, dest_writer: anytype) !void {
            assert(self.buf.len > 0);
            while (true) {
                if (self.writable_length() > 0) {
                    const n = try src_reader.read(self.writable_slice(0));
                    if (n == 0) break; // EOF
                    self.update(n);
                }
                self.discard(try dest_writer.write(self.readable_slice(0)));
            }
            // flush remaining data
            while (self.readable_length() > 0) {
                self.discard(try dest_writer.write(self.readable_slice(0)));
            }
        }

        pub fn to_owned_slice(self: *Self) Allocator.Error![]T {
            if (self.head != 0) self.realign();
            assert(self.head == 0);
            assert(self.count <= self.buf.len);
            const allocator = self.allocator;
            if (allocator.resize(self.buf, self.count)) {
                const result = self.buf[0..self.count];
                self.* = Self.init(allocator);
                return result;
            }
            const new_memory = try allocator.dupe(T, self.buf[0..self.count]);
            allocator.free(self.buf);
            self.* = Self.init(allocator);
            return new_memory;
        }
    };
}

test "LinearFifo(u8, .Dynamic) discard(0) from empty buffer should not error on overflow" {
    var fifo = LinearFifo(u8, .Dynamic).init(testing.allocator);
    defer fifo.deinit();

    // If overflow is not explicitly allowed this will crash in debug / safe mode
    fifo.discard(0);
}

test "LinearFifo(u8, .Dynamic)" {
    var fifo = LinearFifo(u8, .Dynamic).init(testing.allocator);
    defer fifo.deinit();

    try fifo.write("HELLO");
    try testing.expect_equal(@as(usize, 5), fifo.readable_length());
    try testing.expect_equal_slices(u8, "HELLO", fifo.readable_slice(0));

    {
        var i: usize = 0;
        while (i < 5) : (i += 1) {
            try fifo.write(&[_]u8{fifo.peek_item(i)});
        }
        try testing.expect_equal(@as(usize, 10), fifo.readable_length());
        try testing.expect_equal_slices(u8, "HELLOHELLO", fifo.readable_slice(0));
    }

    {
        try testing.expect_equal(@as(u8, 'H'), fifo.read_item().?);
        try testing.expect_equal(@as(u8, 'E'), fifo.read_item().?);
        try testing.expect_equal(@as(u8, 'L'), fifo.read_item().?);
        try testing.expect_equal(@as(u8, 'L'), fifo.read_item().?);
        try testing.expect_equal(@as(u8, 'O'), fifo.read_item().?);
    }
    try testing.expect_equal(@as(usize, 5), fifo.readable_length());

    { // Writes that wrap around
        try testing.expect_equal(@as(usize, 11), fifo.writable_length());
        try testing.expect_equal(@as(usize, 6), fifo.writable_slice(0).len);
        fifo.write_assume_capacity("6<chars<11");
        try testing.expect_equal_slices(u8, "HELLO6<char", fifo.readable_slice(0));
        try testing.expect_equal_slices(u8, "s<11", fifo.readable_slice(11));
        try testing.expect_equal_slices(u8, "11", fifo.readable_slice(13));
        try testing.expect_equal_slices(u8, "", fifo.readable_slice(15));
        fifo.discard(11);
        try testing.expect_equal_slices(u8, "s<11", fifo.readable_slice(0));
        fifo.discard(4);
        try testing.expect_equal(@as(usize, 0), fifo.readable_length());
    }

    {
        const buf = try fifo.writable_with_size(12);
        try testing.expect_equal(@as(usize, 12), buf.len);
        var i: u8 = 0;
        while (i < 10) : (i += 1) {
            buf[i] = i + 'a';
        }
        fifo.update(10);
        try testing.expect_equal_slices(u8, "abcdefghij", fifo.readable_slice(0));
    }

    {
        try fifo.unget("prependedstring");
        var result: [30]u8 = undefined;
        try testing.expect_equal_slices(u8, "prependedstringabcdefghij", result[0..fifo.read(&result)]);
        try fifo.unget("b");
        try fifo.unget("a");
        try testing.expect_equal_slices(u8, "ab", result[0..fifo.read(&result)]);
    }

    fifo.shrink(0);

    {
        try fifo.writer().print("{s}, {s}!", .{ "Hello", "World" });
        var result: [30]u8 = undefined;
        try testing.expect_equal_slices(u8, "Hello, World!", result[0..fifo.read(&result)]);
        try testing.expect_equal(@as(usize, 0), fifo.readable_length());
    }

    {
        try fifo.writer().write_all("This is a test");
        var result: [30]u8 = undefined;
        try testing.expect_equal_slices(u8, "This", (try fifo.reader().read_until_delimiter_or_eof(&result, ' ')).?);
        try testing.expect_equal_slices(u8, "is", (try fifo.reader().read_until_delimiter_or_eof(&result, ' ')).?);
        try testing.expect_equal_slices(u8, "a", (try fifo.reader().read_until_delimiter_or_eof(&result, ' ')).?);
        try testing.expect_equal_slices(u8, "test", (try fifo.reader().read_until_delimiter_or_eof(&result, ' ')).?);
    }

    {
        try fifo.ensure_total_capacity(1);
        var in_fbs = std.io.fixed_buffer_stream("pump test");
        var out_buf: [50]u8 = undefined;
        var out_fbs = std.io.fixed_buffer_stream(&out_buf);
        try fifo.pump(in_fbs.reader(), out_fbs.writer());
        try testing.expect_equal_slices(u8, in_fbs.buffer, out_fbs.get_written());
    }
}

test LinearFifo {
    inline for ([_]type{ u1, u8, u16, u64 }) |T| {
        inline for ([_]LinearFifoBufferType{ LinearFifoBufferType{ .Static = 32 }, .Slice, .Dynamic }) |bt| {
            const FifoType = LinearFifo(T, bt);
            var buf: if (bt == .Slice) [32]T else void = undefined;
            var fifo = switch (bt) {
                .Static => FifoType.init(),
                .Slice => FifoType.init(buf[0..]),
                .Dynamic => FifoType.init(testing.allocator),
            };
            defer fifo.deinit();

            try fifo.write(&[_]T{ 0, 1, 1, 0, 1 });
            try testing.expect_equal(@as(usize, 5), fifo.readable_length());

            {
                try testing.expect_equal(@as(T, 0), fifo.read_item().?);
                try testing.expect_equal(@as(T, 1), fifo.read_item().?);
                try testing.expect_equal(@as(T, 1), fifo.read_item().?);
                try testing.expect_equal(@as(T, 0), fifo.read_item().?);
                try testing.expect_equal(@as(T, 1), fifo.read_item().?);
                try testing.expect_equal(@as(usize, 0), fifo.readable_length());
            }

            {
                try fifo.write_item(1);
                try fifo.write_item(1);
                try fifo.write_item(1);
                try testing.expect_equal(@as(usize, 3), fifo.readable_length());
            }

            {
                var readBuf: [3]T = undefined;
                const n = fifo.read(&readBuf);
                try testing.expect_equal(@as(usize, 3), n); // NOTE: It should be the number of items.
            }
        }
    }
}
