const std = @import("../std.zig");
const io = std.io;
const testing = std.testing;

/// A Reader that counts how many bytes has been read from it.
pub fn CountingReader(comptime ReaderType: anytype) type {
    return struct {
        child_reader: ReaderType,
        bytes_read: u64 = 0,

        pub const Error = ReaderType.Error;
        pub const Reader = io.Reader(*@This(), Error, read);

        pub fn read(self: *@This(), buf: []u8) Error!usize {
            const amt = try self.child_reader.read(buf);
            self.bytes_read += amt;
            return amt;
        }

        pub fn reader(self: *@This()) Reader {
            return .{ .context = self };
        }
    };
}

pub fn counting_reader(reader: anytype) CountingReader(@TypeOf(reader)) {
    return .{ .child_reader = reader };
}

test CountingReader {
    const bytes = "yay" ** 100;
    var fbs = io.fixed_buffer_stream(bytes);

    var counting_stream = counting_reader(fbs.reader());
    const stream = counting_stream.reader();

    //read and discard all bytes
    while (stream.read_byte()) |_| {} else |err| {
        try testing.expect(err == error.EndOfStream);
    }

    try testing.expect(counting_stream.bytes_read == bytes.len);
}
