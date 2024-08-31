in: std.fs.File,
out: std.fs.File,
receive_fifo: std.fifo.LinearFifo(u8, .Dynamic),

pub const Message = struct {
    pub const Header = extern struct {
        tag: Tag,
        /// Size of the body only; does not include this Header.
        bytes_len: u32,
    };

    pub const Tag = enum(u32) {
        /// Body is a UTF-8 string.
        zig_version,
        /// Body is an ErrorBundle.
        error_bundle,
        /// Body is a EmitBinPath.
        emit_bin_path,
        /// Body is a TestMetadata
        test_metadata,
        /// Body is a TestResults
        test_results,

        _,
    };

    /// Trailing:
    /// * extra: [extra_len]u32,
    /// * string_bytes: [string_bytes_len]u8,
    /// See `std.zig.ErrorBundle`.
    pub const ErrorBundle = extern struct {
        extra_len: u32,
        string_bytes_len: u32,
    };

    /// Trailing:
    /// * name: [tests_len]u32
    ///   - null-terminated string_bytes index
    /// * expected_panic_msg: [tests_len]u32,
    ///   - null-terminated string_bytes index
    ///   - 0 means does not expect pani
    /// * string_bytes: [string_bytes_len]u8,
    pub const TestMetadata = extern struct {
        string_bytes_len: u32,
        tests_len: u32,
    };

    pub const TestResults = extern struct {
        index: u32,
        flags: Flags,

        pub const Flags = packed struct(u32) {
            fail: bool,
            skip: bool,
            leak: bool,
            log_err_count: u29 = 0,
        };
    };

    /// Trailing:
    /// * the file system path the emitted binary can be found
    pub const EmitBinPath = extern struct {
        flags: Flags,

        pub const Flags = packed struct(u8) {
            cache_hit: bool,
            reserved: u7 = 0,
        };
    };
};

pub const Options = struct {
    gpa: Allocator,
    in: std.fs.File,
    out: std.fs.File,
    zig_version: []const u8,
};

pub fn init(options: Options) !Server {
    var s: Server = .{
        .in = options.in,
        .out = options.out,
        .receive_fifo = std.fifo.LinearFifo(u8, .Dynamic).init(options.gpa),
    };
    try s.serve_string_message(.zig_version, options.zig_version);
    return s;
}

pub fn deinit(s: *Server) void {
    s.receive_fifo.deinit();
    s.* = undefined;
}

pub fn receive_message(s: *Server) !InMessage.Header {
    const Header = InMessage.Header;
    const fifo = &s.receive_fifo;

    while (true) {
        const buf = fifo.readable_slice(0);
        assert(fifo.readable_length() == buf.len);
        if (buf.len >= @size_of(Header)) {
            // workaround for https://github.com/ziglang/zig/issues/14904
            const bytes_len = bswap_and_workaround_u32(buf[4..][0..4]);
            const tag = bswap_and_workaround_tag(buf[0..][0..4]);

            if (buf.len - @size_of(Header) >= bytes_len) {
                fifo.discard(@size_of(Header));
                return .{
                    .tag = tag,
                    .bytes_len = bytes_len,
                };
            } else {
                const needed = bytes_len - (buf.len - @size_of(Header));
                const write_buffer = try fifo.writable_with_size(needed);
                const amt = try s.in.read(write_buffer);
                fifo.update(amt);
                continue;
            }
        }

        const write_buffer = try fifo.writable_with_size(256);
        const amt = try s.in.read(write_buffer);
        fifo.update(amt);
    }
}

pub fn receive_body_u32(s: *Server) !u32 {
    const fifo = &s.receive_fifo;
    const buf = fifo.readable_slice(0);
    const result = @as(*align(1) const u32, @ptr_cast(buf[0..4])).*;
    fifo.discard(4);
    return bswap(result);
}

pub fn serve_string_message(s: *Server, tag: OutMessage.Tag, msg: []const u8) !void {
    return s.serve_message(.{
        .tag = tag,
        .bytes_len = @as(u32, @int_cast(msg.len)),
    }, &.{msg});
}

pub fn serve_message(
    s: *const Server,
    header: OutMessage.Header,
    bufs: []const []const u8,
) !void {
    var iovecs: [10]std.posix.iovec_const = undefined;
    const header_le = bswap(header);
    iovecs[0] = .{
        .base = @as([*]const u8, @ptr_cast(&header_le)),
        .len = @size_of(OutMessage.Header),
    };
    for (bufs, iovecs[1 .. bufs.len + 1]) |buf, *iovec| {
        iovec.* = .{
            .base = buf.ptr,
            .len = buf.len,
        };
    }
    try s.out.writev_all(iovecs[0 .. bufs.len + 1]);
}

pub fn serve_emit_bin_path(
    s: *Server,
    fs_path: []const u8,
    header: OutMessage.EmitBinPath,
) !void {
    try s.serve_message(.{
        .tag = .emit_bin_path,
        .bytes_len = @as(u32, @int_cast(fs_path.len + @size_of(OutMessage.EmitBinPath))),
    }, &.{
        std.mem.as_bytes(&header),
        fs_path,
    });
}

pub fn serve_test_results(
    s: *Server,
    msg: OutMessage.TestResults,
) !void {
    const msg_le = bswap(msg);
    try s.serve_message(.{
        .tag = .test_results,
        .bytes_len = @as(u32, @int_cast(@size_of(OutMessage.TestResults))),
    }, &.{
        std.mem.as_bytes(&msg_le),
    });
}

pub fn serve_error_bundle(s: *Server, error_bundle: std.zig.ErrorBundle) !void {
    const eb_hdr: OutMessage.ErrorBundle = .{
        .extra_len = @as(u32, @int_cast(error_bundle.extra.len)),
        .string_bytes_len = @as(u32, @int_cast(error_bundle.string_bytes.len)),
    };
    const bytes_len = @size_of(OutMessage.ErrorBundle) +
        4 * error_bundle.extra.len + error_bundle.string_bytes.len;
    try s.serve_message(.{
        .tag = .error_bundle,
        .bytes_len = @as(u32, @int_cast(bytes_len)),
    }, &.{
        std.mem.as_bytes(&eb_hdr),
        // TODO: implement @ptr_cast between slices changing the length
        std.mem.slice_as_bytes(error_bundle.extra),
        error_bundle.string_bytes,
    });
}

pub const TestMetadata = struct {
    names: []u32,
    expected_panic_msgs: []u32,
    string_bytes: []const u8,
};

pub fn serve_test_metadata(s: *Server, test_metadata: TestMetadata) !void {
    const header: OutMessage.TestMetadata = .{
        .tests_len = bswap(@as(u32, @int_cast(test_metadata.names.len))),
        .string_bytes_len = bswap(@as(u32, @int_cast(test_metadata.string_bytes.len))),
    };
    const trailing = 2;
    const bytes_len = @size_of(OutMessage.TestMetadata) +
        trailing * @size_of(u32) * test_metadata.names.len + test_metadata.string_bytes.len;

    if (need_bswap) {
        bswap_u32_array(test_metadata.names);
        bswap_u32_array(test_metadata.expected_panic_msgs);
    }
    defer if (need_bswap) {
        bswap_u32_array(test_metadata.names);
        bswap_u32_array(test_metadata.expected_panic_msgs);
    };

    return s.serve_message(.{
        .tag = .test_metadata,
        .bytes_len = @as(u32, @int_cast(bytes_len)),
    }, &.{
        std.mem.as_bytes(&header),
        // TODO: implement @ptr_cast between slices changing the length
        std.mem.slice_as_bytes(test_metadata.names),
        std.mem.slice_as_bytes(test_metadata.expected_panic_msgs),
        test_metadata.string_bytes,
    });
}

fn bswap(x: anytype) @TypeOf(x) {
    if (!need_bswap) return x;

    const T = @TypeOf(x);
    switch (@typeInfo(T)) {
        .Enum => return @as(T, @enumFromInt(@byte_swap(@int_from_enum(x)))),
        .Int => return @byte_swap(x),
        .Struct => |info| switch (info.layout) {
            .@"extern" => {
                var result: T = undefined;
                inline for (info.fields) |field| {
                    @field(result, field.name) = bswap(@field(x, field.name));
                }
                return result;
            },
            .@"packed" => {
                const I = info.backing_integer.?;
                return @as(T, @bit_cast(@byte_swap(@as(I, @bit_cast(x)))));
            },
            .auto => @compile_error("auto layout struct"),
        },
        else => @compile_error("bswap on type " ++ @type_name(T)),
    }
}

fn bswap_u32_array(slice: []u32) void {
    comptime assert(need_bswap);
    for (slice) |*elem| elem.* = @byte_swap(elem.*);
}

/// workaround for https://github.com/ziglang/zig/issues/14904
fn bswap_and_workaround_u32(bytes_ptr: *const [4]u8) u32 {
    return std.mem.read_int(u32, bytes_ptr, .little);
}

/// workaround for https://github.com/ziglang/zig/issues/14904
fn bswap_and_workaround_tag(bytes_ptr: *const [4]u8) InMessage.Tag {
    const int = std.mem.read_int(u32, bytes_ptr, .little);
    return @as(InMessage.Tag, @enumFromInt(int));
}

const OutMessage = std.zig.Server.Message;
const InMessage = std.zig.Client.Message;

const Server = @This();
const builtin = @import("builtin");
const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const native_endian = builtin.target.cpu.arch.endian();
const need_bswap = native_endian != .little;
