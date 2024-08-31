const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const RingBuffer = std.RingBuffer;

const types = @import("types.zig");
const frame = types.frame;
const LiteralsSection = types.compressed_block.LiteralsSection;
const SequencesSection = types.compressed_block.SequencesSection;
const SkippableHeader = types.frame.Skippable.Header;
const ZstandardHeader = types.frame.Zstandard.Header;
const Table = types.compressed_block.Table;

pub const block = @import("decode/block.zig");

const readers = @import("readers.zig");

/// Returns `true` is `magic` is a valid magic number for a skippable frame
pub fn is_skippable_magic(magic: u32) bool {
    return frame.Skippable.magic_number_min <= magic and magic <= frame.Skippable.magic_number_max;
}

/// Returns the kind of frame at the beginning of `source`.
///
/// Errors returned:
///   - `error.BadMagic` if `source` begins with bytes not equal to the
///     Zstandard frame magic number, or outside the range of magic numbers for
///     skippable frames.
///   - `error.EndOfStream` if `source` contains fewer than 4 bytes
pub fn decode_frame_type(source: anytype) error{ BadMagic, EndOfStream }!frame.Kind {
    const magic = try source.read_int(u32, .little);
    return frame_type(magic);
}

/// Returns the kind of frame associated to `magic`.
///
/// Errors returned:
///   - `error.BadMagic` if `magic` is not a valid magic number.
pub fn frame_type(magic: u32) error{BadMagic}!frame.Kind {
    return if (magic == frame.Zstandard.magic_number)
        .zstandard
    else if (is_skippable_magic(magic))
        .skippable
    else
        error.BadMagic;
}

pub const FrameHeader = union(enum) {
    zstandard: ZstandardHeader,
    skippable: SkippableHeader,
};

pub const HeaderError = error{ BadMagic, EndOfStream, ReservedBitSet };

/// Returns the header of the frame at the beginning of `source`.
///
/// Errors returned:
///   - `error.BadMagic` if `source` begins with bytes not equal to the
///     Zstandard frame magic number, or outside the range of magic numbers for
///     skippable frames.
///   - `error.EndOfStream` if `source` contains fewer than 4 bytes
///   - `error.ReservedBitSet` if the frame is a Zstandard frame and any of the
///     reserved bits are set
pub fn decode_frame_header(source: anytype) (@TypeOf(source).Error || HeaderError)!FrameHeader {
    const magic = try source.read_int(u32, .little);
    const frame_type = try frame_type(magic);
    switch (frame_type) {
        .zstandard => return FrameHeader{ .zstandard = try decode_zstandard_header(source) },
        .skippable => return FrameHeader{
            .skippable = .{
                .magic_number = magic,
                .frame_size = try source.read_int(u32, .little),
            },
        },
    }
}

pub const ReadWriteCount = struct {
    read_count: usize,
    write_count: usize,
};

/// Decodes frames from `src` into `dest`; returns the length of the result.
/// The stream should not have extra trailing bytes - either all bytes in `src`
/// will be decoded, or an error will be returned. An error will be returned if
/// a Zstandard frame in `src` does not declare its content size.
///
/// Errors returned:
///   - `error.DictionaryIdFlagUnsupported` if a `src` contains a frame that
///     uses a dictionary
///   - `error.MalformedFrame` if a frame in `src` is invalid
///   - `error.UnknownContentSizeUnsupported` if a frame in `src` does not
///     declare its content size
pub fn decode(dest: []u8, src: []const u8, verify_checksum: bool) error{
    MalformedFrame,
    UnknownContentSizeUnsupported,
    DictionaryIdFlagUnsupported,
}!usize {
    var write_count: usize = 0;
    var read_count: usize = 0;
    while (read_count < src.len) {
        const counts = decode_frame(dest, src[read_count..], verify_checksum) catch |err| {
            switch (err) {
                error.UnknownContentSizeUnsupported => return error.UnknownContentSizeUnsupported,
                error.DictionaryIdFlagUnsupported => return error.DictionaryIdFlagUnsupported,
                else => return error.MalformedFrame,
            }
        };
        read_count += counts.read_count;
        write_count += counts.write_count;
    }
    return write_count;
}

/// Decodes a stream of frames from `src`; returns the decoded bytes. The stream
/// should not have extra trailing bytes - either all bytes in `src` will be
/// decoded, or an error will be returned.
///
/// Errors returned:
///   - `error.DictionaryIdFlagUnsupported` if a `src` contains a frame that
///     uses a dictionary
///   - `error.MalformedFrame` if a frame in `src` is invalid
///   - `error.OutOfMemory` if `allocator` cannot allocate enough memory
pub fn decode_alloc(
    allocator: Allocator,
    src: []const u8,
    verify_checksum: bool,
    window_size_max: usize,
) error{ DictionaryIdFlagUnsupported, MalformedFrame, OutOfMemory }![]u8 {
    var result = std.ArrayList(u8).init(allocator);
    errdefer result.deinit();

    var read_count: usize = 0;
    while (read_count < src.len) {
        read_count += decode_frame_array_list(
            allocator,
            &result,
            src[read_count..],
            verify_checksum,
            window_size_max,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.DictionaryIdFlagUnsupported => return error.DictionaryIdFlagUnsupported,
            else => return error.MalformedFrame,
        };
    }
    return result.to_owned_slice();
}

/// Decodes the frame at the start of `src` into `dest`. Returns the number of
/// bytes read from `src` and written to `dest`. This function can only decode
/// frames that declare the decompressed content size.
///
/// Errors returned:
///   - `error.BadMagic` if the first 4 bytes of `src` is not a valid magic
///     number for a Zstandard or skippable frame
///   - `error.UnknownContentSizeUnsupported` if the frame does not declare the
///     uncompressed content size
///   - `error.WindowSizeUnknown` if the frame does not have a valid window size
///   - `error.ContentTooLarge` if `dest` is smaller than the uncompressed data
///     size declared by the frame header
///   - `error.ContentSizeTooLarge` if the frame header indicates a content size
///     that is larger than `std.math.max_int(usize)`
///   - `error.DictionaryIdFlagUnsupported` if the frame uses a dictionary
///   - `error.ChecksumFailure` if `verify_checksum` is true and the frame
///     contains a checksum that does not match the checksum of the decompressed
///     data
///   - `error.ReservedBitSet` if any of the reserved bits of the frame header
///     are set
///   - `error.EndOfStream` if `src` does not contain a complete frame
///   - `error.BadContentSize` if the content size declared by the frame does
///     not equal the actual size of decompressed data
///   - an error in `block.Error` if there are errors decoding a block
///   - `error.SkippableSizeTooLarge` if the frame is skippable and reports a
///     size greater than `src.len`
pub fn decode_frame(
    dest: []u8,
    src: []const u8,
    verify_checksum: bool,
) (error{
    BadMagic,
    UnknownContentSizeUnsupported,
    ContentTooLarge,
    ContentSizeTooLarge,
    WindowSizeUnknown,
    DictionaryIdFlagUnsupported,
    SkippableSizeTooLarge,
} || FrameError)!ReadWriteCount {
    var fbs = std.io.fixed_buffer_stream(src);
    switch (try decode_frame_type(fbs.reader())) {
        .zstandard => return decode_zstandard_frame(dest, src, verify_checksum),
        .skippable => {
            const content_size = try fbs.reader().read_int(u32, .little);
            if (content_size > std.math.max_int(usize) - 8) return error.SkippableSizeTooLarge;
            const read_count = @as(usize, content_size) + 8;
            if (read_count > src.len) return error.SkippableSizeTooLarge;
            return ReadWriteCount{
                .read_count = read_count,
                .write_count = 0,
            };
        },
    }
}

/// Decodes the frame at the start of `src` into `dest`. Returns the number of
/// bytes read from `src`.
///
/// Errors returned:
///   - `error.BadMagic` if the first 4 bytes of `src` is not a valid magic
///     number for a Zstandard or skippable frame
///   - `error.WindowSizeUnknown` if the frame does not have a valid window size
///   - `error.WindowTooLarge` if the window size is larger than
///     `window_size_max`
///   - `error.ContentSizeTooLarge` if the frame header indicates a content size
///     that is larger than `std.math.max_int(usize)`
///   - `error.DictionaryIdFlagUnsupported` if the frame uses a dictionary
///   - `error.ChecksumFailure` if `verify_checksum` is true and the frame
///     contains a checksum that does not match the checksum of the decompressed
///     data
///   - `error.ReservedBitSet` if any of the reserved bits of the frame header
///     are set
///   - `error.EndOfStream` if `src` does not contain a complete frame
///   - `error.BadContentSize` if the content size declared by the frame does
///     not equal the actual size of decompressed data
///   - `error.OutOfMemory` if `allocator` cannot allocate enough memory
///   - an error in `block.Error` if there are errors decoding a block
///   - `error.SkippableSizeTooLarge` if the frame is skippable and reports a
///     size greater than `src.len`
pub fn decode_frame_array_list(
    allocator: Allocator,
    dest: *std.ArrayList(u8),
    src: []const u8,
    verify_checksum: bool,
    window_size_max: usize,
) (error{ BadMagic, OutOfMemory, SkippableSizeTooLarge } || FrameContext.Error || FrameError)!usize {
    var fbs = std.io.fixed_buffer_stream(src);
    const reader = fbs.reader();
    const magic = try reader.read_int(u32, .little);
    switch (try frame_type(magic)) {
        .zstandard => return decode_zstandard_frame_array_list(
            allocator,
            dest,
            src,
            verify_checksum,
            window_size_max,
        ),
        .skippable => {
            const content_size = try fbs.reader().read_int(u32, .little);
            if (content_size > std.math.max_int(usize) - 8) return error.SkippableSizeTooLarge;
            const read_count = @as(usize, content_size) + 8;
            if (read_count > src.len) return error.SkippableSizeTooLarge;
            return read_count;
        },
    }
}

/// Returns the frame checksum corresponding to the data fed into `hasher`
pub fn compute_checksum(hasher: *std.hash.XxHash64) u32 {
    const hash = hasher.final();
    return @as(u32, @int_cast(hash & 0xFFFFFFFF));
}

const FrameError = error{
    ChecksumFailure,
    BadContentSize,
    EndOfStream,
    ReservedBitSet,
} || block.Error;

/// Decode a Zstandard frame from `src` into `dest`, returning the number of
/// bytes read from `src` and written to `dest`. The first four bytes of `src`
/// must be the magic number for a Zstandard frame.
///
/// Error returned:
///   - `error.UnknownContentSizeUnsupported` if the frame does not declare the
///     uncompressed content size
///   - `error.ContentTooLarge` if `dest` is smaller than the uncompressed data
///     size declared by the frame header
///   - `error.WindowSizeUnknown` if the frame does not have a valid window size
///   - `error.DictionaryIdFlagUnsupported` if the frame uses a dictionary
///   - `error.ContentSizeTooLarge` if the frame header indicates a content size
///     that is larger than `std.math.max_int(usize)`
///   - `error.ChecksumFailure` if `verify_checksum` is true and the frame
///     contains a checksum that does not match the checksum of the decompressed
///     data
///   - `error.ReservedBitSet` if the reserved bit of the frame header is set
///   - `error.EndOfStream` if `src` does not contain a complete frame
///   - an error in `block.Error` if there are errors decoding a block
///   - `error.BadContentSize` if the content size declared by the frame does
///     not equal the actual size of decompressed data
pub fn decode_zstandard_frame(
    dest: []u8,
    src: []const u8,
    verify_checksum: bool,
) (error{
    UnknownContentSizeUnsupported,
    ContentTooLarge,
    ContentSizeTooLarge,
    WindowSizeUnknown,
    DictionaryIdFlagUnsupported,
} || FrameError)!ReadWriteCount {
    assert(std.mem.read_int(u32, src[0..4], .little) == frame.Zstandard.magic_number);
    var consumed_count: usize = 4;

    var frame_context = context: {
        var fbs = std.io.fixed_buffer_stream(src[consumed_count..]);
        const source = fbs.reader();
        const frame_header = try decode_zstandard_header(source);
        consumed_count += fbs.pos;
        break :context FrameContext.init(
            frame_header,
            std.math.max_int(usize),
            verify_checksum,
        ) catch |err| switch (err) {
            error.WindowTooLarge => unreachable,
            inline else => |e| return e,
        };
    };
    const counts = try decode_zstandard_frame_blocks(
        dest,
        src[consumed_count..],
        &frame_context,
    );
    return ReadWriteCount{
        .read_count = counts.read_count + consumed_count,
        .write_count = counts.write_count,
    };
}

pub fn decode_zstandard_frame_blocks(
    dest: []u8,
    src: []const u8,
    frame_context: *FrameContext,
) (error{ ContentTooLarge, UnknownContentSizeUnsupported } || FrameError)!ReadWriteCount {
    const content_size = frame_context.content_size orelse
        return error.UnknownContentSizeUnsupported;
    if (dest.len < content_size) return error.ContentTooLarge;

    var consumed_count: usize = 0;
    const written_count = decode_frame_blocks_inner(
        dest[0..content_size],
        src[consumed_count..],
        &consumed_count,
        if (frame_context.hasher_opt) |*hasher| hasher else null,
        frame_context.block_size_max,
    ) catch |err| switch (err) {
        error.DestTooSmall => return error.BadContentSize,
        inline else => |e| return e,
    };

    if (written_count != content_size) return error.BadContentSize;
    if (frame_context.has_checksum) {
        if (src.len < consumed_count + 4) return error.EndOfStream;
        const checksum = std.mem.read_int(u32, src[consumed_count..][0..4], .little);
        consumed_count += 4;
        if (frame_context.hasher_opt) |*hasher| {
            if (checksum != compute_checksum(hasher)) return error.ChecksumFailure;
        }
    }
    return ReadWriteCount{ .read_count = consumed_count, .write_count = written_count };
}

pub const FrameContext = struct {
    hasher_opt: ?std.hash.XxHash64,
    window_size: usize,
    has_checksum: bool,
    block_size_max: usize,
    content_size: ?usize,

    const Error = error{
        DictionaryIdFlagUnsupported,
        WindowSizeUnknown,
        WindowTooLarge,
        ContentSizeTooLarge,
    };
    /// Validates `frame_header` and returns the associated `FrameContext`.
    ///
    /// Errors returned:
    ///   - `error.DictionaryIdFlagUnsupported` if the frame uses a dictionary
    ///   - `error.WindowSizeUnknown` if the frame does not have a valid window
    ///     size
    ///   - `error.WindowTooLarge` if the window size is larger than
    ///     `window_size_max`
    ///   - `error.ContentSizeTooLarge` if the frame header indicates a content
    ///     size larger than `std.math.max_int(usize)`
    pub fn init(
        frame_header: ZstandardHeader,
        window_size_max: usize,
        verify_checksum: bool,
    ) Error!FrameContext {
        if (frame_header.descriptor.dictionary_id_flag != 0)
            return error.DictionaryIdFlagUnsupported;

        const window_size_raw = frame_window_size(frame_header) orelse return error.WindowSizeUnknown;
        const window_size = if (window_size_raw > window_size_max)
            return error.WindowTooLarge
        else
            @as(usize, @int_cast(window_size_raw));

        const should_compute_checksum =
            frame_header.descriptor.content_checksum_flag and verify_checksum;

        const content_size = if (frame_header.content_size) |size|
            std.math.cast(usize, size) orelse return error.ContentSizeTooLarge
        else
            null;

        return .{
            .hasher_opt = if (should_compute_checksum) std.hash.XxHash64.init(0) else null,
            .window_size = window_size,
            .has_checksum = frame_header.descriptor.content_checksum_flag,
            .block_size_max = @min(types.block_size_max, window_size),
            .content_size = content_size,
        };
    }
};

/// Decode a Zstandard from from `src` and return number of bytes read; see
/// `decode_zstandard_frame()`. The first four bytes of `src` must be the magic
/// number for a Zstandard frame.
///
/// Errors returned:
///   - `error.WindowSizeUnknown` if the frame does not have a valid window size
///   - `error.WindowTooLarge` if the window size is larger than
///     `window_size_max`
///   - `error.DictionaryIdFlagUnsupported` if the frame uses a dictionary
///   - `error.ContentSizeTooLarge` if the frame header indicates a content size
///     that is larger than `std.math.max_int(usize)`
///   - `error.ChecksumFailure` if `verify_checksum` is true and the frame
///     contains a checksum that does not match the checksum of the decompressed
///     data
///   - `error.ReservedBitSet` if the reserved bit of the frame header is set
///   - `error.EndOfStream` if `src` does not contain a complete frame
///   - `error.OutOfMemory` if `allocator` cannot allocate enough memory
///   - an error in `block.Error` if there are errors decoding a block
///   - `error.BadContentSize` if the content size declared by the frame does
///     not equal the size of decompressed data
pub fn decode_zstandard_frame_array_list(
    allocator: Allocator,
    dest: *std.ArrayList(u8),
    src: []const u8,
    verify_checksum: bool,
    window_size_max: usize,
) (error{OutOfMemory} || FrameContext.Error || FrameError)!usize {
    assert(std.mem.read_int(u32, src[0..4], .little) == frame.Zstandard.magic_number);
    var consumed_count: usize = 4;

    var frame_context = context: {
        var fbs = std.io.fixed_buffer_stream(src[consumed_count..]);
        const source = fbs.reader();
        const frame_header = try decode_zstandard_header(source);
        consumed_count += fbs.pos;
        break :context try FrameContext.init(frame_header, window_size_max, verify_checksum);
    };

    consumed_count += try decode_zstandard_frame_blocks_array_list(
        allocator,
        dest,
        src[consumed_count..],
        &frame_context,
    );
    return consumed_count;
}

pub fn decode_zstandard_frame_blocks_array_list(
    allocator: Allocator,
    dest: *std.ArrayList(u8),
    src: []const u8,
    frame_context: *FrameContext,
) (error{OutOfMemory} || FrameError)!usize {
    const initial_len = dest.items.len;

    var ring_buffer = try RingBuffer.init(allocator, frame_context.window_size);
    defer ring_buffer.deinit(allocator);

    // These tables take 7680 bytes
    var literal_fse_data: [types.compressed_block.table_size_max.literal]Table.Fse = undefined;
    var match_fse_data: [types.compressed_block.table_size_max.match]Table.Fse = undefined;
    var offset_fse_data: [types.compressed_block.table_size_max.offset]Table.Fse = undefined;

    var block_header = try block.decode_block_header_slice(src);
    var consumed_count: usize = 3;
    var decode_state = block.DecodeState.init(&literal_fse_data, &match_fse_data, &offset_fse_data);
    while (true) : ({
        block_header = try block.decode_block_header_slice(src[consumed_count..]);
        consumed_count += 3;
    }) {
        const written_size = try block.decode_block_ring_buffer(
            &ring_buffer,
            src[consumed_count..],
            block_header,
            &decode_state,
            &consumed_count,
            frame_context.block_size_max,
        );
        if (frame_context.content_size) |size| {
            if (dest.items.len - initial_len > size) {
                return error.BadContentSize;
            }
        }
        if (written_size > 0) {
            const written_slice = ring_buffer.slice_last(written_size);
            try dest.append_slice(written_slice.first);
            try dest.append_slice(written_slice.second);
            if (frame_context.hasher_opt) |*hasher| {
                hasher.update(written_slice.first);
                hasher.update(written_slice.second);
            }
        }
        if (block_header.last_block) break;
    }
    if (frame_context.content_size) |size| {
        if (dest.items.len - initial_len != size) {
            return error.BadContentSize;
        }
    }

    if (frame_context.has_checksum) {
        if (src.len < consumed_count + 4) return error.EndOfStream;
        const checksum = std.mem.read_int(u32, src[consumed_count..][0..4], .little);
        consumed_count += 4;
        if (frame_context.hasher_opt) |*hasher| {
            if (checksum != compute_checksum(hasher)) return error.ChecksumFailure;
        }
    }
    return consumed_count;
}

fn decode_frame_blocks_inner(
    dest: []u8,
    src: []const u8,
    consumed_count: *usize,
    hash: ?*std.hash.XxHash64,
    block_size_max: usize,
) (error{ EndOfStream, DestTooSmall } || block.Error)!usize {
    // These tables take 7680 bytes
    var literal_fse_data: [types.compressed_block.table_size_max.literal]Table.Fse = undefined;
    var match_fse_data: [types.compressed_block.table_size_max.match]Table.Fse = undefined;
    var offset_fse_data: [types.compressed_block.table_size_max.offset]Table.Fse = undefined;

    var block_header = try block.decode_block_header_slice(src);
    var bytes_read: usize = 3;
    defer consumed_count.* += bytes_read;
    var decode_state = block.DecodeState.init(&literal_fse_data, &match_fse_data, &offset_fse_data);
    var count: usize = 0;
    while (true) : ({
        block_header = try block.decode_block_header_slice(src[bytes_read..]);
        bytes_read += 3;
    }) {
        const written_size = try block.decode_block(
            dest,
            src[bytes_read..],
            block_header,
            &decode_state,
            &bytes_read,
            block_size_max,
            count,
        );
        if (hash) |hash_state| hash_state.update(dest[count .. count + written_size]);
        count += written_size;
        if (block_header.last_block) break;
    }
    return count;
}

/// Decode the header of a skippable frame. The first four bytes of `src` must
/// be a valid magic number for a skippable frame.
pub fn decode_skippable_header(src: *const [8]u8) SkippableHeader {
    const magic = std.mem.read_int(u32, src[0..4], .little);
    assert(is_skippable_magic(magic));
    const frame_size = std.mem.read_int(u32, src[4..8], .little);
    return .{
        .magic_number = magic,
        .frame_size = frame_size,
    };
}

/// Returns the window size required to decompress a frame, or `null` if it
/// cannot be determined (which indicates a malformed frame header).
pub fn frame_window_size(header: ZstandardHeader) ?u64 {
    if (header.window_descriptor) |descriptor| {
        const exponent = (descriptor & 0b11111000) >> 3;
        const mantissa = descriptor & 0b00000111;
        const window_log = 10 + exponent;
        const window_base = @as(u64, 1) << @as(u6, @int_cast(window_log));
        const window_add = (window_base / 8) * mantissa;
        return window_base + window_add;
    } else return header.content_size;
}

/// Decode the header of a Zstandard frame.
///
/// Errors returned:
///   - `error.ReservedBitSet` if any of the reserved bits of the header are set
///   - `error.EndOfStream` if `source` does not contain a complete header
pub fn decode_zstandard_header(
    source: anytype,
) (@TypeOf(source).Error || error{ EndOfStream, ReservedBitSet })!ZstandardHeader {
    const descriptor = @as(ZstandardHeader.Descriptor, @bit_cast(try source.read_byte()));

    if (descriptor.reserved) return error.ReservedBitSet;

    var window_descriptor: ?u8 = null;
    if (!descriptor.single_segment_flag) {
        window_descriptor = try source.read_byte();
    }

    var dictionary_id: ?u32 = null;
    if (descriptor.dictionary_id_flag > 0) {
        // if flag is 3 then field_size = 4, else field_size = flag
        const field_size = (@as(u4, 1) << descriptor.dictionary_id_flag) >> 1;
        dictionary_id = try source.read_var_int(u32, .little, field_size);
    }

    var content_size: ?u64 = null;
    if (descriptor.single_segment_flag or descriptor.content_size_flag > 0) {
        const field_size = @as(u4, 1) << descriptor.content_size_flag;
        content_size = try source.read_var_int(u64, .little, field_size);
        if (field_size == 2) content_size.? += 256;
    }

    const header = ZstandardHeader{
        .descriptor = descriptor,
        .window_descriptor = window_descriptor,
        .dictionary_id = dictionary_id,
        .content_size = content_size,
    };
    return header;
}

test {
    std.testing.ref_all_decls(@This());
}
