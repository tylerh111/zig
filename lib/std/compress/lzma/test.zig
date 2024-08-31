const std = @import("../../std.zig");
const lzma = @import("../lzma.zig");

fn test_decompress(compressed: []const u8) ![]u8 {
    const allocator = std.testing.allocator;
    var stream = std.io.fixed_buffer_stream(compressed);
    var decompressor = try lzma.decompress(allocator, stream.reader());
    defer decompressor.deinit();
    const reader = decompressor.reader();
    return reader.read_all_alloc(allocator, std.math.max_int(usize));
}

fn test_decompress_equal(expected: []const u8, compressed: []const u8) !void {
    const allocator = std.testing.allocator;
    const decomp = try test_decompress(compressed);
    defer allocator.free(decomp);
    try std.testing.expect_equal_slices(u8, expected, decomp);
}

fn test_decompress_error(expected: anyerror, compressed: []const u8) !void {
    return std.testing.expect_error(expected, test_decompress(compressed));
}

test "decompress empty world" {
    try test_decompress_equal(
        "",
        &[_]u8{
            0x5d, 0x00, 0x00, 0x80, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x83, 0xff,
            0xfb, 0xff, 0xff, 0xc0, 0x00, 0x00, 0x00,
        },
    );
}

test "decompress hello world" {
    try test_decompress_equal(
        "Hello world\n",
        &[_]u8{
            0x5d, 0x00, 0x00, 0x80, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x24, 0x19,
            0x49, 0x98, 0x6f, 0x10, 0x19, 0xc6, 0xd7, 0x31, 0xeb, 0x36, 0x50, 0xb2, 0x98, 0x48, 0xff, 0xfe,
            0xa5, 0xb0, 0x00,
        },
    );
}

test "decompress huge dict" {
    try test_decompress_equal(
        "Hello world\n",
        &[_]u8{
            0x5d, 0x7f, 0x7f, 0x7f, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x24, 0x19,
            0x49, 0x98, 0x6f, 0x10, 0x19, 0xc6, 0xd7, 0x31, 0xeb, 0x36, 0x50, 0xb2, 0x98, 0x48, 0xff, 0xfe,
            0xa5, 0xb0, 0x00,
        },
    );
}

test "unknown size with end of payload marker" {
    try test_decompress_equal(
        "Hello\nWorld!\n",
        @embed_file("testdata/good-unknown_size-with_eopm.lzma"),
    );
}

test "known size without end of payload marker" {
    try test_decompress_equal(
        "Hello\nWorld!\n",
        @embed_file("testdata/good-known_size-without_eopm.lzma"),
    );
}

test "known size with end of payload marker" {
    try test_decompress_equal(
        "Hello\nWorld!\n",
        @embed_file("testdata/good-known_size-with_eopm.lzma"),
    );
}

test "too big uncompressed size in header" {
    try test_decompress_error(
        error.CorruptInput,
        @embed_file("testdata/bad-too_big_size-with_eopm.lzma"),
    );
}

test "too small uncompressed size in header" {
    try test_decompress_error(
        error.CorruptInput,
        @embed_file("testdata/bad-too_small_size-without_eopm-3.lzma"),
    );
}
