const std = @import("std");
const io = std.io;
const DefaultPrng = std.Random.DefaultPrng;
const expect = std.testing.expect;
const expect_equal = std.testing.expect_equal;
const expect_error = std.testing.expect_error;
const mem = std.mem;
const fs = std.fs;
const File = std.fs.File;
const native_endian = @import("builtin").target.cpu.arch.endian();

const tmp_dir = std.testing.tmp_dir;

test "write a file, read it, then delete it" {
    var tmp = tmp_dir(.{});
    defer tmp.cleanup();

    var data: [1024]u8 = undefined;
    var prng = DefaultPrng.init(1234);
    const random = prng.random();
    random.bytes(data[0..]);
    const tmp_file_name = "temp_test_file.txt";
    {
        var file = try tmp.dir.create_file(tmp_file_name, .{});
        defer file.close();

        var buf_stream = io.buffered_writer(file.writer());
        const st = buf_stream.writer();
        try st.print("begin", .{});
        try st.write_all(data[0..]);
        try st.print("end", .{});
        try buf_stream.flush();
    }

    {
        // Make sure the exclusive flag is honored.
        try expect_error(File.OpenError.PathAlreadyExists, tmp.dir.create_file(tmp_file_name, .{ .exclusive = true }));
    }

    {
        var file = try tmp.dir.open_file(tmp_file_name, .{});
        defer file.close();

        const file_size = try file.get_end_pos();
        const expected_file_size: u64 = "begin".len + data.len + "end".len;
        try expect_equal(expected_file_size, file_size);

        var buf_stream = io.buffered_reader(file.reader());
        const st = buf_stream.reader();
        const contents = try st.read_all_alloc(std.testing.allocator, 2 * 1024);
        defer std.testing.allocator.free(contents);

        try expect(mem.eql(u8, contents[0.."begin".len], "begin"));
        try expect(mem.eql(u8, contents["begin".len .. contents.len - "end".len], &data));
        try expect(mem.eql(u8, contents[contents.len - "end".len ..], "end"));
    }
    try tmp.dir.delete_file(tmp_file_name);
}

test "BitStreams with File Stream" {
    var tmp = tmp_dir(.{});
    defer tmp.cleanup();

    const tmp_file_name = "temp_test_file.txt";
    {
        var file = try tmp.dir.create_file(tmp_file_name, .{});
        defer file.close();

        var bit_stream = io.bit_writer(native_endian, file.writer());

        try bit_stream.write_bits(@as(u2, 1), 1);
        try bit_stream.write_bits(@as(u5, 2), 2);
        try bit_stream.write_bits(@as(u128, 3), 3);
        try bit_stream.write_bits(@as(u8, 4), 4);
        try bit_stream.write_bits(@as(u9, 5), 5);
        try bit_stream.write_bits(@as(u1, 1), 1);
        try bit_stream.flush_bits();
    }
    {
        var file = try tmp.dir.open_file(tmp_file_name, .{});
        defer file.close();

        var bit_stream = io.bit_reader(native_endian, file.reader());

        var out_bits: usize = undefined;

        try expect(1 == try bit_stream.read_bits(u2, 1, &out_bits));
        try expect(out_bits == 1);
        try expect(2 == try bit_stream.read_bits(u5, 2, &out_bits));
        try expect(out_bits == 2);
        try expect(3 == try bit_stream.read_bits(u128, 3, &out_bits));
        try expect(out_bits == 3);
        try expect(4 == try bit_stream.read_bits(u8, 4, &out_bits));
        try expect(out_bits == 4);
        try expect(5 == try bit_stream.read_bits(u9, 5, &out_bits));
        try expect(out_bits == 5);
        try expect(1 == try bit_stream.read_bits(u1, 1, &out_bits));
        try expect(out_bits == 1);

        try expect_error(error.EndOfStream, bit_stream.read_bits_no_eof(u1, 1));
    }
    try tmp.dir.delete_file(tmp_file_name);
}

test "File seek ops" {
    var tmp = tmp_dir(.{});
    defer tmp.cleanup();

    const tmp_file_name = "temp_test_file.txt";
    var file = try tmp.dir.create_file(tmp_file_name, .{});
    defer {
        file.close();
        tmp.dir.delete_file(tmp_file_name) catch {};
    }

    try file.write_all(&([_]u8{0x55} ** 8192));

    // Seek to the end
    try file.seek_from_end(0);
    try expect((try file.get_pos()) == try file.get_end_pos());
    // Negative delta
    try file.seek_by(-4096);
    try expect((try file.get_pos()) == 4096);
    // Positive delta
    try file.seek_by(10);
    try expect((try file.get_pos()) == 4106);
    // Absolute position
    try file.seek_to(1234);
    try expect((try file.get_pos()) == 1234);
}

test "set_end_pos" {
    var tmp = tmp_dir(.{});
    defer tmp.cleanup();

    const tmp_file_name = "temp_test_file.txt";
    var file = try tmp.dir.create_file(tmp_file_name, .{});
    defer {
        file.close();
        tmp.dir.delete_file(tmp_file_name) catch {};
    }

    // Verify that the file size changes and the file offset is not moved
    try std.testing.expect((try file.get_end_pos()) == 0);
    try std.testing.expect((try file.get_pos()) == 0);
    try file.set_end_pos(8192);
    try std.testing.expect((try file.get_end_pos()) == 8192);
    try std.testing.expect((try file.get_pos()) == 0);
    try file.seek_to(100);
    try file.set_end_pos(4096);
    try std.testing.expect((try file.get_end_pos()) == 4096);
    try std.testing.expect((try file.get_pos()) == 100);
    try file.set_end_pos(0);
    try std.testing.expect((try file.get_end_pos()) == 0);
    try std.testing.expect((try file.get_pos()) == 100);
}

test "update_times" {
    var tmp = tmp_dir(.{});
    defer tmp.cleanup();

    const tmp_file_name = "just_a_temporary_file.txt";
    var file = try tmp.dir.create_file(tmp_file_name, .{ .read = true });
    defer {
        file.close();
        tmp.dir.delete_file(tmp_file_name) catch {};
    }
    const stat_old = try file.stat();
    // Set atime and mtime to 5s before
    try file.update_times(
        stat_old.atime - 5 * std.time.ns_per_s,
        stat_old.mtime - 5 * std.time.ns_per_s,
    );
    const stat_new = try file.stat();
    try expect(stat_new.atime < stat_old.atime);
    try expect(stat_new.mtime < stat_old.mtime);
}

test "GenericReader methods can return error.EndOfStream" {
    // https://github.com/ziglang/zig/issues/17733
    var fbs = std.io.fixed_buffer_stream("");
    try std.testing.expect_error(
        error.EndOfStream,
        fbs.reader().read_enum(enum(u8) { a, b }, .little),
    );
    try std.testing.expect_error(
        error.EndOfStream,
        fbs.reader().is_bytes("foo"),
    );
}
