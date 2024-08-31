const std = @import("std");
const time = std.time;
const unicode = std.unicode;

const Timer = time.Timer;

const N = 1_000_000;

const KiB = 1024;
const MiB = 1024 * KiB;
const GiB = 1024 * MiB;

const ResultCount = struct {
    count: usize,
    throughput: u64,
};

fn benchmark_codepoint_count(buf: []const u8) !ResultCount {
    var timer = try Timer.start();

    const bytes = N * buf.len;

    const start = timer.lap();
    var i: usize = 0;
    var r: usize = undefined;
    while (i < N) : (i += 1) {
        r = try @call(
            .never_inline,
            std.unicode.utf8_count_codepoints,
            .{buf},
        );
    }
    const end = timer.read();

    const elapsed_s = @as(f64, @float_from_int(end - start)) / time.ns_per_s;
    const throughput = @as(u64, @int_from_float(@as(f64, @float_from_int(bytes)) / elapsed_s));

    return ResultCount{ .count = r, .throughput = throughput };
}

pub fn main() !void {
    const stdout = std.io.get_std_out().writer();

    try stdout.print("short ASCII strings\n", .{});
    {
        const result = try benchmark_codepoint_count("abc");
        try stdout.print("  count: {:5} MiB/s [{d}]\n", .{ result.throughput / (1 * MiB), result.count });
    }

    try stdout.print("short Unicode strings\n", .{});
    {
        const result = try benchmark_codepoint_count("ŌŌŌ");
        try stdout.print("  count: {:5} MiB/s [{d}]\n", .{ result.throughput / (1 * MiB), result.count });
    }

    try stdout.print("pure ASCII strings\n", .{});
    {
        const result = try benchmark_codepoint_count("hello" ** 16);
        try stdout.print("  count: {:5} MiB/s [{d}]\n", .{ result.throughput / (1 * MiB), result.count });
    }

    try stdout.print("pure Unicode strings\n", .{});
    {
        const result = try benchmark_codepoint_count("こんにちは" ** 16);
        try stdout.print("  count: {:5} MiB/s [{d}]\n", .{ result.throughput / (1 * MiB), result.count });
    }

    try stdout.print("mixed ASCII/Unicode strings\n", .{});
    {
        const result = try benchmark_codepoint_count("Hyvää huomenta" ** 16);
        try stdout.print("  count: {:5} MiB/s [{d}]\n", .{ result.throughput / (1 * MiB), result.count });
    }
}
