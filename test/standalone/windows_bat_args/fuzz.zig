const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;

pub fn main() anyerror!void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer if (gpa.deinit() == .leak) @panic("found memory leaks");
    const allocator = gpa.allocator();

    var it = try std.process.args_with_allocator(allocator);
    defer it.deinit();
    _ = it.next() orelse unreachable; // skip binary name
    const child_exe_path = it.next() orelse unreachable;

    const iterations: u64 = iterations: {
        const arg = it.next() orelse "0";
        break :iterations try std.fmt.parse_unsigned(u64, arg, 10);
    };

    var rand_seed = false;
    const seed: u64 = seed: {
        const seed_arg = it.next() orelse {
            rand_seed = true;
            var buf: [8]u8 = undefined;
            try std.posix.getrandom(&buf);
            break :seed std.mem.read_int(u64, &buf, builtin.cpu.arch.endian());
        };
        break :seed try std.fmt.parse_unsigned(u64, seed_arg, 10);
    };
    var random = std.rand.DefaultPrng.init(seed);
    const rand = random.random();

    // If the seed was not given via the CLI, then output the
    // randomly chosen seed so that this run can be reproduced
    if (rand_seed) {
        std.debug.print("rand seed: {}\n", .{seed});
    }

    var tmp = std.testing.tmp_dir(.{});
    defer tmp.cleanup();

    try tmp.dir.set_as_cwd();
    defer tmp.parent_dir.set_as_cwd() catch {};

    var buf = try std.ArrayList(u8).init_capacity(allocator, 128);
    defer buf.deinit();
    try buf.append_slice("@echo off\n");
    try buf.append('"');
    try buf.append_slice(child_exe_path);
    try buf.append('"');
    const preamble_len = buf.items.len;

    try buf.append_slice(" %*");
    try tmp.dir.write_file(.{ .sub_path = "args1.bat", .data = buf.items });
    buf.shrink_retaining_capacity(preamble_len);

    try buf.append_slice(" %1 %2 %3 %4 %5 %6 %7 %8 %9");
    try tmp.dir.write_file(.{ .sub_path = "args2.bat", .data = buf.items });
    buf.shrink_retaining_capacity(preamble_len);

    try buf.append_slice(" \"%~1\" \"%~2\" \"%~3\" \"%~4\" \"%~5\" \"%~6\" \"%~7\" \"%~8\" \"%~9\"");
    try tmp.dir.write_file(.{ .sub_path = "args3.bat", .data = buf.items });
    buf.shrink_retaining_capacity(preamble_len);

    var i: u64 = 0;
    while (iterations == 0 or i < iterations) {
        const rand_arg = try random_arg(allocator, rand);
        defer allocator.free(rand_arg);

        try test_exec(allocator, &.{rand_arg}, null);

        i += 1;
    }
}

fn test_exec(allocator: std.mem.Allocator, args: []const []const u8, env: ?*std.process.EnvMap) !void {
    try test_exec_bat(allocator, "args1.bat", args, env);
    try test_exec_bat(allocator, "args2.bat", args, env);
    try test_exec_bat(allocator, "args3.bat", args, env);
}

fn test_exec_bat(allocator: std.mem.Allocator, bat: []const u8, args: []const []const u8, env: ?*std.process.EnvMap) !void {
    var argv = try std.ArrayList([]const u8).init_capacity(allocator, 1 + args.len);
    defer argv.deinit();
    argv.append_assume_capacity(bat);
    argv.append_slice_assume_capacity(args);

    const can_have_trailing_empty_args = std.mem.eql(u8, bat, "args3.bat");

    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .env_map = env,
        .argv = argv.items,
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    try std.testing.expect_equal_strings("", result.stderr);
    var it = std.mem.split_scalar(u8, result.stdout, '\x00');
    var i: usize = 0;
    while (it.next()) |actual_arg| {
        if (i >= args.len and can_have_trailing_empty_args) {
            try std.testing.expect_equal_strings("", actual_arg);
            continue;
        }
        const expected_arg = args[i];
        try std.testing.expect_equal_slices(u8, expected_arg, actual_arg);
        i += 1;
    }
}

fn random_arg(allocator: Allocator, rand: std.rand.Random) ![]const u8 {
    const Choice = enum {
        backslash,
        quote,
        space,
        control,
        printable,
        surrogate_half,
        non_ascii,
    };

    const choices = rand.uint_at_most_biased(u16, 256);
    var buf = try std.ArrayList(u8).init_capacity(allocator, choices);
    errdefer buf.deinit();

    var last_codepoint: u21 = 0;
    for (0..choices) |_| {
        const choice = rand.enum_value(Choice);
        const codepoint: u21 = switch (choice) {
            .backslash => '\\',
            .quote => '"',
            .space => ' ',
            .control => switch (rand.uint_at_most_biased(u8, 0x21)) {
                // NUL/CR/LF can't roundtrip
                '\x00', '\r', '\n' => ' ',
                0x21 => '\x7F',
                else => |b| b,
            },
            .printable => '!' + rand.uint_at_most_biased(u8, '~' - '!'),
            .surrogate_half => rand.int_range_at_most_biased(u16, 0xD800, 0xDFFF),
            .non_ascii => rand.int_range_at_most_biased(u21, 0x80, 0x10FFFF),
        };
        // Ensure that we always return well-formed WTF-8.
        // Instead of concatenating to ensure well-formed WTF-8,
        // we just skip encoding the low surrogate.
        if (std.unicode.is_surrogate_codepoint(last_codepoint) and std.unicode.is_surrogate_codepoint(codepoint)) {
            if (std.unicode.utf16_is_high_surrogate(@int_cast(last_codepoint)) and std.unicode.utf16_is_low_surrogate(@int_cast(codepoint))) {
                continue;
            }
        }
        try buf.ensure_unused_capacity(4);
        const unused_slice = buf.unused_capacity_slice();
        const len = std.unicode.wtf8_encode(codepoint, unused_slice) catch unreachable;
        buf.items.len += len;
        last_codepoint = codepoint;
    }

    return buf.to_owned_slice();
}
