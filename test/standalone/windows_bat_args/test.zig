const std = @import("std");

pub fn main() anyerror!void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer if (gpa.deinit() == .leak) @panic("found memory leaks");
    const allocator = gpa.allocator();

    var it = try std.process.args_with_allocator(allocator);
    defer it.deinit();
    _ = it.next() orelse unreachable; // skip binary name
    const child_exe_path = it.next() orelse unreachable;

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

    // Test cases are from https://github.com/rust-lang/rust/blob/master/tests/ui/std/windows-bat-args.rs
    try test_exec_error(error.InvalidBatchScriptArg, allocator, &.{"\x00"});
    try test_exec_error(error.InvalidBatchScriptArg, allocator, &.{"\n"});
    try test_exec_error(error.InvalidBatchScriptArg, allocator, &.{"\r"});
    try test_exec(allocator, &.{ "a", "b" }, null);
    try test_exec(allocator, &.{ "c is for cat", "d is for dog" }, null);
    try test_exec(allocator, &.{ "\"", " \"" }, null);
    try test_exec(allocator, &.{ "\\", "\\" }, null);
    try test_exec(allocator, &.{">file.txt"}, null);
    try test_exec(allocator, &.{"whoami.exe"}, null);
    try test_exec(allocator, &.{"&a.exe"}, null);
    try test_exec(allocator, &.{"&echo hello "}, null);
    try test_exec(allocator, &.{ "&echo hello", "&whoami", ">file.txt" }, null);
    try test_exec(allocator, &.{"!TMP!"}, null);
    try test_exec(allocator, &.{"key=value"}, null);
    try test_exec(allocator, &.{"\"key=value\""}, null);
    try test_exec(allocator, &.{"key = value"}, null);
    try test_exec(allocator, &.{"key=[\"value\"]"}, null);
    try test_exec(allocator, &.{ "", "a=b" }, null);
    try test_exec(allocator, &.{"key=\"foo bar\""}, null);
    try test_exec(allocator, &.{"key=[\"my_value]"}, null);
    try test_exec(allocator, &.{"key=[\"my_value\",\"other-value\"]"}, null);
    try test_exec(allocator, &.{"key\\=value"}, null);
    try test_exec(allocator, &.{"key=\"&whoami\""}, null);
    try test_exec(allocator, &.{"key=\"value\"=5"}, null);
    try test_exec(allocator, &.{"key=[\">file.txt\"]"}, null);
    try test_exec(allocator, &.{"%hello"}, null);
    try test_exec(allocator, &.{"%PATH%"}, null);
    try test_exec(allocator, &.{"%%cd:~,%"}, null);
    try test_exec(allocator, &.{"%PATH%PATH%"}, null);
    try test_exec(allocator, &.{"\">file.txt"}, null);
    try test_exec(allocator, &.{"abc\"&echo hello"}, null);
    try test_exec(allocator, &.{"123\">file.txt"}, null);
    try test_exec(allocator, &.{"\"&echo hello&whoami.exe"}, null);
    try test_exec(allocator, &.{ "\"hello^\"world\"", "hello &echo oh no >file.txt" }, null);
    try test_exec(allocator, &.{"&whoami.exe"}, null);

    var env = env: {
        var env = try std.process.get_env_map(allocator);
        errdefer env.deinit();
        // No escaping
        try env.put("FOO", "123");
        // Some possible escaping of %FOO% that could be expanded
        // when escaping cmd.exe meta characters with ^
        try env.put("FOO^", "123"); // only escaping %
        try env.put("^F^O^O^", "123"); // escaping every char
        break :env env;
    };
    defer env.deinit();
    try test_exec(allocator, &.{"%FOO%"}, &env);

    // Ensure that none of the `>file.txt`s have caused file.txt to be created
    try std.testing.expect_error(error.FileNotFound, tmp.dir.access("file.txt", .{}));
}

fn test_exec_error(err: anyerror, allocator: std.mem.Allocator, args: []const []const u8) !void {
    return std.testing.expect_error(err, test_exec(allocator, args, null));
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
        try std.testing.expect_equal_strings(expected_arg, actual_arg);
        i += 1;
    }
}
