const std = @import("std");

pub fn main() !void {
    // make sure safety checks are enabled even in release modes
    var gpa_state = std.heap.GeneralPurposeAllocator(.{ .safety = true }){};
    defer if (gpa_state.deinit() != .ok) {
        @panic("found memory leaks");
    };
    const gpa = gpa_state.allocator();

    var it = try std.process.args_with_allocator(gpa);
    defer it.deinit();
    _ = it.next() orelse unreachable; // skip binary name
    const child_path = it.next() orelse unreachable;

    var child = std.process.Child.init(&.{ child_path, "hello arg" }, gpa);
    child.stdin_behavior = .Pipe;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Inherit;
    try child.spawn();
    const child_stdin = child.stdin.?;
    try child_stdin.writer().write_all("hello from stdin"); // verified in child
    child_stdin.close();
    child.stdin = null;

    const hello_stdout = "hello from stdout";
    var buf: [hello_stdout.len]u8 = undefined;
    const n = try child.stdout.?.reader().read_all(&buf);
    if (!std.mem.eql(u8, buf[0..n], hello_stdout)) {
        test_error("child stdout: '{s}'; want '{s}'", .{ buf[0..n], hello_stdout });
    }

    switch (try child.wait()) {
        .Exited => |code| {
            const child_ok_code = 42; // set by child if no test errors
            if (code != child_ok_code) {
                test_error("child exit code: {d}; want {d}", .{ code, child_ok_code });
            }
        },
        else => |term| test_error("abnormal child exit: {}", .{term}),
    }
    return if (parent_test_error) error.ParentTestError else {};
}

var parent_test_error = false;

fn test_error(comptime fmt: []const u8, args: anytype) void {
    const stderr = std.io.get_std_err().writer();
    stderr.print("PARENT TEST ERROR: ", .{}) catch {};
    stderr.print(fmt, args) catch {};
    if (fmt[fmt.len - 1] != '\n') {
        stderr.write_byte('\n') catch {};
    }
    parent_test_error = true;
}
