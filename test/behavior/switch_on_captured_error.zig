const std = @import("std");
const assert = std.debug.assert;
const expect = std.testing.expect;
const expect_error = std.testing.expect_error;
const expect_equal = std.testing.expect_equal;
const builtin = @import("builtin");

test "switch on error union catch capture" {
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_wasm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const S = struct {
        const Error = error{ A, B, C };
        fn do_the_test() !void {
            try test_scalar();
            try test_multi();
            try test_else();
            try test_capture();
            try test_inline();
            try test_empty_err_set();
            try test_address_of();
        }

        fn test_scalar() !void {
            {
                var a: Error!u64 = 3;
                _ = &a;
                const b: u64 = a catch |err| switch (err) {
                    error.A => 0,
                    error.B => 1,
                    error.C => 2,
                };
                try expect_equal(@as(u64, 3), b);
            }
            {
                var a: Error!u64 = 3;
                _ = &a;
                const b: u64 = a catch |err| switch (err) {
                    error.A => 0,
                    error.B => @intFromError(err) + 4,
                    error.C => @intFromError(err) + 4,
                };
                try expect_equal(@as(u64, 3), b);
            }
            {
                var a: Error!u64 = error.A;
                _ = &a;
                const b: u64 = a catch |err| switch (err) {
                    error.A => 0,
                    error.B => @intFromError(err) + 4,
                    error.C => @intFromError(err) + 4,
                };
                try expect_equal(@as(u64, 0), b);
            }
        }

        fn test_multi() !void {
            {
                var a: Error!u64 = 3;
                _ = &a;
                const b: u64 = a catch |err| switch (err) {
                    error.A, error.B => 0,
                    error.C => @intFromError(err) + 4,
                };
                try expect_equal(@as(u64, 3), b);
            }
            {
                var a: Error!u64 = 3;
                _ = &a;
                const b: u64 = a catch |err| switch (err) {
                    error.A => 0,
                    error.B, error.C => @intFromError(err) + 4,
                };
                try expect_equal(@as(u64, 3), b);
            }
            {
                var a: Error!u64 = error.A;
                _ = &a;
                const b: u64 = a catch |err| switch (err) {
                    error.A, error.B => 0,
                    error.C => @intFromError(err) + 4,
                };
                try expect_equal(@as(u64, 0), b);
            }
            {
                var a: Error!u64 = error.A;
                _ = &a;
                const b: u64 = a catch |err| switch (err) {
                    error.A => 0,
                    error.B, error.C => @intFromError(err) + 4,
                };
                try expect_equal(@as(u64, 0), b);
            }
            {
                var a: Error!u64 = error.B;
                _ = &a;
                const b: u64 = a catch |err| switch (err) {
                    error.A => 0,
                    error.B, error.C => @intFromError(err) + 4,
                };
                try expect_equal(@as(u64, @intFromError(error.B) + 4), b);
            }
        }

        fn test_else() !void {
            {
                var a: Error!u64 = 3;
                _ = &a;
                const b: u64 = a catch |err| switch (err) {
                    error.A => 0,
                    else => 1,
                };
                try expect_equal(@as(u64, 3), b);
            }
            {
                var a: Error!u64 = 3;
                _ = &a;
                const b: u64 = a catch |err| switch (err) {
                    error.A => 0,
                    else => @intFromError(err) + 4,
                };
                try expect_equal(@as(u64, 3), b);
            }
            {
                var a: Error!u64 = error.A;
                _ = &a;
                const b: u64 = a catch |err| switch (err) {
                    error.A => 1,
                    else => @intFromError(err) + 4,
                };
                try expect_equal(@as(u64, 1), b);
            }
            {
                var a: Error!u64 = error.B;
                _ = &a;
                const b: u64 = a catch |err| switch (err) {
                    error.A => 0,
                    else => 1,
                };
                try expect_equal(@as(u64, 1), b);
            }
            {
                var a: Error!u64 = error.B;
                _ = &a;
                const b: u64 = a catch |err| switch (err) {
                    error.A => 0,
                    else => @intFromError(err) + 4,
                };
                try expect_equal(@as(u64, @intFromError(error.B) + 4), b);
            }
        }

        fn test_capture() !void {
            {
                var a: Error!u64 = error.A;
                _ = &a;
                const b: u64 = a catch |err| switch (err) {
                    error.A => |e| @intFromError(e) + 4,
                    else => 0,
                };
                try expect_equal(@as(u64, @intFromError(error.A) + 4), b);
            }
            {
                var a: Error!u64 = error.A;
                _ = &a;
                const b: u64 = a catch |err| switch (err) {
                    error.A => 0,
                    else => |e| @intFromError(e) + 4,
                };
                try expect_equal(@as(u64, 0), b);
            }
            {
                var a: Error!u64 = error.B;
                _ = &a;
                const b: u64 = a catch |err| switch (err) {
                    error.A => 0,
                    else => |e| @intFromError(e) + 4,
                };
                try expect_equal(@as(u64, @intFromError(error.B) + 4), b);
            }
            {
                var a: Error!u64 = error.B;
                _ = &a;
                const b: u64 = a catch |err| switch (err) {
                    error.A => |e| @intFromError(e) + 4,
                    else => |e| @intFromError(e) + 4,
                };
                try expect_equal(@as(u64, @intFromError(error.B) + 4), b);
            }
            {
                var a: Error!u64 = error.B;
                _ = &a;
                const b: u64 = a catch |err| switch (err) {
                    error.A => 0,
                    error.B, error.C => |e| @intFromError(e) + 4,
                };
                try expect_equal(@as(u64, @intFromError(error.B) + 4), b);
            }
        }

        fn test_inline() !void {
            {
                var a: Error!u64 = error.B;
                _ = &a;
                const b: u64 = a catch |err| switch (err) {
                    error.A => 0,
                    inline else => @intFromError(err) + 4,
                };
                try expect_equal(@as(u64, @intFromError(error.B) + 4), b);
            }
            {
                var a: Error!u64 = error.B;
                _ = &a;
                const b: u64 = a catch |err| switch (err) {
                    error.A => |e| @intFromError(e) + 4,
                    inline else => @intFromError(err) + 4,
                };
                try expect_equal(@as(u64, @intFromError(error.B) + 4), b);
            }
            {
                var a: Error!u64 = error.B;
                _ = &a;
                const b: u64 = a catch |err| switch (err) {
                    inline else => |e| @intFromError(e) + 4,
                };
                try expect_equal(@as(u64, @intFromError(error.B) + 4), b);
            }
            {
                var a: Error!u64 = error.B;
                _ = &a;
                const b: u64 = a catch |err| switch (err) {
                    error.A => 0,
                    inline error.B, error.C => |e| @intFromError(e) + 4,
                };
                try expect_equal(@as(u64, @intFromError(error.B) + 4), b);
            }
        }

        fn test_empty_err_set() !void {
            {
                var a: error{}!u64 = 0;
                _ = &a;
                const b: u64 = a catch |err| switch (err) {
                    else => |e| return e,
                };
                try expect_equal(@as(u64, 0), b);
            }
            {
                var a: error{}!u64 = 0;
                _ = &a;
                const b: u64 = a catch |err| switch (err) {
                    error.UnknownError => return error.Fail,
                    else => |e| return e,
                };
                try expect_equal(@as(u64, 0), b);
            }
        }

        fn test_address_of() !void {
            {
                const a: anyerror!usize = 0;
                const ptr = &(a catch |e| switch (e) {
                    else => 3,
                });
                comptime assert(@TypeOf(ptr) == *const usize);
                try expect_equal(ptr, &(a catch unreachable));
            }
            {
                const a: anyerror!usize = error.A;
                const ptr = &(a catch |e| switch (e) {
                    else => 3,
                });
                comptime assert(@TypeOf(ptr) == *const comptime_int);
                try expect_equal(3, ptr.*);
            }
            {
                var a: anyerror!usize = 0;
                _ = &a;
                const ptr = &(a catch |e| switch (e) {
                    else => return,
                });
                comptime assert(@TypeOf(ptr) == *usize);
                ptr.* += 1;
                try expect_equal(@as(usize, 1), a catch unreachable);
            }
            {
                var a: anyerror!usize = error.A;
                _ = &a;
                const ptr = &(a catch |e| switch (e) {
                    else => return,
                });
                comptime assert(@TypeOf(ptr) == *usize);
                unreachable;
            }
        }
    };

    try comptime S.do_the_test();
    try S.do_the_test();
}

test "switch on error union if else capture" {
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_wasm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const S = struct {
        const Error = error{ A, B, C };
        fn do_the_test() !void {
            try test_scalar();
            try test_scalar_ptr();
            try test_multi();
            try test_multi_ptr();
            try test_else();
            try test_else_ptr();
            try test_capture();
            try test_capture_ptr();
            try test_inline();
            try test_inline_ptr();
            try test_empty_err_set();
            try test_empty_err_set_ptr();
            try test_address_of();
        }

        fn test_scalar() !void {
            {
                var a: Error!u64 = 3;
                _ = &a;
                const b: u64 = if (a) |x| x else |err| switch (err) {
                    error.A => 0,
                    error.B => 1,
                    error.C => 2,
                };
                try expect_equal(@as(u64, 3), b);
            }
            {
                var a: Error!u64 = 3;
                _ = &a;
                const b: u64 = if (a) |x| x else |err| switch (err) {
                    error.A => 0,
                    error.B => @intFromError(err) + 4,
                    error.C => @intFromError(err) + 4,
                };
                try expect_equal(@as(u64, 3), b);
            }
            {
                var a: Error!u64 = error.A;
                _ = &a;
                const b: u64 = if (a) |x| x else |err| switch (err) {
                    error.A => 0,
                    error.B => @intFromError(err) + 4,
                    error.C => @intFromError(err) + 4,
                };
                try expect_equal(@as(u64, 0), b);
            }
        }

        fn test_scalar_ptr() !void {
            {
                var a: Error!u64 = 3;
                _ = &a;
                const b: u64 = if (a) |*x| x.* else |err| switch (err) {
                    error.A => 0,
                    error.B => 1,
                    error.C => 2,
                };
                try expect_equal(@as(u64, 3), b);
            }
            {
                var a: Error!u64 = 3;
                _ = &a;
                const b: u64 = if (a) |*x| x.* else |err| switch (err) {
                    error.A => 0,
                    error.B => @intFromError(err) + 4,
                    error.C => @intFromError(err) + 4,
                };
                try expect_equal(@as(u64, 3), b);
            }
            {
                var a: Error!u64 = error.A;
                _ = &a;
                const b: u64 = if (a) |*x| x.* else |err| switch (err) {
                    error.A => 0,
                    error.B => @intFromError(err) + 4,
                    error.C => @intFromError(err) + 4,
                };
                try expect_equal(@as(u64, 0), b);
            }
        }

        fn test_multi() !void {
            {
                var a: Error!u64 = 3;
                _ = &a;
                const b: u64 = if (a) |x| x else |err| switch (err) {
                    error.A, error.B => 0,
                    error.C => @intFromError(err) + 4,
                };
                try expect_equal(@as(u64, 3), b);
            }
            {
                var a: Error!u64 = 3;
                _ = &a;
                const b: u64 = if (a) |x| x else |err| switch (err) {
                    error.A => 0,
                    error.B, error.C => @intFromError(err) + 4,
                };
                try expect_equal(@as(u64, 3), b);
            }
            {
                var a: Error!u64 = error.A;
                _ = &a;
                const b: u64 = if (a) |x| x else |err| switch (err) {
                    error.A, error.B => 0,
                    error.C => @intFromError(err) + 4,
                };
                try expect_equal(@as(u64, 0), b);
            }
            {
                var a: Error!u64 = error.A;
                _ = &a;
                const b: u64 = if (a) |x| x else |err| switch (err) {
                    error.A => 0,
                    error.B, error.C => @intFromError(err) + 4,
                };
                try expect_equal(@as(u64, 0), b);
            }
            {
                var a: Error!u64 = error.B;
                _ = &a;
                const b: u64 = if (a) |x| x else |err| switch (err) {
                    error.A => 0,
                    error.B, error.C => @intFromError(err) + 4,
                };
                try expect_equal(@as(u64, @intFromError(error.B) + 4), b);
            }
        }

        fn test_multi_ptr() !void {
            {
                var a: Error!u64 = 3;
                _ = &a;
                const b: u64 = if (a) |*x| x.* else |err| switch (err) {
                    error.A, error.B => 0,
                    error.C => @intFromError(err) + 4,
                };
                try expect_equal(@as(u64, 3), b);
            }
            {
                var a: Error!u64 = 3;
                _ = &a;
                const b: u64 = if (a) |*x| x.* else |err| switch (err) {
                    error.A => 0,
                    error.B, error.C => @intFromError(err) + 4,
                };
                try expect_equal(@as(u64, 3), b);
            }
            {
                var a: Error!u64 = error.A;
                _ = &a;
                const b: u64 = if (a) |*x| x.* else |err| switch (err) {
                    error.A, error.B => 0,
                    error.C => @intFromError(err) + 4,
                };
                try expect_equal(@as(u64, 0), b);
            }
            {
                var a: Error!u64 = error.A;
                _ = &a;
                const b: u64 = if (a) |*x| x.* else |err| switch (err) {
                    error.A => 0,
                    error.B, error.C => @intFromError(err) + 4,
                };
                try expect_equal(@as(u64, 0), b);
            }
            {
                var a: Error!u64 = error.B;
                _ = &a;
                const b: u64 = if (a) |*x| x.* else |err| switch (err) {
                    error.A => 0,
                    error.B, error.C => @intFromError(err) + 4,
                };
                try expect_equal(@as(u64, @intFromError(error.B) + 4), b);
            }
        }

        fn test_else() !void {
            {
                var a: Error!u64 = 3;
                _ = &a;
                const b: u64 = if (a) |x| x else |err| switch (err) {
                    error.A => 0,
                    else => 1,
                };
                try expect_equal(@as(u64, 3), b);
            }
            {
                var a: Error!u64 = 3;
                _ = &a;
                const b: u64 = if (a) |x| x else |err| switch (err) {
                    error.A => 0,
                    else => @intFromError(err) + 4,
                };
                try expect_equal(@as(u64, 3), b);
            }
            {
                var a: Error!u64 = error.A;
                _ = &a;
                const b: u64 = if (a) |x| x else |err| switch (err) {
                    error.A => 1,
                    else => @intFromError(err) + 4,
                };
                try expect_equal(@as(u64, 1), b);
            }
            {
                var a: Error!u64 = error.B;
                _ = &a;
                const b: u64 = if (a) |x| x else |err| switch (err) {
                    error.A => 0,
                    else => 1,
                };
                try expect_equal(@as(u64, 1), b);
            }
            {
                var a: Error!u64 = error.B;
                _ = &a;
                const b: u64 = if (a) |x| x else |err| switch (err) {
                    error.A => 0,
                    else => @intFromError(err) + 4,
                };
                try expect_equal(@as(u64, @intFromError(error.B) + 4), b);
            }
        }

        fn test_else_ptr() !void {
            {
                var a: Error!u64 = 3;
                _ = &a;
                const b: u64 = if (a) |*x| x.* else |err| switch (err) {
                    error.A => 0,
                    else => 1,
                };
                try expect_equal(@as(u64, 3), b);
            }
            {
                var a: Error!u64 = 3;
                _ = &a;
                const b: u64 = if (a) |*x| x.* else |err| switch (err) {
                    error.A => 0,
                    else => @intFromError(err) + 4,
                };
                try expect_equal(@as(u64, 3), b);
            }
            {
                var a: Error!u64 = error.A;
                _ = &a;
                const b: u64 = if (a) |*x| x.* else |err| switch (err) {
                    error.A => 1,
                    else => @intFromError(err) + 4,
                };
                try expect_equal(@as(u64, 1), b);
            }
            {
                var a: Error!u64 = error.B;
                _ = &a;
                const b: u64 = if (a) |*x| x.* else |err| switch (err) {
                    error.A => 0,
                    else => 1,
                };
                try expect_equal(@as(u64, 1), b);
            }
            {
                var a: Error!u64 = error.B;
                _ = &a;
                const b: u64 = if (a) |*x| x.* else |err| switch (err) {
                    error.A => 0,
                    else => @intFromError(err) + 4,
                };
                try expect_equal(@as(u64, @intFromError(error.B) + 4), b);
            }
        }

        fn test_capture() !void {
            {
                var a: Error!u64 = error.A;
                _ = &a;
                const b: u64 = if (a) |x| x else |err| switch (err) {
                    error.A => |e| @intFromError(e) + 4,
                    else => 0,
                };
                try expect_equal(@as(u64, @intFromError(error.A) + 4), b);
            }
            {
                var a: Error!u64 = error.A;
                _ = &a;
                const b: u64 = if (a) |x| x else |err| switch (err) {
                    error.A => 0,
                    else => |e| @intFromError(e) + 4,
                };
                try expect_equal(@as(u64, 0), b);
            }
            {
                var a: Error!u64 = error.B;
                _ = &a;
                const b: u64 = if (a) |x| x else |err| switch (err) {
                    error.A => 0,
                    else => |e| @intFromError(e) + 4,
                };
                try expect_equal(@as(u64, @intFromError(error.B) + 4), b);
            }
            {
                var a: Error!u64 = error.B;
                _ = &a;
                const b: u64 = if (a) |x| x else |err| switch (err) {
                    error.A => |e| @intFromError(e) + 4,
                    else => |e| @intFromError(e) + 4,
                };
                try expect_equal(@as(u64, @intFromError(error.B) + 4), b);
            }
            {
                var a: Error!u64 = error.B;
                _ = &a;
                const b: u64 = if (a) |x| x else |err| switch (err) {
                    error.A => 0,
                    error.B, error.C => |e| @intFromError(e) + 4,
                };
                try expect_equal(@as(u64, @intFromError(error.B) + 4), b);
            }
        }

        fn test_capture_ptr() !void {
            {
                var a: Error!u64 = error.A;
                _ = &a;
                const b: u64 = if (a) |*x| x.* else |err| switch (err) {
                    error.A => |e| @intFromError(e) + 4,
                    else => 0,
                };
                try expect_equal(@as(u64, @intFromError(error.A) + 4), b);
            }
            {
                var a: Error!u64 = error.A;
                _ = &a;
                const b: u64 = if (a) |*x| x.* else |err| switch (err) {
                    error.A => 0,
                    else => |e| @intFromError(e) + 4,
                };
                try expect_equal(@as(u64, 0), b);
            }
            {
                var a: Error!u64 = error.B;
                _ = &a;
                const b: u64 = if (a) |*x| x.* else |err| switch (err) {
                    error.A => 0,
                    else => |e| @intFromError(e) + 4,
                };
                try expect_equal(@as(u64, @intFromError(error.B) + 4), b);
            }
            {
                var a: Error!u64 = error.B;
                _ = &a;
                const b: u64 = if (a) |*x| x.* else |err| switch (err) {
                    error.A => |e| @intFromError(e) + 4,
                    else => |e| @intFromError(e) + 4,
                };
                try expect_equal(@as(u64, @intFromError(error.B) + 4), b);
            }
            {
                var a: Error!u64 = error.B;
                _ = &a;
                const b: u64 = if (a) |*x| x.* else |err| switch (err) {
                    error.A => 0,
                    error.B, error.C => |e| @intFromError(e) + 4,
                };
                try expect_equal(@as(u64, @intFromError(error.B) + 4), b);
            }
        }

        fn test_inline() !void {
            {
                var a: Error!u64 = error.B;
                _ = &a;
                const b: u64 = if (a) |x| x else |err| switch (err) {
                    error.A => 0,
                    inline else => @intFromError(err) + 4,
                };
                try expect_equal(@as(u64, @intFromError(error.B) + 4), b);
            }
            {
                var a: Error!u64 = error.B;
                _ = &a;
                const b: u64 = if (a) |x| x else |err| switch (err) {
                    error.A => |e| @intFromError(e) + 4,
                    inline else => @intFromError(err) + 4,
                };
                try expect_equal(@as(u64, @intFromError(error.B) + 4), b);
            }
            {
                var a: Error!u64 = error.B;
                _ = &a;
                const b: u64 = if (a) |x| x else |err| switch (err) {
                    inline else => |e| @intFromError(e) + 4,
                };
                try expect_equal(@as(u64, @intFromError(error.B) + 4), b);
            }
            {
                var a: Error!u64 = error.B;
                _ = &a;
                const b: u64 = if (a) |x| x else |err| switch (err) {
                    error.A => 0,
                    inline error.B, error.C => |e| @intFromError(e) + 4,
                };
                try expect_equal(@as(u64, @intFromError(error.B) + 4), b);
            }
        }

        fn test_inline_ptr() !void {
            {
                var a: Error!u64 = error.B;
                _ = &a;
                const b: u64 = if (a) |*x| x.* else |err| switch (err) {
                    error.A => 0,
                    inline else => @intFromError(err) + 4,
                };
                try expect_equal(@as(u64, @intFromError(error.B) + 4), b);
            }
            {
                var a: Error!u64 = error.B;
                _ = &a;
                const b: u64 = if (a) |*x| x.* else |err| switch (err) {
                    error.A => |e| @intFromError(e) + 4,
                    inline else => @intFromError(err) + 4,
                };
                try expect_equal(@as(u64, @intFromError(error.B) + 4), b);
            }
            {
                var a: Error!u64 = error.B;
                _ = &a;
                const b: u64 = if (a) |*x| x.* else |err| switch (err) {
                    inline else => |e| @intFromError(e) + 4,
                };
                try expect_equal(@as(u64, @intFromError(error.B) + 4), b);
            }
            {
                var a: Error!u64 = error.B;
                _ = &a;
                const b: u64 = if (a) |*x| x.* else |err| switch (err) {
                    error.A => 0,
                    inline error.B, error.C => |e| @intFromError(e) + 4,
                };
                try expect_equal(@as(u64, @intFromError(error.B) + 4), b);
            }
        }

        fn test_empty_err_set() !void {
            {
                var a: error{}!u64 = 0;
                _ = &a;
                const b: u64 = if (a) |x| x else |err| switch (err) {
                    else => |e| return e,
                };
                try expect_equal(@as(u64, 0), b);
            }
            {
                var a: error{}!u64 = 0;
                _ = &a;
                const b: u64 = if (a) |x| x else |err| switch (err) {
                    error.UnknownError => return error.Fail,
                    else => |e| return e,
                };
                try expect_equal(@as(u64, 0), b);
            }
        }

        fn test_empty_err_set_ptr() !void {
            {
                var a: error{}!u64 = 0;
                _ = &a;
                const b: u64 = if (a) |*x| x.* else |err| switch (err) {
                    else => |e| return e,
                };
                try expect_equal(@as(u64, 0), b);
            }
            {
                var a: error{}!u64 = 0;
                _ = &a;
                const b: u64 = if (a) |*x| x.* else |err| switch (err) {
                    error.UnknownError => return error.Fail,
                    else => |e| return e,
                };
                try expect_equal(@as(u64, 0), b);
            }
        }

        fn test_address_of() !void {
            if (builtin.zig_backend == .stage2_wasm) return error.SkipZigTest;
            {
                const a: anyerror!usize = 0;
                const ptr = &(if (a) |*v| v.* else |e| switch (e) {
                    else => 3,
                });
                comptime assert(@TypeOf(ptr) == *const usize);
                try expect_equal(ptr, &(a catch unreachable));
            }
            {
                const a: anyerror!usize = error.A;
                const ptr = &(if (a) |*v| v.* else |e| switch (e) {
                    else => 3,
                });
                comptime assert(@TypeOf(ptr) == *const comptime_int);
                try expect_equal(3, ptr.*);
            }
            {
                var a: anyerror!usize = 0;
                _ = &a;
                const ptr = &(if (a) |*v| v.* else |e| switch (e) {
                    else => return,
                });
                comptime assert(@TypeOf(ptr) == *usize);
                ptr.* += 1;
                try expect_equal(@as(usize, 1), a catch unreachable);
            }
            {
                var a: anyerror!usize = error.A;
                _ = &a;
                const ptr = &(if (a) |*v| v.* else |e| switch (e) {
                    else => return,
                });
                comptime assert(@TypeOf(ptr) == *usize);
                unreachable;
            }
        }
    };

    try comptime S.do_the_test();
    try S.do_the_test();
}
