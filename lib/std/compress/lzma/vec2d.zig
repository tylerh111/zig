const std = @import("../../std.zig");
const math = std.math;
const mem = std.mem;
const Allocator = std.mem.Allocator;

pub fn Vec2D(comptime T: type) type {
    return struct {
        data: []T,
        cols: usize,

        const Self = @This();

        pub fn init(allocator: Allocator, value: T, size: struct { usize, usize }) !Self {
            const len = try math.mul(usize, size[0], size[1]);
            const data = try allocator.alloc(T, len);
            @memset(data, value);
            return Self{
                .data = data,
                .cols = size[1],
            };
        }

        pub fn deinit(self: *Self, allocator: Allocator) void {
            allocator.free(self.data);
            self.* = undefined;
        }

        pub fn fill(self: *Self, value: T) void {
            @memset(self.data, value);
        }

        inline fn _get(self: Self, row: usize) ![]T {
            const start_row = try math.mul(usize, row, self.cols);
            const end_row = try math.add(usize, start_row, self.cols);
            return self.data[start_row..end_row];
        }

        pub fn get(self: Self, row: usize) ![]const T {
            return self._get(row);
        }

        pub fn get_mut(self: *Self, row: usize) ![]T {
            return self._get(row);
        }
    };
}

const testing = std.testing;
const expect_equal_slices = std.testing.expect_equal_slices;
const expect_error = std.testing.expect_error;

test "init" {
    const allocator = testing.allocator;
    var vec2d = try Vec2D(i32).init(allocator, 1, .{ 2, 3 });
    defer vec2d.deinit(allocator);

    try expect_equal_slices(i32, &.{ 1, 1, 1 }, try vec2d.get(0));
    try expect_equal_slices(i32, &.{ 1, 1, 1 }, try vec2d.get(1));
}

test "init overflow" {
    const allocator = testing.allocator;
    try expect_error(
        error.Overflow,
        Vec2D(i32).init(allocator, 1, .{ math.max_int(usize), math.max_int(usize) }),
    );
}

test "fill" {
    const allocator = testing.allocator;
    var vec2d = try Vec2D(i32).init(allocator, 0, .{ 2, 3 });
    defer vec2d.deinit(allocator);

    vec2d.fill(7);

    try expect_equal_slices(i32, &.{ 7, 7, 7 }, try vec2d.get(0));
    try expect_equal_slices(i32, &.{ 7, 7, 7 }, try vec2d.get(1));
}

test "get" {
    var data = [_]i32{ 0, 1, 2, 3, 4, 5, 6, 7 };
    const vec2d = Vec2D(i32){
        .data = &data,
        .cols = 2,
    };

    try expect_equal_slices(i32, &.{ 0, 1 }, try vec2d.get(0));
    try expect_equal_slices(i32, &.{ 2, 3 }, try vec2d.get(1));
    try expect_equal_slices(i32, &.{ 4, 5 }, try vec2d.get(2));
    try expect_equal_slices(i32, &.{ 6, 7 }, try vec2d.get(3));
}

test "get_mut" {
    var data = [_]i32{ 0, 1, 2, 3, 4, 5, 6, 7 };
    var vec2d = Vec2D(i32){
        .data = &data,
        .cols = 2,
    };

    const row = try vec2d.get_mut(1);
    row[1] = 9;

    try expect_equal_slices(i32, &.{ 0, 1 }, try vec2d.get(0));
    // (1, 1) should be 9.
    try expect_equal_slices(i32, &.{ 2, 9 }, try vec2d.get(1));
    try expect_equal_slices(i32, &.{ 4, 5 }, try vec2d.get(2));
    try expect_equal_slices(i32, &.{ 6, 7 }, try vec2d.get(3));
}

test "get multiplication overflow" {
    const allocator = testing.allocator;
    var matrix = try Vec2D(i32).init(allocator, 0, .{ 3, 4 });
    defer matrix.deinit(allocator);

    const row = (math.max_int(usize) / 4) + 1;
    try expect_error(error.Overflow, matrix.get(row));
    try expect_error(error.Overflow, matrix.get_mut(row));
}

test "get addition overflow" {
    const allocator = testing.allocator;
    var matrix = try Vec2D(i32).init(allocator, 0, .{ 3, 5 });
    defer matrix.deinit(allocator);

    const row = math.max_int(usize) / 5;
    try expect_error(error.Overflow, matrix.get(row));
    try expect_error(error.Overflow, matrix.get_mut(row));
}
