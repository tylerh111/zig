const std = @import("std.zig");
const assert = std.debug.assert;
const testing = std.testing;
const mem = std.mem;
const math = std.math;

pub const Mode = enum { stable, unstable };

pub const block = @import("sort/block.zig").block;
pub const pdq = @import("sort/pdq.zig").pdq;
pub const pdq_context = @import("sort/pdq.zig").pdq_context;

/// Stable in-place sort. O(n) best case, O(pow(n, 2)) worst case.
/// O(1) memory (no allocator required).
/// Sorts in ascending order with respect to the given `less_than` function.
pub fn insertion(
    comptime T: type,
    items: []T,
    context: anytype,
    comptime lessThanFn: fn (@TypeOf(context), lhs: T, rhs: T) bool,
) void {
    const Context = struct {
        items: []T,
        sub_ctx: @TypeOf(context),

        pub fn less_than(ctx: @This(), a: usize, b: usize) bool {
            return lessThanFn(ctx.sub_ctx, ctx.items[a], ctx.items[b]);
        }

        pub fn swap(ctx: @This(), a: usize, b: usize) void {
            return mem.swap(T, &ctx.items[a], &ctx.items[b]);
        }
    };
    insertion_context(0, items.len, Context{ .items = items, .sub_ctx = context });
}

/// Stable in-place sort. O(n) best case, O(pow(n, 2)) worst case.
/// O(1) memory (no allocator required).
/// `context` must have methods `swap` and `less_than`,
/// which each take 2 `usize` parameters indicating the index of an item.
/// Sorts in ascending order with respect to `less_than`.
pub fn insertion_context(a: usize, b: usize, context: anytype) void {
    assert(a <= b);

    var i = a + 1;
    while (i < b) : (i += 1) {
        var j = i;
        while (j > a and context.less_than(j, j - 1)) : (j -= 1) {
            context.swap(j, j - 1);
        }
    }
}

/// Unstable in-place sort. O(n*log(n)) best case, worst case and average case.
/// O(1) memory (no allocator required).
/// Sorts in ascending order with respect to the given `less_than` function.
pub fn heap(
    comptime T: type,
    items: []T,
    context: anytype,
    comptime lessThanFn: fn (@TypeOf(context), lhs: T, rhs: T) bool,
) void {
    const Context = struct {
        items: []T,
        sub_ctx: @TypeOf(context),

        pub fn less_than(ctx: @This(), a: usize, b: usize) bool {
            return lessThanFn(ctx.sub_ctx, ctx.items[a], ctx.items[b]);
        }

        pub fn swap(ctx: @This(), a: usize, b: usize) void {
            return mem.swap(T, &ctx.items[a], &ctx.items[b]);
        }
    };
    heap_context(0, items.len, Context{ .items = items, .sub_ctx = context });
}

/// Unstable in-place sort. O(n*log(n)) best case, worst case and average case.
/// O(1) memory (no allocator required).
/// `context` must have methods `swap` and `less_than`,
/// which each take 2 `usize` parameters indicating the index of an item.
/// Sorts in ascending order with respect to `less_than`.
pub fn heap_context(a: usize, b: usize, context: anytype) void {
    assert(a <= b);
    // build the heap in linear time.
    var i = a + (b - a) / 2;
    while (i > a) {
        i -= 1;
        sift_down(a, i, b, context);
    }

    // pop maximal elements from the heap.
    i = b;
    while (i > a) {
        i -= 1;
        context.swap(a, i);
        sift_down(a, a, i, context);
    }
}

fn sift_down(a: usize, target: usize, b: usize, context: anytype) void {
    var cur = target;
    while (true) {
        // When we don't overflow from the multiply below, the following expression equals (2*cur) - (2*a) + a + 1
        // The `+ a + 1` is safe because:
        //  for `a > 0` then `2a >= a + 1`.
        //  for `a = 0`, the expression equals `2*cur+1`. `2*cur` is an even number, therefore adding 1 is safe.
        var child = (math.mul(usize, cur - a, 2) catch break) + a + 1;

        // stop if we overshot the boundary
        if (!(child < b)) break;

        // `next_child` is at most `b`, therefore no overflow is possible
        const next_child = child + 1;

        // store the greater child in `child`
        if (next_child < b and context.less_than(child, next_child)) {
            child = next_child;
        }

        // stop if the Heap invariant holds at `cur`.
        if (context.less_than(child, cur)) break;

        // swap `cur` with the greater child,
        // move one step down, and continue sifting.
        context.swap(child, cur);
        cur = child;
    }
}

/// Use to generate a comparator function for a given type. e.g. `sort(u8, slice, {}, asc(u8))`.
pub fn asc(comptime T: type) fn (void, T, T) bool {
    return struct {
        pub fn inner(_: void, a: T, b: T) bool {
            return a < b;
        }
    }.inner;
}

/// Use to generate a comparator function for a given type. e.g. `sort(u8, slice, {}, desc(u8))`.
pub fn desc(comptime T: type) fn (void, T, T) bool {
    return struct {
        pub fn inner(_: void, a: T, b: T) bool {
            return a > b;
        }
    }.inner;
}

const asc_u8 = asc(u8);
const asc_i32 = asc(i32);
const desc_u8 = desc(u8);
const desc_i32 = desc(i32);

const sort_funcs = &[_]fn (comptime type, anytype, anytype, comptime anytype) void{
    block,
    pdq,
    insertion,
    heap,
};

const context_sort_funcs = &[_]fn (usize, usize, anytype) void{
    // blockContext,
    pdq_context,
    insertion_context,
    heap_context,
};

const IdAndValue = struct {
    id: usize,
    value: i32,

    fn less_than(context: void, a: IdAndValue, b: IdAndValue) bool {
        _ = context;
        return a.value < b.value;
    }
};

test "stable sort" {
    const expected = [_]IdAndValue{
        IdAndValue{ .id = 0, .value = 0 },
        IdAndValue{ .id = 1, .value = 0 },
        IdAndValue{ .id = 2, .value = 0 },
        IdAndValue{ .id = 0, .value = 1 },
        IdAndValue{ .id = 1, .value = 1 },
        IdAndValue{ .id = 2, .value = 1 },
        IdAndValue{ .id = 0, .value = 2 },
        IdAndValue{ .id = 1, .value = 2 },
        IdAndValue{ .id = 2, .value = 2 },
    };

    var cases = [_][9]IdAndValue{
        [_]IdAndValue{
            IdAndValue{ .id = 0, .value = 0 },
            IdAndValue{ .id = 0, .value = 1 },
            IdAndValue{ .id = 0, .value = 2 },
            IdAndValue{ .id = 1, .value = 0 },
            IdAndValue{ .id = 1, .value = 1 },
            IdAndValue{ .id = 1, .value = 2 },
            IdAndValue{ .id = 2, .value = 0 },
            IdAndValue{ .id = 2, .value = 1 },
            IdAndValue{ .id = 2, .value = 2 },
        },
        [_]IdAndValue{
            IdAndValue{ .id = 0, .value = 2 },
            IdAndValue{ .id = 0, .value = 1 },
            IdAndValue{ .id = 0, .value = 0 },
            IdAndValue{ .id = 1, .value = 2 },
            IdAndValue{ .id = 1, .value = 1 },
            IdAndValue{ .id = 1, .value = 0 },
            IdAndValue{ .id = 2, .value = 2 },
            IdAndValue{ .id = 2, .value = 1 },
            IdAndValue{ .id = 2, .value = 0 },
        },
    };

    for (&cases) |*case| {
        block(IdAndValue, (case.*)[0..], {}, IdAndValue.less_than);
        for (case.*, 0..) |item, i| {
            try testing.expect(item.id == expected[i].id);
            try testing.expect(item.value == expected[i].value);
        }
    }
}

test "sort" {
    const u8cases = [_][]const []const u8{
        &[_][]const u8{
            "",
            "",
        },
        &[_][]const u8{
            "a",
            "a",
        },
        &[_][]const u8{
            "az",
            "az",
        },
        &[_][]const u8{
            "za",
            "az",
        },
        &[_][]const u8{
            "asdf",
            "adfs",
        },
        &[_][]const u8{
            "one",
            "eno",
        },
    };

    const i32cases = [_][]const []const i32{
        &[_][]const i32{
            &[_]i32{},
            &[_]i32{},
        },
        &[_][]const i32{
            &[_]i32{1},
            &[_]i32{1},
        },
        &[_][]const i32{
            &[_]i32{ 0, 1 },
            &[_]i32{ 0, 1 },
        },
        &[_][]const i32{
            &[_]i32{ 1, 0 },
            &[_]i32{ 0, 1 },
        },
        &[_][]const i32{
            &[_]i32{ 1, -1, 0 },
            &[_]i32{ -1, 0, 1 },
        },
        &[_][]const i32{
            &[_]i32{ 2, 1, 3 },
            &[_]i32{ 1, 2, 3 },
        },
        &[_][]const i32{
            &[_]i32{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 55, 32, 39, 58, 21, 88, 43, 22, 59 },
            &[_]i32{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 21, 22, 32, 39, 43, 55, 58, 59, 88 },
        },
    };

    inline for (sort_funcs) |sort_fn| {
        for (u8cases) |case| {
            var buf: [20]u8 = undefined;
            const slice = buf[0..case[0].len];
            @memcpy(slice, case[0]);
            sort_fn(u8, slice, {}, asc_u8);
            try testing.expect(mem.eql(u8, slice, case[1]));
        }

        for (i32cases) |case| {
            var buf: [20]i32 = undefined;
            const slice = buf[0..case[0].len];
            @memcpy(slice, case[0]);
            sort_fn(i32, slice, {}, asc_i32);
            try testing.expect(mem.eql(i32, slice, case[1]));
        }
    }
}

test "sort descending" {
    const rev_cases = [_][]const []const i32{
        &[_][]const i32{
            &[_]i32{},
            &[_]i32{},
        },
        &[_][]const i32{
            &[_]i32{1},
            &[_]i32{1},
        },
        &[_][]const i32{
            &[_]i32{ 0, 1 },
            &[_]i32{ 1, 0 },
        },
        &[_][]const i32{
            &[_]i32{ 1, 0 },
            &[_]i32{ 1, 0 },
        },
        &[_][]const i32{
            &[_]i32{ 1, -1, 0 },
            &[_]i32{ 1, 0, -1 },
        },
        &[_][]const i32{
            &[_]i32{ 2, 1, 3 },
            &[_]i32{ 3, 2, 1 },
        },
    };

    inline for (sort_funcs) |sort_fn| {
        for (rev_cases) |case| {
            var buf: [8]i32 = undefined;
            const slice = buf[0..case[0].len];
            @memcpy(slice, case[0]);
            sort_fn(i32, slice, {}, desc_i32);
            try testing.expect(mem.eql(i32, slice, case[1]));
        }
    }
}

test "sort with context in the middle of a slice" {
    const Context = struct {
        items: []i32,

        pub fn less_than(ctx: @This(), a: usize, b: usize) bool {
            return ctx.items[a] < ctx.items[b];
        }

        pub fn swap(ctx: @This(), a: usize, b: usize) void {
            return mem.swap(i32, &ctx.items[a], &ctx.items[b]);
        }
    };

    const i32cases = [_][]const []const i32{
        &[_][]const i32{
            &[_]i32{ 0, 1, 8, 3, 6, 5, 4, 2, 9, 7, 10, 55, 32, 39, 58, 21, 88, 43, 22, 59 },
            &[_]i32{ 50, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 21, 22, 32, 39, 43, 55, 58, 59, 88 },
        },
    };

    const ranges = [_]struct { start: usize, end: usize }{
        .{ .start = 10, .end = 20 },
        .{ .start = 1, .end = 11 },
        .{ .start = 3, .end = 7 },
    };

    inline for (context_sort_funcs) |sort_fn| {
        for (i32cases) |case| {
            for (ranges) |range| {
                var buf: [20]i32 = undefined;
                const slice = buf[0..case[0].len];
                @memcpy(slice, case[0]);
                sort_fn(range.start, range.end, Context{ .items = slice });
                try testing.expect_equal_slices(i32, case[1][range.start..range.end], slice[range.start..range.end]);
            }
        }
    }
}

test "sort fuzz testing" {
    var prng = std.Random.DefaultPrng.init(0x12345678);
    const random = prng.random();
    const test_case_count = 10;

    inline for (sort_funcs) |sort_fn| {
        var i: usize = 0;
        while (i < test_case_count) : (i += 1) {
            const array_size = random.int_range_less_than(usize, 0, 1000);
            const array = try testing.allocator.alloc(i32, array_size);
            defer testing.allocator.free(array);
            // populate with random data
            for (array) |*item| {
                item.* = random.int_range_less_than(i32, 0, 100);
            }
            sort_fn(i32, array, {}, asc_i32);
            try testing.expect(is_sorted(i32, array, {}, asc_i32));
        }
    }
}

/// Returns the index of an element in `items` equal to `key`.
/// If there are multiple such elements, returns the index of any one of them.
/// If there are no such elements, returns `null`.
///
/// `items` must be sorted in ascending order with respect to `compare_fn`.
///
/// O(log n) complexity.
pub fn binary_search(
    comptime T: type,
    key: anytype,
    items: []const T,
    context: anytype,
    comptime compare_fn: fn (context: @TypeOf(context), key: @TypeOf(key), mid_item: T) math.Order,
) ?usize {
    var left: usize = 0;
    var right: usize = items.len;

    while (left < right) {
        // Avoid overflowing in the midpoint calculation
        const mid = left + (right - left) / 2;
        // Compare the key with the midpoint element
        switch (compare_fn(context, key, items[mid])) {
            .eq => return mid,
            .gt => left = mid + 1,
            .lt => right = mid,
        }
    }

    return null;
}

test binary_search {
    const S = struct {
        fn order_u32(context: void, lhs: u32, rhs: u32) math.Order {
            _ = context;
            return math.order(lhs, rhs);
        }
        fn order_i32(context: void, lhs: i32, rhs: i32) math.Order {
            _ = context;
            return math.order(lhs, rhs);
        }
    };
    try testing.expect_equal(
        @as(?usize, null),
        binary_search(u32, @as(u32, 1), &[_]u32{}, {}, S.order_u32),
    );
    try testing.expect_equal(
        @as(?usize, 0),
        binary_search(u32, @as(u32, 1), &[_]u32{1}, {}, S.order_u32),
    );
    try testing.expect_equal(
        @as(?usize, null),
        binary_search(u32, @as(u32, 1), &[_]u32{0}, {}, S.order_u32),
    );
    try testing.expect_equal(
        @as(?usize, null),
        binary_search(u32, @as(u32, 0), &[_]u32{1}, {}, S.order_u32),
    );
    try testing.expect_equal(
        @as(?usize, 4),
        binary_search(u32, @as(u32, 5), &[_]u32{ 1, 2, 3, 4, 5 }, {}, S.order_u32),
    );
    try testing.expect_equal(
        @as(?usize, 0),
        binary_search(u32, @as(u32, 2), &[_]u32{ 2, 4, 8, 16, 32, 64 }, {}, S.order_u32),
    );
    try testing.expect_equal(
        @as(?usize, 1),
        binary_search(i32, @as(i32, -4), &[_]i32{ -7, -4, 0, 9, 10 }, {}, S.order_i32),
    );
    try testing.expect_equal(
        @as(?usize, 3),
        binary_search(i32, @as(i32, 98), &[_]i32{ -100, -25, 2, 98, 99, 100 }, {}, S.order_i32),
    );
    const R = struct {
        b: i32,
        e: i32,

        fn r(b: i32, e: i32) @This() {
            return @This(){ .b = b, .e = e };
        }

        fn order(context: void, key: i32, mid_item: @This()) math.Order {
            _ = context;

            if (key < mid_item.b) {
                return .lt;
            }

            if (key > mid_item.e) {
                return .gt;
            }

            return .eq;
        }
    };
    try testing.expect_equal(
        @as(?usize, null),
        binary_search(R, @as(i32, -45), &[_]R{ R.r(-100, -50), R.r(-40, -20), R.r(-10, 20), R.r(30, 40) }, {}, R.order),
    );
    try testing.expect_equal(
        @as(?usize, 2),
        binary_search(R, @as(i32, 10), &[_]R{ R.r(-100, -50), R.r(-40, -20), R.r(-10, 20), R.r(30, 40) }, {}, R.order),
    );
    try testing.expect_equal(
        @as(?usize, 1),
        binary_search(R, @as(i32, -20), &[_]R{ R.r(-100, -50), R.r(-40, -20), R.r(-10, 20), R.r(30, 40) }, {}, R.order),
    );
}

/// Returns the index of the first element in `items` greater than or equal to `key`,
/// or `items.len` if all elements are less than `key`.
///
/// `items` must be sorted in ascending order with respect to `compare_fn`.
///
/// O(log n) complexity.
pub fn lower_bound(
    comptime T: type,
    key: anytype,
    items: []const T,
    context: anytype,
    comptime less_than: fn (context: @TypeOf(context), lhs: @TypeOf(key), rhs: T) bool,
) usize {
    var left: usize = 0;
    var right: usize = items.len;

    while (left < right) {
        const mid = left + (right - left) / 2;
        if (less_than(context, items[mid], key)) {
            left = mid + 1;
        } else {
            right = mid;
        }
    }

    return left;
}

test lower_bound {
    const S = struct {
        fn lower_u32(context: void, lhs: u32, rhs: u32) bool {
            _ = context;
            return lhs < rhs;
        }
        fn lower_i32(context: void, lhs: i32, rhs: i32) bool {
            _ = context;
            return lhs < rhs;
        }
        fn lower_f32(context: void, lhs: f32, rhs: f32) bool {
            _ = context;
            return lhs < rhs;
        }
    };

    try testing.expect_equal(
        @as(usize, 0),
        lower_bound(u32, @as(u32, 0), &[_]u32{}, {}, S.lower_u32),
    );
    try testing.expect_equal(
        @as(usize, 0),
        lower_bound(u32, @as(u32, 0), &[_]u32{ 2, 4, 8, 16, 32, 64 }, {}, S.lower_u32),
    );
    try testing.expect_equal(
        @as(usize, 0),
        lower_bound(u32, @as(u32, 2), &[_]u32{ 2, 4, 8, 16, 32, 64 }, {}, S.lower_u32),
    );
    try testing.expect_equal(
        @as(usize, 2),
        lower_bound(u32, @as(u32, 5), &[_]u32{ 2, 4, 8, 16, 32, 64 }, {}, S.lower_u32),
    );
    try testing.expect_equal(
        @as(usize, 2),
        lower_bound(u32, @as(u32, 8), &[_]u32{ 2, 4, 8, 16, 32, 64 }, {}, S.lower_u32),
    );
    try testing.expect_equal(
        @as(usize, 6),
        lower_bound(u32, @as(u32, 8), &[_]u32{ 2, 4, 7, 7, 7, 7, 16, 32, 64 }, {}, S.lower_u32),
    );
    try testing.expect_equal(
        @as(usize, 2),
        lower_bound(u32, @as(u32, 8), &[_]u32{ 2, 4, 8, 8, 8, 8, 16, 32, 64 }, {}, S.lower_u32),
    );
    try testing.expect_equal(
        @as(usize, 5),
        lower_bound(u32, @as(u32, 64), &[_]u32{ 2, 4, 8, 16, 32, 64 }, {}, S.lower_u32),
    );
    try testing.expect_equal(
        @as(usize, 6),
        lower_bound(u32, @as(u32, 100), &[_]u32{ 2, 4, 8, 16, 32, 64 }, {}, S.lower_u32),
    );
    try testing.expect_equal(
        @as(usize, 2),
        lower_bound(i32, @as(i32, 5), &[_]i32{ 2, 4, 8, 16, 32, 64 }, {}, S.lower_i32),
    );
    try testing.expect_equal(
        @as(usize, 1),
        lower_bound(f32, @as(f32, -33.4), &[_]f32{ -54.2, -26.7, 0.0, 56.55, 100.1, 322.0 }, {}, S.lower_f32),
    );
}

/// Returns the index of the first element in `items` greater than `key`,
/// or `items.len` if all elements are less than or equal to `key`.
///
/// `items` must be sorted in ascending order with respect to `compare_fn`.
///
/// O(log n) complexity.
pub fn upper_bound(
    comptime T: type,
    key: anytype,
    items: []const T,
    context: anytype,
    comptime less_than: fn (context: @TypeOf(context), lhs: @TypeOf(key), rhs: T) bool,
) usize {
    var left: usize = 0;
    var right: usize = items.len;

    while (left < right) {
        const mid = left + (right - left) / 2;
        if (!less_than(context, key, items[mid])) {
            left = mid + 1;
        } else {
            right = mid;
        }
    }

    return left;
}

test upper_bound {
    const S = struct {
        fn lower_u32(context: void, lhs: u32, rhs: u32) bool {
            _ = context;
            return lhs < rhs;
        }
        fn lower_i32(context: void, lhs: i32, rhs: i32) bool {
            _ = context;
            return lhs < rhs;
        }
        fn lower_f32(context: void, lhs: f32, rhs: f32) bool {
            _ = context;
            return lhs < rhs;
        }
    };

    try testing.expect_equal(
        @as(usize, 0),
        upper_bound(u32, @as(u32, 0), &[_]u32{}, {}, S.lower_u32),
    );
    try testing.expect_equal(
        @as(usize, 0),
        upper_bound(u32, @as(u32, 0), &[_]u32{ 2, 4, 8, 16, 32, 64 }, {}, S.lower_u32),
    );
    try testing.expect_equal(
        @as(usize, 1),
        upper_bound(u32, @as(u32, 2), &[_]u32{ 2, 4, 8, 16, 32, 64 }, {}, S.lower_u32),
    );
    try testing.expect_equal(
        @as(usize, 2),
        upper_bound(u32, @as(u32, 5), &[_]u32{ 2, 4, 8, 16, 32, 64 }, {}, S.lower_u32),
    );
    try testing.expect_equal(
        @as(usize, 6),
        upper_bound(u32, @as(u32, 8), &[_]u32{ 2, 4, 7, 7, 7, 7, 16, 32, 64 }, {}, S.lower_u32),
    );
    try testing.expect_equal(
        @as(usize, 6),
        upper_bound(u32, @as(u32, 8), &[_]u32{ 2, 4, 8, 8, 8, 8, 16, 32, 64 }, {}, S.lower_u32),
    );
    try testing.expect_equal(
        @as(usize, 3),
        upper_bound(u32, @as(u32, 8), &[_]u32{ 2, 4, 8, 16, 32, 64 }, {}, S.lower_u32),
    );
    try testing.expect_equal(
        @as(usize, 6),
        upper_bound(u32, @as(u32, 64), &[_]u32{ 2, 4, 8, 16, 32, 64 }, {}, S.lower_u32),
    );
    try testing.expect_equal(
        @as(usize, 6),
        upper_bound(u32, @as(u32, 100), &[_]u32{ 2, 4, 8, 16, 32, 64 }, {}, S.lower_u32),
    );
    try testing.expect_equal(
        @as(usize, 2),
        upper_bound(i32, @as(i32, 5), &[_]i32{ 2, 4, 8, 16, 32, 64 }, {}, S.lower_i32),
    );
    try testing.expect_equal(
        @as(usize, 1),
        upper_bound(f32, @as(f32, -33.4), &[_]f32{ -54.2, -26.7, 0.0, 56.55, 100.1, 322.0 }, {}, S.lower_f32),
    );
}

/// Returns a tuple of the lower and upper indices in `items` between which all elements are equal to `key`.
/// If no element in `items` is equal to `key`, both indices are the
/// index of the first element in `items` greater than `key`.
/// If no element in `items` is greater than `key`, both indices equal `items.len`.
///
/// `items` must be sorted in ascending order with respect to `compare_fn`.
///
/// O(log n) complexity.
///
/// See also: `lower_bound` and `upper_bound`.
pub fn equal_range(
    comptime T: type,
    key: anytype,
    items: []const T,
    context: anytype,
    comptime less_than: fn (context: @TypeOf(context), lhs: @TypeOf(key), rhs: T) bool,
) struct { usize, usize } {
    return .{
        lower_bound(T, key, items, context, less_than),
        upper_bound(T, key, items, context, less_than),
    };
}

test equal_range {
    const S = struct {
        fn lower_u32(context: void, lhs: u32, rhs: u32) bool {
            _ = context;
            return lhs < rhs;
        }
        fn lower_i32(context: void, lhs: i32, rhs: i32) bool {
            _ = context;
            return lhs < rhs;
        }
        fn lower_f32(context: void, lhs: f32, rhs: f32) bool {
            _ = context;
            return lhs < rhs;
        }
    };

    try testing.expect_equal(
        @as(struct { usize, usize }, .{ 0, 0 }),
        equal_range(i32, @as(i32, 0), &[_]i32{}, {}, S.lower_i32),
    );
    try testing.expect_equal(
        @as(struct { usize, usize }, .{ 0, 0 }),
        equal_range(i32, @as(i32, 0), &[_]i32{ 2, 4, 8, 16, 32, 64 }, {}, S.lower_i32),
    );
    try testing.expect_equal(
        @as(struct { usize, usize }, .{ 0, 1 }),
        equal_range(i32, @as(i32, 2), &[_]i32{ 2, 4, 8, 16, 32, 64 }, {}, S.lower_i32),
    );
    try testing.expect_equal(
        @as(struct { usize, usize }, .{ 2, 2 }),
        equal_range(i32, @as(i32, 5), &[_]i32{ 2, 4, 8, 16, 32, 64 }, {}, S.lower_i32),
    );
    try testing.expect_equal(
        @as(struct { usize, usize }, .{ 2, 3 }),
        equal_range(i32, @as(i32, 8), &[_]i32{ 2, 4, 8, 16, 32, 64 }, {}, S.lower_i32),
    );
    try testing.expect_equal(
        @as(struct { usize, usize }, .{ 5, 6 }),
        equal_range(i32, @as(i32, 64), &[_]i32{ 2, 4, 8, 16, 32, 64 }, {}, S.lower_i32),
    );
    try testing.expect_equal(
        @as(struct { usize, usize }, .{ 6, 6 }),
        equal_range(i32, @as(i32, 100), &[_]i32{ 2, 4, 8, 16, 32, 64 }, {}, S.lower_i32),
    );
    try testing.expect_equal(
        @as(struct { usize, usize }, .{ 2, 6 }),
        equal_range(i32, @as(i32, 8), &[_]i32{ 2, 4, 8, 8, 8, 8, 15, 22 }, {}, S.lower_i32),
    );
    try testing.expect_equal(
        @as(struct { usize, usize }, .{ 2, 2 }),
        equal_range(u32, @as(u32, 5), &[_]u32{ 2, 4, 8, 16, 32, 64 }, {}, S.lower_u32),
    );
    try testing.expect_equal(
        @as(struct { usize, usize }, .{ 1, 1 }),
        equal_range(f32, @as(f32, -33.4), &[_]f32{ -54.2, -26.7, 0.0, 56.55, 100.1, 322.0 }, {}, S.lower_f32),
    );
}

pub fn arg_min(
    comptime T: type,
    items: []const T,
    context: anytype,
    comptime less_than: fn (@TypeOf(context), lhs: T, rhs: T) bool,
) ?usize {
    if (items.len == 0) {
        return null;
    }

    var smallest = items[0];
    var smallest_index: usize = 0;
    for (items[1..], 0..) |item, i| {
        if (less_than(context, item, smallest)) {
            smallest = item;
            smallest_index = i + 1;
        }
    }

    return smallest_index;
}

test arg_min {
    try testing.expect_equal(@as(?usize, null), arg_min(i32, &[_]i32{}, {}, asc_i32));
    try testing.expect_equal(@as(?usize, 0), arg_min(i32, &[_]i32{1}, {}, asc_i32));
    try testing.expect_equal(@as(?usize, 0), arg_min(i32, &[_]i32{ 1, 2, 3, 4, 5 }, {}, asc_i32));
    try testing.expect_equal(@as(?usize, 3), arg_min(i32, &[_]i32{ 9, 3, 8, 2, 5 }, {}, asc_i32));
    try testing.expect_equal(@as(?usize, 0), arg_min(i32, &[_]i32{ 1, 1, 1, 1, 1 }, {}, asc_i32));
    try testing.expect_equal(@as(?usize, 0), arg_min(i32, &[_]i32{ -10, 1, 10 }, {}, asc_i32));
    try testing.expect_equal(@as(?usize, 3), arg_min(i32, &[_]i32{ 6, 3, 5, 7, 6 }, {}, desc_i32));
}

pub fn min(
    comptime T: type,
    items: []const T,
    context: anytype,
    comptime less_than: fn (context: @TypeOf(context), lhs: T, rhs: T) bool,
) ?T {
    const i = arg_min(T, items, context, less_than) orelse return null;
    return items[i];
}

test min {
    try testing.expect_equal(@as(?i32, null), min(i32, &[_]i32{}, {}, asc_i32));
    try testing.expect_equal(@as(?i32, 1), min(i32, &[_]i32{1}, {}, asc_i32));
    try testing.expect_equal(@as(?i32, 1), min(i32, &[_]i32{ 1, 2, 3, 4, 5 }, {}, asc_i32));
    try testing.expect_equal(@as(?i32, 2), min(i32, &[_]i32{ 9, 3, 8, 2, 5 }, {}, asc_i32));
    try testing.expect_equal(@as(?i32, 1), min(i32, &[_]i32{ 1, 1, 1, 1, 1 }, {}, asc_i32));
    try testing.expect_equal(@as(?i32, -10), min(i32, &[_]i32{ -10, 1, 10 }, {}, asc_i32));
    try testing.expect_equal(@as(?i32, 7), min(i32, &[_]i32{ 6, 3, 5, 7, 6 }, {}, desc_i32));
}

pub fn arg_max(
    comptime T: type,
    items: []const T,
    context: anytype,
    comptime less_than: fn (context: @TypeOf(context), lhs: T, rhs: T) bool,
) ?usize {
    if (items.len == 0) {
        return null;
    }

    var biggest = items[0];
    var biggest_index: usize = 0;
    for (items[1..], 0..) |item, i| {
        if (less_than(context, biggest, item)) {
            biggest = item;
            biggest_index = i + 1;
        }
    }

    return biggest_index;
}

test arg_max {
    try testing.expect_equal(@as(?usize, null), arg_max(i32, &[_]i32{}, {}, asc_i32));
    try testing.expect_equal(@as(?usize, 0), arg_max(i32, &[_]i32{1}, {}, asc_i32));
    try testing.expect_equal(@as(?usize, 4), arg_max(i32, &[_]i32{ 1, 2, 3, 4, 5 }, {}, asc_i32));
    try testing.expect_equal(@as(?usize, 0), arg_max(i32, &[_]i32{ 9, 3, 8, 2, 5 }, {}, asc_i32));
    try testing.expect_equal(@as(?usize, 0), arg_max(i32, &[_]i32{ 1, 1, 1, 1, 1 }, {}, asc_i32));
    try testing.expect_equal(@as(?usize, 2), arg_max(i32, &[_]i32{ -10, 1, 10 }, {}, asc_i32));
    try testing.expect_equal(@as(?usize, 1), arg_max(i32, &[_]i32{ 6, 3, 5, 7, 6 }, {}, desc_i32));
}

pub fn max(
    comptime T: type,
    items: []const T,
    context: anytype,
    comptime less_than: fn (context: @TypeOf(context), lhs: T, rhs: T) bool,
) ?T {
    const i = arg_max(T, items, context, less_than) orelse return null;
    return items[i];
}

test max {
    try testing.expect_equal(@as(?i32, null), max(i32, &[_]i32{}, {}, asc_i32));
    try testing.expect_equal(@as(?i32, 1), max(i32, &[_]i32{1}, {}, asc_i32));
    try testing.expect_equal(@as(?i32, 5), max(i32, &[_]i32{ 1, 2, 3, 4, 5 }, {}, asc_i32));
    try testing.expect_equal(@as(?i32, 9), max(i32, &[_]i32{ 9, 3, 8, 2, 5 }, {}, asc_i32));
    try testing.expect_equal(@as(?i32, 1), max(i32, &[_]i32{ 1, 1, 1, 1, 1 }, {}, asc_i32));
    try testing.expect_equal(@as(?i32, 10), max(i32, &[_]i32{ -10, 1, 10 }, {}, asc_i32));
    try testing.expect_equal(@as(?i32, 3), max(i32, &[_]i32{ 6, 3, 5, 7, 6 }, {}, desc_i32));
}

pub fn is_sorted(
    comptime T: type,
    items: []const T,
    context: anytype,
    comptime less_than: fn (context: @TypeOf(context), lhs: T, rhs: T) bool,
) bool {
    var i: usize = 1;
    while (i < items.len) : (i += 1) {
        if (less_than(context, items[i], items[i - 1])) {
            return false;
        }
    }

    return true;
}

test is_sorted {
    try testing.expect(is_sorted(i32, &[_]i32{}, {}, asc_i32));
    try testing.expect(is_sorted(i32, &[_]i32{10}, {}, asc_i32));
    try testing.expect(is_sorted(i32, &[_]i32{ 1, 2, 3, 4, 5 }, {}, asc_i32));
    try testing.expect(is_sorted(i32, &[_]i32{ -10, 1, 1, 1, 10 }, {}, asc_i32));

    try testing.expect(is_sorted(i32, &[_]i32{}, {}, desc_i32));
    try testing.expect(is_sorted(i32, &[_]i32{-20}, {}, desc_i32));
    try testing.expect(is_sorted(i32, &[_]i32{ 3, 2, 1, 0, -1 }, {}, desc_i32));
    try testing.expect(is_sorted(i32, &[_]i32{ 10, -10 }, {}, desc_i32));

    try testing.expect(is_sorted(i32, &[_]i32{ 1, 1, 1, 1, 1 }, {}, asc_i32));
    try testing.expect(is_sorted(i32, &[_]i32{ 1, 1, 1, 1, 1 }, {}, desc_i32));

    try testing.expect_equal(false, is_sorted(i32, &[_]i32{ 5, 4, 3, 2, 1 }, {}, asc_i32));
    try testing.expect_equal(false, is_sorted(i32, &[_]i32{ 1, 2, 3, 4, 5 }, {}, desc_i32));

    try testing.expect(is_sorted(u8, "abcd", {}, asc_u8));
    try testing.expect(is_sorted(u8, "zyxw", {}, desc_u8));

    try testing.expect_equal(false, is_sorted(u8, "abcd", {}, desc_u8));
    try testing.expect_equal(false, is_sorted(u8, "zyxw", {}, asc_u8));

    try testing.expect(is_sorted(u8, "ffff", {}, asc_u8));
    try testing.expect(is_sorted(u8, "ffff", {}, desc_u8));
}
