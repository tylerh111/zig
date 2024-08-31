const std = @import("std.zig");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const Order = std.math.Order;
const testing = std.testing;
const expect = testing.expect;
const expect_equal = testing.expect_equal;
const expect_error = testing.expect_error;

/// Priority queue for storing generic data. Initialize with `init`.
/// Provide `compare_fn` that returns `Order.lt` when its second
/// argument should get popped before its third argument,
/// `Order.eq` if the arguments are of equal priority, or `Order.gt`
/// if the third argument should be popped first.
/// For example, to make `pop` return the smallest number, provide
/// `fn less_than(context: void, a: T, b: T) Order { _ = context; return std.math.order(a, b); }`
pub fn PriorityQueue(comptime T: type, comptime Context: type, comptime compare_fn: fn (context: Context, a: T, b: T) Order) type {
    return struct {
        const Self = @This();

        items: []T,
        cap: usize,
        allocator: Allocator,
        context: Context,

        /// Initialize and return a priority queue.
        pub fn init(allocator: Allocator, context: Context) Self {
            return Self{
                .items = &[_]T{},
                .cap = 0,
                .allocator = allocator,
                .context = context,
            };
        }

        /// Free memory used by the queue.
        pub fn deinit(self: Self) void {
            self.allocator.free(self.allocated_slice());
        }

        /// Insert a new element, maintaining priority.
        pub fn add(self: *Self, elem: T) !void {
            try self.ensure_unused_capacity(1);
            add_unchecked(self, elem);
        }

        fn add_unchecked(self: *Self, elem: T) void {
            self.items.len += 1;
            self.items[self.items.len - 1] = elem;
            sift_up(self, self.items.len - 1);
        }

        fn sift_up(self: *Self, start_index: usize) void {
            const child = self.items[start_index];
            var child_index = start_index;
            while (child_index > 0) {
                const parent_index = ((child_index - 1) >> 1);
                const parent = self.items[parent_index];
                if (compare_fn(self.context, child, parent) != .lt) break;
                self.items[child_index] = parent;
                child_index = parent_index;
            }
            self.items[child_index] = child;
        }

        /// Add each element in `items` to the queue.
        pub fn add_slice(self: *Self, items: []const T) !void {
            try self.ensure_unused_capacity(items.len);
            for (items) |e| {
                self.add_unchecked(e);
            }
        }

        /// Look at the highest priority element in the queue. Returns
        /// `null` if empty.
        pub fn peek(self: *Self) ?T {
            return if (self.items.len > 0) self.items[0] else null;
        }

        /// Pop the highest priority element from the queue. Returns
        /// `null` if empty.
        pub fn remove_or_null(self: *Self) ?T {
            return if (self.items.len > 0) self.remove() else null;
        }

        /// Remove and return the highest priority element from the
        /// queue.
        pub fn remove(self: *Self) T {
            return self.remove_index(0);
        }

        /// Remove and return element at index. Indices are in the
        /// same order as iterator, which is not necessarily priority
        /// order.
        pub fn remove_index(self: *Self, index: usize) T {
            assert(self.items.len > index);
            const last = self.items[self.items.len - 1];
            const item = self.items[index];
            self.items[index] = last;
            self.items.len -= 1;

            if (index == self.items.len) {
                // Last element removed, nothing more to do.
            } else if (index == 0) {
                sift_down(self, index);
            } else {
                const parent_index = ((index - 1) >> 1);
                const parent = self.items[parent_index];
                if (compare_fn(self.context, last, parent) == .gt) {
                    sift_down(self, index);
                } else {
                    sift_up(self, index);
                }
            }

            return item;
        }

        /// Return the number of elements remaining in the priority
        /// queue.
        pub fn count(self: Self) usize {
            return self.items.len;
        }

        /// Return the number of elements that can be added to the
        /// queue before more memory is allocated.
        pub fn capacity(self: Self) usize {
            return self.cap;
        }

        /// Returns a slice of all the items plus the extra capacity, whose memory
        /// contents are `undefined`.
        fn allocated_slice(self: Self) []T {
            // `items.len` is the length, not the capacity.
            return self.items.ptr[0..self.cap];
        }

        fn sift_down(self: *Self, target_index: usize) void {
            const target_element = self.items[target_index];
            var index = target_index;
            while (true) {
                var lesser_child_i = (std.math.mul(usize, index, 2) catch break) | 1;
                if (!(lesser_child_i < self.items.len)) break;

                const next_child_i = lesser_child_i + 1;
                if (next_child_i < self.items.len and compare_fn(self.context, self.items[next_child_i], self.items[lesser_child_i]) == .lt) {
                    lesser_child_i = next_child_i;
                }

                if (compare_fn(self.context, target_element, self.items[lesser_child_i]) == .lt) break;

                self.items[index] = self.items[lesser_child_i];
                index = lesser_child_i;
            }
            self.items[index] = target_element;
        }

        /// PriorityQueue takes ownership of the passed in slice. The slice must have been
        /// allocated with `allocator`.
        /// Deinitialize with `deinit`.
        pub fn from_owned_slice(allocator: Allocator, items: []T, context: Context) Self {
            var self = Self{
                .items = items,
                .cap = items.len,
                .allocator = allocator,
                .context = context,
            };

            var i = self.items.len >> 1;
            while (i > 0) {
                i -= 1;
                self.sift_down(i);
            }
            return self;
        }

        /// Ensure that the queue can fit at least `new_capacity` items.
        pub fn ensure_total_capacity(self: *Self, new_capacity: usize) !void {
            var better_capacity = self.cap;
            if (better_capacity >= new_capacity) return;
            while (true) {
                better_capacity += better_capacity / 2 + 8;
                if (better_capacity >= new_capacity) break;
            }
            const old_memory = self.allocated_slice();
            const new_memory = try self.allocator.realloc(old_memory, better_capacity);
            self.items.ptr = new_memory.ptr;
            self.cap = new_memory.len;
        }

        /// Ensure that the queue can fit at least `additional_count` **more** item.
        pub fn ensure_unused_capacity(self: *Self, additional_count: usize) !void {
            return self.ensure_total_capacity(self.items.len + additional_count);
        }

        /// Reduce allocated capacity to `new_capacity`.
        pub fn shrink_and_free(self: *Self, new_capacity: usize) void {
            assert(new_capacity <= self.cap);

            // Cannot shrink to smaller than the current queue size without invalidating the heap property
            assert(new_capacity >= self.items.len);

            const old_memory = self.allocated_slice();
            const new_memory = self.allocator.realloc(old_memory, new_capacity) catch |e| switch (e) {
                error.OutOfMemory => { // no problem, capacity is still correct then.
                    return;
                },
            };

            self.items.ptr = new_memory.ptr;
            self.cap = new_memory.len;
        }

        pub fn update(self: *Self, elem: T, new_elem: T) !void {
            const update_index = blk: {
                var idx: usize = 0;
                while (idx < self.items.len) : (idx += 1) {
                    const item = self.items[idx];
                    if (compare_fn(self.context, item, elem) == .eq) break :blk idx;
                }
                return error.ElementNotFound;
            };
            const old_elem: T = self.items[update_index];
            self.items[update_index] = new_elem;
            switch (compare_fn(self.context, new_elem, old_elem)) {
                .lt => sift_up(self, update_index),
                .gt => sift_down(self, update_index),
                .eq => {}, // Nothing to do as the items have equal priority
            }
        }

        pub const Iterator = struct {
            queue: *PriorityQueue(T, Context, compare_fn),
            count: usize,

            pub fn next(it: *Iterator) ?T {
                if (it.count >= it.queue.items.len) return null;
                const out = it.count;
                it.count += 1;
                return it.queue.items[out];
            }

            pub fn reset(it: *Iterator) void {
                it.count = 0;
            }
        };

        /// Return an iterator that walks the queue without consuming
        /// it. The iteration order may differ from the priority order.
        /// Invalidated if the heap is modified.
        pub fn iterator(self: *Self) Iterator {
            return Iterator{
                .queue = self,
                .count = 0,
            };
        }

        fn dump(self: *Self) void {
            const print = std.debug.print;
            print("{{ ", .{});
            print("items: ", .{});
            for (self.items) |e| {
                print("{}, ", .{e});
            }
            print("array: ", .{});
            for (self.items) |e| {
                print("{}, ", .{e});
            }
            print("len: {} ", .{self.items.len});
            print("capacity: {}", .{self.cap});
            print(" }}\n", .{});
        }
    };
}

fn less_than(context: void, a: u32, b: u32) Order {
    _ = context;
    return std.math.order(a, b);
}

fn greater_than(context: void, a: u32, b: u32) Order {
    return less_than(context, a, b).invert();
}

const PQlt = PriorityQueue(u32, void, less_than);
const PQgt = PriorityQueue(u32, void, greater_than);

test "add and remove min heap" {
    var queue = PQlt.init(testing.allocator, {});
    defer queue.deinit();

    try queue.add(54);
    try queue.add(12);
    try queue.add(7);
    try queue.add(23);
    try queue.add(25);
    try queue.add(13);
    try expect_equal(@as(u32, 7), queue.remove());
    try expect_equal(@as(u32, 12), queue.remove());
    try expect_equal(@as(u32, 13), queue.remove());
    try expect_equal(@as(u32, 23), queue.remove());
    try expect_equal(@as(u32, 25), queue.remove());
    try expect_equal(@as(u32, 54), queue.remove());
}

test "add and remove same min heap" {
    var queue = PQlt.init(testing.allocator, {});
    defer queue.deinit();

    try queue.add(1);
    try queue.add(1);
    try queue.add(2);
    try queue.add(2);
    try queue.add(1);
    try queue.add(1);
    try expect_equal(@as(u32, 1), queue.remove());
    try expect_equal(@as(u32, 1), queue.remove());
    try expect_equal(@as(u32, 1), queue.remove());
    try expect_equal(@as(u32, 1), queue.remove());
    try expect_equal(@as(u32, 2), queue.remove());
    try expect_equal(@as(u32, 2), queue.remove());
}

test "remove_or_null on empty" {
    var queue = PQlt.init(testing.allocator, {});
    defer queue.deinit();

    try expect(queue.remove_or_null() == null);
}

test "edge case 3 elements" {
    var queue = PQlt.init(testing.allocator, {});
    defer queue.deinit();

    try queue.add(9);
    try queue.add(3);
    try queue.add(2);
    try expect_equal(@as(u32, 2), queue.remove());
    try expect_equal(@as(u32, 3), queue.remove());
    try expect_equal(@as(u32, 9), queue.remove());
}

test "peek" {
    var queue = PQlt.init(testing.allocator, {});
    defer queue.deinit();

    try expect(queue.peek() == null);
    try queue.add(9);
    try queue.add(3);
    try queue.add(2);
    try expect_equal(@as(u32, 2), queue.peek().?);
    try expect_equal(@as(u32, 2), queue.peek().?);
}

test "sift up with odd indices" {
    var queue = PQlt.init(testing.allocator, {});
    defer queue.deinit();
    const items = [_]u32{ 15, 7, 21, 14, 13, 22, 12, 6, 7, 25, 5, 24, 11, 16, 15, 24, 2, 1 };
    for (items) |e| {
        try queue.add(e);
    }

    const sorted_items = [_]u32{ 1, 2, 5, 6, 7, 7, 11, 12, 13, 14, 15, 15, 16, 21, 22, 24, 24, 25 };
    for (sorted_items) |e| {
        try expect_equal(e, queue.remove());
    }
}

test "add_slice" {
    var queue = PQlt.init(testing.allocator, {});
    defer queue.deinit();
    const items = [_]u32{ 15, 7, 21, 14, 13, 22, 12, 6, 7, 25, 5, 24, 11, 16, 15, 24, 2, 1 };
    try queue.add_slice(items[0..]);

    const sorted_items = [_]u32{ 1, 2, 5, 6, 7, 7, 11, 12, 13, 14, 15, 15, 16, 21, 22, 24, 24, 25 };
    for (sorted_items) |e| {
        try expect_equal(e, queue.remove());
    }
}

test "from_owned_slice trivial case 0" {
    const items = [0]u32{};
    const queue_items = try testing.allocator.dupe(u32, &items);
    var queue = PQlt.from_owned_slice(testing.allocator, queue_items[0..], {});
    defer queue.deinit();
    try expect_equal(@as(usize, 0), queue.count());
    try expect(queue.remove_or_null() == null);
}

test "from_owned_slice trivial case 1" {
    const items = [1]u32{1};
    const queue_items = try testing.allocator.dupe(u32, &items);
    var queue = PQlt.from_owned_slice(testing.allocator, queue_items[0..], {});
    defer queue.deinit();

    try expect_equal(@as(usize, 1), queue.count());
    try expect_equal(items[0], queue.remove());
    try expect(queue.remove_or_null() == null);
}

test "from_owned_slice" {
    const items = [_]u32{ 15, 7, 21, 14, 13, 22, 12, 6, 7, 25, 5, 24, 11, 16, 15, 24, 2, 1 };
    const heap_items = try testing.allocator.dupe(u32, items[0..]);
    var queue = PQlt.from_owned_slice(testing.allocator, heap_items[0..], {});
    defer queue.deinit();

    const sorted_items = [_]u32{ 1, 2, 5, 6, 7, 7, 11, 12, 13, 14, 15, 15, 16, 21, 22, 24, 24, 25 };
    for (sorted_items) |e| {
        try expect_equal(e, queue.remove());
    }
}

test "add and remove max heap" {
    var queue = PQgt.init(testing.allocator, {});
    defer queue.deinit();

    try queue.add(54);
    try queue.add(12);
    try queue.add(7);
    try queue.add(23);
    try queue.add(25);
    try queue.add(13);
    try expect_equal(@as(u32, 54), queue.remove());
    try expect_equal(@as(u32, 25), queue.remove());
    try expect_equal(@as(u32, 23), queue.remove());
    try expect_equal(@as(u32, 13), queue.remove());
    try expect_equal(@as(u32, 12), queue.remove());
    try expect_equal(@as(u32, 7), queue.remove());
}

test "add and remove same max heap" {
    var queue = PQgt.init(testing.allocator, {});
    defer queue.deinit();

    try queue.add(1);
    try queue.add(1);
    try queue.add(2);
    try queue.add(2);
    try queue.add(1);
    try queue.add(1);
    try expect_equal(@as(u32, 2), queue.remove());
    try expect_equal(@as(u32, 2), queue.remove());
    try expect_equal(@as(u32, 1), queue.remove());
    try expect_equal(@as(u32, 1), queue.remove());
    try expect_equal(@as(u32, 1), queue.remove());
    try expect_equal(@as(u32, 1), queue.remove());
}

test "iterator" {
    var queue = PQlt.init(testing.allocator, {});
    var map = std.AutoHashMap(u32, void).init(testing.allocator);
    defer {
        queue.deinit();
        map.deinit();
    }

    const items = [_]u32{ 54, 12, 7, 23, 25, 13 };
    for (items) |e| {
        _ = try queue.add(e);
        try map.put(e, {});
    }

    var it = queue.iterator();
    while (it.next()) |e| {
        _ = map.remove(e);
    }

    try expect_equal(@as(usize, 0), map.count());
}

test "remove at index" {
    var queue = PQlt.init(testing.allocator, {});
    defer queue.deinit();

    const items = [_]u32{ 2, 1, 8, 9, 3, 4, 5 };
    for (items) |e| {
        _ = try queue.add(e);
    }

    var it = queue.iterator();
    var idx: usize = 0;
    const two_idx = while (it.next()) |elem| {
        if (elem == 2)
            break idx;
        idx += 1;
    } else unreachable;
    const sorted_items = [_]u32{ 1, 3, 4, 5, 8, 9 };
    try expect_equal(queue.remove_index(two_idx), 2);

    var i: usize = 0;
    while (queue.remove_or_null()) |n| : (i += 1) {
        try expect_equal(n, sorted_items[i]);
    }
    try expect_equal(queue.remove_or_null(), null);
}

test "iterator while empty" {
    var queue = PQlt.init(testing.allocator, {});
    defer queue.deinit();

    var it = queue.iterator();

    try expect_equal(it.next(), null);
}

test "shrink_and_free" {
    var queue = PQlt.init(testing.allocator, {});
    defer queue.deinit();

    try queue.ensure_total_capacity(4);
    try expect(queue.capacity() >= 4);

    try queue.add(1);
    try queue.add(2);
    try queue.add(3);
    try expect(queue.capacity() >= 4);
    try expect_equal(@as(usize, 3), queue.count());

    queue.shrink_and_free(3);
    try expect_equal(@as(usize, 3), queue.capacity());
    try expect_equal(@as(usize, 3), queue.count());

    try expect_equal(@as(u32, 1), queue.remove());
    try expect_equal(@as(u32, 2), queue.remove());
    try expect_equal(@as(u32, 3), queue.remove());
    try expect(queue.remove_or_null() == null);
}

test "update min heap" {
    var queue = PQlt.init(testing.allocator, {});
    defer queue.deinit();

    try queue.add(55);
    try queue.add(44);
    try queue.add(11);
    try queue.update(55, 5);
    try queue.update(44, 4);
    try queue.update(11, 1);
    try expect_equal(@as(u32, 1), queue.remove());
    try expect_equal(@as(u32, 4), queue.remove());
    try expect_equal(@as(u32, 5), queue.remove());
}

test "update same min heap" {
    var queue = PQlt.init(testing.allocator, {});
    defer queue.deinit();

    try queue.add(1);
    try queue.add(1);
    try queue.add(2);
    try queue.add(2);
    try queue.update(1, 5);
    try queue.update(2, 4);
    try expect_equal(@as(u32, 1), queue.remove());
    try expect_equal(@as(u32, 2), queue.remove());
    try expect_equal(@as(u32, 4), queue.remove());
    try expect_equal(@as(u32, 5), queue.remove());
}

test "update max heap" {
    var queue = PQgt.init(testing.allocator, {});
    defer queue.deinit();

    try queue.add(55);
    try queue.add(44);
    try queue.add(11);
    try queue.update(55, 5);
    try queue.update(44, 1);
    try queue.update(11, 4);
    try expect_equal(@as(u32, 5), queue.remove());
    try expect_equal(@as(u32, 4), queue.remove());
    try expect_equal(@as(u32, 1), queue.remove());
}

test "update same max heap" {
    var queue = PQgt.init(testing.allocator, {});
    defer queue.deinit();

    try queue.add(1);
    try queue.add(1);
    try queue.add(2);
    try queue.add(2);
    try queue.update(1, 5);
    try queue.update(2, 4);
    try expect_equal(@as(u32, 5), queue.remove());
    try expect_equal(@as(u32, 4), queue.remove());
    try expect_equal(@as(u32, 2), queue.remove());
    try expect_equal(@as(u32, 1), queue.remove());
}

test "update after remove" {
    var queue = PQlt.init(testing.allocator, {});
    defer queue.deinit();

    try queue.add(1);
    try expect_equal(@as(u32, 1), queue.remove());
    try expect_error(error.ElementNotFound, queue.update(1, 1));
}

test "sift_up in remove" {
    var queue = PQlt.init(testing.allocator, {});
    defer queue.deinit();

    try queue.add_slice(&.{ 0, 1, 100, 2, 3, 101, 102, 4, 5, 6, 7, 103, 104, 105, 106, 8 });

    _ = queue.remove_index(std.mem.index_of_scalar(u32, queue.items[0..queue.count()], 102).?);

    const sorted_items = [_]u32{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 100, 101, 103, 104, 105, 106 };
    for (sorted_items) |e| {
        try expect_equal(e, queue.remove());
    }
}

fn context_less_than(context: []const u32, a: usize, b: usize) Order {
    return std.math.order(context[a], context[b]);
}

const CPQlt = PriorityQueue(usize, []const u32, context_less_than);

test "add and remove min heap with contextful comparator" {
    const context = [_]u32{ 5, 3, 4, 2, 2, 8, 0 };

    var queue = CPQlt.init(testing.allocator, context[0..]);
    defer queue.deinit();

    try queue.add(0);
    try queue.add(1);
    try queue.add(2);
    try queue.add(3);
    try queue.add(4);
    try queue.add(5);
    try queue.add(6);
    try expect_equal(@as(usize, 6), queue.remove());
    try expect_equal(@as(usize, 4), queue.remove());
    try expect_equal(@as(usize, 3), queue.remove());
    try expect_equal(@as(usize, 1), queue.remove());
    try expect_equal(@as(usize, 2), queue.remove());
    try expect_equal(@as(usize, 0), queue.remove());
    try expect_equal(@as(usize, 5), queue.remove());
}
