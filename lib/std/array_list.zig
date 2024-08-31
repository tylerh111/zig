const std = @import("std.zig");
const debug = std.debug;
const assert = debug.assert;
const testing = std.testing;
const mem = std.mem;
const math = std.math;
const Allocator = mem.Allocator;

/// A contiguous, growable list of items in memory.
/// This is a wrapper around an array of T values. Initialize with `init`.
///
/// This struct internally stores a `std.mem.Allocator` for memory management.
/// To manually specify an allocator with each function call see `ArrayListUnmanaged`.
pub fn ArrayList(comptime T: type) type {
    return ArrayListAligned(T, null);
}

/// A contiguous, growable list of arbitrarily aligned items in memory.
/// This is a wrapper around an array of T values aligned to `alignment`-byte
/// addresses. If the specified alignment is `null`, then `@alignOf(T)` is used.
/// Initialize with `init`.
///
/// This struct internally stores a `std.mem.Allocator` for memory management.
/// To manually specify an allocator with each function call see `ArrayListAlignedUnmanaged`.
pub fn ArrayListAligned(comptime T: type, comptime alignment: ?u29) type {
    if (alignment) |a| {
        if (a == @alignOf(T)) {
            return ArrayListAligned(T, null);
        }
    }
    return struct {
        const Self = @This();
        /// Contents of the list. This field is intended to be accessed
        /// directly.
        ///
        /// Pointers to elements in this slice are invalidated by various
        /// functions of this ArrayList in accordance with the respective
        /// documentation. In all cases, "invalidated" means that the memory
        /// has been passed to this allocator's resize or free function.
        items: Slice,
        /// How many T values this list can hold without allocating
        /// additional memory.
        capacity: usize,
        allocator: Allocator,

        pub const Slice = if (alignment) |a| ([]align(a) T) else []T;

        pub fn SentinelSlice(comptime s: T) type {
            return if (alignment) |a| ([:s]align(a) T) else [:s]T;
        }

        /// Deinitialize with `deinit` or use `to_owned_slice`.
        pub fn init(allocator: Allocator) Self {
            return Self{
                .items = &[_]T{},
                .capacity = 0,
                .allocator = allocator,
            };
        }

        /// Initialize with capacity to hold `num` elements.
        /// The resulting capacity will equal `num` exactly.
        /// Deinitialize with `deinit` or use `to_owned_slice`.
        pub fn init_capacity(allocator: Allocator, num: usize) Allocator.Error!Self {
            var self = Self.init(allocator);
            try self.ensure_total_capacity_precise(num);
            return self;
        }

        /// Release all allocated memory.
        pub fn deinit(self: Self) void {
            if (@size_of(T) > 0) {
                self.allocator.free(self.allocated_slice());
            }
        }

        /// ArrayList takes ownership of the passed in slice. The slice must have been
        /// allocated with `allocator`.
        /// Deinitialize with `deinit` or use `to_owned_slice`.
        pub fn from_owned_slice(allocator: Allocator, slice: Slice) Self {
            return Self{
                .items = slice,
                .capacity = slice.len,
                .allocator = allocator,
            };
        }

        /// ArrayList takes ownership of the passed in slice. The slice must have been
        /// allocated with `allocator`.
        /// Deinitialize with `deinit` or use `to_owned_slice`.
        pub fn from_owned_slice_sentinel(allocator: Allocator, comptime sentinel: T, slice: [:sentinel]T) Self {
            return Self{
                .items = slice,
                .capacity = slice.len + 1,
                .allocator = allocator,
            };
        }

        /// Initializes an ArrayListUnmanaged with the `items` and `capacity` fields
        /// of this ArrayList. Empties this ArrayList.
        pub fn move_to_unmanaged(self: *Self) ArrayListAlignedUnmanaged(T, alignment) {
            const allocator = self.allocator;
            const result = .{ .items = self.items, .capacity = self.capacity };
            self.* = init(allocator);
            return result;
        }

        /// The caller owns the returned memory. Empties this ArrayList,
        /// Its capacity is cleared, making deinit() safe but unnecessary to call.
        pub fn to_owned_slice(self: *Self) Allocator.Error!Slice {
            const allocator = self.allocator;

            const old_memory = self.allocated_slice();
            if (allocator.resize(old_memory, self.items.len)) {
                const result = self.items;
                self.* = init(allocator);
                return result;
            }

            const new_memory = try allocator.aligned_alloc(T, alignment, self.items.len);
            @memcpy(new_memory, self.items);
            @memset(self.items, undefined);
            self.clear_and_free();
            return new_memory;
        }

        /// The caller owns the returned memory. Empties this ArrayList.
        pub fn to_owned_slice_sentinel(self: *Self, comptime sentinel: T) Allocator.Error!SentinelSlice(sentinel) {
            // This addition can never overflow because `self.items` can never occupy the whole address space
            try self.ensure_total_capacity_precise(self.items.len + 1);
            self.append_assume_capacity(sentinel);
            const result = try self.to_owned_slice();
            return result[0 .. result.len - 1 :sentinel];
        }

        /// Creates a copy of this ArrayList, using the same allocator.
        pub fn clone(self: Self) Allocator.Error!Self {
            var cloned = try Self.init_capacity(self.allocator, self.capacity);
            cloned.append_slice_assume_capacity(self.items);
            return cloned;
        }

        /// Insert `item` at index `i`. Moves `list[i .. list.len]` to higher indices to make room.
        /// If `i` is equal to the length of the list this operation is equivalent to append.
        /// This operation is O(N).
        /// Invalidates element pointers if additional memory is needed.
        /// Asserts that the index is in bounds or equal to the length.
        pub fn insert(self: *Self, i: usize, item: T) Allocator.Error!void {
            const dst = try self.add_many_at(i, 1);
            dst[0] = item;
        }

        /// Insert `item` at index `i`. Moves `list[i .. list.len]` to higher indices to make room.
        /// If `i` is equal to the length of the list this operation is
        /// equivalent to append_assume_capacity.
        /// This operation is O(N).
        /// Asserts that there is enough capacity for the new item.
        /// Asserts that the index is in bounds or equal to the length.
        pub fn insert_assume_capacity(self: *Self, i: usize, item: T) void {
            assert(self.items.len < self.capacity);
            self.items.len += 1;

            mem.copy_backwards(T, self.items[i + 1 .. self.items.len], self.items[i .. self.items.len - 1]);
            self.items[i] = item;
        }

        /// Add `count` new elements at position `index`, which have
        /// `undefined` values. Returns a slice pointing to the newly allocated
        /// elements, which becomes invalid after various `ArrayList`
        /// operations.
        /// Invalidates pre-existing pointers to elements at and after `index`.
        /// Invalidates all pre-existing element pointers if capacity must be
        /// increased to accomodate the new elements.
        /// Asserts that the index is in bounds or equal to the length.
        pub fn add_many_at(self: *Self, index: usize, count: usize) Allocator.Error![]T {
            const new_len = try add_or_oom(self.items.len, count);

            if (self.capacity >= new_len)
                return add_many_at_assume_capacity(self, index, count);

            // Here we avoid copying allocated but unused bytes by
            // attempting a resize in place, and falling back to allocating
            // a new buffer and doing our own copy. With a realloc() call,
            // the allocator implementation would pointlessly copy our
            // extra capacity.
            const new_capacity = grow_capacity(self.capacity, new_len);
            const old_memory = self.allocated_slice();
            if (self.allocator.resize(old_memory, new_capacity)) {
                self.capacity = new_capacity;
                return add_many_at_assume_capacity(self, index, count);
            }

            // Make a new allocation, avoiding `ensure_total_capacity` in order
            // to avoid extra memory copies.
            const new_memory = try self.allocator.aligned_alloc(T, alignment, new_capacity);
            const to_move = self.items[index..];
            @memcpy(new_memory[0..index], self.items[0..index]);
            @memcpy(new_memory[index + count ..][0..to_move.len], to_move);
            self.allocator.free(old_memory);
            self.items = new_memory[0..new_len];
            self.capacity = new_memory.len;
            // The inserted elements at `new_memory[index..][0..count]` have
            // already been set to `undefined` by memory allocation.
            return new_memory[index..][0..count];
        }

        /// Add `count` new elements at position `index`, which have
        /// `undefined` values. Returns a slice pointing to the newly allocated
        /// elements, which becomes invalid after various `ArrayList`
        /// operations.
        /// Asserts that there is enough capacity for the new elements.
        /// Invalidates pre-existing pointers to elements at and after `index`, but
        /// does not invalidate any before that.
        /// Asserts that the index is in bounds or equal to the length.
        pub fn add_many_at_assume_capacity(self: *Self, index: usize, count: usize) []T {
            const new_len = self.items.len + count;
            assert(self.capacity >= new_len);
            const to_move = self.items[index..];
            self.items.len = new_len;
            mem.copy_backwards(T, self.items[index + count ..], to_move);
            const result = self.items[index..][0..count];
            @memset(result, undefined);
            return result;
        }

        /// Insert slice `items` at index `i` by moving `list[i .. list.len]` to make room.
        /// This operation is O(N).
        /// Invalidates pre-existing pointers to elements at and after `index`.
        /// Invalidates all pre-existing element pointers if capacity must be
        /// increased to accomodate the new elements.
        /// Asserts that the index is in bounds or equal to the length.
        pub fn insert_slice(
            self: *Self,
            index: usize,
            items: []const T,
        ) Allocator.Error!void {
            const dst = try self.add_many_at(index, items.len);
            @memcpy(dst, items);
        }

        /// Grows or shrinks the list as necessary.
        /// Invalidates element pointers if additional capacity is allocated.
        /// Asserts that the range is in bounds.
        pub fn replace_range(self: *Self, start: usize, len: usize, new_items: []const T) Allocator.Error!void {
            var unmanaged = self.move_to_unmanaged();
            defer self.* = unmanaged.to_managed(self.allocator);
            return unmanaged.replace_range(self.allocator, start, len, new_items);
        }

        /// Grows or shrinks the list as necessary.
        /// Never invalidates element pointers.
        /// Asserts the capacity is enough for additional items.
        pub fn replace_range_assume_capacity(self: *Self, start: usize, len: usize, new_items: []const T) void {
            var unmanaged = self.move_to_unmanaged();
            defer self.* = unmanaged.to_managed(self.allocator);
            return unmanaged.replace_range_assume_capacity(start, len, new_items);
        }

        /// Extends the list by 1 element. Allocates more memory as necessary.
        /// Invalidates element pointers if additional memory is needed.
        pub fn append(self: *Self, item: T) Allocator.Error!void {
            const new_item_ptr = try self.add_one();
            new_item_ptr.* = item;
        }

        /// Extends the list by 1 element.
        /// Never invalidates element pointers.
        /// Asserts that the list can hold one additional item.
        pub fn append_assume_capacity(self: *Self, item: T) void {
            const new_item_ptr = self.add_one_assume_capacity();
            new_item_ptr.* = item;
        }

        /// Remove the element at index `i`, shift elements after index
        /// `i` forward, and return the removed element.
        /// Invalidates element pointers to end of list.
        /// This operation is O(N).
        /// This preserves item order. Use `swap_remove` if order preservation is not important.
        /// Asserts that the index is in bounds.
        /// Asserts that the list is not empty.
        pub fn ordered_remove(self: *Self, i: usize) T {
            const old_item = self.items[i];
            self.replace_range_assume_capacity(i, 1, &.{});
            return old_item;
        }

        /// Removes the element at the specified index and returns it.
        /// The empty slot is filled from the end of the list.
        /// This operation is O(1).
        /// This may not preserve item order. Use `ordered_remove` if you need to preserve order.
        /// Asserts that the list is not empty.
        /// Asserts that the index is in bounds.
        pub fn swap_remove(self: *Self, i: usize) T {
            if (self.items.len - 1 == i) return self.pop();

            const old_item = self.items[i];
            self.items[i] = self.pop();
            return old_item;
        }

        /// Append the slice of items to the list. Allocates more
        /// memory as necessary.
        /// Invalidates element pointers if additional memory is needed.
        pub fn append_slice(self: *Self, items: []const T) Allocator.Error!void {
            try self.ensure_unused_capacity(items.len);
            self.append_slice_assume_capacity(items);
        }

        /// Append the slice of items to the list.
        /// Never invalidates element pointers.
        /// Asserts that the list can hold the additional items.
        pub fn append_slice_assume_capacity(self: *Self, items: []const T) void {
            const old_len = self.items.len;
            const new_len = old_len + items.len;
            assert(new_len <= self.capacity);
            self.items.len = new_len;
            @memcpy(self.items[old_len..][0..items.len], items);
        }

        /// Append an unaligned slice of items to the list. Allocates more
        /// memory as necessary. Only call this function if calling
        /// `append_slice` instead would be a compile error.
        /// Invalidates element pointers if additional memory is needed.
        pub fn append_unaligned_slice(self: *Self, items: []align(1) const T) Allocator.Error!void {
            try self.ensure_unused_capacity(items.len);
            self.append_unaligned_slice_assume_capacity(items);
        }

        /// Append the slice of items to the list.
        /// Never invalidates element pointers.
        /// This function is only needed when calling
        /// `append_slice_assume_capacity` instead would be a compile error due to the
        /// alignment of the `items` parameter.
        /// Asserts that the list can hold the additional items.
        pub fn append_unaligned_slice_assume_capacity(self: *Self, items: []align(1) const T) void {
            const old_len = self.items.len;
            const new_len = old_len + items.len;
            assert(new_len <= self.capacity);
            self.items.len = new_len;
            @memcpy(self.items[old_len..][0..items.len], items);
        }

        pub const Writer = if (T != u8)
            @compile_error("The Writer interface is only defined for ArrayList(u8) " ++
                "but the given type is ArrayList(" ++ @type_name(T) ++ ")")
        else
            std.io.Writer(*Self, Allocator.Error, append_write);

        /// Initializes a Writer which will append to the list.
        pub fn writer(self: *Self) Writer {
            return .{ .context = self };
        }

        /// Same as `append` except it returns the number of bytes written, which is always the same
        /// as `m.len`. The purpose of this function existing is to match `std.io.Writer` API.
        /// Invalidates element pointers if additional memory is needed.
        fn append_write(self: *Self, m: []const u8) Allocator.Error!usize {
            try self.append_slice(m);
            return m.len;
        }

        /// Append a value to the list `n` times.
        /// Allocates more memory as necessary.
        /// Invalidates element pointers if additional memory is needed.
        /// The function is inline so that a comptime-known `value` parameter will
        /// have a more optimal memset codegen in case it has a repeated byte pattern.
        pub inline fn append_ntimes(self: *Self, value: T, n: usize) Allocator.Error!void {
            const old_len = self.items.len;
            try self.resize(try add_or_oom(old_len, n));
            @memset(self.items[old_len..self.items.len], value);
        }

        /// Append a value to the list `n` times.
        /// Never invalidates element pointers.
        /// The function is inline so that a comptime-known `value` parameter will
        /// have a more optimal memset codegen in case it has a repeated byte pattern.
        /// Asserts that the list can hold the additional items.
        pub inline fn append_ntimes_assume_capacity(self: *Self, value: T, n: usize) void {
            const new_len = self.items.len + n;
            assert(new_len <= self.capacity);
            @memset(self.items.ptr[self.items.len..new_len], value);
            self.items.len = new_len;
        }

        /// Adjust the list length to `new_len`.
        /// Additional elements contain the value `undefined`.
        /// Invalidates element pointers if additional memory is needed.
        pub fn resize(self: *Self, new_len: usize) Allocator.Error!void {
            try self.ensure_total_capacity(new_len);
            self.items.len = new_len;
        }

        /// Reduce allocated capacity to `new_len`.
        /// May invalidate element pointers.
        /// Asserts that the new length is less than or equal to the previous length.
        pub fn shrink_and_free(self: *Self, new_len: usize) void {
            var unmanaged = self.move_to_unmanaged();
            unmanaged.shrink_and_free(self.allocator, new_len);
            self.* = unmanaged.to_managed(self.allocator);
        }

        /// Reduce length to `new_len`.
        /// Invalidates element pointers for the elements `items[new_len..]`.
        /// Asserts that the new length is less than or equal to the previous length.
        pub fn shrink_retaining_capacity(self: *Self, new_len: usize) void {
            assert(new_len <= self.items.len);
            self.items.len = new_len;
        }

        /// Invalidates all element pointers.
        pub fn clear_retaining_capacity(self: *Self) void {
            self.items.len = 0;
        }

        /// Invalidates all element pointers.
        pub fn clear_and_free(self: *Self) void {
            self.allocator.free(self.allocated_slice());
            self.items.len = 0;
            self.capacity = 0;
        }

        /// If the current capacity is less than `new_capacity`, this function will
        /// modify the array so that it can hold at least `new_capacity` items.
        /// Invalidates element pointers if additional memory is needed.
        pub fn ensure_total_capacity(self: *Self, new_capacity: usize) Allocator.Error!void {
            if (@size_of(T) == 0) {
                self.capacity = math.max_int(usize);
                return;
            }

            if (self.capacity >= new_capacity) return;

            const better_capacity = grow_capacity(self.capacity, new_capacity);
            return self.ensure_total_capacity_precise(better_capacity);
        }

        /// If the current capacity is less than `new_capacity`, this function will
        /// modify the array so that it can hold exactly `new_capacity` items.
        /// Invalidates element pointers if additional memory is needed.
        pub fn ensure_total_capacity_precise(self: *Self, new_capacity: usize) Allocator.Error!void {
            if (@size_of(T) == 0) {
                self.capacity = math.max_int(usize);
                return;
            }

            if (self.capacity >= new_capacity) return;

            // Here we avoid copying allocated but unused bytes by
            // attempting a resize in place, and falling back to allocating
            // a new buffer and doing our own copy. With a realloc() call,
            // the allocator implementation would pointlessly copy our
            // extra capacity.
            const old_memory = self.allocated_slice();
            if (self.allocator.resize(old_memory, new_capacity)) {
                self.capacity = new_capacity;
            } else {
                const new_memory = try self.allocator.aligned_alloc(T, alignment, new_capacity);
                @memcpy(new_memory[0..self.items.len], self.items);
                self.allocator.free(old_memory);
                self.items.ptr = new_memory.ptr;
                self.capacity = new_memory.len;
            }
        }

        /// Modify the array so that it can hold at least `additional_count` **more** items.
        /// Invalidates element pointers if additional memory is needed.
        pub fn ensure_unused_capacity(self: *Self, additional_count: usize) Allocator.Error!void {
            return self.ensure_total_capacity(try add_or_oom(self.items.len, additional_count));
        }

        /// Increases the array's length to match the full capacity that is already allocated.
        /// The new elements have `undefined` values.
        /// Never invalidates element pointers.
        pub fn expand_to_capacity(self: *Self) void {
            self.items.len = self.capacity;
        }

        /// Increase length by 1, returning pointer to the new item.
        /// The returned pointer becomes invalid when the list resized.
        pub fn add_one(self: *Self) Allocator.Error!*T {
            // This can never overflow because `self.items` can never occupy the whole address space
            const newlen = self.items.len + 1;
            try self.ensure_total_capacity(newlen);
            return self.add_one_assume_capacity();
        }

        /// Increase length by 1, returning pointer to the new item.
        /// The returned pointer becomes invalid when the list is resized.
        /// Never invalidates element pointers.
        /// Asserts that the list can hold one additional item.
        pub fn add_one_assume_capacity(self: *Self) *T {
            assert(self.items.len < self.capacity);
            self.items.len += 1;
            return &self.items[self.items.len - 1];
        }

        /// Resize the array, adding `n` new elements, which have `undefined` values.
        /// The return value is an array pointing to the newly allocated elements.
        /// The returned pointer becomes invalid when the list is resized.
        /// Resizes list if `self.capacity` is not large enough.
        pub fn add_many_as_array(self: *Self, comptime n: usize) Allocator.Error!*[n]T {
            const prev_len = self.items.len;
            try self.resize(try add_or_oom(self.items.len, n));
            return self.items[prev_len..][0..n];
        }

        /// Resize the array, adding `n` new elements, which have `undefined` values.
        /// The return value is an array pointing to the newly allocated elements.
        /// Never invalidates element pointers.
        /// The returned pointer becomes invalid when the list is resized.
        /// Asserts that the list can hold the additional items.
        pub fn add_many_as_array_assume_capacity(self: *Self, comptime n: usize) *[n]T {
            assert(self.items.len + n <= self.capacity);
            const prev_len = self.items.len;
            self.items.len += n;
            return self.items[prev_len..][0..n];
        }

        /// Resize the array, adding `n` new elements, which have `undefined` values.
        /// The return value is a slice pointing to the newly allocated elements.
        /// The returned pointer becomes invalid when the list is resized.
        /// Resizes list if `self.capacity` is not large enough.
        pub fn add_many_as_slice(self: *Self, n: usize) Allocator.Error![]T {
            const prev_len = self.items.len;
            try self.resize(try add_or_oom(self.items.len, n));
            return self.items[prev_len..][0..n];
        }

        /// Resize the array, adding `n` new elements, which have `undefined` values.
        /// The return value is a slice pointing to the newly allocated elements.
        /// Never invalidates element pointers.
        /// The returned pointer becomes invalid when the list is resized.
        /// Asserts that the list can hold the additional items.
        pub fn add_many_as_slice_assume_capacity(self: *Self, n: usize) []T {
            assert(self.items.len + n <= self.capacity);
            const prev_len = self.items.len;
            self.items.len += n;
            return self.items[prev_len..][0..n];
        }

        /// Remove and return the last element from the list.
        /// Invalidates element pointers to the removed element.
        /// Asserts that the list is not empty.
        pub fn pop(self: *Self) T {
            const val = self.items[self.items.len - 1];
            self.items.len -= 1;
            return val;
        }

        /// Remove and return the last element from the list, or
        /// return `null` if list is empty.
        /// Invalidates element pointers to the removed element, if any.
        pub fn pop_or_null(self: *Self) ?T {
            if (self.items.len == 0) return null;
            return self.pop();
        }

        /// Returns a slice of all the items plus the extra capacity, whose memory
        /// contents are `undefined`.
        pub fn allocated_slice(self: Self) Slice {
            // `items.len` is the length, not the capacity.
            return self.items.ptr[0..self.capacity];
        }

        /// Returns a slice of only the extra capacity after items.
        /// This can be useful for writing directly into an ArrayList.
        /// Note that such an operation must be followed up with a direct
        /// modification of `self.items.len`.
        pub fn unused_capacity_slice(self: Self) Slice {
            return self.allocated_slice()[self.items.len..];
        }

        /// Returns the last element from the list.
        /// Asserts that the list is not empty.
        pub fn get_last(self: Self) T {
            const val = self.items[self.items.len - 1];
            return val;
        }

        /// Returns the last element from the list, or `null` if list is empty.
        pub fn get_last_or_null(self: Self) ?T {
            if (self.items.len == 0) return null;
            return self.get_last();
        }
    };
}

/// An ArrayList, but the allocator is passed as a parameter to the relevant functions
/// rather than stored in the struct itself. The same allocator must be used throughout
/// the entire lifetime of an ArrayListUnmanaged. Initialize directly or with
/// `init_capacity`, and deinitialize with `deinit` or use `to_owned_slice`.
pub fn ArrayListUnmanaged(comptime T: type) type {
    return ArrayListAlignedUnmanaged(T, null);
}

/// A contiguous, growable list of arbitrarily aligned items in memory.
/// This is a wrapper around an array of T values aligned to `alignment`-byte
/// addresses. If the specified alignment is `null`, then `@alignOf(T)` is used.
///
/// Functions that potentially allocate memory accept an `Allocator` parameter.
/// Initialize directly or with `init_capacity`, and deinitialize with `deinit`
/// or use `to_owned_slice`.
pub fn ArrayListAlignedUnmanaged(comptime T: type, comptime alignment: ?u29) type {
    if (alignment) |a| {
        if (a == @alignOf(T)) {
            return ArrayListAlignedUnmanaged(T, null);
        }
    }
    return struct {
        const Self = @This();
        /// Contents of the list. This field is intended to be accessed
        /// directly.
        ///
        /// Pointers to elements in this slice are invalidated by various
        /// functions of this ArrayList in accordance with the respective
        /// documentation. In all cases, "invalidated" means that the memory
        /// has been passed to an allocator's resize or free function.
        items: Slice = &[_]T{},
        /// How many T values this list can hold without allocating
        /// additional memory.
        capacity: usize = 0,

        pub const Slice = if (alignment) |a| ([]align(a) T) else []T;

        pub fn SentinelSlice(comptime s: T) type {
            return if (alignment) |a| ([:s]align(a) T) else [:s]T;
        }

        /// Initialize with capacity to hold `num` elements.
        /// The resulting capacity will equal `num` exactly.
        /// Deinitialize with `deinit` or use `to_owned_slice`.
        pub fn init_capacity(allocator: Allocator, num: usize) Allocator.Error!Self {
            var self = Self{};
            try self.ensure_total_capacity_precise(allocator, num);
            return self;
        }

        /// Initialize with externally-managed memory. The buffer determines the
        /// capacity, and the length is set to zero.
        /// When initialized this way, all functions that accept an Allocator
        /// argument cause illegal behavior.
        pub fn init_buffer(buffer: Slice) Self {
            return .{
                .items = buffer[0..0],
                .capacity = buffer.len,
            };
        }

        /// Release all allocated memory.
        pub fn deinit(self: *Self, allocator: Allocator) void {
            allocator.free(self.allocated_slice());
            self.* = undefined;
        }

        /// Convert this list into an analogous memory-managed one.
        /// The returned list has ownership of the underlying memory.
        pub fn to_managed(self: *Self, allocator: Allocator) ArrayListAligned(T, alignment) {
            return .{ .items = self.items, .capacity = self.capacity, .allocator = allocator };
        }

        /// ArrayListUnmanaged takes ownership of the passed in slice. The slice must have been
        /// allocated with `allocator`.
        /// Deinitialize with `deinit` or use `to_owned_slice`.
        pub fn from_owned_slice(slice: Slice) Self {
            return Self{
                .items = slice,
                .capacity = slice.len,
            };
        }

        /// ArrayListUnmanaged takes ownership of the passed in slice. The slice must have been
        /// allocated with `allocator`.
        /// Deinitialize with `deinit` or use `to_owned_slice`.
        pub fn from_owned_slice_sentinel(comptime sentinel: T, slice: [:sentinel]T) Self {
            return Self{
                .items = slice,
                .capacity = slice.len + 1,
            };
        }

        /// The caller owns the returned memory. Empties this ArrayList.
        /// Its capacity is cleared, making deinit() safe but unnecessary to call.
        pub fn to_owned_slice(self: *Self, allocator: Allocator) Allocator.Error!Slice {
            const old_memory = self.allocated_slice();
            if (allocator.resize(old_memory, self.items.len)) {
                const result = self.items;
                self.* = .{};
                return result;
            }

            const new_memory = try allocator.aligned_alloc(T, alignment, self.items.len);
            @memcpy(new_memory, self.items);
            @memset(self.items, undefined);
            self.clear_and_free(allocator);
            return new_memory;
        }

        /// The caller owns the returned memory. ArrayList becomes empty.
        pub fn to_owned_slice_sentinel(self: *Self, allocator: Allocator, comptime sentinel: T) Allocator.Error!SentinelSlice(sentinel) {
            // This addition can never overflow because `self.items` can never occupy the whole address space
            try self.ensure_total_capacity_precise(allocator, self.items.len + 1);
            self.append_assume_capacity(sentinel);
            const result = try self.to_owned_slice(allocator);
            return result[0 .. result.len - 1 :sentinel];
        }

        /// Creates a copy of this ArrayList.
        pub fn clone(self: Self, allocator: Allocator) Allocator.Error!Self {
            var cloned = try Self.init_capacity(allocator, self.capacity);
            cloned.append_slice_assume_capacity(self.items);
            return cloned;
        }

        /// Insert `item` at index `i`. Moves `list[i .. list.len]` to higher indices to make room.
        /// If `i` is equal to the length of the list this operation is equivalent to append.
        /// This operation is O(N).
        /// Invalidates element pointers if additional memory is needed.
        /// Asserts that the index is in bounds or equal to the length.
        pub fn insert(self: *Self, allocator: Allocator, i: usize, item: T) Allocator.Error!void {
            const dst = try self.add_many_at(allocator, i, 1);
            dst[0] = item;
        }

        /// Insert `item` at index `i`. Moves `list[i .. list.len]` to higher indices to make room.
        /// If in` is equal to the length of the list this operation is equivalent to append.
        /// This operation is O(N).
        /// Asserts that the list has capacity for one additional item.
        /// Asserts that the index is in bounds or equal to the length.
        pub fn insert_assume_capacity(self: *Self, i: usize, item: T) void {
            assert(self.items.len < self.capacity);
            self.items.len += 1;

            mem.copy_backwards(T, self.items[i + 1 .. self.items.len], self.items[i .. self.items.len - 1]);
            self.items[i] = item;
        }

        /// Add `count` new elements at position `index`, which have
        /// `undefined` values. Returns a slice pointing to the newly allocated
        /// elements, which becomes invalid after various `ArrayList`
        /// operations.
        /// Invalidates pre-existing pointers to elements at and after `index`.
        /// Invalidates all pre-existing element pointers if capacity must be
        /// increased to accomodate the new elements.
        /// Asserts that the index is in bounds or equal to the length.
        pub fn add_many_at(
            self: *Self,
            allocator: Allocator,
            index: usize,
            count: usize,
        ) Allocator.Error![]T {
            var managed = self.to_managed(allocator);
            defer self.* = managed.move_to_unmanaged();
            return managed.add_many_at(index, count);
        }

        /// Add `count` new elements at position `index`, which have
        /// `undefined` values. Returns a slice pointing to the newly allocated
        /// elements, which becomes invalid after various `ArrayList`
        /// operations.
        /// Invalidates pre-existing pointers to elements at and after `index`, but
        /// does not invalidate any before that.
        /// Asserts that the list has capacity for the additional items.
        /// Asserts that the index is in bounds or equal to the length.
        pub fn add_many_at_assume_capacity(self: *Self, index: usize, count: usize) []T {
            const new_len = self.items.len + count;
            assert(self.capacity >= new_len);
            const to_move = self.items[index..];
            self.items.len = new_len;
            mem.copy_backwards(T, self.items[index + count ..], to_move);
            const result = self.items[index..][0..count];
            @memset(result, undefined);
            return result;
        }

        /// Insert slice `items` at index `i` by moving `list[i .. list.len]` to make room.
        /// This operation is O(N).
        /// Invalidates pre-existing pointers to elements at and after `index`.
        /// Invalidates all pre-existing element pointers if capacity must be
        /// increased to accomodate the new elements.
        /// Asserts that the index is in bounds or equal to the length.
        pub fn insert_slice(
            self: *Self,
            allocator: Allocator,
            index: usize,
            items: []const T,
        ) Allocator.Error!void {
            const dst = try self.add_many_at(
                allocator,
                index,
                items.len,
            );
            @memcpy(dst, items);
        }

        /// Grows or shrinks the list as necessary.
        /// Invalidates element pointers if additional capacity is allocated.
        /// Asserts that the range is in bounds.
        pub fn replace_range(
            self: *Self,
            allocator: Allocator,
            start: usize,
            len: usize,
            new_items: []const T,
        ) Allocator.Error!void {
            const after_range = start + len;
            const range = self.items[start..after_range];
            if (range.len < new_items.len) {
                const first = new_items[0..range.len];
                const rest = new_items[range.len..];
                @memcpy(range[0..first.len], first);
                try self.insert_slice(allocator, after_range, rest);
            } else {
                self.replace_range_assume_capacity(start, len, new_items);
            }
        }

        /// Grows or shrinks the list as necessary.
        /// Never invalidates element pointers.
        /// Asserts the capacity is enough for additional items.
        pub fn replace_range_assume_capacity(self: *Self, start: usize, len: usize, new_items: []const T) void {
            const after_range = start + len;
            const range = self.items[start..after_range];

            if (range.len == new_items.len)
                @memcpy(range[0..new_items.len], new_items)
            else if (range.len < new_items.len) {
                const first = new_items[0..range.len];
                const rest = new_items[range.len..];
                @memcpy(range[0..first.len], first);
                const dst = self.add_many_at_assume_capacity(after_range, rest.len);
                @memcpy(dst, rest);
            } else {
                const extra = range.len - new_items.len;
                @memcpy(range[0..new_items.len], new_items);
                std.mem.copy_forwards(
                    T,
                    self.items[after_range - extra ..],
                    self.items[after_range..],
                );
                @memset(self.items[self.items.len - extra ..], undefined);
                self.items.len -= extra;
            }
        }

        /// Extend the list by 1 element. Allocates more memory as necessary.
        /// Invalidates element pointers if additional memory is needed.
        pub fn append(self: *Self, allocator: Allocator, item: T) Allocator.Error!void {
            const new_item_ptr = try self.add_one(allocator);
            new_item_ptr.* = item;
        }

        /// Extend the list by 1 element.
        /// Never invalidates element pointers.
        /// Asserts that the list can hold one additional item.
        pub fn append_assume_capacity(self: *Self, item: T) void {
            const new_item_ptr = self.add_one_assume_capacity();
            new_item_ptr.* = item;
        }

        /// Remove the element at index `i` from the list and return its value.
        /// Invalidates pointers to the last element.
        /// This operation is O(N).
        /// Asserts that the list is not empty.
        /// Asserts that the index is in bounds.
        pub fn ordered_remove(self: *Self, i: usize) T {
            const old_item = self.items[i];
            self.replace_range_assume_capacity(i, 1, &.{});
            return old_item;
        }

        /// Removes the element at the specified index and returns it.
        /// The empty slot is filled from the end of the list.
        /// Invalidates pointers to last element.
        /// This operation is O(1).
        /// Asserts that the list is not empty.
        /// Asserts that the index is in bounds.
        pub fn swap_remove(self: *Self, i: usize) T {
            if (self.items.len - 1 == i) return self.pop();

            const old_item = self.items[i];
            self.items[i] = self.pop();
            return old_item;
        }

        /// Append the slice of items to the list. Allocates more
        /// memory as necessary.
        /// Invalidates element pointers if additional memory is needed.
        pub fn append_slice(self: *Self, allocator: Allocator, items: []const T) Allocator.Error!void {
            try self.ensure_unused_capacity(allocator, items.len);
            self.append_slice_assume_capacity(items);
        }

        /// Append the slice of items to the list.
        /// Asserts that the list can hold the additional items.
        pub fn append_slice_assume_capacity(self: *Self, items: []const T) void {
            const old_len = self.items.len;
            const new_len = old_len + items.len;
            assert(new_len <= self.capacity);
            self.items.len = new_len;
            @memcpy(self.items[old_len..][0..items.len], items);
        }

        /// Append the slice of items to the list. Allocates more
        /// memory as necessary. Only call this function if a call to `append_slice` instead would
        /// be a compile error.
        /// Invalidates element pointers if additional memory is needed.
        pub fn append_unaligned_slice(self: *Self, allocator: Allocator, items: []align(1) const T) Allocator.Error!void {
            try self.ensure_unused_capacity(allocator, items.len);
            self.append_unaligned_slice_assume_capacity(items);
        }

        /// Append an unaligned slice of items to the list.
        /// Only call this function if a call to `append_slice_assume_capacity`
        /// instead would be a compile error.
        /// Asserts that the list can hold the additional items.
        pub fn append_unaligned_slice_assume_capacity(self: *Self, items: []align(1) const T) void {
            const old_len = self.items.len;
            const new_len = old_len + items.len;
            assert(new_len <= self.capacity);
            self.items.len = new_len;
            @memcpy(self.items[old_len..][0..items.len], items);
        }

        pub const WriterContext = struct {
            self: *Self,
            allocator: Allocator,
        };

        pub const Writer = if (T != u8)
            @compile_error("The Writer interface is only defined for ArrayList(u8) " ++
                "but the given type is ArrayList(" ++ @type_name(T) ++ ")")
        else
            std.io.Writer(WriterContext, Allocator.Error, append_write);

        /// Initializes a Writer which will append to the list.
        pub fn writer(self: *Self, allocator: Allocator) Writer {
            return .{ .context = .{ .self = self, .allocator = allocator } };
        }

        /// Same as `append` except it returns the number of bytes written,
        /// which is always the same as `m.len`. The purpose of this function
        /// existing is to match `std.io.Writer` API.
        /// Invalidates element pointers if additional memory is needed.
        fn append_write(context: WriterContext, m: []const u8) Allocator.Error!usize {
            try context.self.append_slice(context.allocator, m);
            return m.len;
        }

        pub const FixedWriter = std.io.Writer(*Self, Allocator.Error, append_write_fixed);

        /// Initializes a Writer which will append to the list but will return
        /// `error.OutOfMemory` rather than increasing capacity.
        pub fn fixed_writer(self: *Self) FixedWriter {
            return .{ .context = self };
        }

        /// The purpose of this function existing is to match `std.io.Writer` API.
        fn append_write_fixed(self: *Self, m: []const u8) error{OutOfMemory}!usize {
            const available_capacity = self.capacity - self.items.len;
            if (m.len > available_capacity)
                return error.OutOfMemory;

            self.append_slice_assume_capacity(m);
            return m.len;
        }

        /// Append a value to the list `n` times.
        /// Allocates more memory as necessary.
        /// Invalidates element pointers if additional memory is needed.
        /// The function is inline so that a comptime-known `value` parameter will
        /// have a more optimal memset codegen in case it has a repeated byte pattern.
        pub inline fn append_ntimes(self: *Self, allocator: Allocator, value: T, n: usize) Allocator.Error!void {
            const old_len = self.items.len;
            try self.resize(allocator, try add_or_oom(old_len, n));
            @memset(self.items[old_len..self.items.len], value);
        }

        /// Append a value to the list `n` times.
        /// Never invalidates element pointers.
        /// The function is inline so that a comptime-known `value` parameter will
        /// have better memset codegen in case it has a repeated byte pattern.
        /// Asserts that the list can hold the additional items.
        pub inline fn append_ntimes_assume_capacity(self: *Self, value: T, n: usize) void {
            const new_len = self.items.len + n;
            assert(new_len <= self.capacity);
            @memset(self.items.ptr[self.items.len..new_len], value);
            self.items.len = new_len;
        }

        /// Adjust the list length to `new_len`.
        /// Additional elements contain the value `undefined`.
        /// Invalidates element pointers if additional memory is needed.
        pub fn resize(self: *Self, allocator: Allocator, new_len: usize) Allocator.Error!void {
            try self.ensure_total_capacity(allocator, new_len);
            self.items.len = new_len;
        }

        /// Reduce allocated capacity to `new_len`.
        /// May invalidate element pointers.
        /// Asserts that the new length is less than or equal to the previous length.
        pub fn shrink_and_free(self: *Self, allocator: Allocator, new_len: usize) void {
            assert(new_len <= self.items.len);

            if (@size_of(T) == 0) {
                self.items.len = new_len;
                return;
            }

            const old_memory = self.allocated_slice();
            if (allocator.resize(old_memory, new_len)) {
                self.capacity = new_len;
                self.items.len = new_len;
                return;
            }

            const new_memory = allocator.aligned_alloc(T, alignment, new_len) catch |e| switch (e) {
                error.OutOfMemory => {
                    // No problem, capacity is still correct then.
                    self.items.len = new_len;
                    return;
                },
            };

            @memcpy(new_memory, self.items[0..new_len]);
            allocator.free(old_memory);
            self.items = new_memory;
            self.capacity = new_memory.len;
        }

        /// Reduce length to `new_len`.
        /// Invalidates pointers to elements `items[new_len..]`.
        /// Keeps capacity the same.
        /// Asserts that the new length is less than or equal to the previous length.
        pub fn shrink_retaining_capacity(self: *Self, new_len: usize) void {
            assert(new_len <= self.items.len);
            self.items.len = new_len;
        }

        /// Invalidates all element pointers.
        pub fn clear_retaining_capacity(self: *Self) void {
            self.items.len = 0;
        }

        /// Invalidates all element pointers.
        pub fn clear_and_free(self: *Self, allocator: Allocator) void {
            allocator.free(self.allocated_slice());
            self.items.len = 0;
            self.capacity = 0;
        }

        /// If the current capacity is less than `new_capacity`, this function will
        /// modify the array so that it can hold at least `new_capacity` items.
        /// Invalidates element pointers if additional memory is needed.
        pub fn ensure_total_capacity(self: *Self, allocator: Allocator, new_capacity: usize) Allocator.Error!void {
            if (self.capacity >= new_capacity) return;

            const better_capacity = grow_capacity(self.capacity, new_capacity);
            return self.ensure_total_capacity_precise(allocator, better_capacity);
        }

        /// If the current capacity is less than `new_capacity`, this function will
        /// modify the array so that it can hold exactly `new_capacity` items.
        /// Invalidates element pointers if additional memory is needed.
        pub fn ensure_total_capacity_precise(self: *Self, allocator: Allocator, new_capacity: usize) Allocator.Error!void {
            if (@size_of(T) == 0) {
                self.capacity = math.max_int(usize);
                return;
            }

            if (self.capacity >= new_capacity) return;

            // Here we avoid copying allocated but unused bytes by
            // attempting a resize in place, and falling back to allocating
            // a new buffer and doing our own copy. With a realloc() call,
            // the allocator implementation would pointlessly copy our
            // extra capacity.
            const old_memory = self.allocated_slice();
            if (allocator.resize(old_memory, new_capacity)) {
                self.capacity = new_capacity;
            } else {
                const new_memory = try allocator.aligned_alloc(T, alignment, new_capacity);
                @memcpy(new_memory[0..self.items.len], self.items);
                allocator.free(old_memory);
                self.items.ptr = new_memory.ptr;
                self.capacity = new_memory.len;
            }
        }

        /// Modify the array so that it can hold at least `additional_count` **more** items.
        /// Invalidates element pointers if additional memory is needed.
        pub fn ensure_unused_capacity(
            self: *Self,
            allocator: Allocator,
            additional_count: usize,
        ) Allocator.Error!void {
            return self.ensure_total_capacity(allocator, try add_or_oom(self.items.len, additional_count));
        }

        /// Increases the array's length to match the full capacity that is already allocated.
        /// The new elements have `undefined` values.
        /// Never invalidates element pointers.
        pub fn expand_to_capacity(self: *Self) void {
            self.items.len = self.capacity;
        }

        /// Increase length by 1, returning pointer to the new item.
        /// The returned element pointer becomes invalid when the list is resized.
        pub fn add_one(self: *Self, allocator: Allocator) Allocator.Error!*T {
            // This can never overflow because `self.items` can never occupy the whole address space
            const newlen = self.items.len + 1;
            try self.ensure_total_capacity(allocator, newlen);
            return self.add_one_assume_capacity();
        }

        /// Increase length by 1, returning pointer to the new item.
        /// Never invalidates element pointers.
        /// The returned element pointer becomes invalid when the list is resized.
        /// Asserts that the list can hold one additional item.
        pub fn add_one_assume_capacity(self: *Self) *T {
            assert(self.items.len < self.capacity);

            self.items.len += 1;
            return &self.items[self.items.len - 1];
        }

        /// Resize the array, adding `n` new elements, which have `undefined` values.
        /// The return value is an array pointing to the newly allocated elements.
        /// The returned pointer becomes invalid when the list is resized.
        pub fn add_many_as_array(self: *Self, allocator: Allocator, comptime n: usize) Allocator.Error!*[n]T {
            const prev_len = self.items.len;
            try self.resize(allocator, try add_or_oom(self.items.len, n));
            return self.items[prev_len..][0..n];
        }

        /// Resize the array, adding `n` new elements, which have `undefined` values.
        /// The return value is an array pointing to the newly allocated elements.
        /// Never invalidates element pointers.
        /// The returned pointer becomes invalid when the list is resized.
        /// Asserts that the list can hold the additional items.
        pub fn add_many_as_array_assume_capacity(self: *Self, comptime n: usize) *[n]T {
            assert(self.items.len + n <= self.capacity);
            const prev_len = self.items.len;
            self.items.len += n;
            return self.items[prev_len..][0..n];
        }

        /// Resize the array, adding `n` new elements, which have `undefined` values.
        /// The return value is a slice pointing to the newly allocated elements.
        /// The returned pointer becomes invalid when the list is resized.
        /// Resizes list if `self.capacity` is not large enough.
        pub fn add_many_as_slice(self: *Self, allocator: Allocator, n: usize) Allocator.Error![]T {
            const prev_len = self.items.len;
            try self.resize(allocator, try add_or_oom(self.items.len, n));
            return self.items[prev_len..][0..n];
        }

        /// Resize the array, adding `n` new elements, which have `undefined` values.
        /// The return value is a slice pointing to the newly allocated elements.
        /// Never invalidates element pointers.
        /// The returned pointer becomes invalid when the list is resized.
        /// Asserts that the list can hold the additional items.
        pub fn add_many_as_slice_assume_capacity(self: *Self, n: usize) []T {
            assert(self.items.len + n <= self.capacity);
            const prev_len = self.items.len;
            self.items.len += n;
            return self.items[prev_len..][0..n];
        }

        /// Remove and return the last element from the list.
        /// Invalidates pointers to last element.
        /// Asserts that the list is not empty.
        pub fn pop(self: *Self) T {
            const val = self.items[self.items.len - 1];
            self.items.len -= 1;
            return val;
        }

        /// Remove and return the last element from the list.
        /// If the list is empty, returns `null`.
        /// Invalidates pointers to last element.
        pub fn pop_or_null(self: *Self) ?T {
            if (self.items.len == 0) return null;
            return self.pop();
        }

        /// Returns a slice of all the items plus the extra capacity, whose memory
        /// contents are `undefined`.
        pub fn allocated_slice(self: Self) Slice {
            return self.items.ptr[0..self.capacity];
        }

        /// Returns a slice of only the extra capacity after items.
        /// This can be useful for writing directly into an ArrayList.
        /// Note that such an operation must be followed up with a direct
        /// modification of `self.items.len`.
        pub fn unused_capacity_slice(self: Self) Slice {
            return self.allocated_slice()[self.items.len..];
        }

        /// Return the last element from the list.
        /// Asserts that the list is not empty.
        pub fn get_last(self: Self) T {
            const val = self.items[self.items.len - 1];
            return val;
        }

        /// Return the last element from the list, or
        /// return `null` if list is empty.
        pub fn get_last_or_null(self: Self) ?T {
            if (self.items.len == 0) return null;
            return self.get_last();
        }
    };
}

/// Called when memory growth is necessary. Returns a capacity larger than
/// minimum that grows super-linearly.
fn grow_capacity(current: usize, minimum: usize) usize {
    var new = current;
    while (true) {
        new +|= new / 2 + 8;
        if (new >= minimum)
            return new;
    }
}

/// Integer addition returning `error.OutOfMemory` on overflow.
fn add_or_oom(a: usize, b: usize) error{OutOfMemory}!usize {
    const result, const overflow = @add_with_overflow(a, b);
    if (overflow != 0) return error.OutOfMemory;
    return result;
}

test "init" {
    {
        var list = ArrayList(i32).init(testing.allocator);
        defer list.deinit();

        try testing.expect(list.items.len == 0);
        try testing.expect(list.capacity == 0);
    }

    {
        const list = ArrayListUnmanaged(i32){};

        try testing.expect(list.items.len == 0);
        try testing.expect(list.capacity == 0);
    }
}

test "init_capacity" {
    const a = testing.allocator;
    {
        var list = try ArrayList(i8).init_capacity(a, 200);
        defer list.deinit();
        try testing.expect(list.items.len == 0);
        try testing.expect(list.capacity >= 200);
    }
    {
        var list = try ArrayListUnmanaged(i8).init_capacity(a, 200);
        defer list.deinit(a);
        try testing.expect(list.items.len == 0);
        try testing.expect(list.capacity >= 200);
    }
}

test "clone" {
    const a = testing.allocator;
    {
        var array = ArrayList(i32).init(a);
        try array.append(-1);
        try array.append(3);
        try array.append(5);

        const cloned = try array.clone();
        defer cloned.deinit();

        try testing.expect_equal_slices(i32, array.items, cloned.items);
        try testing.expect_equal(array.allocator, cloned.allocator);
        try testing.expect(cloned.capacity >= array.capacity);

        array.deinit();

        try testing.expect_equal(@as(i32, -1), cloned.items[0]);
        try testing.expect_equal(@as(i32, 3), cloned.items[1]);
        try testing.expect_equal(@as(i32, 5), cloned.items[2]);
    }
    {
        var array = ArrayListUnmanaged(i32){};
        try array.append(a, -1);
        try array.append(a, 3);
        try array.append(a, 5);

        var cloned = try array.clone(a);
        defer cloned.deinit(a);

        try testing.expect_equal_slices(i32, array.items, cloned.items);
        try testing.expect(cloned.capacity >= array.capacity);

        array.deinit(a);

        try testing.expect_equal(@as(i32, -1), cloned.items[0]);
        try testing.expect_equal(@as(i32, 3), cloned.items[1]);
        try testing.expect_equal(@as(i32, 5), cloned.items[2]);
    }
}

test "basic" {
    const a = testing.allocator;
    {
        var list = ArrayList(i32).init(a);
        defer list.deinit();

        {
            var i: usize = 0;
            while (i < 10) : (i += 1) {
                list.append(@as(i32, @int_cast(i + 1))) catch unreachable;
            }
        }

        {
            var i: usize = 0;
            while (i < 10) : (i += 1) {
                try testing.expect(list.items[i] == @as(i32, @int_cast(i + 1)));
            }
        }

        for (list.items, 0..) |v, i| {
            try testing.expect(v == @as(i32, @int_cast(i + 1)));
        }

        try testing.expect(list.pop() == 10);
        try testing.expect(list.items.len == 9);

        list.append_slice(&[_]i32{ 1, 2, 3 }) catch unreachable;
        try testing.expect(list.items.len == 12);
        try testing.expect(list.pop() == 3);
        try testing.expect(list.pop() == 2);
        try testing.expect(list.pop() == 1);
        try testing.expect(list.items.len == 9);

        var unaligned: [3]i32 align(1) = [_]i32{ 4, 5, 6 };
        list.append_unaligned_slice(&unaligned) catch unreachable;
        try testing.expect(list.items.len == 12);
        try testing.expect(list.pop() == 6);
        try testing.expect(list.pop() == 5);
        try testing.expect(list.pop() == 4);
        try testing.expect(list.items.len == 9);

        list.append_slice(&[_]i32{}) catch unreachable;
        try testing.expect(list.items.len == 9);

        // can only set on indices < self.items.len
        list.items[7] = 33;
        list.items[8] = 42;

        try testing.expect(list.pop() == 42);
        try testing.expect(list.pop() == 33);
    }
    {
        var list = ArrayListUnmanaged(i32){};
        defer list.deinit(a);

        {
            var i: usize = 0;
            while (i < 10) : (i += 1) {
                list.append(a, @as(i32, @int_cast(i + 1))) catch unreachable;
            }
        }

        {
            var i: usize = 0;
            while (i < 10) : (i += 1) {
                try testing.expect(list.items[i] == @as(i32, @int_cast(i + 1)));
            }
        }

        for (list.items, 0..) |v, i| {
            try testing.expect(v == @as(i32, @int_cast(i + 1)));
        }

        try testing.expect(list.pop() == 10);
        try testing.expect(list.items.len == 9);

        list.append_slice(a, &[_]i32{ 1, 2, 3 }) catch unreachable;
        try testing.expect(list.items.len == 12);
        try testing.expect(list.pop() == 3);
        try testing.expect(list.pop() == 2);
        try testing.expect(list.pop() == 1);
        try testing.expect(list.items.len == 9);

        var unaligned: [3]i32 align(1) = [_]i32{ 4, 5, 6 };
        list.append_unaligned_slice(a, &unaligned) catch unreachable;
        try testing.expect(list.items.len == 12);
        try testing.expect(list.pop() == 6);
        try testing.expect(list.pop() == 5);
        try testing.expect(list.pop() == 4);
        try testing.expect(list.items.len == 9);

        list.append_slice(a, &[_]i32{}) catch unreachable;
        try testing.expect(list.items.len == 9);

        // can only set on indices < self.items.len
        list.items[7] = 33;
        list.items[8] = 42;

        try testing.expect(list.pop() == 42);
        try testing.expect(list.pop() == 33);
    }
}

test "append_ntimes" {
    const a = testing.allocator;
    {
        var list = ArrayList(i32).init(a);
        defer list.deinit();

        try list.append_ntimes(2, 10);
        try testing.expect_equal(@as(usize, 10), list.items.len);
        for (list.items) |element| {
            try testing.expect_equal(@as(i32, 2), element);
        }
    }
    {
        var list = ArrayListUnmanaged(i32){};
        defer list.deinit(a);

        try list.append_ntimes(a, 2, 10);
        try testing.expect_equal(@as(usize, 10), list.items.len);
        for (list.items) |element| {
            try testing.expect_equal(@as(i32, 2), element);
        }
    }
}

test "append_ntimes with failing allocator" {
    const a = testing.failing_allocator;
    {
        var list = ArrayList(i32).init(a);
        defer list.deinit();
        try testing.expect_error(error.OutOfMemory, list.append_ntimes(2, 10));
    }
    {
        var list = ArrayListUnmanaged(i32){};
        defer list.deinit(a);
        try testing.expect_error(error.OutOfMemory, list.append_ntimes(a, 2, 10));
    }
}

test "ordered_remove" {
    const a = testing.allocator;
    {
        var list = ArrayList(i32).init(a);
        defer list.deinit();

        try list.append(1);
        try list.append(2);
        try list.append(3);
        try list.append(4);
        try list.append(5);
        try list.append(6);
        try list.append(7);

        //remove from middle
        try testing.expect_equal(@as(i32, 4), list.ordered_remove(3));
        try testing.expect_equal(@as(i32, 5), list.items[3]);
        try testing.expect_equal(@as(usize, 6), list.items.len);

        //remove from end
        try testing.expect_equal(@as(i32, 7), list.ordered_remove(5));
        try testing.expect_equal(@as(usize, 5), list.items.len);

        //remove from front
        try testing.expect_equal(@as(i32, 1), list.ordered_remove(0));
        try testing.expect_equal(@as(i32, 2), list.items[0]);
        try testing.expect_equal(@as(usize, 4), list.items.len);
    }
    {
        var list = ArrayListUnmanaged(i32){};
        defer list.deinit(a);

        try list.append(a, 1);
        try list.append(a, 2);
        try list.append(a, 3);
        try list.append(a, 4);
        try list.append(a, 5);
        try list.append(a, 6);
        try list.append(a, 7);

        //remove from middle
        try testing.expect_equal(@as(i32, 4), list.ordered_remove(3));
        try testing.expect_equal(@as(i32, 5), list.items[3]);
        try testing.expect_equal(@as(usize, 6), list.items.len);

        //remove from end
        try testing.expect_equal(@as(i32, 7), list.ordered_remove(5));
        try testing.expect_equal(@as(usize, 5), list.items.len);

        //remove from front
        try testing.expect_equal(@as(i32, 1), list.ordered_remove(0));
        try testing.expect_equal(@as(i32, 2), list.items[0]);
        try testing.expect_equal(@as(usize, 4), list.items.len);
    }
    {
        // remove last item
        var list = ArrayList(i32).init(a);
        defer list.deinit();
        try list.append(1);
        try testing.expect_equal(@as(i32, 1), list.ordered_remove(0));
        try testing.expect_equal(@as(usize, 0), list.items.len);
    }
    {
        // remove last item
        var list = ArrayListUnmanaged(i32){};
        defer list.deinit(a);
        try list.append(a, 1);
        try testing.expect_equal(@as(i32, 1), list.ordered_remove(0));
        try testing.expect_equal(@as(usize, 0), list.items.len);
    }
}

test "swap_remove" {
    const a = testing.allocator;
    {
        var list = ArrayList(i32).init(a);
        defer list.deinit();

        try list.append(1);
        try list.append(2);
        try list.append(3);
        try list.append(4);
        try list.append(5);
        try list.append(6);
        try list.append(7);

        //remove from middle
        try testing.expect(list.swap_remove(3) == 4);
        try testing.expect(list.items[3] == 7);
        try testing.expect(list.items.len == 6);

        //remove from end
        try testing.expect(list.swap_remove(5) == 6);
        try testing.expect(list.items.len == 5);

        //remove from front
        try testing.expect(list.swap_remove(0) == 1);
        try testing.expect(list.items[0] == 5);
        try testing.expect(list.items.len == 4);
    }
    {
        var list = ArrayListUnmanaged(i32){};
        defer list.deinit(a);

        try list.append(a, 1);
        try list.append(a, 2);
        try list.append(a, 3);
        try list.append(a, 4);
        try list.append(a, 5);
        try list.append(a, 6);
        try list.append(a, 7);

        //remove from middle
        try testing.expect(list.swap_remove(3) == 4);
        try testing.expect(list.items[3] == 7);
        try testing.expect(list.items.len == 6);

        //remove from end
        try testing.expect(list.swap_remove(5) == 6);
        try testing.expect(list.items.len == 5);

        //remove from front
        try testing.expect(list.swap_remove(0) == 1);
        try testing.expect(list.items[0] == 5);
        try testing.expect(list.items.len == 4);
    }
}

test "insert" {
    const a = testing.allocator;
    {
        var list = ArrayList(i32).init(a);
        defer list.deinit();

        try list.insert(0, 1);
        try list.append(2);
        try list.insert(2, 3);
        try list.insert(0, 5);
        try testing.expect(list.items[0] == 5);
        try testing.expect(list.items[1] == 1);
        try testing.expect(list.items[2] == 2);
        try testing.expect(list.items[3] == 3);
    }
    {
        var list = ArrayListUnmanaged(i32){};
        defer list.deinit(a);

        try list.insert(a, 0, 1);
        try list.append(a, 2);
        try list.insert(a, 2, 3);
        try list.insert(a, 0, 5);
        try testing.expect(list.items[0] == 5);
        try testing.expect(list.items[1] == 1);
        try testing.expect(list.items[2] == 2);
        try testing.expect(list.items[3] == 3);
    }
}

test "insert_slice" {
    const a = testing.allocator;
    {
        var list = ArrayList(i32).init(a);
        defer list.deinit();

        try list.append(1);
        try list.append(2);
        try list.append(3);
        try list.append(4);
        try list.insert_slice(1, &[_]i32{ 9, 8 });
        try testing.expect(list.items[0] == 1);
        try testing.expect(list.items[1] == 9);
        try testing.expect(list.items[2] == 8);
        try testing.expect(list.items[3] == 2);
        try testing.expect(list.items[4] == 3);
        try testing.expect(list.items[5] == 4);

        const items = [_]i32{1};
        try list.insert_slice(0, items[0..0]);
        try testing.expect(list.items.len == 6);
        try testing.expect(list.items[0] == 1);
    }
    {
        var list = ArrayListUnmanaged(i32){};
        defer list.deinit(a);

        try list.append(a, 1);
        try list.append(a, 2);
        try list.append(a, 3);
        try list.append(a, 4);
        try list.insert_slice(a, 1, &[_]i32{ 9, 8 });
        try testing.expect(list.items[0] == 1);
        try testing.expect(list.items[1] == 9);
        try testing.expect(list.items[2] == 8);
        try testing.expect(list.items[3] == 2);
        try testing.expect(list.items[4] == 3);
        try testing.expect(list.items[5] == 4);

        const items = [_]i32{1};
        try list.insert_slice(a, 0, items[0..0]);
        try testing.expect(list.items.len == 6);
        try testing.expect(list.items[0] == 1);
    }
}

test "ArrayList.replace_range" {
    const a = testing.allocator;

    {
        var list = ArrayList(i32).init(a);
        defer list.deinit();
        try list.append_slice(&[_]i32{ 1, 2, 3, 4, 5 });

        try list.replace_range(1, 0, &[_]i32{ 0, 0, 0 });

        try testing.expect_equal_slices(i32, &[_]i32{ 1, 0, 0, 0, 2, 3, 4, 5 }, list.items);
    }
    {
        var list = ArrayList(i32).init(a);
        defer list.deinit();
        try list.append_slice(&[_]i32{ 1, 2, 3, 4, 5 });

        try list.replace_range(1, 1, &[_]i32{ 0, 0, 0 });

        try testing.expect_equal_slices(
            i32,
            &[_]i32{ 1, 0, 0, 0, 3, 4, 5 },
            list.items,
        );
    }
    {
        var list = ArrayList(i32).init(a);
        defer list.deinit();
        try list.append_slice(&[_]i32{ 1, 2, 3, 4, 5 });

        try list.replace_range(1, 2, &[_]i32{ 0, 0, 0 });

        try testing.expect_equal_slices(i32, &[_]i32{ 1, 0, 0, 0, 4, 5 }, list.items);
    }
    {
        var list = ArrayList(i32).init(a);
        defer list.deinit();
        try list.append_slice(&[_]i32{ 1, 2, 3, 4, 5 });

        try list.replace_range(1, 3, &[_]i32{ 0, 0, 0 });

        try testing.expect_equal_slices(i32, &[_]i32{ 1, 0, 0, 0, 5 }, list.items);
    }
    {
        var list = ArrayList(i32).init(a);
        defer list.deinit();
        try list.append_slice(&[_]i32{ 1, 2, 3, 4, 5 });

        try list.replace_range(1, 4, &[_]i32{ 0, 0, 0 });

        try testing.expect_equal_slices(i32, &[_]i32{ 1, 0, 0, 0 }, list.items);
    }
}

test "ArrayList.replace_range_assume_capacity" {
    const a = testing.allocator;

    {
        var list = ArrayList(i32).init(a);
        defer list.deinit();
        try list.append_slice(&[_]i32{ 1, 2, 3, 4, 5 });

        list.replace_range_assume_capacity(1, 0, &[_]i32{ 0, 0, 0 });

        try testing.expect_equal_slices(i32, &[_]i32{ 1, 0, 0, 0, 2, 3, 4, 5 }, list.items);
    }
    {
        var list = ArrayList(i32).init(a);
        defer list.deinit();
        try list.append_slice(&[_]i32{ 1, 2, 3, 4, 5 });

        list.replace_range_assume_capacity(1, 1, &[_]i32{ 0, 0, 0 });

        try testing.expect_equal_slices(
            i32,
            &[_]i32{ 1, 0, 0, 0, 3, 4, 5 },
            list.items,
        );
    }
    {
        var list = ArrayList(i32).init(a);
        defer list.deinit();
        try list.append_slice(&[_]i32{ 1, 2, 3, 4, 5 });

        list.replace_range_assume_capacity(1, 2, &[_]i32{ 0, 0, 0 });

        try testing.expect_equal_slices(i32, &[_]i32{ 1, 0, 0, 0, 4, 5 }, list.items);
    }
    {
        var list = ArrayList(i32).init(a);
        defer list.deinit();
        try list.append_slice(&[_]i32{ 1, 2, 3, 4, 5 });

        list.replace_range_assume_capacity(1, 3, &[_]i32{ 0, 0, 0 });

        try testing.expect_equal_slices(i32, &[_]i32{ 1, 0, 0, 0, 5 }, list.items);
    }
    {
        var list = ArrayList(i32).init(a);
        defer list.deinit();
        try list.append_slice(&[_]i32{ 1, 2, 3, 4, 5 });

        list.replace_range_assume_capacity(1, 4, &[_]i32{ 0, 0, 0 });

        try testing.expect_equal_slices(i32, &[_]i32{ 1, 0, 0, 0 }, list.items);
    }
}

test "ArrayListUnmanaged.replace_range" {
    const a = testing.allocator;

    {
        var list = ArrayListUnmanaged(i32){};
        defer list.deinit(a);
        try list.append_slice(a, &[_]i32{ 1, 2, 3, 4, 5 });

        try list.replace_range(a, 1, 0, &[_]i32{ 0, 0, 0 });

        try testing.expect_equal_slices(i32, &[_]i32{ 1, 0, 0, 0, 2, 3, 4, 5 }, list.items);
    }
    {
        var list = ArrayListUnmanaged(i32){};
        defer list.deinit(a);
        try list.append_slice(a, &[_]i32{ 1, 2, 3, 4, 5 });

        try list.replace_range(a, 1, 1, &[_]i32{ 0, 0, 0 });

        try testing.expect_equal_slices(
            i32,
            &[_]i32{ 1, 0, 0, 0, 3, 4, 5 },
            list.items,
        );
    }
    {
        var list = ArrayListUnmanaged(i32){};
        defer list.deinit(a);
        try list.append_slice(a, &[_]i32{ 1, 2, 3, 4, 5 });

        try list.replace_range(a, 1, 2, &[_]i32{ 0, 0, 0 });

        try testing.expect_equal_slices(i32, &[_]i32{ 1, 0, 0, 0, 4, 5 }, list.items);
    }
    {
        var list = ArrayListUnmanaged(i32){};
        defer list.deinit(a);
        try list.append_slice(a, &[_]i32{ 1, 2, 3, 4, 5 });

        try list.replace_range(a, 1, 3, &[_]i32{ 0, 0, 0 });

        try testing.expect_equal_slices(i32, &[_]i32{ 1, 0, 0, 0, 5 }, list.items);
    }
    {
        var list = ArrayListUnmanaged(i32){};
        defer list.deinit(a);
        try list.append_slice(a, &[_]i32{ 1, 2, 3, 4, 5 });

        try list.replace_range(a, 1, 4, &[_]i32{ 0, 0, 0 });

        try testing.expect_equal_slices(i32, &[_]i32{ 1, 0, 0, 0 }, list.items);
    }
}

test "ArrayListUnmanaged.replace_range_assume_capacity" {
    const a = testing.allocator;

    {
        var list = ArrayListUnmanaged(i32){};
        defer list.deinit(a);
        try list.append_slice(a, &[_]i32{ 1, 2, 3, 4, 5 });

        list.replace_range_assume_capacity(1, 0, &[_]i32{ 0, 0, 0 });

        try testing.expect_equal_slices(i32, &[_]i32{ 1, 0, 0, 0, 2, 3, 4, 5 }, list.items);
    }
    {
        var list = ArrayListUnmanaged(i32){};
        defer list.deinit(a);
        try list.append_slice(a, &[_]i32{ 1, 2, 3, 4, 5 });

        list.replace_range_assume_capacity(1, 1, &[_]i32{ 0, 0, 0 });

        try testing.expect_equal_slices(
            i32,
            &[_]i32{ 1, 0, 0, 0, 3, 4, 5 },
            list.items,
        );
    }
    {
        var list = ArrayListUnmanaged(i32){};
        defer list.deinit(a);
        try list.append_slice(a, &[_]i32{ 1, 2, 3, 4, 5 });

        list.replace_range_assume_capacity(1, 2, &[_]i32{ 0, 0, 0 });

        try testing.expect_equal_slices(i32, &[_]i32{ 1, 0, 0, 0, 4, 5 }, list.items);
    }
    {
        var list = ArrayListUnmanaged(i32){};
        defer list.deinit(a);
        try list.append_slice(a, &[_]i32{ 1, 2, 3, 4, 5 });

        list.replace_range_assume_capacity(1, 3, &[_]i32{ 0, 0, 0 });

        try testing.expect_equal_slices(i32, &[_]i32{ 1, 0, 0, 0, 5 }, list.items);
    }
    {
        var list = ArrayListUnmanaged(i32){};
        defer list.deinit(a);
        try list.append_slice(a, &[_]i32{ 1, 2, 3, 4, 5 });

        list.replace_range_assume_capacity(1, 4, &[_]i32{ 0, 0, 0 });

        try testing.expect_equal_slices(i32, &[_]i32{ 1, 0, 0, 0 }, list.items);
    }
}

const Item = struct {
    integer: i32,
    sub_items: ArrayList(Item),
};

const ItemUnmanaged = struct {
    integer: i32,
    sub_items: ArrayListUnmanaged(ItemUnmanaged),
};

test "ArrayList(T) of struct T" {
    const a = std.testing.allocator;
    {
        var root = Item{ .integer = 1, .sub_items = ArrayList(Item).init(a) };
        defer root.sub_items.deinit();
        try root.sub_items.append(Item{ .integer = 42, .sub_items = ArrayList(Item).init(a) });
        try testing.expect(root.sub_items.items[0].integer == 42);
    }
    {
        var root = ItemUnmanaged{ .integer = 1, .sub_items = ArrayListUnmanaged(ItemUnmanaged){} };
        defer root.sub_items.deinit(a);
        try root.sub_items.append(a, ItemUnmanaged{ .integer = 42, .sub_items = ArrayListUnmanaged(ItemUnmanaged){} });
        try testing.expect(root.sub_items.items[0].integer == 42);
    }
}

test "ArrayList(u8) implements writer" {
    const a = testing.allocator;

    {
        var buffer = ArrayList(u8).init(a);
        defer buffer.deinit();

        const x: i32 = 42;
        const y: i32 = 1234;
        try buffer.writer().print("x: {}\ny: {}\n", .{ x, y });

        try testing.expect_equal_slices(u8, "x: 42\ny: 1234\n", buffer.items);
    }
    {
        var list = ArrayListAligned(u8, 2).init(a);
        defer list.deinit();

        const writer = list.writer();
        try writer.write_all("a");
        try writer.write_all("bc");
        try writer.write_all("d");
        try writer.write_all("efg");

        try testing.expect_equal_slices(u8, list.items, "abcdefg");
    }
}

test "ArrayListUnmanaged(u8) implements writer" {
    const a = testing.allocator;

    {
        var buffer: ArrayListUnmanaged(u8) = .{};
        defer buffer.deinit(a);

        const x: i32 = 42;
        const y: i32 = 1234;
        try buffer.writer(a).print("x: {}\ny: {}\n", .{ x, y });

        try testing.expect_equal_slices(u8, "x: 42\ny: 1234\n", buffer.items);
    }
    {
        var list: ArrayListAlignedUnmanaged(u8, 2) = .{};
        defer list.deinit(a);

        const writer = list.writer(a);
        try writer.write_all("a");
        try writer.write_all("bc");
        try writer.write_all("d");
        try writer.write_all("efg");

        try testing.expect_equal_slices(u8, list.items, "abcdefg");
    }
}

test "shrink still sets length when resizing is disabled" {
    var failing_allocator = testing.FailingAllocator.init(testing.allocator, .{ .resize_fail_index = 0 });
    const a = failing_allocator.allocator();

    {
        var list = ArrayList(i32).init(a);
        defer list.deinit();

        try list.append(1);
        try list.append(2);
        try list.append(3);

        list.shrink_and_free(1);
        try testing.expect(list.items.len == 1);
    }
    {
        var list = ArrayListUnmanaged(i32){};
        defer list.deinit(a);

        try list.append(a, 1);
        try list.append(a, 2);
        try list.append(a, 3);

        list.shrink_and_free(a, 1);
        try testing.expect(list.items.len == 1);
    }
}

test "shrink_and_free with a copy" {
    var failing_allocator = testing.FailingAllocator.init(testing.allocator, .{ .resize_fail_index = 0 });
    const a = failing_allocator.allocator();

    var list = ArrayList(i32).init(a);
    defer list.deinit();

    try list.append_ntimes(3, 16);
    list.shrink_and_free(4);
    try testing.expect(mem.eql(i32, list.items, &.{ 3, 3, 3, 3 }));
}

test "add_many_as_array" {
    const a = std.testing.allocator;
    {
        var list = ArrayList(u8).init(a);
        defer list.deinit();

        (try list.add_many_as_array(4)).* = "aoeu".*;
        try list.ensure_total_capacity(8);
        list.add_many_as_array_assume_capacity(4).* = "asdf".*;

        try testing.expect_equal_slices(u8, list.items, "aoeuasdf");
    }
    {
        var list = ArrayListUnmanaged(u8){};
        defer list.deinit(a);

        (try list.add_many_as_array(a, 4)).* = "aoeu".*;
        try list.ensure_total_capacity(a, 8);
        list.add_many_as_array_assume_capacity(4).* = "asdf".*;

        try testing.expect_equal_slices(u8, list.items, "aoeuasdf");
    }
}

test "growing memory preserves contents" {
    // Shrink the list after every insertion to ensure that a memory growth
    // will be triggered in the next operation.
    const a = std.testing.allocator;
    {
        var list = ArrayList(u8).init(a);
        defer list.deinit();

        (try list.add_many_as_array(4)).* = "abcd".*;
        list.shrink_and_free(4);

        try list.append_slice("efgh");
        try testing.expect_equal_slices(u8, list.items, "abcdefgh");
        list.shrink_and_free(8);

        try list.insert_slice(4, "ijkl");
        try testing.expect_equal_slices(u8, list.items, "abcdijklefgh");
    }
    {
        var list = ArrayListUnmanaged(u8){};
        defer list.deinit(a);

        (try list.add_many_as_array(a, 4)).* = "abcd".*;
        list.shrink_and_free(a, 4);

        try list.append_slice(a, "efgh");
        try testing.expect_equal_slices(u8, list.items, "abcdefgh");
        list.shrink_and_free(a, 8);

        try list.insert_slice(a, 4, "ijkl");
        try testing.expect_equal_slices(u8, list.items, "abcdijklefgh");
    }
}

test "from_owned_slice" {
    const a = testing.allocator;
    {
        var orig_list = ArrayList(u8).init(a);
        defer orig_list.deinit();
        try orig_list.append_slice("foobar");

        const slice = try orig_list.to_owned_slice();
        var list = ArrayList(u8).from_owned_slice(a, slice);
        defer list.deinit();
        try testing.expect_equal_strings(list.items, "foobar");
    }
    {
        var list = ArrayList(u8).init(a);
        defer list.deinit();
        try list.append_slice("foobar");

        const slice = try list.to_owned_slice();
        var unmanaged = ArrayListUnmanaged(u8).from_owned_slice(slice);
        defer unmanaged.deinit(a);
        try testing.expect_equal_strings(unmanaged.items, "foobar");
    }
}

test "from_owned_slice_sentinel" {
    const a = testing.allocator;
    {
        var orig_list = ArrayList(u8).init(a);
        defer orig_list.deinit();
        try orig_list.append_slice("foobar");

        const sentinel_slice = try orig_list.to_owned_slice_sentinel(0);
        var list = ArrayList(u8).from_owned_slice_sentinel(a, 0, sentinel_slice);
        defer list.deinit();
        try testing.expect_equal_strings(list.items, "foobar");
    }
    {
        var list = ArrayList(u8).init(a);
        defer list.deinit();
        try list.append_slice("foobar");

        const sentinel_slice = try list.to_owned_slice_sentinel(0);
        var unmanaged = ArrayListUnmanaged(u8).from_owned_slice_sentinel(0, sentinel_slice);
        defer unmanaged.deinit(a);
        try testing.expect_equal_strings(unmanaged.items, "foobar");
    }
}

test "to_owned_slice_sentinel" {
    const a = testing.allocator;
    {
        var list = ArrayList(u8).init(a);
        defer list.deinit();

        try list.append_slice("foobar");

        const result = try list.to_owned_slice_sentinel(0);
        defer a.free(result);
        try testing.expect_equal_strings(result, mem.slice_to(result.ptr, 0));
    }
    {
        var list = ArrayListUnmanaged(u8){};
        defer list.deinit(a);

        try list.append_slice(a, "foobar");

        const result = try list.to_owned_slice_sentinel(a, 0);
        defer a.free(result);
        try testing.expect_equal_strings(result, mem.slice_to(result.ptr, 0));
    }
}

test "accepts unaligned slices" {
    const a = testing.allocator;
    {
        var list = std.ArrayListAligned(u8, 8).init(a);
        defer list.deinit();

        try list.append_slice(&.{ 0, 1, 2, 3 });
        try list.insert_slice(2, &.{ 4, 5, 6, 7 });
        try list.replace_range(1, 3, &.{ 8, 9 });

        try testing.expect_equal_slices(u8, list.items, &.{ 0, 8, 9, 6, 7, 2, 3 });
    }
    {
        var list = std.ArrayListAlignedUnmanaged(u8, 8){};
        defer list.deinit(a);

        try list.append_slice(a, &.{ 0, 1, 2, 3 });
        try list.insert_slice(a, 2, &.{ 4, 5, 6, 7 });
        try list.replace_range(a, 1, 3, &.{ 8, 9 });

        try testing.expect_equal_slices(u8, list.items, &.{ 0, 8, 9, 6, 7, 2, 3 });
    }
}

test "ArrayList(u0)" {
    // An ArrayList on zero-sized types should not need to allocate
    const a = testing.failing_allocator;

    var list = ArrayList(u0).init(a);
    defer list.deinit();

    try list.append(0);
    try list.append(0);
    try list.append(0);
    try testing.expect_equal(list.items.len, 3);

    var count: usize = 0;
    for (list.items) |x| {
        try testing.expect_equal(x, 0);
        count += 1;
    }
    try testing.expect_equal(count, 3);
}

test "ArrayList(?u32).pop_or_null()" {
    const a = testing.allocator;

    var list = ArrayList(?u32).init(a);
    defer list.deinit();

    try list.append(null);
    try list.append(1);
    try list.append(2);
    try testing.expect_equal(list.items.len, 3);

    try testing.expect(list.pop_or_null().? == @as(u32, 2));
    try testing.expect(list.pop_or_null().? == @as(u32, 1));
    try testing.expect(list.pop_or_null().? == null);
    try testing.expect(list.pop_or_null() == null);
}

test "ArrayList(u32).get_last()" {
    const a = testing.allocator;

    var list = ArrayList(u32).init(a);
    defer list.deinit();

    try list.append(2);
    const const_list = list;
    try testing.expect_equal(const_list.get_last(), 2);
}

test "ArrayList(u32).get_last_or_null()" {
    const a = testing.allocator;

    var list = ArrayList(u32).init(a);
    defer list.deinit();

    try testing.expect_equal(list.get_last_or_null(), null);

    try list.append(2);
    const const_list = list;
    try testing.expect_equal(const_list.get_last_or_null().?, 2);
}

test "return OutOfMemory when capacity would exceed maximum usize integer value" {
    const a = testing.allocator;
    const new_item: u32 = 42;
    const items = &.{ 42, 43 };

    {
        var list: ArrayListUnmanaged(u32) = .{
            .items = undefined,
            .capacity = math.max_int(usize) - 1,
        };
        list.items.len = math.max_int(usize) - 1;

        try testing.expect_error(error.OutOfMemory, list.append_slice(a, items));
        try testing.expect_error(error.OutOfMemory, list.append_ntimes(a, new_item, 2));
        try testing.expect_error(error.OutOfMemory, list.append_unaligned_slice(a, &.{ new_item, new_item }));
        try testing.expect_error(error.OutOfMemory, list.add_many_at(a, 0, 2));
        try testing.expect_error(error.OutOfMemory, list.add_many_as_array(a, 2));
        try testing.expect_error(error.OutOfMemory, list.add_many_as_slice(a, 2));
        try testing.expect_error(error.OutOfMemory, list.insert_slice(a, 0, items));
        try testing.expect_error(error.OutOfMemory, list.ensure_unused_capacity(a, 2));
    }

    {
        var list: ArrayList(u32) = .{
            .items = undefined,
            .capacity = math.max_int(usize) - 1,
            .allocator = a,
        };
        list.items.len = math.max_int(usize) - 1;

        try testing.expect_error(error.OutOfMemory, list.append_slice(items));
        try testing.expect_error(error.OutOfMemory, list.append_ntimes(new_item, 2));
        try testing.expect_error(error.OutOfMemory, list.append_unaligned_slice(&.{ new_item, new_item }));
        try testing.expect_error(error.OutOfMemory, list.add_many_at(0, 2));
        try testing.expect_error(error.OutOfMemory, list.add_many_as_array(2));
        try testing.expect_error(error.OutOfMemory, list.add_many_as_slice(2));
        try testing.expect_error(error.OutOfMemory, list.insert_slice(0, items));
        try testing.expect_error(error.OutOfMemory, list.ensure_unused_capacity(2));
    }
}
