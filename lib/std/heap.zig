const std = @import("std.zig");
const builtin = @import("builtin");
const root = @import("root");
const assert = std.debug.assert;
const testing = std.testing;
const mem = std.mem;
const c = std.c;
const Allocator = std.mem.Allocator;
const windows = std.os.windows;

pub const LoggingAllocator = @import("heap/logging_allocator.zig").LoggingAllocator;
pub const logging_allocator = @import("heap/logging_allocator.zig").logging_allocator;
pub const ScopedLoggingAllocator = @import("heap/logging_allocator.zig").ScopedLoggingAllocator;
pub const LogToWriterAllocator = @import("heap/log_to_writer_allocator.zig").LogToWriterAllocator;
pub const log_to_writer_allocator = @import("heap/log_to_writer_allocator.zig").log_to_writer_allocator;
pub const ArenaAllocator = @import("heap/arena_allocator.zig").ArenaAllocator;
pub const GeneralPurposeAllocatorConfig = @import("heap/general_purpose_allocator.zig").Config;
pub const GeneralPurposeAllocator = @import("heap/general_purpose_allocator.zig").GeneralPurposeAllocator;
pub const Check = @import("heap/general_purpose_allocator.zig").Check;
pub const WasmAllocator = @import("heap/WasmAllocator.zig");
pub const WasmPageAllocator = @import("heap/WasmPageAllocator.zig");
pub const PageAllocator = @import("heap/PageAllocator.zig");
pub const ThreadSafeAllocator = @import("heap/ThreadSafeAllocator.zig");
pub const SbrkAllocator = @import("heap/sbrk_allocator.zig").SbrkAllocator;

const memory_pool = @import("heap/memory_pool.zig");
pub const MemoryPool = memory_pool.MemoryPool;
pub const MemoryPoolAligned = memory_pool.MemoryPoolAligned;
pub const MemoryPoolExtra = memory_pool.MemoryPoolExtra;
pub const MemoryPoolOptions = memory_pool.Options;

/// TODO Utilize this on Windows.
pub var next_mmap_addr_hint: ?[*]align(mem.page_size) u8 = null;

const CAllocator = struct {
    comptime {
        if (!builtin.link_libc) {
            @compile_error("C allocator is only available when linking against libc");
        }
    }

    pub const supports_malloc_size = @TypeOf(malloc_size) != void;
    pub const malloc_size = if (@hasDecl(c, "malloc_size"))
        c.malloc_size
    else if (@hasDecl(c, "malloc_usable_size"))
        c.malloc_usable_size
    else if (@hasDecl(c, "_msize"))
        c._msize
    else {};

    pub const supports_posix_memalign = @hasDecl(c, "posix_memalign");

    fn get_header(ptr: [*]u8) *[*]u8 {
        return @as(*[*]u8, @ptrFromInt(@int_from_ptr(ptr) - @size_of(usize)));
    }

    fn aligned_alloc(len: usize, log2_align: u8) ?[*]u8 {
        const alignment = @as(usize, 1) << @as(Allocator.Log2Align, @int_cast(log2_align));
        if (supports_posix_memalign) {
            // The posix_memalign only accepts alignment values that are a
            // multiple of the pointer size
            const eff_alignment = @max(alignment, @size_of(usize));

            var aligned_ptr: ?*anyopaque = undefined;
            if (c.posix_memalign(&aligned_ptr, eff_alignment, len) != 0)
                return null;

            return @as([*]u8, @ptr_cast(aligned_ptr));
        }

        // Thin wrapper around regular malloc, overallocate to account for
        // alignment padding and store the original malloc()'ed pointer before
        // the aligned address.
        const unaligned_ptr = @as([*]u8, @ptr_cast(c.malloc(len + alignment - 1 + @size_of(usize)) orelse return null));
        const unaligned_addr = @int_from_ptr(unaligned_ptr);
        const aligned_addr = mem.align_forward(usize, unaligned_addr + @size_of(usize), alignment);
        const aligned_ptr = unaligned_ptr + (aligned_addr - unaligned_addr);
        get_header(aligned_ptr).* = unaligned_ptr;

        return aligned_ptr;
    }

    fn aligned_free(ptr: [*]u8) void {
        if (supports_posix_memalign) {
            return c.free(ptr);
        }

        const unaligned_ptr = get_header(ptr).*;
        c.free(unaligned_ptr);
    }

    fn aligned_alloc_size(ptr: [*]u8) usize {
        if (supports_posix_memalign) {
            return CAllocator.malloc_size(ptr);
        }

        const unaligned_ptr = get_header(ptr).*;
        const delta = @int_from_ptr(ptr) - @int_from_ptr(unaligned_ptr);
        return CAllocator.malloc_size(unaligned_ptr) - delta;
    }

    fn alloc(
        _: *anyopaque,
        len: usize,
        log2_align: u8,
        return_address: usize,
    ) ?[*]u8 {
        _ = return_address;
        assert(len > 0);
        return aligned_alloc(len, log2_align);
    }

    fn resize(
        _: *anyopaque,
        buf: []u8,
        log2_buf_align: u8,
        new_len: usize,
        return_address: usize,
    ) bool {
        _ = log2_buf_align;
        _ = return_address;
        if (new_len <= buf.len) {
            return true;
        }
        if (CAllocator.supports_malloc_size) {
            const full_len = aligned_alloc_size(buf.ptr);
            if (new_len <= full_len) {
                return true;
            }
        }
        return false;
    }

    fn free(
        _: *anyopaque,
        buf: []u8,
        log2_buf_align: u8,
        return_address: usize,
    ) void {
        _ = log2_buf_align;
        _ = return_address;
        aligned_free(buf.ptr);
    }
};

/// Supports the full Allocator interface, including alignment, and exploiting
/// `malloc_usable_size` if available. For an allocator that directly calls
/// `malloc`/`free`, see `raw_c_allocator`.
pub const c_allocator = Allocator{
    .ptr = undefined,
    .vtable = &c_allocator_vtable,
};
const c_allocator_vtable = Allocator.VTable{
    .alloc = CAllocator.alloc,
    .resize = CAllocator.resize,
    .free = CAllocator.free,
};

/// Asserts allocations are within `@alignOf(std.c.max_align_t)` and directly calls
/// `malloc`/`free`. Does not attempt to utilize `malloc_usable_size`.
/// This allocator is safe to use as the backing allocator with
/// `ArenaAllocator` for example and is more optimal in such a case
/// than `c_allocator`.
pub const raw_c_allocator = Allocator{
    .ptr = undefined,
    .vtable = &raw_c_allocator_vtable,
};
const raw_c_allocator_vtable = Allocator.VTable{
    .alloc = raw_calloc,
    .resize = raw_cresize,
    .free = raw_cfree,
};

fn raw_calloc(
    _: *anyopaque,
    len: usize,
    log2_ptr_align: u8,
    ret_addr: usize,
) ?[*]u8 {
    _ = ret_addr;
    assert(log2_ptr_align <= comptime std.math.log2_int(usize, @alignOf(std.c.max_align_t)));
    // Note that this pointer cannot be aligncasted to max_align_t because if
    // len is < max_align_t then the alignment can be smaller. For example, if
    // max_align_t is 16, but the user requests 8 bytes, there is no built-in
    // type in C that is size 8 and has 16 byte alignment, so the alignment may
    // be 8 bytes rather than 16. Similarly if only 1 byte is requested, malloc
    // is allowed to return a 1-byte aligned pointer.
    return @as(?[*]u8, @ptr_cast(c.malloc(len)));
}

fn raw_cresize(
    _: *anyopaque,
    buf: []u8,
    log2_old_align: u8,
    new_len: usize,
    ret_addr: usize,
) bool {
    _ = log2_old_align;
    _ = ret_addr;

    if (new_len <= buf.len)
        return true;

    if (CAllocator.supports_malloc_size) {
        const full_len = CAllocator.malloc_size(buf.ptr);
        if (new_len <= full_len) return true;
    }

    return false;
}

fn raw_cfree(
    _: *anyopaque,
    buf: []u8,
    log2_old_align: u8,
    ret_addr: usize,
) void {
    _ = log2_old_align;
    _ = ret_addr;
    c.free(buf.ptr);
}

/// This allocator makes a syscall directly for every allocation and free.
/// Thread-safe and lock-free.
pub const page_allocator = if (@hasDecl(root, "os") and
    @hasDecl(root.os, "heap") and
    @hasDecl(root.os.heap, "page_allocator"))
    root.os.heap.page_allocator
else if (builtin.target.is_wasm())
    Allocator{
        .ptr = undefined,
        .vtable = &WasmPageAllocator.vtable,
    }
else if (builtin.target.os.tag == .plan9)
    Allocator{
        .ptr = undefined,
        .vtable = &SbrkAllocator(std.os.plan9.sbrk).vtable,
    }
else
    Allocator{
        .ptr = undefined,
        .vtable = &PageAllocator.vtable,
    };

/// This allocator is fast, small, and specific to WebAssembly. In the future,
/// this will be the implementation automatically selected by
/// `GeneralPurposeAllocator` when compiling in `ReleaseSmall` mode for wasm32
/// and wasm64 architectures.
/// Until then, it is available here to play with.
pub const wasm_allocator = Allocator{
    .ptr = undefined,
    .vtable = &std.heap.WasmAllocator.vtable,
};

/// Verifies that the adjusted length will still map to the full length
pub fn align_page_alloc_len(full_len: usize, len: usize) usize {
    const aligned_len = mem.align_alloc_len(full_len, len);
    assert(mem.align_forward(usize, aligned_len, mem.page_size) == full_len);
    return aligned_len;
}

pub const HeapAllocator = switch (builtin.os.tag) {
    .windows => struct {
        heap_handle: ?HeapHandle,

        const HeapHandle = windows.HANDLE;

        pub fn init() HeapAllocator {
            return HeapAllocator{
                .heap_handle = null,
            };
        }

        pub fn allocator(self: *HeapAllocator) Allocator {
            return .{
                .ptr = self,
                .vtable = &.{
                    .alloc = alloc,
                    .resize = resize,
                    .free = free,
                },
            };
        }

        pub fn deinit(self: *HeapAllocator) void {
            if (self.heap_handle) |heap_handle| {
                windows.HeapDestroy(heap_handle);
            }
        }

        fn get_record_ptr(buf: []u8) *align(1) usize {
            return @as(*align(1) usize, @ptrFromInt(@int_from_ptr(buf.ptr) + buf.len));
        }

        fn alloc(
            ctx: *anyopaque,
            n: usize,
            log2_ptr_align: u8,
            return_address: usize,
        ) ?[*]u8 {
            _ = return_address;
            const self: *HeapAllocator = @ptr_cast(@align_cast(ctx));

            const ptr_align = @as(usize, 1) << @as(Allocator.Log2Align, @int_cast(log2_ptr_align));
            const amt = n + ptr_align - 1 + @size_of(usize);
            const optional_heap_handle = @atomicLoad(?HeapHandle, &self.heap_handle, .seq_cst);
            const heap_handle = optional_heap_handle orelse blk: {
                const options = if (builtin.single_threaded) windows.HEAP_NO_SERIALIZE else 0;
                const hh = windows.kernel32.HeapCreate(options, amt, 0) orelse return null;
                const other_hh = @cmpxchg_strong(?HeapHandle, &self.heap_handle, null, hh, .seq_cst, .seq_cst) orelse break :blk hh;
                windows.HeapDestroy(hh);
                break :blk other_hh.?; // can't be null because of the cmpxchg
            };
            const ptr = windows.kernel32.HeapAlloc(heap_handle, 0, amt) orelse return null;
            const root_addr = @int_from_ptr(ptr);
            const aligned_addr = mem.align_forward(usize, root_addr, ptr_align);
            const buf = @as([*]u8, @ptrFromInt(aligned_addr))[0..n];
            get_record_ptr(buf).* = root_addr;
            return buf.ptr;
        }

        fn resize(
            ctx: *anyopaque,
            buf: []u8,
            log2_buf_align: u8,
            new_size: usize,
            return_address: usize,
        ) bool {
            _ = log2_buf_align;
            _ = return_address;
            const self: *HeapAllocator = @ptr_cast(@align_cast(ctx));

            const root_addr = get_record_ptr(buf).*;
            const align_offset = @int_from_ptr(buf.ptr) - root_addr;
            const amt = align_offset + new_size + @size_of(usize);
            const new_ptr = windows.kernel32.HeapReAlloc(
                self.heap_handle.?,
                windows.HEAP_REALLOC_IN_PLACE_ONLY,
                @as(*anyopaque, @ptrFromInt(root_addr)),
                amt,
            ) orelse return false;
            assert(new_ptr == @as(*anyopaque, @ptrFromInt(root_addr)));
            get_record_ptr(buf.ptr[0..new_size]).* = root_addr;
            return true;
        }

        fn free(
            ctx: *anyopaque,
            buf: []u8,
            log2_buf_align: u8,
            return_address: usize,
        ) void {
            _ = log2_buf_align;
            _ = return_address;
            const self: *HeapAllocator = @ptr_cast(@align_cast(ctx));
            windows.HeapFree(self.heap_handle.?, 0, @as(*anyopaque, @ptrFromInt(get_record_ptr(buf).*)));
        }
    },
    else => @compile_error("Unsupported OS"),
};

fn slice_contains_ptr(container: []u8, ptr: [*]u8) bool {
    return @int_from_ptr(ptr) >= @int_from_ptr(container.ptr) and
        @int_from_ptr(ptr) < (@int_from_ptr(container.ptr) + container.len);
}

fn slice_contains_slice(container: []u8, slice: []u8) bool {
    return @int_from_ptr(slice.ptr) >= @int_from_ptr(container.ptr) and
        (@int_from_ptr(slice.ptr) + slice.len) <= (@int_from_ptr(container.ptr) + container.len);
}

pub const FixedBufferAllocator = struct {
    end_index: usize,
    buffer: []u8,

    pub fn init(buffer: []u8) FixedBufferAllocator {
        return FixedBufferAllocator{
            .buffer = buffer,
            .end_index = 0,
        };
    }

    /// *WARNING* using this at the same time as the interface returned by `thread_safe_allocator` is not thread safe
    pub fn allocator(self: *FixedBufferAllocator) Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .free = free,
            },
        };
    }

    /// Provides a lock free thread safe `Allocator` interface to the underlying `FixedBufferAllocator`
    /// *WARNING* using this at the same time as the interface returned by `allocator` is not thread safe
    pub fn thread_safe_allocator(self: *FixedBufferAllocator) Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = thread_safe_alloc,
                .resize = Allocator.no_resize,
                .free = Allocator.no_free,
            },
        };
    }

    pub fn owns_ptr(self: *FixedBufferAllocator, ptr: [*]u8) bool {
        return slice_contains_ptr(self.buffer, ptr);
    }

    pub fn owns_slice(self: *FixedBufferAllocator, slice: []u8) bool {
        return slice_contains_slice(self.buffer, slice);
    }

    /// NOTE: this will not work in all cases, if the last allocation had an adjusted_index
    ///       then we won't be able to determine what the last allocation was.  This is because
    ///       the align_forward operation done in alloc is not reversible.
    pub fn is_last_allocation(self: *FixedBufferAllocator, buf: []u8) bool {
        return buf.ptr + buf.len == self.buffer.ptr + self.end_index;
    }

    fn alloc(ctx: *anyopaque, n: usize, log2_ptr_align: u8, ra: usize) ?[*]u8 {
        const self: *FixedBufferAllocator = @ptr_cast(@align_cast(ctx));
        _ = ra;
        const ptr_align = @as(usize, 1) << @as(Allocator.Log2Align, @int_cast(log2_ptr_align));
        const adjust_off = mem.align_pointer_offset(self.buffer.ptr + self.end_index, ptr_align) orelse return null;
        const adjusted_index = self.end_index + adjust_off;
        const new_end_index = adjusted_index + n;
        if (new_end_index > self.buffer.len) return null;
        self.end_index = new_end_index;
        return self.buffer.ptr + adjusted_index;
    }

    fn resize(
        ctx: *anyopaque,
        buf: []u8,
        log2_buf_align: u8,
        new_size: usize,
        return_address: usize,
    ) bool {
        const self: *FixedBufferAllocator = @ptr_cast(@align_cast(ctx));
        _ = log2_buf_align;
        _ = return_address;
        assert(@in_comptime() or self.owns_slice(buf));

        if (!self.is_last_allocation(buf)) {
            if (new_size > buf.len) return false;
            return true;
        }

        if (new_size <= buf.len) {
            const sub = buf.len - new_size;
            self.end_index -= sub;
            return true;
        }

        const add = new_size - buf.len;
        if (add + self.end_index > self.buffer.len) return false;

        self.end_index += add;
        return true;
    }

    fn free(
        ctx: *anyopaque,
        buf: []u8,
        log2_buf_align: u8,
        return_address: usize,
    ) void {
        const self: *FixedBufferAllocator = @ptr_cast(@align_cast(ctx));
        _ = log2_buf_align;
        _ = return_address;
        assert(@in_comptime() or self.owns_slice(buf));

        if (self.is_last_allocation(buf)) {
            self.end_index -= buf.len;
        }
    }

    fn thread_safe_alloc(ctx: *anyopaque, n: usize, log2_ptr_align: u8, ra: usize) ?[*]u8 {
        const self: *FixedBufferAllocator = @ptr_cast(@align_cast(ctx));
        _ = ra;
        const ptr_align = @as(usize, 1) << @as(Allocator.Log2Align, @int_cast(log2_ptr_align));
        var end_index = @atomicLoad(usize, &self.end_index, .seq_cst);
        while (true) {
            const adjust_off = mem.align_pointer_offset(self.buffer.ptr + end_index, ptr_align) orelse return null;
            const adjusted_index = end_index + adjust_off;
            const new_end_index = adjusted_index + n;
            if (new_end_index > self.buffer.len) return null;
            end_index = @cmpxchg_weak(usize, &self.end_index, end_index, new_end_index, .seq_cst, .seq_cst) orelse
                return self.buffer[adjusted_index..new_end_index].ptr;
        }
    }

    pub fn reset(self: *FixedBufferAllocator) void {
        self.end_index = 0;
    }
};

pub const ThreadSafeFixedBufferAllocator = @compile_error("ThreadSafeFixedBufferAllocator has been replaced with `thread_safe_allocator` on FixedBufferAllocator");

/// Returns a `StackFallbackAllocator` allocating using either a
/// `FixedBufferAllocator` on an array of size `size` and falling back to
/// `fallback_allocator` if that fails.
pub fn stack_fallback(comptime size: usize, fallback_allocator: Allocator) StackFallbackAllocator(size) {
    return StackFallbackAllocator(size){
        .buffer = undefined,
        .fallback_allocator = fallback_allocator,
        .fixed_buffer_allocator = undefined,
    };
}

/// An allocator that attempts to allocate using a
/// `FixedBufferAllocator` using an array of size `size`. If the
/// allocation fails, it will fall back to using
/// `fallback_allocator`. Easily created with `stack_fallback`.
pub fn StackFallbackAllocator(comptime size: usize) type {
    return struct {
        const Self = @This();

        buffer: [size]u8,
        fallback_allocator: Allocator,
        fixed_buffer_allocator: FixedBufferAllocator,
        get_called: if (std.debug.runtime_safety) bool else void =
            if (std.debug.runtime_safety) false else {},

        /// This function both fetches a `Allocator` interface to this
        /// allocator *and* resets the internal buffer allocator.
        pub fn get(self: *Self) Allocator {
            if (std.debug.runtime_safety) {
                assert(!self.get_called); // `get` called multiple times; instead use `const allocator = stack_fallback(N).get();`
                self.get_called = true;
            }
            self.fixed_buffer_allocator = FixedBufferAllocator.init(self.buffer[0..]);
            return .{
                .ptr = self,
                .vtable = &.{
                    .alloc = alloc,
                    .resize = resize,
                    .free = free,
                },
            };
        }

        /// Unlike most std allocators `StackFallbackAllocator` modifies
        /// its internal state before returning an implementation of
        /// the`Allocator` interface and therefore also doesn't use
        /// the usual `.allocator()` method.
        pub const allocator = @compile_error("use 'const allocator = stack_fallback(N).get();' instead");

        fn alloc(
            ctx: *anyopaque,
            len: usize,
            log2_ptr_align: u8,
            ra: usize,
        ) ?[*]u8 {
            const self: *Self = @ptr_cast(@align_cast(ctx));
            return FixedBufferAllocator.alloc(&self.fixed_buffer_allocator, len, log2_ptr_align, ra) orelse
                return self.fallback_allocator.raw_alloc(len, log2_ptr_align, ra);
        }

        fn resize(
            ctx: *anyopaque,
            buf: []u8,
            log2_buf_align: u8,
            new_len: usize,
            ra: usize,
        ) bool {
            const self: *Self = @ptr_cast(@align_cast(ctx));
            if (self.fixed_buffer_allocator.owns_ptr(buf.ptr)) {
                return FixedBufferAllocator.resize(&self.fixed_buffer_allocator, buf, log2_buf_align, new_len, ra);
            } else {
                return self.fallback_allocator.raw_resize(buf, log2_buf_align, new_len, ra);
            }
        }

        fn free(
            ctx: *anyopaque,
            buf: []u8,
            log2_buf_align: u8,
            ra: usize,
        ) void {
            const self: *Self = @ptr_cast(@align_cast(ctx));
            if (self.fixed_buffer_allocator.owns_ptr(buf.ptr)) {
                return FixedBufferAllocator.free(&self.fixed_buffer_allocator, buf, log2_buf_align, ra);
            } else {
                return self.fallback_allocator.raw_free(buf, log2_buf_align, ra);
            }
        }
    };
}

test "c_allocator" {
    if (builtin.link_libc) {
        try test_allocator(c_allocator);
        try test_allocator_aligned(c_allocator);
        try test_allocator_large_alignment(c_allocator);
        try test_allocator_aligned_shrink(c_allocator);
    }
}

test "raw_c_allocator" {
    if (builtin.link_libc) {
        try test_allocator(raw_c_allocator);
    }
}

test "PageAllocator" {
    const allocator = page_allocator;
    try test_allocator(allocator);
    try test_allocator_aligned(allocator);
    if (!builtin.target.is_wasm()) {
        try test_allocator_large_alignment(allocator);
        try test_allocator_aligned_shrink(allocator);
    }

    if (builtin.os.tag == .windows) {
        const slice = try allocator.aligned_alloc(u8, mem.page_size, 128);
        slice[0] = 0x12;
        slice[127] = 0x34;
        allocator.free(slice);
    }
    {
        var buf = try allocator.alloc(u8, mem.page_size + 1);
        defer allocator.free(buf);
        buf = try allocator.realloc(buf, 1); // shrink past the page boundary
    }
}

test "HeapAllocator" {
    if (builtin.os.tag == .windows) {
        // https://github.com/ziglang/zig/issues/13702
        if (builtin.cpu.arch == .aarch64) return error.SkipZigTest;

        var heap_allocator = HeapAllocator.init();
        defer heap_allocator.deinit();
        const allocator = heap_allocator.allocator();

        try test_allocator(allocator);
        try test_allocator_aligned(allocator);
        try test_allocator_large_alignment(allocator);
        try test_allocator_aligned_shrink(allocator);
    }
}

test "ArenaAllocator" {
    var arena_allocator = ArenaAllocator.init(page_allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    try test_allocator(allocator);
    try test_allocator_aligned(allocator);
    try test_allocator_large_alignment(allocator);
    try test_allocator_aligned_shrink(allocator);
}

var test_fixed_buffer_allocator_memory: [800000 * @size_of(u64)]u8 = undefined;
test "FixedBufferAllocator" {
    var fixed_buffer_allocator = mem.validation_wrap(FixedBufferAllocator.init(test_fixed_buffer_allocator_memory[0..]));
    const allocator = fixed_buffer_allocator.allocator();

    try test_allocator(allocator);
    try test_allocator_aligned(allocator);
    try test_allocator_large_alignment(allocator);
    try test_allocator_aligned_shrink(allocator);
}

test "FixedBufferAllocator.reset" {
    var buf: [8]u8 align(@alignOf(u64)) = undefined;
    var fba = FixedBufferAllocator.init(buf[0..]);
    const allocator = fba.allocator();

    const X = 0xeeeeeeeeeeeeeeee;
    const Y = 0xffffffffffffffff;

    const x = try allocator.create(u64);
    x.* = X;
    try testing.expect_error(error.OutOfMemory, allocator.create(u64));

    fba.reset();
    const y = try allocator.create(u64);
    y.* = Y;

    // we expect Y to have overwritten X.
    try testing.expect(x.* == y.*);
    try testing.expect(y.* == Y);
}

test "StackFallbackAllocator" {
    {
        var stack_allocator = stack_fallback(4096, std.testing.allocator);
        try test_allocator(stack_allocator.get());
    }
    {
        var stack_allocator = stack_fallback(4096, std.testing.allocator);
        try test_allocator_aligned(stack_allocator.get());
    }
    {
        var stack_allocator = stack_fallback(4096, std.testing.allocator);
        try test_allocator_large_alignment(stack_allocator.get());
    }
    {
        var stack_allocator = stack_fallback(4096, std.testing.allocator);
        try test_allocator_aligned_shrink(stack_allocator.get());
    }
}

test "FixedBufferAllocator Reuse memory on realloc" {
    var small_fixed_buffer: [10]u8 = undefined;
    // check if we re-use the memory
    {
        var fixed_buffer_allocator = FixedBufferAllocator.init(small_fixed_buffer[0..]);
        const allocator = fixed_buffer_allocator.allocator();

        const slice0 = try allocator.alloc(u8, 5);
        try testing.expect(slice0.len == 5);
        const slice1 = try allocator.realloc(slice0, 10);
        try testing.expect(slice1.ptr == slice0.ptr);
        try testing.expect(slice1.len == 10);
        try testing.expect_error(error.OutOfMemory, allocator.realloc(slice1, 11));
    }
    // check that we don't re-use the memory if it's not the most recent block
    {
        var fixed_buffer_allocator = FixedBufferAllocator.init(small_fixed_buffer[0..]);
        const allocator = fixed_buffer_allocator.allocator();

        var slice0 = try allocator.alloc(u8, 2);
        slice0[0] = 1;
        slice0[1] = 2;
        const slice1 = try allocator.alloc(u8, 2);
        const slice2 = try allocator.realloc(slice0, 4);
        try testing.expect(slice0.ptr != slice2.ptr);
        try testing.expect(slice1.ptr != slice2.ptr);
        try testing.expect(slice2[0] == 1);
        try testing.expect(slice2[1] == 2);
    }
}

test "Thread safe FixedBufferAllocator" {
    var fixed_buffer_allocator = FixedBufferAllocator.init(test_fixed_buffer_allocator_memory[0..]);

    try test_allocator(fixed_buffer_allocator.thread_safe_allocator());
    try test_allocator_aligned(fixed_buffer_allocator.thread_safe_allocator());
    try test_allocator_large_alignment(fixed_buffer_allocator.thread_safe_allocator());
    try test_allocator_aligned_shrink(fixed_buffer_allocator.thread_safe_allocator());
}

/// This one should not try alignments that exceed what C malloc can handle.
pub fn test_allocator(base_allocator: mem.Allocator) !void {
    var validationAllocator = mem.validation_wrap(base_allocator);
    const allocator = validationAllocator.allocator();

    var slice = try allocator.alloc(*i32, 100);
    try testing.expect(slice.len == 100);
    for (slice, 0..) |*item, i| {
        item.* = try allocator.create(i32);
        item.*.* = @as(i32, @int_cast(i));
    }

    slice = try allocator.realloc(slice, 20000);
    try testing.expect(slice.len == 20000);

    for (slice[0..100], 0..) |item, i| {
        try testing.expect(item.* == @as(i32, @int_cast(i)));
        allocator.destroy(item);
    }

    if (allocator.resize(slice, 50)) {
        slice = slice[0..50];
        if (allocator.resize(slice, 25)) {
            slice = slice[0..25];
            try testing.expect(allocator.resize(slice, 0));
            slice = slice[0..0];
            slice = try allocator.realloc(slice, 10);
            try testing.expect(slice.len == 10);
        }
    }
    allocator.free(slice);

    // Zero-length allocation
    const empty = try allocator.alloc(u8, 0);
    allocator.free(empty);
    // Allocation with zero-sized types
    const zero_bit_ptr = try allocator.create(u0);
    zero_bit_ptr.* = 0;
    allocator.destroy(zero_bit_ptr);

    const oversize = try allocator.aligned_alloc(u32, null, 5);
    try testing.expect(oversize.len >= 5);
    for (oversize) |*item| {
        item.* = 0xDEADBEEF;
    }
    allocator.free(oversize);
}

pub fn test_allocator_aligned(base_allocator: mem.Allocator) !void {
    var validationAllocator = mem.validation_wrap(base_allocator);
    const allocator = validationAllocator.allocator();

    // Test a few alignment values, smaller and bigger than the type's one
    inline for ([_]u29{ 1, 2, 4, 8, 16, 32, 64 }) |alignment| {
        // initial
        var slice = try allocator.aligned_alloc(u8, alignment, 10);
        try testing.expect(slice.len == 10);
        // grow
        slice = try allocator.realloc(slice, 100);
        try testing.expect(slice.len == 100);
        if (allocator.resize(slice, 10)) {
            slice = slice[0..10];
        }
        try testing.expect(allocator.resize(slice, 0));
        slice = slice[0..0];
        // realloc from zero
        slice = try allocator.realloc(slice, 100);
        try testing.expect(slice.len == 100);
        if (allocator.resize(slice, 10)) {
            slice = slice[0..10];
        }
        try testing.expect(allocator.resize(slice, 0));
    }
}

pub fn test_allocator_large_alignment(base_allocator: mem.Allocator) !void {
    var validationAllocator = mem.validation_wrap(base_allocator);
    const allocator = validationAllocator.allocator();

    const large_align: usize = mem.page_size / 2;

    var align_mask: usize = undefined;
    align_mask = @shl_with_overflow(~@as(usize, 0), @as(Allocator.Log2Align, @ctz(large_align)))[0];

    var slice = try allocator.aligned_alloc(u8, large_align, 500);
    try testing.expect(@int_from_ptr(slice.ptr) & align_mask == @int_from_ptr(slice.ptr));

    if (allocator.resize(slice, 100)) {
        slice = slice[0..100];
    }

    slice = try allocator.realloc(slice, 5000);
    try testing.expect(@int_from_ptr(slice.ptr) & align_mask == @int_from_ptr(slice.ptr));

    if (allocator.resize(slice, 10)) {
        slice = slice[0..10];
    }

    slice = try allocator.realloc(slice, 20000);
    try testing.expect(@int_from_ptr(slice.ptr) & align_mask == @int_from_ptr(slice.ptr));

    allocator.free(slice);
}

pub fn test_allocator_aligned_shrink(base_allocator: mem.Allocator) !void {
    var validationAllocator = mem.validation_wrap(base_allocator);
    const allocator = validationAllocator.allocator();

    var debug_buffer: [1000]u8 = undefined;
    var fib = FixedBufferAllocator.init(&debug_buffer);
    const debug_allocator = fib.allocator();

    const alloc_size = mem.page_size * 2 + 50;
    var slice = try allocator.aligned_alloc(u8, 16, alloc_size);
    defer allocator.free(slice);

    var stuff_to_free = std.ArrayList([]align(16) u8).init(debug_allocator);
    // On Windows, VirtualAlloc returns addresses aligned to a 64K boundary,
    // which is 16 pages, hence the 32. This test may require to increase
    // the size of the allocations feeding the `allocator` parameter if they
    // fail, because of this high over-alignment we want to have.
    while (@int_from_ptr(slice.ptr) == mem.align_forward(usize, @int_from_ptr(slice.ptr), mem.page_size * 32)) {
        try stuff_to_free.append(slice);
        slice = try allocator.aligned_alloc(u8, 16, alloc_size);
    }
    while (stuff_to_free.pop_or_null()) |item| {
        allocator.free(item);
    }
    slice[0] = 0x12;
    slice[60] = 0x34;

    slice = try allocator.realloc_advanced(slice, alloc_size / 2, 0);
    try testing.expect(slice[0] == 0x12);
    try testing.expect(slice[60] == 0x34);
}

test {
    _ = LoggingAllocator;
    _ = LogToWriterAllocator;
    _ = ScopedLoggingAllocator;
    _ = @import("heap/memory_pool.zig");
    _ = ArenaAllocator;
    _ = GeneralPurposeAllocator;
    if (comptime builtin.target.is_wasm()) {
        _ = WasmAllocator;
        _ = WasmPageAllocator;
    }
}
