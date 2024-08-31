const WasmPageAllocator = @This();
const std = @import("../std.zig");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const mem = std.mem;
const max_int = std.math.max_int;
const assert = std.debug.assert;

comptime {
    if (!builtin.target.is_wasm()) {
        @compile_error("WasmPageAllocator is only available for wasm32 arch");
    }
}

pub const vtable = Allocator.VTable{
    .alloc = alloc,
    .resize = resize,
    .free = free,
};

const PageStatus = enum(u1) {
    used = 0,
    free = 1,

    pub const none_free: u8 = 0;
};

const FreeBlock = struct {
    data: []u128,

    const Io = std.packed_int_array.PackedIntIo(u1, .little);

    fn total_pages(self: FreeBlock) usize {
        return self.data.len * 128;
    }

    fn is_initialized(self: FreeBlock) bool {
        return self.data.len > 0;
    }

    fn get_bit(self: FreeBlock, idx: usize) PageStatus {
        const bit_offset = 0;
        return @as(PageStatus, @enumFromInt(Io.get(mem.slice_as_bytes(self.data), idx, bit_offset)));
    }

    fn set_bits(self: FreeBlock, start_idx: usize, len: usize, val: PageStatus) void {
        const bit_offset = 0;
        var i: usize = 0;
        while (i < len) : (i += 1) {
            Io.set(mem.slice_as_bytes(self.data), start_idx + i, bit_offset, @int_from_enum(val));
        }
    }

    // Use '0xFFFFFFFF' as a _missing_ sentinel
    // This saves ~50 bytes compared to returning a nullable

    // We can guarantee that conventional memory never gets this big,
    // and wasm32 would not be able to address this memory (32 GB > usize).

    // Revisit if this is settled: https://github.com/ziglang/zig/issues/3806
    const not_found = max_int(usize);

    fn use_recycled(self: FreeBlock, num_pages: usize, log2_align: u8) usize {
        @setCold(true);
        for (self.data, 0..) |segment, i| {
            const spills_into_next = @as(i128, @bit_cast(segment)) < 0;
            const has_enough_bits = @pop_count(segment) >= num_pages;

            if (!spills_into_next and !has_enough_bits) continue;

            var j: usize = i * 128;
            while (j < (i + 1) * 128) : (j += 1) {
                var count: usize = 0;
                while (j + count < self.total_pages() and self.get_bit(j + count) == .free) {
                    count += 1;
                    const addr = j * mem.page_size;
                    if (count >= num_pages and mem.is_aligned_log2(addr, log2_align)) {
                        self.set_bits(j, num_pages, .used);
                        return j;
                    }
                }
                j += count;
            }
        }
        return not_found;
    }

    fn recycle(self: FreeBlock, start_idx: usize, len: usize) void {
        self.set_bits(start_idx, len, .free);
    }
};

var _conventional_data = [_]u128{0} ** 16;
// Marking `conventional` as const saves ~40 bytes
const conventional = FreeBlock{ .data = &_conventional_data };
var extended = FreeBlock{ .data = &[_]u128{} };

fn extended_offset() usize {
    return conventional.total_pages();
}

fn n_pages(memsize: usize) usize {
    return mem.align_forward(usize, memsize, mem.page_size) / mem.page_size;
}

fn alloc(ctx: *anyopaque, len: usize, log2_align: u8, ra: usize) ?[*]u8 {
    _ = ctx;
    _ = ra;
    if (len > max_int(usize) - (mem.page_size - 1)) return null;
    const page_count = n_pages(len);
    const page_idx = alloc_pages(page_count, log2_align) catch return null;
    return @as([*]u8, @ptrFromInt(page_idx * mem.page_size));
}

fn alloc_pages(page_count: usize, log2_align: u8) !usize {
    {
        const idx = conventional.use_recycled(page_count, log2_align);
        if (idx != FreeBlock.not_found) {
            return idx;
        }
    }

    const idx = extended.use_recycled(page_count, log2_align);
    if (idx != FreeBlock.not_found) {
        return idx + extended_offset();
    }

    const next_page_idx = @wasmMemorySize(0);
    const next_page_addr = next_page_idx * mem.page_size;
    const aligned_addr = mem.align_forward_log2(next_page_addr, log2_align);
    const drop_page_count = @div_exact(aligned_addr - next_page_addr, mem.page_size);
    const result = @wasmMemoryGrow(0, @as(u32, @int_cast(drop_page_count + page_count)));
    if (result <= 0)
        return error.OutOfMemory;
    assert(result == next_page_idx);
    const aligned_page_idx = next_page_idx + drop_page_count;
    if (drop_page_count > 0) {
        free_pages(next_page_idx, aligned_page_idx);
    }
    return @as(usize, @int_cast(aligned_page_idx));
}

fn free_pages(start: usize, end: usize) void {
    if (start < extended_offset()) {
        conventional.recycle(start, @min(extended_offset(), end) - start);
    }
    if (end > extended_offset()) {
        var new_end = end;
        if (!extended.is_initialized()) {
            // Steal the last page from the memory currently being recycled
            // TODO: would it be better if we use the first page instead?
            new_end -= 1;

            extended.data = @as([*]u128, @ptrFromInt(new_end * mem.page_size))[0 .. mem.page_size / @size_of(u128)];
            // Since this is the first page being freed and we consume it, assume *nothing* is free.
            @memset(extended.data, PageStatus.none_free);
        }
        const clamped_start = @max(extended_offset(), start);
        extended.recycle(clamped_start - extended_offset(), new_end - clamped_start);
    }
}

fn resize(
    ctx: *anyopaque,
    buf: []u8,
    log2_buf_align: u8,
    new_len: usize,
    return_address: usize,
) bool {
    _ = ctx;
    _ = log2_buf_align;
    _ = return_address;
    const aligned_len = mem.align_forward(usize, buf.len, mem.page_size);
    if (new_len > aligned_len) return false;
    const current_n = n_pages(aligned_len);
    const new_n = n_pages(new_len);
    if (new_n != current_n) {
        const base = n_pages(@int_from_ptr(buf.ptr));
        free_pages(base + new_n, base + current_n);
    }
    return true;
}

fn free(
    ctx: *anyopaque,
    buf: []u8,
    log2_buf_align: u8,
    return_address: usize,
) void {
    _ = ctx;
    _ = log2_buf_align;
    _ = return_address;
    const aligned_len = mem.align_forward(usize, buf.len, mem.page_size);
    const current_n = n_pages(aligned_len);
    const base = n_pages(@int_from_ptr(buf.ptr));
    free_pages(base, base + current_n);
}

test "internals" {
    const page_allocator = std.heap.page_allocator;
    const testing = std.testing;

    const conventional_memsize = WasmPageAllocator.conventional.total_pages() * mem.page_size;
    const initial = try page_allocator.alloc(u8, mem.page_size);
    try testing.expect(@int_from_ptr(initial.ptr) < conventional_memsize); // If this isn't conventional, the rest of these tests don't make sense. Also we have a serious memory leak in the test suite.

    var inplace = try page_allocator.realloc(initial, 1);
    try testing.expect_equal(initial.ptr, inplace.ptr);
    inplace = try page_allocator.realloc(inplace, 4);
    try testing.expect_equal(initial.ptr, inplace.ptr);
    page_allocator.free(inplace);

    const reuse = try page_allocator.alloc(u8, 1);
    try testing.expect_equal(initial.ptr, reuse.ptr);
    page_allocator.free(reuse);

    // This segment may span conventional and extended which has really complex rules so we're just ignoring it for now.
    const padding = try page_allocator.alloc(u8, conventional_memsize);
    page_allocator.free(padding);

    const ext = try page_allocator.alloc(u8, conventional_memsize);
    try testing.expect(@int_from_ptr(ext.ptr) >= conventional_memsize);

    const use_small = try page_allocator.alloc(u8, 1);
    try testing.expect_equal(initial.ptr, use_small.ptr);
    page_allocator.free(use_small);

    inplace = try page_allocator.realloc(ext, 1);
    try testing.expect_equal(ext.ptr, inplace.ptr);
    page_allocator.free(inplace);

    const reuse_extended = try page_allocator.alloc(u8, conventional_memsize);
    try testing.expect_equal(ext.ptr, reuse_extended.ptr);
    page_allocator.free(reuse_extended);
}
