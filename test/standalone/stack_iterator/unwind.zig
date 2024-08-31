const std = @import("std");
const builtin = @import("builtin");
const debug = std.debug;
const testing = std.testing;

noinline fn frame3(expected: *[4]usize, unwound: *[4]usize) void {
    expected[0] = @returnAddress();

    var context: debug.ThreadContext = undefined;
    testing.expect(debug.get_context(&context)) catch @panic("failed to get_context");

    const debug_info = debug.get_self_debug_info() catch @panic("failed to open_self_debug_info");
    var it = debug.StackIterator.init_with_context(expected[0], debug_info, &context) catch @panic("failed to init_with_context");
    defer it.deinit();

    for (unwound) |*addr| {
        if (it.next()) |return_address| addr.* = return_address;
    }
}

noinline fn frame2(expected: *[4]usize, unwound: *[4]usize) void {
    // Exercise different __unwind_info / DWARF CFI encodings by forcing some registers to be restored
    if (builtin.target.ofmt != .c) {
        switch (builtin.cpu.arch) {
            .x86 => {
                if (builtin.omit_frame_pointer) {
                    asm volatile (
                        \\movl $3, %%ebx
                        \\movl $1, %%ecx
                        \\movl $2, %%edx
                        \\movl $7, %%edi
                        \\movl $6, %%esi
                        \\movl $5, %%ebp
                        ::: "ebx", "ecx", "edx", "edi", "esi", "ebp");
                } else {
                    asm volatile (
                        \\movl $3, %%ebx
                        \\movl $1, %%ecx
                        \\movl $2, %%edx
                        \\movl $7, %%edi
                        \\movl $6, %%esi
                        ::: "ebx", "ecx", "edx", "edi", "esi");
                }
            },
            .x86_64 => {
                if (builtin.omit_frame_pointer) {
                    asm volatile (
                        \\movq $3, %%rbx
                        \\movq $12, %%r12
                        \\movq $13, %%r13
                        \\movq $14, %%r14
                        \\movq $15, %%r15
                        \\movq $6, %%rbp
                        ::: "rbx", "r12", "r13", "r14", "r15", "rbp");
                } else {
                    asm volatile (
                        \\movq $3, %%rbx
                        \\movq $12, %%r12
                        \\movq $13, %%r13
                        \\movq $14, %%r14
                        \\movq $15, %%r15
                        ::: "rbx", "r12", "r13", "r14", "r15");
                }
            },
            else => {},
        }
    }

    expected[1] = @returnAddress();
    frame3(expected, unwound);
}

noinline fn frame1(expected: *[4]usize, unwound: *[4]usize) void {
    expected[2] = @returnAddress();

    // Use a stack frame that is too big to encode in __unwind_info's stack-immediate encoding
    // to exercise the stack-indirect encoding path
    var pad: [std.math.max_int(u8) * @size_of(usize) + 1]u8 = undefined;
    _ = std.mem.do_not_optimize_away(&pad);

    frame2(expected, unwound);
}

noinline fn frame0(expected: *[4]usize, unwound: *[4]usize) void {
    expected[3] = @returnAddress();
    frame1(expected, unwound);
}

pub fn main() !void {
    // Disabled until the DWARF unwinder bugs on .aarch64 are solved
    if (builtin.omit_frame_pointer and comptime builtin.target.is_darwin() and builtin.cpu.arch == .aarch64) return;

    if (!std.debug.have_ucontext or !std.debug.have_getcontext) return;

    var expected: [4]usize = undefined;
    var unwound: [4]usize = undefined;
    frame0(&expected, &unwound);
    try testing.expect_equal(expected, unwound);
}
