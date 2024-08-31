const std = @import("std.zig");
const builtin = @import("builtin");
const math = std.math;
const mem = std.mem;
const io = std.io;
const posix = std.posix;
const fs = std.fs;
const testing = std.testing;
const elf = std.elf;
const DW = std.dwarf;
const macho = std.macho;
const coff = std.coff;
const pdb = std.pdb;
const root = @import("root");
const File = std.fs.File;
const windows = std.os.windows;
const native_arch = builtin.cpu.arch;
const native_os = builtin.os.tag;
const native_endian = native_arch.endian();

pub const runtime_safety = switch (builtin.mode) {
    .Debug, .ReleaseSafe => true,
    .ReleaseFast, .ReleaseSmall => false,
};

pub const sys_can_stack_trace = switch (builtin.cpu.arch) {
    // Observed to go into an infinite loop.
    // TODO: Make this work.
    .mips,
    .mipsel,
    => false,

    // `@returnAddress()` in LLVM 10 gives
    // "Non-Emscripten WebAssembly hasn't implemented __builtin_return_address".
    .wasm32,
    .wasm64,
    => native_os == .emscripten,

    // `@returnAddress()` is unsupported in LLVM 13.
    .bpfel,
    .bpfeb,
    => false,

    else => true,
};

pub const LineInfo = struct {
    line: u64,
    column: u64,
    file_name: []const u8,

    pub fn deinit(self: LineInfo, allocator: mem.Allocator) void {
        allocator.free(self.file_name);
    }
};

pub const SymbolInfo = struct {
    symbol_name: []const u8 = "???",
    compile_unit_name: []const u8 = "???",
    line_info: ?LineInfo = null,

    pub fn deinit(self: SymbolInfo, allocator: mem.Allocator) void {
        if (self.line_info) |li| {
            li.deinit(allocator);
        }
    }
};
const PdbOrDwarf = union(enum) {
    pdb: pdb.Pdb,
    dwarf: DW.DwarfInfo,

    fn deinit(self: *PdbOrDwarf, allocator: mem.Allocator) void {
        switch (self.*) {
            .pdb => |*inner| inner.deinit(),
            .dwarf => |*inner| inner.deinit(allocator),
        }
    }
};

/// Allows the caller to freely write to stderr until `unlock_std_err` is called.
///
/// During the lock, any `std.Progress` information is cleared from the terminal.
pub fn lock_std_err() void {
    std.Progress.lock_std_err();
}

pub fn unlock_std_err() void {
    std.Progress.unlock_std_err();
}

/// Print to stderr, unbuffered, and silently returning on failure. Intended
/// for use in "printf debugging." Use `std.log` functions for proper logging.
pub fn print(comptime fmt: []const u8, args: anytype) void {
    lock_std_err();
    defer unlock_std_err();
    const stderr = io.get_std_err().writer();
    nosuspend stderr.print(fmt, args) catch return;
}

pub fn get_stderr_mutex() *std.Thread.Mutex {
    @compile_error("deprecated. call std.debug.lock_std_err() and std.debug.unlock_std_err() instead which will integrate properly with std.Progress");
}

/// TODO multithreaded awareness
var self_debug_info: ?DebugInfo = null;

pub fn get_self_debug_info() !*DebugInfo {
    if (self_debug_info) |*info| {
        return info;
    } else {
        self_debug_info = try open_self_debug_info(get_debug_info_allocator());
        return &self_debug_info.?;
    }
}

/// Tries to print a hexadecimal view of the bytes, unbuffered, and ignores any error returned.
/// Obtains the stderr mutex while dumping.
pub fn dump_hex(bytes: []const u8) void {
    lock_std_err();
    defer unlock_std_err();
    dump_hex_fallible(bytes) catch {};
}

/// Prints a hexadecimal view of the bytes, unbuffered, returning any error that occurs.
pub fn dump_hex_fallible(bytes: []const u8) !void {
    const stderr = std.io.get_std_err();
    const ttyconf = std.io.tty.detect_config(stderr);
    const writer = stderr.writer();
    var chunks = mem.window(u8, bytes, 16, 16);
    while (chunks.next()) |window| {
        // 1. Print the address.
        const address = (@int_from_ptr(bytes.ptr) + 0x10 * (chunks.index orelse 0) / 16) - 0x10;
        try ttyconf.set_color(writer, .dim);
        // We print the address in lowercase and the bytes in uppercase hexadecimal to distinguish them more.
        // Also, make sure all lines are aligned by padding the address.
        try writer.print("{x:0>[1]}  ", .{ address, @size_of(usize) * 2 });
        try ttyconf.set_color(writer, .reset);

        // 2. Print the bytes.
        for (window, 0..) |byte, index| {
            try writer.print("{X:0>2} ", .{byte});
            if (index == 7) try writer.write_byte(' ');
        }
        try writer.write_byte(' ');
        if (window.len < 16) {
            var missing_columns = (16 - window.len) * 3;
            if (window.len < 8) missing_columns += 1;
            try writer.write_byte_ntimes(' ', missing_columns);
        }

        // 3. Print the characters.
        for (window) |byte| {
            if (std.ascii.is_print(byte)) {
                try writer.write_byte(byte);
            } else {
                // Related: https://github.com/ziglang/zig/issues/7600
                if (ttyconf == .windows_api) {
                    try writer.write_byte('.');
                    continue;
                }

                // Let's print some common control codes as graphical Unicode symbols.
                // We don't want to do this for all control codes because most control codes apart from
                // the ones that Zig has escape sequences for are likely not very useful to print as symbols.
                switch (byte) {
                    '\n' => try writer.write_all("␊"),
                    '\r' => try writer.write_all("␍"),
                    '\t' => try writer.write_all("␉"),
                    else => try writer.write_byte('.'),
                }
            }
        }
        try writer.write_byte('\n');
    }
}

/// Tries to print the current stack trace to stderr, unbuffered, and ignores any error returned.
/// TODO multithreaded awareness
pub fn dump_current_stack_trace(start_addr: ?usize) void {
    nosuspend {
        if (comptime builtin.target.is_wasm()) {
            if (native_os == .wasi) {
                const stderr = io.get_std_err().writer();
                stderr.print("Unable to dump stack trace: not implemented for Wasm\n", .{}) catch return;
            }
            return;
        }
        const stderr = io.get_std_err().writer();
        if (builtin.strip_debug_info) {
            stderr.print("Unable to dump stack trace: debug info stripped\n", .{}) catch return;
            return;
        }
        const debug_info = get_self_debug_info() catch |err| {
            stderr.print("Unable to dump stack trace: Unable to open debug info: {s}\n", .{@errorName(err)}) catch return;
            return;
        };
        write_current_stack_trace(stderr, debug_info, io.tty.detect_config(io.get_std_err()), start_addr) catch |err| {
            stderr.print("Unable to dump stack trace: {s}\n", .{@errorName(err)}) catch return;
            return;
        };
    }
}

pub const have_ucontext = @hasDecl(posix.system, "ucontext_t") and
    (native_os != .linux or switch (builtin.cpu.arch) {
    .mips, .mipsel, .mips64, .mips64el, .riscv64 => false,
    else => true,
});

/// Platform-specific thread state. This contains register state, and on some platforms
/// information about the stack. This is not safe to trivially copy, because some platforms
/// use internal pointers within this structure. To make a copy, use `copy_context`.
pub const ThreadContext = blk: {
    if (native_os == .windows) {
        break :blk windows.CONTEXT;
    } else if (have_ucontext) {
        break :blk posix.ucontext_t;
    } else {
        break :blk void;
    }
};

/// Copies one context to another, updating any internal pointers
pub fn copy_context(source: *const ThreadContext, dest: *ThreadContext) void {
    if (!have_ucontext) return {};
    dest.* = source.*;
    relocate_context(dest);
}

/// Updates any internal pointers in the context to reflect its current location
pub fn relocate_context(context: *ThreadContext) void {
    return switch (native_os) {
        .macos => {
            context.mcontext = &context.__mcontext_data;
        },
        else => {},
    };
}

pub const have_getcontext = native_os != .openbsd and native_os != .haiku and
    !builtin.target.is_android() and
    (native_os != .linux or switch (builtin.cpu.arch) {
    .x86,
    .x86_64,
    => true,
    else => builtin.link_libc and !builtin.target.is_musl(),
});

/// Capture the current context. The register values in the context will reflect the
/// state after the platform `getcontext` function returns.
///
/// It is valid to call this if the platform doesn't have context capturing support,
/// in that case false will be returned.
pub inline fn get_context(context: *ThreadContext) bool {
    if (native_os == .windows) {
        context.* = std.mem.zeroes(windows.CONTEXT);
        windows.ntdll.RtlCaptureContext(context);
        return true;
    }

    const result = have_getcontext and posix.system.getcontext(context) == 0;
    if (native_os == .macos) {
        assert(context.mcsize == @size_of(std.c.mcontext_t));

        // On aarch64-macos, the system getcontext doesn't write anything into the pc
        // register slot, it only writes lr. This makes the context consistent with
        // other aarch64 getcontext implementations which write the current lr
        // (where getcontext will return to) into both the lr and pc slot of the context.
        if (native_arch == .aarch64) context.mcontext.ss.pc = context.mcontext.ss.lr;
    }

    return result;
}

/// Tries to print the stack trace starting from the supplied base pointer to stderr,
/// unbuffered, and ignores any error returned.
/// TODO multithreaded awareness
pub fn dump_stack_trace_from_base(context: *const ThreadContext) void {
    nosuspend {
        if (comptime builtin.target.is_wasm()) {
            if (native_os == .wasi) {
                const stderr = io.get_std_err().writer();
                stderr.print("Unable to dump stack trace: not implemented for Wasm\n", .{}) catch return;
            }
            return;
        }
        const stderr = io.get_std_err().writer();
        if (builtin.strip_debug_info) {
            stderr.print("Unable to dump stack trace: debug info stripped\n", .{}) catch return;
            return;
        }
        const debug_info = get_self_debug_info() catch |err| {
            stderr.print("Unable to dump stack trace: Unable to open debug info: {s}\n", .{@errorName(err)}) catch return;
            return;
        };
        const tty_config = io.tty.detect_config(io.get_std_err());
        if (native_os == .windows) {
            // On x86_64 and aarch64, the stack will be unwound using RtlVirtualUnwind using the context
            // provided by the exception handler. On x86, RtlVirtualUnwind doesn't exist. Instead, a new backtrace
            // will be captured and frames prior to the exception will be filtered.
            // The caveat is that RtlCaptureStackBackTrace does not include the KiUserExceptionDispatcher frame,
            // which is where the IP in `context` points to, so it can't be used as start_addr.
            // Instead, start_addr is recovered from the stack.
            const start_addr = if (builtin.cpu.arch == .x86) @as(*const usize, @ptrFromInt(context.get_regs().bp + 4)).* else null;
            write_stack_trace_windows(stderr, debug_info, tty_config, context, start_addr) catch return;
            return;
        }

        var it = StackIterator.init_with_context(null, debug_info, context) catch return;
        defer it.deinit();
        print_source_at_address(debug_info, stderr, it.unwind_state.?.dwarf_context.pc, tty_config) catch return;

        while (it.next()) |return_address| {
            print_last_unwind_error(&it, debug_info, stderr, tty_config);

            // On arm64 macOS, the address of the last frame is 0x0 rather than 0x1 as on x86_64 macOS,
            // therefore, we do a check for `return_address == 0` before subtracting 1 from it to avoid
            // an overflow. We do not need to signal `StackIterator` as it will correctly detect this
            // condition on the subsequent iteration and return `null` thus terminating the loop.
            // same behaviour for x86-windows-msvc
            const address = if (return_address == 0) return_address else return_address - 1;
            print_source_at_address(debug_info, stderr, address, tty_config) catch return;
        } else print_last_unwind_error(&it, debug_info, stderr, tty_config);
    }
}

/// Returns a slice with the same pointer as addresses, with a potentially smaller len.
/// On Windows, when first_address is not null, we ask for at least 32 stack frames,
/// and then try to find the first address. If addresses.len is more than 32, we
/// capture that many stack frames exactly, and then look for the first address,
/// chopping off the irrelevant frames and shifting so that the returned addresses pointer
/// equals the passed in addresses pointer.
pub fn capture_stack_trace(first_address: ?usize, stack_trace: *std.builtin.StackTrace) void {
    if (native_os == .windows) {
        const addrs = stack_trace.instruction_addresses;
        const first_addr = first_address orelse {
            stack_trace.index = walk_stack_windows(addrs[0..], null);
            return;
        };
        var addr_buf_stack: [32]usize = undefined;
        const addr_buf = if (addr_buf_stack.len > addrs.len) addr_buf_stack[0..] else addrs;
        const n = walk_stack_windows(addr_buf[0..], null);
        const first_index = for (addr_buf[0..n], 0..) |addr, i| {
            if (addr == first_addr) {
                break i;
            }
        } else {
            stack_trace.index = 0;
            return;
        };
        const end_index = @min(first_index + addrs.len, n);
        const slice = addr_buf[first_index..end_index];
        // We use a for loop here because slice and addrs may alias.
        for (slice, 0..) |addr, i| {
            addrs[i] = addr;
        }
        stack_trace.index = slice.len;
    } else {
        // TODO: This should use the DWARF unwinder if .eh_frame_hdr is available (so that full debug info parsing isn't required).
        //       A new path for loading DebugInfo needs to be created which will only attempt to parse in-memory sections, because
        //       stopping to load other debug info (ie. source line info) from disk here is not required for unwinding.
        var it = StackIterator.init(first_address, null);
        defer it.deinit();
        for (stack_trace.instruction_addresses, 0..) |*addr, i| {
            addr.* = it.next() orelse {
                stack_trace.index = i;
                return;
            };
        }
        stack_trace.index = stack_trace.instruction_addresses.len;
    }
}

/// Tries to print a stack trace to stderr, unbuffered, and ignores any error returned.
/// TODO multithreaded awareness
pub fn dump_stack_trace(stack_trace: std.builtin.StackTrace) void {
    nosuspend {
        if (comptime builtin.target.is_wasm()) {
            if (native_os == .wasi) {
                const stderr = io.get_std_err().writer();
                stderr.print("Unable to dump stack trace: not implemented for Wasm\n", .{}) catch return;
            }
            return;
        }
        const stderr = io.get_std_err().writer();
        if (builtin.strip_debug_info) {
            stderr.print("Unable to dump stack trace: debug info stripped\n", .{}) catch return;
            return;
        }
        const debug_info = get_self_debug_info() catch |err| {
            stderr.print("Unable to dump stack trace: Unable to open debug info: {s}\n", .{@errorName(err)}) catch return;
            return;
        };
        write_stack_trace(stack_trace, stderr, get_debug_info_allocator(), debug_info, io.tty.detect_config(io.get_std_err())) catch |err| {
            stderr.print("Unable to dump stack trace: {s}\n", .{@errorName(err)}) catch return;
            return;
        };
    }
}

/// This function invokes undefined behavior when `ok` is `false`.
/// In Debug and ReleaseSafe modes, calls to this function are always
/// generated, and the `unreachable` statement triggers a panic.
/// In ReleaseFast and ReleaseSmall modes, calls to this function are
/// optimized away, and in fact the optimizer is able to use the assertion
/// in its heuristics.
/// Inside a test block, it is best to use the `std.testing` module rather
/// than this function, because this function may not detect a test failure
/// in ReleaseFast and ReleaseSmall mode. Outside of a test block, this assert
/// function is the correct function to use.
pub fn assert(ok: bool) void {
    if (!ok) unreachable; // assertion failure
}

pub fn panic(comptime format: []const u8, args: anytype) noreturn {
    @setCold(true);

    panic_extra(@errorReturnTrace(), @returnAddress(), format, args);
}

/// `panic_extra` is useful when you want to print out an `@errorReturnTrace`
/// and also print out some values.
pub fn panic_extra(
    trace: ?*std.builtin.StackTrace,
    ret_addr: ?usize,
    comptime format: []const u8,
    args: anytype,
) noreturn {
    @setCold(true);

    const size = 0x1000;
    const trunc_msg = "(msg truncated)";
    var buf: [size + trunc_msg.len]u8 = undefined;
    // a minor annoyance with this is that it will result in the NoSpaceLeft
    // error being part of the @panic stack trace (but that error should
    // only happen rarely)
    const msg = std.fmt.buf_print(buf[0..size], format, args) catch |err| switch (err) {
        error.NoSpaceLeft => blk: {
            @memcpy(buf[size..], trunc_msg);
            break :blk &buf;
        },
    };
    std.builtin.panic(msg, trace, ret_addr);
}

/// Non-zero whenever the program triggered a panic.
/// The counter is incremented/decremented atomically.
var panicking = std.atomic.Value(u8).init(0);

// Locked to avoid interleaving panic messages from multiple threads.
var panic_mutex = std.Thread.Mutex{};

/// Counts how many times the panic handler is invoked by this thread.
/// This is used to catch and handle panics triggered by the panic handler.
threadlocal var panic_stage: usize = 0;

// `panic_impl` could be useful in implementing a custom panic handler which
// calls the default handler (on supported platforms)
pub fn panic_impl(trace: ?*const std.builtin.StackTrace, first_trace_addr: ?usize, msg: []const u8) noreturn {
    @setCold(true);

    if (enable_segfault_handler) {
        // If a segfault happens while panicking, we want it to actually segfault, not trigger
        // the handler.
        reset_segfault_handler();
    }

    // Note there is similar logic in handle_segfault_posix and handle_segfault_windows_extra.
    nosuspend switch (panic_stage) {
        0 => {
            panic_stage = 1;

            _ = panicking.fetch_add(1, .seq_cst);

            // Make sure to release the mutex when done
            {
                panic_mutex.lock();
                defer panic_mutex.unlock();

                const stderr = io.get_std_err().writer();
                if (builtin.single_threaded) {
                    stderr.print("panic: ", .{}) catch posix.abort();
                } else {
                    const current_thread_id = std.Thread.get_current_id();
                    stderr.print("thread {} panic: ", .{current_thread_id}) catch posix.abort();
                }
                stderr.print("{s}\n", .{msg}) catch posix.abort();
                if (trace) |t| {
                    dump_stack_trace(t.*);
                }
                dump_current_stack_trace(first_trace_addr);
            }

            wait_for_other_thread_to_finish_panicking();
        },
        1 => {
            panic_stage = 2;

            // A panic happened while trying to print a previous panic message,
            // we're still holding the mutex but that's fine as we're going to
            // call abort()
            const stderr = io.get_std_err().writer();
            stderr.print("Panicked during a panic. Aborting.\n", .{}) catch posix.abort();
        },
        else => {
            // Panicked while printing "Panicked during a panic."
        },
    };

    posix.abort();
}

/// Must be called only after adding 1 to `panicking`. There are three callsites.
fn wait_for_other_thread_to_finish_panicking() void {
    if (panicking.fetch_sub(1, .seq_cst) != 1) {
        // Another thread is panicking, wait for the last one to finish
        // and call abort()
        if (builtin.single_threaded) unreachable;

        // Sleep forever without hammering the CPU
        var futex = std.atomic.Value(u32).init(0);
        while (true) std.Thread.Futex.wait(&futex, 0);
        unreachable;
    }
}

pub fn write_stack_trace(
    stack_trace: std.builtin.StackTrace,
    out_stream: anytype,
    allocator: mem.Allocator,
    debug_info: *DebugInfo,
    tty_config: io.tty.Config,
) !void {
    _ = allocator;
    if (builtin.strip_debug_info) return error.MissingDebugInfo;
    var frame_index: usize = 0;
    var frames_left: usize = @min(stack_trace.index, stack_trace.instruction_addresses.len);

    while (frames_left != 0) : ({
        frames_left -= 1;
        frame_index = (frame_index + 1) % stack_trace.instruction_addresses.len;
    }) {
        const return_address = stack_trace.instruction_addresses[frame_index];
        try print_source_at_address(debug_info, out_stream, return_address - 1, tty_config);
    }

    if (stack_trace.index > stack_trace.instruction_addresses.len) {
        const dropped_frames = stack_trace.index - stack_trace.instruction_addresses.len;

        tty_config.set_color(out_stream, .bold) catch {};
        try out_stream.print("({d} additional stack frames skipped...)\n", .{dropped_frames});
        tty_config.set_color(out_stream, .reset) catch {};
    }
}

pub const UnwindError = if (have_ucontext)
    @typeInfo(@typeInfo(@TypeOf(StackIterator.next_unwind)).Fn.return_type.?).ErrorUnion.error_set
else
    void;

pub const StackIterator = struct {
    // Skip every frame before this address is found.
    first_address: ?usize,
    // Last known value of the frame pointer register.
    fp: usize,

    // When DebugInfo and a register context is available, this iterator can unwind
    // stacks with frames that don't use a frame pointer (ie. -fomit-frame-pointer),
    // using DWARF and MachO unwind info.
    unwind_state: if (have_ucontext) ?struct {
        debug_info: *DebugInfo,
        dwarf_context: DW.UnwindContext,
        last_error: ?UnwindError = null,
        failed: bool = false,
    } else void = if (have_ucontext) null else {},

    pub fn init(first_address: ?usize, fp: ?usize) StackIterator {
        if (native_arch == .sparc64) {
            // Flush all the register windows on stack.
            asm volatile (
                \\ flushw
                ::: "memory");
        }

        return StackIterator{
            .first_address = first_address,
            // TODO: this is a workaround for #16876
            //.fp = fp orelse @frameAddress(),
            .fp = fp orelse blk: {
                const fa = @frameAddress();
                break :blk fa;
            },
        };
    }

    pub fn init_with_context(first_address: ?usize, debug_info: *DebugInfo, context: *const posix.ucontext_t) !StackIterator {
        // The implementation of DWARF unwinding on aarch64-macos is not complete. However, Apple mandates that
        // the frame pointer register is always used, so on this platform we can safely use the FP-based unwinder.
        if (comptime builtin.target.is_darwin() and native_arch == .aarch64) {
            return init(first_address, context.mcontext.ss.fp);
        } else {
            var iterator = init(first_address, null);
            iterator.unwind_state = .{
                .debug_info = debug_info,
                .dwarf_context = try DW.UnwindContext.init(debug_info.allocator, context, &is_valid_memory),
            };

            return iterator;
        }
    }

    pub fn deinit(self: *StackIterator) void {
        if (have_ucontext and self.unwind_state != null) self.unwind_state.?.dwarf_context.deinit();
    }

    pub fn get_last_error(self: *StackIterator) ?struct {
        err: UnwindError,
        address: usize,
    } {
        if (!have_ucontext) return null;
        if (self.unwind_state) |*unwind_state| {
            if (unwind_state.last_error) |err| {
                unwind_state.last_error = null;
                return .{
                    .err = err,
                    .address = unwind_state.dwarf_context.pc,
                };
            }
        }

        return null;
    }

    // Offset of the saved BP wrt the frame pointer.
    const fp_offset = if (native_arch.is_riscv())
        // On RISC-V the frame pointer points to the top of the saved register
        // area, on pretty much every other architecture it points to the stack
        // slot where the previous frame pointer is saved.
        2 * @size_of(usize)
    else if (native_arch.is_sparc())
        // On SPARC the previous frame pointer is stored at 14 slots past %fp+BIAS.
        14 * @size_of(usize)
    else
        0;

    const fp_bias = if (native_arch.is_sparc())
        // On SPARC frame pointers are biased by a constant.
        2047
    else
        0;

    // Positive offset of the saved PC wrt the frame pointer.
    const pc_offset = if (native_arch == .powerpc64le)
        2 * @size_of(usize)
    else
        @size_of(usize);

    pub fn next(self: *StackIterator) ?usize {
        var address = self.next_internal() orelse return null;

        if (self.first_address) |first_address| {
            while (address != first_address) {
                address = self.next_internal() orelse return null;
            }
            self.first_address = null;
        }

        return address;
    }

    fn is_valid_memory(address: usize) bool {
        // We are unable to determine validity of memory for freestanding targets
        if (native_os == .freestanding or native_os == .uefi) return true;

        const aligned_address = address & ~@as(usize, @int_cast((mem.page_size - 1)));
        if (aligned_address == 0) return false;
        const aligned_memory = @as([*]align(mem.page_size) u8, @ptrFromInt(aligned_address))[0..mem.page_size];

        if (native_os == .windows) {
            var memory_info: windows.MEMORY_BASIC_INFORMATION = undefined;

            // The only error this function can throw is ERROR_INVALID_PARAMETER.
            // supply an address that invalid i'll be thrown.
            const rc = windows.VirtualQuery(aligned_memory, &memory_info, aligned_memory.len) catch {
                return false;
            };

            // Result code has to be bigger than zero (number of bytes written)
            if (rc == 0) {
                return false;
            }

            // Free pages cannot be read, they are unmapped
            if (memory_info.State == windows.MEM_FREE) {
                return false;
            }

            return true;
        } else if (@hasDecl(posix.system, "msync") and native_os != .wasi and native_os != .emscripten) {
            posix.msync(aligned_memory, posix.MSF.ASYNC) catch |err| {
                switch (err) {
                    error.UnmappedMemory => return false,
                    else => unreachable,
                }
            };

            return true;
        } else {
            // We are unable to determine validity of memory on this target.
            return true;
        }
    }

    fn next_unwind(self: *StackIterator) !usize {
        const unwind_state = &self.unwind_state.?;
        const module = try unwind_state.debug_info.get_module_for_address(unwind_state.dwarf_context.pc);
        switch (native_os) {
            .macos, .ios, .watchos, .tvos, .visionos => {
                // __unwind_info is a requirement for unwinding on Darwin. It may fall back to DWARF, but unwinding
                // via DWARF before attempting to use the compact unwind info will produce incorrect results.
                if (module.unwind_info) |unwind_info| {
                    if (DW.unwind_frame_mach_o(&unwind_state.dwarf_context, unwind_info, module.eh_frame, module.base_address)) |return_address| {
                        return return_address;
                    } else |err| {
                        if (err != error.RequiresDWARFUnwind) return err;
                    }
                } else return error.MissingUnwindInfo;
            },
            else => {},
        }

        if (try module.get_dwarf_info_for_address(unwind_state.debug_info.allocator, unwind_state.dwarf_context.pc)) |di| {
            return di.unwind_frame(&unwind_state.dwarf_context, null);
        } else return error.MissingDebugInfo;
    }

    fn next_internal(self: *StackIterator) ?usize {
        if (have_ucontext) {
            if (self.unwind_state) |*unwind_state| {
                if (!unwind_state.failed) {
                    if (unwind_state.dwarf_context.pc == 0) return null;
                    defer self.fp = unwind_state.dwarf_context.get_fp() catch 0;
                    if (self.next_unwind()) |return_address| {
                        return return_address;
                    } else |err| {
                        unwind_state.last_error = err;
                        unwind_state.failed = true;

                        // Fall back to fp-based unwinding on the first failure.
                        // We can't attempt it again for other modules higher in the
                        // stack because the full register state won't have been unwound.
                    }
                }
            }
        }

        const fp = if (comptime native_arch.is_sparc())
            // On SPARC the offset is positive. (!)
            math.add(usize, self.fp, fp_offset) catch return null
        else
            math.sub(usize, self.fp, fp_offset) catch return null;

        // Sanity check.
        if (fp == 0 or !mem.is_aligned(fp, @alignOf(usize)) or !is_valid_memory(fp))
            return null;

        const new_fp = math.add(usize, @as(*const usize, @ptrFromInt(fp)).*, fp_bias) catch return null;

        // Sanity check: the stack grows down thus all the parent frames must be
        // be at addresses that are greater (or equal) than the previous one.
        // A zero frame pointer often signals this is the last frame, that case
        // is gracefully handled by the next call to next_internal.
        if (new_fp != 0 and new_fp < self.fp)
            return null;

        const new_pc = @as(
            *const usize,
            @ptrFromInt(math.add(usize, fp, pc_offset) catch return null),
        ).*;

        self.fp = new_fp;

        return new_pc;
    }
};

pub fn write_current_stack_trace(
    out_stream: anytype,
    debug_info: *DebugInfo,
    tty_config: io.tty.Config,
    start_addr: ?usize,
) !void {
    var context: ThreadContext = undefined;
    const has_context = get_context(&context);
    if (native_os == .windows) {
        return write_stack_trace_windows(out_stream, debug_info, tty_config, &context, start_addr);
    }

    var it = (if (has_context) blk: {
        break :blk StackIterator.init_with_context(start_addr, debug_info, &context) catch null;
    } else null) orelse StackIterator.init(start_addr, null);
    defer it.deinit();

    while (it.next()) |return_address| {
        print_last_unwind_error(&it, debug_info, out_stream, tty_config);

        // On arm64 macOS, the address of the last frame is 0x0 rather than 0x1 as on x86_64 macOS,
        // therefore, we do a check for `return_address == 0` before subtracting 1 from it to avoid
        // an overflow. We do not need to signal `StackIterator` as it will correctly detect this
        // condition on the subsequent iteration and return `null` thus terminating the loop.
        // same behaviour for x86-windows-msvc
        const address = if (return_address == 0) return_address else return_address - 1;
        try print_source_at_address(debug_info, out_stream, address, tty_config);
    } else print_last_unwind_error(&it, debug_info, out_stream, tty_config);
}

pub noinline fn walk_stack_windows(addresses: []usize, existing_context: ?*const windows.CONTEXT) usize {
    if (builtin.cpu.arch == .x86) {
        // RtlVirtualUnwind doesn't exist on x86
        return windows.ntdll.RtlCaptureStackBackTrace(0, addresses.len, @as(**anyopaque, @ptr_cast(addresses.ptr)), null);
    }

    const tib = &windows.teb().NtTib;

    var context: windows.CONTEXT = undefined;
    if (existing_context) |context_ptr| {
        context = context_ptr.*;
    } else {
        context = std.mem.zeroes(windows.CONTEXT);
        windows.ntdll.RtlCaptureContext(&context);
    }

    var i: usize = 0;
    var image_base: usize = undefined;
    var history_table: windows.UNWIND_HISTORY_TABLE = std.mem.zeroes(windows.UNWIND_HISTORY_TABLE);

    while (i < addresses.len) : (i += 1) {
        const current_regs = context.get_regs();
        if (windows.ntdll.RtlLookupFunctionEntry(current_regs.ip, &image_base, &history_table)) |runtime_function| {
            var handler_data: ?*anyopaque = null;
            var establisher_frame: u64 = undefined;
            _ = windows.ntdll.RtlVirtualUnwind(
                windows.UNW_FLAG_NHANDLER,
                image_base,
                current_regs.ip,
                runtime_function,
                &context,
                &handler_data,
                &establisher_frame,
                null,
            );
        } else {
            // leaf function
            context.set_ip(@as(*u64, @ptrFromInt(current_regs.sp)).*);
            context.set_sp(current_regs.sp + @size_of(usize));
        }

        const next_regs = context.get_regs();
        if (next_regs.sp < @int_from_ptr(tib.StackLimit) or next_regs.sp > @int_from_ptr(tib.StackBase)) {
            break;
        }

        if (next_regs.ip == 0) {
            break;
        }

        addresses[i] = next_regs.ip;
    }

    return i;
}

pub fn write_stack_trace_windows(
    out_stream: anytype,
    debug_info: *DebugInfo,
    tty_config: io.tty.Config,
    context: *const windows.CONTEXT,
    start_addr: ?usize,
) !void {
    var addr_buf: [1024]usize = undefined;
    const n = walk_stack_windows(addr_buf[0..], context);
    const addrs = addr_buf[0..n];
    const start_i: usize = if (start_addr) |saddr| blk: {
        for (addrs, 0..) |addr, i| {
            if (addr == saddr) break :blk i;
        }
        return;
    } else 0;
    for (addrs[start_i..]) |addr| {
        try print_source_at_address(debug_info, out_stream, addr - 1, tty_config);
    }
}

fn macho_search_symbols(symbols: []const MachoSymbol, address: usize) ?*const MachoSymbol {
    var min: usize = 0;
    var max: usize = symbols.len - 1;
    while (min < max) {
        const mid = min + (max - min) / 2;
        const curr = &symbols[mid];
        const next = &symbols[mid + 1];
        if (address >= next.address()) {
            min = mid + 1;
        } else if (address < curr.address()) {
            max = mid;
        } else {
            return curr;
        }
    }

    const max_sym = &symbols[symbols.len - 1];
    if (address >= max_sym.address())
        return max_sym;

    return null;
}

test macho_search_symbols {
    const symbols = [_]MachoSymbol{
        .{ .addr = 100, .strx = undefined, .size = undefined, .ofile = undefined },
        .{ .addr = 200, .strx = undefined, .size = undefined, .ofile = undefined },
        .{ .addr = 300, .strx = undefined, .size = undefined, .ofile = undefined },
    };

    try testing.expect_equal(null, macho_search_symbols(&symbols, 0));
    try testing.expect_equal(null, macho_search_symbols(&symbols, 99));
    try testing.expect_equal(&symbols[0], macho_search_symbols(&symbols, 100).?);
    try testing.expect_equal(&symbols[0], macho_search_symbols(&symbols, 150).?);
    try testing.expect_equal(&symbols[0], macho_search_symbols(&symbols, 199).?);

    try testing.expect_equal(&symbols[1], macho_search_symbols(&symbols, 200).?);
    try testing.expect_equal(&symbols[1], macho_search_symbols(&symbols, 250).?);
    try testing.expect_equal(&symbols[1], macho_search_symbols(&symbols, 299).?);

    try testing.expect_equal(&symbols[2], macho_search_symbols(&symbols, 300).?);
    try testing.expect_equal(&symbols[2], macho_search_symbols(&symbols, 301).?);
    try testing.expect_equal(&symbols[2], macho_search_symbols(&symbols, 5000).?);
}

fn print_unknown_source(debug_info: *DebugInfo, out_stream: anytype, address: usize, tty_config: io.tty.Config) !void {
    const module_name = debug_info.get_module_name_for_address(address);
    return print_line_info(
        out_stream,
        null,
        address,
        "???",
        module_name orelse "???",
        tty_config,
        print_line_from_file_any_os,
    );
}

fn print_last_unwind_error(it: *StackIterator, debug_info: *DebugInfo, out_stream: anytype, tty_config: io.tty.Config) void {
    if (!have_ucontext) return;
    if (it.get_last_error()) |unwind_error| {
        print_unwind_error(debug_info, out_stream, unwind_error.address, unwind_error.err, tty_config) catch {};
    }
}

fn print_unwind_error(debug_info: *DebugInfo, out_stream: anytype, address: usize, err: UnwindError, tty_config: io.tty.Config) !void {
    const module_name = debug_info.get_module_name_for_address(address) orelse "???";
    try tty_config.set_color(out_stream, .dim);
    if (err == error.MissingDebugInfo) {
        try out_stream.print("Unwind information for `{s}:0x{x}` was not available, trace may be incomplete\n\n", .{ module_name, address });
    } else {
        try out_stream.print("Unwind error at address `{s}:0x{x}` ({}), trace may be incomplete\n\n", .{ module_name, address, err });
    }
    try tty_config.set_color(out_stream, .reset);
}

pub fn print_source_at_address(debug_info: *DebugInfo, out_stream: anytype, address: usize, tty_config: io.tty.Config) !void {
    const module = debug_info.get_module_for_address(address) catch |err| switch (err) {
        error.MissingDebugInfo, error.InvalidDebugInfo => return print_unknown_source(debug_info, out_stream, address, tty_config),
        else => return err,
    };

    const symbol_info = module.get_symbol_at_address(debug_info.allocator, address) catch |err| switch (err) {
        error.MissingDebugInfo, error.InvalidDebugInfo => return print_unknown_source(debug_info, out_stream, address, tty_config),
        else => return err,
    };
    defer symbol_info.deinit(debug_info.allocator);

    return print_line_info(
        out_stream,
        symbol_info.line_info,
        address,
        symbol_info.symbol_name,
        symbol_info.compile_unit_name,
        tty_config,
        print_line_from_file_any_os,
    );
}

fn print_line_info(
    out_stream: anytype,
    line_info: ?LineInfo,
    address: usize,
    symbol_name: []const u8,
    compile_unit_name: []const u8,
    tty_config: io.tty.Config,
    comptime printLineFromFile: anytype,
) !void {
    nosuspend {
        try tty_config.set_color(out_stream, .bold);

        if (line_info) |*li| {
            try out_stream.print("{s}:{d}:{d}", .{ li.file_name, li.line, li.column });
        } else {
            try out_stream.write_all("???:?:?");
        }

        try tty_config.set_color(out_stream, .reset);
        try out_stream.write_all(": ");
        try tty_config.set_color(out_stream, .dim);
        try out_stream.print("0x{x} in {s} ({s})", .{ address, symbol_name, compile_unit_name });
        try tty_config.set_color(out_stream, .reset);
        try out_stream.write_all("\n");

        // Show the matching source code line if possible
        if (line_info) |li| {
            if (printLineFromFile(out_stream, li)) {
                if (li.column > 0) {
                    // The caret already takes one char
                    const space_needed = @as(usize, @int_cast(li.column - 1));

                    try out_stream.write_byte_ntimes(' ', space_needed);
                    try tty_config.set_color(out_stream, .green);
                    try out_stream.write_all("^");
                    try tty_config.set_color(out_stream, .reset);
                }
                try out_stream.write_all("\n");
            } else |err| switch (err) {
                error.EndOfFile, error.FileNotFound => {},
                error.BadPathName => {},
                error.AccessDenied => {},
                else => return err,
            }
        }
    }
}

pub const OpenSelfDebugInfoError = error{
    MissingDebugInfo,
    UnsupportedOperatingSystem,
} || @typeInfo(@typeInfo(@TypeOf(DebugInfo.init)).Fn.return_type.?).ErrorUnion.error_set;

pub fn open_self_debug_info(allocator: mem.Allocator) OpenSelfDebugInfoError!DebugInfo {
    nosuspend {
        if (builtin.strip_debug_info)
            return error.MissingDebugInfo;
        if (@hasDecl(root, "os") and @hasDecl(root.os, "debug") and @hasDecl(root.os.debug, "open_self_debug_info")) {
            return root.os.debug.open_self_debug_info(allocator);
        }
        switch (native_os) {
            .linux,
            .freebsd,
            .netbsd,
            .dragonfly,
            .openbsd,
            .macos,
            .solaris,
            .illumos,
            .windows,
            => return try DebugInfo.init(allocator),
            else => return error.UnsupportedOperatingSystem,
        }
    }
}

fn read_coff_debug_info(allocator: mem.Allocator, coff_obj: *coff.Coff) !ModuleDebugInfo {
    nosuspend {
        var di = ModuleDebugInfo{
            .base_address = undefined,
            .coff_image_base = coff_obj.get_image_base(),
            .coff_section_headers = undefined,
        };

        if (coff_obj.get_section_by_name(".debug_info")) |_| {
            // This coff file has embedded DWARF debug info
            var sections: DW.DwarfInfo.SectionArray = DW.DwarfInfo.null_section_array;
            errdefer for (sections) |section| if (section) |s| if (s.owned) allocator.free(s.data);

            inline for (@typeInfo(DW.DwarfSection).Enum.fields, 0..) |section, i| {
                sections[i] = if (coff_obj.get_section_by_name("." ++ section.name)) |section_header| blk: {
                    break :blk .{
                        .data = try coff_obj.get_section_data_alloc(section_header, allocator),
                        .virtual_address = section_header.virtual_address,
                        .owned = true,
                    };
                } else null;
            }

            var dwarf = DW.DwarfInfo{
                .endian = native_endian,
                .sections = sections,
                .is_macho = false,
            };

            try DW.open_dwarf_debug_info(&dwarf, allocator);
            di.dwarf = dwarf;
        }

        const raw_path = try coff_obj.get_pdb_path() orelse return di;
        const path = blk: {
            if (fs.path.is_absolute(raw_path)) {
                break :blk raw_path;
            } else {
                const self_dir = try fs.self_exe_dir_path_alloc(allocator);
                defer allocator.free(self_dir);
                break :blk try fs.path.join(allocator, &.{ self_dir, raw_path });
            }
        };
        defer if (path.ptr != raw_path.ptr) allocator.free(path);

        di.pdb = pdb.Pdb.init(allocator, path) catch |err| switch (err) {
            error.FileNotFound, error.IsDir => {
                if (di.dwarf == null) return error.MissingDebugInfo;
                return di;
            },
            else => return err,
        };
        try di.pdb.?.parse_info_stream();
        try di.pdb.?.parse_dbi_stream();

        if (!mem.eql(u8, &coff_obj.guid, &di.pdb.?.guid) or coff_obj.age != di.pdb.?.age)
            return error.InvalidDebugInfo;

        // Only used by the pdb path
        di.coff_section_headers = try coff_obj.get_section_headers_alloc(allocator);
        errdefer allocator.free(di.coff_section_headers);

        return di;
    }
}

fn chop_slice(ptr: []const u8, offset: u64, size: u64) error{Overflow}![]const u8 {
    const start = math.cast(usize, offset) orelse return error.Overflow;
    const end = start + (math.cast(usize, size) orelse return error.Overflow);
    return ptr[start..end];
}

/// Reads debug info from an ELF file, or the current binary if none in specified.
/// If the required sections aren't present but a reference to external debug info is,
/// then this this function will recurse to attempt to load the debug sections from
/// an external file.
pub fn read_elf_debug_info(
    allocator: mem.Allocator,
    elf_filename: ?[]const u8,
    build_id: ?[]const u8,
    expected_crc: ?u32,
    parent_sections: *DW.DwarfInfo.SectionArray,
    parent_mapped_mem: ?[]align(mem.page_size) const u8,
) !ModuleDebugInfo {
    nosuspend {
        const elf_file = (if (elf_filename) |filename| blk: {
            break :blk fs.cwd().open_file(filename, .{});
        } else fs.open_self_exe(.{})) catch |err| switch (err) {
            error.FileNotFound => return error.MissingDebugInfo,
            else => return err,
        };

        const mapped_mem = try map_whole_file(elf_file);
        if (expected_crc) |crc| if (crc != std.hash.crc.Crc32.hash(mapped_mem)) return error.InvalidDebugInfo;

        const hdr: *const elf.Ehdr = @ptr_cast(&mapped_mem[0]);
        if (!mem.eql(u8, hdr.e_ident[0..4], elf.MAGIC)) return error.InvalidElfMagic;
        if (hdr.e_ident[elf.EI_VERSION] != 1) return error.InvalidElfVersion;

        const endian: std.builtin.Endian = switch (hdr.e_ident[elf.EI_DATA]) {
            elf.ELFDATA2LSB => .little,
            elf.ELFDATA2MSB => .big,
            else => return error.InvalidElfEndian,
        };
        assert(endian == native_endian); // this is our own debug info

        const shoff = hdr.e_shoff;
        const str_section_off = shoff + @as(u64, hdr.e_shentsize) * @as(u64, hdr.e_shstrndx);
        const str_shdr: *const elf.Shdr = @ptr_cast(@align_cast(&mapped_mem[math.cast(usize, str_section_off) orelse return error.Overflow]));
        const header_strings = mapped_mem[str_shdr.sh_offset..][0..str_shdr.sh_size];
        const shdrs = @as(
            [*]const elf.Shdr,
            @ptr_cast(@align_cast(&mapped_mem[shoff])),
        )[0..hdr.e_shnum];

        var sections: DW.DwarfInfo.SectionArray = DW.DwarfInfo.null_section_array;

        // Combine section list. This takes ownership over any owned sections from the parent scope.
        for (parent_sections, &sections) |*parent, *section| {
            if (parent.*) |*p| {
                section.* = p.*;
                p.owned = false;
            }
        }
        errdefer for (sections) |section| if (section) |s| if (s.owned) allocator.free(s.data);

        var separate_debug_filename: ?[]const u8 = null;
        var separate_debug_crc: ?u32 = null;

        for (shdrs) |*shdr| {
            if (shdr.sh_type == elf.SHT_NULL or shdr.sh_type == elf.SHT_NOBITS) continue;
            const name = mem.slice_to(header_strings[shdr.sh_name..], 0);

            if (mem.eql(u8, name, ".gnu_debuglink")) {
                const gnu_debuglink = try chop_slice(mapped_mem, shdr.sh_offset, shdr.sh_size);
                const debug_filename = mem.slice_to(@as([*:0]const u8, @ptr_cast(gnu_debuglink.ptr)), 0);
                const crc_offset = mem.align_forward(usize, @int_from_ptr(&debug_filename[debug_filename.len]) + 1, 4) - @int_from_ptr(gnu_debuglink.ptr);
                const crc_bytes = gnu_debuglink[crc_offset..][0..4];
                separate_debug_crc = mem.read_int(u32, crc_bytes, native_endian);
                separate_debug_filename = debug_filename;
                continue;
            }

            var section_index: ?usize = null;
            inline for (@typeInfo(DW.DwarfSection).Enum.fields, 0..) |section, i| {
                if (mem.eql(u8, "." ++ section.name, name)) section_index = i;
            }
            if (section_index == null) continue;
            if (sections[section_index.?] != null) continue;

            const section_bytes = try chop_slice(mapped_mem, shdr.sh_offset, shdr.sh_size);
            sections[section_index.?] = if ((shdr.sh_flags & elf.SHF_COMPRESSED) > 0) blk: {
                var section_stream = io.fixed_buffer_stream(section_bytes);
                var section_reader = section_stream.reader();
                const chdr = section_reader.read_struct(elf.Chdr) catch continue;
                if (chdr.ch_type != .ZLIB) continue;

                var zlib_stream = std.compress.zlib.decompressor(section_stream.reader());

                const decompressed_section = try allocator.alloc(u8, chdr.ch_size);
                errdefer allocator.free(decompressed_section);

                const read = zlib_stream.reader().read_all(decompressed_section) catch continue;
                assert(read == decompressed_section.len);

                break :blk .{
                    .data = decompressed_section,
                    .virtual_address = shdr.sh_addr,
                    .owned = true,
                };
            } else .{
                .data = section_bytes,
                .virtual_address = shdr.sh_addr,
                .owned = false,
            };
        }

        const missing_debug_info =
            sections[@int_from_enum(DW.DwarfSection.debug_info)] == null or
            sections[@int_from_enum(DW.DwarfSection.debug_abbrev)] == null or
            sections[@int_from_enum(DW.DwarfSection.debug_str)] == null or
            sections[@int_from_enum(DW.DwarfSection.debug_line)] == null;

        // Attempt to load debug info from an external file
        // See: https://sourceware.org/gdb/onlinedocs/gdb/Separate-Debug-Files.html
        if (missing_debug_info) {

            // Only allow one level of debug info nesting
            if (parent_mapped_mem) |_| {
                return error.MissingDebugInfo;
            }

            const global_debug_directories = [_][]const u8{
                "/usr/lib/debug",
            };

            // <global debug directory>/.build-id/<2-character id prefix>/<id remainder>.debug
            if (build_id) |id| blk: {
                if (id.len < 3) break :blk;

                // Either md5 (16 bytes) or sha1 (20 bytes) are used here in practice
                const extension = ".debug";
                var id_prefix_buf: [2]u8 = undefined;
                var filename_buf: [38 + extension.len]u8 = undefined;

                _ = std.fmt.buf_print(&id_prefix_buf, "{s}", .{std.fmt.fmt_slice_hex_lower(id[0..1])}) catch unreachable;
                const filename = std.fmt.buf_print(
                    &filename_buf,
                    "{s}" ++ extension,
                    .{std.fmt.fmt_slice_hex_lower(id[1..])},
                ) catch break :blk;

                for (global_debug_directories) |global_directory| {
                    const path = try fs.path.join(allocator, &.{ global_directory, ".build-id", &id_prefix_buf, filename });
                    defer allocator.free(path);

                    return read_elf_debug_info(allocator, path, null, separate_debug_crc, &sections, mapped_mem) catch continue;
                }
            }

            // use the path from .gnu_debuglink, in the same search order as gdb
            if (separate_debug_filename) |separate_filename| blk: {
                if (elf_filename != null and mem.eql(u8, elf_filename.?, separate_filename)) return error.MissingDebugInfo;

                // <cwd>/<gnu_debuglink>
                if (read_elf_debug_info(allocator, separate_filename, null, separate_debug_crc, &sections, mapped_mem)) |debug_info| return debug_info else |_| {}

                // <cwd>/.debug/<gnu_debuglink>
                {
                    const path = try fs.path.join(allocator, &.{ ".debug", separate_filename });
                    defer allocator.free(path);

                    if (read_elf_debug_info(allocator, path, null, separate_debug_crc, &sections, mapped_mem)) |debug_info| return debug_info else |_| {}
                }

                var cwd_buf: [fs.MAX_PATH_BYTES]u8 = undefined;
                const cwd_path = posix.realpath(".", &cwd_buf) catch break :blk;

                // <global debug directory>/<absolute folder of current binary>/<gnu_debuglink>
                for (global_debug_directories) |global_directory| {
                    const path = try fs.path.join(allocator, &.{ global_directory, cwd_path, separate_filename });
                    defer allocator.free(path);
                    if (read_elf_debug_info(allocator, path, null, separate_debug_crc, &sections, mapped_mem)) |debug_info| return debug_info else |_| {}
                }
            }

            return error.MissingDebugInfo;
        }

        var di = DW.DwarfInfo{
            .endian = endian,
            .sections = sections,
            .is_macho = false,
        };

        try DW.open_dwarf_debug_info(&di, allocator);

        return ModuleDebugInfo{
            .base_address = undefined,
            .dwarf = di,
            .mapped_memory = parent_mapped_mem orelse mapped_mem,
            .external_mapped_memory = if (parent_mapped_mem != null) mapped_mem else null,
        };
    }
}

/// This takes ownership of macho_file: users of this function should not close
/// it themselves, even on error.
/// TODO it's weird to take ownership even on error, rework this code.
fn read_mach_odebug_info(allocator: mem.Allocator, macho_file: File) !ModuleDebugInfo {
    const mapped_mem = try map_whole_file(macho_file);

    const hdr: *const macho.mach_header_64 = @ptr_cast(@align_cast(mapped_mem.ptr));
    if (hdr.magic != macho.MH_MAGIC_64)
        return error.InvalidDebugInfo;

    var it = macho.LoadCommandIterator{
        .ncmds = hdr.ncmds,
        .buffer = mapped_mem[@size_of(macho.mach_header_64)..][0..hdr.sizeofcmds],
    };
    const symtab = while (it.next()) |cmd| switch (cmd.cmd()) {
        .SYMTAB => break cmd.cast(macho.symtab_command).?,
        else => {},
    } else return error.MissingDebugInfo;

    const syms = @as(
        [*]const macho.nlist_64,
        @ptr_cast(@align_cast(&mapped_mem[symtab.symoff])),
    )[0..symtab.nsyms];
    const strings = mapped_mem[symtab.stroff..][0 .. symtab.strsize - 1 :0];

    const symbols_buf = try allocator.alloc(MachoSymbol, syms.len);

    var ofile: u32 = undefined;
    var last_sym: MachoSymbol = undefined;
    var symbol_index: usize = 0;
    var state: enum {
        init,
        oso_open,
        oso_close,
        bnsym,
        fun_strx,
        fun_size,
        ensym,
    } = .init;

    for (syms) |*sym| {
        if (!sym.stab()) continue;

        // TODO handle globals N_GSYM, and statics N_STSYM
        switch (sym.n_type) {
            macho.N_OSO => {
                switch (state) {
                    .init, .oso_close => {
                        state = .oso_open;
                        ofile = sym.n_strx;
                    },
                    else => return error.InvalidDebugInfo,
                }
            },
            macho.N_BNSYM => {
                switch (state) {
                    .oso_open, .ensym => {
                        state = .bnsym;
                        last_sym = .{
                            .strx = 0,
                            .addr = sym.n_value,
                            .size = 0,
                            .ofile = ofile,
                        };
                    },
                    else => return error.InvalidDebugInfo,
                }
            },
            macho.N_FUN => {
                switch (state) {
                    .bnsym => {
                        state = .fun_strx;
                        last_sym.strx = sym.n_strx;
                    },
                    .fun_strx => {
                        state = .fun_size;
                        last_sym.size = @as(u32, @int_cast(sym.n_value));
                    },
                    else => return error.InvalidDebugInfo,
                }
            },
            macho.N_ENSYM => {
                switch (state) {
                    .fun_size => {
                        state = .ensym;
                        symbols_buf[symbol_index] = last_sym;
                        symbol_index += 1;
                    },
                    else => return error.InvalidDebugInfo,
                }
            },
            macho.N_SO => {
                switch (state) {
                    .init, .oso_close => {},
                    .oso_open, .ensym => {
                        state = .oso_close;
                    },
                    else => return error.InvalidDebugInfo,
                }
            },
            else => {},
        }
    }

    switch (state) {
        .init => return error.MissingDebugInfo,
        .oso_close => {},
        else => return error.InvalidDebugInfo,
    }

    const symbols = try allocator.realloc(symbols_buf, symbol_index);

    // Even though lld emits symbols in ascending order, this debug code
    // should work for programs linked in any valid way.
    // This sort is so that we can binary search later.
    mem.sort(MachoSymbol, symbols, {}, MachoSymbol.address_less_than);

    return ModuleDebugInfo{
        .base_address = undefined,
        .vmaddr_slide = undefined,
        .mapped_memory = mapped_mem,
        .ofiles = ModuleDebugInfo.OFileTable.init(allocator),
        .symbols = symbols,
        .strings = strings,
    };
}

fn print_line_from_file_any_os(out_stream: anytype, line_info: LineInfo) !void {
    // Need this to always block even in async I/O mode, because this could potentially
    // be called from e.g. the event loop code crashing.
    var f = try fs.cwd().open_file(line_info.file_name, .{});
    defer f.close();
    // TODO fstat and make sure that the file has the correct size

    var buf: [mem.page_size]u8 = undefined;
    var amt_read = try f.read(buf[0..]);
    const line_start = seek: {
        var current_line_start: usize = 0;
        var next_line: usize = 1;
        while (next_line != line_info.line) {
            const slice = buf[current_line_start..amt_read];
            if (mem.index_of_scalar(u8, slice, '\n')) |pos| {
                next_line += 1;
                if (pos == slice.len - 1) {
                    amt_read = try f.read(buf[0..]);
                    current_line_start = 0;
                } else current_line_start += pos + 1;
            } else if (amt_read < buf.len) {
                return error.EndOfFile;
            } else {
                amt_read = try f.read(buf[0..]);
                current_line_start = 0;
            }
        }
        break :seek current_line_start;
    };
    const slice = buf[line_start..amt_read];
    if (mem.index_of_scalar(u8, slice, '\n')) |pos| {
        const line = slice[0 .. pos + 1];
        mem.replace_scalar(u8, line, '\t', ' ');
        return out_stream.write_all(line);
    } else { // Line is the last inside the buffer, and requires another read to find delimiter. Alternatively the file ends.
        mem.replace_scalar(u8, slice, '\t', ' ');
        try out_stream.write_all(slice);
        while (amt_read == buf.len) {
            amt_read = try f.read(buf[0..]);
            if (mem.index_of_scalar(u8, buf[0..amt_read], '\n')) |pos| {
                const line = buf[0 .. pos + 1];
                mem.replace_scalar(u8, line, '\t', ' ');
                return out_stream.write_all(line);
            } else {
                const line = buf[0..amt_read];
                mem.replace_scalar(u8, line, '\t', ' ');
                try out_stream.write_all(line);
            }
        }
        // Make sure printing last line of file inserts extra newline
        try out_stream.write_byte('\n');
    }
}

test print_line_from_file_any_os {
    var output = std.ArrayList(u8).init(std.testing.allocator);
    defer output.deinit();
    const output_stream = output.writer();

    const allocator = std.testing.allocator;
    const join = std.fs.path.join;
    const expect_error = std.testing.expect_error;
    const expect_equal_strings = std.testing.expect_equal_strings;

    var test_dir = std.testing.tmp_dir(.{});
    defer test_dir.cleanup();
    // Relies on testing.tmp_dir internals which is not ideal, but LineInfo requires paths.
    const test_dir_path = try join(allocator, &.{ ".zig-cache", "tmp", test_dir.sub_path[0..] });
    defer allocator.free(test_dir_path);

    // Cases
    {
        const path = try join(allocator, &.{ test_dir_path, "one_line.zig" });
        defer allocator.free(path);
        try test_dir.dir.write_file(.{ .sub_path = "one_line.zig", .data = "no new lines in this file, but one is printed anyway" });

        try expect_error(error.EndOfFile, print_line_from_file_any_os(output_stream, .{ .file_name = path, .line = 2, .column = 0 }));

        try print_line_from_file_any_os(output_stream, .{ .file_name = path, .line = 1, .column = 0 });
        try expect_equal_strings("no new lines in this file, but one is printed anyway\n", output.items);
        output.clear_retaining_capacity();
    }
    {
        const path = try fs.path.join(allocator, &.{ test_dir_path, "three_lines.zig" });
        defer allocator.free(path);
        try test_dir.dir.write_file(.{
            .sub_path = "three_lines.zig",
            .data =
            \\1
            \\2
            \\3
            ,
        });

        try print_line_from_file_any_os(output_stream, .{ .file_name = path, .line = 1, .column = 0 });
        try expect_equal_strings("1\n", output.items);
        output.clear_retaining_capacity();

        try print_line_from_file_any_os(output_stream, .{ .file_name = path, .line = 3, .column = 0 });
        try expect_equal_strings("3\n", output.items);
        output.clear_retaining_capacity();
    }
    {
        const file = try test_dir.dir.create_file("line_overlaps_page_boundary.zig", .{});
        defer file.close();
        const path = try fs.path.join(allocator, &.{ test_dir_path, "line_overlaps_page_boundary.zig" });
        defer allocator.free(path);

        const overlap = 10;
        var writer = file.writer();
        try writer.write_byte_ntimes('a', mem.page_size - overlap);
        try writer.write_byte('\n');
        try writer.write_byte_ntimes('a', overlap);

        try print_line_from_file_any_os(output_stream, .{ .file_name = path, .line = 2, .column = 0 });
        try expect_equal_strings(("a" ** overlap) ++ "\n", output.items);
        output.clear_retaining_capacity();
    }
    {
        const file = try test_dir.dir.create_file("file_ends_on_page_boundary.zig", .{});
        defer file.close();
        const path = try fs.path.join(allocator, &.{ test_dir_path, "file_ends_on_page_boundary.zig" });
        defer allocator.free(path);

        var writer = file.writer();
        try writer.write_byte_ntimes('a', mem.page_size);

        try print_line_from_file_any_os(output_stream, .{ .file_name = path, .line = 1, .column = 0 });
        try expect_equal_strings(("a" ** mem.page_size) ++ "\n", output.items);
        output.clear_retaining_capacity();
    }
    {
        const file = try test_dir.dir.create_file("very_long_first_line_spanning_multiple_pages.zig", .{});
        defer file.close();
        const path = try fs.path.join(allocator, &.{ test_dir_path, "very_long_first_line_spanning_multiple_pages.zig" });
        defer allocator.free(path);

        var writer = file.writer();
        try writer.write_byte_ntimes('a', 3 * mem.page_size);

        try expect_error(error.EndOfFile, print_line_from_file_any_os(output_stream, .{ .file_name = path, .line = 2, .column = 0 }));

        try print_line_from_file_any_os(output_stream, .{ .file_name = path, .line = 1, .column = 0 });
        try expect_equal_strings(("a" ** (3 * mem.page_size)) ++ "\n", output.items);
        output.clear_retaining_capacity();

        try writer.write_all("a\na");

        try print_line_from_file_any_os(output_stream, .{ .file_name = path, .line = 1, .column = 0 });
        try expect_equal_strings(("a" ** (3 * mem.page_size)) ++ "a\n", output.items);
        output.clear_retaining_capacity();

        try print_line_from_file_any_os(output_stream, .{ .file_name = path, .line = 2, .column = 0 });
        try expect_equal_strings("a\n", output.items);
        output.clear_retaining_capacity();
    }
    {
        const file = try test_dir.dir.create_file("file_of_newlines.zig", .{});
        defer file.close();
        const path = try fs.path.join(allocator, &.{ test_dir_path, "file_of_newlines.zig" });
        defer allocator.free(path);

        var writer = file.writer();
        const real_file_start = 3 * mem.page_size;
        try writer.write_byte_ntimes('\n', real_file_start);
        try writer.write_all("abc\ndef");

        try print_line_from_file_any_os(output_stream, .{ .file_name = path, .line = real_file_start + 1, .column = 0 });
        try expect_equal_strings("abc\n", output.items);
        output.clear_retaining_capacity();

        try print_line_from_file_any_os(output_stream, .{ .file_name = path, .line = real_file_start + 2, .column = 0 });
        try expect_equal_strings("def\n", output.items);
        output.clear_retaining_capacity();
    }
}

const MachoSymbol = struct {
    strx: u32,
    addr: u64,
    size: u32,
    ofile: u32,

    /// Returns the address from the macho file
    fn address(self: MachoSymbol) u64 {
        return self.addr;
    }

    fn address_less_than(context: void, lhs: MachoSymbol, rhs: MachoSymbol) bool {
        _ = context;
        return lhs.addr < rhs.addr;
    }
};

/// Takes ownership of file, even on error.
/// TODO it's weird to take ownership even on error, rework this code.
fn map_whole_file(file: File) ![]align(mem.page_size) const u8 {
    nosuspend {
        defer file.close();

        const file_len = math.cast(usize, try file.get_end_pos()) orelse math.max_int(usize);
        const mapped_mem = try posix.mmap(
            null,
            file_len,
            posix.PROT.READ,
            .{ .TYPE = .SHARED },
            file.handle,
            0,
        );
        errdefer posix.munmap(mapped_mem);

        return mapped_mem;
    }
}

pub const WindowsModuleInfo = struct {
    base_address: usize,
    size: u32,
    name: []const u8,
    handle: windows.HMODULE,

    // Set when the image file needed to be mapped from disk
    mapped_file: ?struct {
        file: File,
        section_handle: windows.HANDLE,
        section_view: []const u8,

        pub fn deinit(self: @This()) void {
            const process_handle = windows.kernel32.GetCurrentProcess();
            assert(windows.ntdll.NtUnmapViewOfSection(process_handle, @constCast(@ptr_cast(self.section_view.ptr))) == .SUCCESS);
            windows.CloseHandle(self.section_handle);
            self.file.close();
        }
    } = null,
};

pub const DebugInfo = struct {
    allocator: mem.Allocator,
    address_map: std.AutoHashMap(usize, *ModuleDebugInfo),
    modules: if (native_os == .windows) std.ArrayListUnmanaged(WindowsModuleInfo) else void,

    pub fn init(allocator: mem.Allocator) !DebugInfo {
        var debug_info = DebugInfo{
            .allocator = allocator,
            .address_map = std.AutoHashMap(usize, *ModuleDebugInfo).init(allocator),
            .modules = if (native_os == .windows) .{} else {},
        };

        if (native_os == .windows) {
            errdefer debug_info.modules.deinit(allocator);

            const handle = windows.kernel32.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE | windows.TH32CS_SNAPMODULE32, 0);
            if (handle == windows.INVALID_HANDLE_VALUE) {
                switch (windows.kernel32.GetLastError()) {
                    else => |err| return windows.unexpected_error(err),
                }
            }
            defer windows.CloseHandle(handle);

            var module_entry: windows.MODULEENTRY32 = undefined;
            module_entry.dwSize = @size_of(windows.MODULEENTRY32);
            if (windows.kernel32.Module32First(handle, &module_entry) == 0) {
                return error.MissingDebugInfo;
            }

            var module_valid = true;
            while (module_valid) {
                const module_info = try debug_info.modules.add_one(allocator);
                const name = allocator.dupe(u8, mem.slice_to(&module_entry.szModule, 0)) catch &.{};
                errdefer allocator.free(name);

                module_info.* = .{
                    .base_address = @int_from_ptr(module_entry.modBaseAddr),
                    .size = module_entry.modBaseSize,
                    .name = name,
                    .handle = module_entry.hModule,
                };

                module_valid = windows.kernel32.Module32Next(handle, &module_entry) == 1;
            }
        }

        return debug_info;
    }

    pub fn deinit(self: *DebugInfo) void {
        var it = self.address_map.iterator();
        while (it.next()) |entry| {
            const mdi = entry.value_ptr.*;
            mdi.deinit(self.allocator);
            self.allocator.destroy(mdi);
        }
        self.address_map.deinit();
        if (native_os == .windows) {
            for (self.modules.items) |module| {
                self.allocator.free(module.name);
                if (module.mapped_file) |mapped_file| mapped_file.deinit();
            }
            self.modules.deinit(self.allocator);
        }
    }

    pub fn get_module_for_address(self: *DebugInfo, address: usize) !*ModuleDebugInfo {
        if (comptime builtin.target.is_darwin()) {
            return self.lookup_module_dyld(address);
        } else if (native_os == .windows) {
            return self.lookup_module_win32(address);
        } else if (native_os == .haiku) {
            return self.lookup_module_haiku(address);
        } else if (comptime builtin.target.is_wasm()) {
            return self.lookup_module_wasm(address);
        } else {
            return self.lookup_module_dl(address);
        }
    }

    // Returns the module name for a given address.
    // This can be called when get_module_for_address fails, so implementations should provide
    // a path that doesn't rely on any side-effects of a prior successful module lookup.
    pub fn get_module_name_for_address(self: *DebugInfo, address: usize) ?[]const u8 {
        if (comptime builtin.target.is_darwin()) {
            return self.lookup_module_name_dyld(address);
        } else if (native_os == .windows) {
            return self.lookup_module_name_win32(address);
        } else if (native_os == .haiku) {
            return null;
        } else if (comptime builtin.target.is_wasm()) {
            return null;
        } else {
            return self.lookup_module_name_dl(address);
        }
    }

    fn lookup_module_dyld(self: *DebugInfo, address: usize) !*ModuleDebugInfo {
        const image_count = std.c._dyld_image_count();

        var i: u32 = 0;
        while (i < image_count) : (i += 1) {
            const header = std.c._dyld_get_image_header(i) orelse continue;
            const base_address = @int_from_ptr(header);
            if (address < base_address) continue;
            const vmaddr_slide = std.c._dyld_get_image_vmaddr_slide(i);

            var it = macho.LoadCommandIterator{
                .ncmds = header.ncmds,
                .buffer = @align_cast(@as(
                    [*]u8,
                    @ptrFromInt(@int_from_ptr(header) + @size_of(macho.mach_header_64)),
                )[0..header.sizeofcmds]),
            };

            var unwind_info: ?[]const u8 = null;
            var eh_frame: ?[]const u8 = null;
            while (it.next()) |cmd| switch (cmd.cmd()) {
                .SEGMENT_64 => {
                    const segment_cmd = cmd.cast(macho.segment_command_64).?;
                    if (!mem.eql(u8, "__TEXT", segment_cmd.seg_name())) continue;

                    const seg_start = segment_cmd.vmaddr + vmaddr_slide;
                    const seg_end = seg_start + segment_cmd.vmsize;
                    if (address >= seg_start and address < seg_end) {
                        if (self.address_map.get(base_address)) |obj_di| {
                            return obj_di;
                        }

                        for (cmd.get_sections()) |sect| {
                            if (mem.eql(u8, "__unwind_info", sect.sect_name())) {
                                unwind_info = @as([*]const u8, @ptrFromInt(sect.addr + vmaddr_slide))[0..sect.size];
                            } else if (mem.eql(u8, "__eh_frame", sect.sect_name())) {
                                eh_frame = @as([*]const u8, @ptrFromInt(sect.addr + vmaddr_slide))[0..sect.size];
                            }
                        }

                        const obj_di = try self.allocator.create(ModuleDebugInfo);
                        errdefer self.allocator.destroy(obj_di);

                        const macho_path = mem.slice_to(std.c._dyld_get_image_name(i), 0);
                        const macho_file = fs.cwd().open_file(macho_path, .{}) catch |err| switch (err) {
                            error.FileNotFound => return error.MissingDebugInfo,
                            else => return err,
                        };
                        obj_di.* = try read_mach_odebug_info(self.allocator, macho_file);
                        obj_di.base_address = base_address;
                        obj_di.vmaddr_slide = vmaddr_slide;
                        obj_di.unwind_info = unwind_info;
                        obj_di.eh_frame = eh_frame;

                        try self.address_map.put_no_clobber(base_address, obj_di);

                        return obj_di;
                    }
                },
                else => {},
            };
        }

        return error.MissingDebugInfo;
    }

    fn lookup_module_name_dyld(self: *DebugInfo, address: usize) ?[]const u8 {
        _ = self;
        const image_count = std.c._dyld_image_count();

        var i: u32 = 0;
        while (i < image_count) : (i += 1) {
            const header = std.c._dyld_get_image_header(i) orelse continue;
            const base_address = @int_from_ptr(header);
            if (address < base_address) continue;
            const vmaddr_slide = std.c._dyld_get_image_vmaddr_slide(i);

            var it = macho.LoadCommandIterator{
                .ncmds = header.ncmds,
                .buffer = @align_cast(@as(
                    [*]u8,
                    @ptrFromInt(@int_from_ptr(header) + @size_of(macho.mach_header_64)),
                )[0..header.sizeofcmds]),
            };

            while (it.next()) |cmd| switch (cmd.cmd()) {
                .SEGMENT_64 => {
                    const segment_cmd = cmd.cast(macho.segment_command_64).?;
                    if (!mem.eql(u8, "__TEXT", segment_cmd.seg_name())) continue;

                    const original_address = address - vmaddr_slide;
                    const seg_start = segment_cmd.vmaddr;
                    const seg_end = seg_start + segment_cmd.vmsize;
                    if (original_address >= seg_start and original_address < seg_end) {
                        return fs.path.basename(mem.slice_to(std.c._dyld_get_image_name(i), 0));
                    }
                },
                else => {},
            };
        }

        return null;
    }

    fn lookup_module_win32(self: *DebugInfo, address: usize) !*ModuleDebugInfo {
        for (self.modules.items) |*module| {
            if (address >= module.base_address and address < module.base_address + module.size) {
                if (self.address_map.get(module.base_address)) |obj_di| {
                    return obj_di;
                }

                const obj_di = try self.allocator.create(ModuleDebugInfo);
                errdefer self.allocator.destroy(obj_di);

                const mapped_module = @as([*]const u8, @ptrFromInt(module.base_address))[0..module.size];
                var coff_obj = try coff.Coff.init(mapped_module, true);

                // The string table is not mapped into memory by the loader, so if a section name is in the
                // string table then we have to map the full image file from disk. This can happen when
                // a binary is produced with -gdwarf, since the section names are longer than 8 bytes.
                if (coff_obj.strtab_required()) {
                    var name_buffer: [windows.PATH_MAX_WIDE + 4:0]u16 = undefined;
                    // open_file_absolute_w requires the prefix to be present
                    @memcpy(name_buffer[0..4], &[_]u16{ '\\', '?', '?', '\\' });

                    const process_handle = windows.kernel32.GetCurrentProcess();
                    const len = windows.kernel32.K32GetModuleFileNameExW(
                        process_handle,
                        module.handle,
                        @ptr_cast(&name_buffer[4]),
                        windows.PATH_MAX_WIDE,
                    );

                    if (len == 0) return error.MissingDebugInfo;
                    const coff_file = fs.open_file_absolute_w(name_buffer[0 .. len + 4 :0], .{}) catch |err| switch (err) {
                        error.FileNotFound => return error.MissingDebugInfo,
                        else => return err,
                    };
                    errdefer coff_file.close();

                    var section_handle: windows.HANDLE = undefined;
                    const create_section_rc = windows.ntdll.NtCreateSection(
                        &section_handle,
                        windows.STANDARD_RIGHTS_REQUIRED | windows.SECTION_QUERY | windows.SECTION_MAP_READ,
                        null,
                        null,
                        windows.PAGE_READONLY,
                        // The documentation states that if no AllocationAttribute is specified, then SEC_COMMIT is the default.
                        // In practice, this isn't the case and specifying 0 will result in INVALID_PARAMETER_6.
                        windows.SEC_COMMIT,
                        coff_file.handle,
                    );
                    if (create_section_rc != .SUCCESS) return error.MissingDebugInfo;
                    errdefer windows.CloseHandle(section_handle);

                    var coff_len: usize = 0;
                    var base_ptr: usize = 0;
                    const map_section_rc = windows.ntdll.NtMapViewOfSection(
                        section_handle,
                        process_handle,
                        @ptr_cast(&base_ptr),
                        null,
                        0,
                        null,
                        &coff_len,
                        .ViewUnmap,
                        0,
                        windows.PAGE_READONLY,
                    );
                    if (map_section_rc != .SUCCESS) return error.MissingDebugInfo;
                    errdefer assert(windows.ntdll.NtUnmapViewOfSection(process_handle, @ptrFromInt(base_ptr)) == .SUCCESS);

                    const section_view = @as([*]const u8, @ptrFromInt(base_ptr))[0..coff_len];
                    coff_obj = try coff.Coff.init(section_view, false);

                    module.mapped_file = .{
                        .file = coff_file,
                        .section_handle = section_handle,
                        .section_view = section_view,
                    };
                }
                errdefer if (module.mapped_file) |mapped_file| mapped_file.deinit();

                obj_di.* = try read_coff_debug_info(self.allocator, &coff_obj);
                obj_di.base_address = module.base_address;

                try self.address_map.put_no_clobber(module.base_address, obj_di);
                return obj_di;
            }
        }

        return error.MissingDebugInfo;
    }

    fn lookup_module_name_win32(self: *DebugInfo, address: usize) ?[]const u8 {
        for (self.modules.items) |module| {
            if (address >= module.base_address and address < module.base_address + module.size) {
                return module.name;
            }
        }
        return null;
    }

    fn lookup_module_name_dl(self: *DebugInfo, address: usize) ?[]const u8 {
        _ = self;

        var ctx: struct {
            // Input
            address: usize,
            // Output
            name: []const u8 = "",
        } = .{ .address = address };
        const CtxTy = @TypeOf(ctx);

        if (posix.dl_iterate_phdr(&ctx, error{Found}, struct {
            fn callback(info: *posix.dl_phdr_info, size: usize, context: *CtxTy) !void {
                _ = size;
                if (context.address < info.dlpi_addr) return;
                const phdrs = info.dlpi_phdr[0..info.dlpi_phnum];
                for (phdrs) |*phdr| {
                    if (phdr.p_type != elf.PT_LOAD) continue;

                    const seg_start = info.dlpi_addr +% phdr.p_vaddr;
                    const seg_end = seg_start + phdr.p_memsz;
                    if (context.address >= seg_start and context.address < seg_end) {
                        context.name = mem.slice_to(info.dlpi_name, 0) orelse "";
                        break;
                    }
                } else return;

                return error.Found;
            }
        }.callback)) {
            return null;
        } else |err| switch (err) {
            error.Found => return fs.path.basename(ctx.name),
        }

        return null;
    }

    fn lookup_module_dl(self: *DebugInfo, address: usize) !*ModuleDebugInfo {
        var ctx: struct {
            // Input
            address: usize,
            // Output
            base_address: usize = undefined,
            name: []const u8 = undefined,
            build_id: ?[]const u8 = null,
            gnu_eh_frame: ?[]const u8 = null,
        } = .{ .address = address };
        const CtxTy = @TypeOf(ctx);

        if (posix.dl_iterate_phdr(&ctx, error{Found}, struct {
            fn callback(info: *posix.dl_phdr_info, size: usize, context: *CtxTy) !void {
                _ = size;
                // The base address is too high
                if (context.address < info.dlpi_addr)
                    return;

                const phdrs = info.dlpi_phdr[0..info.dlpi_phnum];
                for (phdrs) |*phdr| {
                    if (phdr.p_type != elf.PT_LOAD) continue;

                    // Overflowing addition is used to handle the case of VSDOs having a p_vaddr = 0xffffffffff700000
                    const seg_start = info.dlpi_addr +% phdr.p_vaddr;
                    const seg_end = seg_start + phdr.p_memsz;
                    if (context.address >= seg_start and context.address < seg_end) {
                        // Android libc uses NULL instead of an empty string to mark the
                        // main program
                        context.name = mem.slice_to(info.dlpi_name, 0) orelse "";
                        context.base_address = info.dlpi_addr;
                        break;
                    }
                } else return;

                for (info.dlpi_phdr[0..info.dlpi_phnum]) |phdr| {
                    switch (phdr.p_type) {
                        elf.PT_NOTE => {
                            // Look for .note.gnu.build-id
                            const note_bytes = @as([*]const u8, @ptrFromInt(info.dlpi_addr + phdr.p_vaddr))[0..phdr.p_memsz];
                            const name_size = mem.read_int(u32, note_bytes[0..4], native_endian);
                            if (name_size != 4) continue;
                            const desc_size = mem.read_int(u32, note_bytes[4..8], native_endian);
                            const note_type = mem.read_int(u32, note_bytes[8..12], native_endian);
                            if (note_type != elf.NT_GNU_BUILD_ID) continue;
                            if (!mem.eql(u8, "GNU\x00", note_bytes[12..16])) continue;
                            context.build_id = note_bytes[16..][0..desc_size];
                        },
                        elf.PT_GNU_EH_FRAME => {
                            context.gnu_eh_frame = @as([*]const u8, @ptrFromInt(info.dlpi_addr + phdr.p_vaddr))[0..phdr.p_memsz];
                        },
                        else => {},
                    }
                }

                // Stop the iteration
                return error.Found;
            }
        }.callback)) {
            return error.MissingDebugInfo;
        } else |err| switch (err) {
            error.Found => {},
        }

        if (self.address_map.get(ctx.base_address)) |obj_di| {
            return obj_di;
        }

        const obj_di = try self.allocator.create(ModuleDebugInfo);
        errdefer self.allocator.destroy(obj_di);

        var sections: DW.DwarfInfo.SectionArray = DW.DwarfInfo.null_section_array;
        if (ctx.gnu_eh_frame) |eh_frame_hdr| {
            // This is a special case - pointer offsets inside .eh_frame_hdr
            // are encoded relative to its base address, so we must use the
            // version that is already memory mapped, and not the one that
            // will be mapped separately from the ELF file.
            sections[@int_from_enum(DW.DwarfSection.eh_frame_hdr)] = .{
                .data = eh_frame_hdr,
                .owned = false,
            };
        }

        obj_di.* = try read_elf_debug_info(self.allocator, if (ctx.name.len > 0) ctx.name else null, ctx.build_id, null, &sections, null);
        obj_di.base_address = ctx.base_address;

        // Missing unwind info isn't treated as a failure, as the unwinder will fall back to FP-based unwinding
        obj_di.dwarf.scan_all_unwind_info(self.allocator, ctx.base_address) catch {};

        try self.address_map.put_no_clobber(ctx.base_address, obj_di);

        return obj_di;
    }

    fn lookup_module_haiku(self: *DebugInfo, address: usize) !*ModuleDebugInfo {
        _ = self;
        _ = address;
        @panic("TODO implement lookup module for Haiku");
    }

    fn lookup_module_wasm(self: *DebugInfo, address: usize) !*ModuleDebugInfo {
        _ = self;
        _ = address;
        @panic("TODO implement lookup module for Wasm");
    }
};

pub const ModuleDebugInfo = switch (native_os) {
    .macos, .ios, .watchos, .tvos, .visionos => struct {
        base_address: usize,
        vmaddr_slide: usize,
        mapped_memory: []align(mem.page_size) const u8,
        symbols: []const MachoSymbol,
        strings: [:0]const u8,
        ofiles: OFileTable,

        // Backed by the in-memory sections mapped by the loader
        unwind_info: ?[]const u8 = null,
        eh_frame: ?[]const u8 = null,

        const OFileTable = std.StringHashMap(OFileInfo);
        const OFileInfo = struct {
            di: DW.DwarfInfo,
            addr_table: std.StringHashMap(u64),
        };

        pub fn deinit(self: *@This(), allocator: mem.Allocator) void {
            var it = self.ofiles.iterator();
            while (it.next()) |entry| {
                const ofile = entry.value_ptr;
                ofile.di.deinit(allocator);
                ofile.addr_table.deinit();
            }
            self.ofiles.deinit();
            allocator.free(self.symbols);
            posix.munmap(self.mapped_memory);
        }

        fn load_ofile(self: *@This(), allocator: mem.Allocator, o_file_path: []const u8) !*OFileInfo {
            const o_file = try fs.cwd().open_file(o_file_path, .{});
            const mapped_mem = try map_whole_file(o_file);

            const hdr: *const macho.mach_header_64 = @ptr_cast(@align_cast(mapped_mem.ptr));
            if (hdr.magic != std.macho.MH_MAGIC_64)
                return error.InvalidDebugInfo;

            var segcmd: ?macho.LoadCommandIterator.LoadCommand = null;
            var symtabcmd: ?macho.symtab_command = null;
            var it = macho.LoadCommandIterator{
                .ncmds = hdr.ncmds,
                .buffer = mapped_mem[@size_of(macho.mach_header_64)..][0..hdr.sizeofcmds],
            };
            while (it.next()) |cmd| switch (cmd.cmd()) {
                .SEGMENT_64 => segcmd = cmd,
                .SYMTAB => symtabcmd = cmd.cast(macho.symtab_command).?,
                else => {},
            };

            if (segcmd == null or symtabcmd == null) return error.MissingDebugInfo;

            // Parse symbols
            const strtab = @as(
                [*]const u8,
                @ptr_cast(&mapped_mem[symtabcmd.?.stroff]),
            )[0 .. symtabcmd.?.strsize - 1 :0];
            const symtab = @as(
                [*]const macho.nlist_64,
                @ptr_cast(@align_cast(&mapped_mem[symtabcmd.?.symoff])),
            )[0..symtabcmd.?.nsyms];

            // TODO handle tentative (common) symbols
            var addr_table = std.StringHashMap(u64).init(allocator);
            try addr_table.ensure_total_capacity(@as(u32, @int_cast(symtab.len)));
            for (symtab) |sym| {
                if (sym.n_strx == 0) continue;
                if (sym.undf() or sym.tentative() or sym.abs()) continue;
                const sym_name = mem.slice_to(strtab[sym.n_strx..], 0);
                // TODO is it possible to have a symbol collision?
                addr_table.put_assume_capacity_no_clobber(sym_name, sym.n_value);
            }

            var sections: DW.DwarfInfo.SectionArray = DW.DwarfInfo.null_section_array;
            if (self.eh_frame) |eh_frame| sections[@int_from_enum(DW.DwarfSection.eh_frame)] = .{
                .data = eh_frame,
                .owned = false,
            };

            for (segcmd.?.get_sections()) |sect| {
                if (!std.mem.eql(u8, "__DWARF", sect.seg_name())) continue;

                var section_index: ?usize = null;
                inline for (@typeInfo(DW.DwarfSection).Enum.fields, 0..) |section, i| {
                    if (mem.eql(u8, "__" ++ section.name, sect.sect_name())) section_index = i;
                }
                if (section_index == null) continue;

                const section_bytes = try chop_slice(mapped_mem, sect.offset, sect.size);
                sections[section_index.?] = .{
                    .data = section_bytes,
                    .virtual_address = sect.addr,
                    .owned = false,
                };
            }

            const missing_debug_info =
                sections[@int_from_enum(DW.DwarfSection.debug_info)] == null or
                sections[@int_from_enum(DW.DwarfSection.debug_abbrev)] == null or
                sections[@int_from_enum(DW.DwarfSection.debug_str)] == null or
                sections[@int_from_enum(DW.DwarfSection.debug_line)] == null;
            if (missing_debug_info) return error.MissingDebugInfo;

            var di = DW.DwarfInfo{
                .endian = .little,
                .sections = sections,
                .is_macho = true,
            };

            try DW.open_dwarf_debug_info(&di, allocator);
            const info = OFileInfo{
                .di = di,
                .addr_table = addr_table,
            };

            // Add the debug info to the cache
            const result = try self.ofiles.get_or_put(o_file_path);
            assert(!result.found_existing);
            result.value_ptr.* = info;

            return result.value_ptr;
        }

        pub fn get_symbol_at_address(self: *@This(), allocator: mem.Allocator, address: usize) !SymbolInfo {
            nosuspend {
                const result = try self.get_ofile_info_for_address(allocator, address);
                if (result.symbol == null) return .{};

                // Take the symbol name from the N_FUN STAB entry, we're going to
                // use it if we fail to find the DWARF infos
                const stab_symbol = mem.slice_to(self.strings[result.symbol.?.strx..], 0);
                if (result.o_file_info == null) return .{ .symbol_name = stab_symbol };

                // Translate again the address, this time into an address inside the
                // .o file
                const relocated_address_o = result.o_file_info.?.addr_table.get(stab_symbol) orelse return .{
                    .symbol_name = "???",
                };

                const addr_off = result.relocated_address - result.symbol.?.addr;
                const o_file_di = &result.o_file_info.?.di;
                if (o_file_di.find_compile_unit(relocated_address_o)) |compile_unit| {
                    return SymbolInfo{
                        .symbol_name = o_file_di.get_symbol_name(relocated_address_o) orelse "???",
                        .compile_unit_name = compile_unit.die.get_attr_string(
                            o_file_di,
                            DW.AT.name,
                            o_file_di.section(.debug_str),
                            compile_unit.*,
                        ) catch |err| switch (err) {
                            error.MissingDebugInfo, error.InvalidDebugInfo => "???",
                        },
                        .line_info = o_file_di.get_line_number_info(
                            allocator,
                            compile_unit.*,
                            relocated_address_o + addr_off,
                        ) catch |err| switch (err) {
                            error.MissingDebugInfo, error.InvalidDebugInfo => null,
                            else => return err,
                        },
                    };
                } else |err| switch (err) {
                    error.MissingDebugInfo, error.InvalidDebugInfo => {
                        return SymbolInfo{ .symbol_name = stab_symbol };
                    },
                    else => return err,
                }
            }
        }

        pub fn get_ofile_info_for_address(self: *@This(), allocator: mem.Allocator, address: usize) !struct {
            relocated_address: usize,
            symbol: ?*const MachoSymbol = null,
            o_file_info: ?*OFileInfo = null,
        } {
            nosuspend {
                // Translate the VA into an address into this object
                const relocated_address = address - self.vmaddr_slide;

                // Find the .o file where this symbol is defined
                const symbol = macho_search_symbols(self.symbols, relocated_address) orelse return .{
                    .relocated_address = relocated_address,
                };

                // Check if its debug infos are already in the cache
                const o_file_path = mem.slice_to(self.strings[symbol.ofile..], 0);
                const o_file_info = self.ofiles.get_ptr(o_file_path) orelse
                    (self.load_ofile(allocator, o_file_path) catch |err| switch (err) {
                    error.FileNotFound,
                    error.MissingDebugInfo,
                    error.InvalidDebugInfo,
                    => return .{
                        .relocated_address = relocated_address,
                        .symbol = symbol,
                    },
                    else => return err,
                });

                return .{
                    .relocated_address = relocated_address,
                    .symbol = symbol,
                    .o_file_info = o_file_info,
                };
            }
        }

        pub fn get_dwarf_info_for_address(self: *@This(), allocator: mem.Allocator, address: usize) !?*const DW.DwarfInfo {
            return if ((try self.get_ofile_info_for_address(allocator, address)).o_file_info) |o_file_info| &o_file_info.di else null;
        }
    },
    .uefi, .windows => struct {
        base_address: usize,
        pdb: ?pdb.Pdb = null,
        dwarf: ?DW.DwarfInfo = null,
        coff_image_base: u64,

        /// Only used if pdb is non-null
        coff_section_headers: []coff.SectionHeader,

        pub fn deinit(self: *@This(), allocator: mem.Allocator) void {
            if (self.dwarf) |*dwarf| {
                dwarf.deinit(allocator);
            }

            if (self.pdb) |*p| {
                p.deinit();
                allocator.free(self.coff_section_headers);
            }
        }

        fn get_symbol_from_pdb(self: *@This(), relocated_address: usize) !?SymbolInfo {
            var coff_section: *align(1) const coff.SectionHeader = undefined;
            const mod_index = for (self.pdb.?.sect_contribs) |sect_contrib| {
                if (sect_contrib.Section > self.coff_section_headers.len) continue;
                // Remember that SectionContribEntry.Section is 1-based.
                coff_section = &self.coff_section_headers[sect_contrib.Section - 1];

                const vaddr_start = coff_section.virtual_address + sect_contrib.Offset;
                const vaddr_end = vaddr_start + sect_contrib.Size;
                if (relocated_address >= vaddr_start and relocated_address < vaddr_end) {
                    break sect_contrib.ModuleIndex;
                }
            } else {
                // we have no information to add to the address
                return null;
            };

            const module = (try self.pdb.?.get_module(mod_index)) orelse
                return error.InvalidDebugInfo;
            const obj_basename = fs.path.basename(module.obj_file_name);

            const symbol_name = self.pdb.?.get_symbol_name(
                module,
                relocated_address - coff_section.virtual_address,
            ) orelse "???";
            const opt_line_info = try self.pdb.?.get_line_number_info(
                module,
                relocated_address - coff_section.virtual_address,
            );

            return SymbolInfo{
                .symbol_name = symbol_name,
                .compile_unit_name = obj_basename,
                .line_info = opt_line_info,
            };
        }

        pub fn get_symbol_at_address(self: *@This(), allocator: mem.Allocator, address: usize) !SymbolInfo {
            // Translate the VA into an address into this object
            const relocated_address = address - self.base_address;

            if (self.pdb != null) {
                if (try self.get_symbol_from_pdb(relocated_address)) |symbol| return symbol;
            }

            if (self.dwarf) |*dwarf| {
                const dwarf_address = relocated_address + self.coff_image_base;
                return get_symbol_from_dwarf(allocator, dwarf_address, dwarf);
            }

            return SymbolInfo{};
        }

        pub fn get_dwarf_info_for_address(self: *@This(), allocator: mem.Allocator, address: usize) !?*const DW.DwarfInfo {
            _ = allocator;
            _ = address;

            return switch (self.debug_data) {
                .dwarf => |*dwarf| dwarf,
                else => null,
            };
        }
    },
    .linux, .netbsd, .freebsd, .dragonfly, .openbsd, .haiku, .solaris, .illumos => struct {
        base_address: usize,
        dwarf: DW.DwarfInfo,
        mapped_memory: []align(mem.page_size) const u8,
        external_mapped_memory: ?[]align(mem.page_size) const u8,

        pub fn deinit(self: *@This(), allocator: mem.Allocator) void {
            self.dwarf.deinit(allocator);
            posix.munmap(self.mapped_memory);
            if (self.external_mapped_memory) |m| posix.munmap(m);
        }

        pub fn get_symbol_at_address(self: *@This(), allocator: mem.Allocator, address: usize) !SymbolInfo {
            // Translate the VA into an address into this object
            const relocated_address = address - self.base_address;
            return get_symbol_from_dwarf(allocator, relocated_address, &self.dwarf);
        }

        pub fn get_dwarf_info_for_address(self: *@This(), allocator: mem.Allocator, address: usize) !?*const DW.DwarfInfo {
            _ = allocator;
            _ = address;
            return &self.dwarf;
        }
    },
    .wasi, .emscripten => struct {
        pub fn deinit(self: *@This(), allocator: mem.Allocator) void {
            _ = self;
            _ = allocator;
        }

        pub fn get_symbol_at_address(self: *@This(), allocator: mem.Allocator, address: usize) !SymbolInfo {
            _ = self;
            _ = allocator;
            _ = address;
            return SymbolInfo{};
        }

        pub fn get_dwarf_info_for_address(self: *@This(), allocator: mem.Allocator, address: usize) !?*const DW.DwarfInfo {
            _ = self;
            _ = allocator;
            _ = address;
            return null;
        }
    },
    else => DW.DwarfInfo,
};

fn get_symbol_from_dwarf(allocator: mem.Allocator, address: u64, di: *DW.DwarfInfo) !SymbolInfo {
    if (nosuspend di.find_compile_unit(address)) |compile_unit| {
        return SymbolInfo{
            .symbol_name = nosuspend di.get_symbol_name(address) orelse "???",
            .compile_unit_name = compile_unit.die.get_attr_string(di, DW.AT.name, di.section(.debug_str), compile_unit.*) catch |err| switch (err) {
                error.MissingDebugInfo, error.InvalidDebugInfo => "???",
            },
            .line_info = nosuspend di.get_line_number_info(allocator, compile_unit.*, address) catch |err| switch (err) {
                error.MissingDebugInfo, error.InvalidDebugInfo => null,
                else => return err,
            },
        };
    } else |err| switch (err) {
        error.MissingDebugInfo, error.InvalidDebugInfo => {
            return SymbolInfo{};
        },
        else => return err,
    }
}

/// TODO multithreaded awareness
var debug_info_allocator: ?mem.Allocator = null;
var debug_info_arena_allocator: std.heap.ArenaAllocator = undefined;
fn get_debug_info_allocator() mem.Allocator {
    if (debug_info_allocator) |a| return a;

    debug_info_arena_allocator = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const allocator = debug_info_arena_allocator.allocator();
    debug_info_allocator = allocator;
    return allocator;
}

/// Whether or not the current target can print useful debug information when a segfault occurs.
pub const have_segfault_handling_support = switch (native_os) {
    .linux,
    .macos,
    .netbsd,
    .solaris,
    .illumos,
    .windows,
    => true,

    .freebsd, .openbsd => @hasDecl(std.c, "ucontext_t"),
    else => false,
};

const enable_segfault_handler = std.options.enable_segfault_handler;
pub const default_enable_segfault_handler = runtime_safety and have_segfault_handling_support;

pub fn maybe_enable_segfault_handler() void {
    if (enable_segfault_handler) {
        std.debug.attach_segfault_handler();
    }
}

var windows_segfault_handle: ?windows.HANDLE = null;

pub fn update_segfault_handler(act: ?*const posix.Sigaction) error{OperationNotSupported}!void {
    try posix.sigaction(posix.SIG.SEGV, act, null);
    try posix.sigaction(posix.SIG.ILL, act, null);
    try posix.sigaction(posix.SIG.BUS, act, null);
    try posix.sigaction(posix.SIG.FPE, act, null);
}

/// Attaches a global SIGSEGV handler which calls `@panic("segmentation fault");`
pub fn attach_segfault_handler() void {
    if (!have_segfault_handling_support) {
        @compile_error("segfault handler not supported for this target");
    }
    if (native_os == .windows) {
        windows_segfault_handle = windows.kernel32.AddVectoredExceptionHandler(0, handle_segfault_windows);
        return;
    }
    var act = posix.Sigaction{
        .handler = .{ .sigaction = handle_segfault_posix },
        .mask = posix.empty_sigset,
        .flags = (posix.SA.SIGINFO | posix.SA.RESTART | posix.SA.RESETHAND),
    };

    update_segfault_handler(&act) catch {
        @panic("unable to install segfault handler, maybe adjust have_segfault_handling_support in std/debug.zig");
    };
}

fn reset_segfault_handler() void {
    if (native_os == .windows) {
        if (windows_segfault_handle) |handle| {
            assert(windows.kernel32.RemoveVectoredExceptionHandler(handle) != 0);
            windows_segfault_handle = null;
        }
        return;
    }
    var act = posix.Sigaction{
        .handler = .{ .handler = posix.SIG.DFL },
        .mask = posix.empty_sigset,
        .flags = 0,
    };
    // To avoid a double-panic, do nothing if an error happens here.
    update_segfault_handler(&act) catch {};
}

fn handle_segfault_posix(sig: i32, info: *const posix.siginfo_t, ctx_ptr: ?*anyopaque) callconv(.C) noreturn {
    // Reset to the default handler so that if a segfault happens in this handler it will crash
    // the process. Also when this handler returns, the original instruction will be repeated
    // and the resulting segfault will crash the process rather than continually dump stack traces.
    reset_segfault_handler();

    const addr = switch (native_os) {
        .linux => @int_from_ptr(info.fields.sigfault.addr),
        .freebsd, .macos => @int_from_ptr(info.addr),
        .netbsd => @int_from_ptr(info.info.reason.fault.addr),
        .openbsd => @int_from_ptr(info.data.fault.addr),
        .solaris, .illumos => @int_from_ptr(info.reason.fault.addr),
        else => unreachable,
    };

    const code = if (native_os == .netbsd) info.info.code else info.code;
    nosuspend switch (panic_stage) {
        0 => {
            panic_stage = 1;
            _ = panicking.fetch_add(1, .seq_cst);

            {
                panic_mutex.lock();
                defer panic_mutex.unlock();

                dump_segfault_info_posix(sig, code, addr, ctx_ptr);
            }

            wait_for_other_thread_to_finish_panicking();
        },
        else => {
            // panic mutex already locked
            dump_segfault_info_posix(sig, code, addr, ctx_ptr);
        },
    };

    // We cannot allow the signal handler to return because when it runs the original instruction
    // again, the memory may be mapped and undefined behavior would occur rather than repeating
    // the segfault. So we simply abort here.
    posix.abort();
}

fn dump_segfault_info_posix(sig: i32, code: i32, addr: usize, ctx_ptr: ?*const anyopaque) void {
    const stderr = io.get_std_err().writer();
    _ = switch (sig) {
        posix.SIG.SEGV => if (native_arch == .x86_64 and native_os == .linux and code == 128) // SI_KERNEL
            // x86_64 doesn't have a full 64-bit virtual address space.
            // Addresses outside of that address space are non-canonical
            // and the CPU won't provide the faulting address to us.
            // This happens when accessing memory addresses such as 0xaaaaaaaaaaaaaaaa
            // but can also happen when no addressable memory is involved;
            // for example when reading/writing model-specific registers
            // by executing `rdmsr` or `wrmsr` in user-space (unprivileged mode).
            stderr.print("General protection exception (no address available)\n", .{})
        else
            stderr.print("Segmentation fault at address 0x{x}\n", .{addr}),
        posix.SIG.ILL => stderr.print("Illegal instruction at address 0x{x}\n", .{addr}),
        posix.SIG.BUS => stderr.print("Bus error at address 0x{x}\n", .{addr}),
        posix.SIG.FPE => stderr.print("Arithmetic exception at address 0x{x}\n", .{addr}),
        else => unreachable,
    } catch posix.abort();

    switch (native_arch) {
        .x86,
        .x86_64,
        .arm,
        .aarch64,
        => {
            const ctx: *const posix.ucontext_t = @ptr_cast(@align_cast(ctx_ptr));
            dump_stack_trace_from_base(ctx);
        },
        else => {},
    }
}

fn handle_segfault_windows(info: *windows.EXCEPTION_POINTERS) callconv(windows.WINAPI) c_long {
    switch (info.ExceptionRecord.ExceptionCode) {
        windows.EXCEPTION_DATATYPE_MISALIGNMENT => handle_segfault_windows_extra(info, 0, "Unaligned Memory Access"),
        windows.EXCEPTION_ACCESS_VIOLATION => handle_segfault_windows_extra(info, 1, null),
        windows.EXCEPTION_ILLEGAL_INSTRUCTION => handle_segfault_windows_extra(info, 2, null),
        windows.EXCEPTION_STACK_OVERFLOW => handle_segfault_windows_extra(info, 0, "Stack Overflow"),
        else => return windows.EXCEPTION_CONTINUE_SEARCH,
    }
}

fn handle_segfault_windows_extra(
    info: *windows.EXCEPTION_POINTERS,
    msg: u8,
    label: ?[]const u8,
) noreturn {
    const exception_address = @int_from_ptr(info.ExceptionRecord.ExceptionAddress);
    if (@hasDecl(windows, "CONTEXT")) {
        nosuspend switch (panic_stage) {
            0 => {
                panic_stage = 1;
                _ = panicking.fetch_add(1, .seq_cst);

                {
                    panic_mutex.lock();
                    defer panic_mutex.unlock();

                    dump_segfault_info_windows(info, msg, label);
                }

                wait_for_other_thread_to_finish_panicking();
            },
            else => {
                // panic mutex already locked
                dump_segfault_info_windows(info, msg, label);
            },
        };
        posix.abort();
    } else {
        switch (msg) {
            0 => panic_impl(null, exception_address, "{s}", label.?),
            1 => {
                const format_item = "Segmentation fault at address 0x{x}";
                var buf: [format_item.len + 64]u8 = undefined; // 64 is arbitrary, but sufficiently large
                const to_print = std.fmt.buf_print(buf[0..buf.len], format_item, .{info.ExceptionRecord.ExceptionInformation[1]}) catch unreachable;
                panic_impl(null, exception_address, to_print);
            },
            2 => panic_impl(null, exception_address, "Illegal Instruction"),
            else => unreachable,
        }
    }
}

fn dump_segfault_info_windows(info: *windows.EXCEPTION_POINTERS, msg: u8, label: ?[]const u8) void {
    const stderr = io.get_std_err().writer();
    _ = switch (msg) {
        0 => stderr.print("{s}\n", .{label.?}),
        1 => stderr.print("Segmentation fault at address 0x{x}\n", .{info.ExceptionRecord.ExceptionInformation[1]}),
        2 => stderr.print("Illegal instruction at address 0x{x}\n", .{info.ContextRecord.get_regs().ip}),
        else => unreachable,
    } catch posix.abort();

    dump_stack_trace_from_base(info.ContextRecord);
}

pub fn dump_stack_pointer_addr(prefix: []const u8) void {
    const sp = asm (""
        : [argc] "={rsp}" (-> usize),
    );
    std.debug.print("{} sp = 0x{x}\n", .{ prefix, sp });
}

test "manage resources correctly" {
    if (builtin.strip_debug_info) return error.SkipZigTest;

    if (native_os == .wasi) return error.SkipZigTest;

    if (native_os == .windows) {
        // https://github.com/ziglang/zig/issues/13963
        return error.SkipZigTest;
    }

    const writer = std.io.null_writer;
    var di = try open_self_debug_info(testing.allocator);
    defer di.deinit();
    try print_source_at_address(&di, writer, show_my_trace(), io.tty.detect_config(std.io.get_std_err()));
}

noinline fn show_my_trace() usize {
    return @returnAddress();
}

/// This API helps you track where a value originated and where it was mutated,
/// or any other points of interest.
/// In debug mode, it adds a small size penalty (104 bytes on 64-bit architectures)
/// to the aggregate that you add it to.
/// In release mode, it is size 0 and all methods are no-ops.
/// This is a pre-made type with default settings.
/// For more advanced usage, see `ConfigurableTrace`.
pub const Trace = ConfigurableTrace(2, 4, builtin.mode == .Debug);

pub fn ConfigurableTrace(comptime size: usize, comptime stack_frame_count: usize, comptime is_enabled: bool) type {
    return struct {
        addrs: [actual_size][stack_frame_count]usize,
        notes: [actual_size][]const u8,
        index: Index,

        const actual_size = if (enabled) size else 0;
        const Index = if (enabled) usize else u0;

        pub const init: @This() = .{
            .addrs = undefined,
            .notes = undefined,
            .index = 0,
        };

        pub const enabled = is_enabled;

        pub const add = if (enabled) add_no_inline else add_no_op;

        pub noinline fn add_no_inline(t: *@This(), note: []const u8) void {
            comptime assert(enabled);
            return add_addr(t, @returnAddress(), note);
        }

        pub inline fn add_no_op(t: *@This(), note: []const u8) void {
            _ = t;
            _ = note;
            comptime assert(!enabled);
        }

        pub fn add_addr(t: *@This(), addr: usize, note: []const u8) void {
            if (!enabled) return;

            if (t.index < size) {
                t.notes[t.index] = note;
                t.addrs[t.index] = [1]usize{0} ** stack_frame_count;
                var stack_trace: std.builtin.StackTrace = .{
                    .index = 0,
                    .instruction_addresses = &t.addrs[t.index],
                };
                capture_stack_trace(addr, &stack_trace);
            }
            // Keep counting even if the end is reached so that the
            // user can find out how much more size they need.
            t.index += 1;
        }

        pub fn dump(t: @This()) void {
            if (!enabled) return;

            const tty_config = io.tty.detect_config(std.io.get_std_err());
            const stderr = io.get_std_err().writer();
            const end = @min(t.index, size);
            const debug_info = get_self_debug_info() catch |err| {
                stderr.print(
                    "Unable to dump stack trace: Unable to open debug info: {s}\n",
                    .{@errorName(err)},
                ) catch return;
                return;
            };
            for (t.addrs[0..end], 0..) |frames_array, i| {
                stderr.print("{s}:\n", .{t.notes[i]}) catch return;
                var frames_array_mutable = frames_array;
                const frames = mem.slice_to(frames_array_mutable[0..], 0);
                const stack_trace: std.builtin.StackTrace = .{
                    .index = frames.len,
                    .instruction_addresses = frames,
                };
                write_stack_trace(stack_trace, stderr, get_debug_info_allocator(), debug_info, tty_config) catch continue;
            }
            if (t.index > end) {
                stderr.print("{d} more traces not shown; consider increasing trace size\n", .{
                    t.index - end,
                }) catch return;
            }
        }

        pub fn format(
            t: Trace,
            comptime fmt: []const u8,
            options: std.fmt.FormatOptions,
            writer: anytype,
        ) !void {
            if (fmt.len != 0) std.fmt.invalid_fmt_error(fmt, t);
            _ = options;
            if (enabled) {
                try writer.write_all("\n");
                t.dump();
                try writer.write_all("\n");
            } else {
                return writer.write_all("(value tracing disabled)");
            }
        }
    };
}

pub const SafetyLock = struct {
    state: State = .unlocked,

    pub const State = if (runtime_safety) enum { unlocked, locked } else enum { unlocked };

    pub fn lock(l: *SafetyLock) void {
        if (!runtime_safety) return;
        assert(l.state == .unlocked);
        l.state = .locked;
    }

    pub fn unlock(l: *SafetyLock) void {
        if (!runtime_safety) return;
        assert(l.state == .locked);
        l.state = .unlocked;
    }

    pub fn assert_unlocked(l: SafetyLock) void {
        if (!runtime_safety) return;
        assert(l.state == .unlocked);
    }
};

/// Detect whether the program is being executed in the Valgrind virtual machine.
///
/// When Valgrind integrations are disabled, this returns comptime-known false.
/// Otherwise, the result is runtime-known.
pub inline fn in_valgrind() bool {
    if (@in_comptime()) return false;
    if (!builtin.valgrind_support) return false;
    return std.valgrind.running_on_valgrind() > 0;
}

test {
    _ = &dump_hex;
}
