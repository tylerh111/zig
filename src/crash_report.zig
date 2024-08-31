const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const debug = std.debug;
const io = std.io;
const print_zir = @import("print_zir.zig");
const windows = std.os.windows;
const posix = std.posix;
const native_os = builtin.os.tag;

const Module = @import("Module.zig");
const Sema = @import("Sema.zig");
const Zir = std.zig.Zir;
const Decl = Module.Decl;

/// To use these crash report diagnostics, publish this panic in your main file
/// and add `pub const enable_segfault_handler = false;` to your `std_options`.
/// You will also need to call initialize() on startup, preferably as the very first operation in your program.
pub const panic = if (build_options.enable_debug_extensions) compiler_panic else std.builtin.default_panic;

/// Install signal handlers to identify crashes and report diagnostics.
pub fn initialize() void {
    if (build_options.enable_debug_extensions and debug.have_segfault_handling_support) {
        attach_segfault_handler();
    }
}

pub const AnalyzeBody = if (build_options.enable_debug_extensions) struct {
    parent: ?*AnalyzeBody,
    sema: *Sema,
    block: *Sema.Block,
    body: []const Zir.Inst.Index,
    body_index: usize,

    pub fn push(self: *@This()) void {
        const head = &zir_state;
        debug.assert(self.parent == null);
        self.parent = head.*;
        head.* = self;
    }

    pub fn pop(self: *@This()) void {
        const head = &zir_state;
        const old = head.*.?;
        debug.assert(old == self);
        head.* = old.parent;
    }

    pub fn set_body_index(self: *@This(), index: usize) void {
        self.body_index = index;
    }
} else struct {
    pub inline fn push(_: @This()) void {}
    pub inline fn pop(_: @This()) void {}
    pub inline fn set_body_index(_: @This(), _: usize) void {}
};

threadlocal var zir_state: ?*AnalyzeBody = if (build_options.enable_debug_extensions) null else @compile_error("Cannot use zir_state without debug extensions.");

pub fn prep_analyze_body(sema: *Sema, block: *Sema.Block, body: []const Zir.Inst.Index) AnalyzeBody {
    return if (build_options.enable_debug_extensions) .{
        .parent = null,
        .sema = sema,
        .block = block,
        .body = body,
        .body_index = 0,
    } else .{};
}

fn dump_status_report() !void {
    const anal = zir_state orelse return;
    // Note: We have the panic mutex here, so we can safely use the global crash heap.
    var fba = std.heap.FixedBufferAllocator.init(&crash_heap);
    const allocator = fba.allocator();

    const stderr = io.get_std_err().writer();
    const block: *Sema.Block = anal.block;
    const mod = anal.sema.mod;
    const block_src_decl = mod.decl_ptr(block.src_decl);

    try stderr.write_all("Analyzing ");
    try write_fully_qualified_decl_with_file(mod, block_src_decl, stderr);
    try stderr.write_all("\n");

    print_zir.render_instruction_context(
        allocator,
        anal.body,
        anal.body_index,
        mod.namespace_ptr(block.namespace).file_scope,
        block_src_decl.src_node,
        6, // indent
        stderr,
    ) catch |err| switch (err) {
        error.OutOfMemory => try stderr.write_all("  <out of memory dumping zir>\n"),
        else => |e| return e,
    };
    try stderr.write_all("    For full context, use the command\n      zig ast-check -t ");
    try write_file_path(mod.namespace_ptr(block.namespace).file_scope, stderr);
    try stderr.write_all("\n\n");

    var parent = anal.parent;
    while (parent) |curr| {
        fba.reset();
        try stderr.write_all("  in ");
        const curr_block_src_decl = mod.decl_ptr(curr.block.src_decl);
        try write_fully_qualified_decl_with_file(mod, curr_block_src_decl, stderr);
        try stderr.write_all("\n    > ");
        print_zir.render_single_instruction(
            allocator,
            curr.body[curr.body_index],
            mod.namespace_ptr(curr.block.namespace).file_scope,
            curr_block_src_decl.src_node,
            6, // indent
            stderr,
        ) catch |err| switch (err) {
            error.OutOfMemory => try stderr.write_all("  <out of memory dumping zir>\n"),
            else => |e| return e,
        };
        try stderr.write_all("\n");

        parent = curr.parent;
    }

    try stderr.write_all("\n");
}

var crash_heap: [16 * 4096]u8 = undefined;

fn write_file_path(file: *Module.File, writer: anytype) !void {
    if (file.mod.root.root_dir.path) |path| {
        try writer.write_all(path);
        try writer.write_all(std.fs.path.sep_str);
    }
    if (file.mod.root.sub_path.len > 0) {
        try writer.write_all(file.mod.root.sub_path);
        try writer.write_all(std.fs.path.sep_str);
    }
    try writer.write_all(file.sub_file_path);
}

fn write_fully_qualified_decl_with_file(mod: *Module, decl: *Decl, writer: anytype) !void {
    try write_file_path(decl.get_file_scope(mod), writer);
    try writer.write_all(": ");
    try decl.render_fully_qualified_debug_name(mod, writer);
}

pub fn compiler_panic(msg: []const u8, error_return_trace: ?*std.builtin.StackTrace, maybe_ret_addr: ?usize) noreturn {
    PanicSwitch.pre_dispatch();
    @setCold(true);
    const ret_addr = maybe_ret_addr orelse @returnAddress();
    const stack_ctx: StackContext = .{ .current = .{ .ret_addr = ret_addr } };
    PanicSwitch.dispatch(error_return_trace, stack_ctx, msg);
}

/// Attaches a global SIGSEGV handler
pub fn attach_segfault_handler() void {
    if (!debug.have_segfault_handling_support) {
        @compile_error("segfault handler not supported for this target");
    }
    if (native_os == .windows) {
        _ = windows.kernel32.AddVectoredExceptionHandler(0, handle_segfault_windows);
        return;
    }
    var act: posix.Sigaction = .{
        .handler = .{ .sigaction = handle_segfault_posix },
        .mask = posix.empty_sigset,
        .flags = (posix.SA.SIGINFO | posix.SA.RESTART | posix.SA.RESETHAND),
    };

    debug.update_segfault_handler(&act) catch {
        @panic("unable to install segfault handler, maybe adjust have_segfault_handling_support in std/debug.zig");
    };
}

fn handle_segfault_posix(sig: i32, info: *const posix.siginfo_t, ctx_ptr: ?*anyopaque) callconv(.C) noreturn {
    // TODO: use alarm() here to prevent infinite loops
    PanicSwitch.pre_dispatch();

    const addr = switch (native_os) {
        .linux => @int_from_ptr(info.fields.sigfault.addr),
        .freebsd, .macos => @int_from_ptr(info.addr),
        .netbsd => @int_from_ptr(info.info.reason.fault.addr),
        .openbsd => @int_from_ptr(info.data.fault.addr),
        .solaris, .illumos => @int_from_ptr(info.reason.fault.addr),
        else => @compile_error("TODO implement handle_segfault_posix for new POSIX OS"),
    };

    var err_buffer: [128]u8 = undefined;
    const error_msg = switch (sig) {
        posix.SIG.SEGV => std.fmt.buf_print(&err_buffer, "Segmentation fault at address 0x{x}", .{addr}) catch "Segmentation fault",
        posix.SIG.ILL => std.fmt.buf_print(&err_buffer, "Illegal instruction at address 0x{x}", .{addr}) catch "Illegal instruction",
        posix.SIG.BUS => std.fmt.buf_print(&err_buffer, "Bus error at address 0x{x}", .{addr}) catch "Bus error",
        else => std.fmt.buf_print(&err_buffer, "Unknown error (signal {}) at address 0x{x}", .{ sig, addr }) catch "Unknown error",
    };

    const stack_ctx: StackContext = switch (builtin.cpu.arch) {
        .x86,
        .x86_64,
        .arm,
        .aarch64,
        => StackContext{ .exception = @ptr_cast(@align_cast(ctx_ptr)) },
        else => .not_supported,
    };

    PanicSwitch.dispatch(null, stack_ctx, error_msg);
}

const WindowsSegfaultMessage = union(enum) {
    literal: []const u8,
    segfault: void,
    illegal_instruction: void,
};

fn handle_segfault_windows(info: *windows.EXCEPTION_POINTERS) callconv(windows.WINAPI) c_long {
    switch (info.ExceptionRecord.ExceptionCode) {
        windows.EXCEPTION_DATATYPE_MISALIGNMENT => handle_segfault_windows_extra(info, .{ .literal = "Unaligned Memory Access" }),
        windows.EXCEPTION_ACCESS_VIOLATION => handle_segfault_windows_extra(info, .segfault),
        windows.EXCEPTION_ILLEGAL_INSTRUCTION => handle_segfault_windows_extra(info, .illegal_instruction),
        windows.EXCEPTION_STACK_OVERFLOW => handle_segfault_windows_extra(info, .{ .literal = "Stack Overflow" }),
        else => return windows.EXCEPTION_CONTINUE_SEARCH,
    }
}

fn handle_segfault_windows_extra(info: *windows.EXCEPTION_POINTERS, comptime msg: WindowsSegfaultMessage) noreturn {
    PanicSwitch.pre_dispatch();

    const stack_ctx = if (@hasDecl(windows, "CONTEXT"))
        StackContext{ .exception = info.ContextRecord }
    else ctx: {
        const addr = @int_from_ptr(info.ExceptionRecord.ExceptionAddress);
        break :ctx StackContext{ .current = .{ .ret_addr = addr } };
    };

    switch (msg) {
        .literal => |err| PanicSwitch.dispatch(null, stack_ctx, err),
        .segfault => {
            const format_item = "Segmentation fault at address 0x{x}";
            var buf: [format_item.len + 32]u8 = undefined; // 32 is arbitrary, but sufficiently large
            const to_print = std.fmt.buf_print(&buf, format_item, .{info.ExceptionRecord.ExceptionInformation[1]}) catch unreachable;
            PanicSwitch.dispatch(null, stack_ctx, to_print);
        },
        .illegal_instruction => {
            const ip: ?usize = switch (stack_ctx) {
                .exception => |ex| ex.get_regs().ip,
                .current => |cur| cur.ret_addr,
                .not_supported => null,
            };

            if (ip) |addr| {
                const format_item = "Illegal instruction at address 0x{x}";
                var buf: [format_item.len + 32]u8 = undefined; // 32 is arbitrary, but sufficiently large
                const to_print = std.fmt.buf_print(&buf, format_item, .{addr}) catch unreachable;
                PanicSwitch.dispatch(null, stack_ctx, to_print);
            } else {
                PanicSwitch.dispatch(null, stack_ctx, "Illegal Instruction");
            }
        },
    }
}

const StackContext = union(enum) {
    current: struct {
        ret_addr: ?usize,
    },
    exception: *const debug.ThreadContext,
    not_supported: void,

    pub fn dump_stack_trace(ctx: @This()) void {
        switch (ctx) {
            .current => |ct| {
                debug.dump_current_stack_trace(ct.ret_addr);
            },
            .exception => |context| {
                debug.dump_stack_trace_from_base(context);
            },
            .not_supported => {
                const stderr = io.get_std_err().writer();
                stderr.write_all("Stack trace not supported on this platform.\n") catch {};
            },
        }
    }
};

const PanicSwitch = struct {
    const RecoverStage = enum {
        initialize,
        report_stack,
        release_mutex,
        release_ref_count,
        abort,
        silent_abort,
    };

    const RecoverVerbosity = enum {
        message_and_stack,
        message_only,
        silent,
    };

    const PanicState = struct {
        recover_stage: RecoverStage = .initialize,
        recover_verbosity: RecoverVerbosity = .message_and_stack,
        panic_ctx: StackContext = undefined,
        panic_trace: ?*const std.builtin.StackTrace = null,
        awaiting_dispatch: bool = false,
    };

    /// Counter for the number of threads currently panicking.
    /// Updated atomically before taking the panic_mutex.
    /// In recoverable cases, the program will not abort
    /// until all panicking threads have dumped their traces.
    var panicking = std.atomic.Value(u8).init(0);

    // Locked to avoid interleaving panic messages from multiple threads.
    var panic_mutex = std.Thread.Mutex{};

    /// Tracks the state of the current panic.  If the code within the
    /// panic triggers a secondary panic, this allows us to recover.
    threadlocal var panic_state_raw: PanicState = .{};

    /// The segfault handlers above need to do some work before they can dispatch
    /// this switch.  Calling pre_dispatch() first makes that work fault tolerant.
    pub fn pre_dispatch() void {
        // TODO: We want segfaults to trigger the panic recursively here,
        // but if there is a segfault accessing this TLS slot it will cause an
        // infinite loop.  We should use `alarm()` to prevent the infinite
        // loop and maybe also use a non-thread-local global to detect if
        // it's happening and print a message.
        var panic_state: *volatile PanicState = &panic_state_raw;
        if (panic_state.awaiting_dispatch) {
            dispatch(null, .{ .current = .{ .ret_addr = null } }, "Panic while preparing callstack");
        }
        panic_state.awaiting_dispatch = true;
    }

    /// This is the entry point to a panic-tolerant panic handler.
    /// pre_dispatch() *MUST* be called exactly once before calling this.
    /// A threadlocal "recover_stage" is updated throughout the process.
    /// If a panic happens during the panic, the recover_stage will be
    /// used to select a recover* function to call to resume the panic.
    /// The recover_verbosity field is used to handle panics while reporting
    /// panics within panics.  If the panic handler triggers a panic, it will
    /// attempt to log an additional stack trace for the secondary panic.  If
    /// that panics, it will fall back to just logging the panic message.  If
    /// it can't even do that witout panicing, it will recover without logging
    /// anything about the internal panic.  Depending on the state, "recover"
    /// here may just mean "call abort".
    pub fn dispatch(
        trace: ?*const std.builtin.StackTrace,
        stack_ctx: StackContext,
        msg: []const u8,
    ) noreturn {
        var panic_state: *volatile PanicState = &panic_state_raw;
        debug.assert(panic_state.awaiting_dispatch);
        panic_state.awaiting_dispatch = false;
        nosuspend switch (panic_state.recover_stage) {
            .initialize => go_to(init_panic, .{ panic_state, trace, stack_ctx, msg }),
            .report_stack => go_to(recover_report_stack, .{ panic_state, trace, stack_ctx, msg }),
            .release_mutex => go_to(recover_release_mutex, .{ panic_state, trace, stack_ctx, msg }),
            .release_ref_count => go_to(recover_release_ref_count, .{ panic_state, trace, stack_ctx, msg }),
            .abort => go_to(recover_abort, .{ panic_state, trace, stack_ctx, msg }),
            .silent_abort => go_to(abort, .{}),
        };
    }

    noinline fn init_panic(
        state: *volatile PanicState,
        trace: ?*const std.builtin.StackTrace,
        stack: StackContext,
        msg: []const u8,
    ) noreturn {
        // use a temporary so there's only one volatile store
        const new_state = PanicState{
            .recover_stage = .abort,
            .panic_ctx = stack,
            .panic_trace = trace,
        };
        state.* = new_state;

        _ = panicking.fetch_add(1, .seq_cst);

        state.recover_stage = .release_ref_count;

        panic_mutex.lock();

        state.recover_stage = .release_mutex;

        const stderr = io.get_std_err().writer();
        if (builtin.single_threaded) {
            stderr.print("panic: ", .{}) catch go_to(release_mutex, .{state});
        } else {
            const current_thread_id = std.Thread.get_current_id();
            stderr.print("thread {} panic: ", .{current_thread_id}) catch go_to(release_mutex, .{state});
        }
        stderr.print("{s}\n", .{msg}) catch go_to(release_mutex, .{state});

        state.recover_stage = .report_stack;

        dump_status_report() catch |err| {
            stderr.print("\nIntercepted error.{} while dumping current state.  Continuing...\n", .{err}) catch {};
        };

        go_to(report_stack, .{state});
    }

    noinline fn recover_report_stack(
        state: *volatile PanicState,
        trace: ?*const std.builtin.StackTrace,
        stack: StackContext,
        msg: []const u8,
    ) noreturn {
        recover(state, trace, stack, msg);

        state.recover_stage = .release_mutex;
        const stderr = io.get_std_err().writer();
        stderr.write_all("\nOriginal Error:\n") catch {};
        go_to(report_stack, .{state});
    }

    noinline fn report_stack(state: *volatile PanicState) noreturn {
        state.recover_stage = .release_mutex;

        if (state.panic_trace) |t| {
            debug.dump_stack_trace(t.*);
        }
        state.panic_ctx.dump_stack_trace();

        go_to(release_mutex, .{state});
    }

    noinline fn recover_release_mutex(
        state: *volatile PanicState,
        trace: ?*const std.builtin.StackTrace,
        stack: StackContext,
        msg: []const u8,
    ) noreturn {
        recover(state, trace, stack, msg);
        go_to(release_mutex, .{state});
    }

    noinline fn release_mutex(state: *volatile PanicState) noreturn {
        state.recover_stage = .abort;

        panic_mutex.unlock();

        go_to(release_ref_count, .{state});
    }

    noinline fn recover_release_ref_count(
        state: *volatile PanicState,
        trace: ?*const std.builtin.StackTrace,
        stack: StackContext,
        msg: []const u8,
    ) noreturn {
        recover(state, trace, stack, msg);
        go_to(release_ref_count, .{state});
    }

    noinline fn release_ref_count(state: *volatile PanicState) noreturn {
        state.recover_stage = .abort;

        if (panicking.fetch_sub(1, .seq_cst) != 1) {
            // Another thread is panicking, wait for the last one to finish
            // and call abort()

            // Sleep forever without hammering the CPU
            var futex = std.atomic.Value(u32).init(0);
            while (true) std.Thread.Futex.wait(&futex, 0);

            // This should be unreachable, recurse into recover_abort.
            @panic("event.wait() returned");
        }

        go_to(abort, .{});
    }

    noinline fn recover_abort(
        state: *volatile PanicState,
        trace: ?*const std.builtin.StackTrace,
        stack: StackContext,
        msg: []const u8,
    ) noreturn {
        recover(state, trace, stack, msg);

        state.recover_stage = .silent_abort;
        const stderr = io.get_std_err().writer();
        stderr.write_all("Aborting...\n") catch {};
        go_to(abort, .{});
    }

    noinline fn abort() noreturn {
        std.process.abort();
    }

    inline fn go_to(comptime func: anytype, args: anytype) noreturn {
        // TODO: Tailcall is broken right now, but eventually this should be used
        // to avoid blowing up the stack.  It's ok for now though, there are no
        // cycles in the state machine so the max stack usage is bounded.
        //@call(.always_tail, func, args);
        @call(.auto, func, args);
    }

    fn recover(
        state: *volatile PanicState,
        trace: ?*const std.builtin.StackTrace,
        stack: StackContext,
        msg: []const u8,
    ) void {
        switch (state.recover_verbosity) {
            .message_and_stack => {
                // lower the verbosity, and restore it at the end if we don't panic.
                state.recover_verbosity = .message_only;

                const stderr = io.get_std_err().writer();
                stderr.write_all("\nPanicked during a panic: ") catch {};
                stderr.write_all(msg) catch {};
                stderr.write_all("\nInner panic stack:\n") catch {};
                if (trace) |t| {
                    debug.dump_stack_trace(t.*);
                }
                stack.dump_stack_trace();

                state.recover_verbosity = .message_and_stack;
            },
            .message_only => {
                state.recover_verbosity = .silent;

                const stderr = io.get_std_err().writer();
                stderr.write_all("\nPanicked while dumping inner panic stack: ") catch {};
                stderr.write_all(msg) catch {};
                stderr.write_all("\n") catch {};

                // If we succeed, restore all the way to dumping the stack.
                state.recover_verbosity = .message_and_stack;
            },
            .silent => {},
        }
    }
};
