const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const io = std.io;
const fmt = std.fmt;
const mem = std.mem;
const process = std.process;
const ArrayList = std.ArrayList;
const File = std.fs.File;
const Step = std.Build.Step;

pub const root = @import("@build");
pub const dependencies = @import("@dependencies");

pub fn main() !void {
    // Here we use an ArenaAllocator backed by a page allocator because a build is a short-lived,
    // one shot program. We don't need to waste time freeing memory and finding places to squish
    // bytes into. So we free everything all at once at the very end.
    var single_threaded_arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer single_threaded_arena.deinit();

    var thread_safe_arena: std.heap.ThreadSafeAllocator = .{
        .child_allocator = single_threaded_arena.allocator(),
    };
    const arena = thread_safe_arena.allocator();

    const args = try process.args_alloc(arena);

    // skip my own exe name
    var arg_idx: usize = 1;

    const zig_exe = next_arg(args, &arg_idx) orelse {
        std.debug.print("Expected path to zig compiler\n", .{});
        return error.InvalidArgs;
    };
    const build_root = next_arg(args, &arg_idx) orelse {
        std.debug.print("Expected build root directory path\n", .{});
        return error.InvalidArgs;
    };
    const cache_root = next_arg(args, &arg_idx) orelse {
        std.debug.print("Expected cache root directory path\n", .{});
        return error.InvalidArgs;
    };
    const global_cache_root = next_arg(args, &arg_idx) orelse {
        std.debug.print("Expected global cache root directory path\n", .{});
        return error.InvalidArgs;
    };

    const build_root_directory: std.Build.Cache.Directory = .{
        .path = build_root,
        .handle = try std.fs.cwd().open_dir(build_root, .{}),
    };

    const local_cache_directory: std.Build.Cache.Directory = .{
        .path = cache_root,
        .handle = try std.fs.cwd().make_open_path(cache_root, .{}),
    };

    const global_cache_directory: std.Build.Cache.Directory = .{
        .path = global_cache_root,
        .handle = try std.fs.cwd().make_open_path(global_cache_root, .{}),
    };

    var graph: std.Build.Graph = .{
        .arena = arena,
        .cache = .{
            .gpa = arena,
            .manifest_dir = try local_cache_directory.handle.make_open_path("h", .{}),
        },
        .zig_exe = zig_exe,
        .env_map = try process.get_env_map(arena),
        .global_cache_root = global_cache_directory,
        .host = .{
            .query = .{},
            .result = try std.zig.system.resolve_target_query(.{}),
        },
    };

    graph.cache.add_prefix(.{ .path = null, .handle = std.fs.cwd() });
    graph.cache.add_prefix(build_root_directory);
    graph.cache.add_prefix(local_cache_directory);
    graph.cache.add_prefix(global_cache_directory);
    graph.cache.hash.add_bytes(builtin.zig_version_string);

    const builder = try std.Build.create(
        &graph,
        build_root_directory,
        local_cache_directory,
        dependencies.root_deps,
    );

    var targets = ArrayList([]const u8).init(arena);
    var debug_log_scopes = ArrayList([]const u8).init(arena);
    var thread_pool_options: std.Thread.Pool.Options = .{ .allocator = arena };

    var install_prefix: ?[]const u8 = null;
    var dir_list = std.Build.DirList{};
    var summary: ?Summary = null;
    var max_rss: u64 = 0;
    var skip_oom_steps: bool = false;
    var color: Color = .auto;
    var seed: u32 = 0;
    var prominent_compile_errors: bool = false;
    var help_menu: bool = false;
    var steps_menu: bool = false;
    var output_tmp_nonce: ?[16]u8 = null;

    while (next_arg(args, &arg_idx)) |arg| {
        if (mem.starts_with(u8, arg, "-Z")) {
            if (arg.len != 18) fatal_with_hint("bad argument: '{s}'", .{arg});
            output_tmp_nonce = arg[2..18].*;
        } else if (mem.starts_with(u8, arg, "-D")) {
            const option_contents = arg[2..];
            if (option_contents.len == 0)
                fatal_with_hint("expected option name after '-D'", .{});
            if (mem.index_of_scalar(u8, option_contents, '=')) |name_end| {
                const option_name = option_contents[0..name_end];
                const option_value = option_contents[name_end + 1 ..];
                if (try builder.add_user_input_option(option_name, option_value))
                    fatal("  access the help menu with 'zig build -h'", .{});
            } else {
                if (try builder.add_user_input_flag(option_contents))
                    fatal("  access the help menu with 'zig build -h'", .{});
            }
        } else if (mem.starts_with(u8, arg, "-")) {
            if (mem.eql(u8, arg, "--verbose")) {
                builder.verbose = true;
            } else if (mem.eql(u8, arg, "-h") or mem.eql(u8, arg, "--help")) {
                help_menu = true;
            } else if (mem.eql(u8, arg, "-p") or mem.eql(u8, arg, "--prefix")) {
                install_prefix = next_arg_or_fatal(args, &arg_idx);
            } else if (mem.eql(u8, arg, "-l") or mem.eql(u8, arg, "--list-steps")) {
                steps_menu = true;
            } else if (mem.starts_with(u8, arg, "-fsys=")) {
                const name = arg["-fsys=".len..];
                graph.system_library_options.put(arena, name, .user_enabled) catch @panic("OOM");
            } else if (mem.starts_with(u8, arg, "-fno-sys=")) {
                const name = arg["-fno-sys=".len..];
                graph.system_library_options.put(arena, name, .user_disabled) catch @panic("OOM");
            } else if (mem.eql(u8, arg, "--release")) {
                builder.release_mode = .any;
            } else if (mem.starts_with(u8, arg, "--release=")) {
                const text = arg["--release=".len..];
                builder.release_mode = std.meta.string_to_enum(std.Build.ReleaseMode, text) orelse {
                    fatal_with_hint("expected [off|any|fast|safe|small] in '{s}', found '{s}'", .{
                        arg, text,
                    });
                };
            } else if (mem.eql(u8, arg, "--prefix-lib-dir")) {
                dir_list.lib_dir = next_arg_or_fatal(args, &arg_idx);
            } else if (mem.eql(u8, arg, "--prefix-exe-dir")) {
                dir_list.exe_dir = next_arg_or_fatal(args, &arg_idx);
            } else if (mem.eql(u8, arg, "--prefix-include-dir")) {
                dir_list.include_dir = next_arg_or_fatal(args, &arg_idx);
            } else if (mem.eql(u8, arg, "--sysroot")) {
                builder.sysroot = next_arg_or_fatal(args, &arg_idx);
            } else if (mem.eql(u8, arg, "--maxrss")) {
                const max_rss_text = next_arg_or_fatal(args, &arg_idx);
                max_rss = std.fmt.parse_int_size_suffix(max_rss_text, 10) catch |err| {
                    std.debug.print("invalid byte size: '{s}': {s}\n", .{
                        max_rss_text, @errorName(err),
                    });
                    process.exit(1);
                };
            } else if (mem.eql(u8, arg, "--skip-oom-steps")) {
                skip_oom_steps = true;
            } else if (mem.eql(u8, arg, "--search-prefix")) {
                const search_prefix = next_arg_or_fatal(args, &arg_idx);
                builder.add_search_prefix(search_prefix);
            } else if (mem.eql(u8, arg, "--libc")) {
                builder.libc_file = next_arg_or_fatal(args, &arg_idx);
            } else if (mem.eql(u8, arg, "--color")) {
                const next_arg = next_arg(args, &arg_idx) orelse
                    fatal_with_hint("expected [auto|on|off] after '{s}'", .{arg});
                color = std.meta.string_to_enum(Color, next_arg) orelse {
                    fatal_with_hint("expected [auto|on|off] after '{s}', found '{s}'", .{
                        arg, next_arg,
                    });
                };
            } else if (mem.eql(u8, arg, "--summary")) {
                const next_arg = next_arg(args, &arg_idx) orelse
                    fatal_with_hint("expected [all|new|failures|none] after '{s}'", .{arg});
                summary = std.meta.string_to_enum(Summary, next_arg) orelse {
                    fatal_with_hint("expected [all|failures|none] after '{s}', found '{s}'", .{
                        arg, next_arg,
                    });
                };
            } else if (mem.eql(u8, arg, "--zig-lib-dir")) {
                builder.zig_lib_dir = .{ .cwd_relative = next_arg_or_fatal(args, &arg_idx) };
            } else if (mem.eql(u8, arg, "--seed")) {
                const next_arg = next_arg(args, &arg_idx) orelse
                    fatal_with_hint("expected u32 after '{s}'", .{arg});
                seed = std.fmt.parse_unsigned(u32, next_arg, 0) catch |err| {
                    fatal("unable to parse seed '{s}' as 32-bit integer: {s}\n", .{
                        next_arg, @errorName(err),
                    });
                };
            } else if (mem.eql(u8, arg, "--debug-log")) {
                const next_arg = next_arg_or_fatal(args, &arg_idx);
                try debug_log_scopes.append(next_arg);
            } else if (mem.eql(u8, arg, "--debug-pkg-config")) {
                builder.debug_pkg_config = true;
            } else if (mem.eql(u8, arg, "--debug-compile-errors")) {
                builder.debug_compile_errors = true;
            } else if (mem.eql(u8, arg, "--system")) {
                // The usage text shows another argument after this parameter
                // but it is handled by the parent process. The build runner
                // only sees this flag.
                graph.system_package_mode = true;
            } else if (mem.eql(u8, arg, "--glibc-runtimes")) {
                builder.glibc_runtimes_dir = next_arg_or_fatal(args, &arg_idx);
            } else if (mem.eql(u8, arg, "--verbose-link")) {
                builder.verbose_link = true;
            } else if (mem.eql(u8, arg, "--verbose-air")) {
                builder.verbose_air = true;
            } else if (mem.eql(u8, arg, "--verbose-llvm-ir")) {
                builder.verbose_llvm_ir = "-";
            } else if (mem.starts_with(u8, arg, "--verbose-llvm-ir=")) {
                builder.verbose_llvm_ir = arg["--verbose-llvm-ir=".len..];
            } else if (mem.eql(u8, arg, "--verbose-llvm-bc=")) {
                builder.verbose_llvm_bc = arg["--verbose-llvm-bc=".len..];
            } else if (mem.eql(u8, arg, "--verbose-cimport")) {
                builder.verbose_cimport = true;
            } else if (mem.eql(u8, arg, "--verbose-cc")) {
                builder.verbose_cc = true;
            } else if (mem.eql(u8, arg, "--verbose-llvm-cpu-features")) {
                builder.verbose_llvm_cpu_features = true;
            } else if (mem.eql(u8, arg, "--prominent-compile-errors")) {
                prominent_compile_errors = true;
            } else if (mem.eql(u8, arg, "-fwine")) {
                builder.enable_wine = true;
            } else if (mem.eql(u8, arg, "-fno-wine")) {
                builder.enable_wine = false;
            } else if (mem.eql(u8, arg, "-fqemu")) {
                builder.enable_qemu = true;
            } else if (mem.eql(u8, arg, "-fno-qemu")) {
                builder.enable_qemu = false;
            } else if (mem.eql(u8, arg, "-fwasmtime")) {
                builder.enable_wasmtime = true;
            } else if (mem.eql(u8, arg, "-fno-wasmtime")) {
                builder.enable_wasmtime = false;
            } else if (mem.eql(u8, arg, "-frosetta")) {
                builder.enable_rosetta = true;
            } else if (mem.eql(u8, arg, "-fno-rosetta")) {
                builder.enable_rosetta = false;
            } else if (mem.eql(u8, arg, "-fdarling")) {
                builder.enable_darling = true;
            } else if (mem.eql(u8, arg, "-fno-darling")) {
                builder.enable_darling = false;
            } else if (mem.eql(u8, arg, "-freference-trace")) {
                builder.reference_trace = 256;
            } else if (mem.starts_with(u8, arg, "-freference-trace=")) {
                const num = arg["-freference-trace=".len..];
                builder.reference_trace = std.fmt.parse_unsigned(u32, num, 10) catch |err| {
                    std.debug.print("unable to parse reference_trace count '{s}': {s}", .{ num, @errorName(err) });
                    process.exit(1);
                };
            } else if (mem.eql(u8, arg, "-fno-reference-trace")) {
                builder.reference_trace = null;
            } else if (mem.starts_with(u8, arg, "-j")) {
                const num = arg["-j".len..];
                const n_jobs = std.fmt.parse_unsigned(u32, num, 10) catch |err| {
                    std.debug.print("unable to parse jobs count '{s}': {s}", .{
                        num, @errorName(err),
                    });
                    process.exit(1);
                };
                if (n_jobs < 1) {
                    std.debug.print("number of jobs must be at least 1\n", .{});
                    process.exit(1);
                }
                thread_pool_options.n_jobs = n_jobs;
            } else if (mem.eql(u8, arg, "--")) {
                builder.args = args_rest(args, arg_idx);
                break;
            } else {
                fatal_with_hint("unrecognized argument: '{s}'", .{arg});
            }
        } else {
            try targets.append(arg);
        }
    }

    const stderr = std.io.get_std_err();
    const ttyconf = get_tty_conf(color, stderr);
    switch (ttyconf) {
        .no_color => try graph.env_map.put("NO_COLOR", "1"),
        .escape_codes => try graph.env_map.put("CLICOLOR_FORCE", "1"),
        .windows_api => {},
    }

    const main_progress_node = std.Progress.start(.{
        .disable_printing = (color == .off),
    });

    builder.debug_log_scopes = debug_log_scopes.items;
    builder.resolve_install_prefix(install_prefix, dir_list);
    {
        var prog_node = main_progress_node.start("Configure", 0);
        defer prog_node.end();
        try builder.run_build(root);
    }

    if (graph.needed_lazy_dependencies.entries.len != 0) {
        var buffer: std.ArrayListUnmanaged(u8) = .{};
        for (graph.needed_lazy_dependencies.keys()) |k| {
            try buffer.append_slice(arena, k);
            try buffer.append(arena, '\n');
        }
        const s = std.fs.path.sep_str;
        const tmp_sub_path = "tmp" ++ s ++ (output_tmp_nonce orelse fatal("missing -Z arg", .{}));
        local_cache_directory.handle.write_file(.{
            .sub_path = tmp_sub_path,
            .data = buffer.items,
            .flags = .{ .exclusive = true },
        }) catch |err| {
            fatal("unable to write configuration results to '{}{s}': {s}", .{
                local_cache_directory, tmp_sub_path, @errorName(err),
            });
        };
        process.exit(3); // Indicate configure phase failed with meaningful stdout.
    }

    if (builder.validate_user_input_did_it_fail()) {
        fatal("  access the help menu with 'zig build -h'", .{});
    }

    validate_system_library_options(builder);

    const stdout_writer = io.get_std_out().writer();

    if (help_menu)
        return usage(builder, stdout_writer);

    if (steps_menu)
        return steps(builder, stdout_writer);

    var run: Run = .{
        .max_rss = max_rss,
        .max_rss_is_default = false,
        .max_rss_mutex = .{},
        .skip_oom_steps = skip_oom_steps,
        .memory_blocked_steps = std.ArrayList(*Step).init(arena),
        .prominent_compile_errors = prominent_compile_errors,

        .claimed_rss = 0,
        .summary = summary,
        .ttyconf = ttyconf,
        .stderr = stderr,
    };

    if (run.max_rss == 0) {
        run.max_rss = process.total_system_memory() catch std.math.max_int(u64);
        run.max_rss_is_default = true;
    }

    run_step_names(
        arena,
        builder,
        targets.items,
        main_progress_node,
        thread_pool_options,
        &run,
        seed,
    ) catch |err| switch (err) {
        error.UncleanExit => process.exit(1),
        else => return err,
    };
}

const Run = struct {
    max_rss: u64,
    max_rss_is_default: bool,
    max_rss_mutex: std.Thread.Mutex,
    skip_oom_steps: bool,
    memory_blocked_steps: std.ArrayList(*Step),
    prominent_compile_errors: bool,

    claimed_rss: usize,
    summary: ?Summary,
    ttyconf: std.io.tty.Config,
    stderr: File,
};

fn run_step_names(
    arena: std.mem.Allocator,
    b: *std.Build,
    step_names: []const []const u8,
    parent_prog_node: std.Progress.Node,
    thread_pool_options: std.Thread.Pool.Options,
    run: *Run,
    seed: u32,
) !void {
    const gpa = b.allocator;
    var step_stack: std.AutoArrayHashMapUnmanaged(*Step, void) = .{};
    defer step_stack.deinit(gpa);

    if (step_names.len == 0) {
        try step_stack.put(gpa, b.default_step, {});
    } else {
        try step_stack.ensure_unused_capacity(gpa, step_names.len);
        for (0..step_names.len) |i| {
            const step_name = step_names[step_names.len - i - 1];
            const s = b.top_level_steps.get(step_name) orelse {
                std.debug.print("no step named '{s}'\n  access the help menu with 'zig build -h'\n", .{step_name});
                process.exit(1);
            };
            step_stack.put_assume_capacity(&s.step, {});
        }
    }

    const starting_steps = try arena.dupe(*Step, step_stack.keys());

    var rng = std.Random.DefaultPrng.init(seed);
    const rand = rng.random();
    rand.shuffle(*Step, starting_steps);

    for (starting_steps) |s| {
        construct_graph_and_check_for_dependency_loop(b, s, &step_stack, rand) catch |err| switch (err) {
            error.DependencyLoopDetected => return error.UncleanExit,
            else => |e| return e,
        };
    }

    {
        // Check that we have enough memory to complete the build.
        var any_problems = false;
        for (step_stack.keys()) |s| {
            if (s.max_rss == 0) continue;
            if (s.max_rss > run.max_rss) {
                if (run.skip_oom_steps) {
                    s.state = .skipped_oom;
                } else {
                    std.debug.print("{s}{s}: this step declares an upper bound of {d} bytes of memory, exceeding the available {d} bytes of memory\n", .{
                        s.owner.dep_prefix, s.name, s.max_rss, run.max_rss,
                    });
                    any_problems = true;
                }
            }
        }
        if (any_problems) {
            if (run.max_rss_is_default) {
                std.debug.print("note: use --maxrss to override the default", .{});
            }
            return error.UncleanExit;
        }
    }

    var thread_pool: std.Thread.Pool = undefined;
    try thread_pool.init(thread_pool_options);
    defer thread_pool.deinit();

    {
        defer parent_prog_node.end();

        const step_prog = parent_prog_node.start("steps", step_stack.count());
        defer step_prog.end();

        var wait_group: std.Thread.WaitGroup = .{};
        defer wait_group.wait();

        // Here we spawn the initial set of tasks with a nice heuristic -
        // dependency order. Each worker when it finishes a step will then
        // check whether it should run any dependants.
        const steps_slice = step_stack.keys();
        for (0..steps_slice.len) |i| {
            const step = steps_slice[steps_slice.len - i - 1];
            if (step.state == .skipped_oom) continue;

            thread_pool.spawn_wg(&wait_group, worker_make_one_step, .{
                &wait_group, &thread_pool, b, step, step_prog, run,
            });
        }
    }
    assert(run.memory_blocked_steps.items.len == 0);

    var test_skip_count: usize = 0;
    var test_fail_count: usize = 0;
    var test_pass_count: usize = 0;
    var test_leak_count: usize = 0;
    var test_count: usize = 0;

    var success_count: usize = 0;
    var skipped_count: usize = 0;
    var failure_count: usize = 0;
    var pending_count: usize = 0;
    var total_compile_errors: usize = 0;
    var compile_error_steps: std.ArrayListUnmanaged(*Step) = .{};
    defer compile_error_steps.deinit(gpa);

    for (step_stack.keys()) |s| {
        test_fail_count += s.test_results.fail_count;
        test_skip_count += s.test_results.skip_count;
        test_leak_count += s.test_results.leak_count;
        test_pass_count += s.test_results.pass_count();
        test_count += s.test_results.test_count;

        switch (s.state) {
            .precheck_unstarted => unreachable,
            .precheck_started => unreachable,
            .running => unreachable,
            .precheck_done => {
                // precheck_done is equivalent to dependency_failure in the case of
                // transitive dependencies. For example:
                // A -> B -> C (failure)
                // B will be marked as dependency_failure, while A may never be queued, and thus
                // remain in the initial state of precheck_done.
                s.state = .dependency_failure;
                pending_count += 1;
            },
            .dependency_failure => pending_count += 1,
            .success => success_count += 1,
            .skipped, .skipped_oom => skipped_count += 1,
            .failure => {
                failure_count += 1;
                const compile_errors_len = s.result_error_bundle.error_message_count();
                if (compile_errors_len > 0) {
                    total_compile_errors += compile_errors_len;
                    try compile_error_steps.append(gpa, s);
                }
            },
        }
    }

    // A proper command line application defaults to silently succeeding.
    // The user may request verbose mode if they have a different preference.
    const failures_only = run.summary != .all and run.summary != .new;
    if (failure_count == 0 and failures_only) return clean_exit();

    const ttyconf = run.ttyconf;
    const stderr = run.stderr;

    if (run.summary != Summary.none) {
        const total_count = success_count + failure_count + pending_count + skipped_count;
        ttyconf.set_color(stderr, .cyan) catch {};
        stderr.write_all("Build Summary:") catch {};
        ttyconf.set_color(stderr, .reset) catch {};
        stderr.writer().print(" {d}/{d} steps succeeded", .{ success_count, total_count }) catch {};
        if (skipped_count > 0) stderr.writer().print("; {d} skipped", .{skipped_count}) catch {};
        if (failure_count > 0) stderr.writer().print("; {d} failed", .{failure_count}) catch {};

        if (test_count > 0) stderr.writer().print("; {d}/{d} tests passed", .{ test_pass_count, test_count }) catch {};
        if (test_skip_count > 0) stderr.writer().print("; {d} skipped", .{test_skip_count}) catch {};
        if (test_fail_count > 0) stderr.writer().print("; {d} failed", .{test_fail_count}) catch {};
        if (test_leak_count > 0) stderr.writer().print("; {d} leaked", .{test_leak_count}) catch {};

        if (run.summary == null) {
            ttyconf.set_color(stderr, .dim) catch {};
            stderr.write_all(" (disable with --summary none)") catch {};
            ttyconf.set_color(stderr, .reset) catch {};
        }
        stderr.write_all("\n") catch {};

        // Print a fancy tree with build results.
        var print_node: PrintNode = .{ .parent = null };
        if (step_names.len == 0) {
            print_node.last = true;
            print_tree_step(b, b.default_step, run, stderr, ttyconf, &print_node, &step_stack) catch {};
        } else {
            const last_index = if (run.summary == .all) b.top_level_steps.count() else blk: {
                var i: usize = step_names.len;
                while (i > 0) {
                    i -= 1;
                    const step = b.top_level_steps.get(step_names[i]).?.step;
                    const found = switch (run.summary orelse .failures) {
                        .all, .none => unreachable,
                        .failures => step.state != .success,
                        .new => !step.result_cached,
                    };
                    if (found) break :blk i;
                }
                break :blk b.top_level_steps.count();
            };
            for (step_names, 0..) |step_name, i| {
                const tls = b.top_level_steps.get(step_name).?;
                print_node.last = i + 1 == last_index;
                print_tree_step(b, &tls.step, run, stderr, ttyconf, &print_node, &step_stack) catch {};
            }
        }
    }

    if (failure_count == 0) return clean_exit();

    // Finally, render compile errors at the bottom of the terminal.
    // We use a separate compile_error_steps array list because step_stack is destructively
    // mutated in print_tree_step above.
    if (run.prominent_compile_errors and total_compile_errors > 0) {
        for (compile_error_steps.items) |s| {
            if (s.result_error_bundle.error_message_count() > 0) {
                s.result_error_bundle.render_to_std_err(render_options(ttyconf));
            }
        }

        // Signal to parent process that we have printed compile errors. The
        // parent process may choose to omit the "following command failed"
        // line in this case.
        process.exit(2);
    }

    process.exit(1);
}

const PrintNode = struct {
    parent: ?*PrintNode,
    last: bool = false,
};

fn print_prefix(node: *PrintNode, stderr: File, ttyconf: std.io.tty.Config) !void {
    const parent = node.parent orelse return;
    if (parent.parent == null) return;
    try print_prefix(parent, stderr, ttyconf);
    if (parent.last) {
        try stderr.write_all("   ");
    } else {
        try stderr.write_all(switch (ttyconf) {
            .no_color, .windows_api => "|  ",
            .escape_codes => "\x1B\x28\x30\x78\x1B\x28\x42  ", // │
        });
    }
}

fn print_child_node_prefix(stderr: File, ttyconf: std.io.tty.Config) !void {
    try stderr.write_all(switch (ttyconf) {
        .no_color, .windows_api => "+- ",
        .escape_codes => "\x1B\x28\x30\x6d\x71\x1B\x28\x42 ", // └─
    });
}

fn print_step_status(
    s: *Step,
    stderr: File,
    ttyconf: std.io.tty.Config,
    run: *const Run,
) !void {
    switch (s.state) {
        .precheck_unstarted => unreachable,
        .precheck_started => unreachable,
        .precheck_done => unreachable,
        .running => unreachable,

        .dependency_failure => {
            try ttyconf.set_color(stderr, .dim);
            try stderr.write_all(" transitive failure\n");
            try ttyconf.set_color(stderr, .reset);
        },

        .success => {
            try ttyconf.set_color(stderr, .green);
            if (s.result_cached) {
                try stderr.write_all(" cached");
            } else if (s.test_results.test_count > 0) {
                const pass_count = s.test_results.pass_count();
                try stderr.writer().print(" {d} passed", .{pass_count});
                if (s.test_results.skip_count > 0) {
                    try ttyconf.set_color(stderr, .yellow);
                    try stderr.writer().print(" {d} skipped", .{s.test_results.skip_count});
                }
            } else {
                try stderr.write_all(" success");
            }
            try ttyconf.set_color(stderr, .reset);
            if (s.result_duration_ns) |ns| {
                try ttyconf.set_color(stderr, .dim);
                if (ns >= std.time.ns_per_min) {
                    try stderr.writer().print(" {d}m", .{ns / std.time.ns_per_min});
                } else if (ns >= std.time.ns_per_s) {
                    try stderr.writer().print(" {d}s", .{ns / std.time.ns_per_s});
                } else if (ns >= std.time.ns_per_ms) {
                    try stderr.writer().print(" {d}ms", .{ns / std.time.ns_per_ms});
                } else if (ns >= std.time.ns_per_us) {
                    try stderr.writer().print(" {d}us", .{ns / std.time.ns_per_us});
                } else {
                    try stderr.writer().print(" {d}ns", .{ns});
                }
                try ttyconf.set_color(stderr, .reset);
            }
            if (s.result_peak_rss != 0) {
                const rss = s.result_peak_rss;
                try ttyconf.set_color(stderr, .dim);
                if (rss >= 1000_000_000) {
                    try stderr.writer().print(" MaxRSS:{d}G", .{rss / 1000_000_000});
                } else if (rss >= 1000_000) {
                    try stderr.writer().print(" MaxRSS:{d}M", .{rss / 1000_000});
                } else if (rss >= 1000) {
                    try stderr.writer().print(" MaxRSS:{d}K", .{rss / 1000});
                } else {
                    try stderr.writer().print(" MaxRSS:{d}B", .{rss});
                }
                try ttyconf.set_color(stderr, .reset);
            }
            try stderr.write_all("\n");
        },
        .skipped, .skipped_oom => |skip| {
            try ttyconf.set_color(stderr, .yellow);
            try stderr.write_all(" skipped");
            if (skip == .skipped_oom) {
                try stderr.write_all(" (not enough memory)");
                try ttyconf.set_color(stderr, .dim);
                try stderr.writer().print(" upper bound of {d} exceeded runner limit ({d})", .{ s.max_rss, run.max_rss });
                try ttyconf.set_color(stderr, .yellow);
            }
            try stderr.write_all("\n");
            try ttyconf.set_color(stderr, .reset);
        },
        .failure => try print_step_failure(s, stderr, ttyconf),
    }
}

fn print_step_failure(
    s: *Step,
    stderr: File,
    ttyconf: std.io.tty.Config,
) !void {
    if (s.result_error_bundle.error_message_count() > 0) {
        try ttyconf.set_color(stderr, .red);
        try stderr.writer().print(" {d} errors\n", .{
            s.result_error_bundle.error_message_count(),
        });
        try ttyconf.set_color(stderr, .reset);
    } else if (!s.test_results.is_success()) {
        try stderr.writer().print(" {d}/{d} passed", .{
            s.test_results.pass_count(), s.test_results.test_count,
        });
        if (s.test_results.fail_count > 0) {
            try stderr.write_all(", ");
            try ttyconf.set_color(stderr, .red);
            try stderr.writer().print("{d} failed", .{
                s.test_results.fail_count,
            });
            try ttyconf.set_color(stderr, .reset);
        }
        if (s.test_results.skip_count > 0) {
            try stderr.write_all(", ");
            try ttyconf.set_color(stderr, .yellow);
            try stderr.writer().print("{d} skipped", .{
                s.test_results.skip_count,
            });
            try ttyconf.set_color(stderr, .reset);
        }
        if (s.test_results.leak_count > 0) {
            try stderr.write_all(", ");
            try ttyconf.set_color(stderr, .red);
            try stderr.writer().print("{d} leaked", .{
                s.test_results.leak_count,
            });
            try ttyconf.set_color(stderr, .reset);
        }
        try stderr.write_all("\n");
    } else if (s.result_error_msgs.items.len > 0) {
        try ttyconf.set_color(stderr, .red);
        try stderr.write_all(" failure\n");
        try ttyconf.set_color(stderr, .reset);
    } else {
        assert(s.result_stderr.len > 0);
        try ttyconf.set_color(stderr, .red);
        try stderr.write_all(" stderr\n");
        try ttyconf.set_color(stderr, .reset);
    }
}

fn print_tree_step(
    b: *std.Build,
    s: *Step,
    run: *const Run,
    stderr: File,
    ttyconf: std.io.tty.Config,
    parent_node: *PrintNode,
    step_stack: *std.AutoArrayHashMapUnmanaged(*Step, void),
) !void {
    const first = step_stack.swap_remove(s);
    const summary = run.summary orelse .failures;
    const skip = switch (summary) {
        .none => unreachable,
        .all => false,
        .new => s.result_cached,
        .failures => s.state == .success,
    };
    if (skip) return;
    try print_prefix(parent_node, stderr, ttyconf);

    if (!first) try ttyconf.set_color(stderr, .dim);
    if (parent_node.parent != null) {
        if (parent_node.last) {
            try print_child_node_prefix(stderr, ttyconf);
        } else {
            try stderr.write_all(switch (ttyconf) {
                .no_color, .windows_api => "+- ",
                .escape_codes => "\x1B\x28\x30\x74\x71\x1B\x28\x42 ", // ├─
            });
        }
    }

    // dep_prefix omitted here because it is redundant with the tree.
    try stderr.write_all(s.name);

    if (first) {
        try print_step_status(s, stderr, ttyconf, run);

        const last_index = if (summary == .all) s.dependencies.items.len -| 1 else blk: {
            var i: usize = s.dependencies.items.len;
            while (i > 0) {
                i -= 1;

                const step = s.dependencies.items[i];
                const found = switch (summary) {
                    .all, .none => unreachable,
                    .failures => step.state != .success,
                    .new => !step.result_cached,
                };
                if (found) break :blk i;
            }
            break :blk s.dependencies.items.len -| 1;
        };
        for (s.dependencies.items, 0..) |dep, i| {
            var print_node: PrintNode = .{
                .parent = parent_node,
                .last = i == last_index,
            };
            try print_tree_step(b, dep, run, stderr, ttyconf, &print_node, step_stack);
        }
    } else {
        if (s.dependencies.items.len == 0) {
            try stderr.write_all(" (reused)\n");
        } else {
            try stderr.writer().print(" (+{d} more reused dependencies)\n", .{
                s.dependencies.items.len,
            });
        }
        try ttyconf.set_color(stderr, .reset);
    }
}

/// Traverse the dependency graph depth-first and make it undirected by having
/// steps know their dependants (they only know dependencies at start).
/// Along the way, check that there is no dependency loop, and record the steps
/// in traversal order in `step_stack`.
/// Each step has its dependencies traversed in random order, this accomplishes
/// two things:
/// - `step_stack` will be in randomized-depth-first order, so the build runner
///   spawns steps in a random (but optimized) order
/// - each step's `dependants` list is also filled in a random order, so that
///   when it finishes executing in `worker_make_one_step`, it spawns next steps
///   to run in random order
fn construct_graph_and_check_for_dependency_loop(
    b: *std.Build,
    s: *Step,
    step_stack: *std.AutoArrayHashMapUnmanaged(*Step, void),
    rand: std.Random,
) !void {
    switch (s.state) {
        .precheck_started => {
            std.debug.print("dependency loop detected:\n  {s}\n", .{s.name});
            return error.DependencyLoopDetected;
        },
        .precheck_unstarted => {
            s.state = .precheck_started;

            try step_stack.ensure_unused_capacity(b.allocator, s.dependencies.items.len);

            // We dupe to avoid shuffling the steps in the summary, it depends
            // on s.dependencies' order.
            const deps = b.allocator.dupe(*Step, s.dependencies.items) catch @panic("OOM");
            rand.shuffle(*Step, deps);

            for (deps) |dep| {
                try step_stack.put(b.allocator, dep, {});
                try dep.dependants.append(b.allocator, s);
                construct_graph_and_check_for_dependency_loop(b, dep, step_stack, rand) catch |err| {
                    if (err == error.DependencyLoopDetected) {
                        std.debug.print("  {s}\n", .{s.name});
                    }
                    return err;
                };
            }

            s.state = .precheck_done;
        },
        .precheck_done => {},

        // These don't happen until we actually run the step graph.
        .dependency_failure => unreachable,
        .running => unreachable,
        .success => unreachable,
        .failure => unreachable,
        .skipped => unreachable,
        .skipped_oom => unreachable,
    }
}

fn worker_make_one_step(
    wg: *std.Thread.WaitGroup,
    thread_pool: *std.Thread.Pool,
    b: *std.Build,
    s: *Step,
    prog_node: std.Progress.Node,
    run: *Run,
) void {
    // First, check the conditions for running this step. If they are not met,
    // then we return without doing the step, relying on another worker to
    // queue this step up again when dependencies are met.
    for (s.dependencies.items) |dep| {
        switch (@atomicLoad(Step.State, &dep.state, .seq_cst)) {
            .success, .skipped => continue,
            .failure, .dependency_failure, .skipped_oom => {
                @atomicStore(Step.State, &s.state, .dependency_failure, .seq_cst);
                return;
            },
            .precheck_done, .running => {
                // dependency is not finished yet.
                return;
            },
            .precheck_unstarted => unreachable,
            .precheck_started => unreachable,
        }
    }

    if (s.max_rss != 0) {
        run.max_rss_mutex.lock();
        defer run.max_rss_mutex.unlock();

        // Avoid running steps twice.
        if (s.state != .precheck_done) {
            // Another worker got the job.
            return;
        }

        const new_claimed_rss = run.claimed_rss + s.max_rss;
        if (new_claimed_rss > run.max_rss) {
            // Running this step right now could possibly exceed the allotted RSS.
            // Add this step to the queue of memory-blocked steps.
            run.memory_blocked_steps.append(s) catch @panic("OOM");
            return;
        }

        run.claimed_rss = new_claimed_rss;
        s.state = .running;
    } else {
        // Avoid running steps twice.
        if (@cmpxchg_strong(Step.State, &s.state, .precheck_done, .running, .seq_cst, .seq_cst) != null) {
            // Another worker got the job.
            return;
        }
    }

    const sub_prog_node = prog_node.start(s.name, 0);
    defer sub_prog_node.end();

    const make_result = s.make(sub_prog_node);

    // No matter the result, we want to display error/warning messages.
    const show_compile_errors = !run.prominent_compile_errors and
        s.result_error_bundle.error_message_count() > 0;
    const show_error_msgs = s.result_error_msgs.items.len > 0;
    const show_stderr = s.result_stderr.len > 0;

    if (show_error_msgs or show_compile_errors or show_stderr) {
        std.debug.lock_std_err();
        defer std.debug.unlock_std_err();

        print_error_messages(b, s, run) catch {};
    }

    handle_result: {
        if (make_result) |_| {
            @atomicStore(Step.State, &s.state, .success, .seq_cst);
        } else |err| switch (err) {
            error.MakeFailed => {
                @atomicStore(Step.State, &s.state, .failure, .seq_cst);
                break :handle_result;
            },
            error.MakeSkipped => @atomicStore(Step.State, &s.state, .skipped, .seq_cst),
        }

        // Successful completion of a step, so we queue up its dependants as well.
        for (s.dependants.items) |dep| {
            thread_pool.spawn_wg(wg, worker_make_one_step, .{
                wg, thread_pool, b, dep, prog_node, run,
            });
        }
    }

    // If this is a step that claims resources, we must now queue up other
    // steps that are waiting for resources.
    if (s.max_rss != 0) {
        run.max_rss_mutex.lock();
        defer run.max_rss_mutex.unlock();

        // Give the memory back to the scheduler.
        run.claimed_rss -= s.max_rss;
        // Avoid kicking off too many tasks that we already know will not have
        // enough resources.
        var remaining = run.max_rss - run.claimed_rss;
        var i: usize = 0;
        var j: usize = 0;
        while (j < run.memory_blocked_steps.items.len) : (j += 1) {
            const dep = run.memory_blocked_steps.items[j];
            assert(dep.max_rss != 0);
            if (dep.max_rss <= remaining) {
                remaining -= dep.max_rss;

                thread_pool.spawn_wg(wg, worker_make_one_step, .{
                    wg, thread_pool, b, dep, prog_node, run,
                });
            } else {
                run.memory_blocked_steps.items[i] = dep;
                i += 1;
            }
        }
        run.memory_blocked_steps.shrink_retaining_capacity(i);
    }
}

fn print_error_messages(b: *std.Build, failing_step: *Step, run: *const Run) !void {
    const gpa = b.allocator;
    const stderr = run.stderr;
    const ttyconf = run.ttyconf;

    // Provide context for where these error messages are coming from by
    // printing the corresponding Step subtree.

    var step_stack: std.ArrayListUnmanaged(*Step) = .{};
    defer step_stack.deinit(gpa);
    try step_stack.append(gpa, failing_step);
    while (step_stack.items[step_stack.items.len - 1].dependants.items.len != 0) {
        try step_stack.append(gpa, step_stack.items[step_stack.items.len - 1].dependants.items[0]);
    }

    // Now, `step_stack` has the subtree that we want to print, in reverse order.
    try ttyconf.set_color(stderr, .dim);
    var indent: usize = 0;
    while (step_stack.pop_or_null()) |s| : (indent += 1) {
        if (indent > 0) {
            try stderr.writer().write_byte_ntimes(' ', (indent - 1) * 3);
            try print_child_node_prefix(stderr, ttyconf);
        }

        try stderr.write_all(s.name);

        if (s == failing_step) {
            try print_step_failure(s, stderr, ttyconf);
        } else {
            try stderr.write_all("\n");
        }
    }
    try ttyconf.set_color(stderr, .reset);

    if (failing_step.result_stderr.len > 0) {
        try stderr.write_all(failing_step.result_stderr);
        if (!mem.ends_with(u8, failing_step.result_stderr, "\n")) {
            try stderr.write_all("\n");
        }
    }

    if (!run.prominent_compile_errors and failing_step.result_error_bundle.error_message_count() > 0)
        try failing_step.result_error_bundle.render_to_writer(render_options(ttyconf), stderr.writer());

    for (failing_step.result_error_msgs.items) |msg| {
        try ttyconf.set_color(stderr, .red);
        try stderr.write_all("error: ");
        try ttyconf.set_color(stderr, .reset);
        try stderr.write_all(msg);
        try stderr.write_all("\n");
    }
}

fn steps(builder: *std.Build, out_stream: anytype) !void {
    const allocator = builder.allocator;
    for (builder.top_level_steps.values()) |top_level_step| {
        const name = if (&top_level_step.step == builder.default_step)
            try fmt.alloc_print(allocator, "{s} (default)", .{top_level_step.step.name})
        else
            top_level_step.step.name;
        try out_stream.print("  {s:<28} {s}\n", .{ name, top_level_step.description });
    }
}

fn usage(b: *std.Build, out_stream: anytype) !void {
    try out_stream.print(
        \\Usage: {s} build [steps] [options]
        \\
        \\Steps:
        \\
    , .{b.graph.zig_exe});
    try steps(b, out_stream);

    try out_stream.write_all(
        \\
        \\General Options:
        \\  -p, --prefix [path]          Where to install files (default: zig-out)
        \\  --prefix-lib-dir [path]      Where to install libraries
        \\  --prefix-exe-dir [path]      Where to install executables
        \\  --prefix-include-dir [path]  Where to install C header files
        \\
        \\  --release[=mode]             Request release mode, optionally specifying a
        \\                               preferred optimization mode: fast, safe, small
        \\
        \\  -fdarling,  -fno-darling     Integration with system-installed Darling to
        \\                               execute macOS programs on Linux hosts
        \\                               (default: no)
        \\  -fqemu,     -fno-qemu        Integration with system-installed QEMU to execute
        \\                               foreign-architecture programs on Linux hosts
        \\                               (default: no)
        \\  --glibc-runtimes [path]      Enhances QEMU integration by providing glibc built
        \\                               for multiple foreign architectures, allowing
        \\                               execution of non-native programs that link with glibc.
        \\  -frosetta,  -fno-rosetta     Rely on Rosetta to execute x86_64 programs on
        \\                               ARM64 macOS hosts. (default: no)
        \\  -fwasmtime, -fno-wasmtime    Integration with system-installed wasmtime to
        \\                               execute WASI binaries. (default: no)
        \\  -fwine,     -fno-wine        Integration with system-installed Wine to execute
        \\                               Windows programs on Linux hosts. (default: no)
        \\
        \\  -h, --help                   Print this help and exit
        \\  -l, --list-steps             Print available steps
        \\  --verbose                    Print commands before executing them
        \\  --color [auto|off|on]        Enable or disable colored error messages
        \\  --prominent-compile-errors   Buffer compile errors and display at end
        \\  --summary [mode]             Control the printing of the build summary
        \\    all                        Print the build summary in its entirety
        \\    new                        Omit cached steps
        \\    failures                   (Default) Only print failed steps
        \\    none                       Do not print the build summary
        \\  -j<N>                        Limit concurrent jobs (default is to use all CPU cores)
        \\  --maxrss <bytes>             Limit memory usage (default is to use available memory)
        \\  --skip-oom-steps             Instead of failing, skip steps that would exceed --maxrss
        \\  --fetch                      Exit after fetching dependency tree
        \\
        \\Project-Specific Options:
        \\
    );

    const arena = b.allocator;
    if (b.available_options_list.items.len == 0) {
        try out_stream.print("  (none)\n", .{});
    } else {
        for (b.available_options_list.items) |option| {
            const name = try fmt.alloc_print(arena, "  -D{s}=[{s}]", .{
                option.name,
                @tag_name(option.type_id),
            });
            try out_stream.print("{s:<30} {s}\n", .{ name, option.description });
            if (option.enum_options) |enum_options| {
                const padding = " " ** 33;
                try out_stream.write_all(padding ++ "Supported Values:\n");
                for (enum_options) |enum_option| {
                    try out_stream.print(padding ++ "  {s}\n", .{enum_option});
                }
            }
        }
    }

    try out_stream.write_all(
        \\
        \\System Integration Options:
        \\  --search-prefix [path]       Add a path to look for binaries, libraries, headers
        \\  --sysroot [path]             Set the system root directory (usually /)
        \\  --libc [file]                Provide a file which specifies libc paths
        \\
        \\  --system [pkgdir]            Disable package fetching; enable all integrations
        \\  -fsys=[name]                 Enable a system integration
        \\  -fno-sys=[name]              Disable a system integration
        \\
        \\  Available System Integrations:                Enabled:
        \\
    );
    if (b.graph.system_library_options.entries.len == 0) {
        try out_stream.write_all("  (none)                                        -\n");
    } else {
        for (b.graph.system_library_options.keys(), b.graph.system_library_options.values()) |k, v| {
            const status = switch (v) {
                .declared_enabled => "yes",
                .declared_disabled => "no",
                .user_enabled, .user_disabled => unreachable, // already emitted error
            };
            try out_stream.print("    {s:<43} {s}\n", .{ k, status });
        }
    }

    try out_stream.write_all(
        \\
        \\Advanced Options:
        \\  -freference-trace[=num]      How many lines of reference trace should be shown per compile error
        \\  -fno-reference-trace         Disable reference trace
        \\  --build-file [file]          Override path to build.zig
        \\  --cache-dir [path]           Override path to local Zig cache directory
        \\  --global-cache-dir [path]    Override path to global Zig cache directory
        \\  --zig-lib-dir [arg]          Override path to Zig lib directory
        \\  --build-runner [file]        Override path to build runner
        \\  --seed [integer]             For shuffling dependency traversal order (default: random)
        \\  --debug-log [scope]          Enable debugging the compiler
        \\  --debug-pkg-config           Fail if unknown pkg-config flags encountered
        \\  --verbose-link               Enable compiler debug output for linking
        \\  --verbose-air                Enable compiler debug output for Zig AIR
        \\  --verbose-llvm-ir[=file]     Enable compiler debug output for LLVM IR
        \\  --verbose-llvm-bc=[file]     Enable compiler debug output for LLVM BC
        \\  --verbose-cimport            Enable compiler debug output for C imports
        \\  --verbose-cc                 Enable compiler debug output for C compilation
        \\  --verbose-llvm-cpu-features  Enable compiler debug output for LLVM CPU features
        \\
    );
}

fn next_arg(args: [][:0]const u8, idx: *usize) ?[:0]const u8 {
    if (idx.* >= args.len) return null;
    defer idx.* += 1;
    return args[idx.*];
}

fn next_arg_or_fatal(args: [][:0]const u8, idx: *usize) [:0]const u8 {
    return next_arg(args, idx) orelse {
        std.debug.print("expected argument after '{s}'\n  access the help menu with 'zig build -h'\n", .{args[idx.*]});
        process.exit(1);
    };
}

fn args_rest(args: [][:0]const u8, idx: usize) ?[][:0]const u8 {
    if (idx >= args.len) return null;
    return args[idx..];
}

fn clean_exit() void {
    // Perhaps in the future there could be an Advanced Options flag such as
    // --debug-build-runner-leaks which would make this function return instead
    // of calling exit.
    process.exit(0);
}

const Color = std.zig.Color;
const Summary = enum { all, new, failures, none };

fn get_tty_conf(color: Color, stderr: File) std.io.tty.Config {
    return switch (color) {
        .auto => std.io.tty.detect_config(stderr),
        .on => .escape_codes,
        .off => .no_color,
    };
}

fn render_options(ttyconf: std.io.tty.Config) std.zig.ErrorBundle.RenderOptions {
    return .{
        .ttyconf = ttyconf,
        .include_source_line = ttyconf != .no_color,
        .include_reference_trace = ttyconf != .no_color,
    };
}

fn fatal_with_hint(comptime f: []const u8, args: anytype) noreturn {
    std.debug.print(f ++ "\n  access the help menu with 'zig build -h'\n", args);
    process.exit(1);
}

fn fatal(comptime f: []const u8, args: anytype) noreturn {
    std.debug.print(f ++ "\n", args);
    process.exit(1);
}

fn validate_system_library_options(b: *std.Build) void {
    var bad = false;
    for (b.graph.system_library_options.keys(), b.graph.system_library_options.values()) |k, v| {
        switch (v) {
            .user_disabled, .user_enabled => {
                // The user tried to enable or disable a system library integration, but
                // the build script did not recognize that option.
                std.debug.print("system library name not recognized by build script: '{s}'\n", .{k});
                bad = true;
            },
            .declared_disabled, .declared_enabled => {},
        }
    }
    if (bad) {
        std.debug.print("  access the help menu with 'zig build -h'\n", .{});
        process.exit(1);
    }
}
