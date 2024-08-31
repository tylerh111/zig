const std = @import("std");
const builtin = @import("builtin");
const remove_comments = @import("comments.zig").remove_comments;
const parse_and_remove_line_commands = @import("source_mapping.zig").parse_and_remove_line_commands;
const compile = @import("compile.zig").compile;
const Diagnostics = @import("errors.zig").Diagnostics;
const cli = @import("cli.zig");
const preprocess = @import("preprocess.zig");
const render_error_message = @import("utils.zig").render_error_message;
const aro = @import("aro");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer std.debug.assert(gpa.deinit() == .ok);
    const allocator = gpa.allocator();

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const stderr = std.io.get_std_err();
    const stderr_config = std.io.tty.detect_config(stderr);

    const args = try std.process.args_alloc(allocator);
    defer std.process.args_free(allocator, args);

    if (args.len < 2) {
        try render_error_message(stderr.writer(), stderr_config, .err, "expected zig lib dir as first argument", .{});
        std.process.exit(1);
    }
    const zig_lib_dir = args[1];
    var cli_args = args[2..];

    var zig_integration = false;
    if (cli_args.len > 0 and std.mem.eql(u8, cli_args[0], "--zig-integration")) {
        zig_integration = true;
        cli_args = args[3..];
    }

    var error_handler: ErrorHandler = switch (zig_integration) {
        true => .{
            .server = .{
                .out = std.io.get_std_out(),
                .in = undefined, // won't be receiving messages
                .receive_fifo = undefined, // won't be receiving messages
            },
        },
        false => .{
            .tty = stderr_config,
        },
    };

    var options = options: {
        var cli_diagnostics = cli.Diagnostics.init(allocator);
        defer cli_diagnostics.deinit();
        var options = cli.parse(allocator, cli_args, &cli_diagnostics) catch |err| switch (err) {
            error.ParseError => {
                try error_handler.emit_cli_diagnostics(allocator, cli_args, &cli_diagnostics);
                std.process.exit(1);
            },
            else => |e| return e,
        };
        try options.maybe_append_rc(std.fs.cwd());

        if (!zig_integration) {
            // print any warnings/notes
            cli_diagnostics.render_to_std_err(args, stderr_config);
            // If there was something printed, then add an extra newline separator
            // so that there is a clear separation between the cli diagnostics and whatever
            // gets printed after
            if (cli_diagnostics.errors.items.len > 0) {
                try stderr.write_all("\n");
            }
        }
        break :options options;
    };
    defer options.deinit();

    if (options.print_help_and_exit) {
        try cli.write_usage(stderr.writer(), "zig rc");
        return;
    }

    // Don't allow verbose when integrating with Zig via stdout
    options.verbose = false;

    const stdout_writer = std.io.get_std_out().writer();
    if (options.verbose) {
        try options.dump_verbose(stdout_writer);
        try stdout_writer.write_byte('\n');
    }

    var dependencies_list = std.ArrayList([]const u8).init(allocator);
    defer {
        for (dependencies_list.items) |item| {
            allocator.free(item);
        }
        dependencies_list.deinit();
    }
    const maybe_dependencies_list: ?*std.ArrayList([]const u8) = if (options.depfile_path != null) &dependencies_list else null;

    const include_paths = get_include_paths(arena, options.auto_includes, zig_lib_dir) catch |err| switch (err) {
        error.OutOfMemory => |e| return e,
        else => |e| {
            switch (e) {
                error.MsvcIncludesNotFound => {
                    try error_handler.emit_message(allocator, .err, "MSVC include paths could not be automatically detected", .{});
                },
                error.MingwIncludesNotFound => {
                    try error_handler.emit_message(allocator, .err, "MinGW include paths could not be automatically detected", .{});
                },
            }
            try error_handler.emit_message(allocator, .note, "to disable auto includes, use the option /:auto-includes none", .{});
            std.process.exit(1);
        },
    };

    const full_input = full_input: {
        if (options.preprocess != .no) {
            var preprocessed_buf = std.ArrayList(u8).init(allocator);
            errdefer preprocessed_buf.deinit();

            // We're going to throw away everything except the final preprocessed output anyway,
            // so we can use a scoped arena for everything else.
            var aro_arena_state = std.heap.ArenaAllocator.init(allocator);
            defer aro_arena_state.deinit();
            const aro_arena = aro_arena_state.allocator();

            var comp = aro.Compilation.init(aro_arena);
            defer comp.deinit();

            var argv = std.ArrayList([]const u8).init(comp.gpa);
            defer argv.deinit();

            try argv.append("arocc"); // dummy command name
            try preprocess.append_aro_args(aro_arena, &argv, options, include_paths);
            try argv.append(options.input_filename);

            if (options.verbose) {
                try stdout_writer.write_all("Preprocessor: arocc (built-in)\n");
                for (argv.items[0 .. argv.items.len - 1]) |arg| {
                    try stdout_writer.print("{s} ", .{arg});
                }
                try stdout_writer.print("{s}\n\n", .{argv.items[argv.items.len - 1]});
            }

            preprocess.preprocess(&comp, preprocessed_buf.writer(), argv.items, maybe_dependencies_list) catch |err| switch (err) {
                error.GeneratedSourceError => {
                    try error_handler.emit_aro_diagnostics(allocator, "failed during preprocessor setup (this is always a bug):", &comp);
                    std.process.exit(1);
                },
                // ArgError can occur if e.g. the .rc file is not found
                error.ArgError, error.PreprocessError => {
                    try error_handler.emit_aro_diagnostics(allocator, "failed during preprocessing:", &comp);
                    std.process.exit(1);
                },
                error.StreamTooLong => {
                    try error_handler.emit_message(allocator, .err, "failed during preprocessing: maximum file size exceeded", .{});
                    std.process.exit(1);
                },
                error.OutOfMemory => |e| return e,
            };

            break :full_input try preprocessed_buf.to_owned_slice();
        } else {
            break :full_input std.fs.cwd().read_file_alloc(allocator, options.input_filename, std.math.max_int(usize)) catch |err| {
                try error_handler.emit_message(allocator, .err, "unable to read input file path '{s}': {s}", .{ options.input_filename, @errorName(err) });
                std.process.exit(1);
            };
        }
    };
    defer allocator.free(full_input);

    if (options.preprocess == .only) {
        try std.fs.cwd().write_file(.{ .sub_path = options.output_filename, .data = full_input });
        return;
    }

    // Note: We still want to run this when no-preprocess is set because:
    //   1. We want to print accurate line numbers after removing multiline comments
    //   2. We want to be able to handle an already-preprocessed input with #line commands in it
    var mapping_results = try parse_and_remove_line_commands(allocator, full_input, full_input, .{ .initial_filename = options.input_filename });
    defer mapping_results.mappings.deinit(allocator);

    const final_input = remove_comments(mapping_results.result, mapping_results.result, &mapping_results.mappings) catch |err| switch (err) {
        error.InvalidSourceMappingCollapse => {
            try error_handler.emit_message(allocator, .err, "failed during comment removal; this is a known bug", .{});
            std.process.exit(1);
        },
        else => |e| return e,
    };

    var output_file = std.fs.cwd().create_file(options.output_filename, .{}) catch |err| {
        try error_handler.emit_message(allocator, .err, "unable to create output file '{s}': {s}", .{ options.output_filename, @errorName(err) });
        std.process.exit(1);
    };
    var output_file_closed = false;
    defer if (!output_file_closed) output_file.close();

    var diagnostics = Diagnostics.init(allocator);
    defer diagnostics.deinit();

    var output_buffered_stream = std.io.buffered_writer(output_file.writer());

    compile(allocator, final_input, output_buffered_stream.writer(), .{
        .cwd = std.fs.cwd(),
        .diagnostics = &diagnostics,
        .source_mappings = &mapping_results.mappings,
        .dependencies_list = maybe_dependencies_list,
        .ignore_include_env_var = options.ignore_include_env_var,
        .extra_include_paths = options.extra_include_paths.items,
        .system_include_paths = include_paths,
        .default_language_id = options.default_language_id,
        .default_code_page = options.default_code_page orelse .windows1252,
        .verbose = options.verbose,
        .null_terminate_string_table_strings = options.null_terminate_string_table_strings,
        .max_string_literal_codepoints = options.max_string_literal_codepoints,
        .silent_duplicate_control_ids = options.silent_duplicate_control_ids,
        .warn_instead_of_error_on_invalid_code_page = options.warn_instead_of_error_on_invalid_code_page,
    }) catch |err| switch (err) {
        error.ParseError, error.CompileError => {
            try error_handler.emit_diagnostics(allocator, std.fs.cwd(), final_input, &diagnostics, mapping_results.mappings);
            // Delete the output file on error
            output_file.close();
            output_file_closed = true;
            // Failing to delete is not really a big deal, so swallow any errors
            std.fs.cwd().delete_file(options.output_filename) catch {};
            std.process.exit(1);
        },
        else => |e| return e,
    };

    try output_buffered_stream.flush();

    // print any warnings/notes
    if (!zig_integration) {
        diagnostics.render_to_std_err(std.fs.cwd(), final_input, stderr_config, mapping_results.mappings);
    }

    // write the depfile
    if (options.depfile_path) |depfile_path| {
        var depfile = std.fs.cwd().create_file(depfile_path, .{}) catch |err| {
            try error_handler.emit_message(allocator, .err, "unable to create depfile '{s}': {s}", .{ depfile_path, @errorName(err) });
            std.process.exit(1);
        };
        defer depfile.close();

        const depfile_writer = depfile.writer();
        var depfile_buffered_writer = std.io.buffered_writer(depfile_writer);
        switch (options.depfile_fmt) {
            .json => {
                var write_stream = std.json.write_stream(depfile_buffered_writer.writer(), .{ .whitespace = .indent_2 });
                defer write_stream.deinit();

                try write_stream.begin_array();
                for (dependencies_list.items) |dep_path| {
                    try write_stream.write(dep_path);
                }
                try write_stream.end_array();
            },
        }
        try depfile_buffered_writer.flush();
    }
}

fn get_include_paths(arena: std.mem.Allocator, auto_includes_option: cli.Options.AutoIncludes, zig_lib_dir: []const u8) ![]const []const u8 {
    var includes = auto_includes_option;
    if (builtin.target.os.tag != .windows) {
        switch (includes) {
            // MSVC can't be found when the host isn't Windows, so short-circuit.
            .msvc => return error.MsvcIncludesNotFound,
            // Skip straight to gnu since we won't be able to detect MSVC on non-Windows hosts.
            .any => includes = .gnu,
            .none, .gnu => {},
        }
    }

    while (true) {
        switch (includes) {
            .none => return &[_][]const u8{},
            .any, .msvc => {
                // MSVC is only detectable on Windows targets. This unreachable is to signify
                // that .any and .msvc should be dealt with on non-Windows targets before this point,
                // since getting MSVC include paths uses Windows-only APIs.
                if (builtin.target.os.tag != .windows) unreachable;

                const target_query: std.Target.Query = .{
                    .os_tag = .windows,
                    .abi = .msvc,
                };
                const target = std.zig.resolve_target_query_or_fatal(target_query);
                const is_native_abi = target_query.is_native_abi();
                const detected_libc = std.zig.LibCDirs.detect(arena, zig_lib_dir, target, is_native_abi, true, null) catch {
                    if (includes == .any) {
                        // fall back to mingw
                        includes = .gnu;
                        continue;
                    }
                    return error.MsvcIncludesNotFound;
                };
                if (detected_libc.libc_include_dir_list.len == 0) {
                    if (includes == .any) {
                        // fall back to mingw
                        includes = .gnu;
                        continue;
                    }
                    return error.MsvcIncludesNotFound;
                }
                return detected_libc.libc_include_dir_list;
            },
            .gnu => {
                const target_query: std.Target.Query = .{
                    .os_tag = .windows,
                    .abi = .gnu,
                };
                const target = std.zig.resolve_target_query_or_fatal(target_query);
                const is_native_abi = target_query.is_native_abi();
                const detected_libc = std.zig.LibCDirs.detect(arena, zig_lib_dir, target, is_native_abi, true, null) catch |err| switch (err) {
                    error.OutOfMemory => |e| return e,
                    else => return error.MingwIncludesNotFound,
                };
                return detected_libc.libc_include_dir_list;
            },
        }
    }
}

const ErrorBundle = std.zig.ErrorBundle;
const SourceMappings = @import("source_mapping.zig").SourceMappings;

const ErrorHandler = union(enum) {
    server: std.zig.Server,
    tty: std.io.tty.Config,

    pub fn emit_cli_diagnostics(
        self: *ErrorHandler,
        allocator: std.mem.Allocator,
        args: []const []const u8,
        diagnostics: *cli.Diagnostics,
    ) !void {
        switch (self.*) {
            .server => |*server| {
                var error_bundle = try cli_diagnostics_to_error_bundle(allocator, diagnostics);
                defer error_bundle.deinit(allocator);

                try server.serve_error_bundle(error_bundle);
            },
            .tty => {
                diagnostics.render_to_std_err(args, self.tty);
            },
        }
    }

    pub fn emit_aro_diagnostics(
        self: *ErrorHandler,
        allocator: std.mem.Allocator,
        fail_msg: []const u8,
        comp: *aro.Compilation,
    ) !void {
        switch (self.*) {
            .server => |*server| {
                var error_bundle = try aro_diagnostics_to_error_bundle(allocator, fail_msg, comp);
                defer error_bundle.deinit(allocator);

                try server.serve_error_bundle(error_bundle);
            },
            .tty => {
                // extra newline to separate this line from the aro errors
                try render_error_message(std.io.get_std_err().writer(), self.tty, .err, "{s}\n", .{fail_msg});
                aro.Diagnostics.render(comp, self.tty);
            },
        }
    }

    pub fn emit_diagnostics(
        self: *ErrorHandler,
        allocator: std.mem.Allocator,
        cwd: std.fs.Dir,
        source: []const u8,
        diagnostics: *Diagnostics,
        mappings: SourceMappings,
    ) !void {
        switch (self.*) {
            .server => |*server| {
                var error_bundle = try diagnostics_to_error_bundle(allocator, source, diagnostics, mappings);
                defer error_bundle.deinit(allocator);

                try server.serve_error_bundle(error_bundle);
            },
            .tty => {
                diagnostics.render_to_std_err(cwd, source, self.tty, mappings);
            },
        }
    }

    pub fn emit_message(
        self: *ErrorHandler,
        allocator: std.mem.Allocator,
        msg_type: @import("utils.zig").ErrorMessageType,
        comptime format: []const u8,
        args: anytype,
    ) !void {
        switch (self.*) {
            .server => |*server| {
                // only emit errors
                if (msg_type != .err) return;

                var error_bundle = try error_string_to_error_bundle(allocator, format, args);
                defer error_bundle.deinit(allocator);

                try server.serve_error_bundle(error_bundle);
            },
            .tty => {
                try render_error_message(std.io.get_std_err().writer(), self.tty, msg_type, format, args);
            },
        }
    }
};

fn cli_diagnostics_to_error_bundle(
    gpa: std.mem.Allocator,
    diagnostics: *cli.Diagnostics,
) !ErrorBundle {
    @setCold(true);

    var bundle: ErrorBundle.Wip = undefined;
    try bundle.init(gpa);
    errdefer bundle.deinit();

    try bundle.add_root_error_message(.{
        .msg = try bundle.add_string("invalid command line option(s)"),
    });

    var cur_err: ?ErrorBundle.ErrorMessage = null;
    var cur_notes: std.ArrayListUnmanaged(ErrorBundle.ErrorMessage) = .{};
    defer cur_notes.deinit(gpa);
    for (diagnostics.errors.items) |err_details| {
        switch (err_details.type) {
            .err => {
                if (cur_err) |err| {
                    try flush_error_message_into_bundle(&bundle, err, cur_notes.items);
                }
                cur_err = .{
                    .msg = try bundle.add_string(err_details.msg.items),
                };
                cur_notes.clear_retaining_capacity();
            },
            .warning => cur_err = null,
            .note => {
                if (cur_err == null) continue;
                cur_err.?.notes_len += 1;
                try cur_notes.append(gpa, .{
                    .msg = try bundle.add_string(err_details.msg.items),
                });
            },
        }
    }
    if (cur_err) |err| {
        try flush_error_message_into_bundle(&bundle, err, cur_notes.items);
    }

    return try bundle.to_owned_bundle("");
}

fn diagnostics_to_error_bundle(
    gpa: std.mem.Allocator,
    source: []const u8,
    diagnostics: *Diagnostics,
    mappings: SourceMappings,
) !ErrorBundle {
    @setCold(true);

    var bundle: ErrorBundle.Wip = undefined;
    try bundle.init(gpa);
    errdefer bundle.deinit();

    var msg_buf: std.ArrayListUnmanaged(u8) = .{};
    defer msg_buf.deinit(gpa);
    var cur_err: ?ErrorBundle.ErrorMessage = null;
    var cur_notes: std.ArrayListUnmanaged(ErrorBundle.ErrorMessage) = .{};
    defer cur_notes.deinit(gpa);
    for (diagnostics.errors.items) |err_details| {
        switch (err_details.type) {
            .hint => continue,
            // Clear the current error so that notes don't bleed into unassociated errors
            .warning => {
                cur_err = null;
                continue;
            },
            .note => if (cur_err == null) continue,
            .err => {},
        }
        const corresponding_span = mappings.get_corresponding_span(err_details.token.line_number).?;
        const err_line = corresponding_span.start_line;
        const err_filename = mappings.files.get(corresponding_span.filename_offset);

        const source_line_start = err_details.token.get_line_start_for_error_display(source);
        // Treat tab stops as 1 column wide for error display purposes,
        // and add one to get a 1-based column
        const column = err_details.token.calculate_column(source, 1, source_line_start) + 1;

        msg_buf.clear_retaining_capacity();
        try err_details.render(msg_buf.writer(gpa), source, diagnostics.strings.items);

        const src_loc = src_loc: {
            var src_loc: ErrorBundle.SourceLocation = .{
                .src_path = try bundle.add_string(err_filename),
                .line = @int_cast(err_line - 1), // 1-based -> 0-based
                .column = @int_cast(column - 1), // 1-based -> 0-based
                .span_start = 0,
                .span_main = 0,
                .span_end = 0,
            };
            if (err_details.print_source_line) {
                const source_line = err_details.token.get_line_for_error_display(source, source_line_start);
                const visual_info = err_details.visual_token_info(source_line_start, source_line_start + source_line.len);
                src_loc.span_start = @int_cast(visual_info.point_offset - visual_info.before_len);
                src_loc.span_main = @int_cast(visual_info.point_offset);
                src_loc.span_end = @int_cast(visual_info.point_offset + 1 + visual_info.after_len);
                src_loc.source_line = try bundle.add_string(source_line);
            }
            break :src_loc try bundle.add_source_location(src_loc);
        };

        switch (err_details.type) {
            .err => {
                if (cur_err) |err| {
                    try flush_error_message_into_bundle(&bundle, err, cur_notes.items);
                }
                cur_err = .{
                    .msg = try bundle.add_string(msg_buf.items),
                    .src_loc = src_loc,
                };
                cur_notes.clear_retaining_capacity();
            },
            .note => {
                cur_err.?.notes_len += 1;
                try cur_notes.append(gpa, .{
                    .msg = try bundle.add_string(msg_buf.items),
                    .src_loc = src_loc,
                });
            },
            .warning, .hint => unreachable,
        }
    }
    if (cur_err) |err| {
        try flush_error_message_into_bundle(&bundle, err, cur_notes.items);
    }

    return try bundle.to_owned_bundle("");
}

fn flush_error_message_into_bundle(wip: *ErrorBundle.Wip, msg: ErrorBundle.ErrorMessage, notes: []const ErrorBundle.ErrorMessage) !void {
    try wip.add_root_error_message(msg);
    const notes_start = try wip.reserve_notes(@int_cast(notes.len));
    for (notes_start.., notes) |i, note| {
        wip.extra.items[i] = @int_from_enum(wip.add_error_message_assume_capacity(note));
    }
}

fn error_string_to_error_bundle(allocator: std.mem.Allocator, comptime format: []const u8, args: anytype) !ErrorBundle {
    @setCold(true);
    var bundle: ErrorBundle.Wip = undefined;
    try bundle.init(allocator);
    errdefer bundle.deinit();
    try bundle.add_root_error_message(.{
        .msg = try bundle.print_string(format, args),
    });
    return try bundle.to_owned_bundle("");
}

fn aro_diagnostics_to_error_bundle(
    gpa: std.mem.Allocator,
    fail_msg: []const u8,
    comp: *aro.Compilation,
) !ErrorBundle {
    @setCold(true);

    var bundle: ErrorBundle.Wip = undefined;
    try bundle.init(gpa);
    errdefer bundle.deinit();

    try bundle.add_root_error_message(.{
        .msg = try bundle.add_string(fail_msg),
    });

    var msg_writer = MsgWriter.init(gpa);
    defer msg_writer.deinit();
    var cur_err: ?ErrorBundle.ErrorMessage = null;
    var cur_notes: std.ArrayListUnmanaged(ErrorBundle.ErrorMessage) = .{};
    defer cur_notes.deinit(gpa);
    for (comp.diagnostics.list.items) |msg| {
        switch (msg.kind) {
            // Clear the current error so that notes don't bleed into unassociated errors
            .off, .warning => {
                cur_err = null;
                continue;
            },
            .note => if (cur_err == null) continue,
            .@"fatal error", .@"error" => {},
            .default => unreachable,
        }
        msg_writer.reset_retaining_capacity();
        aro.Diagnostics.render_message(comp, &msg_writer, msg);

        const src_loc = src_loc: {
            if (msg_writer.path) |src_path| {
                var src_loc: ErrorBundle.SourceLocation = .{
                    .src_path = try bundle.add_string(src_path),
                    .line = msg_writer.line - 1, // 1-based -> 0-based
                    .column = msg_writer.col - 1, // 1-based -> 0-based
                    .span_start = 0,
                    .span_main = 0,
                    .span_end = 0,
                };
                if (msg_writer.source_line) |source_line| {
                    src_loc.span_start = msg_writer.span_main;
                    src_loc.span_main = msg_writer.span_main;
                    src_loc.span_end = msg_writer.span_main;
                    src_loc.source_line = try bundle.add_string(source_line);
                }
                break :src_loc try bundle.add_source_location(src_loc);
            }
            break :src_loc ErrorBundle.SourceLocationIndex.none;
        };

        switch (msg.kind) {
            .@"fatal error", .@"error" => {
                if (cur_err) |err| {
                    try flush_error_message_into_bundle(&bundle, err, cur_notes.items);
                }
                cur_err = .{
                    .msg = try bundle.add_string(msg_writer.buf.items),
                    .src_loc = src_loc,
                };
                cur_notes.clear_retaining_capacity();
            },
            .note => {
                cur_err.?.notes_len += 1;
                try cur_notes.append(gpa, .{
                    .msg = try bundle.add_string(msg_writer.buf.items),
                    .src_loc = src_loc,
                });
            },
            .off, .warning, .default => unreachable,
        }
    }
    if (cur_err) |err| {
        try flush_error_message_into_bundle(&bundle, err, cur_notes.items);
    }

    return try bundle.to_owned_bundle("");
}

// Similar to aro.Diagnostics.MsgWriter but:
// - Writers to an ArrayList
// - Only prints the message itself (no location, source line, error: prefix, etc)
// - Keeps track of source path/line/col instead
const MsgWriter = struct {
    buf: std.ArrayList(u8),
    path: ?[]const u8 = null,
    // 1-indexed
    line: u32 = undefined,
    col: u32 = undefined,
    source_line: ?[]const u8 = null,
    span_main: u32 = undefined,

    fn init(allocator: std.mem.Allocator) MsgWriter {
        return .{
            .buf = std.ArrayList(u8).init(allocator),
        };
    }

    fn deinit(m: *MsgWriter) void {
        m.buf.deinit();
    }

    fn reset_retaining_capacity(m: *MsgWriter) void {
        m.buf.clear_retaining_capacity();
        m.path = null;
        m.source_line = null;
    }

    pub fn print(m: *MsgWriter, comptime fmt: []const u8, args: anytype) void {
        m.buf.writer().print(fmt, args) catch {};
    }

    pub fn write(m: *MsgWriter, msg: []const u8) void {
        m.buf.writer().write_all(msg) catch {};
    }

    pub fn set_color(m: *MsgWriter, color: std.io.tty.Color) void {
        _ = m;
        _ = color;
    }

    pub fn location(m: *MsgWriter, path: []const u8, line: u32, col: u32) void {
        m.path = path;
        m.line = line;
        m.col = col;
    }

    pub fn start(m: *MsgWriter, kind: aro.Diagnostics.Kind) void {
        _ = m;
        _ = kind;
    }

    pub fn end(m: *MsgWriter, maybe_line: ?[]const u8, col: u32, end_with_splice: bool) void {
        _ = end_with_splice;
        m.source_line = maybe_line;
        m.span_main = col;
    }
};
