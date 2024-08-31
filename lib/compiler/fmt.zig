const std = @import("std");
const mem = std.mem;
const fs = std.fs;
const process = std.process;
const Allocator = std.mem.Allocator;
const warn = std.log.warn;
const Color = std.zig.Color;

const usage_fmt =
    \\Usage: zig fmt [file]...
    \\
    \\   Formats the input files and modifies them in-place.
    \\   Arguments can be files or directories, which are searched
    \\   recursively.
    \\
    \\Options:
    \\  -h, --help             Print this help and exit
    \\  --color [auto|off|on]  Enable or disable colored error messages
    \\  --stdin                Format code from stdin; output to stdout
    \\  --check                List non-conforming files and exit with an error
    \\                         if the list is non-empty
    \\  --ast-check            Run zig ast-check on every file
    \\  --exclude [file]       Exclude file or directory from formatting
    \\
    \\
;

const Fmt = struct {
    seen: SeenMap,
    any_error: bool,
    check_ast: bool,
    color: Color,
    gpa: Allocator,
    arena: Allocator,
    out_buffer: std.ArrayList(u8),

    const SeenMap = std.AutoHashMap(fs.File.INode, void);
};

pub fn main() !void {
    var arena_instance = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_instance.deinit();
    const arena = arena_instance.allocator();
    const gpa = arena;

    const args = try process.args_alloc(arena);

    var color: Color = .auto;
    var stdin_flag: bool = false;
    var check_flag: bool = false;
    var check_ast_flag: bool = false;
    var input_files = std.ArrayList([]const u8).init(gpa);
    defer input_files.deinit();
    var excluded_files = std.ArrayList([]const u8).init(gpa);
    defer excluded_files.deinit();

    {
        var i: usize = 1;
        while (i < args.len) : (i += 1) {
            const arg = args[i];
            if (mem.starts_with(u8, arg, "-")) {
                if (mem.eql(u8, arg, "-h") or mem.eql(u8, arg, "--help")) {
                    const stdout = std.io.get_std_out().writer();
                    try stdout.write_all(usage_fmt);
                    return process.clean_exit();
                } else if (mem.eql(u8, arg, "--color")) {
                    if (i + 1 >= args.len) {
                        fatal("expected [auto|on|off] after --color", .{});
                    }
                    i += 1;
                    const next_arg = args[i];
                    color = std.meta.string_to_enum(Color, next_arg) orelse {
                        fatal("expected [auto|on|off] after --color, found '{s}'", .{next_arg});
                    };
                } else if (mem.eql(u8, arg, "--stdin")) {
                    stdin_flag = true;
                } else if (mem.eql(u8, arg, "--check")) {
                    check_flag = true;
                } else if (mem.eql(u8, arg, "--ast-check")) {
                    check_ast_flag = true;
                } else if (mem.eql(u8, arg, "--exclude")) {
                    if (i + 1 >= args.len) {
                        fatal("expected parameter after --exclude", .{});
                    }
                    i += 1;
                    const next_arg = args[i];
                    try excluded_files.append(next_arg);
                } else {
                    fatal("unrecognized parameter: '{s}'", .{arg});
                }
            } else {
                try input_files.append(arg);
            }
        }
    }

    if (stdin_flag) {
        if (input_files.items.len != 0) {
            fatal("cannot use --stdin with positional arguments", .{});
        }

        const stdin = std.io.get_std_in();
        const source_code = std.zig.read_source_file_to_end_alloc(gpa, stdin, null) catch |err| {
            fatal("unable to read stdin: {}", .{err});
        };
        defer gpa.free(source_code);

        var tree = std.zig.Ast.parse(gpa, source_code, .zig) catch |err| {
            fatal("error parsing stdin: {}", .{err});
        };
        defer tree.deinit(gpa);

        if (check_ast_flag) {
            var zir = try std.zig.AstGen.generate(gpa, tree);

            if (zir.has_compile_errors()) {
                var wip_errors: std.zig.ErrorBundle.Wip = undefined;
                try wip_errors.init(gpa);
                defer wip_errors.deinit();
                try wip_errors.add_zir_error_messages(zir, tree, source_code, "<stdin>");
                var error_bundle = try wip_errors.to_owned_bundle("");
                defer error_bundle.deinit(gpa);
                error_bundle.render_to_std_err(color.render_options());
                process.exit(2);
            }
        } else if (tree.errors.len != 0) {
            try std.zig.print_ast_errors_to_stderr(gpa, tree, "<stdin>", color);
            process.exit(2);
        }
        const formatted = try tree.render(gpa);
        defer gpa.free(formatted);

        if (check_flag) {
            const code: u8 = @int_from_bool(mem.eql(u8, formatted, source_code));
            process.exit(code);
        }

        return std.io.get_std_out().write_all(formatted);
    }

    if (input_files.items.len == 0) {
        fatal("expected at least one source file argument", .{});
    }

    var fmt = Fmt{
        .gpa = gpa,
        .arena = arena,
        .seen = Fmt.SeenMap.init(gpa),
        .any_error = false,
        .check_ast = check_ast_flag,
        .color = color,
        .out_buffer = std.ArrayList(u8).init(gpa),
    };
    defer fmt.seen.deinit();
    defer fmt.out_buffer.deinit();

    // Mark any excluded files/directories as already seen,
    // so that they are skipped later during actual processing
    for (excluded_files.items) |file_path| {
        const stat = fs.cwd().stat_file(file_path) catch |err| switch (err) {
            error.FileNotFound => continue,
            // On Windows, stat_file does not work for directories
            error.IsDir => dir: {
                var dir = try fs.cwd().open_dir(file_path, .{});
                defer dir.close();
                break :dir try dir.stat();
            },
            else => |e| return e,
        };
        try fmt.seen.put(stat.inode, {});
    }

    for (input_files.items) |file_path| {
        try fmt_path(&fmt, file_path, check_flag, fs.cwd(), file_path);
    }
    if (fmt.any_error) {
        process.exit(1);
    }
}

const FmtError = error{
    SystemResources,
    OperationAborted,
    IoPending,
    BrokenPipe,
    Unexpected,
    WouldBlock,
    FileClosed,
    DestinationAddressRequired,
    DiskQuota,
    FileTooBig,
    InputOutput,
    NoSpaceLeft,
    AccessDenied,
    OutOfMemory,
    RenameAcrossMountPoints,
    ReadOnlyFileSystem,
    LinkQuotaExceeded,
    FileBusy,
    EndOfStream,
    Unseekable,
    NotOpenForWriting,
    UnsupportedEncoding,
    ConnectionResetByPeer,
    SocketNotConnected,
    LockViolation,
    NetNameDeleted,
    InvalidArgument,
} || fs.File.OpenError;

fn fmt_path(fmt: *Fmt, file_path: []const u8, check_mode: bool, dir: fs.Dir, sub_path: []const u8) FmtError!void {
    fmt_path_file(fmt, file_path, check_mode, dir, sub_path) catch |err| switch (err) {
        error.IsDir, error.AccessDenied => return fmt_path_dir(fmt, file_path, check_mode, dir, sub_path),
        else => {
            warn("unable to format '{s}': {s}", .{ file_path, @errorName(err) });
            fmt.any_error = true;
            return;
        },
    };
}

fn fmt_path_dir(
    fmt: *Fmt,
    file_path: []const u8,
    check_mode: bool,
    parent_dir: fs.Dir,
    parent_sub_path: []const u8,
) FmtError!void {
    var dir = try parent_dir.open_dir(parent_sub_path, .{ .iterate = true });
    defer dir.close();

    const stat = try dir.stat();
    if (try fmt.seen.fetch_put(stat.inode, {})) |_| return;

    var dir_it = dir.iterate();
    while (try dir_it.next()) |entry| {
        const is_dir = entry.kind == .directory;

        if (mem.starts_with(u8, entry.name, ".")) continue;

        if (is_dir or entry.kind == .file and (mem.ends_with(u8, entry.name, ".zig") or mem.ends_with(u8, entry.name, ".zon"))) {
            const full_path = try fs.path.join(fmt.gpa, &[_][]const u8{ file_path, entry.name });
            defer fmt.gpa.free(full_path);

            if (is_dir) {
                try fmt_path_dir(fmt, full_path, check_mode, dir, entry.name);
            } else {
                fmt_path_file(fmt, full_path, check_mode, dir, entry.name) catch |err| {
                    warn("unable to format '{s}': {s}", .{ full_path, @errorName(err) });
                    fmt.any_error = true;
                    return;
                };
            }
        }
    }
}

fn fmt_path_file(
    fmt: *Fmt,
    file_path: []const u8,
    check_mode: bool,
    dir: fs.Dir,
    sub_path: []const u8,
) FmtError!void {
    const source_file = try dir.open_file(sub_path, .{});
    var file_closed = false;
    errdefer if (!file_closed) source_file.close();

    const stat = try source_file.stat();

    if (stat.kind == .directory)
        return error.IsDir;

    const gpa = fmt.gpa;
    const source_code = try std.zig.read_source_file_to_end_alloc(
        gpa,
        source_file,
        std.math.cast(usize, stat.size) orelse return error.FileTooBig,
    );
    defer gpa.free(source_code);

    source_file.close();
    file_closed = true;

    // Add to set after no longer possible to get error.IsDir.
    if (try fmt.seen.fetch_put(stat.inode, {})) |_| return;

    var tree = try std.zig.Ast.parse(gpa, source_code, .zig);
    defer tree.deinit(gpa);

    if (tree.errors.len != 0) {
        try std.zig.print_ast_errors_to_stderr(gpa, tree, file_path, fmt.color);
        fmt.any_error = true;
        return;
    }

    if (fmt.check_ast) {
        if (stat.size > std.zig.max_src_size)
            return error.FileTooBig;

        var zir = try std.zig.AstGen.generate(gpa, tree);
        defer zir.deinit(gpa);

        if (zir.has_compile_errors()) {
            var wip_errors: std.zig.ErrorBundle.Wip = undefined;
            try wip_errors.init(gpa);
            defer wip_errors.deinit();
            try wip_errors.add_zir_error_messages(zir, tree, source_code, file_path);
            var error_bundle = try wip_errors.to_owned_bundle("");
            defer error_bundle.deinit(gpa);
            error_bundle.render_to_std_err(fmt.color.render_options());
            fmt.any_error = true;
        }
    }

    // As a heuristic, we make enough capacity for the same as the input source.
    fmt.out_buffer.shrink_retaining_capacity(0);
    try fmt.out_buffer.ensure_total_capacity(source_code.len);

    try tree.render_to_array_list(&fmt.out_buffer, .{});
    if (mem.eql(u8, fmt.out_buffer.items, source_code))
        return;

    if (check_mode) {
        const stdout = std.io.get_std_out().writer();
        try stdout.print("{s}\n", .{file_path});
        fmt.any_error = true;
    } else {
        var af = try dir.atomic_file(sub_path, .{ .mode = stat.mode });
        defer af.deinit();

        try af.file.write_all(fmt.out_buffer.items);
        try af.finish();
        const stdout = std.io.get_std_out().writer();
        try stdout.print("{s}\n", .{file_path});
    }
}

fn fatal(comptime format: []const u8, args: anytype) noreturn {
    std.log.err(format, args);
    process.exit(1);
}
