const builtin = @import("builtin");
const std = @import("std");
const mem = std.mem;
const io = std.io;
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

fn usage() noreturn {
    io.get_std_out().write_all(
        \\Usage: zig std [options]
        \\
        \\Options:
        \\  -h, --help                Print this help and exit
        \\  -p [port], --port [port]  Port to listen on. Default is 0, meaning an ephemeral port chosen by the system.
        \\  --[no-]open-browser       Force enabling or disabling opening a browser tab to the served website.
        \\                            By default, enabled unless a port is specified.
        \\
    ) catch {};
    std.process.exit(1);
}

pub fn main() !void {
    var arena_instance = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_instance.deinit();
    const arena = arena_instance.allocator();

    var general_purpose_allocator: std.heap.GeneralPurposeAllocator(.{}) = .{};
    const gpa = general_purpose_allocator.allocator();

    var argv = try std.process.args_with_allocator(arena);
    defer argv.deinit();
    assert(argv.skip());
    const zig_lib_directory = argv.next().?;
    const zig_exe_path = argv.next().?;
    const global_cache_path = argv.next().?;

    var lib_dir = try std.fs.cwd().open_dir(zig_lib_directory, .{});
    defer lib_dir.close();

    var listen_port: u16 = 0;
    var force_open_browser: ?bool = null;
    while (argv.next()) |arg| {
        if (mem.eql(u8, arg, "-h") or mem.eql(u8, arg, "--help")) {
            usage();
        } else if (mem.eql(u8, arg, "-p") or mem.eql(u8, arg, "--port")) {
            listen_port = std.fmt.parse_int(u16, argv.next() orelse usage(), 10) catch |err| {
                std.log.err("expected port number: {}", .{err});
                usage();
            };
        } else if (mem.eql(u8, arg, "--open-browser")) {
            force_open_browser = true;
        } else if (mem.eql(u8, arg, "--no-open-browser")) {
            force_open_browser = false;
        } else {
            std.log.err("unrecognized argument: {s}", .{arg});
            usage();
        }
    }
    const should_open_browser = force_open_browser orelse (listen_port == 0);

    const address = std.net.Address.parse_ip("127.0.0.1", listen_port) catch unreachable;
    var http_server = try address.listen(.{});
    const port = http_server.listen_address.in.get_port();
    const url_with_newline = try std.fmt.alloc_print(arena, "http://127.0.0.1:{d}/\n", .{port});
    std.io.get_std_out().write_all(url_with_newline) catch {};
    if (should_open_browser) {
        open_browser_tab(gpa, url_with_newline[0 .. url_with_newline.len - 1 :'\n']) catch |err| {
            std.log.err("unable to open browser: {s}", .{@errorName(err)});
        };
    }

    var context: Context = .{
        .gpa = gpa,
        .zig_exe_path = zig_exe_path,
        .global_cache_path = global_cache_path,
        .lib_dir = lib_dir,
        .zig_lib_directory = zig_lib_directory,
    };

    while (true) {
        const connection = try http_server.accept();
        _ = std.Thread.spawn(.{}, accept, .{ &context, connection }) catch |err| {
            std.log.err("unable to accept connection: {s}", .{@errorName(err)});
            connection.stream.close();
            continue;
        };
    }
}

fn accept(context: *Context, connection: std.net.Server.Connection) void {
    defer connection.stream.close();

    var read_buffer: [8000]u8 = undefined;
    var server = std.http.Server.init(connection, &read_buffer);
    while (server.state == .ready) {
        var request = server.receive_head() catch |err| switch (err) {
            error.HttpConnectionClosing => return,
            else => {
                std.log.err("closing http connection: {s}", .{@errorName(err)});
                return;
            },
        };
        serve_request(&request, context) catch |err| {
            std.log.err("unable to serve {s}: {s}", .{ request.head.target, @errorName(err) });
            return;
        };
    }
}

const Context = struct {
    gpa: Allocator,
    lib_dir: std.fs.Dir,
    zig_lib_directory: []const u8,
    zig_exe_path: []const u8,
    global_cache_path: []const u8,
};

fn serve_request(request: *std.http.Server.Request, context: *Context) !void {
    if (std.mem.eql(u8, request.head.target, "/") or
        std.mem.eql(u8, request.head.target, "/debug") or
        std.mem.eql(u8, request.head.target, "/debug/"))
    {
        try serve_docs_file(request, context, "docs/index.html", "text/html");
    } else if (std.mem.eql(u8, request.head.target, "/main.js") or
        std.mem.eql(u8, request.head.target, "/debug/main.js"))
    {
        try serve_docs_file(request, context, "docs/main.js", "application/javascript");
    } else if (std.mem.eql(u8, request.head.target, "/main.wasm")) {
        try serve_wasm(request, context, .ReleaseFast);
    } else if (std.mem.eql(u8, request.head.target, "/debug/main.wasm")) {
        try serve_wasm(request, context, .Debug);
    } else if (std.mem.eql(u8, request.head.target, "/sources.tar") or
        std.mem.eql(u8, request.head.target, "/debug/sources.tar"))
    {
        try serve_sources_tar(request, context);
    } else {
        try request.respond("not found", .{
            .status = .not_found,
            .extra_headers = &.{
                .{ .name = "content-type", .value = "text/plain" },
            },
        });
    }
}

const cache_control_header: std.http.Header = .{
    .name = "cache-control",
    .value = "max-age=0, must-revalidate",
};

fn serve_docs_file(
    request: *std.http.Server.Request,
    context: *Context,
    name: []const u8,
    content_type: []const u8,
) !void {
    const gpa = context.gpa;
    // The desired API is actually sendfile, which will require enhancing std.http.Server.
    // We load the file with every request so that the user can make changes to the file
    // and refresh the HTML page without restarting this server.
    const file_contents = try context.lib_dir.read_file_alloc(gpa, name, 10 * 1024 * 1024);
    defer gpa.free(file_contents);
    try request.respond(file_contents, .{
        .extra_headers = &.{
            .{ .name = "content-type", .value = content_type },
            cache_control_header,
        },
    });
}

fn serve_sources_tar(request: *std.http.Server.Request, context: *Context) !void {
    const gpa = context.gpa;

    var send_buffer: [0x4000]u8 = undefined;
    var response = request.respond_streaming(.{
        .send_buffer = &send_buffer,
        .respond_options = .{
            .extra_headers = &.{
                .{ .name = "content-type", .value = "application/x-tar" },
                cache_control_header,
            },
        },
    });
    const w = response.writer();

    var std_dir = try context.lib_dir.open_dir("std", .{ .iterate = true });
    defer std_dir.close();

    var walker = try std_dir.walk(gpa);
    defer walker.deinit();

    while (try walker.next()) |entry| {
        switch (entry.kind) {
            .file => {
                if (!std.mem.ends_with(u8, entry.basename, ".zig"))
                    continue;
                if (std.mem.ends_with(u8, entry.basename, "test.zig"))
                    continue;
            },
            else => continue,
        }

        var file = try std_dir.open_file(entry.path, .{});
        defer file.close();

        const stat = try file.stat();
        const padding = p: {
            const remainder = stat.size % 512;
            break :p if (remainder > 0) 512 - remainder else 0;
        };

        var file_header = std.tar.output.Header.init();
        file_header.typeflag = .regular;
        try file_header.set_path("std", entry.path);
        try file_header.set_size(stat.size);
        try file_header.update_checksum();
        try w.write_all(std.mem.as_bytes(&file_header));
        try w.write_file(file);
        try w.write_byte_ntimes(0, padding);
    }

    {
        // Since this command is JIT compiled, the builtin module available in
        // this source file corresponds to the user's host system.
        const builtin_zig = @embed_file("builtin");

        var file_header = std.tar.output.Header.init();
        file_header.typeflag = .regular;
        try file_header.set_path("builtin", "builtin.zig");
        try file_header.set_size(builtin_zig.len);
        try file_header.update_checksum();
        try w.write_all(std.mem.as_bytes(&file_header));
        try w.write_all(builtin_zig);
        const padding = p: {
            const remainder = builtin_zig.len % 512;
            break :p if (remainder > 0) 512 - remainder else 0;
        };
        try w.write_byte_ntimes(0, padding);
    }

    // intentionally omitting the pointless trailer
    //try w.write_byte_ntimes(0, 512 * 2);
    try response.end();
}

fn serve_wasm(
    request: *std.http.Server.Request,
    context: *Context,
    optimize_mode: std.builtin.OptimizeMode,
) !void {
    const gpa = context.gpa;

    var arena_instance = std.heap.ArenaAllocator.init(gpa);
    defer arena_instance.deinit();
    const arena = arena_instance.allocator();

    // Do the compilation every request, so that the user can edit the files
    // and see the changes without restarting the server.
    const wasm_binary_path = try build_wasm_binary(arena, context, optimize_mode);
    // std.http.Server does not have a sendfile API yet.
    const file_contents = try std.fs.cwd().read_file_alloc(gpa, wasm_binary_path, 10 * 1024 * 1024);
    defer gpa.free(file_contents);
    try request.respond(file_contents, .{
        .extra_headers = &.{
            .{ .name = "content-type", .value = "application/wasm" },
            cache_control_header,
        },
    });
}

fn build_wasm_binary(
    arena: Allocator,
    context: *Context,
    optimize_mode: std.builtin.OptimizeMode,
) ![]const u8 {
    const gpa = context.gpa;

    const main_src_path = try std.fs.path.join(arena, &.{
        context.zig_lib_directory, "docs", "wasm", "main.zig",
    });

    var argv: std.ArrayListUnmanaged([]const u8) = .{};

    try argv.append_slice(arena, &.{
        context.zig_exe_path,
        "build-exe",
        "-fno-entry",
        "-O",
        @tag_name(optimize_mode),
        "-target",
        "wasm32-freestanding",
        "-mcpu",
        "baseline+atomics+bulk_memory+multivalue+mutable_globals+nontrapping_fptoint+reference_types+sign_ext",
        "--cache-dir",
        context.global_cache_path,
        "--global-cache-dir",
        context.global_cache_path,
        "--name",
        "autodoc",
        "-rdynamic",
        main_src_path,
        "--listen=-",
    });

    var child = std.process.Child.init(argv.items, gpa);
    child.stdin_behavior = .Pipe;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    try child.spawn();

    var poller = std.io.poll(gpa, enum { stdout, stderr }, .{
        .stdout = child.stdout.?,
        .stderr = child.stderr.?,
    });
    defer poller.deinit();

    try send_message(child.stdin.?, .update);
    try send_message(child.stdin.?, .exit);

    const Header = std.zig.Server.Message.Header;
    var result: ?[]const u8 = null;
    var result_error_bundle = std.zig.ErrorBundle.empty;

    const stdout = poller.fifo(.stdout);

    poll: while (true) {
        while (stdout.readable_length() < @size_of(Header)) {
            if (!(try poller.poll())) break :poll;
        }
        const header = stdout.reader().read_struct(Header) catch unreachable;
        while (stdout.readable_length() < header.bytes_len) {
            if (!(try poller.poll())) break :poll;
        }
        const body = stdout.readable_slice_of_len(header.bytes_len);

        switch (header.tag) {
            .zig_version => {
                if (!std.mem.eql(u8, builtin.zig_version_string, body)) {
                    return error.ZigProtocolVersionMismatch;
                }
            },
            .error_bundle => {
                const EbHdr = std.zig.Server.Message.ErrorBundle;
                const eb_hdr = @as(*align(1) const EbHdr, @ptr_cast(body));
                const extra_bytes =
                    body[@size_of(EbHdr)..][0 .. @size_of(u32) * eb_hdr.extra_len];
                const string_bytes =
                    body[@size_of(EbHdr) + extra_bytes.len ..][0..eb_hdr.string_bytes_len];
                // TODO: use @ptr_cast when the compiler supports it
                const unaligned_extra = std.mem.bytes_as_slice(u32, extra_bytes);
                const extra_array = try arena.alloc(u32, unaligned_extra.len);
                @memcpy(extra_array, unaligned_extra);
                result_error_bundle = .{
                    .string_bytes = try arena.dupe(u8, string_bytes),
                    .extra = extra_array,
                };
            },
            .emit_bin_path => {
                const EbpHdr = std.zig.Server.Message.EmitBinPath;
                const ebp_hdr = @as(*align(1) const EbpHdr, @ptr_cast(body));
                if (!ebp_hdr.flags.cache_hit) {
                    std.log.info("source changes detected; rebuilt wasm component", .{});
                }
                result = try arena.dupe(u8, body[@size_of(EbpHdr)..]);
            },
            else => {}, // ignore other messages
        }

        stdout.discard(body.len);
    }

    const stderr = poller.fifo(.stderr);
    if (stderr.readable_length() > 0) {
        const owned_stderr = try stderr.to_owned_slice();
        defer gpa.free(owned_stderr);
        std.debug.print("{s}", .{owned_stderr});
    }

    // Send EOF to stdin.
    child.stdin.?.close();
    child.stdin = null;

    switch (try child.wait()) {
        .Exited => |code| {
            if (code != 0) {
                std.log.err(
                    "the following command exited with error code {d}:\n{s}",
                    .{ code, try std.Build.Step.alloc_print_cmd(arena, null, argv.items) },
                );
                return error.WasmCompilationFailed;
            }
        },
        .Signal, .Stopped, .Unknown => {
            std.log.err(
                "the following command terminated unexpectedly:\n{s}",
                .{try std.Build.Step.alloc_print_cmd(arena, null, argv.items)},
            );
            return error.WasmCompilationFailed;
        },
    }

    if (result_error_bundle.error_message_count() > 0) {
        const color = std.zig.Color.auto;
        result_error_bundle.render_to_std_err(color.render_options());
        std.log.err("the following command failed with {d} compilation errors:\n{s}", .{
            result_error_bundle.error_message_count(),
            try std.Build.Step.alloc_print_cmd(arena, null, argv.items),
        });
        return error.WasmCompilationFailed;
    }

    return result orelse {
        std.log.err("child process failed to report result\n{s}", .{
            try std.Build.Step.alloc_print_cmd(arena, null, argv.items),
        });
        return error.WasmCompilationFailed;
    };
}

fn send_message(file: std.fs.File, tag: std.zig.Client.Message.Tag) !void {
    const header: std.zig.Client.Message.Header = .{
        .tag = tag,
        .bytes_len = 0,
    };
    try file.write_all(std.mem.as_bytes(&header));
}

fn open_browser_tab(gpa: Allocator, url: []const u8) !void {
    // Until https://github.com/ziglang/zig/issues/19205 is implemented, we
    // spawn a thread for this child process.
    _ = try std.Thread.spawn(.{}, open_browser_tab_thread, .{ gpa, url });
}

fn open_browser_tab_thread(gpa: Allocator, url: []const u8) !void {
    const main_exe = switch (builtin.os.tag) {
        .windows => "explorer",
        .macos => "open",
        else => "xdg-open",
    };
    var child = std.process.Child.init(&.{ main_exe, url }, gpa);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;
    try child.spawn();
    _ = try child.wait();
}
