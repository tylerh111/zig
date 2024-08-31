const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const Node = @import("ast.zig").Node;
const lex = @import("lex.zig");
const Parser = @import("parse.zig").Parser;
const Resource = @import("rc.zig").Resource;
const Token = @import("lex.zig").Token;
const literals = @import("literals.zig");
const Number = literals.Number;
const SourceBytes = literals.SourceBytes;
const Diagnostics = @import("errors.zig").Diagnostics;
const ErrorDetails = @import("errors.zig").ErrorDetails;
const MemoryFlags = @import("res.zig").MemoryFlags;
const rc = @import("rc.zig");
const res = @import("res.zig");
const ico = @import("ico.zig");
const ani = @import("ani.zig");
const bmp = @import("bmp.zig");
const WORD = std.os.windows.WORD;
const DWORD = std.os.windows.DWORD;
const utils = @import("utils.zig");
const NameOrOrdinal = res.NameOrOrdinal;
const CodePage = @import("code_pages.zig").CodePage;
const CodePageLookup = @import("ast.zig").CodePageLookup;
const SourceMappings = @import("source_mapping.zig").SourceMappings;
const windows1252 = @import("windows1252.zig");
const lang = @import("lang.zig");
const code_pages = @import("code_pages.zig");
const errors = @import("errors.zig");
const native_endian = builtin.cpu.arch.endian();

pub const CompileOptions = struct {
    cwd: std.fs.Dir,
    diagnostics: *Diagnostics,
    source_mappings: ?*SourceMappings = null,
    /// List of paths (absolute or relative to `cwd`) for every file that the resources within the .rc file depend on.
    /// Items within the list will be allocated using the allocator of the ArrayList and must be
    /// freed by the caller.
    /// TODO: Maybe a dedicated struct for this purpose so that it's a bit nicer to work with.
    dependencies_list: ?*std.ArrayList([]const u8) = null,
    default_code_page: CodePage = .windows1252,
    ignore_include_env_var: bool = false,
    extra_include_paths: []const []const u8 = &.{},
    /// This is just an API convenience to allow separately passing 'system' (i.e. those
    /// that would normally be gotten from the INCLUDE env var) include paths. This is mostly
    /// intended for use when setting `ignore_include_env_var = true`. When `ignore_include_env_var`
    /// is false, `system_include_paths` will be searched before the paths in the INCLUDE env var.
    system_include_paths: []const []const u8 = &.{},
    default_language_id: ?u16 = null,
    // TODO: Implement verbose output
    verbose: bool = false,
    null_terminate_string_table_strings: bool = false,
    /// Note: This is a u15 to ensure that the maximum number of UTF-16 code units
    ///       plus a null-terminator can always fit into a u16.
    max_string_literal_codepoints: u15 = lex.default_max_string_literal_codepoints,
    silent_duplicate_control_ids: bool = false,
    warn_instead_of_error_on_invalid_code_page: bool = false,
};

pub fn compile(allocator: Allocator, source: []const u8, writer: anytype, options: CompileOptions) !void {
    var lexer = lex.Lexer.init(source, .{
        .default_code_page = options.default_code_page,
        .source_mappings = options.source_mappings,
        .max_string_literal_codepoints = options.max_string_literal_codepoints,
    });
    var parser = Parser.init(&lexer, .{
        .warn_instead_of_error_on_invalid_code_page = options.warn_instead_of_error_on_invalid_code_page,
    });
    var tree = try parser.parse(allocator, options.diagnostics);
    defer tree.deinit();

    var search_dirs = std.ArrayList(SearchDir).init(allocator);
    defer {
        for (search_dirs.items) |*search_dir| {
            search_dir.deinit(allocator);
        }
        search_dirs.deinit();
    }

    if (options.source_mappings) |source_mappings| {
        const root_path = source_mappings.files.get(source_mappings.root_filename_offset);
        // If dirname returns null, then the root path will be the same as
        // the cwd so we don't need to add it as a distinct search path.
        if (std.fs.path.dirname(root_path)) |root_dir_path| {
            var root_dir = try options.cwd.open_dir(root_dir_path, .{});
            errdefer root_dir.close();
            try search_dirs.append(.{ .dir = root_dir, .path = try allocator.dupe(u8, root_dir_path) });
        }
    }
    // Re-open the passed in cwd since we want to be able to close it (std.fs.cwd() shouldn't be closed)
    const cwd_dir = options.cwd.open_dir(".", .{}) catch |err| {
        try options.diagnostics.append(.{
            .err = .failed_to_open_cwd,
            .token = .{
                .id = .invalid,
                .start = 0,
                .end = 0,
                .line_number = 1,
            },
            .print_source_line = false,
            .extra = .{ .file_open_error = .{
                .err = ErrorDetails.FileOpenError.enum_from_error(err),
                .filename_string_index = undefined,
            } },
        });
        return error.CompileError;
    };
    try search_dirs.append(.{ .dir = cwd_dir, .path = null });
    for (options.extra_include_paths) |extra_include_path| {
        var dir = open_search_path_dir(options.cwd, extra_include_path) catch {
            // TODO: maybe a warning that the search path is skipped?
            continue;
        };
        errdefer dir.close();
        try search_dirs.append(.{ .dir = dir, .path = try allocator.dupe(u8, extra_include_path) });
    }
    for (options.system_include_paths) |system_include_path| {
        var dir = open_search_path_dir(options.cwd, system_include_path) catch {
            // TODO: maybe a warning that the search path is skipped?
            continue;
        };
        errdefer dir.close();
        try search_dirs.append(.{ .dir = dir, .path = try allocator.dupe(u8, system_include_path) });
    }
    if (!options.ignore_include_env_var) {
        const INCLUDE = std.process.get_env_var_owned(allocator, "INCLUDE") catch "";
        defer allocator.free(INCLUDE);

        // The only precedence here is llvm-rc which also uses the platform-specific
        // delimiter. There's no precedence set by `rc.exe` since it's Windows-only.
        const delimiter = switch (builtin.os.tag) {
            .windows => ';',
            else => ':',
        };
        var it = std.mem.tokenize_scalar(u8, INCLUDE, delimiter);
        while (it.next()) |search_path| {
            var dir = open_search_path_dir(options.cwd, search_path) catch continue;
            errdefer dir.close();
            try search_dirs.append(.{ .dir = dir, .path = try allocator.dupe(u8, search_path) });
        }
    }

    var arena_allocator = std.heap.ArenaAllocator.init(allocator);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    var compiler = Compiler{
        .source = source,
        .arena = arena,
        .allocator = allocator,
        .cwd = options.cwd,
        .diagnostics = options.diagnostics,
        .dependencies_list = options.dependencies_list,
        .input_code_pages = &tree.input_code_pages,
        .output_code_pages = &tree.output_code_pages,
        // This is only safe because we know search_dirs won't be modified past this point
        .search_dirs = search_dirs.items,
        .null_terminate_string_table_strings = options.null_terminate_string_table_strings,
        .silent_duplicate_control_ids = options.silent_duplicate_control_ids,
    };
    if (options.default_language_id) |default_language_id| {
        compiler.state.language = res.Language.from_int(default_language_id);
    }

    try compiler.write_root(tree.root(), writer);
}

pub const Compiler = struct {
    source: []const u8,
    arena: Allocator,
    allocator: Allocator,
    cwd: std.fs.Dir,
    state: State = .{},
    diagnostics: *Diagnostics,
    dependencies_list: ?*std.ArrayList([]const u8),
    input_code_pages: *const CodePageLookup,
    output_code_pages: *const CodePageLookup,
    search_dirs: []SearchDir,
    null_terminate_string_table_strings: bool,
    silent_duplicate_control_ids: bool,

    pub const State = struct {
        icon_id: u16 = 1,
        string_tables: StringTablesByLanguage = .{},
        language: res.Language = .{},
        font_dir: FontDir = .{},
        version: u32 = 0,
        characteristics: u32 = 0,
    };

    pub fn write_root(self: *Compiler, root: *Node.Root, writer: anytype) !void {
        try write_empty_resource(writer);
        for (root.body) |node| {
            try self.write_node(node, writer);
        }

        // now write the FONTDIR (if it has anything in it)
        try self.state.font_dir.write_res_data(self, writer);
        if (self.state.font_dir.fonts.items.len != 0) {
            // The Win32 RC compiler may write a different FONTDIR resource than us,
            // due to it sometimes writing a non-zero-length device name/face name
            // whereas we *always* write them both as zero-length.
            //
            // In practical terms, this doesn't matter, since for various reasons the format
            // of the FONTDIR cannot be relied on and is seemingly not actually used by anything
            // anymore. We still want to emit some sort of diagnostic for the purposes of being able
            // to know that our .RES is intentionally not meant to be byte-for-byte identical with
            // the rc.exe output.
            //
            // By using the hint type here, we allow this diagnostic to be detected in code,
            // but it will not be printed since the end-user doesn't need to care.
            try self.add_error_details(.{
                .err = .result_contains_fontdir,
                .type = .hint,
                .token = undefined,
            });
        }
        // once we've written every else out, we can write out the finalized STRINGTABLE resources
        var string_tables_it = self.state.string_tables.tables.iterator();
        while (string_tables_it.next()) |string_table_entry| {
            var string_table_it = string_table_entry.value_ptr.blocks.iterator();
            while (string_table_it.next()) |entry| {
                try entry.value_ptr.write_res_data(self, string_table_entry.key_ptr.*, entry.key_ptr.*, writer);
            }
        }
    }

    pub fn write_node(self: *Compiler, node: *Node, writer: anytype) !void {
        switch (node.id) {
            .root => unreachable, // write_root should be called directly instead
            .resource_external => try self.write_resource_external(@align_cast(@fieldParentPtr("base", node)), writer),
            .resource_raw_data => try self.write_resource_raw_data(@align_cast(@fieldParentPtr("base", node)), writer),
            .literal => unreachable, // this is context dependent and should be handled by its parent
            .binary_expression => unreachable,
            .grouped_expression => unreachable,
            .not_expression => unreachable,
            .invalid => {}, // no-op, currently only used for dangling literals at EOF
            .accelerators => try self.write_accelerators(@align_cast(@fieldParentPtr("base", node)), writer),
            .accelerator => unreachable, // handled by write_accelerators
            .dialog => try self.write_dialog(@align_cast(@fieldParentPtr("base", node)), writer),
            .control_statement => unreachable,
            .toolbar => try self.write_toolbar(@align_cast(@fieldParentPtr("base", node)), writer),
            .menu => try self.write_menu(@align_cast(@fieldParentPtr("base", node)), writer),
            .menu_item => unreachable,
            .menu_item_separator => unreachable,
            .menu_item_ex => unreachable,
            .popup => unreachable,
            .popup_ex => unreachable,
            .version_info => try self.write_version_info(@align_cast(@fieldParentPtr("base", node)), writer),
            .version_statement => unreachable,
            .block => unreachable,
            .block_value => unreachable,
            .block_value_value => unreachable,
            .string_table => try self.write_string_table(@align_cast(@fieldParentPtr("base", node))),
            .string_table_string => unreachable, // handled by write_string_table
            .language_statement => self.write_language_statement(@align_cast(@fieldParentPtr("base", node))),
            .font_statement => unreachable,
            .simple_statement => self.write_top_level_simple_statement(@align_cast(@fieldParentPtr("base", node))),
        }
    }

    /// Returns the filename encoded as UTF-8 (allocated by self.allocator)
    pub fn evaluate_filename_expression(self: *Compiler, expression_node: *Node) ![]u8 {
        switch (expression_node.id) {
            .literal => {
                const literal_node = expression_node.cast(.literal).?;
                switch (literal_node.token.id) {
                    .literal, .number => {
                        const slice = literal_node.token.slice(self.source);
                        const code_page = self.input_code_pages.get_for_token(literal_node.token);
                        var buf = try std.ArrayList(u8).init_capacity(self.allocator, slice.len);
                        errdefer buf.deinit();

                        var index: usize = 0;
                        while (code_page.codepoint_at(index, slice)) |codepoint| : (index += codepoint.byte_len) {
                            const c = codepoint.value;
                            if (c == code_pages.Codepoint.invalid) {
                                try buf.append_slice("�");
                            } else {
                                // Anything that is not returned as an invalid codepoint must be encodable as UTF-8.
                                const utf8_len = std.unicode.utf8_codepoint_sequence_length(c) catch unreachable;
                                try buf.ensure_unused_capacity(utf8_len);
                                _ = std.unicode.utf8_encode(c, buf.unused_capacity_slice()) catch unreachable;
                                buf.items.len += utf8_len;
                            }
                        }

                        return buf.to_owned_slice();
                    },
                    .quoted_ascii_string, .quoted_wide_string => {
                        const slice = literal_node.token.slice(self.source);
                        const column = literal_node.token.calculate_column(self.source, 8, null);
                        const bytes = SourceBytes{ .slice = slice, .code_page = self.input_code_pages.get_for_token(literal_node.token) };

                        var buf = std.ArrayList(u8).init(self.allocator);
                        errdefer buf.deinit();

                        // Filenames are sort-of parsed as if they were wide strings, but the max escape width of
                        // hex/octal escapes is still determined by the L prefix. Since we want to end up with
                        // UTF-8, we can parse either string type directly to UTF-8.
                        var parser = literals.IterativeStringParser.init(bytes, .{
                            .start_column = column,
                            .diagnostics = .{ .diagnostics = self.diagnostics, .token = literal_node.token },
                        });

                        while (try parser.next_unchecked()) |parsed| {
                            const c = parsed.codepoint;
                            if (c == code_pages.Codepoint.invalid) {
                                try buf.append_slice("�");
                            } else {
                                var codepoint_buf: [4]u8 = undefined;
                                // If the codepoint cannot be encoded, we fall back to �
                                if (std.unicode.utf8_encode(c, &codepoint_buf)) |len| {
                                    try buf.append_slice(codepoint_buf[0..len]);
                                } else |_| {
                                    try buf.append_slice("�");
                                }
                            }
                        }

                        return buf.to_owned_slice();
                    },
                    else => unreachable, // no other token types should be in a filename literal node
                }
            },
            .binary_expression => {
                const binary_expression_node = expression_node.cast(.binary_expression).?;
                return self.evaluate_filename_expression(binary_expression_node.right);
            },
            .grouped_expression => {
                const grouped_expression_node = expression_node.cast(.grouped_expression).?;
                return self.evaluate_filename_expression(grouped_expression_node.expression);
            },
            else => unreachable,
        }
    }

    /// https://learn.microsoft.com/en-us/windows/win32/menurc/searching-for-files
    ///
    /// Searches, in this order:
    ///  Directory of the 'root' .rc file (if different from CWD)
    ///  CWD
    ///  extra_include_paths (resolved relative to CWD)
    ///  system_include_paths (resolve relative to CWD)
    ///  INCLUDE environment var paths (only if ignore_include_env_var is false; resolved relative to CWD)
    ///
    /// Note: The CWD being searched *in addition to* the directory of the 'root' .rc file
    ///       is also how the Win32 RC compiler preprocessor searches for includes, but that
    ///       differs from how the clang preprocessor searches for includes.
    ///
    /// Note: This will always return the first matching file that can be opened.
    ///       This matches the Win32 RC compiler, which will fail with an error if the first
    ///       matching file is invalid. That is, it does not do the `cmd` PATH searching
    ///       thing of continuing to look for matching files until it finds a valid
    ///       one if a matching file is invalid.
    fn search_for_file(self: *Compiler, path: []const u8) !std.fs.File {
        // If the path is absolute, then it is not resolved relative to any search
        // paths, so there's no point in checking them.
        //
        // This behavior was determined/confirmed with the following test:
        // - A `test.rc` file with the contents `1 RCDATA "/test.bin"`
        // - A `test.bin` file at `C:\test.bin`
        // - A `test.bin` file at `inc\test.bin` relative to the .rc file
        // - Invoking `rc` with `rc /i inc test.rc`
        //
        // This results in a .res file with the contents of `C:\test.bin`, not
        // the contents of `inc\test.bin`. Further, if `C:\test.bin` is deleted,
        // then it start failing to find `/test.bin`, meaning that it does not resolve
        // `/test.bin` relative to include paths and instead only treats it as
        // an absolute path.
        if (std.fs.path.is_absolute(path)) {
            const file = try utils.open_file_not_dir(std.fs.cwd(), path, .{});
            errdefer file.close();

            if (self.dependencies_list) |dependencies_list| {
                const duped_path = try dependencies_list.allocator.dupe(u8, path);
                errdefer dependencies_list.allocator.free(duped_path);
                try dependencies_list.append(duped_path);
            }
        }

        var first_error: ?std.fs.File.OpenError = null;
        for (self.search_dirs) |search_dir| {
            if (utils.open_file_not_dir(search_dir.dir, path, .{})) |file| {
                errdefer file.close();

                if (self.dependencies_list) |dependencies_list| {
                    const searched_file_path = try std.fs.path.join(dependencies_list.allocator, &.{
                        search_dir.path orelse "", path,
                    });
                    errdefer dependencies_list.allocator.free(searched_file_path);
                    try dependencies_list.append(searched_file_path);
                }

                return file;
            } else |err| if (first_error == null) {
                first_error = err;
            }
        }
        return first_error orelse error.FileNotFound;
    }

    pub fn parse_dlg_include_string(self: *Compiler, token: Token) ![]u8 {
        // For the purposes of parsing, we want to strip the L prefix
        // if it exists since we want escaped integers to be limited to
        // their ascii string range.
        //
        // We keep track of whether or not there was an L prefix, though,
        // since there's more weirdness to come.
        var bytes = self.source_bytes_for_token(token);
        var was_wide_string = false;
        if (bytes.slice[0] == 'L' or bytes.slice[0] == 'l') {
            was_wide_string = true;
            bytes.slice = bytes.slice[1..];
        }

        var buf = try std.ArrayList(u8).init_capacity(self.allocator, bytes.slice.len);
        errdefer buf.deinit();

        var iterative_parser = literals.IterativeStringParser.init(bytes, .{
            .start_column = token.calculate_column(self.source, 8, null),
            .diagnostics = .{ .diagnostics = self.diagnostics, .token = token },
        });

        // No real idea what's going on here, but this matches the rc.exe behavior
        while (try iterative_parser.next()) |parsed| {
            const c = parsed.codepoint;
            switch (was_wide_string) {
                true => {
                    switch (c) {
                        0...0x7F, 0xA0...0xFF => try buf.append(@int_cast(c)),
                        0x80...0x9F => {
                            if (windows1252.best_fit_from_codepoint(c)) |_| {
                                try buf.append(@int_cast(c));
                            } else {
                                try buf.append('?');
                            }
                        },
                        else => {
                            if (windows1252.best_fit_from_codepoint(c)) |best_fit| {
                                try buf.append(best_fit);
                            } else if (c < 0x10000 or c == code_pages.Codepoint.invalid) {
                                try buf.append('?');
                            } else {
                                try buf.append_slice("??");
                            }
                        },
                    }
                },
                false => {
                    if (parsed.from_escaped_integer) {
                        try buf.append(@truncate(c));
                    } else {
                        if (windows1252.best_fit_from_codepoint(c)) |best_fit| {
                            try buf.append(best_fit);
                        } else if (c < 0x10000 or c == code_pages.Codepoint.invalid) {
                            try buf.append('?');
                        } else {
                            try buf.append_slice("??");
                        }
                    }
                },
            }
        }

        return buf.to_owned_slice();
    }

    pub fn write_resource_external(self: *Compiler, node: *Node.ResourceExternal, writer: anytype) !void {
        // Init header with data size zero for now, will need to fill it in later
        var header = try self.resource_header(node.id, node.type, .{});
        defer header.deinit(self.allocator);

        const maybe_predefined_type = header.predefined_resource_type();

        // DLGINCLUDE has special handling that doesn't actually need the file to exist
        if (maybe_predefined_type != null and maybe_predefined_type.? == .DLGINCLUDE) {
            const filename_token = node.filename.cast(.literal).?.token;
            const parsed_filename = try self.parse_dlg_include_string(filename_token);
            defer self.allocator.free(parsed_filename);

            // NUL within the parsed string acts as a terminator
            const parsed_filename_terminated = std.mem.slice_to(parsed_filename, 0);

            header.apply_memory_flags(node.common_resource_attributes, self.source);
            header.data_size = @int_cast(parsed_filename_terminated.len + 1);
            try header.write(writer, .{ .diagnostics = self.diagnostics, .token = node.id });
            try writer.write_all(parsed_filename_terminated);
            try writer.write_byte(0);
            try write_data_padding(writer, header.data_size);
            return;
        }

        const filename_utf8 = try self.evaluate_filename_expression(node.filename);
        defer self.allocator.free(filename_utf8);

        // TODO: More robust checking of the validity of the filename.
        //       This currently only checks for NUL bytes, but it should probably also check for
        //       platform-specific invalid characters like '*', '?', '"', '<', '>', '|' (Windows)
        //       Related: https://github.com/ziglang/zig/pull/14533#issuecomment-1416888193
        if (std.mem.index_of_scalar(u8, filename_utf8, 0) != null) {
            return self.add_error_details_and_fail(.{
                .err = .invalid_filename,
                .token = node.filename.get_first_token(),
                .token_span_end = node.filename.get_last_token(),
                .extra = .{ .number = 0 },
            });
        }

        // Allow plain number literals, but complex number expressions are evaluated strangely
        // and almost certainly lead to things not intended by the user (e.g. '(1+-1)' evaluates
        // to the filename '-1'), so error if the filename node is a grouped/binary expression.
        // Note: This is done here instead of during parsing so that we can easily include
        //       the evaluated filename as part of the error messages.
        if (node.filename.id != .literal) {
            const filename_string_index = try self.diagnostics.put_string(filename_utf8);
            try self.add_error_details(.{
                .err = .number_expression_as_filename,
                .token = node.filename.get_first_token(),
                .token_span_end = node.filename.get_last_token(),
                .extra = .{ .number = filename_string_index },
            });
            return self.add_error_details_and_fail(.{
                .err = .number_expression_as_filename,
                .type = .note,
                .token = node.filename.get_first_token(),
                .token_span_end = node.filename.get_last_token(),
                .print_source_line = false,
                .extra = .{ .number = filename_string_index },
            });
        }
        // From here on out, we know that the filename must be comprised of a single token,
        // so get it here to simplify future usage.
        const filename_token = node.filename.get_first_token();

        const file = self.search_for_file(filename_utf8) catch |err| switch (err) {
            error.OutOfMemory => |e| return e,
            else => |e| {
                const filename_string_index = try self.diagnostics.put_string(filename_utf8);
                return self.add_error_details_and_fail(.{
                    .err = .file_open_error,
                    .token = filename_token,
                    .extra = .{ .file_open_error = .{
                        .err = ErrorDetails.FileOpenError.enum_from_error(e),
                        .filename_string_index = filename_string_index,
                    } },
                });
            },
        };
        defer file.close();

        if (maybe_predefined_type) |predefined_type| {
            switch (predefined_type) {
                .GROUP_ICON, .GROUP_CURSOR => {
                    // Check for animated icon first
                    if (ani.is_animated_icon(file.reader())) {
                        // Animated icons are just put into the resource unmodified,
                        // and the resource type changes to ANIICON/ANICURSOR

                        const new_predefined_type: res.RT = switch (predefined_type) {
                            .GROUP_ICON => .ANIICON,
                            .GROUP_CURSOR => .ANICURSOR,
                            else => unreachable,
                        };
                        header.type_value.ordinal = @int_from_enum(new_predefined_type);
                        header.memory_flags = MemoryFlags.defaults(new_predefined_type);
                        header.apply_memory_flags(node.common_resource_attributes, self.source);
                        header.data_size = @int_cast(try file.get_end_pos());

                        try header.write(writer, .{ .diagnostics = self.diagnostics, .token = node.id });
                        try file.seek_to(0);
                        try write_resource_data(writer, file.reader(), header.data_size);
                        return;
                    }

                    // is_animated_icon moved the file cursor so reset to the start
                    try file.seek_to(0);

                    const icon_dir = ico.read(self.allocator, file.reader(), try file.get_end_pos()) catch |err| switch (err) {
                        error.OutOfMemory => |e| return e,
                        else => |e| {
                            return self.icon_read_error(
                                e,
                                filename_utf8,
                                filename_token,
                                predefined_type,
                            );
                        },
                    };
                    defer icon_dir.deinit();

                    // This limit is inherent to the ico format since number of entries is a u16 field.
                    std.debug.assert(icon_dir.entries.len <= std.math.max_int(u16));

                    // Note: The Win32 RC compiler will compile the resource as whatever type is
                    //       in the icon_dir regardless of the type of resource specified in the .rc.
                    //       This leads to unusable .res files when the types mismatch, so
                    //       we error instead.
                    const res_types_match = switch (predefined_type) {
                        .GROUP_ICON => icon_dir.image_type == .icon,
                        .GROUP_CURSOR => icon_dir.image_type == .cursor,
                        else => unreachable,
                    };
                    if (!res_types_match) {
                        return self.add_error_details_and_fail(.{
                            .err = .icon_dir_and_resource_type_mismatch,
                            .token = filename_token,
                            .extra = .{ .resource = switch (predefined_type) {
                                .GROUP_ICON => .icon,
                                .GROUP_CURSOR => .cursor,
                                else => unreachable,
                            } },
                        });
                    }

                    // Memory flags affect the RT_ICON and the RT_GROUP_ICON differently
                    var icon_memory_flags = MemoryFlags.defaults(res.RT.ICON);
                    apply_to_memory_flags(&icon_memory_flags, node.common_resource_attributes, self.source);
                    apply_to_group_memory_flags(&header.memory_flags, node.common_resource_attributes, self.source);

                    const first_icon_id = self.state.icon_id;
                    const entry_type = if (predefined_type == .GROUP_ICON) @int_from_enum(res.RT.ICON) else @int_from_enum(res.RT.CURSOR);
                    for (icon_dir.entries, 0..) |*entry, entry_i_usize| {
                        // We know that the entry index must fit within a u16, so
                        // cast it here to simplify usage sites.
                        const entry_i: u16 = @int_cast(entry_i_usize);
                        var full_data_size = entry.data_size_in_bytes;
                        if (icon_dir.image_type == .cursor) {
                            full_data_size = std.math.add(u32, full_data_size, 4) catch {
                                return self.add_error_details_and_fail(.{
                                    .err = .resource_data_size_exceeds_max,
                                    .token = node.id,
                                });
                            };
                        }

                        const image_header = ResourceHeader{
                            .type_value = .{ .ordinal = entry_type },
                            .name_value = .{ .ordinal = self.state.icon_id },
                            .data_size = full_data_size,
                            .memory_flags = icon_memory_flags,
                            .language = self.state.language,
                            .version = self.state.version,
                            .characteristics = self.state.characteristics,
                        };
                        try image_header.write(writer, .{ .diagnostics = self.diagnostics, .token = node.id });

                        // From https://learn.microsoft.com/en-us/windows/win32/menurc/localheader:
                        // > The LOCALHEADER structure is the first data written to the RT_CURSOR
                        // > resource if a RESDIR structure contains information about a cursor.
                        // where LOCALHEADER is `struct { WORD xHotSpot; WORD yHotSpot; }`
                        if (icon_dir.image_type == .cursor) {
                            try writer.write_int(u16, entry.type_specific_data.cursor.hotspot_x, .little);
                            try writer.write_int(u16, entry.type_specific_data.cursor.hotspot_y, .little);
                        }

                        try file.seek_to(entry.data_offset_from_start_of_file);
                        var header_bytes = file.reader().read_bytes_no_eof(16) catch {
                            return self.icon_read_error(
                                error.UnexpectedEOF,
                                filename_utf8,
                                filename_token,
                                predefined_type,
                            );
                        };

                        const image_format = ico.ImageFormat.detect(&header_bytes);
                        if (!image_format.validate(&header_bytes)) {
                            return self.icon_read_error(
                                error.InvalidHeader,
                                filename_utf8,
                                filename_token,
                                predefined_type,
                            );
                        }
                        switch (image_format) {
                            .riff => switch (icon_dir.image_type) {
                                .icon => {
                                    // The Win32 RC compiler treats this as an error, but icon dirs
                                    // with RIFF encoded icons within them work ~okay (they work
                                    // in some places but not others, they may not animate, etc) if they are
                                    // allowed to be compiled.
                                    try self.add_error_details(.{
                                        .err = .rc_would_error_on_icon_dir,
                                        .type = .warning,
                                        .token = filename_token,
                                        .extra = .{ .icon_dir = .{ .icon_type = .icon, .icon_format = .riff, .index = entry_i } },
                                    });
                                    try self.add_error_details(.{
                                        .err = .rc_would_error_on_icon_dir,
                                        .type = .note,
                                        .print_source_line = false,
                                        .token = filename_token,
                                        .extra = .{ .icon_dir = .{ .icon_type = .icon, .icon_format = .riff, .index = entry_i } },
                                    });
                                },
                                .cursor => {
                                    // The Win32 RC compiler errors in this case too, but we only error
                                    // here because the cursor would fail to be loaded at runtime if we
                                    // compiled it.
                                    return self.add_error_details_and_fail(.{
                                        .err = .format_not_supported_in_icon_dir,
                                        .token = filename_token,
                                        .extra = .{ .icon_dir = .{ .icon_type = .cursor, .icon_format = .riff, .index = entry_i } },
                                    });
                                },
                            },
                            .png => switch (icon_dir.image_type) {
                                .icon => {
                                    // PNG always seems to have 1 for color planes no matter what
                                    entry.type_specific_data.icon.color_planes = 1;
                                    // These seem to be the only values of num_colors that
                                    // get treated specially
                                    entry.type_specific_data.icon.bits_per_pixel = switch (entry.num_colors) {
                                        2 => 1,
                                        8 => 3,
                                        16 => 4,
                                        else => entry.type_specific_data.icon.bits_per_pixel,
                                    };
                                },
                                .cursor => {
                                    // The Win32 RC compiler treats this as an error, but cursor dirs
                                    // with PNG encoded icons within them work fine if they are
                                    // allowed to be compiled.
                                    try self.add_error_details(.{
                                        .err = .rc_would_error_on_icon_dir,
                                        .type = .warning,
                                        .token = filename_token,
                                        .extra = .{ .icon_dir = .{ .icon_type = .cursor, .icon_format = .png, .index = entry_i } },
                                    });
                                },
                            },
                            .dib => {
                                const bitmap_header: *ico.BitmapHeader = @ptr_cast(@align_cast(&header_bytes));
                                if (native_endian == .big) {
                                    std.mem.byte_swap_all_fields(ico.BitmapHeader, bitmap_header);
                                }
                                const bitmap_version = ico.BitmapHeader.Version.get(bitmap_header.bcSize);

                                // The Win32 RC compiler only allows headers with
                                // `bcSize == sizeof(BITMAPINFOHEADER)`, but it seems unlikely
                                // that there's a good reason for that outside of too-old
                                // bitmap headers.
                                // TODO: Need to test V4 and V5 bitmaps to check they actually work
                                if (bitmap_version == .@"win2.0") {
                                    return self.add_error_details_and_fail(.{
                                        .err = .rc_would_error_on_bitmap_version,
                                        .token = filename_token,
                                        .extra = .{ .icon_dir = .{
                                            .icon_type = if (icon_dir.image_type == .icon) .icon else .cursor,
                                            .icon_format = image_format,
                                            .index = entry_i,
                                            .bitmap_version = bitmap_version,
                                        } },
                                    });
                                } else if (bitmap_version != .@"nt3.1") {
                                    try self.add_error_details(.{
                                        .err = .rc_would_error_on_bitmap_version,
                                        .type = .warning,
                                        .token = filename_token,
                                        .extra = .{ .icon_dir = .{
                                            .icon_type = if (icon_dir.image_type == .icon) .icon else .cursor,
                                            .icon_format = image_format,
                                            .index = entry_i,
                                            .bitmap_version = bitmap_version,
                                        } },
                                    });
                                }

                                switch (icon_dir.image_type) {
                                    .icon => {
                                        // The values in the icon's BITMAPINFOHEADER always take precedence over
                                        // the values in the IconDir, but not in the LOCALHEADER (see above).
                                        entry.type_specific_data.icon.color_planes = bitmap_header.bcPlanes;
                                        entry.type_specific_data.icon.bits_per_pixel = bitmap_header.bcBitCount;
                                    },
                                    .cursor => {
                                        // Only cursors get the width/height from BITMAPINFOHEADER (icons don't)
                                        entry.width = @int_cast(bitmap_header.bcWidth);
                                        entry.height = @int_cast(bitmap_header.bcHeight);
                                        entry.type_specific_data.cursor.hotspot_x = bitmap_header.bcPlanes;
                                        entry.type_specific_data.cursor.hotspot_y = bitmap_header.bcBitCount;
                                    },
                                }
                            },
                        }

                        try file.seek_to(entry.data_offset_from_start_of_file);
                        try write_resource_data_no_padding(writer, file.reader(), entry.data_size_in_bytes);
                        try write_data_padding(writer, full_data_size);

                        if (self.state.icon_id == std.math.max_int(u16)) {
                            try self.add_error_details(.{
                                .err = .max_icon_ids_exhausted,
                                .print_source_line = false,
                                .token = filename_token,
                                .extra = .{ .icon_dir = .{
                                    .icon_type = if (icon_dir.image_type == .icon) .icon else .cursor,
                                    .icon_format = image_format,
                                    .index = entry_i,
                                } },
                            });
                            return self.add_error_details_and_fail(.{
                                .err = .max_icon_ids_exhausted,
                                .type = .note,
                                .token = filename_token,
                                .extra = .{ .icon_dir = .{
                                    .icon_type = if (icon_dir.image_type == .icon) .icon else .cursor,
                                    .icon_format = image_format,
                                    .index = entry_i,
                                } },
                            });
                        }
                        self.state.icon_id += 1;
                    }

                    header.data_size = icon_dir.get_res_data_size();

                    try header.write(writer, .{ .diagnostics = self.diagnostics, .token = node.id });
                    try icon_dir.write_res_data(writer, first_icon_id);
                    try write_data_padding(writer, header.data_size);
                    return;
                },
                .RCDATA, .HTML, .MANIFEST, .MESSAGETABLE, .DLGINIT, .PLUGPLAY => {
                    header.apply_memory_flags(node.common_resource_attributes, self.source);
                },
                .BITMAP => {
                    header.apply_memory_flags(node.common_resource_attributes, self.source);
                    const file_size = try file.get_end_pos();

                    const bitmap_info = bmp.read(file.reader(), file_size) catch |err| {
                        const filename_string_index = try self.diagnostics.put_string(filename_utf8);
                        return self.add_error_details_and_fail(.{
                            .err = .bmp_read_error,
                            .token = filename_token,
                            .extra = .{ .bmp_read_error = .{
                                .err = ErrorDetails.BitmapReadError.enum_from_error(err),
                                .filename_string_index = filename_string_index,
                            } },
                        });
                    };

                    if (bitmap_info.get_actual_palette_byte_len() > bitmap_info.get_expected_palette_byte_len()) {
                        const num_ignored_bytes = bitmap_info.get_actual_palette_byte_len() - bitmap_info.get_expected_palette_byte_len();
                        var number_as_bytes: [8]u8 = undefined;
                        std.mem.write_int(u64, &number_as_bytes, num_ignored_bytes, native_endian);
                        const value_string_index = try self.diagnostics.put_string(&number_as_bytes);
                        try self.add_error_details(.{
                            .err = .bmp_ignored_palette_bytes,
                            .type = .warning,
                            .token = filename_token,
                            .extra = .{ .number = value_string_index },
                        });
                    } else if (bitmap_info.get_actual_palette_byte_len() < bitmap_info.get_expected_palette_byte_len()) {
                        const num_padding_bytes = bitmap_info.get_expected_palette_byte_len() - bitmap_info.get_actual_palette_byte_len();

                        // TODO: Make this configurable (command line option)
                        const max_missing_bytes = 4096;
                        if (num_padding_bytes > max_missing_bytes) {
                            var numbers_as_bytes: [16]u8 = undefined;
                            std.mem.write_int(u64, numbers_as_bytes[0..8], num_padding_bytes, native_endian);
                            std.mem.write_int(u64, numbers_as_bytes[8..16], max_missing_bytes, native_endian);
                            const values_string_index = try self.diagnostics.put_string(&numbers_as_bytes);
                            try self.add_error_details(.{
                                .err = .bmp_too_many_missing_palette_bytes,
                                .token = filename_token,
                                .extra = .{ .number = values_string_index },
                            });
                            return self.add_error_details_and_fail(.{
                                .err = .bmp_too_many_missing_palette_bytes,
                                .type = .note,
                                .print_source_line = false,
                                .token = filename_token,
                            });
                        }

                        var number_as_bytes: [8]u8 = undefined;
                        std.mem.write_int(u64, &number_as_bytes, num_padding_bytes, native_endian);
                        const value_string_index = try self.diagnostics.put_string(&number_as_bytes);
                        try self.add_error_details(.{
                            .err = .bmp_missing_palette_bytes,
                            .type = .warning,
                            .token = filename_token,
                            .extra = .{ .number = value_string_index },
                        });
                        const pixel_data_len = bitmap_info.get_pixel_data_len(file_size);
                        if (pixel_data_len > 0) {
                            const miscompiled_bytes = @min(pixel_data_len, num_padding_bytes);
                            std.mem.write_int(u64, &number_as_bytes, miscompiled_bytes, native_endian);
                            const miscompiled_bytes_string_index = try self.diagnostics.put_string(&number_as_bytes);
                            try self.add_error_details(.{
                                .err = .rc_would_miscompile_bmp_palette_padding,
                                .type = .warning,
                                .token = filename_token,
                                .extra = .{ .number = miscompiled_bytes_string_index },
                            });
                        }
                    }

                    // TODO: It might be possible that the calculation done in this function
                    //       could underflow if the underlying file is modified while reading
                    //       it, but need to think about it more to determine if that's a
                    //       real possibility
                    const bmp_bytes_to_write: u32 = @int_cast(bitmap_info.get_expected_byte_len(file_size));

                    header.data_size = bmp_bytes_to_write;
                    try header.write(writer, .{ .diagnostics = self.diagnostics, .token = node.id });
                    try file.seek_to(bmp.file_header_len);
                    const file_reader = file.reader();
                    try write_resource_data_no_padding(writer, file_reader, bitmap_info.dib_header_size);
                    if (bitmap_info.get_bitmasks_byte_len() > 0) {
                        try write_resource_data_no_padding(writer, file_reader, bitmap_info.get_bitmasks_byte_len());
                    }
                    if (bitmap_info.get_expected_palette_byte_len() > 0) {
                        try write_resource_data_no_padding(writer, file_reader, @int_cast(bitmap_info.get_actual_palette_byte_len()));
                        // We know that the number of missing palette bytes is <= 4096
                        // (see `bmp_too_many_missing_palette_bytes` error case above)
                        const padding_bytes: usize = @int_cast(bitmap_info.get_missing_palette_byte_len());
                        if (padding_bytes > 0) {
                            try writer.write_byte_ntimes(0, padding_bytes);
                        }
                    }
                    try file.seek_to(bitmap_info.pixel_data_offset);
                    const pixel_bytes: u32 = @int_cast(file_size - bitmap_info.pixel_data_offset);
                    try write_resource_data_no_padding(writer, file_reader, pixel_bytes);
                    try write_data_padding(writer, bmp_bytes_to_write);
                    return;
                },
                .FONT => {
                    if (self.state.font_dir.ids.get(header.name_value.ordinal) != null) {
                        // Add warning and skip this resource
                        // Note: The Win32 compiler prints this as an error but it doesn't fail the compilation
                        // and the duplicate resource is skipped.
                        try self.add_error_details(ErrorDetails{
                            .err = .font_id_already_defined,
                            .token = node.id,
                            .type = .warning,
                            .extra = .{ .number = header.name_value.ordinal },
                        });
                        try self.add_error_details(ErrorDetails{
                            .err = .font_id_already_defined,
                            .token = self.state.font_dir.ids.get(header.name_value.ordinal).?,
                            .type = .note,
                            .extra = .{ .number = header.name_value.ordinal },
                        });
                        return;
                    }
                    header.apply_memory_flags(node.common_resource_attributes, self.source);
                    const file_size = try file.get_end_pos();
                    if (file_size > std.math.max_int(u32)) {
                        return self.add_error_details_and_fail(.{
                            .err = .resource_data_size_exceeds_max,
                            .token = node.id,
                        });
                    }

                    // We now know that the data size will fit in a u32
                    header.data_size = @int_cast(file_size);
                    try header.write(writer, .{ .diagnostics = self.diagnostics, .token = node.id });

                    var header_slurping_reader = header_slurping_reader(148, file.reader());
                    try write_resource_data(writer, header_slurping_reader.reader(), header.data_size);

                    try self.state.font_dir.add(self.arena, FontDir.Font{
                        .id = header.name_value.ordinal,
                        .header_bytes = header_slurping_reader.slurped_header,
                    }, node.id);
                    return;
                },
                .ACCELERATOR,
                .ANICURSOR,
                .ANIICON,
                .CURSOR,
                .DIALOG,
                .DLGINCLUDE,
                .FONTDIR,
                .ICON,
                .MENU,
                .STRING,
                .TOOLBAR,
                .VERSION,
                .VXD,
                => unreachable,
                _ => unreachable,
            }
        } else {
            header.apply_memory_flags(node.common_resource_attributes, self.source);
        }

        // Fallback to just writing out the entire contents of the file
        const data_size = try file.get_end_pos();
        if (data_size > std.math.max_int(u32)) {
            return self.add_error_details_and_fail(.{
                .err = .resource_data_size_exceeds_max,
                .token = node.id,
            });
        }
        // We now know that the data size will fit in a u32
        header.data_size = @int_cast(data_size);
        try header.write(writer, .{ .diagnostics = self.diagnostics, .token = node.id });
        try write_resource_data(writer, file.reader(), header.data_size);
    }

    fn icon_read_error(
        self: *Compiler,
        err: ico.ReadError,
        filename: []const u8,
        token: Token,
        predefined_type: res.RT,
    ) error{ CompileError, OutOfMemory } {
        const filename_string_index = try self.diagnostics.put_string(filename);
        return self.add_error_details_and_fail(.{
            .err = .icon_read_error,
            .token = token,
            .extra = .{ .icon_read_error = .{
                .err = ErrorDetails.IconReadError.enum_from_error(err),
                .icon_type = switch (predefined_type) {
                    .GROUP_ICON => .icon,
                    .GROUP_CURSOR => .cursor,
                    else => unreachable,
                },
                .filename_string_index = filename_string_index,
            } },
        });
    }

    pub const DataType = enum {
        number,
        ascii_string,
        wide_string,
    };

    pub const Data = union(DataType) {
        number: Number,
        ascii_string: []const u8,
        wide_string: [:0]const u16,

        pub fn deinit(self: Data, allocator: Allocator) void {
            switch (self) {
                .wide_string => |wide_string| {
                    allocator.free(wide_string);
                },
                .ascii_string => |ascii_string| {
                    allocator.free(ascii_string);
                },
                else => {},
            }
        }

        pub fn write(self: Data, writer: anytype) !void {
            switch (self) {
                .number => |number| switch (number.is_long) {
                    false => try writer.write_int(WORD, number.as_word(), .little),
                    true => try writer.write_int(DWORD, number.value, .little),
                },
                .ascii_string => |ascii_string| {
                    try writer.write_all(ascii_string);
                },
                .wide_string => |wide_string| {
                    try writer.write_all(std.mem.slice_as_bytes(wide_string));
                },
            }
        }
    };

    /// Assumes that the node is a number or number expression
    pub fn evaluate_number_expression(expression_node: *Node, source: []const u8, code_page_lookup: *const CodePageLookup) Number {
        switch (expression_node.id) {
            .literal => {
                const literal_node = expression_node.cast(.literal).?;
                std.debug.assert(literal_node.token.id == .number);
                const bytes = SourceBytes{
                    .slice = literal_node.token.slice(source),
                    .code_page = code_page_lookup.get_for_token(literal_node.token),
                };
                return literals.parse_number_literal(bytes);
            },
            .binary_expression => {
                const binary_expression_node = expression_node.cast(.binary_expression).?;
                const lhs = evaluate_number_expression(binary_expression_node.left, source, code_page_lookup);
                const rhs = evaluate_number_expression(binary_expression_node.right, source, code_page_lookup);
                const operator_char = binary_expression_node.operator.slice(source)[0];
                return lhs.evaluate_operator(operator_char, rhs);
            },
            .grouped_expression => {
                const grouped_expression_node = expression_node.cast(.grouped_expression).?;
                return evaluate_number_expression(grouped_expression_node.expression, source, code_page_lookup);
            },
            else => unreachable,
        }
    }

    const FlagsNumber = struct {
        value: u32,
        not_mask: u32 = 0xFFFFFFFF,

        pub fn evaluate_operator(lhs: FlagsNumber, operator_char: u8, rhs: FlagsNumber) FlagsNumber {
            const result = switch (operator_char) {
                '-' => lhs.value -% rhs.value,
                '+' => lhs.value +% rhs.value,
                '|' => lhs.value | rhs.value,
                '&' => lhs.value & rhs.value,
                else => unreachable, // invalid operator, this would be a lexer/parser bug
            };
            return .{
                .value = result,
                .not_mask = lhs.not_mask & rhs.not_mask,
            };
        }

        pub fn apply_not_mask(self: FlagsNumber) u32 {
            return self.value & self.not_mask;
        }
    };

    pub fn evaluate_flags_expression_with_default(default: u32, expression_node: *Node, source: []const u8, code_page_lookup: *const CodePageLookup) u32 {
        var context = FlagsExpressionContext{ .initial_value = default };
        const number = evaluate_flags_expression(expression_node, source, code_page_lookup, &context);
        return number.value;
    }

    pub const FlagsExpressionContext = struct {
        initial_value: u32 = 0,
        initial_value_used: bool = false,
    };

    /// Assumes that the node is a number expression (which can contain not_expressions)
    pub fn evaluate_flags_expression(expression_node: *Node, source: []const u8, code_page_lookup: *const CodePageLookup, context: *FlagsExpressionContext) FlagsNumber {
        switch (expression_node.id) {
            .literal => {
                const literal_node = expression_node.cast(.literal).?;
                std.debug.assert(literal_node.token.id == .number);
                const bytes = SourceBytes{
                    .slice = literal_node.token.slice(source),
                    .code_page = code_page_lookup.get_for_token(literal_node.token),
                };
                var value = literals.parse_number_literal(bytes).value;
                if (!context.initial_value_used) {
                    context.initial_value_used = true;
                    value |= context.initial_value;
                }
                return .{ .value = value };
            },
            .binary_expression => {
                const binary_expression_node = expression_node.cast(.binary_expression).?;
                const lhs = evaluate_flags_expression(binary_expression_node.left, source, code_page_lookup, context);
                const rhs = evaluate_flags_expression(binary_expression_node.right, source, code_page_lookup, context);
                const operator_char = binary_expression_node.operator.slice(source)[0];
                const result = lhs.evaluate_operator(operator_char, rhs);
                return .{ .value = result.apply_not_mask() };
            },
            .grouped_expression => {
                const grouped_expression_node = expression_node.cast(.grouped_expression).?;
                return evaluate_flags_expression(grouped_expression_node.expression, source, code_page_lookup, context);
            },
            .not_expression => {
                const not_expression = expression_node.cast(.not_expression).?;
                const bytes = SourceBytes{
                    .slice = not_expression.number_token.slice(source),
                    .code_page = code_page_lookup.get_for_token(not_expression.number_token),
                };
                const not_number = literals.parse_number_literal(bytes);
                if (!context.initial_value_used) {
                    context.initial_value_used = true;
                    return .{ .value = context.initial_value & ~not_number.value };
                }
                return .{ .value = 0, .not_mask = ~not_number.value };
            },
            else => unreachable,
        }
    }

    pub fn evaluate_data_expression(self: *Compiler, expression_node: *Node) !Data {
        switch (expression_node.id) {
            .literal => {
                const literal_node = expression_node.cast(.literal).?;
                switch (literal_node.token.id) {
                    .number => {
                        const number = evaluate_number_expression(expression_node, self.source, self.input_code_pages);
                        return .{ .number = number };
                    },
                    .quoted_ascii_string => {
                        const column = literal_node.token.calculate_column(self.source, 8, null);
                        const bytes = SourceBytes{
                            .slice = literal_node.token.slice(self.source),
                            .code_page = self.input_code_pages.get_for_token(literal_node.token),
                        };
                        const parsed = try literals.parse_quoted_ascii_string(self.allocator, bytes, .{
                            .start_column = column,
                            .diagnostics = .{ .diagnostics = self.diagnostics, .token = literal_node.token },
                            .output_code_page = self.output_code_pages.get_for_token(literal_node.token),
                        });
                        errdefer self.allocator.free(parsed);
                        return .{ .ascii_string = parsed };
                    },
                    .quoted_wide_string => {
                        const column = literal_node.token.calculate_column(self.source, 8, null);
                        const bytes = SourceBytes{
                            .slice = literal_node.token.slice(self.source),
                            .code_page = self.input_code_pages.get_for_token(literal_node.token),
                        };
                        const parsed_string = try literals.parse_quoted_wide_string(self.allocator, bytes, .{
                            .start_column = column,
                            .diagnostics = .{ .diagnostics = self.diagnostics, .token = literal_node.token },
                        });
                        errdefer self.allocator.free(parsed_string);
                        return .{ .wide_string = parsed_string };
                    },
                    else => unreachable, // no other token types should be in a data literal node
                }
            },
            .binary_expression, .grouped_expression => {
                const result = evaluate_number_expression(expression_node, self.source, self.input_code_pages);
                return .{ .number = result };
            },
            .not_expression => unreachable,
            else => unreachable,
        }
    }

    pub fn write_resource_raw_data(self: *Compiler, node: *Node.ResourceRawData, writer: anytype) !void {
        var data_buffer = std.ArrayList(u8).init(self.allocator);
        defer data_buffer.deinit();
        // The header's data length field is a u32 so limit the resource's data size so that
        // we know we can always specify the real size.
        var limited_writer = limited_writer(data_buffer.writer(), std.math.max_int(u32));
        const data_writer = limited_writer.writer();

        for (node.raw_data) |expression| {
            const data = try self.evaluate_data_expression(expression);
            defer data.deinit(self.allocator);
            data.write(data_writer) catch |err| switch (err) {
                error.NoSpaceLeft => {
                    return self.add_error_details_and_fail(.{
                        .err = .resource_data_size_exceeds_max,
                        .token = node.id,
                    });
                },
                else => |e| return e,
            };
        }

        // This int_cast can't fail because the limited_writer above guarantees that
        // we will never write more than max_int(u32) bytes.
        const data_len: u32 = @int_cast(data_buffer.items.len);
        try self.write_resource_header(writer, node.id, node.type, data_len, node.common_resource_attributes, self.state.language);

        var data_fbs = std.io.fixed_buffer_stream(data_buffer.items);
        try write_resource_data(writer, data_fbs.reader(), data_len);
    }

    pub fn write_resource_header(self: *Compiler, writer: anytype, id_token: Token, type_token: Token, data_size: u32, common_resource_attributes: []Token, language: res.Language) !void {
        var header = try self.resource_header(id_token, type_token, .{
            .language = language,
            .data_size = data_size,
        });
        defer header.deinit(self.allocator);

        header.apply_memory_flags(common_resource_attributes, self.source);

        try header.write(writer, .{ .diagnostics = self.diagnostics, .token = id_token });
    }

    pub fn write_resource_data_no_padding(writer: anytype, data_reader: anytype, data_size: u32) !void {
        var limited_reader = std.io.limited_reader(data_reader, data_size);

        const FifoBuffer = std.fifo.LinearFifo(u8, .{ .Static = 4096 });
        var fifo = FifoBuffer.init();
        try fifo.pump(limited_reader.reader(), writer);
    }

    pub fn write_resource_data(writer: anytype, data_reader: anytype, data_size: u32) !void {
        try write_resource_data_no_padding(writer, data_reader, data_size);
        try write_data_padding(writer, data_size);
    }

    pub fn write_data_padding(writer: anytype, data_size: u32) !void {
        try writer.write_byte_ntimes(0, num_padding_bytes_needed(data_size));
    }

    pub fn num_padding_bytes_needed(data_size: u32) u2 {
        // Result is guaranteed to be between 0 and 3.
        return @int_cast((4 -% data_size) % 4);
    }

    pub fn evaluate_accelerator_key_expression(self: *Compiler, node: *Node, is_virt: bool) !u16 {
        if (node.is_number_expression()) {
            return evaluate_number_expression(node, self.source, self.input_code_pages).as_word();
        } else {
            std.debug.assert(node.is_string_literal());
            const literal: *Node.Literal = @align_cast(@fieldParentPtr("base", node));
            const bytes = SourceBytes{
                .slice = literal.token.slice(self.source),
                .code_page = self.input_code_pages.get_for_token(literal.token),
            };
            const column = literal.token.calculate_column(self.source, 8, null);
            return res.parse_accelerator_key_string(bytes, is_virt, .{
                .start_column = column,
                .diagnostics = .{ .diagnostics = self.diagnostics, .token = literal.token },
            });
        }
    }

    pub fn write_accelerators(self: *Compiler, node: *Node.Accelerators, writer: anytype) !void {
        var data_buffer = std.ArrayList(u8).init(self.allocator);
        defer data_buffer.deinit();

        // The header's data length field is a u32 so limit the resource's data size so that
        // we know we can always specify the real size.
        var limited_writer = limited_writer(data_buffer.writer(), std.math.max_int(u32));
        const data_writer = limited_writer.writer();

        self.write_accelerators_data(node, data_writer) catch |err| switch (err) {
            error.NoSpaceLeft => {
                return self.add_error_details_and_fail(.{
                    .err = .resource_data_size_exceeds_max,
                    .token = node.id,
                });
            },
            else => |e| return e,
        };

        // This int_cast can't fail because the limited_writer above guarantees that
        // we will never write more than max_int(u32) bytes.
        const data_size: u32 = @int_cast(data_buffer.items.len);
        var header = try self.resource_header(node.id, node.type, .{
            .data_size = data_size,
        });
        defer header.deinit(self.allocator);

        header.apply_memory_flags(node.common_resource_attributes, self.source);
        header.apply_optional_statements(node.optional_statements, self.source, self.input_code_pages);

        try header.write(writer, .{ .diagnostics = self.diagnostics, .token = node.id });

        var data_fbs = std.io.fixed_buffer_stream(data_buffer.items);
        try write_resource_data(writer, data_fbs.reader(), data_size);
    }

    /// Expects `data_writer` to be a LimitedWriter limited to u32, meaning all writes to
    /// the writer within this function could return error.NoSpaceLeft
    pub fn write_accelerators_data(self: *Compiler, node: *Node.Accelerators, data_writer: anytype) !void {
        for (node.accelerators, 0..) |accel_node, i| {
            const accelerator: *Node.Accelerator = @align_cast(@fieldParentPtr("base", accel_node));
            var modifiers = res.AcceleratorModifiers{};
            for (accelerator.type_and_options) |type_or_option| {
                const modifier = rc.AcceleratorTypeAndOptions.map.get(type_or_option.slice(self.source)).?;
                modifiers.apply(modifier);
            }
            if (accelerator.event.is_number_expression() and !modifiers.explicit_ascii_or_virtkey) {
                return self.add_error_details_and_fail(.{
                    .err = .accelerator_type_required,
                    .token = accelerator.event.get_first_token(),
                    .token_span_end = accelerator.event.get_last_token(),
                });
            }
            const key = self.evaluate_accelerator_key_expression(accelerator.event, modifiers.is_set(.virtkey)) catch |err| switch (err) {
                error.OutOfMemory => |e| return e,
                else => |e| {
                    return self.add_error_details_and_fail(.{
                        .err = .invalid_accelerator_key,
                        .token = accelerator.event.get_first_token(),
                        .token_span_end = accelerator.event.get_last_token(),
                        .extra = .{ .accelerator_error = .{
                            .err = ErrorDetails.AcceleratorError.enum_from_error(e),
                        } },
                    });
                },
            };
            const cmd_id = evaluate_number_expression(accelerator.idvalue, self.source, self.input_code_pages);

            if (i == node.accelerators.len - 1) {
                modifiers.mark_last();
            }

            try data_writer.write_byte(modifiers.value);
            try data_writer.write_byte(0); // padding
            try data_writer.write_int(u16, key, .little);
            try data_writer.write_int(u16, cmd_id.as_word(), .little);
            try data_writer.write_int(u16, 0, .little); // padding
        }
    }

    const DialogOptionalStatementValues = struct {
        style: u32 = res.WS.SYSMENU | res.WS.BORDER | res.WS.POPUP,
        exstyle: u32 = 0,
        class: ?NameOrOrdinal = null,
        menu: ?NameOrOrdinal = null,
        font: ?FontStatementValues = null,
        caption: ?Token = null,
    };

    pub fn write_dialog(self: *Compiler, node: *Node.Dialog, writer: anytype) !void {
        var data_buffer = std.ArrayList(u8).init(self.allocator);
        defer data_buffer.deinit();
        // The header's data length field is a u32 so limit the resource's data size so that
        // we know we can always specify the real size.
        var limited_writer = limited_writer(data_buffer.writer(), std.math.max_int(u32));
        const data_writer = limited_writer.writer();

        const resource = Resource.from_string(.{
            .slice = node.type.slice(self.source),
            .code_page = self.input_code_pages.get_for_token(node.type),
        });
        std.debug.assert(resource == .dialog or resource == .dialogex);

        var optional_statement_values: DialogOptionalStatementValues = .{};
        defer {
            if (optional_statement_values.class) |class| {
                class.deinit(self.allocator);
            }
            if (optional_statement_values.menu) |menu| {
                menu.deinit(self.allocator);
            }
        }
        var skipped_menu_or_classes = std.ArrayList(*Node.SimpleStatement).init(self.allocator);
        defer skipped_menu_or_classes.deinit();
        var last_menu: *Node.SimpleStatement = undefined;
        var last_class: *Node.SimpleStatement = undefined;
        var last_menu_would_be_forced_ordinal = false;
        var last_menu_has_digit_as_first_char = false;
        var last_menu_did_uppercase = false;
        var last_class_would_be_forced_ordinal = false;

        for (node.optional_statements) |optional_statement| {
            switch (optional_statement.id) {
                .simple_statement => {
                    const simple_statement: *Node.SimpleStatement = @align_cast(@fieldParentPtr("base", optional_statement));
                    const statement_identifier = simple_statement.identifier;
                    const statement_type = rc.OptionalStatements.dialog_map.get(statement_identifier.slice(self.source)) orelse continue;
                    switch (statement_type) {
                        .style, .exstyle => {
                            const style = evaluate_flags_expression_with_default(0, simple_statement.value, self.source, self.input_code_pages);
                            if (statement_type == .style) {
                                optional_statement_values.style = style;
                            } else {
                                optional_statement_values.exstyle = style;
                            }
                        },
                        .caption => {
                            std.debug.assert(simple_statement.value.id == .literal);
                            const literal_node: *Node.Literal = @align_cast(@fieldParentPtr("base", simple_statement.value));
                            optional_statement_values.caption = literal_node.token;
                        },
                        .class => {
                            const is_duplicate = optional_statement_values.class != null;
                            if (is_duplicate) {
                                try skipped_menu_or_classes.append(last_class);
                            }
                            const forced_ordinal = is_duplicate and optional_statement_values.class.? == .ordinal;
                            // In the Win32 RC compiler, if any CLASS values that are interpreted as
                            // an ordinal exist, it affects all future CLASS statements and forces
                            // them to be treated as an ordinal no matter what.
                            if (forced_ordinal) {
                                last_class_would_be_forced_ordinal = true;
                            }
                            // clear out the old one if it exists
                            if (optional_statement_values.class) |prev| {
                                prev.deinit(self.allocator);
                                optional_statement_values.class = null;
                            }

                            if (simple_statement.value.is_number_expression()) {
                                const class_ordinal = evaluate_number_expression(simple_statement.value, self.source, self.input_code_pages);
                                optional_statement_values.class = NameOrOrdinal{ .ordinal = class_ordinal.as_word() };
                            } else {
                                std.debug.assert(simple_statement.value.is_string_literal());
                                const literal_node: *Node.Literal = @align_cast(@fieldParentPtr("base", simple_statement.value));
                                const parsed = try self.parse_quoted_string_as_wide_string(literal_node.token);
                                optional_statement_values.class = NameOrOrdinal{ .name = parsed };
                            }

                            last_class = simple_statement;
                        },
                        .menu => {
                            const is_duplicate = optional_statement_values.menu != null;
                            if (is_duplicate) {
                                try skipped_menu_or_classes.append(last_menu);
                            }
                            const forced_ordinal = is_duplicate and optional_statement_values.menu.? == .ordinal;
                            // In the Win32 RC compiler, if any MENU values that are interpreted as
                            // an ordinal exist, it affects all future MENU statements and forces
                            // them to be treated as an ordinal no matter what.
                            if (forced_ordinal) {
                                last_menu_would_be_forced_ordinal = true;
                            }
                            // clear out the old one if it exists
                            if (optional_statement_values.menu) |prev| {
                                prev.deinit(self.allocator);
                                optional_statement_values.menu = null;
                            }

                            std.debug.assert(simple_statement.value.id == .literal);
                            const literal_node: *Node.Literal = @align_cast(@fieldParentPtr("base", simple_statement.value));

                            const token_slice = literal_node.token.slice(self.source);
                            const bytes = SourceBytes{
                                .slice = token_slice,
                                .code_page = self.input_code_pages.get_for_token(literal_node.token),
                            };
                            optional_statement_values.menu = try NameOrOrdinal.from_string(self.allocator, bytes);

                            if (optional_statement_values.menu.? == .name) {
                                if (NameOrOrdinal.maybe_non_ascii_ordinal_from_string(bytes)) |win32_rc_ordinal| {
                                    try self.add_error_details(.{
                                        .err = .invalid_digit_character_in_ordinal,
                                        .type = .err,
                                        .token = literal_node.token,
                                    });
                                    return self.add_error_details_and_fail(.{
                                        .err = .win32_non_ascii_ordinal,
                                        .type = .note,
                                        .token = literal_node.token,
                                        .print_source_line = false,
                                        .extra = .{ .number = win32_rc_ordinal.ordinal },
                                    });
                                }
                            }

                            // Need to keep track of some properties of the value
                            // in order to emit the appropriate warning(s) later on.
                            // See where the warning are emitted below (outside this loop)
                            // for the full explanation.
                            var did_uppercase = false;
                            var codepoint_i: usize = 0;
                            while (bytes.code_page.codepoint_at(codepoint_i, bytes.slice)) |codepoint| : (codepoint_i += codepoint.byte_len) {
                                const c = codepoint.value;
                                switch (c) {
                                    'a'...'z' => {
                                        did_uppercase = true;
                                        break;
                                    },
                                    else => {},
                                }
                            }
                            last_menu_did_uppercase = did_uppercase;
                            last_menu_has_digit_as_first_char = std.ascii.is_digit(token_slice[0]);
                            last_menu = simple_statement;
                        },
                        else => {},
                    }
                },
                .font_statement => {
                    const font: *Node.FontStatement = @align_cast(@fieldParentPtr("base", optional_statement));
                    if (optional_statement_values.font != null) {
                        optional_statement_values.font.?.node = font;
                    } else {
                        optional_statement_values.font = FontStatementValues{ .node = font };
                    }
                    if (font.weight) |weight| {
                        const value = evaluate_number_expression(weight, self.source, self.input_code_pages);
                        optional_statement_values.font.?.weight = value.as_word();
                    }
                    if (font.italic) |italic| {
                        const value = evaluate_number_expression(italic, self.source, self.input_code_pages);
                        optional_statement_values.font.?.italic = value.as_word() != 0;
                    }
                },
                else => {},
            }
        }

        for (skipped_menu_or_classes.items) |simple_statement| {
            const statement_identifier = simple_statement.identifier;
            const statement_type = rc.OptionalStatements.dialog_map.get(statement_identifier.slice(self.source)) orelse continue;
            try self.add_error_details(.{
                .err = .duplicate_menu_or_class_skipped,
                .type = .warning,
                .token = simple_statement.identifier,
                .token_span_start = simple_statement.base.get_first_token(),
                .token_span_end = simple_statement.base.get_last_token(),
                .extra = .{ .menu_or_class = switch (statement_type) {
                    .menu => .menu,
                    .class => .class,
                    else => unreachable,
                } },
            });
        }
        // The Win32 RC compiler miscompiles the value in the following scenario:
        // Multiple CLASS parameters are specified and any of them are treated as a number, then
        // the last CLASS is always treated as a number no matter what
        if (last_class_would_be_forced_ordinal and optional_statement_values.class.? == .name) {
            const literal_node: *Node.Literal = @align_cast(@fieldParentPtr("base", last_class.value));
            const ordinal_value = res.ForcedOrdinal.from_utf16_le(optional_statement_values.class.?.name);

            try self.add_error_details(.{
                .err = .rc_would_miscompile_dialog_class,
                .type = .warning,
                .token = literal_node.token,
                .extra = .{ .number = ordinal_value },
            });
            try self.add_error_details(.{
                .err = .rc_would_miscompile_dialog_class,
                .type = .note,
                .print_source_line = false,
                .token = literal_node.token,
                .extra = .{ .number = ordinal_value },
            });
            try self.add_error_details(.{
                .err = .rc_would_miscompile_dialog_menu_or_class_id_forced_ordinal,
                .type = .note,
                .print_source_line = false,
                .token = literal_node.token,
                .extra = .{ .menu_or_class = .class },
            });
        }
        // The Win32 RC compiler miscompiles the id in two different scenarios:
        // 1. The first character of the ID is a digit, in which case it is always treated as a number
        //    no matter what (and therefore does not match how the MENU/MENUEX id is parsed)
        // 2. Multiple MENU parameters are specified and any of them are treated as a number, then
        //    the last MENU is always treated as a number no matter what
        if ((last_menu_would_be_forced_ordinal or last_menu_has_digit_as_first_char) and optional_statement_values.menu.? == .name) {
            const literal_node: *Node.Literal = @align_cast(@fieldParentPtr("base", last_menu.value));
            const token_slice = literal_node.token.slice(self.source);
            const bytes = SourceBytes{
                .slice = token_slice,
                .code_page = self.input_code_pages.get_for_token(literal_node.token),
            };
            const ordinal_value = res.ForcedOrdinal.from_bytes(bytes);

            try self.add_error_details(.{
                .err = .rc_would_miscompile_dialog_menu_id,
                .type = .warning,
                .token = literal_node.token,
                .extra = .{ .number = ordinal_value },
            });
            try self.add_error_details(.{
                .err = .rc_would_miscompile_dialog_menu_id,
                .type = .note,
                .print_source_line = false,
                .token = literal_node.token,
                .extra = .{ .number = ordinal_value },
            });
            if (last_menu_would_be_forced_ordinal) {
                try self.add_error_details(.{
                    .err = .rc_would_miscompile_dialog_menu_or_class_id_forced_ordinal,
                    .type = .note,
                    .print_source_line = false,
                    .token = literal_node.token,
                    .extra = .{ .menu_or_class = .menu },
                });
            } else {
                try self.add_error_details(.{
                    .err = .rc_would_miscompile_dialog_menu_id_starts_with_digit,
                    .type = .note,
                    .print_source_line = false,
                    .token = literal_node.token,
                });
            }
        }
        // The MENU id parsing uses the exact same logic as the MENU/MENUEX resource id parsing,
        // which means that it will convert ASCII characters to uppercase during the 'name' parsing.
        // This turns out not to matter (`LoadMenu` does a case-insensitive lookup anyway),
        // but it still makes sense to share the uppercasing logic since the MENU parameter
        // here is just a reference to a MENU/MENUEX id within the .exe.
        // So, because this is an intentional but inconsequential-to-the-user difference
        // between resinator and the Win32 RC compiler, we only emit a hint instead of
        // a warning.
        if (last_menu_did_uppercase) {
            const literal_node: *Node.Literal = @align_cast(@fieldParentPtr("base", last_menu.value));
            try self.add_error_details(.{
                .err = .dialog_menu_id_was_uppercased,
                .type = .hint,
                .token = literal_node.token,
            });
        }

        const x = evaluate_number_expression(node.x, self.source, self.input_code_pages);
        const y = evaluate_number_expression(node.y, self.source, self.input_code_pages);
        const width = evaluate_number_expression(node.width, self.source, self.input_code_pages);
        const height = evaluate_number_expression(node.height, self.source, self.input_code_pages);

        // FONT statement requires DS_SETFONT, and if it's not present DS_SETFRONT must be unset
        if (optional_statement_values.font) |_| {
            optional_statement_values.style |= res.DS.SETFONT;
        } else {
            optional_statement_values.style &= ~res.DS.SETFONT;
        }
        // CAPTION statement implies WS_CAPTION
        if (optional_statement_values.caption) |_| {
            optional_statement_values.style |= res.WS.CAPTION;
        }

        self.write_dialog_header_and_strings(
            node,
            data_writer,
            resource,
            &optional_statement_values,
            x,
            y,
            width,
            height,
        ) catch |err| switch (err) {
            // Dialog header and menu/class/title strings can never exceed u32 bytes
            // on their own, so this error is unreachable.
            error.NoSpaceLeft => unreachable,
            else => |e| return e,
        };

        var controls_by_id = std.AutoHashMap(u32, *const Node.ControlStatement).init(self.allocator);
        // Number of controls are guaranteed by the parser to be within max_int(u16).
        try controls_by_id.ensure_total_capacity(@as(u16, @int_cast(node.controls.len)));
        defer controls_by_id.deinit();

        for (node.controls) |control_node| {
            const control: *Node.ControlStatement = @align_cast(@fieldParentPtr("base", control_node));

            self.write_dialog_control(
                control,
                data_writer,
                resource,
                // We know the data_buffer len is limited to u32 max.
                @int_cast(data_buffer.items.len),
                &controls_by_id,
            ) catch |err| switch (err) {
                error.NoSpaceLeft => {
                    try self.add_error_details(.{
                        .err = .resource_data_size_exceeds_max,
                        .token = node.id,
                    });
                    return self.add_error_details_and_fail(.{
                        .err = .resource_data_size_exceeds_max,
                        .type = .note,
                        .token = control.type,
                    });
                },
                else => |e| return e,
            };
        }

        // We know the data_buffer len is limited to u32 max.
        const data_size: u32 = @int_cast(data_buffer.items.len);
        var header = try self.resource_header(node.id, node.type, .{
            .data_size = data_size,
        });
        defer header.deinit(self.allocator);

        header.apply_memory_flags(node.common_resource_attributes, self.source);
        header.apply_optional_statements(node.optional_statements, self.source, self.input_code_pages);

        try header.write(writer, .{ .diagnostics = self.diagnostics, .token = node.id });

        var data_fbs = std.io.fixed_buffer_stream(data_buffer.items);
        try write_resource_data(writer, data_fbs.reader(), data_size);
    }

    fn write_dialog_header_and_strings(
        self: *Compiler,
        node: *Node.Dialog,
        data_writer: anytype,
        resource: Resource,
        optional_statement_values: *const DialogOptionalStatementValues,
        x: Number,
        y: Number,
        width: Number,
        height: Number,
    ) !void {
        // Header
        if (resource == .dialogex) {
            const help_id: u32 = help_id: {
                if (node.help_id == null) break :help_id 0;
                break :help_id evaluate_number_expression(node.help_id.?, self.source, self.input_code_pages).value;
            };
            try data_writer.write_int(u16, 1, .little); // version number, always 1
            try data_writer.write_int(u16, 0xFFFF, .little); // signature, always 0xFFFF
            try data_writer.write_int(u32, help_id, .little);
            try data_writer.write_int(u32, optional_statement_values.exstyle, .little);
            try data_writer.write_int(u32, optional_statement_values.style, .little);
        } else {
            try data_writer.write_int(u32, optional_statement_values.style, .little);
            try data_writer.write_int(u32, optional_statement_values.exstyle, .little);
        }
        // This limit is enforced by the parser, so we know the number of controls
        // is within the range of a u16.
        try data_writer.write_int(u16, @as(u16, @int_cast(node.controls.len)), .little);
        try data_writer.write_int(u16, x.as_word(), .little);
        try data_writer.write_int(u16, y.as_word(), .little);
        try data_writer.write_int(u16, width.as_word(), .little);
        try data_writer.write_int(u16, height.as_word(), .little);

        // Menu
        if (optional_statement_values.menu) |menu| {
            try menu.write(data_writer);
        } else {
            try data_writer.write_int(u16, 0, .little);
        }
        // Class
        if (optional_statement_values.class) |class| {
            try class.write(data_writer);
        } else {
            try data_writer.write_int(u16, 0, .little);
        }
        // Caption
        if (optional_statement_values.caption) |caption| {
            const parsed = try self.parse_quoted_string_as_wide_string(caption);
            defer self.allocator.free(parsed);
            try data_writer.write_all(std.mem.slice_as_bytes(parsed[0 .. parsed.len + 1]));
        } else {
            try data_writer.write_int(u16, 0, .little);
        }
        // Font
        if (optional_statement_values.font) |font| {
            try self.write_dialog_font(resource, font, data_writer);
        }
    }

    fn write_dialog_control(
        self: *Compiler,
        control: *Node.ControlStatement,
        data_writer: anytype,
        resource: Resource,
        bytes_written_so_far: u32,
        controls_by_id: *std.AutoHashMap(u32, *const Node.ControlStatement),
    ) !void {
        const control_type = rc.Control.map.get(control.type.slice(self.source)).?;

        // Each control must be at a 4-byte boundary. However, the Windows RC
        // compiler will miscompile controls if their extra data ends on an odd offset.
        // We will avoid the miscompilation and emit a warning.
        const num_padding = num_padding_bytes_needed(bytes_written_so_far);
        if (num_padding == 1 or num_padding == 3) {
            try self.add_error_details(.{
                .err = .rc_would_miscompile_control_padding,
                .type = .warning,
                .token = control.type,
            });
            try self.add_error_details(.{
                .err = .rc_would_miscompile_control_padding,
                .type = .note,
                .print_source_line = false,
                .token = control.type,
            });
        }
        try data_writer.write_byte_ntimes(0, num_padding);

        const style = if (control.style) |style_expression|
            // Certain styles are implied by the control type
            evaluate_flags_expression_with_default(res.ControlClass.get_implied_style(control_type), style_expression, self.source, self.input_code_pages)
        else
            res.ControlClass.get_implied_style(control_type);

        const exstyle = if (control.exstyle) |exstyle_expression|
            evaluate_flags_expression_with_default(0, exstyle_expression, self.source, self.input_code_pages)
        else
            0;

        switch (resource) {
            .dialog => {
                // Note: Reverse order from DIALOGEX
                try data_writer.write_int(u32, style, .little);
                try data_writer.write_int(u32, exstyle, .little);
            },
            .dialogex => {
                const help_id: u32 = if (control.help_id) |help_id_expression|
                    evaluate_number_expression(help_id_expression, self.source, self.input_code_pages).value
                else
                    0;
                try data_writer.write_int(u32, help_id, .little);
                // Note: Reverse order from DIALOG
                try data_writer.write_int(u32, exstyle, .little);
                try data_writer.write_int(u32, style, .little);
            },
            else => unreachable,
        }

        const control_x = evaluate_number_expression(control.x, self.source, self.input_code_pages);
        const control_y = evaluate_number_expression(control.y, self.source, self.input_code_pages);
        const control_width = evaluate_number_expression(control.width, self.source, self.input_code_pages);
        const control_height = evaluate_number_expression(control.height, self.source, self.input_code_pages);

        try data_writer.write_int(u16, control_x.as_word(), .little);
        try data_writer.write_int(u16, control_y.as_word(), .little);
        try data_writer.write_int(u16, control_width.as_word(), .little);
        try data_writer.write_int(u16, control_height.as_word(), .little);

        const control_id = evaluate_number_expression(control.id, self.source, self.input_code_pages);
        switch (resource) {
            .dialog => try data_writer.write_int(u16, control_id.as_word(), .little),
            .dialogex => try data_writer.write_int(u32, control_id.value, .little),
            else => unreachable,
        }

        const control_id_for_map: u32 = switch (resource) {
            .dialog => control_id.as_word(),
            .dialogex => control_id.value,
            else => unreachable,
        };
        const result = controls_by_id.get_or_put_assume_capacity(control_id_for_map);
        if (result.found_existing) {
            if (!self.silent_duplicate_control_ids) {
                try self.add_error_details(.{
                    .err = .control_id_already_defined,
                    .type = .warning,
                    .token = control.id.get_first_token(),
                    .token_span_end = control.id.get_last_token(),
                    .extra = .{ .number = control_id_for_map },
                });
                try self.add_error_details(.{
                    .err = .control_id_already_defined,
                    .type = .note,
                    .token = result.value_ptr.*.id.get_first_token(),
                    .token_span_end = result.value_ptr.*.id.get_last_token(),
                    .extra = .{ .number = control_id_for_map },
                });
            }
        } else {
            result.value_ptr.* = control;
        }

        if (res.ControlClass.from_control(control_type)) |control_class| {
            const ordinal = NameOrOrdinal{ .ordinal = @int_from_enum(control_class) };
            try ordinal.write(data_writer);
        } else {
            const class_node = control.class.?;
            if (class_node.is_number_expression()) {
                const number = evaluate_number_expression(class_node, self.source, self.input_code_pages);
                const ordinal = NameOrOrdinal{ .ordinal = number.as_word() };
                // This is different from how the Windows RC compiles ordinals here,
                // but I think that's a miscompilation/bug of the Windows implementation.
                // The Windows behavior is (where LSB = least significant byte):
                // - If the LSB is 0x00 => 0xFFFF0000
                // - If the LSB is < 0x80 => 0x000000<LSB>
                // - If the LSB is >= 0x80 => 0x0000FF<LSB>
                //
                // Because of this, we emit a warning about the potential miscompilation
                try self.add_error_details(.{
                    .err = .rc_would_miscompile_control_class_ordinal,
                    .type = .warning,
                    .token = class_node.get_first_token(),
                    .token_span_end = class_node.get_last_token(),
                });
                try self.add_error_details(.{
                    .err = .rc_would_miscompile_control_class_ordinal,
                    .type = .note,
                    .print_source_line = false,
                    .token = class_node.get_first_token(),
                    .token_span_end = class_node.get_last_token(),
                });
                // And then write out the ordinal using a proper a NameOrOrdinal encoding.
                try ordinal.write(data_writer);
            } else if (class_node.is_string_literal()) {
                const literal_node: *Node.Literal = @align_cast(@fieldParentPtr("base", class_node));
                const parsed = try self.parse_quoted_string_as_wide_string(literal_node.token);
                defer self.allocator.free(parsed);
                if (rc.ControlClass.from_wide_string(parsed)) |control_class| {
                    const ordinal = NameOrOrdinal{ .ordinal = @int_from_enum(control_class) };
                    try ordinal.write(data_writer);
                } else {
                    // NUL acts as a terminator
                    // TODO: Maybe warn when parsed_terminated.len != parsed.len, since
                    //       it seems unlikely that NUL-termination is something intentional
                    const parsed_terminated = std.mem.slice_to(parsed, 0);
                    const name = NameOrOrdinal{ .name = parsed_terminated };
                    try name.write(data_writer);
                }
            } else {
                const literal_node: *Node.Literal = @align_cast(@fieldParentPtr("base", class_node));
                const literal_slice = literal_node.token.slice(self.source);
                // This succeeding is guaranteed by the parser
                const control_class = rc.ControlClass.map.get(literal_slice) orelse unreachable;
                const ordinal = NameOrOrdinal{ .ordinal = @int_from_enum(control_class) };
                try ordinal.write(data_writer);
            }
        }

        if (control.text) |text_token| {
            const bytes = SourceBytes{
                .slice = text_token.slice(self.source),
                .code_page = self.input_code_pages.get_for_token(text_token),
            };
            if (text_token.is_string_literal()) {
                const text = try self.parse_quoted_string_as_wide_string(text_token);
                defer self.allocator.free(text);
                const name = NameOrOrdinal{ .name = text };
                try name.write(data_writer);
            } else {
                std.debug.assert(text_token.id == .number);
                const number = literals.parse_number_literal(bytes);
                const ordinal = NameOrOrdinal{ .ordinal = number.as_word() };
                try ordinal.write(data_writer);
            }
        } else {
            try NameOrOrdinal.write_empty(data_writer);
        }

        var extra_data_buf = std.ArrayList(u8).init(self.allocator);
        defer extra_data_buf.deinit();
        // The extra data byte length must be able to fit within a u16.
        var limited_extra_data_writer = limited_writer(extra_data_buf.writer(), std.math.max_int(u16));
        const extra_data_writer = limited_extra_data_writer.writer();
        for (control.extra_data) |data_expression| {
            const data = try self.evaluate_data_expression(data_expression);
            defer data.deinit(self.allocator);
            data.write(extra_data_writer) catch |err| switch (err) {
                error.NoSpaceLeft => {
                    try self.add_error_details(.{
                        .err = .control_extra_data_size_exceeds_max,
                        .token = control.type,
                    });
                    return self.add_error_details_and_fail(.{
                        .err = .control_extra_data_size_exceeds_max,
                        .type = .note,
                        .token = data_expression.get_first_token(),
                        .token_span_end = data_expression.get_last_token(),
                    });
                },
                else => |e| return e,
            };
        }
        // We know the extra_data_buf size fits within a u16.
        const extra_data_size: u16 = @int_cast(extra_data_buf.items.len);
        try data_writer.write_int(u16, extra_data_size, .little);
        try data_writer.write_all(extra_data_buf.items);
    }

    pub fn write_toolbar(self: *Compiler, node: *Node.Toolbar, writer: anytype) !void {
        var data_buffer = std.ArrayList(u8).init(self.allocator);
        defer data_buffer.deinit();
        const data_writer = data_buffer.writer();

        const button_width = evaluate_number_expression(node.button_width, self.source, self.input_code_pages);
        const button_height = evaluate_number_expression(node.button_height, self.source, self.input_code_pages);

        // I'm assuming this is some sort of version
        // TODO: Try to find something mentioning this
        try data_writer.write_int(u16, 1, .little);
        try data_writer.write_int(u16, button_width.as_word(), .little);
        try data_writer.write_int(u16, button_height.as_word(), .little);
        // Number of buttons is guaranteed by the parser to be within max_int(u16).
        try data_writer.write_int(u16, @as(u16, @int_cast(node.buttons.len)), .little);

        for (node.buttons) |button_or_sep| {
            switch (button_or_sep.id) {
                .literal => { // This is always SEPARATOR
                    std.debug.assert(button_or_sep.cast(.literal).?.token.id == .literal);
                    try data_writer.write_int(u16, 0, .little);
                },
                .simple_statement => {
                    const value_node = button_or_sep.cast(.simple_statement).?.value;
                    const value = evaluate_number_expression(value_node, self.source, self.input_code_pages);
                    try data_writer.write_int(u16, value.as_word(), .little);
                },
                else => unreachable, // This is a bug in the parser
            }
        }

        const data_size: u32 = @int_cast(data_buffer.items.len);
        var header = try self.resource_header(node.id, node.type, .{
            .data_size = data_size,
        });
        defer header.deinit(self.allocator);

        header.apply_memory_flags(node.common_resource_attributes, self.source);

        try header.write(writer, .{ .diagnostics = self.diagnostics, .token = node.id });

        var data_fbs = std.io.fixed_buffer_stream(data_buffer.items);
        try write_resource_data(writer, data_fbs.reader(), data_size);
    }

    /// Weight and italic carry over from previous FONT statements within a single resource,
    /// so they need to be parsed ahead-of-time and stored
    const FontStatementValues = struct {
        weight: u16 = 0,
        italic: bool = false,
        node: *Node.FontStatement,
    };

    pub fn write_dialog_font(self: *Compiler, resource: Resource, values: FontStatementValues, writer: anytype) !void {
        const node = values.node;
        const point_size = evaluate_number_expression(node.point_size, self.source, self.input_code_pages);
        try writer.write_int(u16, point_size.as_word(), .little);

        if (resource == .dialogex) {
            try writer.write_int(u16, values.weight, .little);
        }

        if (resource == .dialogex) {
            try writer.write_int(u8, @int_from_bool(values.italic), .little);
        }

        if (node.char_set) |char_set| {
            const value = evaluate_number_expression(char_set, self.source, self.input_code_pages);
            try writer.write_int(u8, @as(u8, @truncate(value.value)), .little);
        } else if (resource == .dialogex) {
            try writer.write_int(u8, 1, .little); // DEFAULT_CHARSET
        }

        const typeface = try self.parse_quoted_string_as_wide_string(node.typeface);
        defer self.allocator.free(typeface);
        try writer.write_all(std.mem.slice_as_bytes(typeface[0 .. typeface.len + 1]));
    }

    pub fn write_menu(self: *Compiler, node: *Node.Menu, writer: anytype) !void {
        var data_buffer = std.ArrayList(u8).init(self.allocator);
        defer data_buffer.deinit();
        // The header's data length field is a u32 so limit the resource's data size so that
        // we know we can always specify the real size.
        var limited_writer = limited_writer(data_buffer.writer(), std.math.max_int(u32));
        const data_writer = limited_writer.writer();

        const type_bytes = SourceBytes{
            .slice = node.type.slice(self.source),
            .code_page = self.input_code_pages.get_for_token(node.type),
        };
        const resource = Resource.from_string(type_bytes);
        std.debug.assert(resource == .menu or resource == .menuex);

        self.write_menu_data(node, data_writer, resource) catch |err| switch (err) {
            error.NoSpaceLeft => {
                return self.add_error_details_and_fail(.{
                    .err = .resource_data_size_exceeds_max,
                    .token = node.id,
                });
            },
            else => |e| return e,
        };

        // This int_cast can't fail because the limited_writer above guarantees that
        // we will never write more than max_int(u32) bytes.
        const data_size: u32 = @int_cast(data_buffer.items.len);
        var header = try self.resource_header(node.id, node.type, .{
            .data_size = data_size,
        });
        defer header.deinit(self.allocator);

        header.apply_memory_flags(node.common_resource_attributes, self.source);
        header.apply_optional_statements(node.optional_statements, self.source, self.input_code_pages);

        try header.write(writer, .{ .diagnostics = self.diagnostics, .token = node.id });

        var data_fbs = std.io.fixed_buffer_stream(data_buffer.items);
        try write_resource_data(writer, data_fbs.reader(), data_size);
    }

    /// Expects `data_writer` to be a LimitedWriter limited to u32, meaning all writes to
    /// the writer within this function could return error.NoSpaceLeft
    pub fn write_menu_data(self: *Compiler, node: *Node.Menu, data_writer: anytype, resource: Resource) !void {
        // menu header
        const version: u16 = if (resource == .menu) 0 else 1;
        try data_writer.write_int(u16, version, .little);
        const header_size: u16 = if (resource == .menu) 0 else 4;
        try data_writer.write_int(u16, header_size, .little); // cbHeaderSize
        // Note: There can be extra bytes at the end of this header (`rgbExtra`),
        //       but they are always zero-length for us, so we don't write anything
        //       (the length of the rgbExtra field is inferred from the header_size).
        // MENU   => rgbExtra: [cbHeaderSize]u8
        // MENUEX => rgbExtra: [cbHeaderSize-4]u8

        if (resource == .menuex) {
            if (node.help_id) |help_id_node| {
                const help_id = evaluate_number_expression(help_id_node, self.source, self.input_code_pages);
                try data_writer.write_int(u32, help_id.value, .little);
            } else {
                try data_writer.write_int(u32, 0, .little);
            }
        }

        for (node.items, 0..) |item, i| {
            const is_last = i == node.items.len - 1;
            try self.write_menu_item(item, data_writer, is_last);
        }
    }

    pub fn write_menu_item(self: *Compiler, node: *Node, writer: anytype, is_last_of_parent: bool) !void {
        switch (node.id) {
            .menu_item_separator => {
                // This is the 'alternate compability form' of the separator, see
                // https://devblogs.microsoft.com/oldnewthing/20080710-00/?p=21673
                //
                // The 'correct' way is to set the MF_SEPARATOR flag, but the Win32 RC
                // compiler still uses this alternate form, so that's what we use too.
                var flags = res.MenuItemFlags{};
                if (is_last_of_parent) flags.mark_last();
                try writer.write_int(u16, flags.value, .little);
                try writer.write_int(u16, 0, .little); // id
                try writer.write_int(u16, 0, .little); // null-terminated UTF-16 text
            },
            .menu_item => {
                const menu_item: *Node.MenuItem = @align_cast(@fieldParentPtr("base", node));
                var flags = res.MenuItemFlags{};
                for (menu_item.option_list) |option_token| {
                    // This failing would be a bug in the parser
                    const option = rc.MenuItem.Option.map.get(option_token.slice(self.source)) orelse unreachable;
                    flags.apply(option);
                }
                if (is_last_of_parent) flags.mark_last();
                try writer.write_int(u16, flags.value, .little);

                var result = evaluate_number_expression(menu_item.result, self.source, self.input_code_pages);
                try writer.write_int(u16, result.as_word(), .little);

                var text = try self.parse_quoted_string_as_wide_string(menu_item.text);
                defer self.allocator.free(text);
                try writer.write_all(std.mem.slice_as_bytes(text[0 .. text.len + 1]));
            },
            .popup => {
                const popup: *Node.Popup = @align_cast(@fieldParentPtr("base", node));
                var flags = res.MenuItemFlags{ .value = res.MF.POPUP };
                for (popup.option_list) |option_token| {
                    // This failing would be a bug in the parser
                    const option = rc.MenuItem.Option.map.get(option_token.slice(self.source)) orelse unreachable;
                    flags.apply(option);
                }
                if (is_last_of_parent) flags.mark_last();
                try writer.write_int(u16, flags.value, .little);

                var text = try self.parse_quoted_string_as_wide_string(popup.text);
                defer self.allocator.free(text);
                try writer.write_all(std.mem.slice_as_bytes(text[0 .. text.len + 1]));

                for (popup.items, 0..) |item, i| {
                    const is_last = i == popup.items.len - 1;
                    try self.write_menu_item(item, writer, is_last);
                }
            },
            inline .menu_item_ex, .popup_ex => |node_type| {
                const menu_item: *node_type.Type() = @align_cast(@fieldParentPtr("base", node));

                if (menu_item.type) |flags| {
                    const value = evaluate_number_expression(flags, self.source, self.input_code_pages);
                    try writer.write_int(u32, value.value, .little);
                } else {
                    try writer.write_int(u32, 0, .little);
                }

                if (menu_item.state) |state| {
                    const value = evaluate_number_expression(state, self.source, self.input_code_pages);
                    try writer.write_int(u32, value.value, .little);
                } else {
                    try writer.write_int(u32, 0, .little);
                }

                if (menu_item.id) |id| {
                    const value = evaluate_number_expression(id, self.source, self.input_code_pages);
                    try writer.write_int(u32, value.value, .little);
                } else {
                    try writer.write_int(u32, 0, .little);
                }

                var flags: u16 = 0;
                if (is_last_of_parent) flags |= comptime @as(u16, @int_cast(res.MF.END));
                // This constant doesn't seem to have a named #define, it's different than MF_POPUP
                if (node_type == .popup_ex) flags |= 0x01;
                try writer.write_int(u16, flags, .little);

                var text = try self.parse_quoted_string_as_wide_string(menu_item.text);
                defer self.allocator.free(text);
                try writer.write_all(std.mem.slice_as_bytes(text[0 .. text.len + 1]));

                // Only the combination of the flags u16 and the text bytes can cause
                // non-DWORD alignment, so we can just use the byte length of those
                // two values to realign to DWORD alignment.
                const relevant_bytes = 2 + (text.len + 1) * 2;
                try write_data_padding(writer, @int_cast(relevant_bytes));

                if (node_type == .popup_ex) {
                    if (menu_item.help_id) |help_id_node| {
                        const help_id = evaluate_number_expression(help_id_node, self.source, self.input_code_pages);
                        try writer.write_int(u32, help_id.value, .little);
                    } else {
                        try writer.write_int(u32, 0, .little);
                    }

                    for (menu_item.items, 0..) |item, i| {
                        const is_last = i == menu_item.items.len - 1;
                        try self.write_menu_item(item, writer, is_last);
                    }
                }
            },
            else => unreachable,
        }
    }

    pub fn write_version_info(self: *Compiler, node: *Node.VersionInfo, writer: anytype) !void {
        var data_buffer = std.ArrayList(u8).init(self.allocator);
        defer data_buffer.deinit();
        // The node's length field (which is inclusive of the length of all of its children) is a u16
        // so limit the node's data size so that we know we can always specify the real size.
        var limited_writer = limited_writer(data_buffer.writer(), std.math.max_int(u16));
        const data_writer = limited_writer.writer();

        try data_writer.write_int(u16, 0, .little); // placeholder size
        try data_writer.write_int(u16, res.FixedFileInfo.byte_len, .little);
        try data_writer.write_int(u16, res.VersionNode.type_binary, .little);
        const key_bytes = std.mem.slice_as_bytes(res.FixedFileInfo.key[0 .. res.FixedFileInfo.key.len + 1]);
        try data_writer.write_all(key_bytes);
        // The number of bytes written up to this point is always the same, since the name
        // of the node is a constant (FixedFileInfo.key). The total number of bytes
        // written so far is 38, so we need 2 padding bytes to get back to DWORD alignment
        try data_writer.write_int(u16, 0, .little);

        var fixed_file_info = res.FixedFileInfo{};
        for (node.fixed_info) |fixed_info| {
            switch (fixed_info.id) {
                .version_statement => {
                    const version_statement: *Node.VersionStatement = @align_cast(@fieldParentPtr("base", fixed_info));
                    const version_type = rc.VersionInfo.map.get(version_statement.type.slice(self.source)).?;

                    // Ensure that all parts are cleared for each version, to properly account for
                    // potential duplicate PRODUCTVERSION/FILEVERSION statements
                    switch (version_type) {
                        .file_version => @memset(&fixed_file_info.file_version.parts, 0),
                        .product_version => @memset(&fixed_file_info.product_version.parts, 0),
                        else => unreachable,
                    }

                    for (version_statement.parts, 0..) |part, i| {
                        const part_value = evaluate_number_expression(part, self.source, self.input_code_pages);
                        if (part_value.is_long) {
                            try self.add_error_details(.{
                                .err = .rc_would_error_u16_with_l_suffix,
                                .type = .warning,
                                .token = part.get_first_token(),
                                .token_span_end = part.get_last_token(),
                                .extra = .{ .statement_with_u16_param = switch (version_type) {
                                    .file_version => .fileversion,
                                    .product_version => .productversion,
                                    else => unreachable,
                                } },
                            });
                            try self.add_error_details(.{
                                .err = .rc_would_error_u16_with_l_suffix,
                                .print_source_line = false,
                                .type = .note,
                                .token = part.get_first_token(),
                                .token_span_end = part.get_last_token(),
                                .extra = .{ .statement_with_u16_param = switch (version_type) {
                                    .file_version => .fileversion,
                                    .product_version => .productversion,
                                    else => unreachable,
                                } },
                            });
                        }
                        switch (version_type) {
                            .file_version => {
                                fixed_file_info.file_version.parts[i] = part_value.as_word();
                            },
                            .product_version => {
                                fixed_file_info.product_version.parts[i] = part_value.as_word();
                            },
                            else => unreachable,
                        }
                    }
                },
                .simple_statement => {
                    const statement: *Node.SimpleStatement = @align_cast(@fieldParentPtr("base", fixed_info));
                    const statement_type = rc.VersionInfo.map.get(statement.identifier.slice(self.source)).?;
                    const value = evaluate_number_expression(statement.value, self.source, self.input_code_pages);
                    switch (statement_type) {
                        .file_flags_mask => fixed_file_info.file_flags_mask = value.value,
                        .file_flags => fixed_file_info.file_flags = value.value,
                        .file_os => fixed_file_info.file_os = value.value,
                        .file_type => fixed_file_info.file_type = value.value,
                        .file_subtype => fixed_file_info.file_subtype = value.value,
                        else => unreachable,
                    }
                },
                else => unreachable,
            }
        }
        try fixed_file_info.write(data_writer);

        for (node.block_statements) |statement| {
            self.write_version_node(statement, data_writer, &data_buffer) catch |err| switch (err) {
                error.NoSpaceLeft => {
                    try self.add_error_details(.{
                        .err = .version_node_size_exceeds_max,
                        .token = node.id,
                    });
                    return self.add_error_details_and_fail(.{
                        .err = .version_node_size_exceeds_max,
                        .type = .note,
                        .token = statement.get_first_token(),
                        .token_span_end = statement.get_last_token(),
                    });
                },
                else => |e| return e,
            };
        }

        // We know that data_buffer.items.len is within the limits of a u16, since we
        // limited the writer to max_int(u16)
        const data_size: u16 = @int_cast(data_buffer.items.len);
        // And now that we know the full size of this node (including its children), set its size
        std.mem.write_int(u16, data_buffer.items[0..2], data_size, .little);

        var header = try self.resource_header(node.id, node.versioninfo, .{
            .data_size = data_size,
        });
        defer header.deinit(self.allocator);

        header.apply_memory_flags(node.common_resource_attributes, self.source);

        try header.write(writer, .{ .diagnostics = self.diagnostics, .token = node.id });

        var data_fbs = std.io.fixed_buffer_stream(data_buffer.items);
        try write_resource_data(writer, data_fbs.reader(), data_size);
    }

    /// Expects writer to be a LimitedWriter limited to u16, meaning all writes to
    /// the writer within this function could return error.NoSpaceLeft, and that buf.items.len
    /// will never be able to exceed max_int(u16).
    pub fn write_version_node(self: *Compiler, node: *Node, writer: anytype, buf: *std.ArrayList(u8)) !void {
        // We can assume that buf.items.len will never be able to exceed the limits of a u16
        try write_data_padding(writer, @as(u16, @int_cast(buf.items.len)));

        const node_and_children_size_offset = buf.items.len;
        try writer.write_int(u16, 0, .little); // placeholder for size
        const data_size_offset = buf.items.len;
        try writer.write_int(u16, 0, .little); // placeholder for data size
        const data_type_offset = buf.items.len;
        // Data type is string unless the node contains values that are numbers.
        try writer.write_int(u16, res.VersionNode.type_string, .little);

        switch (node.id) {
            inline .block, .block_value => |node_type| {
                const block_or_value: *node_type.Type() = @align_cast(@fieldParentPtr("base", node));
                const parsed_key = try self.parse_quoted_string_as_wide_string(block_or_value.key);
                defer self.allocator.free(parsed_key);

                const parsed_key_to_first_null = std.mem.slice_to(parsed_key, 0);
                try writer.write_all(std.mem.slice_as_bytes(parsed_key_to_first_null[0 .. parsed_key_to_first_null.len + 1]));

                var has_number_value: bool = false;
                for (block_or_value.values) |value_value_node_uncasted| {
                    const value_value_node = value_value_node_uncasted.cast(.block_value_value).?;
                    if (value_value_node.expression.is_number_expression()) {
                        has_number_value = true;
                        break;
                    }
                }
                // The units used here are dependent on the type. If there are any numbers, then
                // this is a byte count. If there are only strings, then this is a count of
                // UTF-16 code units.
                //
                // The Win32 RC compiler miscompiles this count in the case of values that
                // have a mix of numbers and strings. This is detected and a warning is emitted
                // during parsing, so we can just do the correct thing here.
                var values_size: usize = 0;

                try write_data_padding(writer, @int_cast(buf.items.len));

                for (block_or_value.values, 0..) |value_value_node_uncasted, i| {
                    const value_value_node = value_value_node_uncasted.cast(.block_value_value).?;
                    const value_node = value_value_node.expression;
                    if (value_node.is_number_expression()) {
                        const number = evaluate_number_expression(value_node, self.source, self.input_code_pages);
                        // This is used to write u16 or u32 depending on the number's suffix
                        const data_wrapper = Data{ .number = number };
                        try data_wrapper.write(writer);
                        // Numbers use byte count
                        values_size += if (number.is_long) 4 else 2;
                    } else {
                        std.debug.assert(value_node.is_string_literal());
                        const literal_node = value_node.cast(.literal).?;
                        const parsed_value = try self.parse_quoted_string_as_wide_string(literal_node.token);
                        defer self.allocator.free(parsed_value);

                        const parsed_to_first_null = std.mem.slice_to(parsed_value, 0);
                        try writer.write_all(std.mem.slice_as_bytes(parsed_to_first_null));
                        // Strings use UTF-16 code-unit count including the null-terminator, but
                        // only if there are no number values in the list.
                        var value_size = parsed_to_first_null.len;
                        if (has_number_value) value_size *= 2; // 2 bytes per UTF-16 code unit
                        values_size += value_size;
                        // The null-terminator is only included if there's a trailing comma
                        // or this is the last value. If the value evaluates to empty, then
                        // it never gets a null terminator. If there was an explicit null-terminator
                        // in the string, we still need to potentially add one since we already
                        // sliced to the terminator.
                        const is_last = i == block_or_value.values.len - 1;
                        const is_empty = parsed_to_first_null.len == 0;
                        const is_only = block_or_value.values.len == 1;
                        if ((!is_empty or !is_only) and (is_last or value_value_node.trailing_comma)) {
                            try writer.write_int(u16, 0, .little);
                            values_size += if (has_number_value) 2 else 1;
                        }
                    }
                }
                var data_size_slice = buf.items[data_size_offset..];
                std.mem.write_int(u16, data_size_slice[0..@size_of(u16)], @as(u16, @int_cast(values_size)), .little);

                if (has_number_value) {
                    const data_type_slice = buf.items[data_type_offset..];
                    std.mem.write_int(u16, data_type_slice[0..@size_of(u16)], res.VersionNode.type_binary, .little);
                }

                if (node_type == .block) {
                    const block = block_or_value;
                    for (block.children) |child| {
                        try self.write_version_node(child, writer, buf);
                    }
                }
            },
            else => unreachable,
        }

        const node_and_children_size = buf.items.len - node_and_children_size_offset;
        const node_and_children_size_slice = buf.items[node_and_children_size_offset..];
        std.mem.write_int(u16, node_and_children_size_slice[0..@size_of(u16)], @as(u16, @int_cast(node_and_children_size)), .little);
    }

    pub fn write_string_table(self: *Compiler, node: *Node.StringTable) !void {
        const language = get_language_from_optional_statements(node.optional_statements, self.source, self.input_code_pages) orelse self.state.language;

        for (node.strings) |string_node| {
            const string: *Node.StringTableString = @align_cast(@fieldParentPtr("base", string_node));
            const string_id_data = try self.evaluate_data_expression(string.id);
            const string_id = string_id_data.number.as_word();

            self.state.string_tables.set(
                self.arena,
                language,
                string_id,
                string.string,
                &node.base,
                self.source,
                self.input_code_pages,
                self.state.version,
                self.state.characteristics,
            ) catch |err| switch (err) {
                error.StringAlreadyDefined => {
                    // It might be nice to have these errors point to the ids rather than the
                    // string tokens, but that would mean storing the id token of each string
                    // which doesn't seem worth it just for slightly better error messages.
                    try self.add_error_details(ErrorDetails{
                        .err = .string_already_defined,
                        .token = string.string,
                        .extra = .{ .string_and_language = .{ .id = string_id, .language = language } },
                    });
                    const existing_def_table = self.state.string_tables.tables.get_ptr(language).?;
                    const existing_definition = existing_def_table.get(string_id).?;
                    return self.add_error_details_and_fail(ErrorDetails{
                        .err = .string_already_defined,
                        .type = .note,
                        .token = existing_definition,
                        .extra = .{ .string_and_language = .{ .id = string_id, .language = language } },
                    });
                },
                error.OutOfMemory => |e| return e,
            };
        }
    }

    /// Expects this to be a top-level LANGUAGE statement
    pub fn write_language_statement(self: *Compiler, node: *Node.LanguageStatement) void {
        const primary = Compiler.evaluate_number_expression(node.primary_language_id, self.source, self.input_code_pages);
        const sublanguage = Compiler.evaluate_number_expression(node.sublanguage_id, self.source, self.input_code_pages);
        self.state.language.primary_language_id = @truncate(primary.value);
        self.state.language.sublanguage_id = @truncate(sublanguage.value);
    }

    /// Expects this to be a top-level VERSION or CHARACTERISTICS statement
    pub fn write_top_level_simple_statement(self: *Compiler, node: *Node.SimpleStatement) void {
        const value = Compiler.evaluate_number_expression(node.value, self.source, self.input_code_pages);
        const statement_type = rc.TopLevelKeywords.map.get(node.identifier.slice(self.source)).?;
        switch (statement_type) {
            .characteristics => self.state.characteristics = value.value,
            .version => self.state.version = value.value,
            else => unreachable,
        }
    }

    pub const ResourceHeaderOptions = struct {
        language: ?res.Language = null,
        data_size: DWORD = 0,
    };

    pub fn resource_header(self: *Compiler, id_token: Token, type_token: Token, options: ResourceHeaderOptions) !ResourceHeader {
        const id_bytes = self.source_bytes_for_token(id_token);
        const type_bytes = self.source_bytes_for_token(type_token);
        return ResourceHeader.init(
            self.allocator,
            id_bytes,
            type_bytes,
            options.data_size,
            options.language orelse self.state.language,
            self.state.version,
            self.state.characteristics,
        ) catch |err| switch (err) {
            error.OutOfMemory => |e| return e,
            error.TypeNonAsciiOrdinal => {
                const win32_rc_ordinal = NameOrOrdinal.maybe_non_ascii_ordinal_from_string(type_bytes).?;
                try self.add_error_details(.{
                    .err = .invalid_digit_character_in_ordinal,
                    .type = .err,
                    .token = type_token,
                });
                return self.add_error_details_and_fail(.{
                    .err = .win32_non_ascii_ordinal,
                    .type = .note,
                    .token = type_token,
                    .print_source_line = false,
                    .extra = .{ .number = win32_rc_ordinal.ordinal },
                });
            },
            error.IdNonAsciiOrdinal => {
                const win32_rc_ordinal = NameOrOrdinal.maybe_non_ascii_ordinal_from_string(id_bytes).?;
                try self.add_error_details(.{
                    .err = .invalid_digit_character_in_ordinal,
                    .type = .err,
                    .token = id_token,
                });
                return self.add_error_details_and_fail(.{
                    .err = .win32_non_ascii_ordinal,
                    .type = .note,
                    .token = id_token,
                    .print_source_line = false,
                    .extra = .{ .number = win32_rc_ordinal.ordinal },
                });
            },
        };
    }

    pub const ResourceHeader = struct {
        name_value: NameOrOrdinal,
        type_value: NameOrOrdinal,
        language: res.Language,
        memory_flags: MemoryFlags,
        data_size: DWORD,
        version: DWORD,
        characteristics: DWORD,
        data_version: DWORD = 0,

        pub const InitError = error{ OutOfMemory, IdNonAsciiOrdinal, TypeNonAsciiOrdinal };

        pub fn init(allocator: Allocator, id_bytes: SourceBytes, type_bytes: SourceBytes, data_size: DWORD, language: res.Language, version: DWORD, characteristics: DWORD) InitError!ResourceHeader {
            const type_value = type: {
                const resource_type = Resource.from_string(type_bytes);
                if (res.RT.from_resource(resource_type)) |rt_constant| {
                    break :type NameOrOrdinal{ .ordinal = @int_from_enum(rt_constant) };
                } else {
                    break :type try NameOrOrdinal.from_string(allocator, type_bytes);
                }
            };
            errdefer type_value.deinit(allocator);
            if (type_value == .name) {
                if (NameOrOrdinal.maybe_non_ascii_ordinal_from_string(type_bytes)) |_| {
                    return error.TypeNonAsciiOrdinal;
                }
            }

            const name_value = try NameOrOrdinal.from_string(allocator, id_bytes);
            errdefer name_value.deinit(allocator);
            if (name_value == .name) {
                if (NameOrOrdinal.maybe_non_ascii_ordinal_from_string(id_bytes)) |_| {
                    return error.IdNonAsciiOrdinal;
                }
            }

            const predefined_resource_type = type_value.predefined_resource_type();

            return ResourceHeader{
                .name_value = name_value,
                .type_value = type_value,
                .data_size = data_size,
                .memory_flags = MemoryFlags.defaults(predefined_resource_type),
                .language = language,
                .version = version,
                .characteristics = characteristics,
            };
        }

        pub fn deinit(self: ResourceHeader, allocator: Allocator) void {
            self.name_value.deinit(allocator);
            self.type_value.deinit(allocator);
        }

        pub const SizeInfo = struct {
            bytes: u32,
            padding_after_name: u2,
        };

        fn calc_size(self: ResourceHeader) error{Overflow}!SizeInfo {
            var header_size: u32 = 8;
            header_size = try std.math.add(
                u32,
                header_size,
                std.math.cast(u32, self.name_value.byte_len()) orelse return error.Overflow,
            );
            header_size = try std.math.add(
                u32,
                header_size,
                std.math.cast(u32, self.type_value.byte_len()) orelse return error.Overflow,
            );
            const padding_after_name = num_padding_bytes_needed(header_size);
            header_size = try std.math.add(u32, header_size, padding_after_name);
            header_size = try std.math.add(u32, header_size, 16);
            return .{ .bytes = header_size, .padding_after_name = padding_after_name };
        }

        pub fn write_assert_no_overflow(self: ResourceHeader, writer: anytype) !void {
            return self.write_size_info(writer, self.calc_size() catch unreachable);
        }

        pub fn write(self: ResourceHeader, writer: anytype, err_ctx: errors.DiagnosticsContext) !void {
            const size_info = self.calc_size() catch {
                try err_ctx.diagnostics.append(.{
                    .err = .resource_data_size_exceeds_max,
                    .token = err_ctx.token,
                });
                return error.CompileError;
            };
            return self.write_size_info(writer, size_info);
        }

        fn write_size_info(self: ResourceHeader, writer: anytype, size_info: SizeInfo) !void {
            try writer.write_int(DWORD, self.data_size, .little); // DataSize
            try writer.write_int(DWORD, size_info.bytes, .little); // HeaderSize
            try self.type_value.write(writer); // TYPE
            try self.name_value.write(writer); // NAME
            try writer.write_byte_ntimes(0, size_info.padding_after_name);

            try writer.write_int(DWORD, self.data_version, .little); // DataVersion
            try writer.write_int(WORD, self.memory_flags.value, .little); // MemoryFlags
            try writer.write_int(WORD, self.language.as_int(), .little); // LanguageId
            try writer.write_int(DWORD, self.version, .little); // Version
            try writer.write_int(DWORD, self.characteristics, .little); // Characteristics
        }

        pub fn predefined_resource_type(self: ResourceHeader) ?res.RT {
            return self.type_value.predefined_resource_type();
        }

        pub fn apply_memory_flags(self: *ResourceHeader, tokens: []Token, source: []const u8) void {
            apply_to_memory_flags(&self.memory_flags, tokens, source);
        }

        pub fn apply_optional_statements(self: *ResourceHeader, statements: []*Node, source: []const u8, code_page_lookup: *const CodePageLookup) void {
            apply_to_optional_statements(&self.language, &self.version, &self.characteristics, statements, source, code_page_lookup);
        }
    };

    fn apply_to_memory_flags(flags: *MemoryFlags, tokens: []Token, source: []const u8) void {
        for (tokens) |token| {
            const attribute = rc.CommonResourceAttributes.map.get(token.slice(source)).?;
            flags.set(attribute);
        }
    }

    /// RT_GROUP_ICON and RT_GROUP_CURSOR have their own special rules for memory flags
    fn apply_to_group_memory_flags(flags: *MemoryFlags, tokens: []Token, source: []const u8) void {
        // There's probably a cleaner implementation of this, but this will result in the same
        // flags as the Win32 RC compiler for all 986,410 K-permutations of memory flags
        // for an ICON resource.
        //
        // This was arrived at by iterating over the permutations and creating a
        // list where each line looks something like this:
        // MOVEABLE PRELOAD -> 0x1050 (MOVEABLE|PRELOAD|DISCARDABLE)
        //
        // and then noticing a few things:

        // 1. Any permutation that does not have PRELOAD in it just uses the
        //    default flags.
        const initial_flags = flags.*;
        var flags_set = std.enums.EnumSet(rc.CommonResourceAttributes).init_empty();
        for (tokens) |token| {
            const attribute = rc.CommonResourceAttributes.map.get(token.slice(source)).?;
            flags_set.insert(attribute);
        }
        if (!flags_set.contains(.preload)) return;

        // 2. Any permutation of flags where applying only the PRELOAD and LOADONCALL flags
        //    results in no actual change by the end will just use the default flags.
        //    For example, `PRELOAD LOADONCALL` will result in default flags, but
        //    `LOADONCALL PRELOAD` will have PRELOAD set after they are both applied in order.
        for (tokens) |token| {
            const attribute = rc.CommonResourceAttributes.map.get(token.slice(source)).?;
            switch (attribute) {
                .preload, .loadoncall => flags.set(attribute),
                else => {},
            }
        }
        if (flags.value == initial_flags.value) return;

        // 3. If none of DISCARDABLE, SHARED, or PURE is specified, then PRELOAD
        //    implies `flags &= ~SHARED` and LOADONCALL implies `flags |= SHARED`
        const shared_set = comptime blk: {
            var set = std.enums.EnumSet(rc.CommonResourceAttributes).init_empty();
            set.insert(.discardable);
            set.insert(.shared);
            set.insert(.pure);
            break :blk set;
        };
        const discardable_shared_or_pure_specified = flags_set.intersect_with(shared_set).count() != 0;
        for (tokens) |token| {
            const attribute = rc.CommonResourceAttributes.map.get(token.slice(source)).?;
            flags.set_group(attribute, !discardable_shared_or_pure_specified);
        }
    }

    /// Only handles the 'base' optional statements that are shared between resource types.
    fn apply_to_optional_statements(language: *res.Language, version: *u32, characteristics: *u32, statements: []*Node, source: []const u8, code_page_lookup: *const CodePageLookup) void {
        for (statements) |node| switch (node.id) {
            .language_statement => {
                const language_statement: *Node.LanguageStatement = @align_cast(@fieldParentPtr("base", node));
                language.* = language_from_language_statement(language_statement, source, code_page_lookup);
            },
            .simple_statement => {
                const simple_statement: *Node.SimpleStatement = @align_cast(@fieldParentPtr("base", node));
                const statement_type = rc.OptionalStatements.map.get(simple_statement.identifier.slice(source)) orelse continue;
                const result = Compiler.evaluate_number_expression(simple_statement.value, source, code_page_lookup);
                switch (statement_type) {
                    .version => version.* = result.value,
                    .characteristics => characteristics.* = result.value,
                    else => unreachable, // only VERSION and CHARACTERISTICS should be in an optional statements list
                }
            },
            else => {},
        };
    }

    pub fn language_from_language_statement(language_statement: *const Node.LanguageStatement, source: []const u8, code_page_lookup: *const CodePageLookup) res.Language {
        const primary = Compiler.evaluate_number_expression(language_statement.primary_language_id, source, code_page_lookup);
        const sublanguage = Compiler.evaluate_number_expression(language_statement.sublanguage_id, source, code_page_lookup);
        return .{
            .primary_language_id = @truncate(primary.value),
            .sublanguage_id = @truncate(sublanguage.value),
        };
    }

    pub fn get_language_from_optional_statements(statements: []*Node, source: []const u8, code_page_lookup: *const CodePageLookup) ?res.Language {
        for (statements) |node| switch (node.id) {
            .language_statement => {
                const language_statement: *Node.LanguageStatement = @align_cast(@fieldParentPtr("base", node));
                return language_from_language_statement(language_statement, source, code_page_lookup);
            },
            else => continue,
        };
        return null;
    }

    pub fn write_empty_resource(writer: anytype) !void {
        const header = ResourceHeader{
            .name_value = .{ .ordinal = 0 },
            .type_value = .{ .ordinal = 0 },
            .language = .{
                .primary_language_id = 0,
                .sublanguage_id = 0,
            },
            .memory_flags = .{ .value = 0 },
            .data_size = 0,
            .version = 0,
            .characteristics = 0,
        };
        try header.write_assert_no_overflow(writer);
    }

    pub fn source_bytes_for_token(self: *Compiler, token: Token) SourceBytes {
        return .{
            .slice = token.slice(self.source),
            .code_page = self.input_code_pages.get_for_token(token),
        };
    }

    /// Helper that calls parse_quoted_string_as_wide_string with the relevant context
    /// Resulting slice is allocated by `self.allocator`.
    pub fn parse_quoted_string_as_wide_string(self: *Compiler, token: Token) ![:0]u16 {
        return literals.parse_quoted_string_as_wide_string(
            self.allocator,
            self.source_bytes_for_token(token),
            .{
                .start_column = token.calculate_column(self.source, 8, null),
                .diagnostics = .{ .diagnostics = self.diagnostics, .token = token },
            },
        );
    }

    fn add_error_details(self: *Compiler, details: ErrorDetails) Allocator.Error!void {
        try self.diagnostics.append(details);
    }

    fn add_error_details_and_fail(self: *Compiler, details: ErrorDetails) error{ CompileError, OutOfMemory } {
        try self.add_error_details(details);
        return error.CompileError;
    }
};

pub const OpenSearchPathError = std.fs.Dir.OpenError;

fn open_search_path_dir(dir: std.fs.Dir, path: []const u8) OpenSearchPathError!std.fs.Dir {
    // Validate the search path to avoid possible unreachable on invalid paths,
    // see https://github.com/ziglang/zig/issues/15607 for why this is currently necessary.
    try validate_search_path(path);
    return dir.open_dir(path, .{});
}

/// Very crude attempt at validating a path. This is imperfect
/// and AFAIK it is effectively impossible to implement perfect path
/// validation, since it ultimately depends on the underlying filesystem.
/// Note that this function won't be necessary if/when
/// https://github.com/ziglang/zig/issues/15607
/// is accepted/implemented.
fn validate_search_path(path: []const u8) error{BadPathName}!void {
    switch (builtin.os.tag) {
        .windows => {
            // This will return error.BadPathName on non-Win32 namespaced paths
            // (e.g. the NT \??\ prefix, the device \\.\ prefix, etc).
            // Those path types are something of an unavoidable way to
            // still hit unreachable during the open_dir call.
            var component_iterator = try std.fs.path.component_iterator(path);
            while (component_iterator.next()) |component| {
                // https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file
                if (std.mem.index_of_any(u8, component.name, "\x00<>:\"|?*") != null) return error.BadPathName;
            }
        },
        else => {
            if (std.mem.index_of_scalar(u8, path, 0) != null) return error.BadPathName;
        },
    }
}

pub const SearchDir = struct {
    dir: std.fs.Dir,
    path: ?[]const u8,

    pub fn deinit(self: *SearchDir, allocator: Allocator) void {
        self.dir.close();
        if (self.path) |path| {
            allocator.free(path);
        }
    }
};

/// Slurps the first `size` bytes read into `slurped_header`
pub fn HeaderSlurpingReader(comptime size: usize, comptime ReaderType: anytype) type {
    return struct {
        child_reader: ReaderType,
        bytes_read: usize = 0,
        slurped_header: [size]u8 = [_]u8{0x00} ** size,

        pub const Error = ReaderType.Error;
        pub const Reader = std.io.Reader(*@This(), Error, read);

        pub fn read(self: *@This(), buf: []u8) Error!usize {
            const amt = try self.child_reader.read(buf);
            if (self.bytes_read < size) {
                const bytes_to_add = @min(amt, size - self.bytes_read);
                const end_index = self.bytes_read + bytes_to_add;
                @memcpy(self.slurped_header[self.bytes_read..end_index], buf[0..bytes_to_add]);
            }
            self.bytes_read +|= amt;
            return amt;
        }

        pub fn reader(self: *@This()) Reader {
            return .{ .context = self };
        }
    };
}

pub fn header_slurping_reader(comptime size: usize, reader: anytype) HeaderSlurpingReader(size, @TypeOf(reader)) {
    return .{ .child_reader = reader };
}

/// Sort of like std.io.LimitedReader, but a Writer.
/// Returns an error if writing the requested number of bytes
/// would ever exceed bytes_left, i.e. it does not always
/// write up to the limit and instead will error if the
/// limit would be breached if the entire slice was written.
pub fn LimitedWriter(comptime WriterType: type) type {
    return struct {
        inner_writer: WriterType,
        bytes_left: u64,

        pub const Error = error{NoSpaceLeft} || WriterType.Error;
        pub const Writer = std.io.Writer(*Self, Error, write);

        const Self = @This();

        pub fn write(self: *Self, bytes: []const u8) Error!usize {
            if (bytes.len > self.bytes_left) return error.NoSpaceLeft;
            const amt = try self.inner_writer.write(bytes);
            self.bytes_left -= amt;
            return amt;
        }

        pub fn writer(self: *Self) Writer {
            return .{ .context = self };
        }
    };
}

/// Returns an initialised `LimitedWriter`
/// `bytes_left` is a `u64` to be able to take 64 bit file offsets
pub fn limited_writer(inner_writer: anytype, bytes_left: u64) LimitedWriter(@TypeOf(inner_writer)) {
    return .{ .inner_writer = inner_writer, .bytes_left = bytes_left };
}

test "limited_writer basic usage" {
    var buf: [4]u8 = undefined;
    var fbs = std.io.fixed_buffer_stream(&buf);
    var limited_stream = limited_writer(fbs.writer(), 4);
    var writer = limited_stream.writer();

    try std.testing.expect_equal(@as(usize, 3), try writer.write("123"));
    try std.testing.expect_equal_slices(u8, "123", buf[0..3]);
    try std.testing.expect_error(error.NoSpaceLeft, writer.write("45"));
    try std.testing.expect_equal(@as(usize, 1), try writer.write("4"));
    try std.testing.expect_equal_slices(u8, "1234", buf[0..4]);
    try std.testing.expect_error(error.NoSpaceLeft, writer.write("5"));
}

pub const FontDir = struct {
    fonts: std.ArrayListUnmanaged(Font) = .{},
    /// To keep track of which ids are set and where they were set from
    ids: std.AutoHashMapUnmanaged(u16, Token) = .{},

    pub const Font = struct {
        id: u16,
        header_bytes: [148]u8,
    };

    pub fn deinit(self: *FontDir, allocator: Allocator) void {
        self.fonts.deinit(allocator);
    }

    pub fn add(self: *FontDir, allocator: Allocator, font: Font, id_token: Token) !void {
        try self.ids.put_no_clobber(allocator, font.id, id_token);
        try self.fonts.append(allocator, font);
    }

    pub fn write_res_data(self: *FontDir, compiler: *Compiler, writer: anytype) !void {
        if (self.fonts.items.len == 0) return;

        // We know the number of fonts is limited to max_int(u16) because fonts
        // must have a valid and unique u16 ordinal ID (trying to specify a FONT
        // with e.g. id 65537 will wrap around to 1 and be ignored if there's already
        // a font with that ID in the file).
        const num_fonts: u16 = @int_cast(self.fonts.items.len);

        // u16 count + [(u16 id + 150 bytes) for each font]
        // Note: This works out to a maximum data_size of 9,961,322.
        const data_size: u32 = 2 + (2 + 150) * num_fonts;

        var header = Compiler.ResourceHeader{
            .name_value = try NameOrOrdinal.name_from_string(compiler.allocator, .{ .slice = "FONTDIR", .code_page = .windows1252 }),
            .type_value = NameOrOrdinal{ .ordinal = @int_from_enum(res.RT.FONTDIR) },
            .memory_flags = res.MemoryFlags.defaults(res.RT.FONTDIR),
            .language = compiler.state.language,
            .version = compiler.state.version,
            .characteristics = compiler.state.characteristics,
            .data_size = data_size,
        };
        defer header.deinit(compiler.allocator);

        try header.write_assert_no_overflow(writer);
        try writer.write_int(u16, num_fonts, .little);
        for (self.fonts.items) |font| {
            // The format of the FONTDIR is a strange beast.
            // Technically, each FONT is seemingly meant to be written as a
            // FONTDIRENTRY with two trailing NUL-terminated strings corresponding to
            // the 'device name' and 'face name' of the .FNT file, but:
            //
            // 1. When dealing with .FNT files, the Win32 implementation
            //    gets the device name and face name from the wrong locations,
            //    so it's basically never going to write the real device/face name
            //    strings.
            // 2. When dealing with files 76-140 bytes long, the Win32 implementation
            //    can just crash (if there are no NUL bytes in the file).
            // 3. The 32-bit Win32 rc.exe uses a 148 byte size for the portion of
            //    the FONTDIRENTRY before the NUL-terminated strings, which
            //    does not match the documented FONTDIRENTRY size that (presumably)
            //    this format is meant to be using, so anything iterating the
            //    FONTDIR according to the available documentation will get bogus results.
            // 4. The FONT resource can be used for non-.FNT types like TTF and OTF,
            //    in which case emulating the Win32 behavior of unconditionally
            //    interpreting the bytes as a .FNT and trying to grab device/face names
            //    from random bytes in the TTF/OTF file can lead to weird behavior
            //    and errors in the Win32 implementation (for example, the device/face
            //    name fields are offsets into the file where the NUL-terminated
            //    string is located, but the Win32 implementation actually treats
            //    them as signed so if they are negative then the Win32 implementation
            //    will error; this happening for TTF fonts would just be a bug
            //    since the TTF could otherwise be valid)
            // 5. The FONTDIR resource doesn't actually seem to be used at all by
            //    anything that I've found, and instead in Windows 3.0 and newer
            //    it seems like the FONT resources are always just iterated/accessed
            //    directly without ever looking at the FONTDIR.
            //
            // All of these combined means that we:
            // - Do not need or want to emulate Win32 behavior here
            // - For maximum simplicity and compatibility, we just write the first
            //   148 bytes of the file without any interpretation (padded with
            //   zeroes to get up to 148 bytes if necessary), and then
            //   unconditionally write two NUL bytes, meaning that we always
            //   write 'device name' and 'face name' as if they were 0-length
            //   strings.
            //
            // This gives us byte-for-byte .RES compatibility in the common case while
            // allowing us to avoid any erroneous errors caused by trying to read
            // the face/device name from a bogus location. Note that the Win32
            // implementation never actually writes the real device/face name here
            // anyway (except in the bizarre case that a .FNT file has the proper
            // device/face name offsets within a reserved section of the .FNT file)
            // so there's no feasible way that anything can actually think that the
            // device name/face name in the FONTDIR is reliable.

            // First, the ID is written, though
            try writer.write_int(u16, font.id, .little);
            try writer.write_all(&font.header_bytes);
            try writer.write_byte_ntimes(0, 2);
        }
        try Compiler.write_data_padding(writer, data_size);
    }
};

pub const StringTablesByLanguage = struct {
    /// String tables for each language are written to the .res file in order depending on
    /// when the first STRINGTABLE for the language was defined, and all blocks for a given
    /// language are written contiguously.
    /// Using an ArrayHashMap here gives us this property for free.
    tables: std.AutoArrayHashMapUnmanaged(res.Language, StringTable) = .{},

    pub fn deinit(self: *StringTablesByLanguage, allocator: Allocator) void {
        self.tables.deinit(allocator);
    }

    pub fn set(
        self: *StringTablesByLanguage,
        allocator: Allocator,
        language: res.Language,
        id: u16,
        string_token: Token,
        node: *Node,
        source: []const u8,
        code_page_lookup: *const CodePageLookup,
        version: u32,
        characteristics: u32,
    ) StringTable.SetError!void {
        var get_or_put_result = try self.tables.get_or_put(allocator, language);
        if (!get_or_put_result.found_existing) {
            get_or_put_result.value_ptr.* = StringTable{};
        }
        return get_or_put_result.value_ptr.set(allocator, id, string_token, node, source, code_page_lookup, version, characteristics);
    }
};

pub const StringTable = struct {
    /// Blocks are written to the .res file in order depending on when the first string
    /// was added to the block (i.e. `STRINGTABLE { 16 "b" 0 "a" }` would then get written
    /// with block ID 2 (the one with "b") first and block ID 1 (the one with "a") second).
    /// Using an ArrayHashMap here gives us this property for free.
    blocks: std.AutoArrayHashMapUnmanaged(u16, Block) = .{},

    pub const Block = struct {
        strings: std.ArrayListUnmanaged(Token) = .{},
        set_indexes: std.bit_set.IntegerBitSet(16) = .{ .mask = 0 },
        memory_flags: MemoryFlags = MemoryFlags.defaults(res.RT.STRING),
        characteristics: u32,
        version: u32,

        /// Returns the index to insert the string into the `strings` list.
        /// Returns null if the string should be appended.
        fn get_insertion_index(self: *Block, index: u8) ?u8 {
            std.debug.assert(!self.set_indexes.is_set(index));

            const first_set = self.set_indexes.find_first_set() orelse return null;
            if (first_set > index) return 0;

            const last_set = 15 - @clz(self.set_indexes.mask);
            if (index > last_set) return null;

            var bit = first_set + 1;
            var insertion_index: u8 = 1;
            while (bit != index) : (bit += 1) {
                if (self.set_indexes.is_set(bit)) insertion_index += 1;
            }
            return insertion_index;
        }

        fn get_token_index(self: *Block, string_index: u8) ?u8 {
            const count = self.strings.items.len;
            if (count == 0) return null;
            if (count == 1) return 0;

            const first_set = self.set_indexes.find_first_set() orelse unreachable;
            if (first_set == string_index) return 0;
            const last_set = 15 - @clz(self.set_indexes.mask);
            if (last_set == string_index) return @int_cast(count - 1);

            if (first_set == last_set) return null;

            var bit = first_set + 1;
            var token_index: u8 = 1;
            while (bit < last_set) : (bit += 1) {
                if (!self.set_indexes.is_set(bit)) continue;
                if (bit == string_index) return token_index;
                token_index += 1;
            }
            return null;
        }

        fn dump(self: *Block) void {
            var bit_it = self.set_indexes.iterator(.{});
            var string_index: usize = 0;
            while (bit_it.next()) |bit_index| {
                const token = self.strings.items[string_index];
                std.debug.print("{}: [{}] {any}\n", .{ bit_index, string_index, token });
                string_index += 1;
            }
        }

        pub fn apply_attributes(self: *Block, string_table: *Node.StringTable, source: []const u8, code_page_lookup: *const CodePageLookup) void {
            Compiler.apply_to_memory_flags(&self.memory_flags, string_table.common_resource_attributes, source);
            var dummy_language: res.Language = undefined;
            Compiler.apply_to_optional_statements(&dummy_language, &self.version, &self.characteristics, string_table.optional_statements, source, code_page_lookup);
        }

        fn trim_to_double_nul(comptime T: type, str: []const T) []const T {
            var last_was_null = false;
            for (str, 0..) |c, i| {
                if (c == 0) {
                    if (last_was_null) return str[0 .. i - 1];
                    last_was_null = true;
                } else {
                    last_was_null = false;
                }
            }
            return str;
        }

        test "trim_to_double_nul" {
            try std.testing.expect_equal_strings("a\x00b", trim_to_double_nul(u8, "a\x00b"));
            try std.testing.expect_equal_strings("a", trim_to_double_nul(u8, "a\x00\x00b"));
        }

        pub fn write_res_data(self: *Block, compiler: *Compiler, language: res.Language, block_id: u16, writer: anytype) !void {
            var data_buffer = std.ArrayList(u8).init(compiler.allocator);
            defer data_buffer.deinit();
            const data_writer = data_buffer.writer();

            var i: u8 = 0;
            var string_i: u8 = 0;
            while (true) : (i += 1) {
                if (!self.set_indexes.is_set(i)) {
                    try data_writer.write_int(u16, 0, .little);
                    if (i == 15) break else continue;
                }

                const string_token = self.strings.items[string_i];
                const slice = string_token.slice(compiler.source);
                const column = string_token.calculate_column(compiler.source, 8, null);
                const code_page = compiler.input_code_pages.get_for_token(string_token);
                const bytes = SourceBytes{ .slice = slice, .code_page = code_page };
                const utf16_string = try literals.parse_quoted_string_as_wide_string(compiler.allocator, bytes, .{
                    .start_column = column,
                    .diagnostics = .{ .diagnostics = compiler.diagnostics, .token = string_token },
                });
                defer compiler.allocator.free(utf16_string);

                const trimmed_string = trim: {
                    // Two NUL characters in a row act as a terminator
                    // Note: This is only the case for STRINGTABLE strings
                    const trimmed = trim_to_double_nul(u16, utf16_string);
                    // We also want to trim any trailing NUL characters
                    break :trim std.mem.trim_right(u16, trimmed, &[_]u16{0});
                };

                // String literals are limited to max_int(u15) codepoints, so these UTF-16 encoded
                // strings are limited to max_int(u15) * 2 = 65,534 code units (since 2 is the
                // maximum number of UTF-16 code units per codepoint).
                // This leaves room for exactly one NUL terminator.
                var string_len_in_utf16_code_units: u16 = @int_cast(trimmed_string.len);
                // If the option is set, then a NUL terminator is added unconditionally.
                // We already trimmed any trailing NULs, so we know it will be a new addition to the string.
                if (compiler.null_terminate_string_table_strings) string_len_in_utf16_code_units += 1;
                try data_writer.write_int(u16, string_len_in_utf16_code_units, .little);
                try data_writer.write_all(std.mem.slice_as_bytes(trimmed_string));
                if (compiler.null_terminate_string_table_strings) {
                    try data_writer.write_int(u16, 0, .little);
                }

                if (i == 15) break;
                string_i += 1;
            }

            // This int_cast will never be able to fail due to the length constraints on string literals.
            //
            // - STRINGTABLE resource definitions can can only provide one string literal per index.
            // - STRINGTABLE strings are limited to max_int(u16) UTF-16 code units (see 'string_len_in_utf16_code_units'
            //   above), which means that the maximum number of bytes per string literal is
            //   2 * max_int(u16) = 131,070 (since there are 2 bytes per UTF-16 code unit).
            // - Each Block/RT_STRING resource includes exactly 16 strings and each have a 2 byte
            //   length field, so the maximum number of total bytes in a RT_STRING resource's data is
            //   16 * (131,070 + 2) = 2,097,152 which is well within the u32 max.
            //
            // Note: The string literal maximum length is enforced by the lexer.
            const data_size: u32 = @int_cast(data_buffer.items.len);

            const header = Compiler.ResourceHeader{
                .name_value = .{ .ordinal = block_id },
                .type_value = .{ .ordinal = @int_from_enum(res.RT.STRING) },
                .memory_flags = self.memory_flags,
                .language = language,
                .version = self.version,
                .characteristics = self.characteristics,
                .data_size = data_size,
            };
            // The only variable parts of the header are name and type, which in this case
            // we fully control and know are numbers, so they have a fixed size.
            try header.write_assert_no_overflow(writer);

            var data_fbs = std.io.fixed_buffer_stream(data_buffer.items);
            try Compiler.write_resource_data(writer, data_fbs.reader(), data_size);
        }
    };

    pub fn deinit(self: *StringTable, allocator: Allocator) void {
        var it = self.blocks.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.strings.deinit(allocator);
        }
        self.blocks.deinit(allocator);
    }

    const SetError = error{StringAlreadyDefined} || Allocator.Error;

    pub fn set(
        self: *StringTable,
        allocator: Allocator,
        id: u16,
        string_token: Token,
        node: *Node,
        source: []const u8,
        code_page_lookup: *const CodePageLookup,
        version: u32,
        characteristics: u32,
    ) SetError!void {
        const block_id = (id / 16) + 1;
        const string_index: u8 = @int_cast(id & 0xF);

        var get_or_put_result = try self.blocks.get_or_put(allocator, block_id);
        if (!get_or_put_result.found_existing) {
            get_or_put_result.value_ptr.* = Block{ .version = version, .characteristics = characteristics };
            get_or_put_result.value_ptr.apply_attributes(node.cast(.string_table).?, source, code_page_lookup);
        } else {
            if (get_or_put_result.value_ptr.set_indexes.is_set(string_index)) {
                return error.StringAlreadyDefined;
            }
        }

        var block = get_or_put_result.value_ptr;
        if (block.get_insertion_index(string_index)) |insertion_index| {
            try block.strings.insert(allocator, insertion_index, string_token);
        } else {
            try block.strings.append(allocator, string_token);
        }
        block.set_indexes.set(string_index);
    }

    pub fn get(self: *StringTable, id: u16) ?Token {
        const block_id = (id / 16) + 1;
        const string_index: u8 = @int_cast(id & 0xF);

        const block = self.blocks.get_ptr(block_id) orelse return null;
        const token_index = block.get_token_index(string_index) orelse return null;
        return block.strings.items[token_index];
    }

    pub fn dump(self: *StringTable) !void {
        var it = self.iterator();
        while (it.next()) |entry| {
            std.debug.print("block: {}\n", .{entry.key_ptr.*});
            entry.value_ptr.dump();
        }
    }
};

test "StringTable" {
    const S = struct {
        fn make_dummy_token(id: usize) Token {
            return Token{
                .id = .invalid,
                .start = id,
                .end = id,
                .line_number = id,
            };
        }
    };
    const allocator = std.testing.allocator;
    var string_table = StringTable{};
    defer string_table.deinit(allocator);

    var code_page_lookup = CodePageLookup.init(allocator, .windows1252);
    defer code_page_lookup.deinit();

    var dummy_node = Node.StringTable{
        .type = S.make_dummy_token(0),
        .common_resource_attributes = &.{},
        .optional_statements = &.{},
        .begin_token = S.make_dummy_token(0),
        .strings = &.{},
        .end_token = S.make_dummy_token(0),
    };

    // randomize an array of ids 0-99
    var ids = ids: {
        var buf: [100]u16 = undefined;
        var i: u16 = 0;
        while (i < buf.len) : (i += 1) {
            buf[i] = i;
        }
        break :ids buf;
    };
    var prng = std.rand.DefaultPrng.init(0);
    var random = prng.random();
    random.shuffle(u16, &ids);

    // set each one in the randomized order
    for (ids) |id| {
        try string_table.set(allocator, id, S.make_dummy_token(id), &dummy_node.base, "", &code_page_lookup, 0, 0);
    }

    // make sure each one exists and is the right value when gotten
    var id: u16 = 0;
    while (id < 100) : (id += 1) {
        const dummy = S.make_dummy_token(id);
        try std.testing.expect_error(error.StringAlreadyDefined, string_table.set(allocator, id, dummy, &dummy_node.base, "", &code_page_lookup, 0, 0));
        try std.testing.expect_equal(dummy, string_table.get(id).?);
    }

    // make sure non-existent string ids are not found
    try std.testing.expect_equal(@as(?Token, null), string_table.get(100));
}
