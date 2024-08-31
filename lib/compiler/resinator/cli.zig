const std = @import("std");
const CodePage = @import("code_pages.zig").CodePage;
const lang = @import("lang.zig");
const res = @import("res.zig");
const Allocator = std.mem.Allocator;
const lex = @import("lex.zig");

/// This is what /SL 100 will set the maximum string literal length to
pub const max_string_literal_length_100_percent = 8192;

pub const usage_string_after_command_name =
    \\ [options] [--] <INPUT> [<OUTPUT>]
    \\
    \\The sequence -- can be used to signify when to stop parsing options.
    \\This is necessary when the input path begins with a forward slash.
    \\
    \\Supported Win32 RC Options:
    \\  /?, /h                  Print this help and exit.
    \\  /v                      Verbose (print progress messages).
    \\  /d <name>[=<value>]     Define a symbol (during preprocessing).
    \\  /u <name>               Undefine a symbol (during preprocessing).
    \\  /fo <value>             Specify output file path.
    \\  /l <value>              Set default language using hexadecimal id (ex: 409).
    \\  /ln <value>             Set default language using language name (ex: en-us).
    \\  /i <value>              Add an include path.
    \\  /x                      Ignore INCLUDE environment variable.
    \\  /c <value>              Set default code page (ex: 65001).
    \\  /w                      Warn on invalid code page in .rc (instead of error).
    \\  /y                      Suppress warnings for duplicate control IDs.
    \\  /n                      Null-terminate all strings in string tables.
    \\  /sl <value>             Specify string literal length limit in percentage (1-100)
    \\                          where 100 corresponds to a limit of 8192. If the /sl
    \\                          option is not specified, the default limit is 4097.
    \\  /p                      Only run the preprocessor and output a .rcpp file.
    \\
    \\No-op Win32 RC Options:
    \\  /nologo, /a, /r         Options that are recognized but do nothing.
    \\
    \\Unsupported Win32 RC Options:
    \\  /fm, /q, /g, /gn, /g1, /g2     Unsupported MUI-related options.
    \\  /?c, /hc, /t, /tp:<prefix>,    Unsupported LCX/LCE-related options.
    \\     /tn, /tm, /tc, /tw, /te,
    \\                    /ti, /ta
    \\  /z                             Unsupported font-substitution-related option.
    \\  /s                             Unsupported HWB-related option.
    \\
    \\Custom Options (resinator-specific):
    \\  /:no-preprocess           Do not run the preprocessor.
    \\  /:debug                   Output the preprocessed .rc file and the parsed AST.
    \\  /:auto-includes <value>   Set the automatic include path detection behavior.
    \\    any                     (default) Use MSVC if available, fall back to MinGW
    \\    msvc                    Use MSVC include paths (must be present on the system)
    \\    gnu                     Use MinGW include paths
    \\    none                    Do not use any autodetected include paths
    \\  /:depfile <path>          Output a file containing a list of all the files that
    \\                            the .rc includes or otherwise depends on.
    \\  /:depfile-fmt <value>     Output format of the depfile, if /:depfile is set.
    \\    json                    (default) A top-level JSON array of paths
    \\  /:mingw-includes <path>   Path to a directory containing MinGW include files. If
    \\                            not specified, bundled MinGW include files will be used.
    \\
    \\Note: For compatibility reasons, all custom options start with :
    \\
;

pub fn write_usage(writer: anytype, command_name: []const u8) !void {
    try writer.write_all("Usage: ");
    try writer.write_all(command_name);
    try writer.write_all(usage_string_after_command_name);
}

pub const Diagnostics = struct {
    errors: std.ArrayListUnmanaged(ErrorDetails) = .{},
    allocator: Allocator,

    pub const ErrorDetails = struct {
        arg_index: usize,
        arg_span: ArgSpan = .{},
        msg: std.ArrayListUnmanaged(u8) = .{},
        type: Type = .err,
        print_args: bool = true,

        pub const Type = enum { err, warning, note };
        pub const ArgSpan = struct {
            point_at_next_arg: bool = false,
            name_offset: usize = 0,
            prefix_len: usize = 0,
            value_offset: usize = 0,
            name_len: usize = 0,
        };
    };

    pub fn init(allocator: Allocator) Diagnostics {
        return .{
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Diagnostics) void {
        for (self.errors.items) |*details| {
            details.msg.deinit(self.allocator);
        }
        self.errors.deinit(self.allocator);
    }

    pub fn append(self: *Diagnostics, error_details: ErrorDetails) !void {
        try self.errors.append(self.allocator, error_details);
    }

    pub fn render_to_std_err(self: *Diagnostics, args: []const []const u8, config: std.io.tty.Config) void {
        std.debug.lock_std_err();
        defer std.debug.unlock_std_err();
        const stderr = std.io.get_std_err().writer();
        self.render_to_writer(args, stderr, config) catch return;
    }

    pub fn render_to_writer(self: *Diagnostics, args: []const []const u8, writer: anytype, config: std.io.tty.Config) !void {
        for (self.errors.items) |err_details| {
            try render_error_message(writer, config, err_details, args);
        }
    }

    pub fn has_error(self: *const Diagnostics) bool {
        for (self.errors.items) |err| {
            if (err.type == .err) return true;
        }
        return false;
    }
};

pub const Options = struct {
    allocator: Allocator,
    input_filename: []const u8 = &[_]u8{},
    output_filename: []const u8 = &[_]u8{},
    extra_include_paths: std.ArrayListUnmanaged([]const u8) = .{},
    ignore_include_env_var: bool = false,
    preprocess: Preprocess = .yes,
    default_language_id: ?u16 = null,
    default_code_page: ?CodePage = null,
    verbose: bool = false,
    symbols: std.StringArrayHashMapUnmanaged(SymbolValue) = .{},
    null_terminate_string_table_strings: bool = false,
    max_string_literal_codepoints: u15 = lex.default_max_string_literal_codepoints,
    silent_duplicate_control_ids: bool = false,
    warn_instead_of_error_on_invalid_code_page: bool = false,
    debug: bool = false,
    print_help_and_exit: bool = false,
    auto_includes: AutoIncludes = .any,
    depfile_path: ?[]const u8 = null,
    depfile_fmt: DepfileFormat = .json,
    mingw_includes_dir: ?[]const u8 = null,

    pub const AutoIncludes = enum { any, msvc, gnu, none };
    pub const DepfileFormat = enum { json };
    pub const Preprocess = enum { no, yes, only };
    pub const SymbolAction = enum { define, undefine };
    pub const SymbolValue = union(SymbolAction) {
        define: []const u8,
        undefine: void,

        pub fn deinit(self: SymbolValue, allocator: Allocator) void {
            switch (self) {
                .define => |value| allocator.free(value),
                .undefine => {},
            }
        }
    };

    /// Does not check that identifier contains only valid characters
    pub fn define(self: *Options, identifier: []const u8, value: []const u8) !void {
        if (self.symbols.get_ptr(identifier)) |val_ptr| {
            // If the symbol is undefined, then that always takes precedence so
            // we shouldn't change anything.
            if (val_ptr.* == .undefine) return;
            // Otherwise, the new value takes precedence.
            const duped_value = try self.allocator.dupe(u8, value);
            errdefer self.allocator.free(duped_value);
            val_ptr.deinit(self.allocator);
            val_ptr.* = .{ .define = duped_value };
            return;
        }
        const duped_key = try self.allocator.dupe(u8, identifier);
        errdefer self.allocator.free(duped_key);
        const duped_value = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(duped_value);
        try self.symbols.put(self.allocator, duped_key, .{ .define = duped_value });
    }

    /// Does not check that identifier contains only valid characters
    pub fn undefine(self: *Options, identifier: []const u8) !void {
        if (self.symbols.get_ptr(identifier)) |action| {
            action.deinit(self.allocator);
            action.* = .{ .undefine = {} };
            return;
        }
        const duped_key = try self.allocator.dupe(u8, identifier);
        errdefer self.allocator.free(duped_key);
        try self.symbols.put(self.allocator, duped_key, .{ .undefine = {} });
    }

    /// If the current input filename both:
    /// - does not have an extension, and
    /// - does not exist in the cwd
    /// then this function will append `.rc` to the input filename
    ///
    /// Note: This behavior is different from the Win32 compiler.
    ///       It always appends .RC if the filename does not have
    ///       a `.` in it and it does not even try the verbatim name
    ///       in that scenario.
    ///
    /// The approach taken here is meant to give us a 'best of both
    /// worlds' situation where we'll be compatible with most use-cases
    /// of the .rc extension being omitted from the CLI args, but still
    /// work fine if the file itself does not have an extension.
    pub fn maybe_append_rc(options: *Options, cwd: std.fs.Dir) !void {
        if (std.fs.path.extension(options.input_filename).len == 0) {
            cwd.access(options.input_filename, .{}) catch |err| switch (err) {
                error.FileNotFound => {
                    var filename_bytes = try options.allocator.alloc(u8, options.input_filename.len + 3);
                    @memcpy(filename_bytes[0..options.input_filename.len], options.input_filename);
                    @memcpy(filename_bytes[filename_bytes.len - 3 ..], ".rc");
                    options.allocator.free(options.input_filename);
                    options.input_filename = filename_bytes;
                },
                else => {},
            };
        }
    }

    pub fn deinit(self: *Options) void {
        for (self.extra_include_paths.items) |extra_include_path| {
            self.allocator.free(extra_include_path);
        }
        self.extra_include_paths.deinit(self.allocator);
        self.allocator.free(self.input_filename);
        self.allocator.free(self.output_filename);
        var symbol_it = self.symbols.iterator();
        while (symbol_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.symbols.deinit(self.allocator);
        if (self.depfile_path) |depfile_path| {
            self.allocator.free(depfile_path);
        }
        if (self.mingw_includes_dir) |mingw_includes_dir| {
            self.allocator.free(mingw_includes_dir);
        }
    }

    pub fn dump_verbose(self: *const Options, writer: anytype) !void {
        try writer.print("Input filename: {s}\n", .{self.input_filename});
        try writer.print("Output filename: {s}\n", .{self.output_filename});
        if (self.extra_include_paths.items.len > 0) {
            try writer.write_all(" Extra include paths:\n");
            for (self.extra_include_paths.items) |extra_include_path| {
                try writer.print("  \"{s}\"\n", .{extra_include_path});
            }
        }
        if (self.ignore_include_env_var) {
            try writer.write_all(" The INCLUDE environment variable will be ignored\n");
        }
        if (self.preprocess == .no) {
            try writer.write_all(" The preprocessor will not be invoked\n");
        } else if (self.preprocess == .only) {
            try writer.write_all(" Only the preprocessor will be invoked\n");
        }
        if (self.symbols.count() > 0) {
            try writer.write_all(" Symbols:\n");
            var it = self.symbols.iterator();
            while (it.next()) |symbol| {
                try writer.print("  {s} {s}", .{ switch (symbol.value_ptr.*) {
                    .define => "#define",
                    .undefine => "#undef",
                }, symbol.key_ptr.* });
                if (symbol.value_ptr.* == .define) {
                    try writer.print(" {s}", .{symbol.value_ptr.define});
                }
                try writer.write_all("\n");
            }
        }
        if (self.null_terminate_string_table_strings) {
            try writer.write_all(" Strings in string tables will be null-terminated\n");
        }
        if (self.max_string_literal_codepoints != lex.default_max_string_literal_codepoints) {
            try writer.print(" Max string literal length: {}\n", .{self.max_string_literal_codepoints});
        }
        if (self.silent_duplicate_control_ids) {
            try writer.write_all(" Duplicate control IDs will not emit warnings\n");
        }
        if (self.silent_duplicate_control_ids) {
            try writer.write_all(" Invalid code page in .rc will produce a warning (instead of an error)\n");
        }

        const language_id = self.default_language_id orelse res.Language.default;
        const language_name = language_name: {
            if (std.meta.int_to_enum(lang.LanguageId, language_id)) |lang_enum_val| {
                break :language_name @tag_name(lang_enum_val);
            } else |_| {}
            if (language_id == lang.LOCALE_CUSTOM_UNSPECIFIED) {
                break :language_name "LOCALE_CUSTOM_UNSPECIFIED";
            }
            break :language_name "<UNKNOWN>";
        };
        try writer.print("Default language: {s} (id=0x{x})\n", .{ language_name, language_id });

        const code_page = self.default_code_page orelse .windows1252;
        try writer.print("Default codepage: {s} (id={})\n", .{ @tag_name(code_page), @int_from_enum(code_page) });
    }
};

pub const Arg = struct {
    prefix: enum { long, short, slash },
    name_offset: usize,
    full: []const u8,

    pub fn from_string(str: []const u8) ?@This() {
        if (std.mem.starts_with(u8, str, "--")) {
            return .{ .prefix = .long, .name_offset = 2, .full = str };
        } else if (std.mem.starts_with(u8, str, "-")) {
            return .{ .prefix = .short, .name_offset = 1, .full = str };
        } else if (std.mem.starts_with(u8, str, "/")) {
            return .{ .prefix = .slash, .name_offset = 1, .full = str };
        }
        return null;
    }

    pub fn prefix_slice(self: Arg) []const u8 {
        return self.full[0..(if (self.prefix == .long) 2 else 1)];
    }

    pub fn name(self: Arg) []const u8 {
        return self.full[self.name_offset..];
    }

    pub fn option_without_prefix(self: Arg, option_len: usize) []const u8 {
        return self.name()[0..option_len];
    }

    pub fn missing_span(self: Arg) Diagnostics.ErrorDetails.ArgSpan {
        return .{
            .point_at_next_arg = true,
            .value_offset = 0,
            .name_offset = self.name_offset,
            .prefix_len = self.prefix_slice().len,
        };
    }

    pub fn option_and_after_span(self: Arg) Diagnostics.ErrorDetails.ArgSpan {
        return self.option_span(0);
    }

    pub fn option_span(self: Arg, option_len: usize) Diagnostics.ErrorDetails.ArgSpan {
        return .{
            .name_offset = self.name_offset,
            .prefix_len = self.prefix_slice().len,
            .name_len = option_len,
        };
    }

    pub const Value = struct {
        slice: []const u8,
        index_increment: u2 = 1,

        pub fn arg_span(self: Value, arg: Arg) Diagnostics.ErrorDetails.ArgSpan {
            const prefix_len = arg.prefix_slice().len;
            switch (self.index_increment) {
                1 => return .{
                    .value_offset = @int_from_ptr(self.slice.ptr) - @int_from_ptr(arg.full.ptr),
                    .prefix_len = prefix_len,
                    .name_offset = arg.name_offset,
                },
                2 => return .{
                    .point_at_next_arg = true,
                    .prefix_len = prefix_len,
                    .name_offset = arg.name_offset,
                },
                else => unreachable,
            }
        }

        pub fn index(self: Value, arg_index: usize) usize {
            if (self.index_increment == 2) return arg_index + 1;
            return arg_index;
        }
    };

    pub fn value(self: Arg, option_len: usize, index: usize, args: []const []const u8) error{MissingValue}!Value {
        const rest = self.full[self.name_offset + option_len ..];
        if (rest.len > 0) return .{ .slice = rest };
        if (index + 1 >= args.len) return error.MissingValue;
        return .{ .slice = args[index + 1], .index_increment = 2 };
    }

    pub const Context = struct {
        index: usize,
        arg: Arg,
        value: Value,
    };
};

pub const ParseError = error{ParseError} || Allocator.Error;

/// Note: Does not run `Options.maybe_append_rc` automatically. If that behavior is desired,
///       it must be called separately.
pub fn parse(allocator: Allocator, args: []const []const u8, diagnostics: *Diagnostics) ParseError!Options {
    var options = Options{ .allocator = allocator };
    errdefer options.deinit();

    var output_filename: ?[]const u8 = null;
    var output_filename_context: Arg.Context = undefined;

    var arg_i: usize = 0;
    next_arg: while (arg_i < args.len) {
        var arg = Arg.from_string(args[arg_i]) orelse break;
        if (arg.name().len == 0) {
            switch (arg.prefix) {
                // -- on its own ends arg parsing
                .long => {
                    arg_i += 1;
                    break;
                },
                // - or / on its own is an error
                else => {
                    var err_details = Diagnostics.ErrorDetails{ .arg_index = arg_i, .arg_span = arg.option_and_after_span() };
                    var msg_writer = err_details.msg.writer(allocator);
                    try msg_writer.print("invalid option: {s}", .{arg.prefix_slice()});
                    try diagnostics.append(err_details);
                    arg_i += 1;
                    continue :next_arg;
                },
            }
        }

        while (arg.name().len > 0) {
            const arg_name = arg.name();
            // Note: These cases should be in order from longest to shortest, since
            //       shorter options that are a substring of a longer one could make
            //       the longer option's branch unreachable.
            if (std.ascii.starts_with_ignore_case(arg_name, ":no-preprocess")) {
                options.preprocess = .no;
                arg.name_offset += ":no-preprocess".len;
            } else if (std.ascii.starts_with_ignore_case(arg_name, ":mingw-includes")) {
                const value = arg.value(":mingw-includes".len, arg_i, args) catch {
                    var err_details = Diagnostics.ErrorDetails{ .arg_index = arg_i, .arg_span = arg.missing_span() };
                    var msg_writer = err_details.msg.writer(allocator);
                    try msg_writer.print("missing value after {s}{s} option", .{ arg.prefix_slice(), arg.option_without_prefix(":mingw-includes".len) });
                    try diagnostics.append(err_details);
                    arg_i += 1;
                    break :next_arg;
                };
                if (options.mingw_includes_dir) |overwritten_path| {
                    allocator.free(overwritten_path);
                    options.mingw_includes_dir = null;
                }
                const path = try allocator.dupe(u8, value.slice);
                errdefer allocator.free(path);
                options.mingw_includes_dir = path;
                arg_i += value.index_increment;
                continue :next_arg;
            } else if (std.ascii.starts_with_ignore_case(arg_name, ":auto-includes")) {
                const value = arg.value(":auto-includes".len, arg_i, args) catch {
                    var err_details = Diagnostics.ErrorDetails{ .arg_index = arg_i, .arg_span = arg.missing_span() };
                    var msg_writer = err_details.msg.writer(allocator);
                    try msg_writer.print("missing value after {s}{s} option", .{ arg.prefix_slice(), arg.option_without_prefix(":auto-includes".len) });
                    try diagnostics.append(err_details);
                    arg_i += 1;
                    break :next_arg;
                };
                options.auto_includes = std.meta.string_to_enum(Options.AutoIncludes, value.slice) orelse blk: {
                    var err_details = Diagnostics.ErrorDetails{ .arg_index = arg_i, .arg_span = value.arg_span(arg) };
                    var msg_writer = err_details.msg.writer(allocator);
                    try msg_writer.print("invalid auto includes setting: {s} ", .{value.slice});
                    try diagnostics.append(err_details);
                    break :blk options.auto_includes;
                };
                arg_i += value.index_increment;
                continue :next_arg;
            } else if (std.ascii.starts_with_ignore_case(arg_name, ":depfile-fmt")) {
                const value = arg.value(":depfile-fmt".len, arg_i, args) catch {
                    var err_details = Diagnostics.ErrorDetails{ .arg_index = arg_i, .arg_span = arg.missing_span() };
                    var msg_writer = err_details.msg.writer(allocator);
                    try msg_writer.print("missing value after {s}{s} option", .{ arg.prefix_slice(), arg.option_without_prefix(":depfile-fmt".len) });
                    try diagnostics.append(err_details);
                    arg_i += 1;
                    break :next_arg;
                };
                options.depfile_fmt = std.meta.string_to_enum(Options.DepfileFormat, value.slice) orelse blk: {
                    var err_details = Diagnostics.ErrorDetails{ .arg_index = arg_i, .arg_span = value.arg_span(arg) };
                    var msg_writer = err_details.msg.writer(allocator);
                    try msg_writer.print("invalid depfile format setting: {s} ", .{value.slice});
                    try diagnostics.append(err_details);
                    break :blk options.depfile_fmt;
                };
                arg_i += value.index_increment;
                continue :next_arg;
            } else if (std.ascii.starts_with_ignore_case(arg_name, ":depfile")) {
                const value = arg.value(":depfile".len, arg_i, args) catch {
                    var err_details = Diagnostics.ErrorDetails{ .arg_index = arg_i, .arg_span = arg.missing_span() };
                    var msg_writer = err_details.msg.writer(allocator);
                    try msg_writer.print("missing value after {s}{s} option", .{ arg.prefix_slice(), arg.option_without_prefix(":depfile".len) });
                    try diagnostics.append(err_details);
                    arg_i += 1;
                    break :next_arg;
                };
                if (options.depfile_path) |overwritten_path| {
                    allocator.free(overwritten_path);
                    options.depfile_path = null;
                }
                const path = try allocator.dupe(u8, value.slice);
                errdefer allocator.free(path);
                options.depfile_path = path;
                arg_i += value.index_increment;
                continue :next_arg;
            } else if (std.ascii.starts_with_ignore_case(arg_name, "nologo")) {
                // No-op, we don't display any 'logo' to suppress
                arg.name_offset += "nologo".len;
            } else if (std.ascii.starts_with_ignore_case(arg_name, ":debug")) {
                options.debug = true;
                arg.name_offset += ":debug".len;
            }
            // Unsupported LCX/LCE options that need a value (within the same arg only)
            else if (std.ascii.starts_with_ignore_case(arg_name, "tp:")) {
                const rest = arg.full[arg.name_offset + 3 ..];
                if (rest.len == 0) {
                    var err_details = Diagnostics.ErrorDetails{ .arg_index = arg_i, .arg_span = .{
                        .name_offset = arg.name_offset,
                        .prefix_len = arg.prefix_slice().len,
                        .value_offset = arg.name_offset + 3,
                    } };
                    var msg_writer = err_details.msg.writer(allocator);
                    try msg_writer.print("missing value for {s}{s} option", .{ arg.prefix_slice(), arg.option_without_prefix(3) });
                    try diagnostics.append(err_details);
                }
                var err_details = Diagnostics.ErrorDetails{ .type = .err, .arg_index = arg_i, .arg_span = arg.option_and_after_span() };
                var msg_writer = err_details.msg.writer(allocator);
                try msg_writer.print("the {s}{s} option is unsupported", .{ arg.prefix_slice(), arg.option_without_prefix(3) });
                try diagnostics.append(err_details);
                arg_i += 1;
                continue :next_arg;
            }
            // Unsupported LCX/LCE options that need a value
            else if (std.ascii.starts_with_ignore_case(arg_name, "tn")) {
                const value = arg.value(2, arg_i, args) catch no_value: {
                    var err_details = Diagnostics.ErrorDetails{ .arg_index = arg_i, .arg_span = arg.missing_span() };
                    var msg_writer = err_details.msg.writer(allocator);
                    try msg_writer.print("missing value after {s}{s} option", .{ arg.prefix_slice(), arg.option_without_prefix(2) });
                    try diagnostics.append(err_details);
                    // dummy zero-length slice starting where the value would have been
                    const value_start = arg.name_offset + 2;
                    break :no_value Arg.Value{ .slice = arg.full[value_start..value_start] };
                };
                var err_details = Diagnostics.ErrorDetails{ .type = .err, .arg_index = arg_i, .arg_span = arg.option_and_after_span() };
                var msg_writer = err_details.msg.writer(allocator);
                try msg_writer.print("the {s}{s} option is unsupported", .{ arg.prefix_slice(), arg.option_without_prefix(2) });
                try diagnostics.append(err_details);
                arg_i += value.index_increment;
                continue :next_arg;
            }
            // Unsupported MUI options that need a value
            else if (std.ascii.starts_with_ignore_case(arg_name, "fm") or
                std.ascii.starts_with_ignore_case(arg_name, "gn") or
                std.ascii.starts_with_ignore_case(arg_name, "g2"))
            {
                const value = arg.value(2, arg_i, args) catch no_value: {
                    var err_details = Diagnostics.ErrorDetails{ .arg_index = arg_i, .arg_span = arg.missing_span() };
                    var msg_writer = err_details.msg.writer(allocator);
                    try msg_writer.print("missing value after {s}{s} option", .{ arg.prefix_slice(), arg.option_without_prefix(2) });
                    try diagnostics.append(err_details);
                    // dummy zero-length slice starting where the value would have been
                    const value_start = arg.name_offset + 2;
                    break :no_value Arg.Value{ .slice = arg.full[value_start..value_start] };
                };
                var err_details = Diagnostics.ErrorDetails{ .type = .err, .arg_index = arg_i, .arg_span = arg.option_and_after_span() };
                var msg_writer = err_details.msg.writer(allocator);
                try msg_writer.print("the {s}{s} option is unsupported", .{ arg.prefix_slice(), arg.option_without_prefix(2) });
                try diagnostics.append(err_details);
                arg_i += value.index_increment;
                continue :next_arg;
            }
            // Unsupported MUI options that do not need a value
            else if (std.ascii.starts_with_ignore_case(arg_name, "g1")) {
                var err_details = Diagnostics.ErrorDetails{ .type = .err, .arg_index = arg_i, .arg_span = arg.option_span(2) };
                var msg_writer = err_details.msg.writer(allocator);
                try msg_writer.print("the {s}{s} option is unsupported", .{ arg.prefix_slice(), arg.option_without_prefix(2) });
                try diagnostics.append(err_details);
                arg.name_offset += 2;
            }
            // Unsupported LCX/LCE options that do not need a value
            else if (std.ascii.starts_with_ignore_case(arg_name, "tm") or
                std.ascii.starts_with_ignore_case(arg_name, "tc") or
                std.ascii.starts_with_ignore_case(arg_name, "tw") or
                std.ascii.starts_with_ignore_case(arg_name, "te") or
                std.ascii.starts_with_ignore_case(arg_name, "ti") or
                std.ascii.starts_with_ignore_case(arg_name, "ta"))
            {
                var err_details = Diagnostics.ErrorDetails{ .type = .err, .arg_index = arg_i, .arg_span = arg.option_span(2) };
                var msg_writer = err_details.msg.writer(allocator);
                try msg_writer.print("the {s}{s} option is unsupported", .{ arg.prefix_slice(), arg.option_without_prefix(2) });
                try diagnostics.append(err_details);
                arg.name_offset += 2;
            } else if (std.ascii.starts_with_ignore_case(arg_name, "fo")) {
                const value = arg.value(2, arg_i, args) catch {
                    var err_details = Diagnostics.ErrorDetails{ .arg_index = arg_i, .arg_span = arg.missing_span() };
                    var msg_writer = err_details.msg.writer(allocator);
                    try msg_writer.print("missing output path after {s}{s} option", .{ arg.prefix_slice(), arg.option_without_prefix(2) });
                    try diagnostics.append(err_details);
                    arg_i += 1;
                    break :next_arg;
                };
                output_filename_context = .{ .index = arg_i, .arg = arg, .value = value };
                output_filename = value.slice;
                arg_i += value.index_increment;
                continue :next_arg;
            } else if (std.ascii.starts_with_ignore_case(arg_name, "sl")) {
                const value = arg.value(2, arg_i, args) catch {
                    var err_details = Diagnostics.ErrorDetails{ .arg_index = arg_i, .arg_span = arg.missing_span() };
                    var msg_writer = err_details.msg.writer(allocator);
                    try msg_writer.print("missing language tag after {s}{s} option", .{ arg.prefix_slice(), arg.option_without_prefix(2) });
                    try diagnostics.append(err_details);
                    arg_i += 1;
                    break :next_arg;
                };
                const percent_str = value.slice;
                const percent: u32 = parse_percent(percent_str) catch {
                    var err_details = Diagnostics.ErrorDetails{ .arg_index = arg_i, .arg_span = value.arg_span(arg) };
                    var msg_writer = err_details.msg.writer(allocator);
                    try msg_writer.print("invalid percent format '{s}'", .{percent_str});
                    try diagnostics.append(err_details);
                    var note_details = Diagnostics.ErrorDetails{ .type = .note, .print_args = false, .arg_index = arg_i };
                    var note_writer = note_details.msg.writer(allocator);
                    try note_writer.write_all("string length percent must be an integer between 1 and 100 (inclusive)");
                    try diagnostics.append(note_details);
                    arg_i += value.index_increment;
                    continue :next_arg;
                };
                if (percent == 0 or percent > 100) {
                    var err_details = Diagnostics.ErrorDetails{ .arg_index = arg_i, .arg_span = value.arg_span(arg) };
                    var msg_writer = err_details.msg.writer(allocator);
                    try msg_writer.print("percent out of range: {} (parsed from '{s}')", .{ percent, percent_str });
                    try diagnostics.append(err_details);
                    var note_details = Diagnostics.ErrorDetails{ .type = .note, .print_args = false, .arg_index = arg_i };
                    var note_writer = note_details.msg.writer(allocator);
                    try note_writer.write_all("string length percent must be an integer between 1 and 100 (inclusive)");
                    try diagnostics.append(note_details);
                    arg_i += value.index_increment;
                    continue :next_arg;
                }
                const percent_float = @as(f32, @float_from_int(percent)) / 100;
                options.max_string_literal_codepoints = @int_from_float(percent_float * max_string_literal_length_100_percent);
                arg_i += value.index_increment;
                continue :next_arg;
            } else if (std.ascii.starts_with_ignore_case(arg_name, "ln")) {
                const value = arg.value(2, arg_i, args) catch {
                    var err_details = Diagnostics.ErrorDetails{ .arg_index = arg_i, .arg_span = arg.missing_span() };
                    var msg_writer = err_details.msg.writer(allocator);
                    try msg_writer.print("missing language tag after {s}{s} option", .{ arg.prefix_slice(), arg.option_without_prefix(2) });
                    try diagnostics.append(err_details);
                    arg_i += 1;
                    break :next_arg;
                };
                const tag = value.slice;
                options.default_language_id = lang.tag_to_int(tag) catch {
                    var err_details = Diagnostics.ErrorDetails{ .arg_index = arg_i, .arg_span = value.arg_span(arg) };
                    var msg_writer = err_details.msg.writer(allocator);
                    try msg_writer.print("invalid language tag: {s}", .{tag});
                    try diagnostics.append(err_details);
                    arg_i += value.index_increment;
                    continue :next_arg;
                };
                if (options.default_language_id.? == lang.LOCALE_CUSTOM_UNSPECIFIED) {
                    var err_details = Diagnostics.ErrorDetails{ .type = .warning, .arg_index = arg_i, .arg_span = value.arg_span(arg) };
                    var msg_writer = err_details.msg.writer(allocator);
                    try msg_writer.print("language tag '{s}' does not have an assigned ID so it will be resolved to LOCALE_CUSTOM_UNSPECIFIED (id=0x{x})", .{ tag, lang.LOCALE_CUSTOM_UNSPECIFIED });
                    try diagnostics.append(err_details);
                }
                arg_i += value.index_increment;
                continue :next_arg;
            } else if (std.ascii.starts_with_ignore_case(arg_name, "l")) {
                const value = arg.value(1, arg_i, args) catch {
                    var err_details = Diagnostics.ErrorDetails{ .arg_index = arg_i, .arg_span = arg.missing_span() };
                    var msg_writer = err_details.msg.writer(allocator);
                    try msg_writer.print("missing language ID after {s}{s} option", .{ arg.prefix_slice(), arg.option_without_prefix(1) });
                    try diagnostics.append(err_details);
                    arg_i += 1;
                    break :next_arg;
                };
                const num_str = value.slice;
                options.default_language_id = lang.parse_int(num_str) catch {
                    var err_details = Diagnostics.ErrorDetails{ .arg_index = arg_i, .arg_span = value.arg_span(arg) };
                    var msg_writer = err_details.msg.writer(allocator);
                    try msg_writer.print("invalid language ID: {s}", .{num_str});
                    try diagnostics.append(err_details);
                    arg_i += value.index_increment;
                    continue :next_arg;
                };
                arg_i += value.index_increment;
                continue :next_arg;
            } else if (std.ascii.starts_with_ignore_case(arg_name, "h") or std.mem.starts_with(u8, arg_name, "?")) {
                options.print_help_and_exit = true;
                // If there's been an error to this point, then we still want to fail
                if (diagnostics.has_error()) return error.ParseError;
                return options;
            }
            // 1 char unsupported MUI options that need a value
            else if (std.ascii.starts_with_ignore_case(arg_name, "q") or
                std.ascii.starts_with_ignore_case(arg_name, "g"))
            {
                const value = arg.value(1, arg_i, args) catch no_value: {
                    var err_details = Diagnostics.ErrorDetails{ .arg_index = arg_i, .arg_span = arg.missing_span() };
                    var msg_writer = err_details.msg.writer(allocator);
                    try msg_writer.print("missing value after {s}{s} option", .{ arg.prefix_slice(), arg.option_without_prefix(1) });
                    try diagnostics.append(err_details);
                    // dummy zero-length slice starting where the value would have been
                    const value_start = arg.name_offset + 1;
                    break :no_value Arg.Value{ .slice = arg.full[value_start..value_start] };
                };
                var err_details = Diagnostics.ErrorDetails{ .type = .err, .arg_index = arg_i, .arg_span = arg.option_and_after_span() };
                var msg_writer = err_details.msg.writer(allocator);
                try msg_writer.print("the {s}{s} option is unsupported", .{ arg.prefix_slice(), arg.option_without_prefix(1) });
                try diagnostics.append(err_details);
                arg_i += value.index_increment;
                continue :next_arg;
            }
            // Undocumented (and unsupported) options that need a value
            //  /z has to do something with font substitution
            //  /s has something to do with HWB resources being inserted into the .res
            else if (std.ascii.starts_with_ignore_case(arg_name, "z") or
                std.ascii.starts_with_ignore_case(arg_name, "s"))
            {
                const value = arg.value(1, arg_i, args) catch no_value: {
                    var err_details = Diagnostics.ErrorDetails{ .arg_index = arg_i, .arg_span = arg.missing_span() };
                    var msg_writer = err_details.msg.writer(allocator);
                    try msg_writer.print("missing value after {s}{s} option", .{ arg.prefix_slice(), arg.option_without_prefix(1) });
                    try diagnostics.append(err_details);
                    // dummy zero-length slice starting where the value would have been
                    const value_start = arg.name_offset + 1;
                    break :no_value Arg.Value{ .slice = arg.full[value_start..value_start] };
                };
                var err_details = Diagnostics.ErrorDetails{ .type = .err, .arg_index = arg_i, .arg_span = arg.option_and_after_span() };
                var msg_writer = err_details.msg.writer(allocator);
                try msg_writer.print("the {s}{s} option is unsupported", .{ arg.prefix_slice(), arg.option_without_prefix(1) });
                try diagnostics.append(err_details);
                arg_i += value.index_increment;
                continue :next_arg;
            }
            // 1 char unsupported LCX/LCE options that do not need a value
            else if (std.ascii.starts_with_ignore_case(arg_name, "t")) {
                var err_details = Diagnostics.ErrorDetails{ .type = .err, .arg_index = arg_i, .arg_span = arg.option_span(1) };
                var msg_writer = err_details.msg.writer(allocator);
                try msg_writer.print("the {s}{s} option is unsupported", .{ arg.prefix_slice(), arg.option_without_prefix(1) });
                try diagnostics.append(err_details);
                arg.name_offset += 1;
            } else if (std.ascii.starts_with_ignore_case(arg_name, "c")) {
                const value = arg.value(1, arg_i, args) catch {
                    var err_details = Diagnostics.ErrorDetails{ .arg_index = arg_i, .arg_span = arg.missing_span() };
                    var msg_writer = err_details.msg.writer(allocator);
                    try msg_writer.print("missing code page ID after {s}{s} option", .{ arg.prefix_slice(), arg.option_without_prefix(1) });
                    try diagnostics.append(err_details);
                    arg_i += 1;
                    break :next_arg;
                };
                const num_str = value.slice;
                const code_page_id = std.fmt.parse_unsigned(u16, num_str, 10) catch {
                    var err_details = Diagnostics.ErrorDetails{ .arg_index = arg_i, .arg_span = value.arg_span(arg) };
                    var msg_writer = err_details.msg.writer(allocator);
                    try msg_writer.print("invalid code page ID: {s}", .{num_str});
                    try diagnostics.append(err_details);
                    arg_i += value.index_increment;
                    continue :next_arg;
                };
                options.default_code_page = CodePage.get_by_identifier_ensure_supported(code_page_id) catch |err| switch (err) {
                    error.InvalidCodePage => {
                        var err_details = Diagnostics.ErrorDetails{ .arg_index = arg_i, .arg_span = value.arg_span(arg) };
                        var msg_writer = err_details.msg.writer(allocator);
                        try msg_writer.print("invalid or unknown code page ID: {}", .{code_page_id});
                        try diagnostics.append(err_details);
                        arg_i += value.index_increment;
                        continue :next_arg;
                    },
                    error.UnsupportedCodePage => {
                        var err_details = Diagnostics.ErrorDetails{ .arg_index = arg_i, .arg_span = value.arg_span(arg) };
                        var msg_writer = err_details.msg.writer(allocator);
                        try msg_writer.print("unsupported code page: {s} (id={})", .{
                            @tag_name(CodePage.get_by_identifier(code_page_id) catch unreachable),
                            code_page_id,
                        });
                        try diagnostics.append(err_details);
                        arg_i += value.index_increment;
                        continue :next_arg;
                    },
                };
                arg_i += value.index_increment;
                continue :next_arg;
            } else if (std.ascii.starts_with_ignore_case(arg_name, "v")) {
                options.verbose = true;
                arg.name_offset += 1;
            } else if (std.ascii.starts_with_ignore_case(arg_name, "x")) {
                options.ignore_include_env_var = true;
                arg.name_offset += 1;
            } else if (std.ascii.starts_with_ignore_case(arg_name, "p")) {
                options.preprocess = .only;
                arg.name_offset += 1;
            } else if (std.ascii.starts_with_ignore_case(arg_name, "i")) {
                const value = arg.value(1, arg_i, args) catch {
                    var err_details = Diagnostics.ErrorDetails{ .arg_index = arg_i, .arg_span = arg.missing_span() };
                    var msg_writer = err_details.msg.writer(allocator);
                    try msg_writer.print("missing include path after {s}{s} option", .{ arg.prefix_slice(), arg.option_without_prefix(1) });
                    try diagnostics.append(err_details);
                    arg_i += 1;
                    break :next_arg;
                };
                const path = value.slice;
                const duped = try allocator.dupe(u8, path);
                errdefer allocator.free(duped);
                try options.extra_include_paths.append(options.allocator, duped);
                arg_i += value.index_increment;
                continue :next_arg;
            } else if (std.ascii.starts_with_ignore_case(arg_name, "r")) {
                // From https://learn.microsoft.com/en-us/windows/win32/menurc/using-rc-the-rc-command-line-
                // "Ignored. Provided for compatibility with existing makefiles."
                arg.name_offset += 1;
            } else if (std.ascii.starts_with_ignore_case(arg_name, "n")) {
                options.null_terminate_string_table_strings = true;
                arg.name_offset += 1;
            } else if (std.ascii.starts_with_ignore_case(arg_name, "y")) {
                options.silent_duplicate_control_ids = true;
                arg.name_offset += 1;
            } else if (std.ascii.starts_with_ignore_case(arg_name, "w")) {
                options.warn_instead_of_error_on_invalid_code_page = true;
                arg.name_offset += 1;
            } else if (std.ascii.starts_with_ignore_case(arg_name, "a")) {
                // Undocumented option with unknown function
                // TODO: More investigation to figure out what it does (if anything)
                var err_details = Diagnostics.ErrorDetails{ .type = .warning, .arg_index = arg_i, .arg_span = arg.option_span(1) };
                var msg_writer = err_details.msg.writer(allocator);
                try msg_writer.print("option {s}{s} has no effect (it is undocumented and its function is unknown in the Win32 RC compiler)", .{ arg.prefix_slice(), arg.option_without_prefix(1) });
                try diagnostics.append(err_details);
                arg.name_offset += 1;
            } else if (std.ascii.starts_with_ignore_case(arg_name, "d")) {
                const value = arg.value(1, arg_i, args) catch {
                    var err_details = Diagnostics.ErrorDetails{ .arg_index = arg_i, .arg_span = arg.missing_span() };
                    var msg_writer = err_details.msg.writer(allocator);
                    try msg_writer.print("missing symbol to define after {s}{s} option", .{ arg.prefix_slice(), arg.option_without_prefix(1) });
                    try diagnostics.append(err_details);
                    arg_i += 1;
                    break :next_arg;
                };
                var tokenizer = std.mem.tokenize(u8, value.slice, "=");
                // guaranteed to exist since an empty value.slice would invoke
                // the 'missing symbol to define' branch above
                const symbol = tokenizer.next().?;
                const symbol_value = tokenizer.next() orelse "1";

                if (is_valid_identifier(symbol)) {
                    try options.define(symbol, symbol_value);
                } else {
                    var err_details = Diagnostics.ErrorDetails{ .type = .warning, .arg_index = arg_i, .arg_span = value.arg_span(arg) };
                    var msg_writer = err_details.msg.writer(allocator);
                    try msg_writer.print("symbol \"{s}\" is not a valid identifier and therefore cannot be defined", .{symbol});
                    try diagnostics.append(err_details);
                }
                arg_i += value.index_increment;
                continue :next_arg;
            } else if (std.ascii.starts_with_ignore_case(arg_name, "u")) {
                const value = arg.value(1, arg_i, args) catch {
                    var err_details = Diagnostics.ErrorDetails{ .arg_index = arg_i, .arg_span = arg.missing_span() };
                    var msg_writer = err_details.msg.writer(allocator);
                    try msg_writer.print("missing symbol to undefine after {s}{s} option", .{ arg.prefix_slice(), arg.option_without_prefix(1) });
                    try diagnostics.append(err_details);
                    arg_i += 1;
                    break :next_arg;
                };
                const symbol = value.slice;
                if (is_valid_identifier(symbol)) {
                    try options.undefine(symbol);
                } else {
                    var err_details = Diagnostics.ErrorDetails{ .type = .warning, .arg_index = arg_i, .arg_span = value.arg_span(arg) };
                    var msg_writer = err_details.msg.writer(allocator);
                    try msg_writer.print("symbol \"{s}\" is not a valid identifier and therefore cannot be undefined", .{symbol});
                    try diagnostics.append(err_details);
                }
                arg_i += value.index_increment;
                continue :next_arg;
            } else {
                var err_details = Diagnostics.ErrorDetails{ .arg_index = arg_i, .arg_span = arg.option_and_after_span() };
                var msg_writer = err_details.msg.writer(allocator);
                try msg_writer.print("invalid option: {s}{s}", .{ arg.prefix_slice(), arg.name() });
                try diagnostics.append(err_details);
                arg_i += 1;
                continue :next_arg;
            }
        } else {
            // The while loop exited via its conditional, meaning we are done with
            // the current arg and can move on the the next
            arg_i += 1;
            continue;
        }
    }

    const positionals = args[arg_i..];

    if (positionals.len < 1) {
        var err_details = Diagnostics.ErrorDetails{ .print_args = false, .arg_index = arg_i };
        var msg_writer = err_details.msg.writer(allocator);
        try msg_writer.write_all("missing input filename");
        try diagnostics.append(err_details);

        const last_arg = args[args.len - 1];
        if (arg_i > 0 and last_arg.len > 0 and last_arg[0] == '/' and std.ascii.ends_with_ignore_case(last_arg, ".rc")) {
            var note_details = Diagnostics.ErrorDetails{ .type = .note, .print_args = true, .arg_index = arg_i - 1 };
            var note_writer = note_details.msg.writer(allocator);
            try note_writer.write_all("if this argument was intended to be the input filename, then -- should be specified in front of it to exclude it from option parsing");
            try diagnostics.append(note_details);
        }

        // This is a fatal enough problem to justify an early return, since
        // things after this rely on the value of the input filename.
        return error.ParseError;
    }
    options.input_filename = try allocator.dupe(u8, positionals[0]);

    if (positionals.len > 1) {
        if (output_filename != null) {
            var err_details = Diagnostics.ErrorDetails{ .arg_index = arg_i + 1 };
            var msg_writer = err_details.msg.writer(allocator);
            try msg_writer.write_all("output filename already specified");
            try diagnostics.append(err_details);
            var note_details = Diagnostics.ErrorDetails{
                .type = .note,
                .arg_index = output_filename_context.value.index(output_filename_context.index),
                .arg_span = output_filename_context.value.arg_span(output_filename_context.arg),
            };
            var note_writer = note_details.msg.writer(allocator);
            try note_writer.write_all("output filename previously specified here");
            try diagnostics.append(note_details);
        } else {
            output_filename = positionals[1];
        }
    }
    if (output_filename == null) {
        var buf = std.ArrayList(u8).init(allocator);
        errdefer buf.deinit();

        if (std.fs.path.dirname(options.input_filename)) |dirname| {
            var end_pos = dirname.len;
            // We want to ensure that we write a path separator at the end, so if the dirname
            // doesn't end with a path sep then include the char after the dirname
            // which must be a path sep.
            if (!std.fs.path.is_sep(dirname[dirname.len - 1])) end_pos += 1;
            try buf.append_slice(options.input_filename[0..end_pos]);
        }
        try buf.append_slice(std.fs.path.stem(options.input_filename));
        if (options.preprocess == .only) {
            try buf.append_slice(".rcpp");
        } else {
            try buf.append_slice(".res");
        }

        options.output_filename = try buf.to_owned_slice();
    } else {
        options.output_filename = try allocator.dupe(u8, output_filename.?);
    }

    if (diagnostics.has_error()) {
        return error.ParseError;
    }

    return options;
}

/// Returns true if the str is a valid C identifier for use in a #define/#undef macro
pub fn is_valid_identifier(str: []const u8) bool {
    for (str, 0..) |c, i| switch (c) {
        '0'...'9' => if (i == 0) return false,
        'a'...'z', 'A'...'Z', '_' => {},
        else => return false,
    };
    return true;
}

/// This function is specific to how the Win32 RC command line interprets
/// max string literal length percent.
/// - Wraps on overflow of u32
/// - Stops parsing on any invalid hexadecimal digits
/// - Errors if a digit is not the first char
/// - `-` (negative) prefix is allowed
pub fn parse_percent(str: []const u8) error{InvalidFormat}!u32 {
    var result: u32 = 0;
    const radix: u8 = 10;
    var buf = str;

    const Prefix = enum { none, minus };
    var prefix: Prefix = .none;
    switch (buf[0]) {
        '-' => {
            prefix = .minus;
            buf = buf[1..];
        },
        else => {},
    }

    for (buf, 0..) |c, i| {
        const digit = switch (c) {
            // On invalid digit for the radix, just stop parsing but don't fail
            '0'...'9' => std.fmt.char_to_digit(c, radix) catch break,
            else => {
                // First digit must be valid
                if (i == 0) {
                    return error.InvalidFormat;
                }
                break;
            },
        };

        if (result != 0) {
            result *%= radix;
        }
        result +%= digit;
    }

    switch (prefix) {
        .none => {},
        .minus => result = 0 -% result,
    }

    return result;
}

test parse_percent {
    try std.testing.expect_equal(@as(u32, 16), try parse_percent("16"));
    try std.testing.expect_equal(@as(u32, 0), try parse_percent("0x1A"));
    try std.testing.expect_equal(@as(u32, 0x1), try parse_percent("1zzzz"));
    try std.testing.expect_equal(@as(u32, 0xffffffff), try parse_percent("-1"));
    try std.testing.expect_equal(@as(u32, 0xfffffff0), try parse_percent("-16"));
    try std.testing.expect_equal(@as(u32, 1), try parse_percent("4294967297"));
    try std.testing.expect_error(error.InvalidFormat, parse_percent("--1"));
    try std.testing.expect_error(error.InvalidFormat, parse_percent("ha"));
    try std.testing.expect_error(error.InvalidFormat, parse_percent("¹"));
    try std.testing.expect_error(error.InvalidFormat, parse_percent("~1"));
}

pub fn render_error_message(writer: anytype, config: std.io.tty.Config, err_details: Diagnostics.ErrorDetails, args: []const []const u8) !void {
    try config.set_color(writer, .dim);
    try writer.write_all("<cli>");
    try config.set_color(writer, .reset);
    try config.set_color(writer, .bold);
    try writer.write_all(": ");
    switch (err_details.type) {
        .err => {
            try config.set_color(writer, .red);
            try writer.write_all("error: ");
        },
        .warning => {
            try config.set_color(writer, .yellow);
            try writer.write_all("warning: ");
        },
        .note => {
            try config.set_color(writer, .cyan);
            try writer.write_all("note: ");
        },
    }
    try config.set_color(writer, .reset);
    try config.set_color(writer, .bold);
    try writer.write_all(err_details.msg.items);
    try writer.write_byte('\n');
    try config.set_color(writer, .reset);

    if (!err_details.print_args) {
        try writer.write_byte('\n');
        return;
    }

    try config.set_color(writer, .dim);
    const prefix = " ... ";
    try writer.write_all(prefix);
    try config.set_color(writer, .reset);

    const arg_with_name = args[err_details.arg_index];
    const prefix_slice = arg_with_name[0..err_details.arg_span.prefix_len];
    const before_name_slice = arg_with_name[err_details.arg_span.prefix_len..err_details.arg_span.name_offset];
    var name_slice = arg_with_name[err_details.arg_span.name_offset..];
    if (err_details.arg_span.name_len > 0) name_slice.len = err_details.arg_span.name_len;
    const after_name_slice = arg_with_name[err_details.arg_span.name_offset + name_slice.len ..];

    try writer.write_all(prefix_slice);
    if (before_name_slice.len > 0) {
        try config.set_color(writer, .dim);
        try writer.write_all(before_name_slice);
        try config.set_color(writer, .reset);
    }
    try writer.write_all(name_slice);
    if (after_name_slice.len > 0) {
        try config.set_color(writer, .dim);
        try writer.write_all(after_name_slice);
        try config.set_color(writer, .reset);
    }

    var next_arg_len: usize = 0;
    if (err_details.arg_span.point_at_next_arg and err_details.arg_index + 1 < args.len) {
        const next_arg = args[err_details.arg_index + 1];
        try writer.write_byte(' ');
        try writer.write_all(next_arg);
        next_arg_len = next_arg.len;
    }

    const last_shown_arg_index = if (err_details.arg_span.point_at_next_arg) err_details.arg_index + 1 else err_details.arg_index;
    if (last_shown_arg_index + 1 < args.len) {
        // special case for when pointing to a missing value within the same arg
        // as the name
        if (err_details.arg_span.value_offset >= arg_with_name.len) {
            try writer.write_byte(' ');
        }
        try config.set_color(writer, .dim);
        try writer.write_all(" ...");
        try config.set_color(writer, .reset);
    }
    try writer.write_byte('\n');

    try config.set_color(writer, .green);
    try writer.write_byte_ntimes(' ', prefix.len);
    // Special case for when the option is *only* a prefix (e.g. invalid option: -)
    if (err_details.arg_span.prefix_len == arg_with_name.len) {
        try writer.write_byte_ntimes('^', err_details.arg_span.prefix_len);
    } else {
        try writer.write_byte_ntimes('~', err_details.arg_span.prefix_len);
        try writer.write_byte_ntimes(' ', err_details.arg_span.name_offset - err_details.arg_span.prefix_len);
        if (!err_details.arg_span.point_at_next_arg and err_details.arg_span.value_offset == 0) {
            try writer.write_byte('^');
            try writer.write_byte_ntimes('~', name_slice.len - 1);
        } else if (err_details.arg_span.value_offset > 0) {
            try writer.write_byte_ntimes('~', err_details.arg_span.value_offset - err_details.arg_span.name_offset);
            try writer.write_byte('^');
            if (err_details.arg_span.value_offset < arg_with_name.len) {
                try writer.write_byte_ntimes('~', arg_with_name.len - err_details.arg_span.value_offset - 1);
            }
        } else if (err_details.arg_span.point_at_next_arg) {
            try writer.write_byte_ntimes('~', arg_with_name.len - err_details.arg_span.name_offset + 1);
            try writer.write_byte('^');
            if (next_arg_len > 0) {
                try writer.write_byte_ntimes('~', next_arg_len - 1);
            }
        }
    }
    try writer.write_byte('\n');
    try config.set_color(writer, .reset);
}

fn test_parse(args: []const []const u8) !Options {
    return (try test_parse_output(args, "")).?;
}

fn test_parse_warning(args: []const []const u8, expected_output: []const u8) !Options {
    return (try test_parse_output(args, expected_output)).?;
}

fn test_parse_error(args: []const []const u8, expected_output: []const u8) !void {
    var maybe_options = try test_parse_output(args, expected_output);
    if (maybe_options != null) {
        std.debug.print("expected error, got options: {}\n", .{maybe_options.?});
        maybe_options.?.deinit();
        return error.TestExpectedError;
    }
}

fn test_parse_output(args: []const []const u8, expected_output: []const u8) !?Options {
    var diagnostics = Diagnostics.init(std.testing.allocator);
    defer diagnostics.deinit();

    var output = std.ArrayList(u8).init(std.testing.allocator);
    defer output.deinit();

    var options = parse(std.testing.allocator, args, &diagnostics) catch |err| switch (err) {
        error.ParseError => {
            try diagnostics.render_to_writer(args, output.writer(), .no_color);
            try std.testing.expect_equal_strings(expected_output, output.items);
            return null;
        },
        else => |e| return e,
    };
    errdefer options.deinit();

    try diagnostics.render_to_writer(args, output.writer(), .no_color);
    try std.testing.expect_equal_strings(expected_output, output.items);
    return options;
}

test "parse errors: basic" {
    try test_parse_error(&.{"/"},
        \\<cli>: error: invalid option: /
        \\ ... /
        \\     ^
        \\<cli>: error: missing input filename
        \\
        \\
    );
    try test_parse_error(&.{"/ln"},
        \\<cli>: error: missing language tag after /ln option
        \\ ... /ln
        \\     ~~~~^
        \\<cli>: error: missing input filename
        \\
        \\
    );
    try test_parse_error(&.{"-vln"},
        \\<cli>: error: missing language tag after -ln option
        \\ ... -vln
        \\     ~ ~~~^
        \\<cli>: error: missing input filename
        \\
        \\
    );
    try test_parse_error(&.{"/_not-an-option"},
        \\<cli>: error: invalid option: /_not-an-option
        \\ ... /_not-an-option
        \\     ~^~~~~~~~~~~~~~
        \\<cli>: error: missing input filename
        \\
        \\
    );
    try test_parse_error(&.{"-_not-an-option"},
        \\<cli>: error: invalid option: -_not-an-option
        \\ ... -_not-an-option
        \\     ~^~~~~~~~~~~~~~
        \\<cli>: error: missing input filename
        \\
        \\
    );
    try test_parse_error(&.{"--_not-an-option"},
        \\<cli>: error: invalid option: --_not-an-option
        \\ ... --_not-an-option
        \\     ~~^~~~~~~~~~~~~~
        \\<cli>: error: missing input filename
        \\
        \\
    );
    try test_parse_error(&.{"/v_not-an-option"},
        \\<cli>: error: invalid option: /_not-an-option
        \\ ... /v_not-an-option
        \\     ~ ^~~~~~~~~~~~~~
        \\<cli>: error: missing input filename
        \\
        \\
    );
    try test_parse_error(&.{"-v_not-an-option"},
        \\<cli>: error: invalid option: -_not-an-option
        \\ ... -v_not-an-option
        \\     ~ ^~~~~~~~~~~~~~
        \\<cli>: error: missing input filename
        \\
        \\
    );
    try test_parse_error(&.{"--v_not-an-option"},
        \\<cli>: error: invalid option: --_not-an-option
        \\ ... --v_not-an-option
        \\     ~~ ^~~~~~~~~~~~~~
        \\<cli>: error: missing input filename
        \\
        \\
    );
    try test_parse_error(&.{"/some/absolute/path/parsed/as/an/option.rc"},
        \\<cli>: error: the /s option is unsupported
        \\ ... /some/absolute/path/parsed/as/an/option.rc
        \\     ~^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        \\<cli>: error: missing input filename
        \\
        \\<cli>: note: if this argument was intended to be the input filename, then -- should be specified in front of it to exclude it from option parsing
        \\ ... /some/absolute/path/parsed/as/an/option.rc
        \\     ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        \\
    );
}

test "parse errors: /ln" {
    try test_parse_error(&.{ "/ln", "invalid", "foo.rc" },
        \\<cli>: error: invalid language tag: invalid
        \\ ... /ln invalid ...
        \\     ~~~~^~~~~~~
        \\
    );
    try test_parse_error(&.{ "/lninvalid", "foo.rc" },
        \\<cli>: error: invalid language tag: invalid
        \\ ... /lninvalid ...
        \\     ~~~^~~~~~~
        \\
    );
}

test "parse: options" {
    {
        var options = try test_parse(&.{ "/v", "foo.rc" });
        defer options.deinit();

        try std.testing.expect_equal(true, options.verbose);
        try std.testing.expect_equal_strings("foo.rc", options.input_filename);
        try std.testing.expect_equal_strings("foo.res", options.output_filename);
    }
    {
        var options = try test_parse(&.{ "/vx", "foo.rc" });
        defer options.deinit();

        try std.testing.expect_equal(true, options.verbose);
        try std.testing.expect_equal(true, options.ignore_include_env_var);
        try std.testing.expect_equal_strings("foo.rc", options.input_filename);
        try std.testing.expect_equal_strings("foo.res", options.output_filename);
    }
    {
        var options = try test_parse(&.{ "/xv", "foo.rc" });
        defer options.deinit();

        try std.testing.expect_equal(true, options.verbose);
        try std.testing.expect_equal(true, options.ignore_include_env_var);
        try std.testing.expect_equal_strings("foo.rc", options.input_filename);
        try std.testing.expect_equal_strings("foo.res", options.output_filename);
    }
    {
        var options = try test_parse(&.{ "/xvFObar.res", "foo.rc" });
        defer options.deinit();

        try std.testing.expect_equal(true, options.verbose);
        try std.testing.expect_equal(true, options.ignore_include_env_var);
        try std.testing.expect_equal_strings("foo.rc", options.input_filename);
        try std.testing.expect_equal_strings("bar.res", options.output_filename);
    }
}

test "parse: define and undefine" {
    {
        var options = try test_parse(&.{ "/dfoo", "foo.rc" });
        defer options.deinit();

        const action = options.symbols.get("foo").?;
        try std.testing.expect_equal_strings("1", action.define);
    }
    {
        var options = try test_parse(&.{ "/dfoo=bar", "/dfoo=baz", "foo.rc" });
        defer options.deinit();

        const action = options.symbols.get("foo").?;
        try std.testing.expect_equal_strings("baz", action.define);
    }
    {
        var options = try test_parse(&.{ "/ufoo", "foo.rc" });
        defer options.deinit();

        const action = options.symbols.get("foo").?;
        try std.testing.expect_equal(Options.SymbolAction.undefine, action);
    }
    {
        // Once undefined, future defines are ignored
        var options = try test_parse(&.{ "/ufoo", "/dfoo", "foo.rc" });
        defer options.deinit();

        const action = options.symbols.get("foo").?;
        try std.testing.expect_equal(Options.SymbolAction.undefine, action);
    }
    {
        // Undefined always takes precedence
        var options = try test_parse(&.{ "/dfoo", "/ufoo", "/dfoo", "foo.rc" });
        defer options.deinit();

        const action = options.symbols.get("foo").?;
        try std.testing.expect_equal(Options.SymbolAction.undefine, action);
    }
    {
        // Warn + ignore invalid identifiers
        var options = try test_parse_warning(
            &.{ "/dfoo bar", "/u", "0leadingdigit", "foo.rc" },
            \\<cli>: warning: symbol "foo bar" is not a valid identifier and therefore cannot be defined
            \\ ... /dfoo bar ...
            \\     ~~^~~~~~~
            \\<cli>: warning: symbol "0leadingdigit" is not a valid identifier and therefore cannot be undefined
            \\ ... /u 0leadingdigit ...
            \\     ~~~^~~~~~~~~~~~~
            \\
            ,
        );
        defer options.deinit();

        try std.testing.expect_equal(@as(usize, 0), options.symbols.count());
    }
}

test "parse: /sl" {
    try test_parse_error(&.{ "/sl", "0", "foo.rc" },
        \\<cli>: error: percent out of range: 0 (parsed from '0')
        \\ ... /sl 0 ...
        \\     ~~~~^
        \\<cli>: note: string length percent must be an integer between 1 and 100 (inclusive)
        \\
        \\
    );
    try test_parse_error(&.{ "/sl", "abcd", "foo.rc" },
        \\<cli>: error: invalid percent format 'abcd'
        \\ ... /sl abcd ...
        \\     ~~~~^~~~
        \\<cli>: note: string length percent must be an integer between 1 and 100 (inclusive)
        \\
        \\
    );
    {
        var options = try test_parse(&.{"foo.rc"});
        defer options.deinit();

        try std.testing.expect_equal(@as(u15, lex.default_max_string_literal_codepoints), options.max_string_literal_codepoints);
    }
    {
        var options = try test_parse(&.{ "/sl100", "foo.rc" });
        defer options.deinit();

        try std.testing.expect_equal(@as(u15, max_string_literal_length_100_percent), options.max_string_literal_codepoints);
    }
    {
        var options = try test_parse(&.{ "-SL33", "foo.rc" });
        defer options.deinit();

        try std.testing.expect_equal(@as(u15, 2703), options.max_string_literal_codepoints);
    }
    {
        var options = try test_parse(&.{ "/sl15", "foo.rc" });
        defer options.deinit();

        try std.testing.expect_equal(@as(u15, 1228), options.max_string_literal_codepoints);
    }
}

test "parse: unsupported MUI-related options" {
    try test_parse_error(&.{ "/q", "blah", "/g1", "-G2", "blah", "/fm", "blah", "/g", "blah", "foo.rc" },
        \\<cli>: error: the /q option is unsupported
        \\ ... /q ...
        \\     ~^
        \\<cli>: error: the /g1 option is unsupported
        \\ ... /g1 ...
        \\     ~^~
        \\<cli>: error: the -G2 option is unsupported
        \\ ... -G2 ...
        \\     ~^~
        \\<cli>: error: the /fm option is unsupported
        \\ ... /fm ...
        \\     ~^~
        \\<cli>: error: the /g option is unsupported
        \\ ... /g ...
        \\     ~^
        \\
    );
}

test "parse: unsupported LCX/LCE-related options" {
    try test_parse_error(&.{ "/t", "/tp:", "/tp:blah", "/tm", "/tc", "/tw", "-TEti", "/ta", "/tn", "blah", "foo.rc" },
        \\<cli>: error: the /t option is unsupported
        \\ ... /t ...
        \\     ~^
        \\<cli>: error: missing value for /tp: option
        \\ ... /tp:  ...
        \\     ~~~~^
        \\<cli>: error: the /tp: option is unsupported
        \\ ... /tp: ...
        \\     ~^~~
        \\<cli>: error: the /tp: option is unsupported
        \\ ... /tp:blah ...
        \\     ~^~~~~~~
        \\<cli>: error: the /tm option is unsupported
        \\ ... /tm ...
        \\     ~^~
        \\<cli>: error: the /tc option is unsupported
        \\ ... /tc ...
        \\     ~^~
        \\<cli>: error: the /tw option is unsupported
        \\ ... /tw ...
        \\     ~^~
        \\<cli>: error: the -TE option is unsupported
        \\ ... -TEti ...
        \\     ~^~
        \\<cli>: error: the -ti option is unsupported
        \\ ... -TEti ...
        \\     ~  ^~
        \\<cli>: error: the /ta option is unsupported
        \\ ... /ta ...
        \\     ~^~
        \\<cli>: error: the /tn option is unsupported
        \\ ... /tn ...
        \\     ~^~
        \\
    );
}

test "maybe_append_rc" {
    var tmp = std.testing.tmp_dir(.{});
    defer tmp.cleanup();

    var options = try test_parse(&.{"foo"});
    defer options.deinit();
    try std.testing.expect_equal_strings("foo", options.input_filename);

    // Create the file so that it's found. In this scenario, .rc should not get
    // appended.
    var file = try tmp.dir.create_file("foo", .{});
    file.close();
    try options.maybe_append_rc(tmp.dir);
    try std.testing.expect_equal_strings("foo", options.input_filename);

    // Now delete the file and try again. Since the verbatim name is no longer found
    // and the input filename does not have an extension, .rc should get appended.
    try tmp.dir.delete_file("foo");
    try options.maybe_append_rc(tmp.dir);
    try std.testing.expect_equal_strings("foo.rc", options.input_filename);
}
