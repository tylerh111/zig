//! String formatting and parsing.

const std = @import("std.zig");
const builtin = @import("builtin");

const io = std.io;
const math = std.math;
const assert = std.debug.assert;
const mem = std.mem;
const unicode = std.unicode;
const meta = std.meta;
const lossy_cast = math.lossy_cast;
const expect_fmt = std.testing.expect_fmt;

pub const default_max_depth = 3;

pub const Alignment = enum {
    left,
    center,
    right,
};

pub const FormatOptions = struct {
    precision: ?usize = null,
    width: ?usize = null,
    alignment: Alignment = .right,
    fill: u21 = ' ',
};

/// Renders fmt string with args, calling `writer` with slices of bytes.
/// If `writer` returns an error, the error is returned from `format` and
/// `writer` is not called again.
///
/// The format string must be comptime-known and may contain placeholders following
/// this format:
/// `{[argument][specifier]:[fill][alignment][width].[precision]}`
///
/// Above, each word including its surrounding [ and ] is a parameter which you have to replace with something:
///
/// - *argument* is either the numeric index or the field name of the argument that should be inserted
///   - when using a field name, you are required to enclose the field name (an identifier) in square
///     brackets, e.g. {[score]...} as opposed to the numeric index form which can be written e.g. {2...}
/// - *specifier* is a type-dependent formatting option that determines how a type should formatted (see below)
/// - *fill* is a single unicode codepoint which is used to pad the formatted text
/// - *alignment* is one of the three bytes '<', '^', or '>' to make the text left-, center-, or right-aligned, respectively
/// - *width* is the total width of the field in unicode codepoints
/// - *precision* specifies how many decimals a formatted number should have
///
/// Note that most of the parameters are optional and may be omitted. Also you can leave out separators like `:` and `.` when
/// all parameters after the separator are omitted.
/// Only exception is the *fill* parameter. If *fill* is required, one has to specify *alignment* as well, as otherwise
/// the digits after `:` is interpreted as *width*, not *fill*.
///
/// The *specifier* has several options for types:
/// - `x` and `X`: output numeric value in hexadecimal notation
/// - `s`:
///   - for pointer-to-many and C pointers of u8, print as a C-string using zero-termination
///   - for slices of u8, print the entire slice as a string without zero-termination
/// - `e`: output floating point value in scientific notation
/// - `d`: output numeric value in decimal notation
/// - `b`: output integer value in binary notation
/// - `o`: output integer value in octal notation
/// - `c`: output integer as an ASCII character. Integer type must have 8 bits at max.
/// - `u`: output integer as an UTF-8 sequence. Integer type must have 21 bits at max.
/// - `?`: output optional value as either the unwrapped value, or `null`; may be followed by a format specifier for the underlying value.
/// - `!`: output error union value as either the unwrapped value, or the formatted error value; may be followed by a format specifier for the underlying value.
/// - `*`: output the address of the value instead of the value itself.
/// - `any`: output a value of any type using its default format.
///
/// If a formatted user type contains a function of the type
/// ```
/// pub fn format(value: ?, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void
/// ```
/// with `?` being the type formatted, this function will be called instead of the default implementation.
/// This allows user types to be formatted in a logical manner instead of dumping all fields of the type.
///
/// A user type may be a `struct`, `vector`, `union` or `enum` type.
///
/// To print literal curly braces, escape them by writing them twice, e.g. `{{` or `}}`.
pub fn format(
    writer: anytype,
    comptime fmt: []const u8,
    args: anytype,
) !void {
    const ArgsType = @TypeOf(args);
    const args_type_info = @typeInfo(ArgsType);
    if (args_type_info != .Struct) {
        @compile_error("expected tuple or struct argument, found " ++ @type_name(ArgsType));
    }

    const fields_info = args_type_info.Struct.fields;
    if (fields_info.len > max_format_args) {
        @compile_error("32 arguments max are supported per format call");
    }

    @setEvalBranchQuota(2000000);
    comptime var arg_state: ArgState = .{ .args_len = fields_info.len };
    comptime var i = 0;
    inline while (i < fmt.len) {
        const start_index = i;

        inline while (i < fmt.len) : (i += 1) {
            switch (fmt[i]) {
                '{', '}' => break,
                else => {},
            }
        }

        comptime var end_index = i;
        comptime var unescape_brace = false;

        // Handle {{ and }}, those are un-escaped as single braces
        if (i + 1 < fmt.len and fmt[i + 1] == fmt[i]) {
            unescape_brace = true;
            // Make the first brace part of the literal...
            end_index += 1;
            // ...and skip both
            i += 2;
        }

        // Write out the literal
        if (start_index != end_index) {
            try writer.write_all(fmt[start_index..end_index]);
        }

        // We've already skipped the other brace, restart the loop
        if (unescape_brace) continue;

        if (i >= fmt.len) break;

        if (fmt[i] == '}') {
            @compile_error("missing opening {");
        }

        // Get past the {
        comptime assert(fmt[i] == '{');
        i += 1;

        const fmt_begin = i;
        // Find the closing brace
        inline while (i < fmt.len and fmt[i] != '}') : (i += 1) {}
        const fmt_end = i;

        if (i >= fmt.len) {
            @compile_error("missing closing }");
        }

        // Get past the }
        comptime assert(fmt[i] == '}');
        i += 1;

        const placeholder = comptime Placeholder.parse(fmt[fmt_begin..fmt_end].*);
        const arg_pos = comptime switch (placeholder.arg) {
            .none => null,
            .number => |pos| pos,
            .named => |arg_name| meta.field_index(ArgsType, arg_name) orelse
                @compile_error("no argument with name '" ++ arg_name ++ "'"),
        };

        const width = switch (placeholder.width) {
            .none => null,
            .number => |v| v,
            .named => |arg_name| blk: {
                const arg_i = comptime meta.field_index(ArgsType, arg_name) orelse
                    @compile_error("no argument with name '" ++ arg_name ++ "'");
                _ = comptime arg_state.next_arg(arg_i) orelse @compile_error("too few arguments");
                break :blk @field(args, arg_name);
            },
        };

        const precision = switch (placeholder.precision) {
            .none => null,
            .number => |v| v,
            .named => |arg_name| blk: {
                const arg_i = comptime meta.field_index(ArgsType, arg_name) orelse
                    @compile_error("no argument with name '" ++ arg_name ++ "'");
                _ = comptime arg_state.next_arg(arg_i) orelse @compile_error("too few arguments");
                break :blk @field(args, arg_name);
            },
        };

        const arg_to_print = comptime arg_state.next_arg(arg_pos) orelse
            @compile_error("too few arguments");

        try format_type(
            @field(args, fields_info[arg_to_print].name),
            placeholder.specifier_arg,
            FormatOptions{
                .fill = placeholder.fill,
                .alignment = placeholder.alignment,
                .width = width,
                .precision = precision,
            },
            writer,
            std.options.fmt_max_depth,
        );
    }

    if (comptime arg_state.has_unused_args()) {
        const missing_count = arg_state.args_len - @pop_count(arg_state.used_args);
        switch (missing_count) {
            0 => unreachable,
            1 => @compile_error("unused argument in '" ++ fmt ++ "'"),
            else => @compile_error(comptime_print("{d}", .{missing_count}) ++ " unused arguments in '" ++ fmt ++ "'"),
        }
    }
}

fn cache_string(str: anytype) []const u8 {
    return &str;
}

pub const Placeholder = struct {
    specifier_arg: []const u8,
    fill: u21,
    alignment: Alignment,
    arg: Specifier,
    width: Specifier,
    precision: Specifier,

    pub fn parse(comptime str: anytype) Placeholder {
        const view = std.unicode.Utf8View.init_comptime(&str);
        comptime var parser = Parser{
            .buf = &str,
            .iter = view.iterator(),
        };

        // Parse the positional argument number
        const arg = comptime parser.specifier() catch |err|
            @compile_error(@errorName(err));

        // Parse the format specifier
        const specifier_arg = comptime parser.until(':');

        // Skip the colon, if present
        if (comptime parser.char()) |ch| {
            if (ch != ':') {
                @compile_error("expected : or }, found '" ++ unicode.utf8_encode_comptime(ch) ++ "'");
            }
        }

        // Parse the fill character
        // The fill parameter requires the alignment parameter to be specified
        // too
        const fill = comptime if (parser.peek(1)) |ch|
            switch (ch) {
                '<', '^', '>' => parser.char().?,
                else => ' ',
            }
        else
            ' ';

        // Parse the alignment parameter
        const alignment: Alignment = comptime if (parser.peek(0)) |ch| init: {
            switch (ch) {
                '<', '^', '>' => _ = parser.char(),
                else => {},
            }
            break :init switch (ch) {
                '<' => .left,
                '^' => .center,
                else => .right,
            };
        } else .right;

        // Parse the width parameter
        const width = comptime parser.specifier() catch |err|
            @compile_error(@errorName(err));

        // Skip the dot, if present
        if (comptime parser.char()) |ch| {
            if (ch != '.') {
                @compile_error("expected . or }, found '" ++ unicode.utf8_encode_comptime(ch) ++ "'");
            }
        }

        // Parse the precision parameter
        const precision = comptime parser.specifier() catch |err|
            @compile_error(@errorName(err));

        if (comptime parser.char()) |ch| {
            @compile_error("extraneous trailing character '" ++ unicode.utf8_encode_comptime(ch) ++ "'");
        }

        return Placeholder{
            .specifier_arg = cache_string(specifier_arg[0..specifier_arg.len].*),
            .fill = fill,
            .alignment = alignment,
            .arg = arg,
            .width = width,
            .precision = precision,
        };
    }
};

pub const Specifier = union(enum) {
    none,
    number: usize,
    named: []const u8,
};

pub const Parser = struct {
    buf: []const u8,
    pos: usize = 0,
    iter: std.unicode.Utf8Iterator = undefined,

    // Returns a decimal number or null if the current character is not a
    // digit
    pub fn number(self: *@This()) ?usize {
        var r: ?usize = null;

        while (self.peek(0)) |code_point| {
            switch (code_point) {
                '0'...'9' => {
                    if (r == null) r = 0;
                    r.? *= 10;
                    r.? += code_point - '0';
                },
                else => break,
            }
            _ = self.iter.next_codepoint();
        }

        return r;
    }

    // Returns a substring of the input starting from the current position
    // and ending where `ch` is found or until the end if not found
    pub fn until(self: *@This(), ch: u21) []const u8 {
        var result: []const u8 = &[_]u8{};
        while (self.peek(0)) |code_point| {
            if (code_point == ch)
                break;
            result = result ++ (self.iter.next_codepoint_slice() orelse &[_]u8{});
        }
        return result;
    }

    // Returns one character, if available
    pub fn char(self: *@This()) ?u21 {
        if (self.iter.next_codepoint()) |code_point| {
            return code_point;
        }
        return null;
    }

    pub fn maybe(self: *@This(), val: u21) bool {
        if (self.peek(0) == val) {
            _ = self.iter.next_codepoint();
            return true;
        }
        return false;
    }

    // Returns a decimal number or null if the current character is not a
    // digit
    pub fn specifier(self: *@This()) !Specifier {
        if (self.maybe('[')) {
            const arg_name = self.until(']');

            if (!self.maybe(']'))
                return @field(anyerror, "Expected closing ]");

            return Specifier{ .named = arg_name };
        }
        if (self.number()) |i|
            return Specifier{ .number = i };

        return Specifier{ .none = {} };
    }

    // Returns the n-th next character or null if that's past the end
    pub fn peek(self: *@This(), n: usize) ?u21 {
        const original_i = self.iter.i;
        defer self.iter.i = original_i;

        var i = 0;
        var code_point: ?u21 = null;
        while (i <= n) : (i += 1) {
            code_point = self.iter.next_codepoint();
            if (code_point == null) return null;
        }
        return code_point;
    }
};

pub const ArgSetType = u32;
const max_format_args = @typeInfo(ArgSetType).Int.bits;

pub const ArgState = struct {
    next_arg: usize = 0,
    used_args: ArgSetType = 0,
    args_len: usize,

    pub fn has_unused_args(self: *@This()) bool {
        return @pop_count(self.used_args) != self.args_len;
    }

    pub fn next_arg(self: *@This(), arg_index: ?usize) ?usize {
        const next_index = arg_index orelse init: {
            const arg = self.next_arg;
            self.next_arg += 1;
            break :init arg;
        };

        if (next_index >= self.args_len) {
            return null;
        }

        // Mark this argument as used
        self.used_args |= @as(ArgSetType, 1) << @as(u5, @int_cast(next_index));
        return next_index;
    }
};

pub fn format_address(value: anytype, options: FormatOptions, writer: anytype) @TypeOf(writer).Error!void {
    _ = options;
    const T = @TypeOf(value);

    switch (@typeInfo(T)) {
        .Pointer => |info| {
            try writer.write_all(@type_name(info.child) ++ "@");
            if (info.size == .Slice)
                try format_int(@int_from_ptr(value.ptr), 16, .lower, FormatOptions{}, writer)
            else
                try format_int(@int_from_ptr(value), 16, .lower, FormatOptions{}, writer);
            return;
        },
        .Optional => |info| {
            if (@typeInfo(info.child) == .Pointer) {
                try writer.write_all(@type_name(info.child) ++ "@");
                try format_int(@int_from_ptr(value), 16, .lower, FormatOptions{}, writer);
                return;
            }
        },
        else => {},
    }

    @compile_error("cannot format non-pointer type " ++ @type_name(T) ++ " with * specifier");
}

// This ANY const is a workaround for: https://github.com/ziglang/zig/issues/7948
const ANY = "any";

pub fn default_spec(comptime T: type) [:0]const u8 {
    switch (@typeInfo(T)) {
        .Array => |_| return ANY,
        .Pointer => |ptr_info| switch (ptr_info.size) {
            .One => switch (@typeInfo(ptr_info.child)) {
                .Array => |_| return ANY,
                else => {},
            },
            .Many, .C => return "*",
            .Slice => return ANY,
        },
        .Optional => |info| return "?" ++ default_spec(info.child),
        .ErrorUnion => |info| return "!" ++ default_spec(info.payload),
        else => {},
    }
    return "";
}

fn strip_optional_or_error_union_spec(comptime fmt: []const u8) []const u8 {
    return if (std.mem.eql(u8, fmt[1..], ANY))
        ANY
    else
        fmt[1..];
}

pub fn invalid_fmt_error(comptime fmt: []const u8, value: anytype) void {
    @compile_error("invalid format string '" ++ fmt ++ "' for type '" ++ @type_name(@TypeOf(value)) ++ "'");
}

pub fn format_type(
    value: anytype,
    comptime fmt: []const u8,
    options: FormatOptions,
    writer: anytype,
    max_depth: usize,
) @TypeOf(writer).Error!void {
    const T = @TypeOf(value);
    const actual_fmt = comptime if (std.mem.eql(u8, fmt, ANY))
        default_spec(T)
    else if (fmt.len != 0 and (fmt[0] == '?' or fmt[0] == '!')) switch (@typeInfo(T)) {
        .Optional, .ErrorUnion => fmt,
        else => strip_optional_or_error_union_spec(fmt),
    } else fmt;

    if (comptime std.mem.eql(u8, actual_fmt, "*")) {
        return format_address(value, options, writer);
    }

    if (std.meta.has_method(T, "format")) {
        return try value.format(actual_fmt, options, writer);
    }

    switch (@typeInfo(T)) {
        .ComptimeInt, .Int, .ComptimeFloat, .Float => {
            return format_value(value, actual_fmt, options, writer);
        },
        .Void => {
            if (actual_fmt.len != 0) invalid_fmt_error(fmt, value);
            return format_buf("void", options, writer);
        },
        .Bool => {
            if (actual_fmt.len != 0) invalid_fmt_error(fmt, value);
            return format_buf(if (value) "true" else "false", options, writer);
        },
        .Optional => {
            if (actual_fmt.len == 0 or actual_fmt[0] != '?')
                @compile_error("cannot format optional without a specifier (i.e. {?} or {any})");
            const remaining_fmt = comptime strip_optional_or_error_union_spec(actual_fmt);
            if (value) |payload| {
                return format_type(payload, remaining_fmt, options, writer, max_depth);
            } else {
                return format_buf("null", options, writer);
            }
        },
        .ErrorUnion => {
            if (actual_fmt.len == 0 or actual_fmt[0] != '!')
                @compile_error("cannot format error union without a specifier (i.e. {!} or {any})");
            const remaining_fmt = comptime strip_optional_or_error_union_spec(actual_fmt);
            if (value) |payload| {
                return format_type(payload, remaining_fmt, options, writer, max_depth);
            } else |err| {
                return format_type(err, "", options, writer, max_depth);
            }
        },
        .ErrorSet => {
            if (actual_fmt.len != 0) invalid_fmt_error(fmt, value);
            try writer.write_all("error.");
            return writer.write_all(@errorName(value));
        },
        .Enum => |enumInfo| {
            try writer.write_all(@type_name(T));
            if (enumInfo.is_exhaustive) {
                if (actual_fmt.len != 0) invalid_fmt_error(fmt, value);
                try writer.write_all(".");
                try writer.write_all(@tag_name(value));
                return;
            }

            // Use @tag_name only if value is one of known fields
            @setEvalBranchQuota(3 * enumInfo.fields.len);
            inline for (enumInfo.fields) |enumField| {
                if (@int_from_enum(value) == enumField.value) {
                    try writer.write_all(".");
                    try writer.write_all(@tag_name(value));
                    return;
                }
            }

            try writer.write_all("(");
            try format_type(@int_from_enum(value), actual_fmt, options, writer, max_depth);
            try writer.write_all(")");
        },
        .Union => |info| {
            if (actual_fmt.len != 0) invalid_fmt_error(fmt, value);
            try writer.write_all(@type_name(T));
            if (max_depth == 0) {
                return writer.write_all("{ ... }");
            }
            if (info.tag_type) |UnionTagType| {
                try writer.write_all("{ .");
                try writer.write_all(@tag_name(@as(UnionTagType, value)));
                try writer.write_all(" = ");
                inline for (info.fields) |u_field| {
                    if (value == @field(UnionTagType, u_field.name)) {
                        try format_type(@field(value, u_field.name), ANY, options, writer, max_depth - 1);
                    }
                }
                try writer.write_all(" }");
            } else {
                try format(writer, "@{x}", .{@int_from_ptr(&value)});
            }
        },
        .Struct => |info| {
            if (actual_fmt.len != 0) invalid_fmt_error(fmt, value);
            if (info.is_tuple) {
                // Skip the type and field names when formatting tuples.
                if (max_depth == 0) {
                    return writer.write_all("{ ... }");
                }
                try writer.write_all("{");
                inline for (info.fields, 0..) |f, i| {
                    if (i == 0) {
                        try writer.write_all(" ");
                    } else {
                        try writer.write_all(", ");
                    }
                    try format_type(@field(value, f.name), ANY, options, writer, max_depth - 1);
                }
                return writer.write_all(" }");
            }
            try writer.write_all(@type_name(T));
            if (max_depth == 0) {
                return writer.write_all("{ ... }");
            }
            try writer.write_all("{");
            inline for (info.fields, 0..) |f, i| {
                if (i == 0) {
                    try writer.write_all(" .");
                } else {
                    try writer.write_all(", .");
                }
                try writer.write_all(f.name);
                try writer.write_all(" = ");
                try format_type(@field(value, f.name), ANY, options, writer, max_depth - 1);
            }
            try writer.write_all(" }");
        },
        .Pointer => |ptr_info| switch (ptr_info.size) {
            .One => switch (@typeInfo(ptr_info.child)) {
                .Array, .Enum, .Union, .Struct => {
                    return format_type(value.*, actual_fmt, options, writer, max_depth);
                },
                else => return format(writer, "{s}@{x}", .{ @type_name(ptr_info.child), @int_from_ptr(value) }),
            },
            .Many, .C => {
                if (actual_fmt.len == 0)
                    @compile_error("cannot format pointer without a specifier (i.e. {s} or {*})");
                if (ptr_info.sentinel) |_| {
                    return format_type(mem.span(value), actual_fmt, options, writer, max_depth);
                }
                if (actual_fmt[0] == 's' and ptr_info.child == u8) {
                    return format_buf(mem.span(value), options, writer);
                }
                invalid_fmt_error(fmt, value);
            },
            .Slice => {
                if (actual_fmt.len == 0)
                    @compile_error("cannot format slice without a specifier (i.e. {s} or {any})");
                if (max_depth == 0) {
                    return writer.write_all("{ ... }");
                }
                if (actual_fmt[0] == 's' and ptr_info.child == u8) {
                    return format_buf(value, options, writer);
                }
                try writer.write_all("{ ");
                for (value, 0..) |elem, i| {
                    try format_type(elem, actual_fmt, options, writer, max_depth - 1);
                    if (i != value.len - 1) {
                        try writer.write_all(", ");
                    }
                }
                try writer.write_all(" }");
            },
        },
        .Array => |info| {
            if (actual_fmt.len == 0)
                @compile_error("cannot format array without a specifier (i.e. {s} or {any})");
            if (max_depth == 0) {
                return writer.write_all("{ ... }");
            }
            if (actual_fmt[0] == 's' and info.child == u8) {
                return format_buf(&value, options, writer);
            }
            try writer.write_all("{ ");
            for (value, 0..) |elem, i| {
                try format_type(elem, actual_fmt, options, writer, max_depth - 1);
                if (i < value.len - 1) {
                    try writer.write_all(", ");
                }
            }
            try writer.write_all(" }");
        },
        .Vector => |info| {
            try writer.write_all("{ ");
            var i: usize = 0;
            while (i < info.len) : (i += 1) {
                try format_value(value[i], actual_fmt, options, writer);
                if (i < info.len - 1) {
                    try writer.write_all(", ");
                }
            }
            try writer.write_all(" }");
        },
        .Fn => @compile_error("unable to format function body type, use '*const " ++ @type_name(T) ++ "' for a function pointer type"),
        .Type => {
            if (actual_fmt.len != 0) invalid_fmt_error(fmt, value);
            return format_buf(@type_name(value), options, writer);
        },
        .EnumLiteral => {
            if (actual_fmt.len != 0) invalid_fmt_error(fmt, value);
            const buffer = [_]u8{'.'} ++ @tag_name(value);
            return format_buf(buffer, options, writer);
        },
        .Null => {
            if (actual_fmt.len != 0) invalid_fmt_error(fmt, value);
            return format_buf("null", options, writer);
        },
        else => @compile_error("unable to format type '" ++ @type_name(T) ++ "'"),
    }
}

fn format_value(
    value: anytype,
    comptime fmt: []const u8,
    options: FormatOptions,
    writer: anytype,
) !void {
    const T = @TypeOf(value);
    switch (@typeInfo(T)) {
        .Float, .ComptimeFloat => return format_float_value(value, fmt, options, writer),
        .Int, .ComptimeInt => return format_int_value(value, fmt, options, writer),
        .Bool => return format_buf(if (value) "true" else "false", options, writer),
        else => comptime unreachable,
    }
}

pub fn format_int_value(
    value: anytype,
    comptime fmt: []const u8,
    options: FormatOptions,
    writer: anytype,
) !void {
    comptime var base = 10;
    comptime var case: Case = .lower;

    const int_value = if (@TypeOf(value) == comptime_int) blk: {
        const Int = math.IntFittingRange(value, value);
        break :blk @as(Int, value);
    } else value;

    if (fmt.len == 0 or comptime std.mem.eql(u8, fmt, "d")) {
        base = 10;
        case = .lower;
    } else if (comptime std.mem.eql(u8, fmt, "c")) {
        if (@typeInfo(@TypeOf(int_value)).Int.bits <= 8) {
            return format_ascii_char(@as(u8, int_value), options, writer);
        } else {
            @compile_error("cannot print integer that is larger than 8 bits as an ASCII character");
        }
    } else if (comptime std.mem.eql(u8, fmt, "u")) {
        if (@typeInfo(@TypeOf(int_value)).Int.bits <= 21) {
            return format_unicode_codepoint(@as(u21, int_value), options, writer);
        } else {
            @compile_error("cannot print integer that is larger than 21 bits as an UTF-8 sequence");
        }
    } else if (comptime std.mem.eql(u8, fmt, "b")) {
        base = 2;
        case = .lower;
    } else if (comptime std.mem.eql(u8, fmt, "x")) {
        base = 16;
        case = .lower;
    } else if (comptime std.mem.eql(u8, fmt, "X")) {
        base = 16;
        case = .upper;
    } else if (comptime std.mem.eql(u8, fmt, "o")) {
        base = 8;
        case = .lower;
    } else {
        invalid_fmt_error(fmt, value);
    }

    return format_int(int_value, base, case, options, writer);
}

pub const format_float = @import("fmt/format_float.zig");
pub const format_float = format_float.format_float;
pub const FormatFloatError = format_float.FormatError;

fn format_float_value(
    value: anytype,
    comptime fmt: []const u8,
    options: FormatOptions,
    writer: anytype,
) !void {
    var buf: [format_float.buffer_size(.decimal, f64)]u8 = undefined;

    if (fmt.len == 0 or comptime std.mem.eql(u8, fmt, "e")) {
        const s = format_float(&buf, value, .{ .mode = .scientific, .precision = options.precision }) catch |err| switch (err) {
            error.BufferTooSmall => "(float)",
        };
        return format_buf(s, options, writer);
    } else if (comptime std.mem.eql(u8, fmt, "d")) {
        const s = format_float(&buf, value, .{ .mode = .decimal, .precision = options.precision }) catch |err| switch (err) {
            error.BufferTooSmall => "(float)",
        };
        return format_buf(s, options, writer);
    } else if (comptime std.mem.eql(u8, fmt, "x")) {
        var buf_stream = std.io.fixed_buffer_stream(&buf);
        format_float_hexadecimal(value, options, buf_stream.writer()) catch |err| switch (err) {
            error.NoSpaceLeft => unreachable,
        };
        return format_buf(buf_stream.get_written(), options, writer);
    } else {
        invalid_fmt_error(fmt, value);
    }
}

test {
    _ = &format_float;
}

pub const Case = enum { lower, upper };

fn format_slice_hex_impl(comptime case: Case) type {
    const charset = "0123456789" ++ if (case == .upper) "ABCDEF" else "abcdef";

    return struct {
        pub fn format_slice_hex_impl(
            bytes: []const u8,
            comptime fmt: []const u8,
            options: std.fmt.FormatOptions,
            writer: anytype,
        ) !void {
            _ = fmt;
            _ = options;
            var buf: [2]u8 = undefined;

            for (bytes) |c| {
                buf[0] = charset[c >> 4];
                buf[1] = charset[c & 15];
                try writer.write_all(&buf);
            }
        }
    };
}

const formatSliceHexLower = format_slice_hex_impl(.lower).format_slice_hex_impl;
const formatSliceHexUpper = format_slice_hex_impl(.upper).format_slice_hex_impl;

/// Return a Formatter for a []const u8 where every byte is formatted as a pair
/// of lowercase hexadecimal digits.
pub fn fmt_slice_hex_lower(bytes: []const u8) std.fmt.Formatter(formatSliceHexLower) {
    return .{ .data = bytes };
}

/// Return a Formatter for a []const u8 where every byte is formatted as pair
/// of uppercase hexadecimal digits.
pub fn fmt_slice_hex_upper(bytes: []const u8) std.fmt.Formatter(formatSliceHexUpper) {
    return .{ .data = bytes };
}

fn format_slice_escape_impl(comptime case: Case) type {
    const charset = "0123456789" ++ if (case == .upper) "ABCDEF" else "abcdef";

    return struct {
        pub fn format_slice_escape_impl(
            bytes: []const u8,
            comptime fmt: []const u8,
            options: std.fmt.FormatOptions,
            writer: anytype,
        ) !void {
            _ = fmt;
            _ = options;
            var buf: [4]u8 = undefined;

            buf[0] = '\\';
            buf[1] = 'x';

            for (bytes) |c| {
                if (std.ascii.is_print(c)) {
                    try writer.write_byte(c);
                } else {
                    buf[2] = charset[c >> 4];
                    buf[3] = charset[c & 15];
                    try writer.write_all(&buf);
                }
            }
        }
    };
}

const formatSliceEscapeLower = format_slice_escape_impl(.lower).format_slice_escape_impl;
const formatSliceEscapeUpper = format_slice_escape_impl(.upper).format_slice_escape_impl;

/// Return a Formatter for a []const u8 where every non-printable ASCII
/// character is escaped as \xNN, where NN is the character in lowercase
/// hexadecimal notation.
pub fn fmt_slice_escape_lower(bytes: []const u8) std.fmt.Formatter(formatSliceEscapeLower) {
    return .{ .data = bytes };
}

/// Return a Formatter for a []const u8 where every non-printable ASCII
/// character is escaped as \xNN, where NN is the character in uppercase
/// hexadecimal notation.
pub fn fmt_slice_escape_upper(bytes: []const u8) std.fmt.Formatter(formatSliceEscapeUpper) {
    return .{ .data = bytes };
}

fn format_size_impl(comptime base: comptime_int) type {
    return struct {
        fn format_size_impl(
            value: u64,
            comptime fmt: []const u8,
            options: FormatOptions,
            writer: anytype,
        ) !void {
            _ = fmt;
            if (value == 0) {
                return format_buf("0B", options, writer);
            }
            // The worst case in terms of space needed is 32 bytes + 3 for the suffix.
            var buf: [format_float.min_buffer_size + 3]u8 = undefined;

            const mags_si = " kMGTPEZY";
            const mags_iec = " KMGTPEZY";

            const log2 = math.log2(value);
            const magnitude = switch (base) {
                1000 => @min(log2 / comptime math.log2(1000), mags_si.len - 1),
                1024 => @min(log2 / 10, mags_iec.len - 1),
                else => unreachable,
            };
            const new_value = lossy_cast(f64, value) / math.pow(f64, lossy_cast(f64, base), lossy_cast(f64, magnitude));
            const suffix = switch (base) {
                1000 => mags_si[magnitude],
                1024 => mags_iec[magnitude],
                else => unreachable,
            };

            const s = switch (magnitude) {
                0 => buf[0..format_int_buf(&buf, value, 10, .lower, .{})],
                else => format_float(&buf, new_value, .{ .mode = .decimal, .precision = options.precision }) catch |err| switch (err) {
                    error.BufferTooSmall => unreachable,
                },
            };

            var i: usize = s.len;
            if (suffix == ' ') {
                buf[i] = 'B';
                i += 1;
            } else switch (base) {
                1000 => {
                    buf[i..][0..2].* = [_]u8{ suffix, 'B' };
                    i += 2;
                },
                1024 => {
                    buf[i..][0..3].* = [_]u8{ suffix, 'i', 'B' };
                    i += 3;
                },
                else => unreachable,
            }

            return format_buf(buf[0..i], options, writer);
        }
    };
}

const formatSizeDec = format_size_impl(1000).format_size_impl;
const formatSizeBin = format_size_impl(1024).format_size_impl;

/// Return a Formatter for a u64 value representing a file size.
/// This formatter represents the number as multiple of 1000 and uses the SI
/// measurement units (kB, MB, GB, ...).
pub fn fmt_int_size_dec(value: u64) std.fmt.Formatter(formatSizeDec) {
    return .{ .data = value };
}

/// Return a Formatter for a u64 value representing a file size.
/// This formatter represents the number as multiple of 1024 and uses the IEC
/// measurement units (KiB, MiB, GiB, ...).
pub fn fmt_int_size_bin(value: u64) std.fmt.Formatter(formatSizeBin) {
    return .{ .data = value };
}

fn check_text_fmt(comptime fmt: []const u8) void {
    if (fmt.len != 1)
        @compile_error("unsupported format string '" ++ fmt ++ "' when formatting text");
    switch (fmt[0]) {
        // Example of deprecation:
        // '[deprecated_specifier]' => @compile_error("specifier '[deprecated_specifier]' has been deprecated, wrap your argument in `std.some_function` instead"),
        'x' => @compile_error("specifier 'x' has been deprecated, wrap your argument in std.fmt.fmt_slice_hex_lower instead"),
        'X' => @compile_error("specifier 'X' has been deprecated, wrap your argument in std.fmt.fmt_slice_hex_upper instead"),
        else => {},
    }
}

pub fn format_text(
    bytes: []const u8,
    comptime fmt: []const u8,
    options: FormatOptions,
    writer: anytype,
) !void {
    comptime check_text_fmt(fmt);
    return format_buf(bytes, options, writer);
}

pub fn format_ascii_char(
    c: u8,
    options: FormatOptions,
    writer: anytype,
) !void {
    return format_buf(@as(*const [1]u8, &c), options, writer);
}

pub fn format_unicode_codepoint(
    c: u21,
    options: FormatOptions,
    writer: anytype,
) !void {
    var buf: [4]u8 = undefined;
    const len = unicode.utf8_encode(c, &buf) catch |err| switch (err) {
        error.Utf8CannotEncodeSurrogateHalf, error.CodepointTooLarge => {
            return format_buf(&unicode.utf8_encode_comptime(unicode.replacement_character), options, writer);
        },
    };
    return format_buf(buf[0..len], options, writer);
}

pub fn format_buf(
    buf: []const u8,
    options: FormatOptions,
    writer: anytype,
) !void {
    if (options.width) |min_width| {
        // In case of error assume the buffer content is ASCII-encoded
        const width = unicode.utf8_count_codepoints(buf) catch buf.len;
        const padding = if (width < min_width) min_width - width else 0;

        if (padding == 0)
            return writer.write_all(buf);

        var fill_buffer: [4]u8 = undefined;
        const fill_utf8 = if (unicode.utf8_encode(options.fill, &fill_buffer)) |len|
            fill_buffer[0..len]
        else |err| switch (err) {
            error.Utf8CannotEncodeSurrogateHalf,
            error.CodepointTooLarge,
            => &unicode.utf8_encode_comptime(unicode.replacement_character),
        };
        switch (options.alignment) {
            .left => {
                try writer.write_all(buf);
                try writer.write_bytes_ntimes(fill_utf8, padding);
            },
            .center => {
                const left_padding = padding / 2;
                const right_padding = (padding + 1) / 2;
                try writer.write_bytes_ntimes(fill_utf8, left_padding);
                try writer.write_all(buf);
                try writer.write_bytes_ntimes(fill_utf8, right_padding);
            },
            .right => {
                try writer.write_bytes_ntimes(fill_utf8, padding);
                try writer.write_all(buf);
            },
        }
    } else {
        // Fast path, avoid counting the number of codepoints
        try writer.write_all(buf);
    }
}

pub fn format_float_hexadecimal(
    value: anytype,
    options: FormatOptions,
    writer: anytype,
) !void {
    if (math.signbit(value)) {
        try writer.write_byte('-');
    }
    if (math.is_nan(value)) {
        return writer.write_all("nan");
    }
    if (math.is_inf(value)) {
        return writer.write_all("inf");
    }

    const T = @TypeOf(value);
    const TU = std.meta.Int(.unsigned, @bitSizeOf(T));

    const mantissa_bits = math.float_mantissa_bits(T);
    const fractional_bits = math.float_fractional_bits(T);
    const exponent_bits = math.float_exponent_bits(T);
    const mantissa_mask = (1 << mantissa_bits) - 1;
    const exponent_mask = (1 << exponent_bits) - 1;
    const exponent_bias = (1 << (exponent_bits - 1)) - 1;

    const as_bits = @as(TU, @bit_cast(value));
    var mantissa = as_bits & mantissa_mask;
    var exponent: i32 = @as(u16, @truncate((as_bits >> mantissa_bits) & exponent_mask));

    const is_denormal = exponent == 0 and mantissa != 0;
    const is_zero = exponent == 0 and mantissa == 0;

    if (is_zero) {
        // Handle this case here to simplify the logic below.
        try writer.write_all("0x0");
        if (options.precision) |precision| {
            if (precision > 0) {
                try writer.write_all(".");
                try writer.write_byte_ntimes('0', precision);
            }
        } else {
            try writer.write_all(".0");
        }
        try writer.write_all("p0");
        return;
    }

    if (is_denormal) {
        // Adjust the exponent for printing.
        exponent += 1;
    } else {
        if (fractional_bits == mantissa_bits)
            mantissa |= 1 << fractional_bits; // Add the implicit integer bit.
    }

    const mantissa_digits = (fractional_bits + 3) / 4;
    // Fill in zeroes to round the fraction width to a multiple of 4.
    mantissa <<= mantissa_digits * 4 - fractional_bits;

    if (options.precision) |precision| {
        // Round if needed.
        if (precision < mantissa_digits) {
            // We always have at least 4 extra bits.
            var extra_bits = (mantissa_digits - precision) * 4;
            // The result LSB is the Guard bit, we need two more (Round and
            // Sticky) to round the value.
            while (extra_bits > 2) {
                mantissa = (mantissa >> 1) | (mantissa & 1);
                extra_bits -= 1;
            }
            // Round to nearest, tie to even.
            mantissa |= @int_from_bool(mantissa & 0b100 != 0);
            mantissa += 1;
            // Drop the excess bits.
            mantissa >>= 2;
            // Restore the alignment.
            mantissa <<= @as(math.Log2Int(TU), @int_cast((mantissa_digits - precision) * 4));

            const overflow = mantissa & (1 << 1 + mantissa_digits * 4) != 0;
            // Prefer a normalized result in case of overflow.
            if (overflow) {
                mantissa >>= 1;
                exponent += 1;
            }
        }
    }

    // +1 for the decimal part.
    var buf: [1 + mantissa_digits]u8 = undefined;
    _ = format_int_buf(&buf, mantissa, 16, .lower, .{ .fill = '0', .width = 1 + mantissa_digits });

    try writer.write_all("0x");
    try writer.write_byte(buf[0]);
    const trimmed = mem.trim_right(u8, buf[1..], "0");
    if (options.precision) |precision| {
        if (precision > 0) try writer.write_all(".");
    } else if (trimmed.len > 0) {
        try writer.write_all(".");
    }
    try writer.write_all(trimmed);
    // Add trailing zeros if explicitly requested.
    if (options.precision) |precision| if (precision > 0) {
        if (precision > trimmed.len)
            try writer.write_byte_ntimes('0', precision - trimmed.len);
    };
    try writer.write_all("p");
    try format_int(exponent - exponent_bias, 10, .lower, .{}, writer);
}

pub fn format_int(
    value: anytype,
    base: u8,
    case: Case,
    options: FormatOptions,
    writer: anytype,
) !void {
    assert(base >= 2);

    const int_value = if (@TypeOf(value) == comptime_int) blk: {
        const Int = math.IntFittingRange(value, value);
        break :blk @as(Int, value);
    } else value;

    const value_info = @typeInfo(@TypeOf(int_value)).Int;

    // The type must have the same size as `base` or be wider in order for the
    // division to work
    const min_int_bits = comptime @max(value_info.bits, 8);
    const MinInt = std.meta.Int(.unsigned, min_int_bits);

    const abs_value = @abs(int_value);
    // The worst case in terms of space needed is base 2, plus 1 for the sign
    var buf: [1 + @max(@as(comptime_int, value_info.bits), 1)]u8 = undefined;

    var a: MinInt = abs_value;
    var index: usize = buf.len;

    if (base == 10) {
        while (a >= 100) : (a = @div_trunc(a, 100)) {
            index -= 2;
            buf[index..][0..2].* = digits2(@as(usize, @int_cast(a % 100)));
        }

        if (a < 10) {
            index -= 1;
            buf[index] = '0' + @as(u8, @int_cast(a));
        } else {
            index -= 2;
            buf[index..][0..2].* = digits2(@as(usize, @int_cast(a)));
        }
    } else {
        while (true) {
            const digit = a % base;
            index -= 1;
            buf[index] = digit_to_char(@as(u8, @int_cast(digit)), case);
            a /= base;
            if (a == 0) break;
        }
    }

    if (value_info.signedness == .signed) {
        if (value < 0) {
            // Negative integer
            index -= 1;
            buf[index] = '-';
        } else if (options.width == null or options.width.? == 0) {
            // Positive integer, omit the plus sign
        } else {
            // Positive integer
            index -= 1;
            buf[index] = '+';
        }
    }

    return format_buf(buf[index..], options, writer);
}

pub fn format_int_buf(out_buf: []u8, value: anytype, base: u8, case: Case, options: FormatOptions) usize {
    var fbs = std.io.fixed_buffer_stream(out_buf);
    format_int(value, base, case, options, fbs.writer()) catch unreachable;
    return fbs.pos;
}

// Converts values in the range [0, 100) to a string.
pub fn digits2(value: usize) [2]u8 {
    return ("0001020304050607080910111213141516171819" ++
        "2021222324252627282930313233343536373839" ++
        "4041424344454647484950515253545556575859" ++
        "6061626364656667686970717273747576777879" ++
        "8081828384858687888990919293949596979899")[value * 2 ..][0..2].*;
}

const FormatDurationData = struct {
    ns: u64,
    negative: bool = false,
};

fn format_duration(data: FormatDurationData, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
    _ = fmt;

    // worst case: "-XXXyXXwXXdXXhXXmXX.XXXs".len = 24
    var buf: [24]u8 = undefined;
    var fbs = std.io.fixed_buffer_stream(&buf);
    var buf_writer = fbs.writer();
    if (data.negative) {
        buf_writer.write_byte('-') catch unreachable;
    }

    var ns_remaining = data.ns;
    inline for (.{
        .{ .ns = 365 * std.time.ns_per_day, .sep = 'y' },
        .{ .ns = std.time.ns_per_week, .sep = 'w' },
        .{ .ns = std.time.ns_per_day, .sep = 'd' },
        .{ .ns = std.time.ns_per_hour, .sep = 'h' },
        .{ .ns = std.time.ns_per_min, .sep = 'm' },
    }) |unit| {
        if (ns_remaining >= unit.ns) {
            const units = ns_remaining / unit.ns;
            format_int(units, 10, .lower, .{}, buf_writer) catch unreachable;
            buf_writer.write_byte(unit.sep) catch unreachable;
            ns_remaining -= units * unit.ns;
            if (ns_remaining == 0)
                return format_buf(fbs.get_written(), options, writer);
        }
    }

    inline for (.{
        .{ .ns = std.time.ns_per_s, .sep = "s" },
        .{ .ns = std.time.ns_per_ms, .sep = "ms" },
        .{ .ns = std.time.ns_per_us, .sep = "us" },
    }) |unit| {
        const kunits = ns_remaining * 1000 / unit.ns;
        if (kunits >= 1000) {
            format_int(kunits / 1000, 10, .lower, .{}, buf_writer) catch unreachable;
            const frac = kunits % 1000;
            if (frac > 0) {
                // Write up to 3 decimal places
                var decimal_buf = [_]u8{ '.', 0, 0, 0 };
                _ = format_int_buf(decimal_buf[1..], frac, 10, .lower, .{ .fill = '0', .width = 3 });
                var end: usize = 4;
                while (end > 1) : (end -= 1) {
                    if (decimal_buf[end - 1] != '0') break;
                }
                buf_writer.write_all(decimal_buf[0..end]) catch unreachable;
            }
            buf_writer.write_all(unit.sep) catch unreachable;
            return format_buf(fbs.get_written(), options, writer);
        }
    }

    format_int(ns_remaining, 10, .lower, .{}, buf_writer) catch unreachable;
    buf_writer.write_all("ns") catch unreachable;
    return format_buf(fbs.get_written(), options, writer);
}

/// Return a Formatter for number of nanoseconds according to its magnitude:
/// [#y][#w][#d][#h][#m]#[.###][n|u|m]s
pub fn fmt_duration(ns: u64) Formatter(format_duration) {
    const data = FormatDurationData{ .ns = ns };
    return .{ .data = data };
}

test fmt_duration {
    var buf: [24]u8 = undefined;
    inline for (.{
        .{ .s = "0ns", .d = 0 },
        .{ .s = "1ns", .d = 1 },
        .{ .s = "999ns", .d = std.time.ns_per_us - 1 },
        .{ .s = "1us", .d = std.time.ns_per_us },
        .{ .s = "1.45us", .d = 1450 },
        .{ .s = "1.5us", .d = 3 * std.time.ns_per_us / 2 },
        .{ .s = "14.5us", .d = 14500 },
        .{ .s = "145us", .d = 145000 },
        .{ .s = "999.999us", .d = std.time.ns_per_ms - 1 },
        .{ .s = "1ms", .d = std.time.ns_per_ms + 1 },
        .{ .s = "1.5ms", .d = 3 * std.time.ns_per_ms / 2 },
        .{ .s = "1.11ms", .d = 1110000 },
        .{ .s = "1.111ms", .d = 1111000 },
        .{ .s = "1.111ms", .d = 1111100 },
        .{ .s = "999.999ms", .d = std.time.ns_per_s - 1 },
        .{ .s = "1s", .d = std.time.ns_per_s },
        .{ .s = "59.999s", .d = std.time.ns_per_min - 1 },
        .{ .s = "1m", .d = std.time.ns_per_min },
        .{ .s = "1h", .d = std.time.ns_per_hour },
        .{ .s = "1d", .d = std.time.ns_per_day },
        .{ .s = "1w", .d = std.time.ns_per_week },
        .{ .s = "1y", .d = 365 * std.time.ns_per_day },
        .{ .s = "1y52w23h59m59.999s", .d = 730 * std.time.ns_per_day - 1 }, // 365d = 52w1d
        .{ .s = "1y1h1.001s", .d = 365 * std.time.ns_per_day + std.time.ns_per_hour + std.time.ns_per_s + std.time.ns_per_ms },
        .{ .s = "1y1h1s", .d = 365 * std.time.ns_per_day + std.time.ns_per_hour + std.time.ns_per_s + 999 * std.time.ns_per_us },
        .{ .s = "1y1h999.999us", .d = 365 * std.time.ns_per_day + std.time.ns_per_hour + std.time.ns_per_ms - 1 },
        .{ .s = "1y1h1ms", .d = 365 * std.time.ns_per_day + std.time.ns_per_hour + std.time.ns_per_ms },
        .{ .s = "1y1h1ms", .d = 365 * std.time.ns_per_day + std.time.ns_per_hour + std.time.ns_per_ms + 1 },
        .{ .s = "1y1m999ns", .d = 365 * std.time.ns_per_day + std.time.ns_per_min + 999 },
        .{ .s = "584y49w23h34m33.709s", .d = math.max_int(u64) },
    }) |tc| {
        const slice = try buf_print(&buf, "{}", .{fmt_duration(tc.d)});
        try std.testing.expect_equal_strings(tc.s, slice);
    }

    inline for (.{
        .{ .s = "=======0ns", .f = "{s:=>10}", .d = 0 },
        .{ .s = "1ns=======", .f = "{s:=<10}", .d = 1 },
        .{ .s = "  999ns   ", .f = "{s:^10}", .d = std.time.ns_per_us - 1 },
    }) |tc| {
        const slice = try buf_print(&buf, tc.f, .{fmt_duration(tc.d)});
        try std.testing.expect_equal_strings(tc.s, slice);
    }
}

fn format_duration_signed(ns: i64, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
    if (ns < 0) {
        const data = FormatDurationData{ .ns = @as(u64, @int_cast(-ns)), .negative = true };
        try format_duration(data, fmt, options, writer);
    } else {
        const data = FormatDurationData{ .ns = @as(u64, @int_cast(ns)) };
        try format_duration(data, fmt, options, writer);
    }
}

/// Return a Formatter for number of nanoseconds according to its signed magnitude:
/// [#y][#w][#d][#h][#m]#[.###][n|u|m]s
pub fn fmt_duration_signed(ns: i64) Formatter(format_duration_signed) {
    return .{ .data = ns };
}

test fmt_duration_signed {
    var buf: [24]u8 = undefined;
    inline for (.{
        .{ .s = "0ns", .d = 0 },
        .{ .s = "1ns", .d = 1 },
        .{ .s = "-1ns", .d = -(1) },
        .{ .s = "999ns", .d = std.time.ns_per_us - 1 },
        .{ .s = "-999ns", .d = -(std.time.ns_per_us - 1) },
        .{ .s = "1us", .d = std.time.ns_per_us },
        .{ .s = "-1us", .d = -(std.time.ns_per_us) },
        .{ .s = "1.45us", .d = 1450 },
        .{ .s = "-1.45us", .d = -(1450) },
        .{ .s = "1.5us", .d = 3 * std.time.ns_per_us / 2 },
        .{ .s = "-1.5us", .d = -(3 * std.time.ns_per_us / 2) },
        .{ .s = "14.5us", .d = 14500 },
        .{ .s = "-14.5us", .d = -(14500) },
        .{ .s = "145us", .d = 145000 },
        .{ .s = "-145us", .d = -(145000) },
        .{ .s = "999.999us", .d = std.time.ns_per_ms - 1 },
        .{ .s = "-999.999us", .d = -(std.time.ns_per_ms - 1) },
        .{ .s = "1ms", .d = std.time.ns_per_ms + 1 },
        .{ .s = "-1ms", .d = -(std.time.ns_per_ms + 1) },
        .{ .s = "1.5ms", .d = 3 * std.time.ns_per_ms / 2 },
        .{ .s = "-1.5ms", .d = -(3 * std.time.ns_per_ms / 2) },
        .{ .s = "1.11ms", .d = 1110000 },
        .{ .s = "-1.11ms", .d = -(1110000) },
        .{ .s = "1.111ms", .d = 1111000 },
        .{ .s = "-1.111ms", .d = -(1111000) },
        .{ .s = "1.111ms", .d = 1111100 },
        .{ .s = "-1.111ms", .d = -(1111100) },
        .{ .s = "999.999ms", .d = std.time.ns_per_s - 1 },
        .{ .s = "-999.999ms", .d = -(std.time.ns_per_s - 1) },
        .{ .s = "1s", .d = std.time.ns_per_s },
        .{ .s = "-1s", .d = -(std.time.ns_per_s) },
        .{ .s = "59.999s", .d = std.time.ns_per_min - 1 },
        .{ .s = "-59.999s", .d = -(std.time.ns_per_min - 1) },
        .{ .s = "1m", .d = std.time.ns_per_min },
        .{ .s = "-1m", .d = -(std.time.ns_per_min) },
        .{ .s = "1h", .d = std.time.ns_per_hour },
        .{ .s = "-1h", .d = -(std.time.ns_per_hour) },
        .{ .s = "1d", .d = std.time.ns_per_day },
        .{ .s = "-1d", .d = -(std.time.ns_per_day) },
        .{ .s = "1w", .d = std.time.ns_per_week },
        .{ .s = "-1w", .d = -(std.time.ns_per_week) },
        .{ .s = "1y", .d = 365 * std.time.ns_per_day },
        .{ .s = "-1y", .d = -(365 * std.time.ns_per_day) },
        .{ .s = "1y52w23h59m59.999s", .d = 730 * std.time.ns_per_day - 1 }, // 365d = 52w1d
        .{ .s = "-1y52w23h59m59.999s", .d = -(730 * std.time.ns_per_day - 1) }, // 365d = 52w1d
        .{ .s = "1y1h1.001s", .d = 365 * std.time.ns_per_day + std.time.ns_per_hour + std.time.ns_per_s + std.time.ns_per_ms },
        .{ .s = "-1y1h1.001s", .d = -(365 * std.time.ns_per_day + std.time.ns_per_hour + std.time.ns_per_s + std.time.ns_per_ms) },
        .{ .s = "1y1h1s", .d = 365 * std.time.ns_per_day + std.time.ns_per_hour + std.time.ns_per_s + 999 * std.time.ns_per_us },
        .{ .s = "-1y1h1s", .d = -(365 * std.time.ns_per_day + std.time.ns_per_hour + std.time.ns_per_s + 999 * std.time.ns_per_us) },
        .{ .s = "1y1h999.999us", .d = 365 * std.time.ns_per_day + std.time.ns_per_hour + std.time.ns_per_ms - 1 },
        .{ .s = "-1y1h999.999us", .d = -(365 * std.time.ns_per_day + std.time.ns_per_hour + std.time.ns_per_ms - 1) },
        .{ .s = "1y1h1ms", .d = 365 * std.time.ns_per_day + std.time.ns_per_hour + std.time.ns_per_ms },
        .{ .s = "-1y1h1ms", .d = -(365 * std.time.ns_per_day + std.time.ns_per_hour + std.time.ns_per_ms) },
        .{ .s = "1y1h1ms", .d = 365 * std.time.ns_per_day + std.time.ns_per_hour + std.time.ns_per_ms + 1 },
        .{ .s = "-1y1h1ms", .d = -(365 * std.time.ns_per_day + std.time.ns_per_hour + std.time.ns_per_ms + 1) },
        .{ .s = "1y1m999ns", .d = 365 * std.time.ns_per_day + std.time.ns_per_min + 999 },
        .{ .s = "-1y1m999ns", .d = -(365 * std.time.ns_per_day + std.time.ns_per_min + 999) },
        .{ .s = "292y24w3d23h47m16.854s", .d = math.max_int(i64) },
        .{ .s = "-292y24w3d23h47m16.854s", .d = math.min_int(i64) + 1 },
    }) |tc| {
        const slice = try buf_print(&buf, "{}", .{fmt_duration_signed(tc.d)});
        try std.testing.expect_equal_strings(tc.s, slice);
    }

    inline for (.{
        .{ .s = "=======0ns", .f = "{s:=>10}", .d = 0 },
        .{ .s = "1ns=======", .f = "{s:=<10}", .d = 1 },
        .{ .s = "-1ns======", .f = "{s:=<10}", .d = -(1) },
        .{ .s = "  -999ns  ", .f = "{s:^10}", .d = -(std.time.ns_per_us - 1) },
    }) |tc| {
        const slice = try buf_print(&buf, tc.f, .{fmt_duration_signed(tc.d)});
        try std.testing.expect_equal_strings(tc.s, slice);
    }
}

pub const ParseIntError = error{
    /// The result cannot fit in the type specified
    Overflow,

    /// The input was empty or contained an invalid character
    InvalidCharacter,
};

/// Creates a Formatter type from a format function. Wrapping data in Formatter(func) causes
/// the data to be formatted using the given function `func`.  `func` must be of the following
/// form:
///
///     fn format_example(
///         data: T,
///         comptime fmt: []const u8,
///         options: std.fmt.FormatOptions,
///         writer: anytype,
///     ) !void;
///
pub fn Formatter(comptime format_fn: anytype) type {
    const Data = @typeInfo(@TypeOf(format_fn)).Fn.params[0].type.?;
    return struct {
        data: Data,
        pub fn format(
            self: @This(),
            comptime fmt: []const u8,
            options: std.fmt.FormatOptions,
            writer: anytype,
        ) @TypeOf(writer).Error!void {
            try format_fn(self.data, fmt, options, writer);
        }
    };
}

/// Parses the string `buf` as signed or unsigned representation in the
/// specified base of an integral value of type `T`.
///
/// When `base` is zero the string prefix is examined to detect the true base:
///  * A prefix of "0b" implies base=2,
///  * A prefix of "0o" implies base=8,
///  * A prefix of "0x" implies base=16,
///  * Otherwise base=10 is assumed.
///
/// Ignores '_' character in `buf`.
/// See also `parse_unsigned`.
pub fn parse_int(comptime T: type, buf: []const u8, base: u8) ParseIntError!T {
    return parse_int_with_generic_character(T, u8, buf, base);
}

/// Like `parse_int`, but with a generic `Character` type.
pub fn parse_int_with_generic_character(
    comptime Result: type,
    comptime Character: type,
    buf: []const Character,
    base: u8,
) ParseIntError!Result {
    if (buf.len == 0) return error.InvalidCharacter;
    if (buf[0] == '+') return parse_int_with_sign(Result, Character, buf[1..], base, .pos);
    if (buf[0] == '-') return parse_int_with_sign(Result, Character, buf[1..], base, .neg);
    return parse_int_with_sign(Result, Character, buf, base, .pos);
}

test parse_int {
    try std.testing.expect_equal(-10, try parse_int(i32, "-10", 10));
    try std.testing.expect_equal(10, try parse_int(i32, "+10", 10));
    try std.testing.expect_equal(10, try parse_int(u32, "+10", 10));
    try std.testing.expect_error(error.Overflow, parse_int(u32, "-10", 10));
    try std.testing.expect_error(error.InvalidCharacter, parse_int(u32, " 10", 10));
    try std.testing.expect_error(error.InvalidCharacter, parse_int(u32, "10 ", 10));
    try std.testing.expect_error(error.InvalidCharacter, parse_int(u32, "_10_", 10));
    try std.testing.expect_error(error.InvalidCharacter, parse_int(u32, "0x_10_", 10));
    try std.testing.expect_error(error.InvalidCharacter, parse_int(u32, "0x10_", 10));
    try std.testing.expect_error(error.InvalidCharacter, parse_int(u32, "0x_10", 10));
    try std.testing.expect_equal(255, try parse_int(u8, "255", 10));
    try std.testing.expect_error(error.Overflow, parse_int(u8, "256", 10));

    // +0 and -0 should work for unsigned
    try std.testing.expect_equal(0, try parse_int(u8, "-0", 10));
    try std.testing.expect_equal(0, try parse_int(u8, "+0", 10));

    // ensure min_int is parsed correctly
    try std.testing.expect_equal(math.min_int(i1), try parse_int(i1, "-1", 10));
    try std.testing.expect_equal(math.min_int(i8), try parse_int(i8, "-128", 10));
    try std.testing.expect_equal(math.min_int(i43), try parse_int(i43, "-4398046511104", 10));

    // empty string or bare +- is invalid
    try std.testing.expect_error(error.InvalidCharacter, parse_int(u32, "", 10));
    try std.testing.expect_error(error.InvalidCharacter, parse_int(i32, "", 10));
    try std.testing.expect_error(error.InvalidCharacter, parse_int(u32, "+", 10));
    try std.testing.expect_error(error.InvalidCharacter, parse_int(i32, "+", 10));
    try std.testing.expect_error(error.InvalidCharacter, parse_int(u32, "-", 10));
    try std.testing.expect_error(error.InvalidCharacter, parse_int(i32, "-", 10));

    // autodectect the base
    try std.testing.expect_equal(111, try parse_int(i32, "111", 0));
    try std.testing.expect_equal(111, try parse_int(i32, "1_1_1", 0));
    try std.testing.expect_equal(111, try parse_int(i32, "1_1_1", 0));
    try std.testing.expect_equal(7, try parse_int(i32, "+0b111", 0));
    try std.testing.expect_equal(7, try parse_int(i32, "+0B111", 0));
    try std.testing.expect_equal(7, try parse_int(i32, "+0b1_11", 0));
    try std.testing.expect_equal(73, try parse_int(i32, "+0o111", 0));
    try std.testing.expect_equal(73, try parse_int(i32, "+0O111", 0));
    try std.testing.expect_equal(73, try parse_int(i32, "+0o11_1", 0));
    try std.testing.expect_equal(273, try parse_int(i32, "+0x111", 0));
    try std.testing.expect_equal(-7, try parse_int(i32, "-0b111", 0));
    try std.testing.expect_equal(-7, try parse_int(i32, "-0b11_1", 0));
    try std.testing.expect_equal(-73, try parse_int(i32, "-0o111", 0));
    try std.testing.expect_equal(-273, try parse_int(i32, "-0x111", 0));
    try std.testing.expect_equal(-273, try parse_int(i32, "-0X111", 0));
    try std.testing.expect_equal(-273, try parse_int(i32, "-0x1_11", 0));

    // bare binary/octal/decimal prefix is invalid
    try std.testing.expect_error(error.InvalidCharacter, parse_int(u32, "0b", 0));
    try std.testing.expect_error(error.InvalidCharacter, parse_int(u32, "0o", 0));
    try std.testing.expect_error(error.InvalidCharacter, parse_int(u32, "0x", 0));

    // edge cases which previously errored due to base overflowing T
    try std.testing.expect_equal(@as(i2, -2), try std.fmt.parse_int(i2, "-10", 2));
    try std.testing.expect_equal(@as(i4, -8), try std.fmt.parse_int(i4, "-10", 8));
    try std.testing.expect_equal(@as(i5, -16), try std.fmt.parse_int(i5, "-10", 16));
}

fn parse_int_with_sign(
    comptime Result: type,
    comptime Character: type,
    buf: []const Character,
    base: u8,
    comptime sign: enum { pos, neg },
) ParseIntError!Result {
    if (buf.len == 0) return error.InvalidCharacter;

    var buf_base = base;
    var buf_start = buf;
    if (base == 0) {
        // Treat is as a decimal number by default.
        buf_base = 10;
        // Detect the base by looking at buf prefix.
        if (buf.len > 2 and buf[0] == '0') {
            if (math.cast(u8, buf[1])) |c| switch (std.ascii.to_lower(c)) {
                'b' => {
                    buf_base = 2;
                    buf_start = buf[2..];
                },
                'o' => {
                    buf_base = 8;
                    buf_start = buf[2..];
                },
                'x' => {
                    buf_base = 16;
                    buf_start = buf[2..];
                },
                else => {},
            };
        }
    }

    const add = switch (sign) {
        .pos => math.add,
        .neg => math.sub,
    };

    // accumulate into Accumulate which is always 8 bits or larger.  this prevents
    // `buf_base` from overflowing Result.
    const info = @typeInfo(Result);
    const Accumulate = std.meta.Int(info.Int.signedness, @max(8, info.Int.bits));
    var accumulate: Accumulate = 0;

    if (buf_start[0] == '_' or buf_start[buf_start.len - 1] == '_') return error.InvalidCharacter;

    for (buf_start) |c| {
        if (c == '_') continue;
        const digit = try char_to_digit(math.cast(u8, c) orelse return error.InvalidCharacter, buf_base);
        if (accumulate != 0) {
            accumulate = try math.mul(Accumulate, accumulate, math.cast(Accumulate, buf_base) orelse return error.Overflow);
        } else if (sign == .neg) {
            // The first digit of a negative number.
            // Consider parsing "-4" as an i3.
            // This should work, but positive 4 overflows i3, so we can't cast the digit to T and subtract.
            accumulate = math.cast(Accumulate, -@as(i8, @int_cast(digit))) orelse return error.Overflow;
            continue;
        }
        accumulate = try add(Accumulate, accumulate, math.cast(Accumulate, digit) orelse return error.Overflow);
    }

    return if (Result == Accumulate)
        accumulate
    else
        math.cast(Result, accumulate) orelse return error.Overflow;
}

/// Parses the string `buf` as unsigned representation in the specified base
/// of an integral value of type `T`.
///
/// When `base` is zero the string prefix is examined to detect the true base:
///  * A prefix of "0b" implies base=2,
///  * A prefix of "0o" implies base=8,
///  * A prefix of "0x" implies base=16,
///  * Otherwise base=10 is assumed.
///
/// Ignores '_' character in `buf`.
/// See also `parse_int`.
pub fn parse_unsigned(comptime T: type, buf: []const u8, base: u8) ParseIntError!T {
    return parse_int_with_sign(T, u8, buf, base, .pos);
}

test parse_unsigned {
    try std.testing.expect_equal(50124, try parse_unsigned(u16, "050124", 10));
    try std.testing.expect_equal(65535, try parse_unsigned(u16, "65535", 10));
    try std.testing.expect_equal(65535, try parse_unsigned(u16, "65_535", 10));
    try std.testing.expect_error(error.Overflow, parse_unsigned(u16, "65536", 10));

    try std.testing.expect_equal(0xffffffffffffffff, try parse_unsigned(u64, "0ffffffffffffffff", 16));
    try std.testing.expect_equal(0xffffffffffffffff, try parse_unsigned(u64, "0f_fff_fff_fff_fff_fff", 16));
    try std.testing.expect_error(error.Overflow, parse_unsigned(u64, "10000000000000000", 16));

    try std.testing.expect_equal(0xDEADBEEF, try parse_unsigned(u32, "DeadBeef", 16));

    try std.testing.expect_equal(1, try parse_unsigned(u7, "1", 10));
    try std.testing.expect_equal(8, try parse_unsigned(u7, "1000", 2));

    try std.testing.expect_error(error.InvalidCharacter, parse_unsigned(u32, "f", 10));
    try std.testing.expect_error(error.InvalidCharacter, parse_unsigned(u8, "109", 8));

    try std.testing.expect_equal(1442151747, try parse_unsigned(u32, "NUMBER", 36));

    // these numbers should fit even though the base itself doesn't fit in the destination type
    try std.testing.expect_equal(0, try parse_unsigned(u1, "0", 10));
    try std.testing.expect_equal(1, try parse_unsigned(u1, "1", 10));
    try std.testing.expect_error(error.Overflow, parse_unsigned(u1, "2", 10));
    try std.testing.expect_equal(1, try parse_unsigned(u1, "001", 16));
    try std.testing.expect_equal(3, try parse_unsigned(u2, "3", 16));
    try std.testing.expect_error(error.Overflow, parse_unsigned(u2, "4", 16));

    // parse_unsigned does not expect a sign
    try std.testing.expect_error(error.InvalidCharacter, parse_unsigned(u8, "+0", 10));
    try std.testing.expect_error(error.InvalidCharacter, parse_unsigned(u8, "-0", 10));

    // test empty string error
    try std.testing.expect_error(error.InvalidCharacter, parse_unsigned(u8, "", 10));
}

/// Parses a number like '2G', '2Gi', or '2GiB'.
pub fn parse_int_size_suffix(buf: []const u8, digit_base: u8) ParseIntError!usize {
    var without_B = buf;
    if (mem.ends_with(u8, buf, "B")) without_B.len -= 1;
    var without_i = without_B;
    var magnitude_base: usize = 1000;
    if (mem.ends_with(u8, without_B, "i")) {
        without_i.len -= 1;
        magnitude_base = 1024;
    }
    if (without_i.len == 0) return error.InvalidCharacter;
    const orders_of_magnitude: usize = switch (without_i[without_i.len - 1]) {
        'k', 'K' => 1,
        'M' => 2,
        'G' => 3,
        'T' => 4,
        'P' => 5,
        'E' => 6,
        'Z' => 7,
        'Y' => 8,
        'R' => 9,
        'Q' => 10,
        else => 0,
    };
    var without_suffix = without_i;
    if (orders_of_magnitude > 0) {
        without_suffix.len -= 1;
    } else if (without_i.len != without_B.len) {
        return error.InvalidCharacter;
    }
    const multiplier = math.powi(usize, magnitude_base, orders_of_magnitude) catch |err| switch (err) {
        error.Underflow => unreachable,
        error.Overflow => return error.Overflow,
    };
    const number = try std.fmt.parse_int(usize, without_suffix, digit_base);
    return math.mul(usize, number, multiplier);
}

test parse_int_size_suffix {
    try std.testing.expect_equal(2, try parse_int_size_suffix("2", 10));
    try std.testing.expect_equal(2, try parse_int_size_suffix("2B", 10));
    try std.testing.expect_equal(2000, try parse_int_size_suffix("2kB", 10));
    try std.testing.expect_equal(2000, try parse_int_size_suffix("2k", 10));
    try std.testing.expect_equal(2048, try parse_int_size_suffix("2KiB", 10));
    try std.testing.expect_equal(2048, try parse_int_size_suffix("2Ki", 10));
    try std.testing.expect_equal(10240, try parse_int_size_suffix("aKiB", 16));
    try std.testing.expect_error(error.InvalidCharacter, parse_int_size_suffix("", 10));
    try std.testing.expect_error(error.InvalidCharacter, parse_int_size_suffix("2iB", 10));
}

pub const parse_float = @import("fmt/parse_float.zig").parse_float;
pub const ParseFloatError = @import("fmt/parse_float.zig").ParseFloatError;

test {
    _ = &parse_float;
}

pub fn char_to_digit(c: u8, base: u8) (error{InvalidCharacter}!u8) {
    const value = switch (c) {
        '0'...'9' => c - '0',
        'A'...'Z' => c - 'A' + 10,
        'a'...'z' => c - 'a' + 10,
        else => return error.InvalidCharacter,
    };

    if (value >= base) return error.InvalidCharacter;

    return value;
}

pub fn digit_to_char(digit: u8, case: Case) u8 {
    return switch (digit) {
        0...9 => digit + '0',
        10...35 => digit + ((if (case == .upper) @as(u8, 'A') else @as(u8, 'a')) - 10),
        else => unreachable,
    };
}

pub const BufPrintError = error{
    /// As much as possible was written to the buffer, but it was too small to fit all the printed bytes.
    NoSpaceLeft,
};

/// Print a Formatter string into `buf`. Actually just a thin wrapper around `format` and `fixed_buffer_stream`.
/// Returns a slice of the bytes printed to.
pub fn buf_print(buf: []u8, comptime fmt: []const u8, args: anytype) BufPrintError![]u8 {
    var fbs = std.io.fixed_buffer_stream(buf);
    format(fbs.writer().any(), fmt, args) catch |err| switch (err) {
        error.NoSpaceLeft => return error.NoSpaceLeft,
        else => unreachable,
    };
    return fbs.get_written();
}

pub fn buf_print_z(buf: []u8, comptime fmt: []const u8, args: anytype) BufPrintError![:0]u8 {
    const result = try buf_print(buf, fmt ++ "\x00", args);
    return result[0 .. result.len - 1 :0];
}

/// Count the characters needed for format. Useful for preallocating memory
pub fn count(comptime fmt: []const u8, args: anytype) u64 {
    var counting_writer = std.io.counting_writer(std.io.null_writer);
    format(counting_writer.writer().any(), fmt, args) catch unreachable;
    return counting_writer.bytes_written;
}

pub const AllocPrintError = error{OutOfMemory};

pub fn alloc_print(allocator: mem.Allocator, comptime fmt: []const u8, args: anytype) AllocPrintError![]u8 {
    const size = math.cast(usize, count(fmt, args)) orelse return error.OutOfMemory;
    const buf = try allocator.alloc(u8, size);
    return buf_print(buf, fmt, args) catch |err| switch (err) {
        error.NoSpaceLeft => unreachable, // we just counted the size above
    };
}

pub fn alloc_print_z(allocator: mem.Allocator, comptime fmt: []const u8, args: anytype) AllocPrintError![:0]u8 {
    const result = try alloc_print(allocator, fmt ++ "\x00", args);
    return result[0 .. result.len - 1 :0];
}

test buf_print_int_to_slice {
    var buffer: [100]u8 = undefined;
    const buf = buffer[0..];

    try std.testing.expect_equal_slices(u8, "-1", buf_print_int_to_slice(buf, @as(i1, -1), 10, .lower, FormatOptions{}));

    try std.testing.expect_equal_slices(u8, "-101111000110000101001110", buf_print_int_to_slice(buf, @as(i32, -12345678), 2, .lower, FormatOptions{}));
    try std.testing.expect_equal_slices(u8, "-12345678", buf_print_int_to_slice(buf, @as(i32, -12345678), 10, .lower, FormatOptions{}));
    try std.testing.expect_equal_slices(u8, "-bc614e", buf_print_int_to_slice(buf, @as(i32, -12345678), 16, .lower, FormatOptions{}));
    try std.testing.expect_equal_slices(u8, "-BC614E", buf_print_int_to_slice(buf, @as(i32, -12345678), 16, .upper, FormatOptions{}));

    try std.testing.expect_equal_slices(u8, "12345678", buf_print_int_to_slice(buf, @as(u32, 12345678), 10, .upper, FormatOptions{}));

    try std.testing.expect_equal_slices(u8, "   666", buf_print_int_to_slice(buf, @as(u32, 666), 10, .lower, FormatOptions{ .width = 6 }));
    try std.testing.expect_equal_slices(u8, "  1234", buf_print_int_to_slice(buf, @as(u32, 0x1234), 16, .lower, FormatOptions{ .width = 6 }));
    try std.testing.expect_equal_slices(u8, "1234", buf_print_int_to_slice(buf, @as(u32, 0x1234), 16, .lower, FormatOptions{ .width = 1 }));

    try std.testing.expect_equal_slices(u8, "+42", buf_print_int_to_slice(buf, @as(i32, 42), 10, .lower, FormatOptions{ .width = 3 }));
    try std.testing.expect_equal_slices(u8, "-42", buf_print_int_to_slice(buf, @as(i32, -42), 10, .lower, FormatOptions{ .width = 3 }));
}

pub fn buf_print_int_to_slice(buf: []u8, value: anytype, base: u8, case: Case, options: FormatOptions) []u8 {
    return buf[0..format_int_buf(buf, value, base, case, options)];
}

pub inline fn comptime_print(comptime fmt: []const u8, args: anytype) *const [count(fmt, args):0]u8 {
    comptime {
        var buf: [count(fmt, args):0]u8 = undefined;
        _ = buf_print(&buf, fmt, args) catch unreachable;
        buf[buf.len] = 0;
        const final = buf;
        return &final;
    }
}

test comptime_print {
    @setEvalBranchQuota(2000);
    try std.testing.expect_equal(*const [3:0]u8, @TypeOf(comptime_print("{}", .{100})));
    try std.testing.expect_equal_slices(u8, "100", comptime_print("{}", .{100}));
    try std.testing.expect_equal_strings("30", comptime_print("{d}", .{30.0}));
    try std.testing.expect_equal_strings("30.0", comptime_print("{d:3.1}", .{30.0}));
    try std.testing.expect_equal_strings("0.05", comptime_print("{d}", .{0.05}));
    try std.testing.expect_equal_strings("5e-2", comptime_print("{e}", .{0.05}));
}

test "parse u64 digit too big" {
    _ = parse_unsigned(u64, "123a", 10) catch |err| {
        if (err == error.InvalidCharacter) return;
        unreachable;
    };
    unreachable;
}

test "parse unsigned comptime" {
    comptime {
        try std.testing.expect_equal(2, try parse_unsigned(usize, "2", 10));
    }
}

test "escaped braces" {
    try expect_fmt("escaped: {{foo}}\n", "escaped: {{{{foo}}}}\n", .{});
    try expect_fmt("escaped: {foo}\n", "escaped: {{foo}}\n", .{});
}

test "optional" {
    {
        const value: ?i32 = 1234;
        try expect_fmt("optional: 1234\n", "optional: {?}\n", .{value});
        try expect_fmt("optional: 1234\n", "optional: {?d}\n", .{value});
        try expect_fmt("optional: 4d2\n", "optional: {?x}\n", .{value});
    }
    {
        const value: ?[]const u8 = "string";
        try expect_fmt("optional: string\n", "optional: {?s}\n", .{value});
    }
    {
        const value: ?i32 = null;
        try expect_fmt("optional: null\n", "optional: {?}\n", .{value});
    }
    {
        const value = @as(?*i32, @ptrFromInt(0xf000d000));
        try expect_fmt("optional: *i32@f000d000\n", "optional: {*}\n", .{value});
    }
}

test "error" {
    {
        const value: anyerror!i32 = 1234;
        try expect_fmt("error union: 1234\n", "error union: {!}\n", .{value});
        try expect_fmt("error union: 1234\n", "error union: {!d}\n", .{value});
        try expect_fmt("error union: 4d2\n", "error union: {!x}\n", .{value});
    }
    {
        const value: anyerror![]const u8 = "string";
        try expect_fmt("error union: string\n", "error union: {!s}\n", .{value});
    }
    {
        const value: anyerror!i32 = error.InvalidChar;
        try expect_fmt("error union: error.InvalidChar\n", "error union: {!}\n", .{value});
    }
}

test "int.small" {
    {
        const value: u3 = 0b101;
        try expect_fmt("u3: 5\n", "u3: {}\n", .{value});
    }
}

test "int.specifier" {
    {
        const value: u8 = 'a';
        try expect_fmt("u8: a\n", "u8: {c}\n", .{value});
    }
    {
        const value: u8 = 0b1100;
        try expect_fmt("u8: 0b1100\n", "u8: 0b{b}\n", .{value});
    }
    {
        const value: u16 = 0o1234;
        try expect_fmt("u16: 0o1234\n", "u16: 0o{o}\n", .{value});
    }
    {
        const value: u8 = 'a';
        try expect_fmt("UTF-8: a\n", "UTF-8: {u}\n", .{value});
    }
    {
        const value: u21 = 0x1F310;
        try expect_fmt("UTF-8: 🌐\n", "UTF-8: {u}\n", .{value});
    }
    {
        const value: u21 = 0xD800;
        try expect_fmt("UTF-8: �\n", "UTF-8: {u}\n", .{value});
    }
    {
        const value: u21 = 0x110001;
        try expect_fmt("UTF-8: �\n", "UTF-8: {u}\n", .{value});
    }
}

test "int.padded" {
    try expect_fmt("u8: '   1'", "u8: '{:4}'", .{@as(u8, 1)});
    try expect_fmt("u8: '1000'", "u8: '{:0<4}'", .{@as(u8, 1)});
    try expect_fmt("u8: '0001'", "u8: '{:0>4}'", .{@as(u8, 1)});
    try expect_fmt("u8: '0100'", "u8: '{:0^4}'", .{@as(u8, 1)});
    try expect_fmt("i8: '-1  '", "i8: '{:<4}'", .{@as(i8, -1)});
    try expect_fmt("i8: '  -1'", "i8: '{:>4}'", .{@as(i8, -1)});
    try expect_fmt("i8: ' -1 '", "i8: '{:^4}'", .{@as(i8, -1)});
    try expect_fmt("i16: '-1234'", "i16: '{:4}'", .{@as(i16, -1234)});
    try expect_fmt("i16: '+1234'", "i16: '{:4}'", .{@as(i16, 1234)});
    try expect_fmt("i16: '-12345'", "i16: '{:4}'", .{@as(i16, -12345)});
    try expect_fmt("i16: '+12345'", "i16: '{:4}'", .{@as(i16, 12345)});
    try expect_fmt("u16: '12345'", "u16: '{:4}'", .{@as(u16, 12345)});

    try expect_fmt("UTF-8: 'ü   '", "UTF-8: '{u:<4}'", .{'ü'});
    try expect_fmt("UTF-8: '   ü'", "UTF-8: '{u:>4}'", .{'ü'});
    try expect_fmt("UTF-8: ' ü  '", "UTF-8: '{u:^4}'", .{'ü'});
}

test "buffer" {
    {
        var buf1: [32]u8 = undefined;
        var fbs = std.io.fixed_buffer_stream(&buf1);
        try format_type(1234, "", FormatOptions{}, fbs.writer(), std.options.fmt_max_depth);
        try std.testing.expect_equal_strings("1234", fbs.get_written());

        fbs.reset();
        try format_type('a', "c", FormatOptions{}, fbs.writer(), std.options.fmt_max_depth);
        try std.testing.expect_equal_strings("a", fbs.get_written());

        fbs.reset();
        try format_type(0b1100, "b", FormatOptions{}, fbs.writer(), std.options.fmt_max_depth);
        try std.testing.expect_equal_strings("1100", fbs.get_written());
    }
}

// Test formatting of arrays by value, by single-item pointer, and as a slice
fn expect_array_fmt(expected: []const u8, comptime template: []const u8, comptime array_value: anytype) !void {
    try expect_fmt(expected, template, .{array_value});
    try expect_fmt(expected, template, .{&array_value});
    var runtime_zero: usize = 0;
    _ = &runtime_zero;
    try expect_fmt(expected, template, .{array_value[runtime_zero..]});
}

test "array" {
    {
        const value: [3]u8 = "abc".*;
        try expect_array_fmt("array: abc\n", "array: {s}\n", value);
        try expect_array_fmt("array: { 97, 98, 99 }\n", "array: {d}\n", value);
        try expect_array_fmt("array: { 61, 62, 63 }\n", "array: {x}\n", value);
        try expect_array_fmt("array: { 97, 98, 99 }\n", "array: {any}\n", value);

        var buf: [100]u8 = undefined;
        try expect_fmt(
            try buf_print(buf[0..], "array: [3]u8@{x}\n", .{@int_from_ptr(&value)}),
            "array: {*}\n",
            .{&value},
        );
    }

    {
        const value = [2][3]u8{ "abc".*, "def".* };

        try expect_array_fmt("array: { abc, def }\n", "array: {s}\n", value);
        try expect_array_fmt("array: { { 97, 98, 99 }, { 100, 101, 102 } }\n", "array: {d}\n", value);
        try expect_array_fmt("array: { { 61, 62, 63 }, { 64, 65, 66 } }\n", "array: {x}\n", value);
    }
}

test "slice" {
    {
        const value: []const u8 = "abc";
        try expect_fmt("slice: abc\n", "slice: {s}\n", .{value});
        try expect_fmt("slice: { 97, 98, 99 }\n", "slice: {d}\n", .{value});
        try expect_fmt("slice: { 61, 62, 63 }\n", "slice: {x}\n", .{value});
        try expect_fmt("slice: { 97, 98, 99 }\n", "slice: {any}\n", .{value});
    }
    {
        var runtime_zero: usize = 0;
        _ = &runtime_zero;
        const value = @as([*]align(1) const []const u8, @ptrFromInt(0xdeadbeef))[runtime_zero..runtime_zero];
        try expect_fmt("slice: []const u8@deadbeef\n", "slice: {*}\n", .{value});
    }
    {
        const null_term_slice: [:0]const u8 = "\x00hello\x00";
        try expect_fmt("buf: \x00hello\x00\n", "buf: {s}\n", .{null_term_slice});
    }

    try expect_fmt("buf:  Test\n", "buf: {s:5}\n", .{"Test"});
    try expect_fmt("buf: Test\n Other text", "buf: {s}\n Other text", .{"Test"});

    {
        var int_slice = [_]u32{ 1, 4096, 391891, 1111111111 };
        var runtime_zero: usize = 0;
        _ = &runtime_zero;
        try expect_fmt("int: { 1, 4096, 391891, 1111111111 }", "int: {any}", .{int_slice[runtime_zero..]});
        try expect_fmt("int: { 1, 4096, 391891, 1111111111 }", "int: {d}", .{int_slice[runtime_zero..]});
        try expect_fmt("int: { 1, 1000, 5fad3, 423a35c7 }", "int: {x}", .{int_slice[runtime_zero..]});
        try expect_fmt("int: { 00001, 01000, 5fad3, 423a35c7 }", "int: {x:0>5}", .{int_slice[runtime_zero..]});
    }
    {
        const S1 = struct {
            x: u8,
        };
        const struct_slice: []const S1 = &[_]S1{ S1{ .x = 8 }, S1{ .x = 42 } };
        try expect_fmt("slice: { fmt.test.slice.S1{ .x = 8 }, fmt.test.slice.S1{ .x = 42 } }", "slice: {any}", .{struct_slice});
    }
    {
        const S2 = struct {
            x: u8,

            pub fn format(s: @This(), comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
                try writer.print("S2({})", .{s.x});
            }
        };
        const struct_slice: []const S2 = &[_]S2{ S2{ .x = 8 }, S2{ .x = 42 } };
        try expect_fmt("slice: { S2(8), S2(42) }", "slice: {any}", .{struct_slice});
    }
}

test "escape non-printable" {
    try expect_fmt("abc 123", "{s}", .{fmt_slice_escape_lower("abc 123")});
    try expect_fmt("ab\\xffc", "{s}", .{fmt_slice_escape_lower("ab\xffc")});
    try expect_fmt("abc 123", "{s}", .{fmt_slice_escape_upper("abc 123")});
    try expect_fmt("ab\\xFFc", "{s}", .{fmt_slice_escape_upper("ab\xffc")});
}

test "pointer" {
    {
        const value = @as(*align(1) i32, @ptrFromInt(0xdeadbeef));
        try expect_fmt("pointer: i32@deadbeef\n", "pointer: {}\n", .{value});
        try expect_fmt("pointer: i32@deadbeef\n", "pointer: {*}\n", .{value});
    }
    const FnPtr = *align(1) const fn () void;
    {
        const value = @as(FnPtr, @ptrFromInt(0xdeadbeef));
        try expect_fmt("pointer: fn () void@deadbeef\n", "pointer: {}\n", .{value});
    }
    {
        const value = @as(FnPtr, @ptrFromInt(0xdeadbeef));
        try expect_fmt("pointer: fn () void@deadbeef\n", "pointer: {}\n", .{value});
    }
}

test "cstr" {
    try expect_fmt(
        "cstr: Test C\n",
        "cstr: {s}\n",
        .{@as([*c]const u8, @ptr_cast("Test C"))},
    );
    try expect_fmt(
        "cstr:     Test C\n",
        "cstr: {s:10}\n",
        .{@as([*c]const u8, @ptr_cast("Test C"))},
    );
}

test "filesize" {
    try expect_fmt("file size: 42B\n", "file size: {}\n", .{fmt_int_size_dec(42)});
    try expect_fmt("file size: 42B\n", "file size: {}\n", .{fmt_int_size_bin(42)});
    try expect_fmt("file size: 63MB\n", "file size: {}\n", .{fmt_int_size_dec(63 * 1000 * 1000)});
    try expect_fmt("file size: 63MiB\n", "file size: {}\n", .{fmt_int_size_bin(63 * 1024 * 1024)});
    try expect_fmt("file size: 42B\n", "file size: {:.2}\n", .{fmt_int_size_dec(42)});
    try expect_fmt("file size:       42B\n", "file size: {:>9.2}\n", .{fmt_int_size_dec(42)});
    try expect_fmt("file size: 66.06MB\n", "file size: {:.2}\n", .{fmt_int_size_dec(63 * 1024 * 1024)});
    try expect_fmt("file size: 60.08MiB\n", "file size: {:.2}\n", .{fmt_int_size_bin(63 * 1000 * 1000)});
    try expect_fmt("file size: =66.06MB=\n", "file size: {:=^9.2}\n", .{fmt_int_size_dec(63 * 1024 * 1024)});
    try expect_fmt("file size:   66.06MB\n", "file size: {: >9.2}\n", .{fmt_int_size_dec(63 * 1024 * 1024)});
    try expect_fmt("file size: 66.06MB  \n", "file size: {: <9.2}\n", .{fmt_int_size_dec(63 * 1024 * 1024)});
    try expect_fmt("file size: 0.01844674407370955ZB\n", "file size: {}\n", .{fmt_int_size_dec(math.max_int(u64))});
}

test "struct" {
    {
        const Struct = struct {
            field: u8,
        };
        const value = Struct{ .field = 42 };
        try expect_fmt("struct: fmt.test.struct.Struct{ .field = 42 }\n", "struct: {}\n", .{value});
        try expect_fmt("struct: fmt.test.struct.Struct{ .field = 42 }\n", "struct: {}\n", .{&value});
    }
    {
        const Struct = struct {
            a: u0,
            b: u1,
        };
        const value = Struct{ .a = 0, .b = 1 };
        try expect_fmt("struct: fmt.test.struct.Struct{ .a = 0, .b = 1 }\n", "struct: {}\n", .{value});
    }

    const S = struct {
        a: u32,
        b: anyerror,
    };

    const inst = S{
        .a = 456,
        .b = error.Unused,
    };

    try expect_fmt("fmt.test.struct.S{ .a = 456, .b = error.Unused }", "{}", .{inst});
    // Tuples
    try expect_fmt("{ }", "{}", .{.{}});
    try expect_fmt("{ -1 }", "{}", .{.{-1}});
    try expect_fmt("{ -1, 42, 2.5e4 }", "{}", .{.{ -1, 42, 0.25e5 }});
}

test "enum" {
    const Enum = enum {
        One,
        Two,
    };
    const value = Enum.Two;
    try expect_fmt("enum: fmt.test.enum.Enum.Two\n", "enum: {}\n", .{value});
    try expect_fmt("enum: fmt.test.enum.Enum.Two\n", "enum: {}\n", .{&value});
    try expect_fmt("enum: fmt.test.enum.Enum.One\n", "enum: {}\n", .{Enum.One});
    try expect_fmt("enum: fmt.test.enum.Enum.Two\n", "enum: {}\n", .{Enum.Two});

    // test very large enum to verify ct branch quota is large enough
    // TODO: https://github.com/ziglang/zig/issues/15609
    if (!((builtin.cpu.arch == .wasm32) and builtin.mode == .Debug)) {
        try expect_fmt("enum: os.windows.win32error.Win32Error.INVALID_FUNCTION\n", "enum: {}\n", .{std.os.windows.Win32Error.INVALID_FUNCTION});
    }

    const E = enum {
        One,
        Two,
        Three,
    };

    const inst = E.Two;

    try expect_fmt("fmt.test.enum.E.Two", "{}", .{inst});
}

test "non-exhaustive enum" {
    const Enum = enum(u16) {
        One = 0x000f,
        Two = 0xbeef,
        _,
    };
    try expect_fmt("enum: fmt.test.non-exhaustive enum.Enum.One\n", "enum: {}\n", .{Enum.One});
    try expect_fmt("enum: fmt.test.non-exhaustive enum.Enum.Two\n", "enum: {}\n", .{Enum.Two});
    try expect_fmt("enum: fmt.test.non-exhaustive enum.Enum(4660)\n", "enum: {}\n", .{@as(Enum, @enumFromInt(0x1234))});
    try expect_fmt("enum: fmt.test.non-exhaustive enum.Enum.One\n", "enum: {x}\n", .{Enum.One});
    try expect_fmt("enum: fmt.test.non-exhaustive enum.Enum.Two\n", "enum: {x}\n", .{Enum.Two});
    try expect_fmt("enum: fmt.test.non-exhaustive enum.Enum.Two\n", "enum: {X}\n", .{Enum.Two});
    try expect_fmt("enum: fmt.test.non-exhaustive enum.Enum(1234)\n", "enum: {x}\n", .{@as(Enum, @enumFromInt(0x1234))});
}

test "float.scientific" {
    try expect_fmt("f32: 1.34e0", "f32: {e}", .{@as(f32, 1.34)});
    try expect_fmt("f32: 1.234e1", "f32: {e}", .{@as(f32, 12.34)});
    try expect_fmt("f64: -1.234e11", "f64: {e}", .{@as(f64, -12.34e10)});
    try expect_fmt("f64: 9.99996e-40", "f64: {e}", .{@as(f64, 9.999960e-40)});
}

test "float.scientific.precision" {
    try expect_fmt("f64: 1.40971e-42", "f64: {e:.5}", .{@as(f64, 1.409706e-42)});
    try expect_fmt("f64: 1.00000e-9", "f64: {e:.5}", .{@as(f64, @as(f32, @bit_cast(@as(u32, 814313563))))});
    try expect_fmt("f64: 7.81250e-3", "f64: {e:.5}", .{@as(f64, @as(f32, @bit_cast(@as(u32, 1006632960))))});
    // libc rounds 1.000005e5 to 1.00000e5 but zig does 1.00001e5.
    // In fact, libc doesn't round a lot of 5 cases up when one past the precision point.
    try expect_fmt("f64: 1.00001e5", "f64: {e:.5}", .{@as(f64, @as(f32, @bit_cast(@as(u32, 1203982400))))});
}

test "float.special" {
    try expect_fmt("f64: nan", "f64: {}", .{math.nan(f64)});
    // negative nan is not defined by IEE 754,
    // and ARM thus normalizes it to positive nan
    if (builtin.target.cpu.arch != .arm) {
        try expect_fmt("f64: -nan", "f64: {}", .{-math.nan(f64)});
    }
    try expect_fmt("f64: inf", "f64: {}", .{math.inf(f64)});
    try expect_fmt("f64: -inf", "f64: {}", .{-math.inf(f64)});
}

test "float.hexadecimal.special" {
    try expect_fmt("f64: nan", "f64: {x}", .{math.nan(f64)});
    // negative nan is not defined by IEE 754,
    // and ARM thus normalizes it to positive nan
    if (builtin.target.cpu.arch != .arm) {
        try expect_fmt("f64: -nan", "f64: {x}", .{-math.nan(f64)});
    }
    try expect_fmt("f64: inf", "f64: {x}", .{math.inf(f64)});
    try expect_fmt("f64: -inf", "f64: {x}", .{-math.inf(f64)});

    try expect_fmt("f64: 0x0.0p0", "f64: {x}", .{@as(f64, 0)});
    try expect_fmt("f64: -0x0.0p0", "f64: {x}", .{-@as(f64, 0)});
}

test "float.hexadecimal" {
    try expect_fmt("f16: 0x1.554p-2", "f16: {x}", .{@as(f16, 1.0 / 3.0)});
    try expect_fmt("f32: 0x1.555556p-2", "f32: {x}", .{@as(f32, 1.0 / 3.0)});
    try expect_fmt("f64: 0x1.5555555555555p-2", "f64: {x}", .{@as(f64, 1.0 / 3.0)});
    try expect_fmt("f80: 0x1.5555555555555556p-2", "f80: {x}", .{@as(f80, 1.0 / 3.0)});
    try expect_fmt("f128: 0x1.5555555555555555555555555555p-2", "f128: {x}", .{@as(f128, 1.0 / 3.0)});

    try expect_fmt("f16: 0x1p-14", "f16: {x}", .{math.float_min(f16)});
    try expect_fmt("f32: 0x1p-126", "f32: {x}", .{math.float_min(f32)});
    try expect_fmt("f64: 0x1p-1022", "f64: {x}", .{math.float_min(f64)});
    try expect_fmt("f80: 0x1p-16382", "f80: {x}", .{math.float_min(f80)});
    try expect_fmt("f128: 0x1p-16382", "f128: {x}", .{math.float_min(f128)});

    try expect_fmt("f16: 0x0.004p-14", "f16: {x}", .{math.float_true_min(f16)});
    try expect_fmt("f32: 0x0.000002p-126", "f32: {x}", .{math.float_true_min(f32)});
    try expect_fmt("f64: 0x0.0000000000001p-1022", "f64: {x}", .{math.float_true_min(f64)});
    try expect_fmt("f80: 0x0.0000000000000002p-16382", "f80: {x}", .{math.float_true_min(f80)});
    try expect_fmt("f128: 0x0.0000000000000000000000000001p-16382", "f128: {x}", .{math.float_true_min(f128)});

    try expect_fmt("f16: 0x1.ffcp15", "f16: {x}", .{math.float_max(f16)});
    try expect_fmt("f32: 0x1.fffffep127", "f32: {x}", .{math.float_max(f32)});
    try expect_fmt("f64: 0x1.fffffffffffffp1023", "f64: {x}", .{math.float_max(f64)});
    try expect_fmt("f80: 0x1.fffffffffffffffep16383", "f80: {x}", .{math.float_max(f80)});
    try expect_fmt("f128: 0x1.ffffffffffffffffffffffffffffp16383", "f128: {x}", .{math.float_max(f128)});
}

test "float.hexadecimal.precision" {
    try expect_fmt("f16: 0x1.5p-2", "f16: {x:.1}", .{@as(f16, 1.0 / 3.0)});
    try expect_fmt("f32: 0x1.555p-2", "f32: {x:.3}", .{@as(f32, 1.0 / 3.0)});
    try expect_fmt("f64: 0x1.55555p-2", "f64: {x:.5}", .{@as(f64, 1.0 / 3.0)});
    try expect_fmt("f80: 0x1.5555555p-2", "f80: {x:.7}", .{@as(f80, 1.0 / 3.0)});
    try expect_fmt("f128: 0x1.555555555p-2", "f128: {x:.9}", .{@as(f128, 1.0 / 3.0)});

    try expect_fmt("f16: 0x1.00000p0", "f16: {x:.5}", .{@as(f16, 1.0)});
    try expect_fmt("f32: 0x1.00000p0", "f32: {x:.5}", .{@as(f32, 1.0)});
    try expect_fmt("f64: 0x1.00000p0", "f64: {x:.5}", .{@as(f64, 1.0)});
    try expect_fmt("f80: 0x1.00000p0", "f80: {x:.5}", .{@as(f80, 1.0)});
    try expect_fmt("f128: 0x1.00000p0", "f128: {x:.5}", .{@as(f128, 1.0)});
}

test "float.decimal" {
    try expect_fmt("f64: 152314000000000000000000000000", "f64: {d}", .{@as(f64, 1.52314e29)});
    try expect_fmt("f32: 0", "f32: {d}", .{@as(f32, 0.0)});
    try expect_fmt("f32: 0", "f32: {d:.0}", .{@as(f32, 0.0)});
    try expect_fmt("f32: 1.1", "f32: {d:.1}", .{@as(f32, 1.1234)});
    try expect_fmt("f32: 1234.57", "f32: {d:.2}", .{@as(f32, 1234.567)});
    // -11.1234 is converted to f64 -11.12339... internally (errol3() function takes f64).
    // -11.12339... is rounded back up to -11.1234
    try expect_fmt("f32: -11.1234", "f32: {d:.4}", .{@as(f32, -11.1234)});
    try expect_fmt("f32: 91.12345", "f32: {d:.5}", .{@as(f32, 91.12345)});
    try expect_fmt("f64: 91.1234567890", "f64: {d:.10}", .{@as(f64, 91.12345678901235)});
    try expect_fmt("f64: 0.00000", "f64: {d:.5}", .{@as(f64, 0.0)});
    try expect_fmt("f64: 6", "f64: {d:.0}", .{@as(f64, 5.700)});
    try expect_fmt("f64: 10.0", "f64: {d:.1}", .{@as(f64, 9.999)});
    try expect_fmt("f64: 1.000", "f64: {d:.3}", .{@as(f64, 1.0)});
    try expect_fmt("f64: 0.00030000", "f64: {d:.8}", .{@as(f64, 0.0003)});
    try expect_fmt("f64: 0.00000", "f64: {d:.5}", .{@as(f64, 1.40130e-45)});
    try expect_fmt("f64: 0.00000", "f64: {d:.5}", .{@as(f64, 9.999960e-40)});
    try expect_fmt("f64: 10000000000000.00", "f64: {d:.2}", .{@as(f64, 9999999999999.999)});
    try expect_fmt("f64: 10000000000000000000000000000000000000", "f64: {d}", .{@as(f64, 1e37)});
    try expect_fmt("f64: 100000000000000000000000000000000000000", "f64: {d}", .{@as(f64, 1e38)});
}

test "float.libc.sanity" {
    try expect_fmt("f64: 0.00001", "f64: {d:.5}", .{@as(f64, @as(f32, @bit_cast(@as(u32, 916964781))))});
    try expect_fmt("f64: 0.00001", "f64: {d:.5}", .{@as(f64, @as(f32, @bit_cast(@as(u32, 925353389))))});
    try expect_fmt("f64: 0.10000", "f64: {d:.5}", .{@as(f64, @as(f32, @bit_cast(@as(u32, 1036831278))))});
    try expect_fmt("f64: 1.00000", "f64: {d:.5}", .{@as(f64, @as(f32, @bit_cast(@as(u32, 1065353133))))});
    try expect_fmt("f64: 10.00000", "f64: {d:.5}", .{@as(f64, @as(f32, @bit_cast(@as(u32, 1092616192))))});

    // libc differences
    //
    // This is 0.015625 exactly according to gdb. We thus round down,
    // however glibc rounds up for some reason. This occurs for all
    // floats of the form x.yyyy25 on a precision point.
    try expect_fmt("f64: 0.01563", "f64: {d:.5}", .{@as(f64, @as(f32, @bit_cast(@as(u32, 1015021568))))});
    // errol3 rounds to ... 630 but libc rounds to ...632. Grisu3
    // also rounds to 630 so I'm inclined to believe libc is not
    // optimal here.
    try expect_fmt("f64: 18014400656965630.00000", "f64: {d:.5}", .{@as(f64, @as(f32, @bit_cast(@as(u32, 1518338049))))});
}

test "custom" {
    const Vec2 = struct {
        const SelfType = @This();
        x: f32,
        y: f32,

        pub fn format(
            self: SelfType,
            comptime fmt: []const u8,
            options: FormatOptions,
            writer: anytype,
        ) !void {
            _ = options;
            if (fmt.len == 0 or comptime std.mem.eql(u8, fmt, "p")) {
                return std.fmt.format(writer, "({d:.3},{d:.3})", .{ self.x, self.y });
            } else if (comptime std.mem.eql(u8, fmt, "d")) {
                return std.fmt.format(writer, "{d:.3}x{d:.3}", .{ self.x, self.y });
            } else {
                @compile_error("unknown format character: '" ++ fmt ++ "'");
            }
        }
    };

    var value = Vec2{
        .x = 10.2,
        .y = 2.22,
    };
    try expect_fmt("point: (10.200,2.220)\n", "point: {}\n", .{&value});
    try expect_fmt("dim: 10.200x2.220\n", "dim: {d}\n", .{&value});

    // same thing but not passing a pointer
    try expect_fmt("point: (10.200,2.220)\n", "point: {}\n", .{value});
    try expect_fmt("dim: 10.200x2.220\n", "dim: {d}\n", .{value});
}

test "union" {
    const TU = union(enum) {
        float: f32,
        int: u32,
    };

    const UU = union {
        float: f32,
        int: u32,
    };

    const EU = extern union {
        float: f32,
        int: u32,
    };

    const tu_inst = TU{ .int = 123 };
    const uu_inst = UU{ .int = 456 };
    const eu_inst = EU{ .float = 321.123 };

    try expect_fmt("fmt.test.union.TU{ .int = 123 }", "{}", .{tu_inst});

    var buf: [100]u8 = undefined;
    const uu_result = try buf_print(buf[0..], "{}", .{uu_inst});
    try std.testing.expect_equal_strings("fmt.test.union.UU@", uu_result[0..18]);

    const eu_result = try buf_print(buf[0..], "{}", .{eu_inst});
    try std.testing.expect_equal_strings("fmt.test.union.EU@", eu_result[0..18]);
}

test "struct.self-referential" {
    const S = struct {
        const SelfType = @This();
        a: ?*SelfType,
    };

    var inst = S{
        .a = null,
    };
    inst.a = &inst;

    try expect_fmt("fmt.test.struct.self-referential.S{ .a = fmt.test.struct.self-referential.S{ .a = fmt.test.struct.self-referential.S{ .a = fmt.test.struct.self-referential.S{ ... } } } }", "{}", .{inst});
}

test "struct.zero-size" {
    const A = struct {
        fn foo() void {}
    };
    const B = struct {
        a: A,
        c: i32,
    };

    const a = A{};
    const b = B{ .a = a, .c = 0 };

    try expect_fmt("fmt.test.struct.zero-size.B{ .a = fmt.test.struct.zero-size.A{ }, .c = 0 }", "{}", .{b});
}

test "bytes.hex" {
    const some_bytes = "\xCA\xFE\xBA\xBE";
    try expect_fmt("lowercase: cafebabe\n", "lowercase: {x}\n", .{fmt_slice_hex_lower(some_bytes)});
    try expect_fmt("uppercase: CAFEBABE\n", "uppercase: {X}\n", .{fmt_slice_hex_upper(some_bytes)});
    //Test Slices
    try expect_fmt("uppercase: CAFE\n", "uppercase: {X}\n", .{fmt_slice_hex_upper(some_bytes[0..2])});
    try expect_fmt("lowercase: babe\n", "lowercase: {x}\n", .{fmt_slice_hex_lower(some_bytes[2..])});
    const bytes_with_zeros = "\x00\x0E\xBA\xBE";
    try expect_fmt("lowercase: 000ebabe\n", "lowercase: {x}\n", .{fmt_slice_hex_lower(bytes_with_zeros)});
}

/// Encodes a sequence of bytes as hexadecimal digits.
/// Returns an array containing the encoded bytes.
pub fn bytes_to_hex(input: anytype, case: Case) [input.len * 2]u8 {
    if (input.len == 0) return [_]u8{};
    comptime assert(@TypeOf(input[0]) == u8); // elements to encode must be unsigned bytes

    const charset = "0123456789" ++ if (case == .upper) "ABCDEF" else "abcdef";
    var result: [input.len * 2]u8 = undefined;
    for (input, 0..) |b, i| {
        result[i * 2 + 0] = charset[b >> 4];
        result[i * 2 + 1] = charset[b & 15];
    }
    return result;
}

/// Decodes the sequence of bytes represented by the specified string of
/// hexadecimal characters.
/// Returns a slice of the output buffer containing the decoded bytes.
pub fn hex_to_bytes(out: []u8, input: []const u8) ![]u8 {
    // Expect 0 or n pairs of hexadecimal digits.
    if (input.len & 1 != 0)
        return error.InvalidLength;
    if (out.len * 2 < input.len)
        return error.NoSpaceLeft;

    var in_i: usize = 0;
    while (in_i < input.len) : (in_i += 2) {
        const hi = try char_to_digit(input[in_i], 16);
        const lo = try char_to_digit(input[in_i + 1], 16);
        out[in_i / 2] = (hi << 4) | lo;
    }

    return out[0 .. in_i / 2];
}

test bytes_to_hex {
    const input = "input slice";
    const encoded = bytes_to_hex(input, .lower);
    var decoded: [input.len]u8 = undefined;
    try std.testing.expect_equal_slices(u8, input, try hex_to_bytes(&decoded, &encoded));
}

test hex_to_bytes {
    var buf: [32]u8 = undefined;
    try expect_fmt("90" ** 32, "{s}", .{fmt_slice_hex_upper(try hex_to_bytes(&buf, "90" ** 32))});
    try expect_fmt("ABCD", "{s}", .{fmt_slice_hex_upper(try hex_to_bytes(&buf, "ABCD"))});
    try expect_fmt("", "{s}", .{fmt_slice_hex_upper(try hex_to_bytes(&buf, ""))});
    try std.testing.expect_error(error.InvalidCharacter, hex_to_bytes(&buf, "012Z"));
    try std.testing.expect_error(error.InvalidLength, hex_to_bytes(&buf, "AAA"));
    try std.testing.expect_error(error.NoSpaceLeft, hex_to_bytes(buf[0..1], "ABAB"));
}

test "format_int_value with comptime_int" {
    const value: comptime_int = 123456789123456789;

    var buf: [20]u8 = undefined;
    var fbs = std.io.fixed_buffer_stream(&buf);
    try format_int_value(value, "", FormatOptions{}, fbs.writer());
    try std.testing.expect_equal_strings("123456789123456789", fbs.get_written());
}

test "format_float_value with comptime_float" {
    const value: comptime_float = 1.0;

    var buf: [20]u8 = undefined;
    var fbs = std.io.fixed_buffer_stream(&buf);
    try format_float_value(value, "", FormatOptions{}, fbs.writer());
    try std.testing.expect_equal_strings(fbs.get_written(), "1e0");

    try expect_fmt("1e0", "{}", .{value});
    try expect_fmt("1e0", "{}", .{1.0});
}

test "format_type max_depth" {
    const Vec2 = struct {
        const SelfType = @This();
        x: f32,
        y: f32,

        pub fn format(
            self: SelfType,
            comptime fmt: []const u8,
            options: FormatOptions,
            writer: anytype,
        ) !void {
            _ = options;
            if (fmt.len == 0) {
                return std.fmt.format(writer, "({d:.3},{d:.3})", .{ self.x, self.y });
            } else {
                @compile_error("unknown format string: '" ++ fmt ++ "'");
            }
        }
    };
    const E = enum {
        One,
        Two,
        Three,
    };
    const TU = union(enum) {
        const SelfType = @This();
        float: f32,
        int: u32,
        ptr: ?*SelfType,
    };
    const S = struct {
        const SelfType = @This();
        a: ?*SelfType,
        tu: TU,
        e: E,
        vec: Vec2,
    };

    var inst = S{
        .a = null,
        .tu = TU{ .ptr = null },
        .e = E.Two,
        .vec = Vec2{ .x = 10.2, .y = 2.22 },
    };
    inst.a = &inst;
    inst.tu.ptr = &inst.tu;

    var buf: [1000]u8 = undefined;
    var fbs = std.io.fixed_buffer_stream(&buf);
    try format_type(inst, "", FormatOptions{}, fbs.writer(), 0);
    try std.testing.expect_equal_strings("fmt.test.format_type max_depth.S{ ... }", fbs.get_written());

    fbs.reset();
    try format_type(inst, "", FormatOptions{}, fbs.writer(), 1);
    try std.testing.expect_equal_strings("fmt.test.format_type max_depth.S{ .a = fmt.test.format_type max_depth.S{ ... }, .tu = fmt.test.format_type max_depth.TU{ ... }, .e = fmt.test.format_type max_depth.E.Two, .vec = (10.200,2.220) }", fbs.get_written());

    fbs.reset();
    try format_type(inst, "", FormatOptions{}, fbs.writer(), 2);
    try std.testing.expect_equal_strings("fmt.test.format_type max_depth.S{ .a = fmt.test.format_type max_depth.S{ .a = fmt.test.format_type max_depth.S{ ... }, .tu = fmt.test.format_type max_depth.TU{ ... }, .e = fmt.test.format_type max_depth.E.Two, .vec = (10.200,2.220) }, .tu = fmt.test.format_type max_depth.TU{ .ptr = fmt.test.format_type max_depth.TU{ ... } }, .e = fmt.test.format_type max_depth.E.Two, .vec = (10.200,2.220) }", fbs.get_written());

    fbs.reset();
    try format_type(inst, "", FormatOptions{}, fbs.writer(), 3);
    try std.testing.expect_equal_strings("fmt.test.format_type max_depth.S{ .a = fmt.test.format_type max_depth.S{ .a = fmt.test.format_type max_depth.S{ .a = fmt.test.format_type max_depth.S{ ... }, .tu = fmt.test.format_type max_depth.TU{ ... }, .e = fmt.test.format_type max_depth.E.Two, .vec = (10.200,2.220) }, .tu = fmt.test.format_type max_depth.TU{ .ptr = fmt.test.format_type max_depth.TU{ ... } }, .e = fmt.test.format_type max_depth.E.Two, .vec = (10.200,2.220) }, .tu = fmt.test.format_type max_depth.TU{ .ptr = fmt.test.format_type max_depth.TU{ .ptr = fmt.test.format_type max_depth.TU{ ... } } }, .e = fmt.test.format_type max_depth.E.Two, .vec = (10.200,2.220) }", fbs.get_written());
}

test "positional" {
    try expect_fmt("2 1 0", "{2} {1} {0}", .{ @as(usize, 0), @as(usize, 1), @as(usize, 2) });
    try expect_fmt("2 1 0", "{2} {1} {}", .{ @as(usize, 0), @as(usize, 1), @as(usize, 2) });
    try expect_fmt("0 0", "{0} {0}", .{@as(usize, 0)});
    try expect_fmt("0 1", "{} {1}", .{ @as(usize, 0), @as(usize, 1) });
    try expect_fmt("1 0 0 1", "{1} {} {0} {}", .{ @as(usize, 0), @as(usize, 1) });
}

test "positional with specifier" {
    try expect_fmt("10.0", "{0d:.1}", .{@as(f64, 9.999)});
}

test "positional/alignment/width/precision" {
    try expect_fmt("10.0", "{0d: >3.1}", .{@as(f64, 9.999)});
}

test "vector" {
    if (builtin.target.cpu.arch == .riscv64) {
        // https://github.com/ziglang/zig/issues/4486
        return error.SkipZigTest;
    }

    const vbool: @Vector(4, bool) = [_]bool{ true, false, true, false };
    const vi64: @Vector(4, i64) = [_]i64{ -2, -1, 0, 1 };
    const vu64: @Vector(4, u64) = [_]u64{ 1000, 2000, 3000, 4000 };

    try expect_fmt("{ true, false, true, false }", "{}", .{vbool});
    try expect_fmt("{ -2, -1, 0, 1 }", "{}", .{vi64});
    try expect_fmt("{    -2,    -1,    +0,    +1 }", "{d:5}", .{vi64});
    try expect_fmt("{ 1000, 2000, 3000, 4000 }", "{}", .{vu64});
    try expect_fmt("{ 3e8, 7d0, bb8, fa0 }", "{x}", .{vu64});
}

test "enum-literal" {
    try expect_fmt(".hello_world", "{}", .{.hello_world});
}

test "padding" {
    try expect_fmt("Simple", "{s}", .{"Simple"});
    try expect_fmt("      true", "{:10}", .{true});
    try expect_fmt("      true", "{:>10}", .{true});
    try expect_fmt("======true", "{:=>10}", .{true});
    try expect_fmt("true======", "{:=<10}", .{true});
    try expect_fmt("   true   ", "{:^10}", .{true});
    try expect_fmt("===true===", "{:=^10}", .{true});
    try expect_fmt("           Minimum width", "{s:18} width", .{"Minimum"});
    try expect_fmt("==================Filled", "{s:=>24}", .{"Filled"});
    try expect_fmt("        Centered        ", "{s:^24}", .{"Centered"});
    try expect_fmt("-", "{s:-^1}", .{""});
    try expect_fmt("==crêpe===", "{s:=^10}", .{"crêpe"});
    try expect_fmt("=====crêpe", "{s:=>10}", .{"crêpe"});
    try expect_fmt("crêpe=====", "{s:=<10}", .{"crêpe"});
    try expect_fmt("====a", "{c:=>5}", .{'a'});
    try expect_fmt("==a==", "{c:=^5}", .{'a'});
    try expect_fmt("a====", "{c:=<5}", .{'a'});
}

test "padding fill char utf" {
    try expect_fmt("──crêpe───", "{s:─^10}", .{"crêpe"});
    try expect_fmt("─────crêpe", "{s:─>10}", .{"crêpe"});
    try expect_fmt("crêpe─────", "{s:─<10}", .{"crêpe"});
    try expect_fmt("────a", "{c:─>5}", .{'a'});
    try expect_fmt("──a──", "{c:─^5}", .{'a'});
    try expect_fmt("a────", "{c:─<5}", .{'a'});
}

test "decimal float padding" {
    const number: f32 = 3.1415;
    try expect_fmt("left-pad:   **3.142\n", "left-pad:   {d:*>7.3}\n", .{number});
    try expect_fmt("center-pad: *3.142*\n", "center-pad: {d:*^7.3}\n", .{number});
    try expect_fmt("right-pad:  3.142**\n", "right-pad:  {d:*<7.3}\n", .{number});
}

test "sci float padding" {
    const number: f32 = 3.1415;
    try expect_fmt("left-pad:   ****3.142e0\n", "left-pad:   {e:*>11.3}\n", .{number});
    try expect_fmt("center-pad: **3.142e0**\n", "center-pad: {e:*^11.3}\n", .{number});
    try expect_fmt("right-pad:  3.142e0****\n", "right-pad:  {e:*<11.3}\n", .{number});
}

test "null" {
    const inst = null;
    try expect_fmt("null", "{}", .{inst});
}

test "type" {
    try expect_fmt("u8", "{}", .{u8});
    try expect_fmt("?f32", "{}", .{?f32});
    try expect_fmt("[]const u8", "{}", .{[]const u8});
}

test "named arguments" {
    try expect_fmt("hello world!", "{s} world{c}", .{ "hello", '!' });
    try expect_fmt("hello world!", "{[greeting]s} world{[punctuation]c}", .{ .punctuation = '!', .greeting = "hello" });
    try expect_fmt("hello world!", "{[1]s} world{[0]c}", .{ '!', "hello" });
}

test "runtime width specifier" {
    const width: usize = 9;
    try expect_fmt("~~hello~~", "{s:~^[1]}", .{ "hello", width });
    try expect_fmt("~~hello~~", "{s:~^[width]}", .{ .string = "hello", .width = width });
    try expect_fmt("    hello", "{s:[1]}", .{ "hello", width });
    try expect_fmt("42     hello", "{d} {s:[2]}", .{ 42, "hello", width });
}

test "runtime precision specifier" {
    const number: f32 = 3.1415;
    const precision: usize = 2;
    try expect_fmt("3.14e0", "{:1.[1]}", .{ number, precision });
    try expect_fmt("3.14e0", "{:1.[precision]}", .{ .number = number, .precision = precision });
}

test "recursive format function" {
    const R = union(enum) {
        const R = @This();
        Leaf: i32,
        Branch: struct { left: *const R, right: *const R },

        pub fn format(self: R, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
            return switch (self) {
                .Leaf => |n| std.fmt.format(writer, "Leaf({})", .{n}),
                .Branch => |b| std.fmt.format(writer, "Branch({}, {})", .{ b.left, b.right }),
            };
        }
    };

    var r = R{ .Leaf = 1 };
    try expect_fmt("Leaf(1)\n", "{}\n", .{&r});
}
