const std = @import("std");
const ConfigHeader = @This();
const Step = std.Build.Step;
const Allocator = std.mem.Allocator;

pub const Style = union(enum) {
    /// The configure format supported by autotools. It uses `#undef foo` to
    /// mark lines that can be substituted with different values.
    autoconf: std.Build.LazyPath,
    /// The configure format supported by CMake. It uses `@FOO@`, `${}` and
    /// `#cmakedefine` for template substitution.
    cmake: std.Build.LazyPath,
    /// Instead of starting with an input file, start with nothing.
    blank,
    /// Start with nothing, like blank, and output a nasm .asm file.
    nasm,

    pub fn get_path(style: Style) ?std.Build.LazyPath {
        switch (style) {
            .autoconf, .cmake => |s| return s,
            .blank, .nasm => return null,
        }
    }
};

pub const Value = union(enum) {
    undef,
    defined,
    boolean: bool,
    int: i64,
    ident: []const u8,
    string: []const u8,
};

step: Step,
values: std.StringArrayHashMap(Value),
output_file: std.Build.GeneratedFile,

style: Style,
max_bytes: usize,
include_path: []const u8,
include_guard_override: ?[]const u8,

pub const base_id: Step.Id = .config_header;

pub const Options = struct {
    style: Style = .blank,
    max_bytes: usize = 2 * 1024 * 1024,
    include_path: ?[]const u8 = null,
    first_ret_addr: ?usize = null,
    include_guard_override: ?[]const u8 = null,
};

pub fn create(owner: *std.Build, options: Options) *ConfigHeader {
    const config_header = owner.allocator.create(ConfigHeader) catch @panic("OOM");

    var include_path: []const u8 = "config.h";

    if (options.style.get_path()) |s| default_include_path: {
        const sub_path = switch (s) {
            .src_path => |sp| sp.sub_path,
            .generated => break :default_include_path,
            .cwd_relative => |sub_path| sub_path,
            .dependency => |dependency| dependency.sub_path,
        };
        const basename = std.fs.path.basename(sub_path);
        if (std.mem.ends_with(u8, basename, ".h.in")) {
            include_path = basename[0 .. basename.len - 3];
        }
    }

    if (options.include_path) |p| {
        include_path = p;
    }

    const name = if (options.style.get_path()) |s|
        owner.fmt("configure {s} header {s} to {s}", .{
            @tag_name(options.style), s.get_display_name(), include_path,
        })
    else
        owner.fmt("configure {s} header to {s}", .{ @tag_name(options.style), include_path });

    config_header.* = .{
        .step = Step.init(.{
            .id = base_id,
            .name = name,
            .owner = owner,
            .makeFn = make,
            .first_ret_addr = options.first_ret_addr orelse @returnAddress(),
        }),
        .style = options.style,
        .values = std.StringArrayHashMap(Value).init(owner.allocator),

        .max_bytes = options.max_bytes,
        .include_path = include_path,
        .include_guard_override = options.include_guard_override,
        .output_file = .{ .step = &config_header.step },
    };

    return config_header;
}

pub fn add_values(config_header: *ConfigHeader, values: anytype) void {
    return add_values_inner(config_header, values) catch @panic("OOM");
}

pub fn get_output(config_header: *ConfigHeader) std.Build.LazyPath {
    return .{ .generated = .{ .file = &config_header.output_file } };
}

fn add_values_inner(config_header: *ConfigHeader, values: anytype) !void {
    inline for (@typeInfo(@TypeOf(values)).Struct.fields) |field| {
        try put_value(config_header, field.name, field.type, @field(values, field.name));
    }
}

fn put_value(config_header: *ConfigHeader, field_name: []const u8, comptime T: type, v: T) !void {
    switch (@typeInfo(T)) {
        .Null => {
            try config_header.values.put(field_name, .undef);
        },
        .Void => {
            try config_header.values.put(field_name, .defined);
        },
        .Bool => {
            try config_header.values.put(field_name, .{ .boolean = v });
        },
        .Int => {
            try config_header.values.put(field_name, .{ .int = v });
        },
        .ComptimeInt => {
            try config_header.values.put(field_name, .{ .int = v });
        },
        .EnumLiteral => {
            try config_header.values.put(field_name, .{ .ident = @tag_name(v) });
        },
        .Optional => {
            if (v) |x| {
                return put_value(config_header, field_name, @TypeOf(x), x);
            } else {
                try config_header.values.put(field_name, .undef);
            }
        },
        .Pointer => |ptr| {
            switch (@typeInfo(ptr.child)) {
                .Array => |array| {
                    if (ptr.size == .One and array.child == u8) {
                        try config_header.values.put(field_name, .{ .string = v });
                        return;
                    }
                },
                .Int => {
                    if (ptr.size == .Slice and ptr.child == u8) {
                        try config_header.values.put(field_name, .{ .string = v });
                        return;
                    }
                },
                else => {},
            }

            @compile_error("unsupported ConfigHeader value type: " ++ @type_name(T));
        },
        else => @compile_error("unsupported ConfigHeader value type: " ++ @type_name(T)),
    }
}

fn make(step: *Step, prog_node: std.Progress.Node) !void {
    _ = prog_node;
    const b = step.owner;
    const config_header: *ConfigHeader = @fieldParentPtr("step", step);
    const gpa = b.allocator;
    const arena = b.allocator;

    var man = b.graph.cache.obtain();
    defer man.deinit();

    // Random bytes to make ConfigHeader unique. Refresh this with new
    // random bytes when ConfigHeader implementation is modified in a
    // non-backwards-compatible way.
    man.hash.add(@as(u32, 0xdef08d23));
    man.hash.add_bytes(config_header.include_path);
    man.hash.add_optional_bytes(config_header.include_guard_override);

    var output = std.ArrayList(u8).init(gpa);
    defer output.deinit();

    const header_text = "This file was generated by ConfigHeader using the Zig Build System.";
    const c_generated_line = "/* " ++ header_text ++ " */\n";
    const asm_generated_line = "; " ++ header_text ++ "\n";

    switch (config_header.style) {
        .autoconf => |file_source| {
            try output.append_slice(c_generated_line);
            const src_path = file_source.get_path2(b, step);
            const contents = std.fs.cwd().read_file_alloc(arena, src_path, config_header.max_bytes) catch |err| {
                return step.fail("unable to read autoconf input file '{s}': {s}", .{
                    src_path, @errorName(err),
                });
            };
            try render_autoconf(step, contents, &output, config_header.values, src_path);
        },
        .cmake => |file_source| {
            try output.append_slice(c_generated_line);
            const src_path = file_source.get_path2(b, step);
            const contents = std.fs.cwd().read_file_alloc(arena, src_path, config_header.max_bytes) catch |err| {
                return step.fail("unable to read cmake input file '{s}': {s}", .{
                    src_path, @errorName(err),
                });
            };
            try render_cmake(step, contents, &output, config_header.values, src_path);
        },
        .blank => {
            try output.append_slice(c_generated_line);
            try render_blank(&output, config_header.values, config_header.include_path, config_header.include_guard_override);
        },
        .nasm => {
            try output.append_slice(asm_generated_line);
            try render_nasm(&output, config_header.values);
        },
    }

    man.hash.add_bytes(output.items);

    if (try step.cache_hit(&man)) {
        const digest = man.final();
        config_header.output_file.path = try b.cache_root.join(arena, &.{
            "o", &digest, config_header.include_path,
        });
        return;
    }

    const digest = man.final();

    // If output_path has directory parts, deal with them.  Example:
    // output_dir is zig-cache/o/HASH
    // output_path is libavutil/avconfig.h
    // We want to open directory zig-cache/o/HASH/libavutil/
    // but keep output_dir as zig-cache/o/HASH for -I include
    const sub_path = b.path_join(&.{ "o", &digest, config_header.include_path });
    const sub_path_dirname = std.fs.path.dirname(sub_path).?;

    b.cache_root.handle.make_path(sub_path_dirname) catch |err| {
        return step.fail("unable to make path '{}{s}': {s}", .{
            b.cache_root, sub_path_dirname, @errorName(err),
        });
    };

    b.cache_root.handle.write_file(.{ .sub_path = sub_path, .data = output.items }) catch |err| {
        return step.fail("unable to write file '{}{s}': {s}", .{
            b.cache_root, sub_path, @errorName(err),
        });
    };

    config_header.output_file.path = try b.cache_root.join(arena, &.{sub_path});
    try man.write_manifest();
}

fn render_autoconf(
    step: *Step,
    contents: []const u8,
    output: *std.ArrayList(u8),
    values: std.StringArrayHashMap(Value),
    src_path: []const u8,
) !void {
    var values_copy = try values.clone();
    defer values_copy.deinit();

    var any_errors = false;
    var line_index: u32 = 0;
    var line_it = std.mem.split_scalar(u8, contents, '\n');
    while (line_it.next()) |line| : (line_index += 1) {
        if (!std.mem.starts_with(u8, line, "#")) {
            try output.append_slice(line);
            try output.append_slice("\n");
            continue;
        }
        var it = std.mem.tokenize_any(u8, line[1..], " \t\r");
        const undef = it.next().?;
        if (!std.mem.eql(u8, undef, "undef")) {
            try output.append_slice(line);
            try output.append_slice("\n");
            continue;
        }
        const name = it.rest();
        const kv = values_copy.fetch_swap_remove(name) orelse {
            try step.add_error("{s}:{d}: error: unspecified config header value: '{s}'", .{
                src_path, line_index + 1, name,
            });
            any_errors = true;
            continue;
        };
        try render_value_c(output, name, kv.value);
    }

    for (values_copy.keys()) |name| {
        try step.add_error("{s}: error: config header value unused: '{s}'", .{ src_path, name });
        any_errors = true;
    }

    if (any_errors) {
        return error.MakeFailed;
    }
}

fn render_cmake(
    step: *Step,
    contents: []const u8,
    output: *std.ArrayList(u8),
    values: std.StringArrayHashMap(Value),
    src_path: []const u8,
) !void {
    const build = step.owner;
    const allocator = build.allocator;

    var values_copy = try values.clone();
    defer values_copy.deinit();

    var any_errors = false;
    var line_index: u32 = 0;
    var line_it = std.mem.split_scalar(u8, contents, '\n');
    while (line_it.next()) |raw_line| : (line_index += 1) {
        const last_line = line_it.index == line_it.buffer.len;

        const line = expand_variables_cmake(allocator, raw_line, values) catch |err| switch (err) {
            error.InvalidCharacter => {
                try step.add_error("{s}:{d}: error: invalid character in a variable name", .{
                    src_path, line_index + 1,
                });
                any_errors = true;
                continue;
            },
            else => {
                try step.add_error("{s}:{d}: unable to substitute variable: error: {s}", .{
                    src_path, line_index + 1, @errorName(err),
                });
                any_errors = true;
                continue;
            },
        };
        defer allocator.free(line);

        if (!std.mem.starts_with(u8, line, "#")) {
            try output.append_slice(line);
            if (!last_line) {
                try output.append_slice("\n");
            }
            continue;
        }
        var it = std.mem.tokenize_any(u8, line[1..], " \t\r");
        const cmakedefine = it.next().?;
        if (!std.mem.eql(u8, cmakedefine, "cmakedefine") and
            !std.mem.eql(u8, cmakedefine, "cmakedefine01"))
        {
            try output.append_slice(line);
            if (!last_line) {
                try output.append_slice("\n");
            }
            continue;
        }

        const booldefine = std.mem.eql(u8, cmakedefine, "cmakedefine01");

        const name = it.next() orelse {
            try step.add_error("{s}:{d}: error: missing define name", .{
                src_path, line_index + 1,
            });
            any_errors = true;
            continue;
        };
        var value = values_copy.get(name) orelse blk: {
            if (booldefine) {
                break :blk Value{ .int = 0 };
            }
            break :blk Value.undef;
        };

        value = blk: {
            switch (value) {
                .boolean => |b| {
                    if (!b) {
                        break :blk Value.undef;
                    }
                },
                .int => |i| {
                    if (i == 0) {
                        break :blk Value.undef;
                    }
                },
                .string => |string| {
                    if (string.len == 0) {
                        break :blk Value.undef;
                    }
                },

                else => {},
            }
            break :blk value;
        };

        if (booldefine) {
            value = blk: {
                switch (value) {
                    .undef => {
                        break :blk Value{ .boolean = false };
                    },
                    .defined => {
                        break :blk Value{ .boolean = false };
                    },
                    .boolean => |b| {
                        break :blk Value{ .boolean = b };
                    },
                    .int => |i| {
                        break :blk Value{ .boolean = i != 0 };
                    },
                    .string => |string| {
                        break :blk Value{ .boolean = string.len != 0 };
                    },

                    else => {
                        break :blk Value{ .boolean = false };
                    },
                }
            };
        } else if (value != Value.undef) {
            value = Value{ .ident = it.rest() };
        }

        try render_value_c(output, name, value);
    }

    if (any_errors) {
        return error.HeaderConfigFailed;
    }
}

fn render_blank(
    output: *std.ArrayList(u8),
    defines: std.StringArrayHashMap(Value),
    include_path: []const u8,
    include_guard_override: ?[]const u8,
) !void {
    const include_guard_name = include_guard_override orelse blk: {
        const name = try output.allocator.dupe(u8, include_path);
        for (name) |*byte| {
            switch (byte.*) {
                'a'...'z' => byte.* = byte.* - 'a' + 'A',
                'A'...'Z', '0'...'9' => continue,
                else => byte.* = '_',
            }
        }
        break :blk name;
    };

    try output.append_slice("#ifndef ");
    try output.append_slice(include_guard_name);
    try output.append_slice("\n#define ");
    try output.append_slice(include_guard_name);
    try output.append_slice("\n");

    const values = defines.values();
    for (defines.keys(), 0..) |name, i| {
        try render_value_c(output, name, values[i]);
    }

    try output.append_slice("#endif /* ");
    try output.append_slice(include_guard_name);
    try output.append_slice(" */\n");
}

fn render_nasm(output: *std.ArrayList(u8), defines: std.StringArrayHashMap(Value)) !void {
    const values = defines.values();
    for (defines.keys(), 0..) |name, i| {
        try render_value_nasm(output, name, values[i]);
    }
}

fn render_value_c(output: *std.ArrayList(u8), name: []const u8, value: Value) !void {
    switch (value) {
        .undef => {
            try output.append_slice("/* #undef ");
            try output.append_slice(name);
            try output.append_slice(" */\n");
        },
        .defined => {
            try output.append_slice("#define ");
            try output.append_slice(name);
            try output.append_slice("\n");
        },
        .boolean => |b| {
            try output.append_slice("#define ");
            try output.append_slice(name);
            try output.append_slice(if (b) " 1\n" else " 0\n");
        },
        .int => |i| {
            try output.writer().print("#define {s} {d}\n", .{ name, i });
        },
        .ident => |ident| {
            try output.writer().print("#define {s} {s}\n", .{ name, ident });
        },
        .string => |string| {
            // TODO: use C-specific escaping instead of zig string literals
            try output.writer().print("#define {s} \"{}\"\n", .{ name, std.zig.fmt_escapes(string) });
        },
    }
}

fn render_value_nasm(output: *std.ArrayList(u8), name: []const u8, value: Value) !void {
    switch (value) {
        .undef => {
            try output.append_slice("; %undef ");
            try output.append_slice(name);
            try output.append_slice("\n");
        },
        .defined => {
            try output.append_slice("%define ");
            try output.append_slice(name);
            try output.append_slice("\n");
        },
        .boolean => |b| {
            try output.append_slice("%define ");
            try output.append_slice(name);
            try output.append_slice(if (b) " 1\n" else " 0\n");
        },
        .int => |i| {
            try output.writer().print("%define {s} {d}\n", .{ name, i });
        },
        .ident => |ident| {
            try output.writer().print("%define {s} {s}\n", .{ name, ident });
        },
        .string => |string| {
            // TODO: use nasm-specific escaping instead of zig string literals
            try output.writer().print("%define {s} \"{}\"\n", .{ name, std.zig.fmt_escapes(string) });
        },
    }
}

fn expand_variables_cmake(
    allocator: Allocator,
    contents: []const u8,
    values: std.StringArrayHashMap(Value),
) ![]const u8 {
    var result = std.ArrayList(u8).init(allocator);
    errdefer result.deinit();

    const valid_varname_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/_.+-";
    const open_var = "${";

    var curr: usize = 0;
    var source_offset: usize = 0;
    const Position = struct {
        source: usize,
        target: usize,
    };
    var var_stack = std.ArrayList(Position).init(allocator);
    defer var_stack.deinit();
    loop: while (curr < contents.len) : (curr += 1) {
        switch (contents[curr]) {
            '@' => blk: {
                if (std.mem.index_of_scalar_pos(u8, contents, curr + 1, '@')) |close_pos| {
                    if (close_pos == curr + 1) {
                        // closed immediately, preserve as a literal
                        break :blk;
                    }
                    const valid_varname_end = std.mem.index_of_none_pos(u8, contents, curr + 1, valid_varname_chars) orelse 0;
                    if (valid_varname_end != close_pos) {
                        // contains invalid characters, preserve as a literal
                        break :blk;
                    }

                    const key = contents[curr + 1 .. close_pos];
                    const value = values.get(key) orelse .undef;
                    const missing = contents[source_offset..curr];
                    try result.append_slice(missing);
                    switch (value) {
                        .undef, .defined => {},
                        .boolean => |b| {
                            try result.append(if (b) '1' else '0');
                        },
                        .int => |i| {
                            try result.writer().print("{d}", .{i});
                        },
                        .ident, .string => |s| {
                            try result.append_slice(s);
                        },
                    }

                    curr = close_pos;
                    source_offset = close_pos + 1;

                    continue :loop;
                }
            },
            '$' => blk: {
                const next = curr + 1;
                if (next == contents.len or contents[next] != '{') {
                    // no open bracket detected, preserve as a literal
                    break :blk;
                }
                const missing = contents[source_offset..curr];
                try result.append_slice(missing);
                try result.append_slice(open_var);

                source_offset = curr + open_var.len;
                curr = next;
                try var_stack.append(Position{
                    .source = curr,
                    .target = result.items.len - open_var.len,
                });

                continue :loop;
            },
            '}' => blk: {
                if (var_stack.items.len == 0) {
                    // no open bracket, preserve as a literal
                    break :blk;
                }
                const open_pos = var_stack.pop();
                if (source_offset == open_pos.source) {
                    source_offset += open_var.len;
                }
                const missing = contents[source_offset..curr];
                try result.append_slice(missing);

                const key_start = open_pos.target + open_var.len;
                const key = result.items[key_start..];
                const value = values.get(key) orelse .undef;
                result.shrink_retaining_capacity(result.items.len - key.len - open_var.len);
                switch (value) {
                    .undef, .defined => {},
                    .boolean => |b| {
                        try result.append(if (b) '1' else '0');
                    },
                    .int => |i| {
                        try result.writer().print("{d}", .{i});
                    },
                    .ident, .string => |s| {
                        try result.append_slice(s);
                    },
                }

                source_offset = curr + 1;

                continue :loop;
            },
            '\\' => {
                // backslash is not considered a special character
                continue :loop;
            },
            else => {},
        }

        if (var_stack.items.len > 0 and std.mem.index_of_scalar(u8, valid_varname_chars, contents[curr]) == null) {
            return error.InvalidCharacter;
        }
    }

    if (source_offset != contents.len) {
        const missing = contents[source_offset..];
        try result.append_slice(missing);
    }

    return result.to_owned_slice();
}

fn test_replace_variables(
    allocator: Allocator,
    contents: []const u8,
    expected: []const u8,
    values: std.StringArrayHashMap(Value),
) !void {
    const actual = try expand_variables_cmake(allocator, contents, values);
    defer allocator.free(actual);

    try std.testing.expect_equal_strings(expected, actual);
}

test "expand_variables_cmake simple cases" {
    const allocator = std.testing.allocator;
    var values = std.StringArrayHashMap(Value).init(allocator);
    defer values.deinit();

    try values.put_no_clobber("undef", .undef);
    try values.put_no_clobber("defined", .defined);
    try values.put_no_clobber("true", Value{ .boolean = true });
    try values.put_no_clobber("false", Value{ .boolean = false });
    try values.put_no_clobber("int", Value{ .int = 42 });
    try values.put_no_clobber("ident", Value{ .string = "value" });
    try values.put_no_clobber("string", Value{ .string = "text" });

    // empty strings are preserved
    try test_replace_variables(allocator, "", "", values);

    // line with misc content is preserved
    try test_replace_variables(allocator, "no substitution", "no substitution", values);

    // empty ${} wrapper is removed
    try test_replace_variables(allocator, "${}", "", values);

    // empty @ sigils are preserved
    try test_replace_variables(allocator, "@", "@", values);
    try test_replace_variables(allocator, "@@", "@@", values);
    try test_replace_variables(allocator, "@@@", "@@@", values);
    try test_replace_variables(allocator, "@@@@", "@@@@", values);

    // simple substitution
    try test_replace_variables(allocator, "@undef@", "", values);
    try test_replace_variables(allocator, "${undef}", "", values);
    try test_replace_variables(allocator, "@defined@", "", values);
    try test_replace_variables(allocator, "${defined}", "", values);
    try test_replace_variables(allocator, "@true@", "1", values);
    try test_replace_variables(allocator, "${true}", "1", values);
    try test_replace_variables(allocator, "@false@", "0", values);
    try test_replace_variables(allocator, "${false}", "0", values);
    try test_replace_variables(allocator, "@int@", "42", values);
    try test_replace_variables(allocator, "${int}", "42", values);
    try test_replace_variables(allocator, "@ident@", "value", values);
    try test_replace_variables(allocator, "${ident}", "value", values);
    try test_replace_variables(allocator, "@string@", "text", values);
    try test_replace_variables(allocator, "${string}", "text", values);

    // double packed substitution
    try test_replace_variables(allocator, "@string@@string@", "texttext", values);
    try test_replace_variables(allocator, "${string}${string}", "texttext", values);

    // triple packed substitution
    try test_replace_variables(allocator, "@string@@int@@string@", "text42text", values);
    try test_replace_variables(allocator, "@string@${int}@string@", "text42text", values);
    try test_replace_variables(allocator, "${string}@int@${string}", "text42text", values);
    try test_replace_variables(allocator, "${string}${int}${string}", "text42text", values);

    // double separated substitution
    try test_replace_variables(allocator, "@int@.@int@", "42.42", values);
    try test_replace_variables(allocator, "${int}.${int}", "42.42", values);

    // triple separated substitution
    try test_replace_variables(allocator, "@int@.@true@.@int@", "42.1.42", values);
    try test_replace_variables(allocator, "@int@.${true}.@int@", "42.1.42", values);
    try test_replace_variables(allocator, "${int}.@true@.${int}", "42.1.42", values);
    try test_replace_variables(allocator, "${int}.${true}.${int}", "42.1.42", values);

    // misc prefix is preserved
    try test_replace_variables(allocator, "false is @false@", "false is 0", values);
    try test_replace_variables(allocator, "false is ${false}", "false is 0", values);

    // misc suffix is preserved
    try test_replace_variables(allocator, "@true@ is true", "1 is true", values);
    try test_replace_variables(allocator, "${true} is true", "1 is true", values);

    // surrounding content is preserved
    try test_replace_variables(allocator, "what is 6*7? @int@!", "what is 6*7? 42!", values);
    try test_replace_variables(allocator, "what is 6*7? ${int}!", "what is 6*7? 42!", values);

    // incomplete key is preserved
    try test_replace_variables(allocator, "@undef", "@undef", values);
    try test_replace_variables(allocator, "${undef", "${undef", values);
    try test_replace_variables(allocator, "{undef}", "{undef}", values);
    try test_replace_variables(allocator, "undef@", "undef@", values);
    try test_replace_variables(allocator, "undef}", "undef}", values);

    // unknown key is removed
    try test_replace_variables(allocator, "@bad@", "", values);
    try test_replace_variables(allocator, "${bad}", "", values);
}

test "expand_variables_cmake edge cases" {
    const allocator = std.testing.allocator;
    var values = std.StringArrayHashMap(Value).init(allocator);
    defer values.deinit();

    // special symbols
    try values.put_no_clobber("at", Value{ .string = "@" });
    try values.put_no_clobber("dollar", Value{ .string = "$" });
    try values.put_no_clobber("underscore", Value{ .string = "_" });

    // basic value
    try values.put_no_clobber("string", Value{ .string = "text" });

    // proxy case values
    try values.put_no_clobber("string_proxy", Value{ .string = "string" });
    try values.put_no_clobber("string_at", Value{ .string = "@string@" });
    try values.put_no_clobber("string_curly", Value{ .string = "{string}" });
    try values.put_no_clobber("string_var", Value{ .string = "${string}" });

    // stack case values
    try values.put_no_clobber("nest_underscore_proxy", Value{ .string = "underscore" });
    try values.put_no_clobber("nest_proxy", Value{ .string = "nest_underscore_proxy" });

    // @-vars resolved only when they wrap valid characters, otherwise considered literals
    try test_replace_variables(allocator, "@@string@@", "@text@", values);
    try test_replace_variables(allocator, "@${string}@", "@text@", values);

    // @-vars are resolved inside ${}-vars
    try test_replace_variables(allocator, "${@string_proxy@}", "text", values);

    // expanded variables are considered strings after expansion
    try test_replace_variables(allocator, "@string_at@", "@string@", values);
    try test_replace_variables(allocator, "${string_at}", "@string@", values);
    try test_replace_variables(allocator, "$@string_curly@", "${string}", values);
    try test_replace_variables(allocator, "$${string_curly}", "${string}", values);
    try test_replace_variables(allocator, "${string_var}", "${string}", values);
    try test_replace_variables(allocator, "@string_var@", "${string}", values);
    try test_replace_variables(allocator, "${dollar}{${string}}", "${text}", values);
    try test_replace_variables(allocator, "@dollar@{${string}}", "${text}", values);
    try test_replace_variables(allocator, "@dollar@{@string@}", "${text}", values);

    // when expanded variables contain invalid characters, they prevent further expansion
    try test_replace_variables(allocator, "${${string_var}}", "", values);
    try test_replace_variables(allocator, "${@string_var@}", "", values);

    // nested expanded variables are expanded from the inside out
    try test_replace_variables(allocator, "${string${underscore}proxy}", "string", values);
    try test_replace_variables(allocator, "${string@underscore@proxy}", "string", values);

    // nested vars are only expanded when ${} is closed
    try test_replace_variables(allocator, "@nest@underscore@proxy@", "underscore", values);
    try test_replace_variables(allocator, "${nest${underscore}proxy}", "nest_underscore_proxy", values);
    try test_replace_variables(allocator, "@nest@@nest_underscore@underscore@proxy@@proxy@", "underscore", values);
    try test_replace_variables(allocator, "${nest${${nest_underscore${underscore}proxy}}proxy}", "nest_underscore_proxy", values);

    // invalid characters lead to an error
    try std.testing.expect_error(error.InvalidCharacter, test_replace_variables(allocator, "${str*ing}", "", values));
    try std.testing.expect_error(error.InvalidCharacter, test_replace_variables(allocator, "${str$ing}", "", values));
    try std.testing.expect_error(error.InvalidCharacter, test_replace_variables(allocator, "${str@ing}", "", values));
}

test "expand_variables_cmake escaped characters" {
    const allocator = std.testing.allocator;
    var values = std.StringArrayHashMap(Value).init(allocator);
    defer values.deinit();

    try values.put_no_clobber("string", Value{ .string = "text" });

    // backslash is an invalid character for @ lookup
    try test_replace_variables(allocator, "\\@string\\@", "\\@string\\@", values);

    // backslash is preserved, but doesn't affect ${} variable expansion
    try test_replace_variables(allocator, "\\${string}", "\\text", values);

    // backslash breaks ${} opening bracket identification
    try test_replace_variables(allocator, "$\\{string}", "$\\{string}", values);

    // backslash is skipped when checking for invalid characters, yet it mangles the key
    try test_replace_variables(allocator, "${string\\}", "", values);
}
