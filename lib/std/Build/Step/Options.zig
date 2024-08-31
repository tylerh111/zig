const std = @import("std");
const builtin = @import("builtin");
const fs = std.fs;
const Step = std.Build.Step;
const GeneratedFile = std.Build.GeneratedFile;
const LazyPath = std.Build.LazyPath;

const Options = @This();

pub const base_id: Step.Id = .options;

step: Step,
generated_file: GeneratedFile,

contents: std.ArrayList(u8),
args: std.ArrayList(Arg),
encountered_types: std.StringHashMap(void),

pub fn create(owner: *std.Build) *Options {
    const options = owner.allocator.create(Options) catch @panic("OOM");
    options.* = .{
        .step = Step.init(.{
            .id = base_id,
            .name = "options",
            .owner = owner,
            .makeFn = make,
        }),
        .generated_file = undefined,
        .contents = std.ArrayList(u8).init(owner.allocator),
        .args = std.ArrayList(Arg).init(owner.allocator),
        .encountered_types = std.StringHashMap(void).init(owner.allocator),
    };
    options.generated_file = .{ .step = &options.step };

    return options;
}

pub fn add_option(options: *Options, comptime T: type, name: []const u8, value: T) void {
    return add_option_fallible(options, T, name, value) catch @panic("unhandled error");
}

fn add_option_fallible(options: *Options, comptime T: type, name: []const u8, value: T) !void {
    const out = options.contents.writer();
    try print_type(options, out, T, value, 0, name);
}

fn print_type(options: *Options, out: anytype, comptime T: type, value: T, indent: u8, name: ?[]const u8) !void {
    switch (T) {
        []const []const u8 => {
            if (name) |payload| {
                try out.print("pub const {}: []const []const u8 = ", .{std.zig.fmt_id(payload)});
            }

            try out.write_all("&[_][]const u8{\n");

            for (value) |slice| {
                try out.write_byte_ntimes(' ', indent);
                try out.print("    \"{}\",\n", .{std.zig.fmt_escapes(slice)});
            }

            if (name != null) {
                try out.write_all("};\n");
            } else {
                try out.write_all("},\n");
            }

            return;
        },
        []const u8 => {
            if (name) |some| {
                try out.print("pub const {}: []const u8 = \"{}\";", .{ std.zig.fmt_id(some), std.zig.fmt_escapes(value) });
            } else {
                try out.print("\"{}\",", .{std.zig.fmt_escapes(value)});
            }
            return out.write_all("\n");
        },
        [:0]const u8 => {
            if (name) |some| {
                try out.print("pub const {}: [:0]const u8 = \"{}\";", .{ std.zig.fmt_id(some), std.zig.fmt_escapes(value) });
            } else {
                try out.print("\"{}\",", .{std.zig.fmt_escapes(value)});
            }
            return out.write_all("\n");
        },
        ?[]const u8 => {
            if (name) |some| {
                try out.print("pub const {}: ?[]const u8 = ", .{std.zig.fmt_id(some)});
            }

            if (value) |payload| {
                try out.print("\"{}\"", .{std.zig.fmt_escapes(payload)});
            } else {
                try out.write_all("null");
            }

            if (name != null) {
                try out.write_all(";\n");
            } else {
                try out.write_all(",\n");
            }
            return;
        },
        ?[:0]const u8 => {
            if (name) |some| {
                try out.print("pub const {}: ?[:0]const u8 = ", .{std.zig.fmt_id(some)});
            }

            if (value) |payload| {
                try out.print("\"{}\"", .{std.zig.fmt_escapes(payload)});
            } else {
                try out.write_all("null");
            }

            if (name != null) {
                try out.write_all(";\n");
            } else {
                try out.write_all(",\n");
            }
            return;
        },
        std.SemanticVersion => {
            if (name) |some| {
                try out.print("pub const {}: @import(\"std\").SemanticVersion = ", .{std.zig.fmt_id(some)});
            }

            try out.write_all(".{\n");
            try out.write_byte_ntimes(' ', indent);
            try out.print("    .major = {d},\n", .{value.major});
            try out.write_byte_ntimes(' ', indent);
            try out.print("    .minor = {d},\n", .{value.minor});
            try out.write_byte_ntimes(' ', indent);
            try out.print("    .patch = {d},\n", .{value.patch});

            if (value.pre) |some| {
                try out.write_byte_ntimes(' ', indent);
                try out.print("    .pre = \"{}\",\n", .{std.zig.fmt_escapes(some)});
            }
            if (value.build) |some| {
                try out.write_byte_ntimes(' ', indent);
                try out.print("    .build = \"{}\",\n", .{std.zig.fmt_escapes(some)});
            }

            if (name != null) {
                try out.write_all("};\n");
            } else {
                try out.write_all("},\n");
            }
            return;
        },
        else => {},
    }

    switch (@typeInfo(T)) {
        .Array => {
            if (name) |some| {
                try out.print("pub const {}: {s} = ", .{ std.zig.fmt_id(some), @type_name(T) });
            }

            try out.print("{s} {{\n", .{@type_name(T)});
            for (value) |item| {
                try out.write_byte_ntimes(' ', indent + 4);
                try print_type(options, out, @TypeOf(item), item, indent + 4, null);
            }
            try out.write_byte_ntimes(' ', indent);
            try out.write_all("}");

            if (name != null) {
                try out.write_all(";\n");
            } else {
                try out.write_all(",\n");
            }
            return;
        },
        .Pointer => |p| {
            if (p.size != .Slice) {
                @compile_error("Non-slice pointers are not yet supported in build options");
            }

            if (name) |some| {
                try out.print("pub const {}: {s} = ", .{ std.zig.fmt_id(some), @type_name(T) });
            }

            try out.print("&[_]{s} {{\n", .{@type_name(p.child)});
            for (value) |item| {
                try out.write_byte_ntimes(' ', indent + 4);
                try print_type(options, out, @TypeOf(item), item, indent + 4, null);
            }
            try out.write_byte_ntimes(' ', indent);
            try out.write_all("}");

            if (name != null) {
                try out.write_all(";\n");
            } else {
                try out.write_all(",\n");
            }
            return;
        },
        .Optional => {
            if (name) |some| {
                try out.print("pub const {}: {s} = ", .{ std.zig.fmt_id(some), @type_name(T) });
            }

            if (value) |inner| {
                try print_type(options, out, @TypeOf(inner), inner, indent + 4, null);
                // Pop the '\n' and ',' chars
                _ = options.contents.pop();
                _ = options.contents.pop();
            } else {
                try out.write_all("null");
            }

            if (name != null) {
                try out.write_all(";\n");
            } else {
                try out.write_all(",\n");
            }
            return;
        },
        .Void,
        .Bool,
        .Int,
        .ComptimeInt,
        .Float,
        .Null,
        => {
            if (name) |some| {
                try out.print("pub const {}: {s} = {any};\n", .{ std.zig.fmt_id(some), @type_name(T), value });
            } else {
                try out.print("{any},\n", .{value});
            }
            return;
        },
        .Enum => |info| {
            try print_enum(options, out, T, info, indent);

            if (name) |some| {
                try out.print("pub const {}: {} = .{p_};\n", .{
                    std.zig.fmt_id(some),
                    std.zig.fmt_id(@type_name(T)),
                    std.zig.fmt_id(@tag_name(value)),
                });
            }
            return;
        },
        .Struct => |info| {
            try print_struct(options, out, T, info, indent);

            if (name) |some| {
                try out.print("pub const {}: {} = ", .{
                    std.zig.fmt_id(some),
                    std.zig.fmt_id(@type_name(T)),
                });
                try print_struct_value(options, out, info, value, indent);
            }
            return;
        },
        else => @compile_error(std.fmt.comptime_print("`{s}` are not yet supported as build options", .{@tag_name(@typeInfo(T))})),
    }
}

fn print_user_defined_type(options: *Options, out: anytype, comptime T: type, indent: u8) !void {
    switch (@typeInfo(T)) {
        .Enum => |info| {
            return try print_enum(options, out, T, info, indent);
        },
        .Struct => |info| {
            return try print_struct(options, out, T, info, indent);
        },
        else => {},
    }
}

fn print_enum(options: *Options, out: anytype, comptime T: type, comptime val: std.builtin.Type.Enum, indent: u8) !void {
    const gop = try options.encountered_types.get_or_put(@type_name(T));
    if (gop.found_existing) return;

    try out.write_byte_ntimes(' ', indent);
    try out.print("pub const {} = enum ({s}) {{\n", .{ std.zig.fmt_id(@type_name(T)), @type_name(val.tag_type) });

    inline for (val.fields) |field| {
        try out.write_byte_ntimes(' ', indent);
        try out.print("    {p} = {d},\n", .{ std.zig.fmt_id(field.name), field.value });
    }

    if (!val.is_exhaustive) {
        try out.write_byte_ntimes(' ', indent);
        try out.write_all("    _,\n");
    }

    try out.write_byte_ntimes(' ', indent);
    try out.write_all("};\n");
}

fn print_struct(options: *Options, out: anytype, comptime T: type, comptime val: std.builtin.Type.Struct, indent: u8) !void {
    const gop = try options.encountered_types.get_or_put(@type_name(T));
    if (gop.found_existing) return;

    try out.write_byte_ntimes(' ', indent);
    try out.print("pub const {} = ", .{std.zig.fmt_id(@type_name(T))});

    switch (val.layout) {
        .@"extern" => try out.write_all("extern struct"),
        .@"packed" => try out.write_all("packed struct"),
        else => try out.write_all("struct"),
    }

    try out.write_all(" {\n");

    inline for (val.fields) |field| {
        try out.write_byte_ntimes(' ', indent);

        const type_name = @type_name(field.type);

        // If the type name doesn't contains a '.' the type is from zig builtins.
        if (std.mem.contains_at_least(u8, type_name, 1, ".")) {
            try out.print("    {p_}: {}", .{ std.zig.fmt_id(field.name), std.zig.fmt_id(type_name) });
        } else {
            try out.print("    {p_}: {s}", .{ std.zig.fmt_id(field.name), type_name });
        }

        if (field.default_value != null) {
            const default_value = @as(*field.type, @ptr_cast(@align_cast(@constCast(field.default_value.?)))).*;

            try out.write_all(" = ");
            switch (@typeInfo(@TypeOf(default_value))) {
                .Enum => try out.print(".{s},\n", .{@tag_name(default_value)}),
                .Struct => |info| {
                    try print_struct_value(options, out, info, default_value, indent + 4);
                },
                else => try print_type(options, out, @TypeOf(default_value), default_value, indent, null),
            }
        } else {
            try out.write_all(",\n");
        }
    }

    // TODO: write declarations

    try out.write_byte_ntimes(' ', indent);
    try out.write_all("};\n");

    inline for (val.fields) |field| {
        try print_user_defined_type(options, out, field.type, 0);
    }
}

fn print_struct_value(options: *Options, out: anytype, comptime struct_val: std.builtin.Type.Struct, val: anytype, indent: u8) !void {
    try out.write_all(".{\n");

    if (struct_val.is_tuple) {
        inline for (struct_val.fields) |field| {
            try out.write_byte_ntimes(' ', indent);
            try print_type(options, out, @TypeOf(@field(val, field.name)), @field(val, field.name), indent, null);
        }
    } else {
        inline for (struct_val.fields) |field| {
            try out.write_byte_ntimes(' ', indent);
            try out.print("    .{p_} = ", .{std.zig.fmt_id(field.name)});

            const field_name = @field(val, field.name);
            switch (@typeInfo(@TypeOf(field_name))) {
                .Enum => try out.print(".{s},\n", .{@tag_name(field_name)}),
                .Struct => |struct_info| {
                    try print_struct_value(options, out, struct_info, field_name, indent + 4);
                },
                else => try print_type(options, out, @TypeOf(field_name), field_name, indent, null),
            }
        }
    }

    if (indent == 0) {
        try out.write_all("};\n");
    } else {
        try out.write_byte_ntimes(' ', indent);
        try out.write_all("},\n");
    }
}

/// The value is the path in the cache dir.
/// Adds a dependency automatically.
pub fn add_option_path(
    options: *Options,
    name: []const u8,
    path: LazyPath,
) void {
    options.args.append(.{
        .name = options.step.owner.dupe(name),
        .path = path.dupe(options.step.owner),
    }) catch @panic("OOM");
    path.add_step_dependencies(&options.step);
}

/// Deprecated: use `add_option_path(options, name, artifact.get_emitted_bin())` instead.
pub fn add_option_artifact(options: *Options, name: []const u8, artifact: *Step.Compile) void {
    return add_option_path(options, name, artifact.get_emitted_bin());
}

pub fn create_module(options: *Options) *std.Build.Module {
    return options.step.owner.create_module(.{
        .root_source_file = options.get_output(),
    });
}

/// deprecated: use `get_output`
pub const get_source = get_output;

/// Returns the main artifact of this Build Step which is a Zig source file
/// generated from the key-value pairs of the Options.
pub fn get_output(options: *Options) LazyPath {
    return .{ .generated = .{ .file = &options.generated_file } };
}

fn make(step: *Step, prog_node: std.Progress.Node) !void {
    // This step completes so quickly that no progress is necessary.
    _ = prog_node;

    const b = step.owner;
    const options: *Options = @fieldParentPtr("step", step);

    for (options.args.items) |item| {
        options.add_option(
            []const u8,
            item.name,
            item.path.get_path2(b, step),
        );
    }

    const basename = "options.zig";

    // Hash contents to file name.
    var hash = b.graph.cache.hash;
    // Random bytes to make unique. Refresh this with new random bytes when
    // implementation is modified in a non-backwards-compatible way.
    hash.add(@as(u32, 0xad95e922));
    hash.add_bytes(options.contents.items);
    const sub_path = "c" ++ fs.path.sep_str ++ hash.final() ++ fs.path.sep_str ++ basename;

    options.generated_file.path = try b.cache_root.join(b.allocator, &.{sub_path});

    // Optimize for the hot path. Stat the file, and if it already exists,
    // cache hit.
    if (b.cache_root.handle.access(sub_path, .{})) |_| {
        // This is the hot path, success.
        step.result_cached = true;
        return;
    } else |outer_err| switch (outer_err) {
        error.FileNotFound => {
            const sub_dirname = fs.path.dirname(sub_path).?;
            b.cache_root.handle.make_path(sub_dirname) catch |e| {
                return step.fail("unable to make path '{}{s}': {s}", .{
                    b.cache_root, sub_dirname, @errorName(e),
                });
            };

            const rand_int = std.crypto.random.int(u64);
            const tmp_sub_path = "tmp" ++ fs.path.sep_str ++
                std.Build.hex64(rand_int) ++ fs.path.sep_str ++
                basename;
            const tmp_sub_path_dirname = fs.path.dirname(tmp_sub_path).?;

            b.cache_root.handle.make_path(tmp_sub_path_dirname) catch |err| {
                return step.fail("unable to make temporary directory '{}{s}': {s}", .{
                    b.cache_root, tmp_sub_path_dirname, @errorName(err),
                });
            };

            b.cache_root.handle.write_file(.{ .sub_path = tmp_sub_path, .data = options.contents.items }) catch |err| {
                return step.fail("unable to write options to '{}{s}': {s}", .{
                    b.cache_root, tmp_sub_path, @errorName(err),
                });
            };

            b.cache_root.handle.rename(tmp_sub_path, sub_path) catch |err| switch (err) {
                error.PathAlreadyExists => {
                    // Other process beat us to it. Clean up the temp file.
                    b.cache_root.handle.delete_file(tmp_sub_path) catch |e| {
                        try step.add_error("warning: unable to delete temp file '{}{s}': {s}", .{
                            b.cache_root, tmp_sub_path, @errorName(e),
                        });
                    };
                    step.result_cached = true;
                    return;
                },
                else => {
                    return step.fail("unable to rename options from '{}{s}' to '{}{s}': {s}", .{
                        b.cache_root,    tmp_sub_path,
                        b.cache_root,    sub_path,
                        @errorName(err),
                    });
                },
            };
        },
        else => |e| return step.fail("unable to access options file '{}{s}': {s}", .{
            b.cache_root, sub_path, @errorName(e),
        }),
    }
}

const Arg = struct {
    name: []const u8,
    path: LazyPath,
};

test Options {
    if (builtin.os.tag == .wasi) return error.SkipZigTest;

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var graph: std.Build.Graph = .{
        .arena = arena.allocator(),
        .cache = .{
            .gpa = arena.allocator(),
            .manifest_dir = std.fs.cwd(),
        },
        .zig_exe = "test",
        .env_map = std.process.EnvMap.init(arena.allocator()),
        .global_cache_root = .{ .path = "test", .handle = std.fs.cwd() },
        .host = .{
            .query = .{},
            .result = try std.zig.system.resolve_target_query(.{}),
        },
    };

    var builder = try std.Build.create(
        &graph,
        .{ .path = "test", .handle = std.fs.cwd() },
        .{ .path = "test", .handle = std.fs.cwd() },
        &.{},
    );

    const options = builder.add_options();

    const KeywordEnum = enum {
        @"0.8.1",
    };

    const NormalEnum = enum {
        foo,
        bar,
    };

    const nested_array = [2][2]u16{
        [2]u16{ 300, 200 },
        [2]u16{ 300, 200 },
    };
    const nested_slice: []const []const u16 = &[_][]const u16{ &nested_array[0], &nested_array[1] };

    const NormalStruct = struct {
        hello: ?[]const u8,
        world: bool = true,
    };

    const NestedStruct = struct {
        normal_struct: NormalStruct,
        normal_enum: NormalEnum = .foo,
    };

    options.add_option(usize, "option1", 1);
    options.add_option(?usize, "option2", null);
    options.add_option(?usize, "option3", 3);
    options.add_option(comptime_int, "option4", 4);
    options.add_option([]const u8, "string", "zigisthebest");
    options.add_option(?[]const u8, "optional_string", null);
    options.add_option([2][2]u16, "nested_array", nested_array);
    options.add_option([]const []const u16, "nested_slice", nested_slice);
    options.add_option(KeywordEnum, "keyword_enum", .@"0.8.1");
    options.add_option(std.SemanticVersion, "semantic_version", try std.SemanticVersion.parse("0.1.2-foo+bar"));
    options.add_option(NormalEnum, "normal1_enum", NormalEnum.foo);
    options.add_option(NormalEnum, "normal2_enum", NormalEnum.bar);
    options.add_option(NormalStruct, "normal1_struct", NormalStruct{
        .hello = "foo",
    });
    options.add_option(NormalStruct, "normal2_struct", NormalStruct{
        .hello = null,
        .world = false,
    });
    options.add_option(NestedStruct, "nested_struct", NestedStruct{
        .normal_struct = .{ .hello = "bar" },
    });

    try std.testing.expect_equal_strings(
        \\pub const option1: usize = 1;
        \\pub const option2: ?usize = null;
        \\pub const option3: ?usize = 3;
        \\pub const option4: comptime_int = 4;
        \\pub const string: []const u8 = "zigisthebest";
        \\pub const optional_string: ?[]const u8 = null;
        \\pub const nested_array: [2][2]u16 = [2][2]u16 {
        \\    [2]u16 {
        \\        300,
        \\        200,
        \\    },
        \\    [2]u16 {
        \\        300,
        \\        200,
        \\    },
        \\};
        \\pub const nested_slice: []const []const u16 = &[_][]const u16 {
        \\    &[_]u16 {
        \\        300,
        \\        200,
        \\    },
        \\    &[_]u16 {
        \\        300,
        \\        200,
        \\    },
        \\};
        \\pub const @"Build.Step.Options.decltest.Options.KeywordEnum" = enum (u0) {
        \\    @"0.8.1" = 0,
        \\};
        \\pub const keyword_enum: @"Build.Step.Options.decltest.Options.KeywordEnum" = .@"0.8.1";
        \\pub const semantic_version: @import("std").SemanticVersion = .{
        \\    .major = 0,
        \\    .minor = 1,
        \\    .patch = 2,
        \\    .pre = "foo",
        \\    .build = "bar",
        \\};
        \\pub const @"Build.Step.Options.decltest.Options.NormalEnum" = enum (u1) {
        \\    foo = 0,
        \\    bar = 1,
        \\};
        \\pub const normal1_enum: @"Build.Step.Options.decltest.Options.NormalEnum" = .foo;
        \\pub const normal2_enum: @"Build.Step.Options.decltest.Options.NormalEnum" = .bar;
        \\pub const @"Build.Step.Options.decltest.Options.NormalStruct" = struct {
        \\    hello: ?[]const u8,
        \\    world: bool = true,
        \\};
        \\pub const normal1_struct: @"Build.Step.Options.decltest.Options.NormalStruct" = .{
        \\    .hello = "foo",
        \\    .world = true,
        \\};
        \\pub const normal2_struct: @"Build.Step.Options.decltest.Options.NormalStruct" = .{
        \\    .hello = null,
        \\    .world = false,
        \\};
        \\pub const @"Build.Step.Options.decltest.Options.NestedStruct" = struct {
        \\    normal_struct: @"Build.Step.Options.decltest.Options.NormalStruct",
        \\    normal_enum: @"Build.Step.Options.decltest.Options.NormalEnum" = .foo,
        \\};
        \\pub const nested_struct: @"Build.Step.Options.decltest.Options.NestedStruct" = .{
        \\    .normal_struct = .{
        \\        .hello = "bar",
        \\        .world = true,
        \\    },
        \\    .normal_enum = .foo,
        \\};
        \\
    , options.contents.items);

    _ = try std.zig.Ast.parse(arena.allocator(), try options.contents.to_owned_slice_sentinel(0), .zig);
}
