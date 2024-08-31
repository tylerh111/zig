const std = @import("std");
const fs = std.fs;
const io = std.io;
const mem = std.mem;
const meta = std.meta;
const Allocator = std.mem.Allocator;
const Target = std.Target;
const target = @import("target.zig");
const assert = std.debug.assert;
const glibc = @import("glibc.zig");
const introspect = @import("introspect.zig");
const fatal = @import("main.zig").fatal;

pub fn cmd_targets(
    allocator: Allocator,
    args: []const []const u8,
    /// Output stream
    stdout: anytype,
    native_target: Target,
) !void {
    _ = args;
    var zig_lib_directory = introspect.find_zig_lib_dir(allocator) catch |err| {
        fatal("unable to find zig installation directory: {s}\n", .{@errorName(err)});
    };
    defer zig_lib_directory.handle.close();
    defer allocator.free(zig_lib_directory.path.?);

    const abilists_contents = zig_lib_directory.handle.read_file_alloc(
        allocator,
        glibc.abilists_path,
        glibc.abilists_max_size,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => fatal("unable to read " ++ glibc.abilists_path ++ ": {s}", .{@errorName(err)}),
    };
    defer allocator.free(abilists_contents);

    const glibc_abi = try glibc.load_meta_data(allocator, abilists_contents);
    defer glibc_abi.destroy(allocator);

    var bw = io.buffered_writer(stdout);
    const w = bw.writer();
    var jws = std.json.write_stream(w, .{ .whitespace = .indent_1 });

    try jws.begin_object();

    try jws.object_field("arch");
    try jws.begin_array();
    for (meta.field_names(Target.Cpu.Arch)) |field| {
        try jws.write(field);
    }
    try jws.end_array();

    try jws.object_field("os");
    try jws.begin_array();
    for (meta.field_names(Target.Os.Tag)) |field| {
        try jws.write(field);
    }
    try jws.end_array();

    try jws.object_field("abi");
    try jws.begin_array();
    for (meta.field_names(Target.Abi)) |field| {
        try jws.write(field);
    }
    try jws.end_array();

    try jws.object_field("libc");
    try jws.begin_array();
    for (std.zig.target.available_libcs) |libc| {
        const tmp = try std.fmt.alloc_print(allocator, "{s}-{s}-{s}", .{
            @tag_name(libc.arch), @tag_name(libc.os), @tag_name(libc.abi),
        });
        defer allocator.free(tmp);
        try jws.write(tmp);
    }
    try jws.end_array();

    try jws.object_field("glibc");
    try jws.begin_array();
    for (glibc_abi.all_versions) |ver| {
        const tmp = try std.fmt.alloc_print(allocator, "{}", .{ver});
        defer allocator.free(tmp);
        try jws.write(tmp);
    }
    try jws.end_array();

    try jws.object_field("cpus");
    try jws.begin_object();
    for (meta.tags(Target.Cpu.Arch)) |arch| {
        try jws.object_field(@tag_name(arch));
        try jws.begin_object();
        for (arch.all_cpu_models()) |model| {
            try jws.object_field(model.name);
            try jws.begin_array();
            for (arch.all_features_list(), 0..) |feature, i_usize| {
                const index = @as(Target.Cpu.Feature.Set.Index, @int_cast(i_usize));
                if (model.features.is_enabled(index)) {
                    try jws.write(feature.name);
                }
            }
            try jws.end_array();
        }
        try jws.end_object();
    }
    try jws.end_object();

    try jws.object_field("cpuFeatures");
    try jws.begin_object();
    for (meta.tags(Target.Cpu.Arch)) |arch| {
        try jws.object_field(@tag_name(arch));
        try jws.begin_array();
        for (arch.all_features_list()) |feature| {
            try jws.write(feature.name);
        }
        try jws.end_array();
    }
    try jws.end_object();

    try jws.object_field("native");
    try jws.begin_object();
    {
        const triple = try native_target.zig_triple(allocator);
        defer allocator.free(triple);
        try jws.object_field("triple");
        try jws.write(triple);
    }
    {
        try jws.object_field("cpu");
        try jws.begin_object();
        try jws.object_field("arch");
        try jws.write(@tag_name(native_target.cpu.arch));

        try jws.object_field("name");
        const cpu = native_target.cpu;
        try jws.write(cpu.model.name);

        {
            try jws.object_field("features");
            try jws.begin_array();
            for (native_target.cpu.arch.all_features_list(), 0..) |feature, i_usize| {
                const index = @as(Target.Cpu.Feature.Set.Index, @int_cast(i_usize));
                if (cpu.features.is_enabled(index)) {
                    try jws.write(feature.name);
                }
            }
            try jws.end_array();
        }
        try jws.end_object();
    }
    try jws.object_field("os");
    try jws.write(@tag_name(native_target.os.tag));
    try jws.object_field("abi");
    try jws.write(@tag_name(native_target.abi));
    try jws.end_object();

    try jws.end_object();

    try w.write_byte('\n');
    return bw.flush();
}
