const std = @import("std");
const build_options = @import("build_options");
const introspect = @import("introspect.zig");
const Allocator = std.mem.Allocator;
const fatal = @import("main.zig").fatal;

pub fn cmd_env(arena: Allocator, args: []const []const u8, stdout: std.fs.File.Writer) !void {
    _ = args;
    const self_exe_path = try introspect.find_zig_exe_path(arena);

    var zig_lib_directory = introspect.find_zig_lib_dir_from_self_exe(arena, self_exe_path) catch |err| {
        fatal("unable to find zig installation directory: {s}\n", .{@errorName(err)});
    };
    defer zig_lib_directory.handle.close();

    const zig_std_dir = try std.fs.path.join(arena, &[_][]const u8{ zig_lib_directory.path.?, "std" });

    const global_cache_dir = try introspect.resolve_global_cache_dir(arena);

    const host = try std.zig.system.resolve_target_query(.{});
    const triple = try host.zig_triple(arena);

    var bw = std.io.buffered_writer(stdout);
    const w = bw.writer();

    var jws = std.json.write_stream(w, .{ .whitespace = .indent_1 });

    try jws.begin_object();

    try jws.object_field("zig_exe");
    try jws.write(self_exe_path);

    try jws.object_field("lib_dir");
    try jws.write(zig_lib_directory.path.?);

    try jws.object_field("std_dir");
    try jws.write(zig_std_dir);

    try jws.object_field("global_cache_dir");
    try jws.write(global_cache_dir);

    try jws.object_field("version");
    try jws.write(build_options.version);

    try jws.object_field("target");
    try jws.write(triple);

    try jws.object_field("env");
    try jws.begin_object();
    inline for (@typeInfo(std.zig.EnvVar).Enum.fields) |field| {
        try jws.object_field(field.name);
        try jws.write(try @field(std.zig.EnvVar, field.name).get(arena));
    }
    try jws.end_object();

    try jws.end_object();
    try w.write_byte('\n');

    try bw.flush();
}
