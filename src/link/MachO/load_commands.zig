const std = @import("std");
const assert = std.debug.assert;
const log = std.log.scoped(.link);
const macho = std.macho;
const mem = std.mem;

const Allocator = mem.Allocator;
const DebugSymbols = @import("DebugSymbols.zig");
const Dylib = @import("Dylib.zig");
const MachO = @import("../MachO.zig");

pub const default_dyld_path: [*:0]const u8 = "/usr/lib/dyld";

fn calc_install_name_len(cmd_size: u64, name: []const u8, assume_max_path_len: bool) u64 {
    const darwin_path_max = 1024;
    const name_len = if (assume_max_path_len) darwin_path_max else name.len + 1;
    return mem.align_forward(u64, cmd_size + name_len, @alignOf(u64));
}

pub fn calc_load_commands_size(macho_file: *MachO, assume_max_path_len: bool) !u32 {
    var sizeofcmds: u64 = 0;

    // LC_SEGMENT_64
    sizeofcmds += @size_of(macho.segment_command_64) * macho_file.segments.items.len;
    for (macho_file.segments.items) |seg| {
        sizeofcmds += seg.nsects * @size_of(macho.section_64);
    }

    // LC_DYLD_INFO_ONLY
    sizeofcmds += @size_of(macho.dyld_info_command);
    // LC_FUNCTION_STARTS
    sizeofcmds += @size_of(macho.linkedit_data_command);
    // LC_DATA_IN_CODE
    sizeofcmds += @size_of(macho.linkedit_data_command);
    // LC_SYMTAB
    sizeofcmds += @size_of(macho.symtab_command);
    // LC_DYSYMTAB
    sizeofcmds += @size_of(macho.dysymtab_command);
    // LC_LOAD_DYLINKER
    sizeofcmds += calc_install_name_len(
        @size_of(macho.dylinker_command),
        mem.slice_to(default_dyld_path, 0),
        false,
    );
    // LC_MAIN
    if (!macho_file.base.is_dyn_lib()) {
        sizeofcmds += @size_of(macho.entry_point_command);
    }
    // LC_ID_DYLIB
    if (macho_file.base.is_dyn_lib()) {
        const gpa = macho_file.base.comp.gpa;
        const emit = macho_file.base.emit;
        const install_name = macho_file.install_name orelse
            try emit.directory.join(gpa, &.{emit.sub_path});
        defer if (macho_file.install_name == null) gpa.free(install_name);
        sizeofcmds += calc_install_name_len(
            @size_of(macho.dylib_command),
            install_name,
            assume_max_path_len,
        );
    }
    // LC_RPATH
    {
        for (macho_file.base.rpath_list) |rpath| {
            sizeofcmds += calc_install_name_len(
                @size_of(macho.rpath_command),
                rpath,
                assume_max_path_len,
            );
        }
    }
    // LC_SOURCE_VERSION
    sizeofcmds += @size_of(macho.source_version_command);
    if (macho_file.platform.is_build_version_compatible()) {
        // LC_BUILD_VERSION
        sizeofcmds += @size_of(macho.build_version_command) + @size_of(macho.build_tool_version);
    } else {
        // LC_VERSION_MIN_*
        sizeofcmds += @size_of(macho.version_min_command);
    }
    // LC_UUID
    sizeofcmds += @size_of(macho.uuid_command);
    // LC_LOAD_DYLIB
    for (macho_file.dylibs.items) |index| {
        const dylib = macho_file.get_file(index).?.dylib;
        assert(dylib.is_alive(macho_file));
        const dylib_id = dylib.id.?;
        sizeofcmds += calc_install_name_len(
            @size_of(macho.dylib_command),
            dylib_id.name,
            assume_max_path_len,
        );
    }
    // LC_CODE_SIGNATURE
    if (macho_file.requires_code_sig()) {
        sizeofcmds += @size_of(macho.linkedit_data_command);
    }

    return @as(u32, @int_cast(sizeofcmds));
}

pub fn calc_load_commands_size_dsym(macho_file: *MachO, dsym: *const DebugSymbols) u32 {
    var sizeofcmds: u64 = 0;

    // LC_SEGMENT_64
    sizeofcmds += @size_of(macho.segment_command_64) * (macho_file.segments.items.len - 1);
    for (macho_file.segments.items) |seg| {
        sizeofcmds += seg.nsects * @size_of(macho.section_64);
    }
    sizeofcmds += @size_of(macho.segment_command_64) * dsym.segments.items.len;
    for (dsym.segments.items) |seg| {
        sizeofcmds += seg.nsects * @size_of(macho.section_64);
    }

    // LC_SYMTAB
    sizeofcmds += @size_of(macho.symtab_command);
    // LC_UUID
    sizeofcmds += @size_of(macho.uuid_command);

    return @as(u32, @int_cast(sizeofcmds));
}

pub fn calc_load_commands_size_object(macho_file: *MachO) u32 {
    var sizeofcmds: u64 = 0;

    // LC_SEGMENT_64
    {
        assert(macho_file.segments.items.len == 1);
        sizeofcmds += @size_of(macho.segment_command_64);
        const seg = macho_file.segments.items[0];
        sizeofcmds += seg.nsects * @size_of(macho.section_64);
    }

    // LC_DATA_IN_CODE
    sizeofcmds += @size_of(macho.linkedit_data_command);
    // LC_SYMTAB
    sizeofcmds += @size_of(macho.symtab_command);
    // LC_DYSYMTAB
    sizeofcmds += @size_of(macho.dysymtab_command);

    if (macho_file.platform.is_build_version_compatible()) {
        // LC_BUILD_VERSION
        sizeofcmds += @size_of(macho.build_version_command) + @size_of(macho.build_tool_version);
    } else {
        // LC_VERSION_MIN_*
        sizeofcmds += @size_of(macho.version_min_command);
    }

    return @as(u32, @int_cast(sizeofcmds));
}

pub fn calc_min_header_pad_size(macho_file: *MachO) !u32 {
    var padding: u32 = (try calc_load_commands_size(macho_file, false)) + (macho_file.headerpad_size orelse 0);
    log.debug("minimum requested headerpad size 0x{x}", .{padding + @size_of(macho.mach_header_64)});

    if (macho_file.headerpad_max_install_names) {
        const min_headerpad_size: u32 = try calc_load_commands_size(macho_file, true);
        log.debug("headerpad_max_install_names minimum headerpad size 0x{x}", .{
            min_headerpad_size + @size_of(macho.mach_header_64),
        });
        padding = @max(padding, min_headerpad_size);
    }

    const offset = @size_of(macho.mach_header_64) + padding;
    log.debug("actual headerpad size 0x{x}", .{offset});

    return offset;
}

pub fn write_dylinker_lc(writer: anytype) !void {
    const name_len = mem.slice_to(default_dyld_path, 0).len;
    const cmdsize = @as(u32, @int_cast(mem.align_forward(
        u64,
        @size_of(macho.dylinker_command) + name_len,
        @size_of(u64),
    )));
    try writer.write_struct(macho.dylinker_command{
        .cmd = .LOAD_DYLINKER,
        .cmdsize = cmdsize,
        .name = @size_of(macho.dylinker_command),
    });
    try writer.write_all(mem.slice_to(default_dyld_path, 0));
    const padding = cmdsize - @size_of(macho.dylinker_command) - name_len;
    if (padding > 0) {
        try writer.write_byte_ntimes(0, padding);
    }
}

const WriteDylibLCCtx = struct {
    cmd: macho.LC,
    name: []const u8,
    timestamp: u32 = 2,
    current_version: u32 = 0x10000,
    compatibility_version: u32 = 0x10000,
};

pub fn write_dylib_lc(ctx: WriteDylibLCCtx, writer: anytype) !void {
    const name_len = ctx.name.len + 1;
    const cmdsize = @as(u32, @int_cast(mem.align_forward(
        u64,
        @size_of(macho.dylib_command) + name_len,
        @size_of(u64),
    )));
    try writer.write_struct(macho.dylib_command{
        .cmd = ctx.cmd,
        .cmdsize = cmdsize,
        .dylib = .{
            .name = @size_of(macho.dylib_command),
            .timestamp = ctx.timestamp,
            .current_version = ctx.current_version,
            .compatibility_version = ctx.compatibility_version,
        },
    });
    try writer.write_all(ctx.name);
    try writer.write_byte(0);
    const padding = cmdsize - @size_of(macho.dylib_command) - name_len;
    if (padding > 0) {
        try writer.write_byte_ntimes(0, padding);
    }
}

pub fn write_dylib_id_lc(macho_file: *MachO, writer: anytype) !void {
    const comp = macho_file.base.comp;
    const gpa = comp.gpa;
    assert(comp.config.output_mode == .Lib and comp.config.link_mode == .dynamic);
    const emit = macho_file.base.emit;
    const install_name = macho_file.install_name orelse
        try emit.directory.join(gpa, &.{emit.sub_path});
    defer if (macho_file.install_name == null) gpa.free(install_name);
    const curr = comp.version orelse std.SemanticVersion{
        .major = 1,
        .minor = 0,
        .patch = 0,
    };
    const compat = macho_file.compatibility_version orelse std.SemanticVersion{
        .major = 1,
        .minor = 0,
        .patch = 0,
    };
    try write_dylib_lc(.{
        .cmd = .ID_DYLIB,
        .name = install_name,
        .current_version = @as(u32, @int_cast(curr.major << 16 | curr.minor << 8 | curr.patch)),
        .compatibility_version = @as(u32, @int_cast(compat.major << 16 | compat.minor << 8 | compat.patch)),
    }, writer);
}

pub fn write_rpath_lcs(rpaths: []const []const u8, writer: anytype) !void {
    for (rpaths) |rpath| {
        const rpath_len = rpath.len + 1;
        const cmdsize = @as(u32, @int_cast(mem.align_forward(
            u64,
            @size_of(macho.rpath_command) + rpath_len,
            @size_of(u64),
        )));
        try writer.write_struct(macho.rpath_command{
            .cmdsize = cmdsize,
            .path = @size_of(macho.rpath_command),
        });
        try writer.write_all(rpath);
        try writer.write_byte(0);
        const padding = cmdsize - @size_of(macho.rpath_command) - rpath_len;
        if (padding > 0) {
            try writer.write_byte_ntimes(0, padding);
        }
    }
}

pub fn write_version_min_lc(platform: MachO.Platform, sdk_version: ?std.SemanticVersion, writer: anytype) !void {
    const cmd: macho.LC = switch (platform.os_tag) {
        .macos => .VERSION_MIN_MACOSX,
        .ios => .VERSION_MIN_IPHONEOS,
        .tvos => .VERSION_MIN_TVOS,
        .watchos => .VERSION_MIN_WATCHOS,
        else => unreachable,
    };
    try writer.write_all(mem.as_bytes(&macho.version_min_command{
        .cmd = cmd,
        .version = platform.to_apple_version(),
        .sdk = if (sdk_version) |ver|
            MachO.semantic_version_to_apple_version(ver)
        else
            platform.to_apple_version(),
    }));
}

pub fn write_build_version_lc(platform: MachO.Platform, sdk_version: ?std.SemanticVersion, writer: anytype) !void {
    const cmdsize = @size_of(macho.build_version_command) + @size_of(macho.build_tool_version);
    try writer.write_struct(macho.build_version_command{
        .cmdsize = cmdsize,
        .platform = platform.to_apple_platform(),
        .minos = platform.to_apple_version(),
        .sdk = if (sdk_version) |ver|
            MachO.semantic_version_to_apple_version(ver)
        else
            platform.to_apple_version(),
        .ntools = 1,
    });
    try writer.write_all(mem.as_bytes(&macho.build_tool_version{
        .tool = .ZIG,
        .version = 0x0,
    }));
}
