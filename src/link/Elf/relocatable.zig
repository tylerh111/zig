pub fn flush_static_lib(elf_file: *Elf, comp: *Compilation, module_obj_path: ?[]const u8) link.File.FlushError!void {
    const gpa = comp.gpa;

    var positionals = std.ArrayList(Compilation.LinkObject).init(gpa);
    defer positionals.deinit();

    try positionals.ensure_unused_capacity(comp.objects.len);
    positionals.append_slice_assume_capacity(comp.objects);

    for (comp.c_object_table.keys()) |key| {
        try positionals.append(.{ .path = key.status.success.object_path });
    }

    if (module_obj_path) |path| try positionals.append(.{ .path = path });

    if (comp.include_compiler_rt) {
        try positionals.append(.{ .path = comp.compiler_rt_obj.?.full_object_path });
    }

    for (positionals.items) |obj| {
        parse_positional(elf_file, obj.path) catch |err| switch (err) {
            error.MalformedObject, error.MalformedArchive, error.InvalidCpuArch => continue, // already reported
            error.UnknownFileType => try elf_file.report_parse_error(obj.path, "unknown file type for an object file", .{}),
            else => |e| try elf_file.report_parse_error(
                obj.path,
                "unexpected error: parsing input file failed with error {s}",
                .{@errorName(e)},
            ),
        };
    }

    if (comp.link_errors.items.len > 0) return error.FlushFailure;

    // First, we flush relocatable object file generated with our backends.
    if (elf_file.zig_object_ptr()) |zig_object| {
        zig_object.resolve_symbols(elf_file);
        try elf_file.add_comment_string();
        try elf_file.finalize_merge_sections();
        zig_object.claim_unresolved_object(elf_file);

        try elf_file.init_merge_sections();
        try elf_file.init_symtab();
        try elf_file.init_sh_strtab();
        try elf_file.sort_shdrs();
        try zig_object.add_atoms_to_rela_sections(elf_file);
        try elf_file.update_merge_section_sizes();
        try update_section_sizes(elf_file);

        try allocate_alloc_sections(elf_file);
        try elf_file.allocate_non_alloc_sections();

        if (build_options.enable_logging) {
            state_log.debug("{}", .{elf_file.dump_state()});
        }

        try elf_file.write_merge_sections();
        try write_synthetic_sections(elf_file);
        try elf_file.write_shdr_table();
        try elf_file.write_elf_header();

        // TODO we can avoid reading in the file contents we just wrote if we give the linker
        // ability to write directly to a buffer.
        try zig_object.read_file_contents(elf_file);
    }

    var files = std.ArrayList(File.Index).init(gpa);
    defer files.deinit();
    try files.ensure_total_capacity_precise(elf_file.objects.items.len + 1);
    if (elf_file.zig_object_ptr()) |zig_object| files.append_assume_capacity(zig_object.index);
    for (elf_file.objects.items) |index| files.append_assume_capacity(index);

    // Update ar symtab from parsed objects
    var ar_symtab: Archive.ArSymtab = .{};
    defer ar_symtab.deinit(gpa);

    for (files.items) |index| {
        try elf_file.file(index).?.update_ar_symtab(&ar_symtab, elf_file);
    }

    ar_symtab.sort();

    // Save object paths in filenames strtab.
    var ar_strtab: Archive.ArStrtab = .{};
    defer ar_strtab.deinit(gpa);

    for (files.items) |index| {
        const file_ptr = elf_file.file(index).?;
        try file_ptr.update_ar_strtab(gpa, &ar_strtab);
        try file_ptr.update_ar_size(elf_file);
    }

    // Update file offsets of contributing objects.
    const total_size: usize = blk: {
        var pos: usize = elf.ARMAG.len;
        pos += @size_of(elf.ar_hdr) + ar_symtab.size(.p64);

        if (ar_strtab.size() > 0) {
            pos = mem.align_forward(usize, pos, 2);
            pos += @size_of(elf.ar_hdr) + ar_strtab.size();
        }

        for (files.items) |index| {
            const file_ptr = elf_file.file(index).?;
            const state = switch (file_ptr) {
                .zig_object => |x| &x.output_ar_state,
                .object => |x| &x.output_ar_state,
                else => unreachable,
            };
            pos = mem.align_forward(usize, pos, 2);
            state.file_off = pos;
            pos += @size_of(elf.ar_hdr) + (math.cast(usize, state.size) orelse return error.Overflow);
        }

        break :blk pos;
    };

    if (build_options.enable_logging) {
        state_log.debug("ar_symtab\n{}\n", .{ar_symtab.fmt(elf_file)});
        state_log.debug("ar_strtab\n{}\n", .{ar_strtab});
    }

    var buffer = std.ArrayList(u8).init(gpa);
    defer buffer.deinit();
    try buffer.ensure_total_capacity_precise(total_size);

    // Write magic
    try buffer.writer().write_all(elf.ARMAG);

    // Write symtab
    try ar_symtab.write(.p64, elf_file, buffer.writer());

    // Write strtab
    if (ar_strtab.size() > 0) {
        if (!mem.is_aligned(buffer.items.len, 2)) try buffer.writer().write_byte(0);
        try ar_strtab.write(buffer.writer());
    }

    // Write object files
    for (files.items) |index| {
        if (!mem.is_aligned(buffer.items.len, 2)) try buffer.writer().write_byte(0);
        try elf_file.file(index).?.write_ar(elf_file, buffer.writer());
    }

    assert(buffer.items.len == total_size);

    try elf_file.base.file.?.set_end_pos(total_size);
    try elf_file.base.file.?.pwrite_all(buffer.items, 0);

    if (comp.link_errors.items.len > 0) return error.FlushFailure;
}

pub fn flush_object(elf_file: *Elf, comp: *Compilation, module_obj_path: ?[]const u8) link.File.FlushError!void {
    const gpa = elf_file.base.comp.gpa;

    var positionals = std.ArrayList(Compilation.LinkObject).init(gpa);
    defer positionals.deinit();
    try positionals.ensure_unused_capacity(comp.objects.len);
    positionals.append_slice_assume_capacity(comp.objects);

    // This is a set of object files emitted by clang in a single `build-exe` invocation.
    // For instance, the implicit `a.o` as compiled by `zig build-exe a.c` will end up
    // in this set.
    for (comp.c_object_table.keys()) |key| {
        try positionals.append(.{ .path = key.status.success.object_path });
    }

    if (module_obj_path) |path| try positionals.append(.{ .path = path });

    for (positionals.items) |obj| {
        elf_file.parse_positional(obj.path, obj.must_link) catch |err| switch (err) {
            error.MalformedObject, error.MalformedArchive, error.InvalidCpuArch => continue, // already reported
            else => |e| try elf_file.report_parse_error(
                obj.path,
                "unexpected error: parsing input file failed with error {s}",
                .{@errorName(e)},
            ),
        };
    }

    if (comp.link_errors.items.len > 0) return error.FlushFailure;

    // Now, we are ready to resolve the symbols across all input files.
    // We will first resolve the files in the ZigObject, next in the parsed
    // input Object files.
    elf_file.resolve_symbols();
    elf_file.mark_eh_frame_atoms_dead();
    try elf_file.resolve_merge_sections();
    try elf_file.add_comment_string();
    try elf_file.finalize_merge_sections();
    claim_unresolved(elf_file);

    try init_sections(elf_file);
    try elf_file.init_merge_sections();
    try elf_file.sort_shdrs();
    if (elf_file.zig_object_ptr()) |zig_object| {
        try zig_object.add_atoms_to_rela_sections(elf_file);
    }
    for (elf_file.objects.items) |index| {
        const object = elf_file.file(index).?.object;
        try object.add_atoms_to_output_sections(elf_file);
        try object.add_atoms_to_rela_sections(elf_file);
    }
    try elf_file.update_merge_section_sizes();
    try update_section_sizes(elf_file);

    try allocate_alloc_sections(elf_file);
    try elf_file.allocate_non_alloc_sections();

    if (build_options.enable_logging) {
        state_log.debug("{}", .{elf_file.dump_state()});
    }

    try write_atoms(elf_file);
    try elf_file.write_merge_sections();
    try write_synthetic_sections(elf_file);
    try elf_file.write_shdr_table();
    try elf_file.write_elf_header();

    if (comp.link_errors.items.len > 0) return error.FlushFailure;
}

fn parse_positional(elf_file: *Elf, path: []const u8) Elf.ParseError!void {
    if (try Object.is_object(path)) {
        try parse_object(elf_file, path);
    } else if (try Archive.is_archive(path)) {
        try parse_archive(elf_file, path);
    } else return error.UnknownFileType;
    // TODO: should we check for LD script?
    // Actually, should we even unpack an archive?
}

fn parse_object(elf_file: *Elf, path: []const u8) Elf.ParseError!void {
    const gpa = elf_file.base.comp.gpa;
    const handle = try std.fs.cwd().open_file(path, .{});
    const fh = try elf_file.add_file_handle(handle);

    const index = @as(File.Index, @int_cast(try elf_file.files.add_one(gpa)));
    elf_file.files.set(index, .{ .object = .{
        .path = try gpa.dupe(u8, path),
        .file_handle = fh,
        .index = index,
    } });
    try elf_file.objects.append(gpa, index);

    const object = elf_file.file(index).?.object;
    try object.parse_ar(elf_file);
}

fn parse_archive(elf_file: *Elf, path: []const u8) Elf.ParseError!void {
    const gpa = elf_file.base.comp.gpa;
    const handle = try std.fs.cwd().open_file(path, .{});
    const fh = try elf_file.add_file_handle(handle);

    var archive = Archive{};
    defer archive.deinit(gpa);
    try archive.parse(elf_file, path, fh);

    const objects = try archive.objects.to_owned_slice(gpa);
    defer gpa.free(objects);

    for (objects) |extracted| {
        const index = @as(File.Index, @int_cast(try elf_file.files.add_one(gpa)));
        elf_file.files.set(index, .{ .object = extracted });
        const object = &elf_file.files.items(.data)[index].object;
        object.index = index;
        try object.parse_ar(elf_file);
        try elf_file.objects.append(gpa, index);
    }
}

fn claim_unresolved(elf_file: *Elf) void {
    if (elf_file.zig_object_ptr()) |zig_object| {
        zig_object.claim_unresolved_object(elf_file);
    }
    for (elf_file.objects.items) |index| {
        elf_file.file(index).?.object.claim_unresolved_object(elf_file);
    }
}

fn init_sections(elf_file: *Elf) !void {
    const ptr_size = elf_file.ptr_width_bytes();

    for (elf_file.objects.items) |index| {
        const object = elf_file.file(index).?.object;
        try object.init_output_sections(elf_file);
        try object.init_rela_sections(elf_file);
    }

    const needs_eh_frame = for (elf_file.objects.items) |index| {
        if (elf_file.file(index).?.object.cies.items.len > 0) break true;
    } else false;
    if (needs_eh_frame) {
        elf_file.eh_frame_section_index = try elf_file.add_section(.{
            .name = ".eh_frame",
            .type = elf.SHT_PROGBITS,
            .flags = elf.SHF_ALLOC,
            .addralign = ptr_size,
            .offset = std.math.max_int(u64),
        });
        elf_file.eh_frame_rela_section_index = try elf_file.add_rela_shdr(".rela.eh_frame", elf_file.eh_frame_section_index.?);
    }

    try init_comdat_groups(elf_file);
    try elf_file.init_symtab();
    try elf_file.init_sh_strtab();
}

fn init_comdat_groups(elf_file: *Elf) !void {
    const gpa = elf_file.base.comp.gpa;

    for (elf_file.objects.items) |index| {
        const object = elf_file.file(index).?.object;

        for (object.comdat_groups.items) |cg_index| {
            const cg = elf_file.comdat_group(cg_index);
            const cg_owner = elf_file.comdat_group_owner(cg.owner);
            if (cg_owner.file != index) continue;

            const cg_sec = try elf_file.comdat_group_sections.add_one(gpa);
            cg_sec.* = .{
                .shndx = try elf_file.add_section(.{
                    .name = ".group",
                    .type = elf.SHT_GROUP,
                    .entsize = @size_of(u32),
                    .addralign = @alignOf(u32),
                    .offset = std.math.max_int(u64),
                }),
                .cg_index = cg_index,
            };
        }
    }
}

fn update_section_sizes(elf_file: *Elf) !void {
    for (elf_file.output_sections.keys(), elf_file.output_sections.values()) |shndx, atom_list| {
        const shdr = &elf_file.shdrs.items[shndx];
        for (atom_list.items) |atom_index| {
            const atom_ptr = elf_file.atom(atom_index) orelse continue;
            if (!atom_ptr.flags.alive) continue;
            const offset = atom_ptr.alignment.forward(shdr.sh_size);
            const padding = offset - shdr.sh_size;
            atom_ptr.value = @int_cast(offset);
            shdr.sh_size += padding + atom_ptr.size;
            shdr.sh_addralign = @max(shdr.sh_addralign, atom_ptr.alignment.to_byte_units() orelse 1);
        }
    }

    for (elf_file.output_rela_sections.values()) |sec| {
        const shdr = &elf_file.shdrs.items[sec.shndx];
        for (sec.atom_list.items) |atom_index| {
            const atom_ptr = elf_file.atom(atom_index) orelse continue;
            if (!atom_ptr.flags.alive) continue;
            const relocs = atom_ptr.relocs(elf_file);
            shdr.sh_size += shdr.sh_entsize * relocs.len;
        }

        if (shdr.sh_size == 0) shdr.sh_offset = 0;
    }

    if (elf_file.eh_frame_section_index) |index| {
        elf_file.shdrs.items[index].sh_size = try eh_frame.calc_eh_frame_size(elf_file);
    }
    if (elf_file.eh_frame_rela_section_index) |index| {
        const shdr = &elf_file.shdrs.items[index];
        shdr.sh_size = eh_frame.calc_eh_frame_relocs(elf_file) * shdr.sh_entsize;
    }

    try elf_file.update_symtab_size();
    update_comdat_groups_sizes(elf_file);
    elf_file.update_sh_strtab_size();
}

fn update_comdat_groups_sizes(elf_file: *Elf) void {
    for (elf_file.comdat_group_sections.items) |cg| {
        const shdr = &elf_file.shdrs.items[cg.shndx];
        shdr.sh_size = cg.size(elf_file);
        shdr.sh_link = elf_file.symtab_section_index.?;

        const sym = elf_file.symbol(cg.symbol(elf_file));
        shdr.sh_info = sym.output_symtab_index(elf_file) orelse
            elf_file.section_symbol_output_symtab_index(sym.output_shndx().?);
    }
}

/// Allocates alloc sections when merging relocatable objects files together.
fn allocate_alloc_sections(elf_file: *Elf) !void {
    for (elf_file.shdrs.items) |*shdr| {
        if (shdr.sh_type == elf.SHT_NULL) continue;
        if (shdr.sh_flags & elf.SHF_ALLOC == 0) continue;
        if (shdr.sh_type == elf.SHT_NOBITS) {
            shdr.sh_offset = 0;
            continue;
        }
        const needed_size = shdr.sh_size;
        if (needed_size > elf_file.allocated_size(shdr.sh_offset)) {
            shdr.sh_size = 0;
            const new_offset = elf_file.find_free_space(needed_size, shdr.sh_addralign);
            shdr.sh_offset = new_offset;
            shdr.sh_size = needed_size;
        }
    }
}

fn write_atoms(elf_file: *Elf) !void {
    const gpa = elf_file.base.comp.gpa;

    // TODO iterate over `output_sections` directly
    for (elf_file.shdrs.items, 0..) |shdr, shndx| {
        if (shdr.sh_type == elf.SHT_NULL) continue;
        if (shdr.sh_type == elf.SHT_NOBITS) continue;

        const atom_list = elf_file.output_sections.get(@int_cast(shndx)) orelse continue;
        if (atom_list.items.len == 0) continue;

        log.debug("writing atoms in '{s}' section", .{elf_file.get_sh_string(shdr.sh_name)});

        // TODO really, really handle debug section separately
        const base_offset = if (elf_file.is_debug_section(@int_cast(shndx))) blk: {
            const zig_object = elf_file.zig_object_ptr().?;
            if (shndx == elf_file.debug_info_section_index.?)
                break :blk zig_object.debug_info_section_zig_size;
            if (shndx == elf_file.debug_abbrev_section_index.?)
                break :blk zig_object.debug_abbrev_section_zig_size;
            if (shndx == elf_file.debug_str_section_index.?)
                break :blk zig_object.debug_str_section_zig_size;
            if (shndx == elf_file.debug_aranges_section_index.?)
                break :blk zig_object.debug_aranges_section_zig_size;
            if (shndx == elf_file.debug_line_section_index.?)
                break :blk zig_object.debug_line_section_zig_size;
            unreachable;
        } else 0;
        const sh_offset = shdr.sh_offset + base_offset;
        const sh_size = math.cast(usize, shdr.sh_size - base_offset) orelse return error.Overflow;

        const buffer = try gpa.alloc(u8, sh_size);
        defer gpa.free(buffer);
        const padding_byte: u8 = if (shdr.sh_type == elf.SHT_PROGBITS and
            shdr.sh_flags & elf.SHF_EXECINSTR != 0)
            0xcc // int3
        else
            0;
        @memset(buffer, padding_byte);

        for (atom_list.items) |atom_index| {
            const atom_ptr = elf_file.atom(atom_index).?;
            assert(atom_ptr.flags.alive);

            const offset = math.cast(usize, atom_ptr.value - @as(i64, @int_cast(shdr.sh_addr - base_offset))) orelse
                return error.Overflow;
            const size = math.cast(usize, atom_ptr.size) orelse return error.Overflow;

            log.debug("writing atom({d}) from 0x{x} to 0x{x}", .{
                atom_index,
                sh_offset + offset,
                sh_offset + offset + size,
            });

            // TODO decompress directly into provided buffer
            const out_code = buffer[offset..][0..size];
            const in_code = switch (atom_ptr.file(elf_file).?) {
                .object => |x| try x.code_decompress_alloc(elf_file, atom_index),
                .zig_object => |x| try x.code_alloc(elf_file, atom_index),
                else => unreachable,
            };
            defer gpa.free(in_code);
            @memcpy(out_code, in_code);
        }

        try elf_file.base.file.?.pwrite_all(buffer, sh_offset);
    }
}

fn write_synthetic_sections(elf_file: *Elf) !void {
    const gpa = elf_file.base.comp.gpa;

    for (elf_file.output_rela_sections.values()) |sec| {
        if (sec.atom_list.items.len == 0) continue;

        const shdr = elf_file.shdrs.items[sec.shndx];

        const num_relocs = math.cast(usize, @div_exact(shdr.sh_size, shdr.sh_entsize)) orelse
            return error.Overflow;
        var relocs = try std.ArrayList(elf.Elf64_Rela).init_capacity(gpa, num_relocs);
        defer relocs.deinit();

        for (sec.atom_list.items) |atom_index| {
            const atom_ptr = elf_file.atom(atom_index) orelse continue;
            if (!atom_ptr.flags.alive) continue;
            try atom_ptr.write_relocs(elf_file, &relocs);
        }
        assert(relocs.items.len == num_relocs);

        const SortRelocs = struct {
            pub fn less_than(ctx: void, lhs: elf.Elf64_Rela, rhs: elf.Elf64_Rela) bool {
                _ = ctx;
                return lhs.r_offset < rhs.r_offset;
            }
        };

        mem.sort(elf.Elf64_Rela, relocs.items, {}, SortRelocs.less_than);

        log.debug("writing {s} from 0x{x} to 0x{x}", .{
            elf_file.get_sh_string(shdr.sh_name),
            shdr.sh_offset,
            shdr.sh_offset + shdr.sh_size,
        });

        try elf_file.base.file.?.pwrite_all(mem.slice_as_bytes(relocs.items), shdr.sh_offset);
    }

    if (elf_file.eh_frame_section_index) |shndx| {
        const shdr = elf_file.shdrs.items[shndx];
        const sh_size = math.cast(usize, shdr.sh_size) orelse return error.Overflow;
        var buffer = try std.ArrayList(u8).init_capacity(gpa, sh_size);
        defer buffer.deinit();
        try eh_frame.write_eh_frame_object(elf_file, buffer.writer());
        log.debug("writing .eh_frame from 0x{x} to 0x{x}", .{
            shdr.sh_offset,
            shdr.sh_offset + shdr.sh_size,
        });
        assert(buffer.items.len == sh_size);
        try elf_file.base.file.?.pwrite_all(buffer.items, shdr.sh_offset);
    }
    if (elf_file.eh_frame_rela_section_index) |shndx| {
        const shdr = elf_file.shdrs.items[shndx];
        const sh_size = math.cast(usize, shdr.sh_size) orelse return error.Overflow;
        var buffer = try std.ArrayList(u8).init_capacity(gpa, sh_size);
        defer buffer.deinit();
        try eh_frame.write_eh_frame_relocs(elf_file, buffer.writer());
        assert(buffer.items.len == sh_size);
        log.debug("writing .rela.eh_frame from 0x{x} to 0x{x}", .{
            shdr.sh_offset,
            shdr.sh_offset + shdr.sh_size,
        });
        try elf_file.base.file.?.pwrite_all(buffer.items, shdr.sh_offset);
    }

    try write_comdat_groups(elf_file);
    try elf_file.write_symtab();
    try elf_file.write_sh_strtab();
}

fn write_comdat_groups(elf_file: *Elf) !void {
    const gpa = elf_file.base.comp.gpa;
    for (elf_file.comdat_group_sections.items) |cgs| {
        const shdr = elf_file.shdrs.items[cgs.shndx];
        const sh_size = math.cast(usize, shdr.sh_size) orelse return error.Overflow;
        var buffer = try std.ArrayList(u8).init_capacity(gpa, sh_size);
        defer buffer.deinit();
        try cgs.write(elf_file, buffer.writer());
        assert(buffer.items.len == sh_size);
        log.debug("writing COMDAT group from 0x{x} to 0x{x}", .{
            shdr.sh_offset,
            shdr.sh_offset + shdr.sh_size,
        });
        try elf_file.base.file.?.pwrite_all(buffer.items, shdr.sh_offset);
    }
}

const assert = std.debug.assert;
const build_options = @import("build_options");
const eh_frame = @import("eh_frame.zig");
const elf = std.elf;
const link = @import("../../link.zig");
const log = std.log.scoped(.link);
const math = std.math;
const mem = std.mem;
const state_log = std.log.scoped(.link_state);
const std = @import("std");

const Archive = @import("Archive.zig");
const Compilation = @import("../../Compilation.zig");
const Elf = @import("../Elf.zig");
const File = @import("file.zig").File;
const Object = @import("Object.zig");
