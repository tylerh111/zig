pub const InfoReader = struct {
    bytes: []const u8,
    strtab: []const u8,
    pos: usize = 0,

    pub fn read_compile_unit_header(p: *InfoReader) !CompileUnitHeader {
        var length: u64 = try p.read_int(u32);
        const is_64bit = length == 0xffffffff;
        if (is_64bit) {
            length = try p.read_int(u64);
        }
        const dw_fmt: DwarfFormat = if (is_64bit) .dwarf64 else .dwarf32;
        return .{
            .format = dw_fmt,
            .length = length,
            .version = try p.read_int(u16),
            .debug_abbrev_offset = try p.read_offset(dw_fmt),
            .address_size = try p.read_byte(),
        };
    }

    pub fn seek_to_die(p: *InfoReader, code: Code, cuh: CompileUnitHeader, abbrev_reader: *AbbrevReader) !void {
        const cuh_length = math.cast(usize, cuh.length) orelse return error.Overflow;
        const end_pos = p.pos + switch (cuh.format) {
            .dwarf32 => @as(usize, 4),
            .dwarf64 => 12,
        } + cuh_length;
        while (p.pos < end_pos) {
            const di_code = try p.read_uleb128(u64);
            if (di_code == 0) return error.Eof;
            if (di_code == code) return;

            while (try abbrev_reader.read_attr()) |attr| switch (attr.at) {
                dwarf.FORM.sec_offset,
                dwarf.FORM.ref_addr,
                => {
                    _ = try p.read_offset(cuh.format);
                },

                dwarf.FORM.addr => {
                    _ = try p.read_nbytes(cuh.address_size);
                },

                dwarf.FORM.block1,
                dwarf.FORM.block2,
                dwarf.FORM.block4,
                dwarf.FORM.block,
                => {
                    _ = try p.read_block(attr.form);
                },

                dwarf.FORM.exprloc => {
                    _ = try p.read_expr_loc();
                },

                dwarf.FORM.flag_present => {},

                dwarf.FORM.data1,
                dwarf.FORM.ref1,
                dwarf.FORM.flag,
                dwarf.FORM.data2,
                dwarf.FORM.ref2,
                dwarf.FORM.data4,
                dwarf.FORM.ref4,
                dwarf.FORM.data8,
                dwarf.FORM.ref8,
                dwarf.FORM.ref_sig8,
                dwarf.FORM.udata,
                dwarf.FORM.ref_udata,
                dwarf.FORM.sdata,
                => {
                    _ = try p.read_constant(attr.form);
                },

                dwarf.FORM.strp,
                dwarf.FORM.string,
                => {
                    _ = try p.read_string(attr.form, cuh);
                },

                else => {
                    // TODO better errors
                    log.err("unhandled DW_FORM_* value with identifier {x}", .{attr.form});
                    return error.UnhandledDwFormValue;
                },
            };
        }
    }

    pub fn read_block(p: *InfoReader, form: Form) ![]const u8 {
        const len: u64 = switch (form) {
            dwarf.FORM.block1 => try p.read_byte(),
            dwarf.FORM.block2 => try p.read_int(u16),
            dwarf.FORM.block4 => try p.read_int(u32),
            dwarf.FORM.block => try p.read_uleb128(u64),
            else => unreachable,
        };
        return p.read_nbytes(len);
    }

    pub fn read_expr_loc(p: *InfoReader) ![]const u8 {
        const len: u64 = try p.read_uleb128(u64);
        return p.read_nbytes(len);
    }

    pub fn read_constant(p: *InfoReader, form: Form) !u64 {
        return switch (form) {
            dwarf.FORM.data1, dwarf.FORM.ref1, dwarf.FORM.flag => try p.read_byte(),
            dwarf.FORM.data2, dwarf.FORM.ref2 => try p.read_int(u16),
            dwarf.FORM.data4, dwarf.FORM.ref4 => try p.read_int(u32),
            dwarf.FORM.data8, dwarf.FORM.ref8, dwarf.FORM.ref_sig8 => try p.read_int(u64),
            dwarf.FORM.udata, dwarf.FORM.ref_udata => try p.read_uleb128(u64),
            dwarf.FORM.sdata => @bit_cast(try p.read_ileb128(i64)),
            else => return error.UnhandledConstantForm,
        };
    }

    pub fn read_string(p: *InfoReader, form: Form, cuh: CompileUnitHeader) ![:0]const u8 {
        switch (form) {
            dwarf.FORM.strp => {
                const off = try p.read_offset(cuh.format);
                const off_u = math.cast(usize, off) orelse return error.Overflow;
                return mem.slice_to(@as([*:0]const u8, @ptr_cast(p.strtab.ptr + off_u)), 0);
            },
            dwarf.FORM.string => {
                const start = p.pos;
                while (p.pos < p.bytes.len) : (p.pos += 1) {
                    if (p.bytes[p.pos] == 0) break;
                }
                if (p.bytes[p.pos] != 0) return error.Eof;
                return p.bytes[start..p.pos :0];
            },
            else => unreachable,
        }
    }

    pub fn read_byte(p: *InfoReader) !u8 {
        if (p.pos + 1 > p.bytes.len) return error.Eof;
        defer p.pos += 1;
        return p.bytes[p.pos];
    }

    pub fn read_nbytes(p: *InfoReader, num: u64) ![]const u8 {
        const num_usize = math.cast(usize, num) orelse return error.Overflow;
        if (p.pos + num_usize > p.bytes.len) return error.Eof;
        defer p.pos += num_usize;
        return p.bytes[p.pos..][0..num_usize];
    }

    pub fn read_int(p: *InfoReader, comptime Int: type) !Int {
        if (p.pos + @size_of(Int) > p.bytes.len) return error.Eof;
        defer p.pos += @size_of(Int);
        return mem.read_int(Int, p.bytes[p.pos..][0..@size_of(Int)], .little);
    }

    pub fn read_offset(p: *InfoReader, dw_fmt: DwarfFormat) !u64 {
        return switch (dw_fmt) {
            .dwarf32 => try p.read_int(u32),
            .dwarf64 => try p.read_int(u64),
        };
    }

    pub fn read_uleb128(p: *InfoReader, comptime Type: type) !Type {
        var stream = std.io.fixed_buffer_stream(p.bytes[p.pos..]);
        var creader = std.io.counting_reader(stream.reader());
        const value: Type = try leb.read_uleb128(Type, creader.reader());
        p.pos += math.cast(usize, creader.bytes_read) orelse return error.Overflow;
        return value;
    }

    pub fn read_ileb128(p: *InfoReader, comptime Type: type) !Type {
        var stream = std.io.fixed_buffer_stream(p.bytes[p.pos..]);
        var creader = std.io.counting_reader(stream.reader());
        const value: Type = try leb.read_ileb128(Type, creader.reader());
        p.pos += math.cast(usize, creader.bytes_read) orelse return error.Overflow;
        return value;
    }

    pub fn seek_to(p: *InfoReader, off: u64) !void {
        p.pos = math.cast(usize, off) orelse return error.Overflow;
    }
};

pub const AbbrevReader = struct {
    bytes: []const u8,
    pos: usize = 0,

    pub fn has_more(p: AbbrevReader) bool {
        return p.pos < p.bytes.len;
    }

    pub fn read_decl(p: *AbbrevReader) !?AbbrevDecl {
        const pos = p.pos;
        const code = try p.read_uleb128(Code);
        if (code == 0) return null;

        const tag = try p.read_uleb128(Tag);
        const has_children = (try p.read_byte()) > 0;
        return .{
            .code = code,
            .pos = pos,
            .len = p.pos - pos,
            .tag = tag,
            .has_children = has_children,
        };
    }

    pub fn read_attr(p: *AbbrevReader) !?AbbrevAttr {
        const pos = p.pos;
        const at = try p.read_uleb128(At);
        const form = try p.read_uleb128(Form);
        return if (at == 0 and form == 0) null else .{
            .at = at,
            .form = form,
            .pos = pos,
            .len = p.pos - pos,
        };
    }

    pub fn read_byte(p: *AbbrevReader) !u8 {
        if (p.pos + 1 > p.bytes.len) return error.Eof;
        defer p.pos += 1;
        return p.bytes[p.pos];
    }

    pub fn read_uleb128(p: *AbbrevReader, comptime Type: type) !Type {
        var stream = std.io.fixed_buffer_stream(p.bytes[p.pos..]);
        var creader = std.io.counting_reader(stream.reader());
        const value: Type = try leb.read_uleb128(Type, creader.reader());
        p.pos += math.cast(usize, creader.bytes_read) orelse return error.Overflow;
        return value;
    }

    pub fn seek_to(p: *AbbrevReader, off: u64) !void {
        p.pos = math.cast(usize, off) orelse return error.Overflow;
    }
};

const AbbrevDecl = struct {
    code: Code,
    pos: usize,
    len: usize,
    tag: Tag,
    has_children: bool,
};

const AbbrevAttr = struct {
    at: At,
    form: Form,
    pos: usize,
    len: usize,
};

const CompileUnitHeader = struct {
    format: DwarfFormat,
    length: u64,
    version: u16,
    debug_abbrev_offset: u64,
    address_size: u8,
};

const Die = struct {
    pos: usize,
    len: usize,
};

const DwarfFormat = enum {
    dwarf32,
    dwarf64,
};

const dwarf = std.dwarf;
const leb = std.leb;
const log = std.log.scoped(.link);
const math = std.math;
const mem = std.mem;
const std = @import("std");

const At = u64;
const Code = u64;
const Form = u64;
const Tag = u64;

pub const AT = dwarf.AT;
pub const FORM = dwarf.FORM;
pub const TAG = dwarf.TAG;
