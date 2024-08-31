const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const mem = std.mem;
const log = std.log.scoped(.c);

const link = @import("../link.zig");
const Zcu = @import("../Module.zig");
const Module = @import("../Package/Module.zig");
const Compilation = @import("../Compilation.zig");
const Value = @import("../Value.zig");
const Type = @import("../type.zig").Type;
const C = link.File.C;
const Decl = Zcu.Decl;
const trace = @import("../tracy.zig").trace;
const LazySrcLoc = std.zig.LazySrcLoc;
const Air = @import("../Air.zig");
const Liveness = @import("../Liveness.zig");
const InternPool = @import("../InternPool.zig");
const Alignment = InternPool.Alignment;

const BigIntLimb = std.math.big.Limb;
const BigInt = std.math.big.int;

pub const CType = @import("c/Type.zig");

pub const CValue = union(enum) {
    none: void,
    new_local: LocalIndex,
    local: LocalIndex,
    /// Address of a local.
    local_ref: LocalIndex,
    /// A constant instruction, to be rendered inline.
    constant: Value,
    /// Index into the parameters
    arg: usize,
    /// The array field of a parameter
    arg_array: usize,
    /// Index into a tuple's fields
    field: usize,
    /// By-value
    decl: InternPool.DeclIndex,
    decl_ref: InternPool.DeclIndex,
    /// An undefined value (cannot be dereferenced)
    undef: Type,
    /// Rendered as an identifier (using fmt_ident)
    identifier: []const u8,
    /// Rendered as "payload." followed by as identifier (using fmt_ident)
    payload_identifier: []const u8,
    /// Rendered with fmt_ctype_pool_string
    ctype_pool_string: CType.Pool.String,
};

const BlockData = struct {
    block_id: usize,
    result: CValue,
};

pub const CValueMap = std.AutoHashMap(Air.Inst.Ref, CValue);

pub const LazyFnKey = union(enum) {
    tag_name: InternPool.DeclIndex,
    never_tail: InternPool.DeclIndex,
    never_inline: InternPool.DeclIndex,
};
pub const LazyFnValue = struct {
    fn_name: CType.Pool.String,
    data: Data,

    const Data = union {
        tag_name: Type,
        never_tail: void,
        never_inline: void,
    };
};
pub const LazyFnMap = std.AutoArrayHashMapUnmanaged(LazyFnKey, LazyFnValue);

const Local = struct {
    ctype: CType,
    flags: packed struct(u32) {
        alignas: CType.AlignAs,
        _: u20 = undefined,
    },

    fn get_type(local: Local) LocalType {
        return .{ .ctype = local.ctype, .alignas = local.flags.alignas };
    }
};

const LocalIndex = u16;
const LocalType = struct { ctype: CType, alignas: CType.AlignAs };
const LocalsList = std.AutoArrayHashMapUnmanaged(LocalIndex, void);
const LocalsMap = std.AutoArrayHashMapUnmanaged(LocalType, LocalsList);

const ValueRenderLocation = enum {
    FunctionArgument,
    Initializer,
    StaticInitializer,
    Other,

    fn is_initializer(loc: ValueRenderLocation) bool {
        return switch (loc) {
            .Initializer, .StaticInitializer => true,
            else => false,
        };
    }

    fn to_ctype_kind(loc: ValueRenderLocation) CType.Kind {
        return switch (loc) {
            .FunctionArgument => .parameter,
            .Initializer, .Other => .complete,
            .StaticInitializer => .global,
        };
    }
};

const BuiltinInfo = enum { none, bits };

const reserved_idents = std.StaticStringMap(void).init_comptime(.{
    // C language
    .{ "alignas", {
        @setEvalBranchQuota(4000);
    } },
    .{ "alignof", {} },
    .{ "asm", {} },
    .{ "atomic_bool", {} },
    .{ "atomic_char", {} },
    .{ "atomic_char16_t", {} },
    .{ "atomic_char32_t", {} },
    .{ "atomic_int", {} },
    .{ "atomic_int_fast16_t", {} },
    .{ "atomic_int_fast32_t", {} },
    .{ "atomic_int_fast64_t", {} },
    .{ "atomic_int_fast8_t", {} },
    .{ "atomic_int_least16_t", {} },
    .{ "atomic_int_least32_t", {} },
    .{ "atomic_int_least64_t", {} },
    .{ "atomic_int_least8_t", {} },
    .{ "atomic_intmax_t", {} },
    .{ "atomic_intptr_t", {} },
    .{ "atomic_llong", {} },
    .{ "atomic_long", {} },
    .{ "atomic_ptrdiff_t", {} },
    .{ "atomic_schar", {} },
    .{ "atomic_short", {} },
    .{ "atomic_size_t", {} },
    .{ "atomic_uchar", {} },
    .{ "atomic_uint", {} },
    .{ "atomic_uint_fast16_t", {} },
    .{ "atomic_uint_fast32_t", {} },
    .{ "atomic_uint_fast64_t", {} },
    .{ "atomic_uint_fast8_t", {} },
    .{ "atomic_uint_least16_t", {} },
    .{ "atomic_uint_least32_t", {} },
    .{ "atomic_uint_least64_t", {} },
    .{ "atomic_uint_least8_t", {} },
    .{ "atomic_uintmax_t", {} },
    .{ "atomic_uintptr_t", {} },
    .{ "atomic_ullong", {} },
    .{ "atomic_ulong", {} },
    .{ "atomic_ushort", {} },
    .{ "atomic_wchar_t", {} },
    .{ "auto", {} },
    .{ "bool", {} },
    .{ "break", {} },
    .{ "case", {} },
    .{ "char", {} },
    .{ "complex", {} },
    .{ "const", {} },
    .{ "continue", {} },
    .{ "default", {} },
    .{ "do", {} },
    .{ "double", {} },
    .{ "else", {} },
    .{ "enum", {} },
    .{ "extern", {} },
    .{ "float", {} },
    .{ "for", {} },
    .{ "fortran", {} },
    .{ "goto", {} },
    .{ "if", {} },
    .{ "imaginary", {} },
    .{ "inline", {} },
    .{ "int", {} },
    .{ "int16_t", {} },
    .{ "int32_t", {} },
    .{ "int64_t", {} },
    .{ "int8_t", {} },
    .{ "intptr_t", {} },
    .{ "long", {} },
    .{ "noreturn", {} },
    .{ "register", {} },
    .{ "restrict", {} },
    .{ "return", {} },
    .{ "short", {} },
    .{ "signed", {} },
    .{ "size_t", {} },
    .{ "sizeof", {} },
    .{ "ssize_t", {} },
    .{ "static", {} },
    .{ "static_assert", {} },
    .{ "struct", {} },
    .{ "switch", {} },
    .{ "thread_local", {} },
    .{ "typedef", {} },
    .{ "typeof", {} },
    .{ "uint16_t", {} },
    .{ "uint32_t", {} },
    .{ "uint64_t", {} },
    .{ "uint8_t", {} },
    .{ "uintptr_t", {} },
    .{ "union", {} },
    .{ "unsigned", {} },
    .{ "void", {} },
    .{ "volatile", {} },
    .{ "while", {} },

    // stdarg.h
    .{ "va_start", {} },
    .{ "va_arg", {} },
    .{ "va_end", {} },
    .{ "va_copy", {} },

    // stddef.h
    .{ "offsetof", {} },

    // windows.h
    .{ "max", {} },
    .{ "min", {} },
});

fn is_reserved_ident(ident: []const u8) bool {
    if (ident.len >= 2 and ident[0] == '_') { // C language
        switch (ident[1]) {
            'A'...'Z', '_' => return true,
            else => return false,
        }
    } else if (mem.starts_with(u8, ident, "DUMMYSTRUCTNAME") or
        mem.starts_with(u8, ident, "DUMMYUNIONNAME"))
    { // windows.h
        return true;
    } else return reserved_idents.has(ident);
}

fn format_ident(
    ident: []const u8,
    comptime fmt_str: []const u8,
    _: std.fmt.FormatOptions,
    writer: anytype,
) @TypeOf(writer).Error!void {
    const solo = fmt_str.len != 0 and fmt_str[0] == ' '; // space means solo; not part of a bigger ident.
    if (solo and is_reserved_ident(ident)) {
        try writer.write_all("zig_e_");
    }
    for (ident, 0..) |c, i| {
        switch (c) {
            'a'...'z', 'A'...'Z', '_' => try writer.write_byte(c),
            '.' => try writer.write_byte('_'),
            '0'...'9' => if (i == 0) {
                try writer.print("_{x:2}", .{c});
            } else {
                try writer.write_byte(c);
            },
            else => try writer.print("_{x:2}", .{c}),
        }
    }
}
pub fn fmt_ident(ident: []const u8) std.fmt.Formatter(format_ident) {
    return .{ .data = ident };
}

const CTypePoolStringFormatData = struct {
    ctype_pool_string: CType.Pool.String,
    ctype_pool: *const CType.Pool,
};
fn format_ctype_pool_string(
    data: CTypePoolStringFormatData,
    comptime fmt_str: []const u8,
    fmt_opts: std.fmt.FormatOptions,
    writer: anytype,
) @TypeOf(writer).Error!void {
    if (data.ctype_pool_string.to_slice(data.ctype_pool)) |slice|
        try format_ident(slice, fmt_str, fmt_opts, writer)
    else
        try writer.print("{}", .{data.ctype_pool_string.fmt(data.ctype_pool)});
}
pub fn fmt_ctype_pool_string(
    ctype_pool_string: CType.Pool.String,
    ctype_pool: *const CType.Pool,
) std.fmt.Formatter(format_ctype_pool_string) {
    return .{ .data = .{ .ctype_pool_string = ctype_pool_string, .ctype_pool = ctype_pool } };
}

// Returns true if `format_ident` would make any edits to ident.
// This must be kept in sync with `format_ident`.
pub fn is_mangled_ident(ident: []const u8, solo: bool) bool {
    if (solo and is_reserved_ident(ident)) return true;
    for (ident, 0..) |c, i| {
        switch (c) {
            'a'...'z', 'A'...'Z', '_' => {},
            '0'...'9' => if (i == 0) return true,
            else => return true,
        }
    }
    return false;
}

/// This data is available when outputting .c code for a `InternPool.Index`
/// that corresponds to `func`.
/// It is not available when generating .h file.
pub const Function = struct {
    air: Air,
    liveness: Liveness,
    value_map: CValueMap,
    blocks: std.AutoHashMapUnmanaged(Air.Inst.Index, BlockData) = .{},
    next_arg_index: usize = 0,
    next_block_index: usize = 0,
    object: Object,
    lazy_fns: LazyFnMap,
    func_index: InternPool.Index,
    /// All the locals, to be emitted at the top of the function.
    locals: std.ArrayListUnmanaged(Local) = .{},
    /// Which locals are available for reuse, based on Type.
    free_locals_map: LocalsMap = .{},
    /// Locals which will not be freed by Liveness. This is used after a
    /// Function body is lowered in order to make `free_locals_map` have
    /// 100% of the locals within so that it can be used to render the block
    /// of variable declarations at the top of a function, sorted descending
    /// by type alignment.
    /// The value is whether the alloc needs to be emitted in the header.
    allocs: std.AutoArrayHashMapUnmanaged(LocalIndex, bool) = .{},

    fn resolve_inst(f: *Function, ref: Air.Inst.Ref) !CValue {
        const gop = try f.value_map.get_or_put(ref);
        if (gop.found_existing) return gop.value_ptr.*;

        const zcu = f.object.dg.zcu;
        const val = (try f.air.value(ref, zcu)).?;
        const ty = f.type_of(ref);

        const result: CValue = if (lowers_to_array(ty, zcu)) result: {
            const writer = f.object.code_header_writer();
            const decl_c_value = try f.alloc_local_value(.{
                .ctype = try f.ctype_from_type(ty, .complete),
                .alignas = CType.AlignAs.from_abi_alignment(ty.abi_alignment(zcu)),
            });
            const gpa = f.object.dg.gpa;
            try f.allocs.put(gpa, decl_c_value.new_local, false);
            try writer.write_all("static ");
            try f.object.dg.render_type_and_name(writer, ty, decl_c_value, Const, .none, .complete);
            try writer.write_all(" = ");
            try f.object.dg.render_value(writer, val, .StaticInitializer);
            try writer.write_all(";\n ");
            break :result .{ .local = decl_c_value.new_local };
        } else .{ .constant = val };

        gop.value_ptr.* = result;
        return result;
    }

    fn want_safety(f: *Function) bool {
        return switch (f.object.dg.zcu.optimize_mode()) {
            .Debug, .ReleaseSafe => true,
            .ReleaseFast, .ReleaseSmall => false,
        };
    }

    /// Skips the reuse logic. This function should be used for any persistent allocation, i.e.
    /// those which go into `allocs`. This function does not add the resulting local into `allocs`;
    /// that responsibility lies with the caller.
    fn alloc_local_value(f: *Function, local_type: LocalType) !CValue {
        try f.locals.ensure_unused_capacity(f.object.dg.gpa, 1);
        defer f.locals.append_assume_capacity(.{
            .ctype = local_type.ctype,
            .flags = .{ .alignas = local_type.alignas },
        });
        return .{ .new_local = @int_cast(f.locals.items.len) };
    }

    fn alloc_local(f: *Function, inst: ?Air.Inst.Index, ty: Type) !CValue {
        return f.alloc_aligned_local(inst, .{
            .ctype = try f.ctype_from_type(ty, .complete),
            .alignas = CType.AlignAs.from_abi_alignment(ty.abi_alignment(f.object.dg.zcu)),
        });
    }

    /// Only allocates the local; does not print anything. Will attempt to re-use locals, so should
    /// not be used for persistent locals (i.e. those in `allocs`).
    fn alloc_aligned_local(f: *Function, inst: ?Air.Inst.Index, local_type: LocalType) !CValue {
        const result: CValue = result: {
            if (f.free_locals_map.get_ptr(local_type)) |locals_list| {
                if (locals_list.pop_or_null()) |local_entry| {
                    break :result .{ .new_local = local_entry.key };
                }
            }
            break :result try f.alloc_local_value(local_type);
        };
        if (inst) |i| {
            log.debug("%{d}: allocating t{d}", .{ i, result.new_local });
        } else {
            log.debug("allocating t{d}", .{result.new_local});
        }
        return result;
    }

    fn write_cvalue(f: *Function, w: anytype, c_value: CValue, location: ValueRenderLocation) !void {
        switch (c_value) {
            .none => unreachable,
            .new_local, .local => |i| try w.print("t{d}", .{i}),
            .local_ref => |i| try w.print("&t{d}", .{i}),
            .constant => |val| try f.object.dg.render_value(w, val, location),
            .arg => |i| try w.print("a{d}", .{i}),
            .arg_array => |i| try f.write_cvalue_member(w, .{ .arg = i }, .{ .identifier = "array" }),
            .undef => |ty| try f.object.dg.render_undef_value(w, ty, location),
            else => try f.object.dg.write_cvalue(w, c_value),
        }
    }

    fn write_cvalue_deref(f: *Function, w: anytype, c_value: CValue) !void {
        switch (c_value) {
            .none => unreachable,
            .new_local, .local, .constant => {
                try w.write_all("(*");
                try f.write_cvalue(w, c_value, .Other);
                try w.write_byte(')');
            },
            .local_ref => |i| try w.print("t{d}", .{i}),
            .arg => |i| try w.print("(*a{d})", .{i}),
            .arg_array => |i| {
                try w.write_all("(*");
                try f.write_cvalue_member(w, .{ .arg = i }, .{ .identifier = "array" });
                try w.write_byte(')');
            },
            else => try f.object.dg.write_cvalue_deref(w, c_value),
        }
    }

    fn write_cvalue_member(
        f: *Function,
        writer: anytype,
        c_value: CValue,
        member: CValue,
    ) error{ OutOfMemory, AnalysisFail }!void {
        switch (c_value) {
            .new_local, .local, .local_ref, .constant, .arg, .arg_array => {
                try f.write_cvalue(writer, c_value, .Other);
                try writer.write_byte('.');
                try f.write_cvalue(writer, member, .Other);
            },
            else => return f.object.dg.write_cvalue_member(writer, c_value, member),
        }
    }

    fn write_cvalue_deref_member(f: *Function, writer: anytype, c_value: CValue, member: CValue) !void {
        switch (c_value) {
            .new_local, .local, .arg, .arg_array => {
                try f.write_cvalue(writer, c_value, .Other);
                try writer.write_all("->");
            },
            .constant => {
                try writer.write_byte('(');
                try f.write_cvalue(writer, c_value, .Other);
                try writer.write_all(")->");
            },
            .local_ref => {
                try f.write_cvalue_deref(writer, c_value);
                try writer.write_byte('.');
            },
            else => return f.object.dg.write_cvalue_deref_member(writer, c_value, member),
        }
        try f.write_cvalue(writer, member, .Other);
    }

    fn fail(f: *Function, comptime format: []const u8, args: anytype) error{ AnalysisFail, OutOfMemory } {
        return f.object.dg.fail(format, args);
    }

    fn ctype_from_type(f: *Function, ty: Type, kind: CType.Kind) !CType {
        return f.object.dg.ctype_from_type(ty, kind);
    }

    fn byte_size(f: *Function, ctype: CType) u64 {
        return f.object.dg.byte_size(ctype);
    }

    fn render_type(f: *Function, w: anytype, ctype: Type) !void {
        return f.object.dg.render_type(w, ctype);
    }

    fn render_ctype(f: *Function, w: anytype, ctype: CType) !void {
        return f.object.dg.render_ctype(w, ctype);
    }

    fn render_int_cast(f: *Function, w: anytype, dest_ty: Type, src: CValue, v: Vectorize, src_ty: Type, location: ValueRenderLocation) !void {
        return f.object.dg.render_int_cast(w, dest_ty, .{ .c_value = .{ .f = f, .value = src, .v = v } }, src_ty, location);
    }

    fn fmt_int_literal(f: *Function, val: Value) !std.fmt.Formatter(format_int_literal) {
        return f.object.dg.fmt_int_literal(val, .Other);
    }

    fn get_lazy_fn_name(f: *Function, key: LazyFnKey, data: LazyFnValue.Data) ![]const u8 {
        const gpa = f.object.dg.gpa;
        const zcu = f.object.dg.zcu;
        const ctype_pool = &f.object.dg.ctype_pool;

        const gop = try f.lazy_fns.get_or_put(gpa, key);
        if (!gop.found_existing) {
            errdefer _ = f.lazy_fns.pop();

            gop.value_ptr.* = .{
                .fn_name = switch (key) {
                    .tag_name,
                    .never_tail,
                    .never_inline,
                    => |owner_decl| try ctype_pool.fmt(gpa, "zig_{s}_{}__{d}", .{
                        @tag_name(key),
                        fmt_ident(zcu.decl_ptr(owner_decl).name.to_slice(&zcu.intern_pool)),
                        @int_from_enum(owner_decl),
                    }),
                },
                .data = switch (key) {
                    .tag_name => .{ .tag_name = data.tag_name },
                    .never_tail => .{ .never_tail = data.never_tail },
                    .never_inline => .{ .never_inline = data.never_inline },
                },
            };
        }
        return gop.value_ptr.fn_name.to_slice(ctype_pool).?;
    }

    pub fn deinit(f: *Function) void {
        const gpa = f.object.dg.gpa;
        f.allocs.deinit(gpa);
        f.locals.deinit(gpa);
        deinit_free_locals_map(gpa, &f.free_locals_map);
        f.blocks.deinit(gpa);
        f.value_map.deinit();
        f.lazy_fns.deinit(gpa);
    }

    fn type_of(f: *Function, inst: Air.Inst.Ref) Type {
        const zcu = f.object.dg.zcu;
        return f.air.type_of(inst, &zcu.intern_pool);
    }

    fn type_of_index(f: *Function, inst: Air.Inst.Index) Type {
        const zcu = f.object.dg.zcu;
        return f.air.type_of_index(inst, &zcu.intern_pool);
    }

    fn copy_cvalue(f: *Function, ctype: CType, dst: CValue, src: CValue) !void {
        switch (dst) {
            .new_local, .local => |dst_local_index| switch (src) {
                .new_local, .local => |src_local_index| if (dst_local_index == src_local_index) return,
                else => {},
            },
            else => {},
        }
        const writer = f.object.writer();
        const a = try Assignment.start(f, writer, ctype);
        try f.write_cvalue(writer, dst, .Other);
        try a.assign(f, writer);
        try f.write_cvalue(writer, src, .Initializer);
        try a.end(f, writer);
    }

    fn move_cvalue(f: *Function, inst: Air.Inst.Index, ty: Type, src: CValue) !CValue {
        switch (src) {
            // Move the freshly allocated local to be owned by this instruction,
            // by returning it here instead of freeing it.
            .new_local => return src,
            else => {
                try free_cvalue(f, inst, src);
                const dst = try f.alloc_local(inst, ty);
                try f.copy_cvalue(try f.ctype_from_type(ty, .complete), dst, src);
                return dst;
            },
        }
    }

    fn free_cvalue(f: *Function, inst: ?Air.Inst.Index, val: CValue) !void {
        switch (val) {
            .new_local => |local_index| try free_local(f, inst, local_index, null),
            else => {},
        }
    }
};

/// This data is available when outputting .c code for a `Zcu`.
/// It is not available when generating .h file.
pub const Object = struct {
    dg: DeclGen,
    /// This is a borrowed reference from `link.C`.
    code: std.ArrayList(u8),
    /// Goes before code. Initialized and deinitialized in `gen_func`.
    code_header: std.ArrayList(u8) = undefined,
    indent_writer: IndentWriter(std.ArrayList(u8).Writer),

    fn writer(o: *Object) IndentWriter(std.ArrayList(u8).Writer).Writer {
        return o.indent_writer.writer();
    }

    fn code_header_writer(o: *Object) ArrayListWriter {
        return array_list_writer(&o.code_header);
    }
};

/// This data is available both when outputting .c code and when outputting an .h file.
pub const DeclGen = struct {
    gpa: mem.Allocator,
    zcu: *Zcu,
    mod: *Module,
    pass: Pass,
    is_naked_fn: bool,
    /// This is a borrowed reference from `link.C`.
    fwd_decl: std.ArrayList(u8),
    error_msg: ?*Zcu.ErrorMsg,
    ctype_pool: CType.Pool,
    scratch: std.ArrayListUnmanaged(u32),
    /// Keeps track of anonymous decls that need to be rendered before this
    /// (named) Decl in the output C code.
    anon_decl_deps: std.AutoArrayHashMapUnmanaged(InternPool.Index, C.DeclBlock),
    aligned_anon_decls: std.AutoArrayHashMapUnmanaged(InternPool.Index, Alignment),

    pub const Pass = union(enum) {
        decl: InternPool.DeclIndex,
        anon: InternPool.Index,
        flush,
    };

    fn fwd_decl_writer(dg: *DeclGen) ArrayListWriter {
        return array_list_writer(&dg.fwd_decl);
    }

    fn fail(dg: *DeclGen, comptime format: []const u8, args: anytype) error{ AnalysisFail, OutOfMemory } {
        @setCold(true);
        const zcu = dg.zcu;
        const decl_index = dg.pass.decl;
        const decl = zcu.decl_ptr(decl_index);
        const src_loc = decl.src_loc(zcu);
        dg.error_msg = try Zcu.ErrorMsg.create(dg.gpa, src_loc, format, args);
        return error.AnalysisFail;
    }

    fn render_anon_decl_value(
        dg: *DeclGen,
        writer: anytype,
        anon_decl: InternPool.Key.Ptr.BaseAddr.AnonDecl,
        location: ValueRenderLocation,
    ) error{ OutOfMemory, AnalysisFail }!void {
        const zcu = dg.zcu;
        const ip = &zcu.intern_pool;
        const ctype_pool = &dg.ctype_pool;
        const decl_val = Value.from_interned(anon_decl.val);
        const decl_ty = decl_val.type_of(zcu);

        // Render an undefined pointer if we have a pointer to a zero-bit or comptime type.
        const ptr_ty = Type.from_interned(anon_decl.orig_ty);
        if (ptr_ty.is_ptr_at_runtime(zcu) and !decl_ty.is_fn_or_has_runtime_bits(zcu)) {
            return dg.write_cvalue(writer, .{ .undef = ptr_ty });
        }

        // Chase function values in order to be able to reference the original function.
        if (decl_val.get_function(zcu)) |func|
            return dg.render_decl_value(writer, func.owner_decl, location);
        if (decl_val.get_extern_func(zcu)) |extern_func|
            return dg.render_decl_value(writer, extern_func.decl, location);

        assert(decl_val.get_variable(zcu) == null);

        // We shouldn't cast C function pointers as this is UB (when you call
        // them).  The analysis until now should ensure that the C function
        // pointers are compatible.  If they are not, then there is a bug
        // somewhere and we should let the C compiler tell us about it.
        const ptr_ctype = try dg.ctype_from_type(ptr_ty, .complete);
        const elem_ctype = ptr_ctype.info(ctype_pool).pointer.elem_ctype;
        const decl_ctype = try dg.ctype_from_type(decl_ty, .complete);
        const need_cast = !elem_ctype.eql(decl_ctype) and
            (elem_ctype.info(ctype_pool) != .function or decl_ctype.info(ctype_pool) != .function);
        if (need_cast) {
            try writer.write_all("((");
            try dg.render_ctype(writer, ptr_ctype);
            try writer.write_byte(')');
        }
        try writer.write_byte('&');
        try render_anon_decl_name(writer, decl_val);
        if (need_cast) try writer.write_byte(')');

        // Indicate that the anon decl should be rendered to the output so that
        // our reference above is not undefined.
        const ptr_type = ip.index_to_key(anon_decl.orig_ty).ptr_type;
        const gop = try dg.anon_decl_deps.get_or_put(dg.gpa, anon_decl.val);
        if (!gop.found_existing) gop.value_ptr.* = .{};

        // Only insert an alignment entry if the alignment is greater than ABI
        // alignment. If there is already an entry, keep the greater alignment.
        const explicit_alignment = ptr_type.flags.alignment;
        if (explicit_alignment != .none) {
            const abi_alignment = Type.from_interned(ptr_type.child).abi_alignment(zcu);
            if (explicit_alignment.order(abi_alignment).compare(.gt)) {
                const aligned_gop = try dg.aligned_anon_decls.get_or_put(dg.gpa, anon_decl.val);
                aligned_gop.value_ptr.* = if (aligned_gop.found_existing)
                    aligned_gop.value_ptr.max_strict(explicit_alignment)
                else
                    explicit_alignment;
            }
        }
    }

    fn render_decl_value(
        dg: *DeclGen,
        writer: anytype,
        decl_index: InternPool.DeclIndex,
        location: ValueRenderLocation,
    ) error{ OutOfMemory, AnalysisFail }!void {
        const zcu = dg.zcu;
        const ctype_pool = &dg.ctype_pool;
        const decl = zcu.decl_ptr(decl_index);
        assert(decl.has_tv);

        // Render an undefined pointer if we have a pointer to a zero-bit or comptime type.
        const decl_ty = decl.type_of(zcu);
        const ptr_ty = try decl.decl_ptr_type(zcu);
        if (!decl_ty.is_fn_or_has_runtime_bits(zcu)) {
            return dg.write_cvalue(writer, .{ .undef = ptr_ty });
        }

        // Chase function values in order to be able to reference the original function.
        if (decl.val.get_function(zcu)) |func| if (func.owner_decl != decl_index)
            return dg.render_decl_value(writer, func.owner_decl, location);
        if (decl.val.get_extern_func(zcu)) |extern_func| if (extern_func.decl != decl_index)
            return dg.render_decl_value(writer, extern_func.decl, location);

        if (decl.val.get_variable(zcu)) |variable| try dg.render_fwd_decl(decl_index, variable, .tentative);

        // We shouldn't cast C function pointers as this is UB (when you call
        // them).  The analysis until now should ensure that the C function
        // pointers are compatible.  If they are not, then there is a bug
        // somewhere and we should let the C compiler tell us about it.
        const ctype = try dg.ctype_from_type(ptr_ty, .complete);
        const elem_ctype = ctype.info(ctype_pool).pointer.elem_ctype;
        const decl_ctype = try dg.ctype_from_type(decl_ty, .complete);
        const need_cast = !elem_ctype.eql(decl_ctype) and
            (elem_ctype.info(ctype_pool) != .function or decl_ctype.info(ctype_pool) != .function);
        if (need_cast) {
            try writer.write_all("((");
            try dg.render_ctype(writer, ctype);
            try writer.write_byte(')');
        }
        try writer.write_byte('&');
        try dg.render_decl_name(writer, decl_index, 0);
        if (need_cast) try writer.write_byte(')');
    }

    fn render_pointer(
        dg: *DeclGen,
        writer: anytype,
        derivation: Value.PointerDeriveStep,
        location: ValueRenderLocation,
    ) error{ OutOfMemory, AnalysisFail }!void {
        const zcu = dg.zcu;
        switch (derivation) {
            .comptime_alloc_ptr, .comptime_field_ptr => unreachable,
            .int => |int| {
                const ptr_ctype = try dg.ctype_from_type(int.ptr_ty, .complete);
                const addr_val = try zcu.int_value(Type.usize, int.addr);
                try writer.write_byte('(');
                try dg.render_ctype(writer, ptr_ctype);
                try writer.print("){x}", .{try dg.fmt_int_literal(addr_val, .Other)});
            },

            .decl_ptr => |decl| try dg.render_decl_value(writer, decl, location),
            .anon_decl_ptr => |ad| try dg.render_anon_decl_value(writer, ad, location),

            inline .eu_payload_ptr, .opt_payload_ptr => |info| {
                try writer.write_all("&(");
                try dg.render_pointer(writer, info.parent.*, location);
                try writer.write_all(")->payload");
            },

            .field_ptr => |field| {
                const parent_ptr_ty = try field.parent.ptr_type(zcu);

                // Ensure complete type definition is available before accessing fields.
                _ = try dg.ctype_from_type(parent_ptr_ty.child_type(zcu), .complete);

                switch (field_location(parent_ptr_ty, field.result_ptr_ty, field.field_idx, zcu)) {
                    .begin => {
                        const ptr_ctype = try dg.ctype_from_type(field.result_ptr_ty, .complete);
                        try writer.write_byte('(');
                        try dg.render_ctype(writer, ptr_ctype);
                        try writer.write_byte(')');
                        try dg.render_pointer(writer, field.parent.*, location);
                    },
                    .field => |name| {
                        try writer.write_all("&(");
                        try dg.render_pointer(writer, field.parent.*, location);
                        try writer.write_all(")->");
                        try dg.write_cvalue(writer, name);
                    },
                    .byte_offset => |byte_offset| {
                        const ptr_ctype = try dg.ctype_from_type(field.result_ptr_ty, .complete);
                        try writer.write_byte('(');
                        try dg.render_ctype(writer, ptr_ctype);
                        try writer.write_byte(')');
                        const offset_val = try zcu.int_value(Type.usize, byte_offset);
                        try writer.write_all("((char *)");
                        try dg.render_pointer(writer, field.parent.*, location);
                        try writer.print(" + {})", .{try dg.fmt_int_literal(offset_val, .Other)});
                    },
                }
            },

            .elem_ptr => |elem| if (!(try elem.parent.ptr_type(zcu)).child_type(zcu).has_runtime_bits(zcu)) {
                // Element type is zero-bit, so lowers to `void`. The index is irrelevant; just cast the pointer.
                const ptr_ctype = try dg.ctype_from_type(elem.result_ptr_ty, .complete);
                try writer.write_byte('(');
                try dg.render_ctype(writer, ptr_ctype);
                try writer.write_byte(')');
                try dg.render_pointer(writer, elem.parent.*, location);
            } else {
                const index_val = try zcu.int_value(Type.usize, elem.elem_idx);
                // We want to do pointer arithmetic on a pointer to the element type.
                // We might have a pointer-to-array. In this case, we must cast first.
                const result_ctype = try dg.ctype_from_type(elem.result_ptr_ty, .complete);
                const parent_ctype = try dg.ctype_from_type(try elem.parent.ptr_type(zcu), .complete);
                if (result_ctype.eql(parent_ctype)) {
                    // The pointer already has an appropriate type - just do the arithmetic.
                    try writer.write_byte('(');
                    try dg.render_pointer(writer, elem.parent.*, location);
                    try writer.print(" + {})", .{try dg.fmt_int_literal(index_val, .Other)});
                } else {
                    // We probably have an array pointer `T (*)[n]`. Cast to an element pointer,
                    // and *then* apply the index.
                    try writer.write_all("((");
                    try dg.render_ctype(writer, result_ctype);
                    try writer.write_byte(')');
                    try dg.render_pointer(writer, elem.parent.*, location);
                    try writer.print(" + {})", .{try dg.fmt_int_literal(index_val, .Other)});
                }
            },

            .offset_and_cast => |oac| {
                const ptr_ctype = try dg.ctype_from_type(oac.new_ptr_ty, .complete);
                try writer.write_byte('(');
                try dg.render_ctype(writer, ptr_ctype);
                try writer.write_byte(')');
                if (oac.byte_offset == 0) {
                    try dg.render_pointer(writer, oac.parent.*, location);
                } else {
                    const offset_val = try zcu.int_value(Type.usize, oac.byte_offset);
                    try writer.write_all("((char *)");
                    try dg.render_pointer(writer, oac.parent.*, location);
                    try writer.print(" + {})", .{try dg.fmt_int_literal(offset_val, .Other)});
                }
            },
        }
    }

    fn render_error_name(dg: *DeclGen, writer: anytype, err_name: InternPool.NullTerminatedString) !void {
        const zcu = dg.zcu;
        const ip = &zcu.intern_pool;
        try writer.print("zig_error_{}", .{fmt_ident(err_name.to_slice(ip))});
    }

    fn render_value(
        dg: *DeclGen,
        writer: anytype,
        val: Value,
        location: ValueRenderLocation,
    ) error{ OutOfMemory, AnalysisFail }!void {
        const zcu = dg.zcu;
        const ip = &zcu.intern_pool;
        const target = &dg.mod.resolved_target.result;
        const ctype_pool = &dg.ctype_pool;

        const initializer_type: ValueRenderLocation = switch (location) {
            .StaticInitializer => .StaticInitializer,
            else => .Initializer,
        };

        const ty = val.type_of(zcu);
        if (val.is_undef_deep(zcu)) return dg.render_undef_value(writer, ty, location);
        const ctype = try dg.ctype_from_type(ty, location.to_ctype_kind());
        switch (ip.index_to_key(val.to_intern())) {
            // types, not values
            .int_type,
            .ptr_type,
            .array_type,
            .vector_type,
            .opt_type,
            .anyframe_type,
            .error_union_type,
            .simple_type,
            .struct_type,
            .anon_struct_type,
            .union_type,
            .opaque_type,
            .enum_type,
            .func_type,
            .error_set_type,
            .inferred_error_set_type,
            // memoization, not values
            .memoized_call,
            => unreachable,

            .undef => unreachable, // handled above
            .simple_value => |simple_value| switch (simple_value) {
                // non-runtime values
                .undefined => unreachable,
                .void => unreachable,
                .null => unreachable,
                .empty_struct => unreachable,
                .@"unreachable" => unreachable,
                .generic_poison => unreachable,

                .false => try writer.write_all("false"),
                .true => try writer.write_all("true"),
            },
            .variable,
            .extern_func,
            .func,
            .enum_literal,
            .empty_enum_value,
            => unreachable, // non-runtime values
            .int => |int| switch (int.storage) {
                .u64, .i64, .big_int => try writer.print("{}", .{try dg.fmt_int_literal(val, location)}),
                .lazy_align, .lazy_size => {
                    try writer.write_all("((");
                    try dg.render_ctype(writer, ctype);
                    try writer.print("){x})", .{try dg.fmt_int_literal(
                        try zcu.int_value(Type.usize, val.to_unsigned_int(zcu)),
                        .Other,
                    )});
                },
            },
            .err => |err| try dg.render_error_name(writer, err.name),
            .error_union => |error_union| switch (ctype.info(ctype_pool)) {
                .basic => switch (error_union.val) {
                    .err_name => |err_name| try dg.render_error_name(writer, err_name),
                    .payload => try writer.write_all("0"),
                },
                .pointer, .aligned, .array, .vector, .fwd_decl, .function => unreachable,
                .aggregate => |aggregate| {
                    if (!location.is_initializer()) {
                        try writer.write_byte('(');
                        try dg.render_ctype(writer, ctype);
                        try writer.write_byte(')');
                    }
                    try writer.write_byte('{');
                    for (0..aggregate.fields.len) |field_index| {
                        if (field_index > 0) try writer.write_byte(',');
                        switch (aggregate.fields.at(field_index, ctype_pool).name.index) {
                            .@"error" => switch (error_union.val) {
                                .err_name => |err_name| try dg.render_error_name(writer, err_name),
                                .payload => try writer.write_byte('0'),
                            },
                            .payload => switch (error_union.val) {
                                .err_name => try dg.render_undef_value(
                                    writer,
                                    ty.error_union_payload(zcu),
                                    initializer_type,
                                ),
                                .payload => |payload| try dg.render_value(
                                    writer,
                                    Value.from_interned(payload),
                                    initializer_type,
                                ),
                            },
                            else => unreachable,
                        }
                    }
                    try writer.write_byte('}');
                },
            },
            .enum_tag => |enum_tag| try dg.render_value(writer, Value.from_interned(enum_tag.int), location),
            .float => {
                const bits = ty.float_bits(target.*);
                const f128_val = val.to_float(f128, zcu);

                // All unsigned ints matching float types are pre-allocated.
                const repr_ty = zcu.int_type(.unsigned, bits) catch unreachable;

                assert(bits <= 128);
                var repr_val_limbs: [BigInt.calc_twos_comp_limb_count(128)]BigIntLimb = undefined;
                var repr_val_big = BigInt.Mutable{
                    .limbs = &repr_val_limbs,
                    .len = undefined,
                    .positive = undefined,
                };

                switch (bits) {
                    16 => repr_val_big.set(@as(u16, @bit_cast(val.to_float(f16, zcu)))),
                    32 => repr_val_big.set(@as(u32, @bit_cast(val.to_float(f32, zcu)))),
                    64 => repr_val_big.set(@as(u64, @bit_cast(val.to_float(f64, zcu)))),
                    80 => repr_val_big.set(@as(u80, @bit_cast(val.to_float(f80, zcu)))),
                    128 => repr_val_big.set(@as(u128, @bit_cast(f128_val))),
                    else => unreachable,
                }

                var empty = true;
                if (std.math.is_finite(f128_val)) {
                    try writer.write_all("zig_make_");
                    try dg.render_type_for_builtin_fn_name(writer, ty);
                    try writer.write_byte('(');
                    switch (bits) {
                        16 => try writer.print("{x}", .{val.to_float(f16, zcu)}),
                        32 => try writer.print("{x}", .{val.to_float(f32, zcu)}),
                        64 => try writer.print("{x}", .{val.to_float(f64, zcu)}),
                        80 => try writer.print("{x}", .{val.to_float(f80, zcu)}),
                        128 => try writer.print("{x}", .{f128_val}),
                        else => unreachable,
                    }
                    try writer.write_all(", ");
                    empty = false;
                } else {
                    // is_signal_nan is equivalent to is_nan currently, and MSVC doens't have nans, so prefer nan
                    const operation = if (std.math.is_nan(f128_val))
                        "nan"
                    else if (std.math.is_signal_nan(f128_val))
                        "nans"
                    else if (std.math.is_inf(f128_val))
                        "inf"
                    else
                        unreachable;

                    if (location == .StaticInitializer) {
                        if (!std.math.is_nan(f128_val) and std.math.is_signal_nan(f128_val))
                            return dg.fail("TODO: C backend: implement nans rendering in static initializers", .{});

                        // MSVC doesn't have a way to define a custom or signaling NaN value in a constant expression

                        // TODO: Re-enable this check, otherwise we're writing qnan bit patterns on msvc incorrectly
                        // if (std.math.is_nan(f128_val) and f128_val != std.math.nan(f128))
                        //     return dg.fail("Only quiet nans are supported in global variable initializers", .{});
                    }

                    try writer.write_all("zig_");
                    try writer.write_all(if (location == .StaticInitializer) "init" else "make");
                    try writer.write_all("_special_");
                    try dg.render_type_for_builtin_fn_name(writer, ty);
                    try writer.write_byte('(');
                    if (std.math.signbit(f128_val)) try writer.write_byte('-');
                    try writer.write_all(", ");
                    try writer.write_all(operation);
                    try writer.write_all(", ");
                    if (std.math.is_nan(f128_val)) switch (bits) {
                        // We only actually need to pass the significand, but it will get
                        // properly masked anyway, so just pass the whole value.
                        16 => try writer.print("\"0x{x}\"", .{@as(u16, @bit_cast(val.to_float(f16, zcu)))}),
                        32 => try writer.print("\"0x{x}\"", .{@as(u32, @bit_cast(val.to_float(f32, zcu)))}),
                        64 => try writer.print("\"0x{x}\"", .{@as(u64, @bit_cast(val.to_float(f64, zcu)))}),
                        80 => try writer.print("\"0x{x}\"", .{@as(u80, @bit_cast(val.to_float(f80, zcu)))}),
                        128 => try writer.print("\"0x{x}\"", .{@as(u128, @bit_cast(f128_val))}),
                        else => unreachable,
                    };
                    try writer.write_all(", ");
                    empty = false;
                }
                try writer.print("{x}", .{try dg.fmt_int_literal(
                    try zcu.int_value_big(repr_ty, repr_val_big.to_const()),
                    location,
                )});
                if (!empty) try writer.write_byte(')');
            },
            .slice => |slice| {
                const aggregate = ctype.info(ctype_pool).aggregate;
                if (!location.is_initializer()) {
                    try writer.write_byte('(');
                    try dg.render_ctype(writer, ctype);
                    try writer.write_byte(')');
                }
                try writer.write_byte('{');
                for (0..aggregate.fields.len) |field_index| {
                    if (field_index > 0) try writer.write_byte(',');
                    try dg.render_value(writer, Value.from_interned(
                        switch (aggregate.fields.at(field_index, ctype_pool).name.index) {
                            .ptr => slice.ptr,
                            .len => slice.len,
                            else => unreachable,
                        },
                    ), initializer_type);
                }
                try writer.write_byte('}');
            },
            .ptr => {
                var arena = std.heap.ArenaAllocator.init(zcu.gpa);
                defer arena.deinit();
                const derivation = try val.pointer_derivation(arena.allocator(), zcu);
                try dg.render_pointer(writer, derivation, location);
            },
            .opt => |opt| switch (ctype.info(ctype_pool)) {
                .basic => if (ctype.is_bool()) try writer.write_all(switch (opt.val) {
                    .none => "true",
                    else => "false",
                }) else switch (opt.val) {
                    .none => try writer.write_all("0"),
                    else => |payload| switch (ip.index_to_key(payload)) {
                        .undef => |err_ty| try dg.render_undef_value(
                            writer,
                            Type.from_interned(err_ty),
                            location,
                        ),
                        .err => |err| try dg.render_error_name(writer, err.name),
                        else => unreachable,
                    },
                },
                .pointer => switch (opt.val) {
                    .none => try writer.write_all("NULL"),
                    else => |payload| try dg.render_value(writer, Value.from_interned(payload), location),
                },
                .aligned, .array, .vector, .fwd_decl, .function => unreachable,
                .aggregate => |aggregate| {
                    switch (opt.val) {
                        .none => {},
                        else => |payload| switch (aggregate.fields.at(0, ctype_pool).name.index) {
                            .is_null, .payload => {},
                            .ptr, .len => return dg.render_value(
                                writer,
                                Value.from_interned(payload),
                                location,
                            ),
                            else => unreachable,
                        },
                    }
                    if (!location.is_initializer()) {
                        try writer.write_byte('(');
                        try dg.render_ctype(writer, ctype);
                        try writer.write_byte(')');
                    }
                    try writer.write_byte('{');
                    for (0..aggregate.fields.len) |field_index| {
                        if (field_index > 0) try writer.write_byte(',');
                        switch (aggregate.fields.at(field_index, ctype_pool).name.index) {
                            .is_null => try writer.write_all(switch (opt.val) {
                                .none => "true",
                                else => "false",
                            }),
                            .payload => switch (opt.val) {
                                .none => try dg.render_undef_value(
                                    writer,
                                    ty.optional_child(zcu),
                                    initializer_type,
                                ),
                                else => |payload| try dg.render_value(
                                    writer,
                                    Value.from_interned(payload),
                                    initializer_type,
                                ),
                            },
                            .ptr => try writer.write_all("NULL"),
                            .len => try dg.render_undef_value(writer, Type.usize, initializer_type),
                            else => unreachable,
                        }
                    }
                    try writer.write_byte('}');
                },
            },
            .aggregate => switch (ip.index_to_key(ty.to_intern())) {
                .array_type, .vector_type => {
                    if (location == .FunctionArgument) {
                        try writer.write_byte('(');
                        try dg.render_ctype(writer, ctype);
                        try writer.write_byte(')');
                    }
                    const ai = ty.array_info(zcu);
                    if (ai.elem_type.eql(Type.u8, zcu)) {
                        var literal = string_literal(writer, ty.array_len_including_sentinel(zcu));
                        try literal.start();
                        var index: usize = 0;
                        while (index < ai.len) : (index += 1) {
                            const elem_val = try val.elem_value(zcu, index);
                            const elem_val_u8: u8 = if (elem_val.is_undef(zcu))
                                undef_pattern(u8)
                            else
                                @int_cast(elem_val.to_unsigned_int(zcu));
                            try literal.write_char(elem_val_u8);
                        }
                        if (ai.sentinel) |s| {
                            const s_u8: u8 = @int_cast(s.to_unsigned_int(zcu));
                            if (s_u8 != 0) try literal.write_char(s_u8);
                        }
                        try literal.end();
                    } else {
                        try writer.write_byte('{');
                        var index: usize = 0;
                        while (index < ai.len) : (index += 1) {
                            if (index != 0) try writer.write_byte(',');
                            const elem_val = try val.elem_value(zcu, index);
                            try dg.render_value(writer, elem_val, initializer_type);
                        }
                        if (ai.sentinel) |s| {
                            if (index != 0) try writer.write_byte(',');
                            try dg.render_value(writer, s, initializer_type);
                        }
                        try writer.write_byte('}');
                    }
                },
                .anon_struct_type => |tuple| {
                    if (!location.is_initializer()) {
                        try writer.write_byte('(');
                        try dg.render_ctype(writer, ctype);
                        try writer.write_byte(')');
                    }

                    try writer.write_byte('{');
                    var empty = true;
                    for (0..tuple.types.len) |field_index| {
                        const comptime_val = tuple.values.get(ip)[field_index];
                        if (comptime_val != .none) continue;
                        const field_ty = Type.from_interned(tuple.types.get(ip)[field_index]);
                        if (!field_ty.has_runtime_bits_ignore_comptime(zcu)) continue;

                        if (!empty) try writer.write_byte(',');

                        const field_val = Value.from_interned(
                            switch (ip.index_to_key(val.to_intern()).aggregate.storage) {
                                .bytes => |bytes| try ip.get(zcu.gpa, .{ .int = .{
                                    .ty = field_ty.to_intern(),
                                    .storage = .{ .u64 = bytes.at(field_index, ip) },
                                } }),
                                .elems => |elems| elems[field_index],
                                .repeated_elem => |elem| elem,
                            },
                        );
                        try dg.render_value(writer, field_val, initializer_type);

                        empty = false;
                    }
                    try writer.write_byte('}');
                },
                .struct_type => {
                    const loaded_struct = ip.load_struct_type(ty.to_intern());
                    switch (loaded_struct.layout) {
                        .auto, .@"extern" => {
                            if (!location.is_initializer()) {
                                try writer.write_byte('(');
                                try dg.render_ctype(writer, ctype);
                                try writer.write_byte(')');
                            }

                            try writer.write_byte('{');
                            var field_it = loaded_struct.iterate_runtime_order(ip);
                            var need_comma = false;
                            while (field_it.next()) |field_index| {
                                const field_ty = Type.from_interned(loaded_struct.field_types.get(ip)[field_index]);
                                if (!field_ty.has_runtime_bits_ignore_comptime(zcu)) continue;

                                if (need_comma) try writer.write_byte(',');
                                need_comma = true;
                                const field_val = switch (ip.index_to_key(val.to_intern()).aggregate.storage) {
                                    .bytes => |bytes| try ip.get(zcu.gpa, .{ .int = .{
                                        .ty = field_ty.to_intern(),
                                        .storage = .{ .u64 = bytes.at(field_index, ip) },
                                    } }),
                                    .elems => |elems| elems[field_index],
                                    .repeated_elem => |elem| elem,
                                };
                                try dg.render_value(writer, Value.from_interned(field_val), initializer_type);
                            }
                            try writer.write_byte('}');
                        },
                        .@"packed" => {
                            const int_info = ty.int_info(zcu);

                            const bits = Type.smallest_unsigned_bits(int_info.bits - 1);
                            const bit_offset_ty = try zcu.int_type(.unsigned, bits);

                            var bit_offset: u64 = 0;
                            var eff_num_fields: usize = 0;

                            for (0..loaded_struct.field_types.len) |field_index| {
                                const field_ty = Type.from_interned(loaded_struct.field_types.get(ip)[field_index]);
                                if (!field_ty.has_runtime_bits_ignore_comptime(zcu)) continue;
                                eff_num_fields += 1;
                            }

                            if (eff_num_fields == 0) {
                                try writer.write_byte('(');
                                try dg.render_undef_value(writer, ty, location);
                                try writer.write_byte(')');
                            } else if (ty.bit_size(zcu) > 64) {
                                // zig_or_u128(zig_or_u128(zig_shl_u128(a, a_off), zig_shl_u128(b, b_off)), zig_shl_u128(c, c_off))
                                var num_or = eff_num_fields - 1;
                                while (num_or > 0) : (num_or -= 1) {
                                    try writer.write_all("zig_or_");
                                    try dg.render_type_for_builtin_fn_name(writer, ty);
                                    try writer.write_byte('(');
                                }

                                var eff_index: usize = 0;
                                var needs_closing_paren = false;
                                for (0..loaded_struct.field_types.len) |field_index| {
                                    const field_ty = Type.from_interned(loaded_struct.field_types.get(ip)[field_index]);
                                    if (!field_ty.has_runtime_bits_ignore_comptime(zcu)) continue;

                                    const field_val = switch (ip.index_to_key(val.to_intern()).aggregate.storage) {
                                        .bytes => |bytes| try ip.get(zcu.gpa, .{ .int = .{
                                            .ty = field_ty.to_intern(),
                                            .storage = .{ .u64 = bytes.at(field_index, ip) },
                                        } }),
                                        .elems => |elems| elems[field_index],
                                        .repeated_elem => |elem| elem,
                                    };
                                    const cast_context = IntCastContext{ .value = .{ .value = Value.from_interned(field_val) } };
                                    if (bit_offset != 0) {
                                        try writer.write_all("zig_shl_");
                                        try dg.render_type_for_builtin_fn_name(writer, ty);
                                        try writer.write_byte('(');
                                        try dg.render_int_cast(writer, ty, cast_context, field_ty, .FunctionArgument);
                                        try writer.write_all(", ");
                                        try dg.render_value(writer, try zcu.int_value(bit_offset_ty, bit_offset), .FunctionArgument);
                                        try writer.write_byte(')');
                                    } else {
                                        try dg.render_int_cast(writer, ty, cast_context, field_ty, .FunctionArgument);
                                    }

                                    if (needs_closing_paren) try writer.write_byte(')');
                                    if (eff_index != eff_num_fields - 1) try writer.write_all(", ");

                                    bit_offset += field_ty.bit_size(zcu);
                                    needs_closing_paren = true;
                                    eff_index += 1;
                                }
                            } else {
                                try writer.write_byte('(');
                                // a << a_off | b << b_off | c << c_off
                                var empty = true;
                                for (0..loaded_struct.field_types.len) |field_index| {
                                    const field_ty = Type.from_interned(loaded_struct.field_types.get(ip)[field_index]);
                                    if (!field_ty.has_runtime_bits_ignore_comptime(zcu)) continue;

                                    if (!empty) try writer.write_all(" | ");
                                    try writer.write_byte('(');
                                    try dg.render_ctype(writer, ctype);
                                    try writer.write_byte(')');

                                    const field_val = switch (ip.index_to_key(val.to_intern()).aggregate.storage) {
                                        .bytes => |bytes| try ip.get(zcu.gpa, .{ .int = .{
                                            .ty = field_ty.to_intern(),
                                            .storage = .{ .u64 = bytes.at(field_index, ip) },
                                        } }),
                                        .elems => |elems| elems[field_index],
                                        .repeated_elem => |elem| elem,
                                    };

                                    if (bit_offset != 0) {
                                        try dg.render_value(writer, Value.from_interned(field_val), .Other);
                                        try writer.write_all(" << ");
                                        try dg.render_value(writer, try zcu.int_value(bit_offset_ty, bit_offset), .FunctionArgument);
                                    } else {
                                        try dg.render_value(writer, Value.from_interned(field_val), .Other);
                                    }

                                    bit_offset += field_ty.bit_size(zcu);
                                    empty = false;
                                }
                                try writer.write_byte(')');
                            }
                        },
                    }
                },
                else => unreachable,
            },
            .un => |un| {
                const loaded_union = ip.load_union_type(ty.to_intern());
                if (un.tag == .none) {
                    const backing_ty = try ty.union_backing_type(zcu);
                    switch (loaded_union.get_layout(ip)) {
                        .@"packed" => {
                            if (!location.is_initializer()) {
                                try writer.write_byte('(');
                                try dg.render_type(writer, backing_ty);
                                try writer.write_byte(')');
                            }
                            try dg.render_value(writer, Value.from_interned(un.val), location);
                        },
                        .@"extern" => {
                            if (location == .StaticInitializer) {
                                return dg.fail("TODO: C backend: implement extern union backing type rendering in static initializers", .{});
                            }

                            const ptr_ty = try zcu.single_const_ptr_type(ty);
                            try writer.write_all("*((");
                            try dg.render_type(writer, ptr_ty);
                            try writer.write_all(")(");
                            try dg.render_type(writer, backing_ty);
                            try writer.write_all("){");
                            try dg.render_value(writer, Value.from_interned(un.val), location);
                            try writer.write_all("})");
                        },
                        else => unreachable,
                    }
                } else {
                    if (!location.is_initializer()) {
                        try writer.write_byte('(');
                        try dg.render_ctype(writer, ctype);
                        try writer.write_byte(')');
                    }

                    const field_index = zcu.union_tag_field_index(loaded_union, Value.from_interned(un.tag)).?;
                    const field_ty = Type.from_interned(loaded_union.field_types.get(ip)[field_index]);
                    const field_name = loaded_union.load_tag_type(ip).names.get(ip)[field_index];
                    if (loaded_union.get_layout(ip) == .@"packed") {
                        if (field_ty.has_runtime_bits(zcu)) {
                            if (field_ty.is_ptr_at_runtime(zcu)) {
                                try writer.write_byte('(');
                                try dg.render_ctype(writer, ctype);
                                try writer.write_byte(')');
                            } else if (field_ty.zig_type_tag(zcu) == .Float) {
                                try writer.write_byte('(');
                                try dg.render_ctype(writer, ctype);
                                try writer.write_byte(')');
                            }
                            try dg.render_value(writer, Value.from_interned(un.val), location);
                        } else try writer.write_all("0");
                        return;
                    }

                    const has_tag = loaded_union.has_tag(ip);
                    if (has_tag) try writer.write_byte('{');
                    const aggregate = ctype.info(ctype_pool).aggregate;
                    for (0..if (has_tag) aggregate.fields.len else 1) |outer_field_index| {
                        if (outer_field_index > 0) try writer.write_byte(',');
                        switch (if (has_tag)
                            aggregate.fields.at(outer_field_index, ctype_pool).name.index
                        else
                            .payload) {
                            .tag => try dg.render_value(
                                writer,
                                Value.from_interned(un.tag),
                                initializer_type,
                            ),
                            .payload => {
                                try writer.write_byte('{');
                                if (field_ty.has_runtime_bits(zcu)) {
                                    try writer.print(" .{ } = ", .{fmt_ident(field_name.to_slice(ip))});
                                    try dg.render_value(
                                        writer,
                                        Value.from_interned(un.val),
                                        initializer_type,
                                    );
                                    try writer.write_byte(' ');
                                } else for (0..loaded_union.field_types.len) |inner_field_index| {
                                    const inner_field_ty = Type.from_interned(
                                        loaded_union.field_types.get(ip)[inner_field_index],
                                    );
                                    if (!inner_field_ty.has_runtime_bits(zcu)) continue;
                                    try dg.render_undef_value(writer, inner_field_ty, initializer_type);
                                    break;
                                }
                                try writer.write_byte('}');
                            },
                            else => unreachable,
                        }
                    }
                    if (has_tag) try writer.write_byte('}');
                }
            },
        }
    }

    fn render_undef_value(
        dg: *DeclGen,
        writer: anytype,
        ty: Type,
        location: ValueRenderLocation,
    ) error{ OutOfMemory, AnalysisFail }!void {
        const zcu = dg.zcu;
        const ip = &zcu.intern_pool;
        const target = &dg.mod.resolved_target.result;
        const ctype_pool = &dg.ctype_pool;

        const initializer_type: ValueRenderLocation = switch (location) {
            .StaticInitializer => .StaticInitializer,
            else => .Initializer,
        };

        const safety_on = switch (zcu.optimize_mode()) {
            .Debug, .ReleaseSafe => true,
            .ReleaseFast, .ReleaseSmall => false,
        };

        const ctype = try dg.ctype_from_type(ty, location.to_ctype_kind());
        switch (ty.to_intern()) {
            .c_longdouble_type,
            .f16_type,
            .f32_type,
            .f64_type,
            .f80_type,
            .f128_type,
            => {
                const bits = ty.float_bits(target.*);
                // All unsigned ints matching float types are pre-allocated.
                const repr_ty = zcu.int_type(.unsigned, bits) catch unreachable;

                try writer.write_all("zig_make_");
                try dg.render_type_for_builtin_fn_name(writer, ty);
                try writer.write_byte('(');
                switch (bits) {
                    16 => try writer.print("{x}", .{@as(f16, @bit_cast(undef_pattern(i16)))}),
                    32 => try writer.print("{x}", .{@as(f32, @bit_cast(undef_pattern(i32)))}),
                    64 => try writer.print("{x}", .{@as(f64, @bit_cast(undef_pattern(i64)))}),
                    80 => try writer.print("{x}", .{@as(f80, @bit_cast(undef_pattern(i80)))}),
                    128 => try writer.print("{x}", .{@as(f128, @bit_cast(undef_pattern(i128)))}),
                    else => unreachable,
                }
                try writer.write_all(", ");
                try dg.render_undef_value(writer, repr_ty, .FunctionArgument);
                return writer.write_byte(')');
            },
            .bool_type => try writer.write_all(if (safety_on) "0xaa" else "false"),
            else => switch (ip.index_to_key(ty.to_intern())) {
                .simple_type,
                .int_type,
                .enum_type,
                .error_set_type,
                .inferred_error_set_type,
                => return writer.print("{x}", .{
                    try dg.fmt_int_literal(try zcu.undef_value(ty), location),
                }),
                .ptr_type => |ptr_type| switch (ptr_type.flags.size) {
                    .One, .Many, .C => {
                        try writer.write_all("((");
                        try dg.render_ctype(writer, ctype);
                        return writer.print("){x})", .{
                            try dg.fmt_int_literal(try zcu.undef_value(Type.usize), .Other),
                        });
                    },
                    .Slice => {
                        if (!location.is_initializer()) {
                            try writer.write_byte('(');
                            try dg.render_ctype(writer, ctype);
                            try writer.write_byte(')');
                        }

                        try writer.write_all("{(");
                        const ptr_ty = ty.slice_ptr_field_type(zcu);
                        try dg.render_type(writer, ptr_ty);
                        return writer.print("){x}, {0x}}}", .{
                            try dg.fmt_int_literal(try zcu.undef_value(Type.usize), .Other),
                        });
                    },
                },
                .opt_type => |child_type| switch (ctype.info(ctype_pool)) {
                    .basic, .pointer => try dg.render_undef_value(
                        writer,
                        Type.from_interned(if (ctype.is_bool()) .bool_type else child_type),
                        location,
                    ),
                    .aligned, .array, .vector, .fwd_decl, .function => unreachable,
                    .aggregate => |aggregate| {
                        switch (aggregate.fields.at(0, ctype_pool).name.index) {
                            .is_null, .payload => {},
                            .ptr, .len => return dg.render_undef_value(
                                writer,
                                Type.from_interned(child_type),
                                location,
                            ),
                            else => unreachable,
                        }
                        if (!location.is_initializer()) {
                            try writer.write_byte('(');
                            try dg.render_ctype(writer, ctype);
                            try writer.write_byte(')');
                        }
                        try writer.write_byte('{');
                        for (0..aggregate.fields.len) |field_index| {
                            if (field_index > 0) try writer.write_byte(',');
                            try dg.render_undef_value(writer, Type.from_interned(
                                switch (aggregate.fields.at(field_index, ctype_pool).name.index) {
                                    .is_null => .bool_type,
                                    .payload => child_type,
                                    else => unreachable,
                                },
                            ), initializer_type);
                        }
                        try writer.write_byte('}');
                    },
                },
                .struct_type => {
                    const loaded_struct = ip.load_struct_type(ty.to_intern());
                    switch (loaded_struct.layout) {
                        .auto, .@"extern" => {
                            if (!location.is_initializer()) {
                                try writer.write_byte('(');
                                try dg.render_ctype(writer, ctype);
                                try writer.write_byte(')');
                            }

                            try writer.write_byte('{');
                            var field_it = loaded_struct.iterate_runtime_order(ip);
                            var need_comma = false;
                            while (field_it.next()) |field_index| {
                                const field_ty = Type.from_interned(loaded_struct.field_types.get(ip)[field_index]);
                                if (!field_ty.has_runtime_bits_ignore_comptime(zcu)) continue;

                                if (need_comma) try writer.write_byte(',');
                                need_comma = true;
                                try dg.render_undef_value(writer, field_ty, initializer_type);
                            }
                            return writer.write_byte('}');
                        },
                        .@"packed" => return writer.print("{x}", .{
                            try dg.fmt_int_literal(try zcu.undef_value(ty), .Other),
                        }),
                    }
                },
                .anon_struct_type => |anon_struct_info| {
                    if (!location.is_initializer()) {
                        try writer.write_byte('(');
                        try dg.render_ctype(writer, ctype);
                        try writer.write_byte(')');
                    }

                    try writer.write_byte('{');
                    var need_comma = false;
                    for (0..anon_struct_info.types.len) |field_index| {
                        if (anon_struct_info.values.get(ip)[field_index] != .none) continue;
                        const field_ty = Type.from_interned(anon_struct_info.types.get(ip)[field_index]);
                        if (!field_ty.has_runtime_bits_ignore_comptime(zcu)) continue;

                        if (need_comma) try writer.write_byte(',');
                        need_comma = true;
                        try dg.render_undef_value(writer, field_ty, initializer_type);
                    }
                    return writer.write_byte('}');
                },
                .union_type => {
                    const loaded_union = ip.load_union_type(ty.to_intern());
                    switch (loaded_union.get_layout(ip)) {
                        .auto, .@"extern" => {
                            if (!location.is_initializer()) {
                                try writer.write_byte('(');
                                try dg.render_ctype(writer, ctype);
                                try writer.write_byte(')');
                            }

                            const has_tag = loaded_union.has_tag(ip);
                            if (has_tag) try writer.write_byte('{');
                            const aggregate = ctype.info(ctype_pool).aggregate;
                            for (0..if (has_tag) aggregate.fields.len else 1) |outer_field_index| {
                                if (outer_field_index > 0) try writer.write_byte(',');
                                switch (if (has_tag)
                                    aggregate.fields.at(outer_field_index, ctype_pool).name.index
                                else
                                    .payload) {
                                    .tag => try dg.render_undef_value(
                                        writer,
                                        Type.from_interned(loaded_union.enum_tag_ty),
                                        initializer_type,
                                    ),
                                    .payload => {
                                        try writer.write_byte('{');
                                        for (0..loaded_union.field_types.len) |inner_field_index| {
                                            const inner_field_ty = Type.from_interned(
                                                loaded_union.field_types.get(ip)[inner_field_index],
                                            );
                                            if (!inner_field_ty.has_runtime_bits(zcu)) continue;
                                            try dg.render_undef_value(
                                                writer,
                                                inner_field_ty,
                                                initializer_type,
                                            );
                                            break;
                                        }
                                        try writer.write_byte('}');
                                    },
                                    else => unreachable,
                                }
                            }
                            if (has_tag) try writer.write_byte('}');
                        },
                        .@"packed" => return writer.print("{x}", .{
                            try dg.fmt_int_literal(try zcu.undef_value(ty), .Other),
                        }),
                    }
                },
                .error_union_type => |error_union_type| switch (ctype.info(ctype_pool)) {
                    .basic => try dg.render_undef_value(
                        writer,
                        Type.from_interned(error_union_type.error_set_type),
                        location,
                    ),
                    .pointer, .aligned, .array, .vector, .fwd_decl, .function => unreachable,
                    .aggregate => |aggregate| {
                        if (!location.is_initializer()) {
                            try writer.write_byte('(');
                            try dg.render_ctype(writer, ctype);
                            try writer.write_byte(')');
                        }
                        try writer.write_byte('{');
                        for (0..aggregate.fields.len) |field_index| {
                            if (field_index > 0) try writer.write_byte(',');
                            try dg.render_undef_value(
                                writer,
                                Type.from_interned(
                                    switch (aggregate.fields.at(field_index, ctype_pool).name.index) {
                                        .@"error" => error_union_type.error_set_type,
                                        .payload => error_union_type.payload_type,
                                        else => unreachable,
                                    },
                                ),
                                initializer_type,
                            );
                        }
                        try writer.write_byte('}');
                    },
                },
                .array_type, .vector_type => {
                    const ai = ty.array_info(zcu);
                    if (ai.elem_type.eql(Type.u8, zcu)) {
                        const c_len = ty.array_len_including_sentinel(zcu);
                        var literal = string_literal(writer, c_len);
                        try literal.start();
                        var index: u64 = 0;
                        while (index < c_len) : (index += 1)
                            try literal.write_char(0xaa);
                        return literal.end();
                    } else {
                        if (!location.is_initializer()) {
                            try writer.write_byte('(');
                            try dg.render_ctype(writer, ctype);
                            try writer.write_byte(')');
                        }

                        try writer.write_byte('{');
                        const c_len = ty.array_len_including_sentinel(zcu);
                        var index: u64 = 0;
                        while (index < c_len) : (index += 1) {
                            if (index > 0) try writer.write_all(", ");
                            try dg.render_undef_value(writer, ty.child_type(zcu), initializer_type);
                        }
                        return writer.write_byte('}');
                    }
                },
                .anyframe_type,
                .opaque_type,
                .func_type,
                => unreachable,

                .undef,
                .simple_value,
                .variable,
                .extern_func,
                .func,
                .int,
                .err,
                .error_union,
                .enum_literal,
                .enum_tag,
                .empty_enum_value,
                .float,
                .ptr,
                .slice,
                .opt,
                .aggregate,
                .un,
                .memoized_call,
                => unreachable,
            },
        }
    }

    fn render_function_signature(
        dg: *DeclGen,
        w: anytype,
        fn_decl_index: InternPool.DeclIndex,
        kind: CType.Kind,
        name: union(enum) {
            export_index: u32,
            ident: []const u8,
            fmt_ctype_pool_string: std.fmt.Formatter(format_ctype_pool_string),
        },
    ) !void {
        const zcu = dg.zcu;
        const ip = &zcu.intern_pool;

        const fn_decl = zcu.decl_ptr(fn_decl_index);
        const fn_ty = fn_decl.type_of(zcu);
        const fn_ctype = try dg.ctype_from_type(fn_ty, kind);

        const fn_info = zcu.type_to_func(fn_ty).?;
        if (fn_info.cc == .Naked) {
            switch (kind) {
                .forward => try w.write_all("zig_naked_decl "),
                .complete => try w.write_all("zig_naked "),
                else => unreachable,
            }
        }
        if (fn_decl.val.get_function(zcu)) |func| if (func.analysis(ip).is_cold)
            try w.write_all("zig_cold ");
        if (fn_info.return_type == .noreturn_type) try w.write_all("zig_noreturn ");

        var trailing = try render_type_prefix(dg.pass, &dg.ctype_pool, zcu, w, fn_ctype, .suffix, .{});

        if (to_calling_convention(fn_info.cc)) |call_conv| {
            try w.print("{}zig_callconv({s})", .{ trailing, call_conv });
            trailing = .maybe_space;
        }

        switch (kind) {
            .forward => {},
            .complete => if (fn_decl.alignment.to_byte_units()) |a| {
                try w.print("{}zig_align_fn({})", .{ trailing, a });
                trailing = .maybe_space;
            },
            else => unreachable,
        }

        switch (name) {
            .export_index => |export_index| {
                try w.print("{}", .{trailing});
                try dg.render_decl_name(w, fn_decl_index, export_index);
            },
            .ident => |ident| try w.print("{}{ }", .{ trailing, fmt_ident(ident) }),
            .fmt_ctype_pool_string => |fmt| try w.print("{}{ }", .{ trailing, fmt }),
        }

        try render_type_suffix(
            dg.pass,
            &dg.ctype_pool,
            zcu,
            w,
            fn_ctype,
            .suffix,
            CQualifiers.init(.{ .@"const" = switch (kind) {
                .forward => false,
                .complete => true,
                else => unreachable,
            } }),
        );

        switch (kind) {
            .forward => {
                if (fn_decl.alignment.to_byte_units()) |a| {
                    try w.print(" zig_align_fn({})", .{a});
                }
                switch (name) {
                    .export_index => |export_index| mangled: {
                        const maybe_exports = zcu.decl_exports.get(fn_decl_index);
                        const external_name = (if (maybe_exports) |exports|
                            exports.items[export_index].opts.name
                        else if (fn_decl.is_extern(zcu))
                            fn_decl.name
                        else
                            break :mangled).to_slice(ip);
                        const is_mangled = is_mangled_ident(external_name, true);
                        const is_export = export_index > 0;
                        if (is_mangled and is_export) {
                            try w.print(" zig_mangled_export({ }, {s}, {s})", .{
                                fmt_ident(external_name),
                                fmt_string_literal(external_name, null),
                                fmt_string_literal(
                                    maybe_exports.?.items[0].opts.name.to_slice(ip),
                                    null,
                                ),
                            });
                        } else if (is_mangled) {
                            try w.print(" zig_mangled_final({ }, {s})", .{
                                fmt_ident(external_name), fmt_string_literal(external_name, null),
                            });
                        } else if (is_export) {
                            try w.print(" zig_export({s}, {s})", .{
                                fmt_string_literal(
                                    maybe_exports.?.items[0].opts.name.to_slice(ip),
                                    null,
                                ),
                                fmt_string_literal(external_name, null),
                            });
                        }
                    },
                    .ident, .fmt_ctype_pool_string => {},
                }
            },
            .complete => {},
            else => unreachable,
        }
    }

    fn ctype_from_type(dg: *DeclGen, ty: Type, kind: CType.Kind) !CType {
        defer std.debug.assert(dg.scratch.items.len == 0);
        return dg.ctype_pool.from_type(dg.gpa, &dg.scratch, ty, dg.zcu, dg.mod, kind);
    }

    fn byte_size(dg: *DeclGen, ctype: CType) u64 {
        return ctype.byte_size(&dg.ctype_pool, dg.mod);
    }

    /// Renders a type as a single identifier, generating intermediate typedefs
    /// if necessary.
    ///
    /// This is guaranteed to be valid in both typedefs and declarations/definitions.
    ///
    /// There are three type formats in total that we support rendering:
    ///   | Function            | Example 1 (*u8) | Example 2 ([10]*u8) |
    ///   |---------------------|-----------------|---------------------|
    ///   | `render_type_and_name` | "uint8_t *name" | "uint8_t *name[10]" |
    ///   | `render_type`        | "uint8_t *"     | "uint8_t *[10]"     |
    ///
    fn render_type(dg: *DeclGen, w: anytype, t: Type) error{OutOfMemory}!void {
        try dg.render_ctype(w, try dg.ctype_from_type(t, .complete));
    }

    fn render_ctype(dg: *DeclGen, w: anytype, ctype: CType) error{OutOfMemory}!void {
        _ = try render_type_prefix(dg.pass, &dg.ctype_pool, dg.zcu, w, ctype, .suffix, .{});
        try render_type_suffix(dg.pass, &dg.ctype_pool, dg.zcu, w, ctype, .suffix, .{});
    }

    const IntCastContext = union(enum) {
        c_value: struct {
            f: *Function,
            value: CValue,
            v: Vectorize,
        },
        value: struct {
            value: Value,
        },

        pub fn write_value(self: *const IntCastContext, dg: *DeclGen, w: anytype, location: ValueRenderLocation) !void {
            switch (self.*) {
                .c_value => |v| {
                    try v.f.write_cvalue(w, v.value, location);
                    try v.v.elem(v.f, w);
                },
                .value => |v| try dg.render_value(w, v.value, location),
            }
        }
    };
    fn int_cast_is_noop(dg: *DeclGen, dest_ty: Type, src_ty: Type) bool {
        const zcu = dg.zcu;
        const dest_bits = dest_ty.bit_size(zcu);
        const dest_int_info = dest_ty.int_info(zcu);

        const src_is_ptr = src_ty.is_ptr_at_runtime(zcu);
        const src_eff_ty: Type = if (src_is_ptr) switch (dest_int_info.signedness) {
            .unsigned => Type.usize,
            .signed => Type.isize,
        } else src_ty;

        const src_bits = src_eff_ty.bit_size(zcu);
        const src_int_info = if (src_eff_ty.is_abi_int(zcu)) src_eff_ty.int_info(zcu) else null;
        if (dest_bits <= 64 and src_bits <= 64) {
            const needs_cast = src_int_info == null or
                (to_cint_bits(dest_int_info.bits) != to_cint_bits(src_int_info.?.bits) or
                dest_int_info.signedness != src_int_info.?.signedness);
            return !needs_cast and !src_is_ptr;
        } else return false;
    }
    /// Renders a cast to an int type, from either an int or a pointer.
    ///
    /// Some platforms don't have 128 bit integers, so we need to use
    /// the zig_make_ and zig_lo_ macros in those cases.
    ///
    ///   | Dest type bits   | Src type         | Result
    ///   |------------------|------------------|---------------------------|
    ///   | < 64 bit integer | pointer          | (zig_<dest_ty>)(zig_<u|i>size)src
    ///   | < 64 bit integer | < 64 bit integer | (zig_<dest_ty>)src
    ///   | < 64 bit integer | > 64 bit integer | zig_lo(src)
    ///   | > 64 bit integer | pointer          | zig_make_<dest_ty>(0, (zig_<u|i>size)src)
    ///   | > 64 bit integer | < 64 bit integer | zig_make_<dest_ty>(0, src)
    ///   | > 64 bit integer | > 64 bit integer | zig_make_<dest_ty>(zig_hi_<src_ty>(src), zig_lo_<src_ty>(src))
    fn render_int_cast(
        dg: *DeclGen,
        w: anytype,
        dest_ty: Type,
        context: IntCastContext,
        src_ty: Type,
        location: ValueRenderLocation,
    ) !void {
        const zcu = dg.zcu;
        const dest_bits = dest_ty.bit_size(zcu);
        const dest_int_info = dest_ty.int_info(zcu);

        const src_is_ptr = src_ty.is_ptr_at_runtime(zcu);
        const src_eff_ty: Type = if (src_is_ptr) switch (dest_int_info.signedness) {
            .unsigned => Type.usize,
            .signed => Type.isize,
        } else src_ty;

        const src_bits = src_eff_ty.bit_size(zcu);
        const src_int_info = if (src_eff_ty.is_abi_int(zcu)) src_eff_ty.int_info(zcu) else null;
        if (dest_bits <= 64 and src_bits <= 64) {
            const needs_cast = src_int_info == null or
                (to_cint_bits(dest_int_info.bits) != to_cint_bits(src_int_info.?.bits) or
                dest_int_info.signedness != src_int_info.?.signedness);

            if (needs_cast) {
                try w.write_byte('(');
                try dg.render_type(w, dest_ty);
                try w.write_byte(')');
            }
            if (src_is_ptr) {
                try w.write_byte('(');
                try dg.render_type(w, src_eff_ty);
                try w.write_byte(')');
            }
            try context.write_value(dg, w, location);
        } else if (dest_bits <= 64 and src_bits > 64) {
            assert(!src_is_ptr);
            if (dest_bits < 64) {
                try w.write_byte('(');
                try dg.render_type(w, dest_ty);
                try w.write_byte(')');
            }
            try w.write_all("zig_lo_");
            try dg.render_type_for_builtin_fn_name(w, src_eff_ty);
            try w.write_byte('(');
            try context.write_value(dg, w, .FunctionArgument);
            try w.write_byte(')');
        } else if (dest_bits > 64 and src_bits <= 64) {
            try w.write_all("zig_make_");
            try dg.render_type_for_builtin_fn_name(w, dest_ty);
            try w.write_all("(0, "); // TODO: Should the 0 go through fmt_int_literal?
            if (src_is_ptr) {
                try w.write_byte('(');
                try dg.render_type(w, src_eff_ty);
                try w.write_byte(')');
            }
            try context.write_value(dg, w, .FunctionArgument);
            try w.write_byte(')');
        } else {
            assert(!src_is_ptr);
            try w.write_all("zig_make_");
            try dg.render_type_for_builtin_fn_name(w, dest_ty);
            try w.write_all("(zig_hi_");
            try dg.render_type_for_builtin_fn_name(w, src_eff_ty);
            try w.write_byte('(');
            try context.write_value(dg, w, .FunctionArgument);
            try w.write_all("), zig_lo_");
            try dg.render_type_for_builtin_fn_name(w, src_eff_ty);
            try w.write_byte('(');
            try context.write_value(dg, w, .FunctionArgument);
            try w.write_all("))");
        }
    }

    /// Renders a type and name in field declaration/definition format.
    ///
    /// There are three type formats in total that we support rendering:
    ///   | Function            | Example 1 (*u8) | Example 2 ([10]*u8) |
    ///   |---------------------|-----------------|---------------------|
    ///   | `render_type_and_name` | "uint8_t *name" | "uint8_t *name[10]" |
    ///   | `render_type`        | "uint8_t *"     | "uint8_t *[10]"     |
    ///
    fn render_type_and_name(
        dg: *DeclGen,
        w: anytype,
        ty: Type,
        name: CValue,
        qualifiers: CQualifiers,
        alignment: Alignment,
        kind: CType.Kind,
    ) error{ OutOfMemory, AnalysisFail }!void {
        try dg.render_ctype_and_name(
            w,
            try dg.ctype_from_type(ty, kind),
            name,
            qualifiers,
            CType.AlignAs.from_alignment(.{
                .@"align" = alignment,
                .abi = ty.abi_alignment(dg.zcu),
            }),
        );
    }

    fn render_ctype_and_name(
        dg: *DeclGen,
        w: anytype,
        ctype: CType,
        name: CValue,
        qualifiers: CQualifiers,
        alignas: CType.AlignAs,
    ) error{ OutOfMemory, AnalysisFail }!void {
        switch (alignas.abi_order()) {
            .lt => try w.print("zig_under_align({}) ", .{alignas.to_byte_units()}),
            .eq => {},
            .gt => try w.print("zig_align({}) ", .{alignas.to_byte_units()}),
        }

        try w.print("{}", .{
            try render_type_prefix(dg.pass, &dg.ctype_pool, dg.zcu, w, ctype, .suffix, qualifiers),
        });
        try dg.write_name(w, name);
        try render_type_suffix(dg.pass, &dg.ctype_pool, dg.zcu, w, ctype, .suffix, .{});
    }

    fn decl_is_global(dg: *DeclGen, val: Value) bool {
        const zcu = dg.zcu;
        return switch (zcu.intern_pool.index_to_key(val.to_intern())) {
            .variable => |variable| zcu.decl_exports.contains(variable.decl),
            .extern_func => true,
            .func => |func| zcu.decl_exports.contains(func.owner_decl),
            else => unreachable,
        };
    }

    fn write_name(dg: *DeclGen, w: anytype, c_value: CValue) !void {
        switch (c_value) {
            .new_local, .local => |i| try w.print("t{d}", .{i}),
            .constant => |val| try render_anon_decl_name(w, val),
            .decl => |decl| try dg.render_decl_name(w, decl, 0),
            .identifier => |ident| try w.print("{ }", .{fmt_ident(ident)}),
            else => unreachable,
        }
    }

    fn write_cvalue(dg: *DeclGen, w: anytype, c_value: CValue) !void {
        switch (c_value) {
            .none, .new_local, .local, .local_ref => unreachable,
            .constant => |val| try render_anon_decl_name(w, val),
            .arg, .arg_array => unreachable,
            .field => |i| try w.print("f{d}", .{i}),
            .decl => |decl| try dg.render_decl_name(w, decl, 0),
            .decl_ref => |decl| {
                try w.write_byte('&');
                try dg.render_decl_name(w, decl, 0);
            },
            .undef => |ty| try dg.render_undef_value(w, ty, .Other),
            .identifier => |ident| try w.print("{ }", .{fmt_ident(ident)}),
            .payload_identifier => |ident| try w.print("{ }.{ }", .{
                fmt_ident("payload"),
                fmt_ident(ident),
            }),
            .ctype_pool_string => |string| try w.print("{ }", .{
                fmt_ctype_pool_string(string, &dg.ctype_pool),
            }),
        }
    }

    fn write_cvalue_deref(dg: *DeclGen, w: anytype, c_value: CValue) !void {
        switch (c_value) {
            .none,
            .new_local,
            .local,
            .local_ref,
            .constant,
            .arg,
            .arg_array,
            .ctype_pool_string,
            => unreachable,
            .field => |i| try w.print("f{d}", .{i}),
            .decl => |decl| {
                try w.write_all("(*");
                try dg.render_decl_name(w, decl, 0);
                try w.write_byte(')');
            },
            .decl_ref => |decl| try dg.render_decl_name(w, decl, 0),
            .undef => unreachable,
            .identifier => |ident| try w.print("(*{ })", .{fmt_ident(ident)}),
            .payload_identifier => |ident| try w.print("(*{ }.{ })", .{
                fmt_ident("payload"),
                fmt_ident(ident),
            }),
        }
    }

    fn write_cvalue_member(
        dg: *DeclGen,
        writer: anytype,
        c_value: CValue,
        member: CValue,
    ) error{ OutOfMemory, AnalysisFail }!void {
        try dg.write_cvalue(writer, c_value);
        try writer.write_byte('.');
        try dg.write_cvalue(writer, member);
    }

    fn write_cvalue_deref_member(dg: *DeclGen, writer: anytype, c_value: CValue, member: CValue) !void {
        switch (c_value) {
            .none,
            .new_local,
            .local,
            .local_ref,
            .constant,
            .field,
            .undef,
            .arg,
            .arg_array,
            .ctype_pool_string,
            => unreachable,
            .decl, .identifier, .payload_identifier => {
                try dg.write_cvalue(writer, c_value);
                try writer.write_all("->");
            },
            .decl_ref => {
                try dg.write_cvalue_deref(writer, c_value);
                try writer.write_byte('.');
            },
        }
        try dg.write_cvalue(writer, member);
    }

    fn render_fwd_decl(
        dg: *DeclGen,
        decl_index: InternPool.DeclIndex,
        variable: InternPool.Key.Variable,
        fwd_kind: enum { tentative, final },
    ) !void {
        const zcu = dg.zcu;
        const decl = zcu.decl_ptr(decl_index);
        const fwd = dg.fwd_decl_writer();
        const is_global = variable.is_extern or dg.decl_is_global(decl.val);
        try fwd.write_all(if (is_global) "zig_extern " else "static ");
        const maybe_exports = zcu.decl_exports.get(decl_index);
        const export_weak_linkage = if (maybe_exports) |exports|
            exports.items[0].opts.linkage == .weak
        else
            false;
        if (variable.is_weak_linkage or export_weak_linkage) try fwd.write_all("zig_weak_linkage ");
        if (variable.is_threadlocal and !dg.mod.single_threaded) try fwd.write_all("zig_threadlocal ");
        try dg.render_type_and_name(
            fwd,
            decl.type_of(zcu),
            .{ .decl = decl_index },
            CQualifiers.init(.{ .@"const" = variable.is_const }),
            decl.alignment,
            .complete,
        );
        mangled: {
            const external_name = (if (maybe_exports) |exports|
                exports.items[0].opts.name
            else if (variable.is_extern)
                decl.name
            else
                break :mangled).to_slice(&zcu.intern_pool);
            if (is_mangled_ident(external_name, true)) {
                try fwd.print(" zig_mangled_{s}({ }, {s})", .{
                    @tag_name(fwd_kind),
                    fmt_ident(external_name),
                    fmt_string_literal(external_name, null),
                });
            }
        }
        try fwd.write_all(";\n");
    }

    fn render_decl_name(dg: *DeclGen, writer: anytype, decl_index: InternPool.DeclIndex, export_index: u32) !void {
        const zcu = dg.zcu;
        const ip = &zcu.intern_pool;
        const decl = zcu.decl_ptr(decl_index);

        if (zcu.decl_exports.get(decl_index)) |exports| {
            try writer.print("{ }", .{
                fmt_ident(exports.items[export_index].opts.name.to_slice(ip)),
            });
        } else if (decl.get_extern_decl(zcu).unwrap()) |extern_decl_index| {
            try writer.print("{ }", .{
                fmt_ident(zcu.decl_ptr(extern_decl_index).name.to_slice(ip)),
            });
        } else {
            // MSVC has a limit of 4095 character token length limit, and fmt_ident can (worst case),
            // expand to 3x the length of its input, but let's cut it off at a much shorter limit.
            var name: [100]u8 = undefined;
            var name_stream = std.io.fixed_buffer_stream(&name);
            decl.render_fully_qualified_name(zcu, name_stream.writer()) catch |err| switch (err) {
                error.NoSpaceLeft => {},
            };
            try writer.print("{}__{d}", .{
                fmt_ident(name_stream.get_written()),
                @int_from_enum(decl_index),
            });
        }
    }

    fn render_anon_decl_name(writer: anytype, anon_decl_val: Value) !void {
        try writer.print("__anon_{d}", .{@int_from_enum(anon_decl_val.to_intern())});
    }

    fn render_type_for_builtin_fn_name(dg: *DeclGen, writer: anytype, ty: Type) !void {
        try dg.render_ctype_for_builtin_fn_name(writer, try dg.ctype_from_type(ty, .complete));
    }

    fn render_ctype_for_builtin_fn_name(dg: *DeclGen, writer: anytype, ctype: CType) !void {
        switch (ctype.info(&dg.ctype_pool)) {
            else => |ctype_info| try writer.print("{c}{d}", .{
                if (ctype.is_bool())
                    sign_abbrev(.unsigned)
                else if (ctype.is_integer())
                    sign_abbrev(ctype.signedness(dg.mod))
                else if (ctype.is_float())
                    @as(u8, 'f')
                else if (ctype_info == .pointer)
                    @as(u8, 'p')
                else
                    return dg.fail("TODO: CBE: implement render_type_for_builtin_fn_name for {s} type", .{@tag_name(ctype_info)}),
                if (ctype.is_float()) ctype.float_active_bits(dg.mod) else dg.byte_size(ctype) * 8,
            }),
            .array => try writer.write_all("big"),
        }
    }

    fn render_builtin_info(dg: *DeclGen, writer: anytype, ty: Type, info: BuiltinInfo) !void {
        const ctype = try dg.ctype_from_type(ty, .complete);
        const is_big = ctype.info(&dg.ctype_pool) == .array;
        switch (info) {
            .none => if (!is_big) return,
            .bits => {},
        }

        const zcu = dg.zcu;
        const int_info = if (ty.is_abi_int(zcu)) ty.int_info(zcu) else std.builtin.Type.Int{
            .signedness = .unsigned,
            .bits = @as(u16, @int_cast(ty.bit_size(zcu))),
        };

        if (is_big) try writer.print(", {}", .{int_info.signedness == .signed});
        try writer.print(", {}", .{try dg.fmt_int_literal(
            try zcu.int_value(if (is_big) Type.u16 else Type.u8, int_info.bits),
            .FunctionArgument,
        )});
    }

    fn fmt_int_literal(
        dg: *DeclGen,
        val: Value,
        loc: ValueRenderLocation,
    ) !std.fmt.Formatter(format_int_literal) {
        const zcu = dg.zcu;
        const kind = loc.to_ctype_kind();
        const ty = val.type_of(zcu);
        return std.fmt.Formatter(format_int_literal){ .data = .{
            .dg = dg,
            .int_info = ty.int_info(zcu),
            .kind = kind,
            .ctype = try dg.ctype_from_type(ty, kind),
            .val = val,
        } };
    }
};

const CTypeFix = enum { prefix, suffix };
const CQualifiers = std.enums.EnumSet(enum { @"const", @"volatile", restrict });
const Const = CQualifiers.init(.{ .@"const" = true });
const RenderCTypeTrailing = enum {
    no_space,
    maybe_space,

    pub fn format(
        self: @This(),
        comptime fmt: []const u8,
        _: std.fmt.FormatOptions,
        w: anytype,
    ) @TypeOf(w).Error!void {
        if (fmt.len != 0)
            @compile_error("invalid format string '" ++ fmt ++ "' for type '" ++
                @type_name(@This()) ++ "'");
        comptime assert(fmt.len == 0);
        switch (self) {
            .no_space => {},
            .maybe_space => try w.write_byte(' '),
        }
    }
};
fn render_aligned_type_name(w: anytype, ctype: CType) !void {
    try w.print("anon__aligned_{d}", .{@int_from_enum(ctype.index)});
}
fn render_fwd_decl_type_name(
    zcu: *Zcu,
    w: anytype,
    ctype: CType,
    fwd_decl: CType.Info.FwdDecl,
    attributes: []const u8,
) !void {
    try w.print("{s} {s}", .{ @tag_name(fwd_decl.tag), attributes });
    switch (fwd_decl.name) {
        .anon => try w.print("anon__lazy_{d}", .{@int_from_enum(ctype.index)}),
        .owner_decl => |owner_decl| try w.print("{}__{d}", .{
            fmt_ident(zcu.decl_ptr(owner_decl).name.to_slice(&zcu.intern_pool)),
            @int_from_enum(owner_decl),
        }),
    }
}
fn render_type_prefix(
    pass: DeclGen.Pass,
    ctype_pool: *const CType.Pool,
    zcu: *Zcu,
    w: anytype,
    ctype: CType,
    parent_fix: CTypeFix,
    qualifiers: CQualifiers,
) @TypeOf(w).Error!RenderCTypeTrailing {
    var trailing = RenderCTypeTrailing.maybe_space;
    switch (ctype.info(ctype_pool)) {
        .basic => |basic_info| try w.write_all(@tag_name(basic_info)),

        .pointer => |pointer_info| {
            try w.print("{}*", .{try render_type_prefix(
                pass,
                ctype_pool,
                zcu,
                w,
                pointer_info.elem_ctype,
                .prefix,
                CQualifiers.init(.{
                    .@"const" = pointer_info.@"const",
                    .@"volatile" = pointer_info.@"volatile",
                }),
            )});
            trailing = .no_space;
        },

        .aligned => switch (pass) {
            .decl => |decl_index| try w.print("decl__{d}_{d}", .{
                @int_from_enum(decl_index), @int_from_enum(ctype.index),
            }),
            .anon => |anon_decl| try w.print("anon__{d}_{d}", .{
                @int_from_enum(anon_decl), @int_from_enum(ctype.index),
            }),
            .flush => try render_aligned_type_name(w, ctype),
        },

        .array, .vector => |sequence_info| {
            const child_trailing = try render_type_prefix(
                pass,
                ctype_pool,
                zcu,
                w,
                sequence_info.elem_ctype,
                .suffix,
                qualifiers,
            );
            switch (parent_fix) {
                .prefix => {
                    try w.print("{}(", .{child_trailing});
                    return .no_space;
                },
                .suffix => return child_trailing,
            }
        },

        .fwd_decl => |fwd_decl_info| switch (fwd_decl_info.name) {
            .anon => switch (pass) {
                .decl => |decl_index| try w.print("decl__{d}_{d}", .{
                    @int_from_enum(decl_index), @int_from_enum(ctype.index),
                }),
                .anon => |anon_decl| try w.print("anon__{d}_{d}", .{
                    @int_from_enum(anon_decl), @int_from_enum(ctype.index),
                }),
                .flush => try render_fwd_decl_type_name(zcu, w, ctype, fwd_decl_info, ""),
            },
            .owner_decl => try render_fwd_decl_type_name(zcu, w, ctype, fwd_decl_info, ""),
        },

        .aggregate => |aggregate_info| switch (aggregate_info.name) {
            .anon => {
                try w.print("{s} {s}", .{
                    @tag_name(aggregate_info.tag),
                    if (aggregate_info.@"packed") "zig_packed(" else "",
                });
                try render_fields(zcu, w, ctype_pool, aggregate_info, 1);
                if (aggregate_info.@"packed") try w.write_byte(')');
            },
            .fwd_decl => |fwd_decl| return render_type_prefix(
                pass,
                ctype_pool,
                zcu,
                w,
                fwd_decl,
                parent_fix,
                qualifiers,
            ),
        },

        .function => |function_info| {
            const child_trailing = try render_type_prefix(
                pass,
                ctype_pool,
                zcu,
                w,
                function_info.return_ctype,
                .suffix,
                .{},
            );
            switch (parent_fix) {
                .prefix => {
                    try w.print("{}(", .{child_trailing});
                    return .no_space;
                },
                .suffix => return child_trailing,
            }
        },
    }
    var qualifier_it = qualifiers.iterator();
    while (qualifier_it.next()) |qualifier| {
        try w.print("{}{s}", .{ trailing, @tag_name(qualifier) });
        trailing = .maybe_space;
    }
    return trailing;
}
fn render_type_suffix(
    pass: DeclGen.Pass,
    ctype_pool: *const CType.Pool,
    zcu: *Zcu,
    w: anytype,
    ctype: CType,
    parent_fix: CTypeFix,
    qualifiers: CQualifiers,
) @TypeOf(w).Error!void {
    switch (ctype.info(ctype_pool)) {
        .basic, .aligned, .fwd_decl, .aggregate => {},
        .pointer => |pointer_info| try render_type_suffix(
            pass,
            ctype_pool,
            zcu,
            w,
            pointer_info.elem_ctype,
            .prefix,
            .{},
        ),
        .array, .vector => |sequence_info| {
            switch (parent_fix) {
                .prefix => try w.write_byte(')'),
                .suffix => {},
            }

            try w.print("[{}]", .{sequence_info.len});
            try render_type_suffix(pass, ctype_pool, zcu, w, sequence_info.elem_ctype, .suffix, .{});
        },
        .function => |function_info| {
            switch (parent_fix) {
                .prefix => try w.write_byte(')'),
                .suffix => {},
            }

            try w.write_byte('(');
            var need_comma = false;
            for (0..function_info.param_ctypes.len) |param_index| {
                const param_type = function_info.param_ctypes.at(param_index, ctype_pool);
                if (need_comma) try w.write_all(", ");
                need_comma = true;
                const trailing =
                    try render_type_prefix(pass, ctype_pool, zcu, w, param_type, .suffix, qualifiers);
                if (qualifiers.contains(.@"const")) try w.print("{}a{d}", .{ trailing, param_index });
                try render_type_suffix(pass, ctype_pool, zcu, w, param_type, .suffix, .{});
            }
            if (function_info.varargs) {
                if (need_comma) try w.write_all(", ");
                need_comma = true;
                try w.write_all("...");
            }
            if (!need_comma) try w.write_all("void");
            try w.write_byte(')');

            try render_type_suffix(pass, ctype_pool, zcu, w, function_info.return_ctype, .suffix, .{});
        },
    }
}
fn render_fields(
    zcu: *Zcu,
    writer: anytype,
    ctype_pool: *const CType.Pool,
    aggregate_info: CType.Info.Aggregate,
    indent: usize,
) !void {
    try writer.write_all("{\n");
    for (0..aggregate_info.fields.len) |field_index| {
        const field_info = aggregate_info.fields.at(field_index, ctype_pool);
        try writer.write_byte_ntimes(' ', indent + 1);
        switch (field_info.alignas.abi_order()) {
            .lt => {
                std.debug.assert(aggregate_info.@"packed");
                if (field_info.alignas.@"align" != .@"1") try writer.print("zig_under_align({}) ", .{
                    field_info.alignas.to_byte_units(),
                });
            },
            .eq => if (aggregate_info.@"packed" and field_info.alignas.@"align" != .@"1")
                try writer.print("zig_align({}) ", .{field_info.alignas.to_byte_units()}),
            .gt => {
                std.debug.assert(field_info.alignas.@"align" != .@"1");
                try writer.print("zig_align({}) ", .{field_info.alignas.to_byte_units()});
            },
        }
        const trailing = try render_type_prefix(
            .flush,
            ctype_pool,
            zcu,
            writer,
            field_info.ctype,
            .suffix,
            .{},
        );
        try writer.print("{}{ }", .{ trailing, fmt_ctype_pool_string(field_info.name, ctype_pool) });
        try render_type_suffix(.flush, ctype_pool, zcu, writer, field_info.ctype, .suffix, .{});
        try writer.write_all(";\n");
    }
    try writer.write_byte_ntimes(' ', indent);
    try writer.write_byte('}');
}

pub fn gen_type_decl(
    zcu: *Zcu,
    writer: anytype,
    global_ctype_pool: *const CType.Pool,
    global_ctype: CType,
    pass: DeclGen.Pass,
    decl_ctype_pool: *const CType.Pool,
    decl_ctype: CType,
    found_existing: bool,
) !void {
    switch (global_ctype.info(global_ctype_pool)) {
        .basic, .pointer, .array, .vector, .function => {},
        .aligned => |aligned_info| {
            if (!found_existing) {
                std.debug.assert(aligned_info.alignas.abi_order().compare(.lt));
                try writer.print("typedef zig_under_align({d}) ", .{aligned_info.alignas.to_byte_units()});
                try writer.print("{}", .{try render_type_prefix(
                    .flush,
                    global_ctype_pool,
                    zcu,
                    writer,
                    aligned_info.ctype,
                    .suffix,
                    .{},
                )});
                try render_aligned_type_name(writer, global_ctype);
                try render_type_suffix(.flush, global_ctype_pool, zcu, writer, aligned_info.ctype, .suffix, .{});
                try writer.write_all(";\n");
            }
            switch (pass) {
                .decl, .anon => {
                    try writer.write_all("typedef ");
                    _ = try render_type_prefix(.flush, global_ctype_pool, zcu, writer, global_ctype, .suffix, .{});
                    try writer.write_byte(' ');
                    _ = try render_type_prefix(pass, decl_ctype_pool, zcu, writer, decl_ctype, .suffix, .{});
                    try writer.write_all(";\n");
                },
                .flush => {},
            }
        },
        .fwd_decl => |fwd_decl_info| switch (fwd_decl_info.name) {
            .anon => switch (pass) {
                .decl, .anon => {
                    try writer.write_all("typedef ");
                    _ = try render_type_prefix(.flush, global_ctype_pool, zcu, writer, global_ctype, .suffix, .{});
                    try writer.write_byte(' ');
                    _ = try render_type_prefix(pass, decl_ctype_pool, zcu, writer, decl_ctype, .suffix, .{});
                    try writer.write_all(";\n");
                },
                .flush => {},
            },
            .owner_decl => |owner_decl_index| if (!found_existing) {
                _ = try render_type_prefix(.flush, global_ctype_pool, zcu, writer, global_ctype, .suffix, .{});
                try writer.write_byte(';');
                const owner_decl = zcu.decl_ptr(owner_decl_index);
                const owner_mod = zcu.namespace_ptr(owner_decl.src_namespace).file_scope.mod;
                if (!owner_mod.strip) {
                    try writer.write_all(" /* ");
                    try owner_decl.render_fully_qualified_name(zcu, writer);
                    try writer.write_all(" */");
                }
                try writer.write_byte('\n');
            },
        },
        .aggregate => |aggregate_info| switch (aggregate_info.name) {
            .anon => {},
            .fwd_decl => |fwd_decl| if (!found_existing) {
                try render_fwd_decl_type_name(
                    zcu,
                    writer,
                    fwd_decl,
                    fwd_decl.info(global_ctype_pool).fwd_decl,
                    if (aggregate_info.@"packed") "zig_packed(" else "",
                );
                try writer.write_byte(' ');
                try render_fields(zcu, writer, global_ctype_pool, aggregate_info, 0);
                if (aggregate_info.@"packed") try writer.write_byte(')');
                try writer.write_all(";\n");
            },
        },
    }
}

pub fn gen_global_asm(zcu: *Zcu, writer: anytype) !void {
    for (zcu.global_assembly.values()) |asm_source| {
        try writer.print("__asm({s});\n", .{fmt_string_literal(asm_source, null)});
    }
}

pub fn gen_err_decls(o: *Object) !void {
    const zcu = o.dg.zcu;
    const ip = &zcu.intern_pool;
    const writer = o.writer();

    var max_name_len: usize = 0;
    // do not generate an invalid empty enum when the global error set is empty
    if (zcu.global_error_set.keys().len > 1) {
        try writer.write_all("enum {\n");
        o.indent_writer.push_indent();
        for (zcu.global_error_set.keys()[1..], 1..) |name_nts, value| {
            const name = name_nts.to_slice(ip);
            max_name_len = @max(name.len, max_name_len);
            const err_val = try zcu.intern(.{ .err = .{
                .ty = .anyerror_type,
                .name = name_nts,
            } });
            try o.dg.render_value(writer, Value.from_interned(err_val), .Other);
            try writer.print(" = {d}u,\n", .{value});
        }
        o.indent_writer.pop_indent();
        try writer.write_all("};\n");
    }
    const array_identifier = "zig_errorName";
    const name_prefix = array_identifier ++ "_";
    const name_buf = try o.dg.gpa.alloc(u8, name_prefix.len + max_name_len);
    defer o.dg.gpa.free(name_buf);

    @memcpy(name_buf[0..name_prefix.len], name_prefix);
    for (zcu.global_error_set.keys()) |name| {
        const name_slice = name.to_slice(ip);
        @memcpy(name_buf[name_prefix.len..][0..name_slice.len], name_slice);
        const identifier = name_buf[0 .. name_prefix.len + name_slice.len];

        const name_ty = try zcu.array_type(.{
            .len = name_slice.len,
            .child = .u8_type,
            .sentinel = .zero_u8,
        });
        const name_val = try zcu.intern(.{ .aggregate = .{
            .ty = name_ty.to_intern(),
            .storage = .{ .bytes = name.to_string() },
        } });

        try writer.write_all("static ");
        try o.dg.render_type_and_name(
            writer,
            name_ty,
            .{ .identifier = identifier },
            Const,
            .none,
            .complete,
        );
        try writer.write_all(" = ");
        try o.dg.render_value(writer, Value.from_interned(name_val), .StaticInitializer);
        try writer.write_all(";\n");
    }

    const name_array_ty = try zcu.array_type(.{
        .len = zcu.global_error_set.count(),
        .child = .slice_const_u8_sentinel_0_type,
    });

    try writer.write_all("static ");
    try o.dg.render_type_and_name(
        writer,
        name_array_ty,
        .{ .identifier = array_identifier },
        Const,
        .none,
        .complete,
    );
    try writer.write_all(" = {");
    for (zcu.global_error_set.keys(), 0..) |name_nts, value| {
        const name = name_nts.to_slice(ip);
        if (value != 0) try writer.write_byte(',');
        try writer.print("{{" ++ name_prefix ++ "{}, {}}}", .{
            fmt_ident(name),
            try o.dg.fmt_int_literal(try zcu.int_value(Type.usize, name.len), .StaticInitializer),
        });
    }
    try writer.write_all("};\n");
}

fn gen_exports(o: *Object) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const zcu = o.dg.zcu;
    const ip = &zcu.intern_pool;
    const decl_index = switch (o.dg.pass) {
        .decl => |decl| decl,
        .anon, .flush => return,
    };
    const decl = zcu.decl_ptr(decl_index);
    const fwd = o.dg.fwd_decl_writer();

    const exports = zcu.decl_exports.get(decl_index) orelse return;
    if (exports.items.len < 2) return;

    const is_variable_const = switch (ip.index_to_key(decl.val.to_intern())) {
        .func => return for (exports.items[1..], 1..) |@"export", i| {
            try fwd.write_all("zig_extern ");
            if (@"export".opts.linkage == .weak) try fwd.write_all("zig_weak_linkage_fn ");
            try o.dg.render_function_signature(
                fwd,
                decl_index,
                .forward,
                .{ .export_index = @int_cast(i) },
            );
            try fwd.write_all(";\n");
        },
        .extern_func => {
            // TODO: when sema allows re-exporting extern decls
            unreachable;
        },
        .variable => |variable| variable.is_const,
        else => true,
    };
    for (exports.items[1..]) |@"export"| {
        try fwd.write_all("zig_extern ");
        if (@"export".opts.linkage == .weak) try fwd.write_all("zig_weak_linkage ");
        const export_name = @"export".opts.name.to_slice(ip);
        try o.dg.render_type_and_name(
            fwd,
            decl.type_of(zcu),
            .{ .identifier = export_name },
            CQualifiers.init(.{ .@"const" = is_variable_const }),
            decl.alignment,
            .complete,
        );
        if (is_mangled_ident(export_name, true)) {
            try fwd.print(" zig_mangled_export({ }, {s}, {s})", .{
                fmt_ident(export_name),
                fmt_string_literal(export_name, null),
                fmt_string_literal(exports.items[0].opts.name.to_slice(ip), null),
            });
        } else {
            try fwd.print(" zig_export({s}, {s})", .{
                fmt_string_literal(exports.items[0].opts.name.to_slice(ip), null),
                fmt_string_literal(export_name, null),
            });
        }
        try fwd.write_all(";\n");
    }
}

pub fn gen_lazy_fn(o: *Object, lazy_ctype_pool: *const CType.Pool, lazy_fn: LazyFnMap.Entry) !void {
    const zcu = o.dg.zcu;
    const ip = &zcu.intern_pool;
    const ctype_pool = &o.dg.ctype_pool;
    const w = o.writer();
    const key = lazy_fn.key_ptr.*;
    const val = lazy_fn.value_ptr;
    switch (key) {
        .tag_name => {
            const enum_ty = val.data.tag_name;

            const name_slice_ty = Type.slice_const_u8_sentinel_0;

            try w.write_all("static ");
            try o.dg.render_type(w, name_slice_ty);
            try w.print(" {}(", .{val.fn_name.fmt(lazy_ctype_pool)});
            try o.dg.render_type_and_name(w, enum_ty, .{ .identifier = "tag" }, Const, .none, .complete);
            try w.write_all(") {\n switch (tag) {\n");
            const tag_names = enum_ty.enum_fields(zcu);
            for (0..tag_names.len) |tag_index| {
                const tag_name = tag_names.get(ip)[tag_index];
                const tag_name_len = tag_name.length(ip);
                const tag_val = try zcu.enum_value_field_index(enum_ty, @int_cast(tag_index));

                const name_ty = try zcu.array_type(.{
                    .len = tag_name_len,
                    .child = .u8_type,
                    .sentinel = .zero_u8,
                });
                const name_val = try zcu.intern(.{ .aggregate = .{
                    .ty = name_ty.to_intern(),
                    .storage = .{ .bytes = tag_name.to_string() },
                } });

                try w.print("  case {}: {{\n   static ", .{
                    try o.dg.fmt_int_literal(try tag_val.int_from_enum(enum_ty, zcu), .Other),
                });
                try o.dg.render_type_and_name(w, name_ty, .{ .identifier = "name" }, Const, .none, .complete);
                try w.write_all(" = ");
                try o.dg.render_value(w, Value.from_interned(name_val), .Initializer);
                try w.write_all(";\n   return (");
                try o.dg.render_type(w, name_slice_ty);
                try w.print("){{{}, {}}};\n", .{
                    fmt_ident("name"),
                    try o.dg.fmt_int_literal(try zcu.int_value(Type.usize, tag_name_len), .Other),
                });

                try w.write_all("  }\n");
            }
            try w.write_all(" }\n while (");
            try o.dg.render_value(w, Value.true, .Other);
            try w.write_all(") ");
            _ = try air_breakpoint(w);
            try w.write_all("}\n");
        },
        .never_tail, .never_inline => |fn_decl_index| {
            const fn_decl = zcu.decl_ptr(fn_decl_index);
            const fn_ctype = try o.dg.ctype_from_type(fn_decl.type_of(zcu), .complete);
            const fn_info = fn_ctype.info(ctype_pool).function;
            const fn_name = fmt_ctype_pool_string(val.fn_name, lazy_ctype_pool);

            const fwd_decl_writer = o.dg.fwd_decl_writer();
            try fwd_decl_writer.print("static zig_{s} ", .{@tag_name(key)});
            try o.dg.render_function_signature(fwd_decl_writer, fn_decl_index, .forward, .{
                .fmt_ctype_pool_string = fn_name,
            });
            try fwd_decl_writer.write_all(";\n");

            try w.print("static zig_{s} ", .{@tag_name(key)});
            try o.dg.render_function_signature(w, fn_decl_index, .complete, .{
                .fmt_ctype_pool_string = fn_name,
            });
            try w.write_all(" {\n return ");
            try o.dg.render_decl_name(w, fn_decl_index, 0);
            try w.write_byte('(');
            for (0..fn_info.param_ctypes.len) |arg| {
                if (arg > 0) try w.write_all(", ");
                try o.dg.write_cvalue(w, .{ .arg = arg });
            }
            try w.write_all(");\n}\n");
        },
    }
}

pub fn gen_func(f: *Function) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const o = &f.object;
    const zcu = o.dg.zcu;
    const gpa = o.dg.gpa;
    const decl_index = o.dg.pass.decl;
    const decl = zcu.decl_ptr(decl_index);

    o.code_header = std.ArrayList(u8).init(gpa);
    defer o.code_header.deinit();

    const is_global = o.dg.decl_is_global(decl.val);
    const fwd_decl_writer = o.dg.fwd_decl_writer();
    try fwd_decl_writer.write_all(if (is_global) "zig_extern " else "static ");

    if (zcu.decl_exports.get(decl_index)) |exports|
        if (exports.items[0].opts.linkage == .weak) try fwd_decl_writer.write_all("zig_weak_linkage_fn ");
    try o.dg.render_function_signature(fwd_decl_writer, decl_index, .forward, .{ .export_index = 0 });
    try fwd_decl_writer.write_all(";\n");
    try gen_exports(o);

    try o.indent_writer.insert_newline();
    if (!is_global) try o.writer().write_all("static ");
    if (decl.@"linksection".to_slice(&zcu.intern_pool)) |s|
        try o.writer().print("zig_linksection_fn({s}) ", .{fmt_string_literal(s, null)});
    try o.dg.render_function_signature(o.writer(), decl_index, .complete, .{ .export_index = 0 });
    try o.writer().write_byte(' ');

    // In case we need to use the header, populate it with a copy of the function
    // signature here. We anticipate a brace, newline, and space.
    try o.code_header.ensure_unused_capacity(o.code.items.len + 3);
    o.code_header.append_slice_assume_capacity(o.code.items);
    o.code_header.append_slice_assume_capacity("{\n ");
    const empty_header_len = o.code_header.items.len;

    f.free_locals_map.clear_retaining_capacity();

    const main_body = f.air.get_main_body();
    try gen_body_resolve_state(f, undefined, &.{}, main_body, false);

    try o.indent_writer.insert_newline();

    // Take advantage of the free_locals map to bucket locals per type. All
    // locals corresponding to AIR instructions should be in there due to
    // Liveness analysis, however, locals from alloc instructions will be
    // missing. These are added now to complete the map. Then we can sort by
    // alignment, descending.
    const free_locals = &f.free_locals_map;
    assert(f.value_map.count() == 0); // there must not be any unfreed locals
    for (f.allocs.keys(), f.allocs.values()) |local_index, should_emit| {
        if (!should_emit) continue;
        const local = f.locals.items[local_index];
        log.debug("inserting local {d} into free_locals", .{local_index});
        const gop = try free_locals.get_or_put(gpa, local.get_type());
        if (!gop.found_existing) gop.value_ptr.* = .{};
        try gop.value_ptr.put_no_clobber(gpa, local_index, {});
    }

    const SortContext = struct {
        keys: []const LocalType,

        pub fn less_than(ctx: @This(), lhs_index: usize, rhs_index: usize) bool {
            const lhs_ty = ctx.keys[lhs_index];
            const rhs_ty = ctx.keys[rhs_index];
            return lhs_ty.alignas.order(rhs_ty.alignas).compare(.gt);
        }
    };
    free_locals.sort(SortContext{ .keys = free_locals.keys() });

    const w = o.code_header_writer();
    for (free_locals.values()) |list| {
        for (list.keys()) |local_index| {
            const local = f.locals.items[local_index];
            try o.dg.render_ctype_and_name(w, local.ctype, .{ .local = local_index }, .{}, local.flags.alignas);
            try w.write_all(";\n ");
        }
    }

    // If we have a header to insert, append the body to the header
    // and then return the result, freeing the body.
    if (o.code_header.items.len > empty_header_len) {
        try o.code_header.append_slice(o.code.items[empty_header_len..]);
        mem.swap(std.ArrayList(u8), &o.code, &o.code_header);
    }
}

pub fn gen_decl(o: *Object) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const zcu = o.dg.zcu;
    const decl_index = o.dg.pass.decl;
    const decl = zcu.decl_ptr(decl_index);
    const decl_ty = decl.type_of(zcu);

    if (!decl_ty.is_fn_or_has_runtime_bits_ignore_comptime(zcu)) return;
    if (decl.val.get_extern_func(zcu)) |_| {
        const fwd_decl_writer = o.dg.fwd_decl_writer();
        try fwd_decl_writer.write_all("zig_extern ");
        try o.dg.render_function_signature(fwd_decl_writer, decl_index, .forward, .{ .export_index = 0 });
        try fwd_decl_writer.write_all(";\n");
        try gen_exports(o);
    } else if (decl.val.get_variable(zcu)) |variable| {
        try o.dg.render_fwd_decl(decl_index, variable, .final);
        try gen_exports(o);

        if (variable.is_extern) return;

        const is_global = variable.is_extern or o.dg.decl_is_global(decl.val);
        const w = o.writer();
        if (!is_global) try w.write_all("static ");
        if (variable.is_weak_linkage) try w.write_all("zig_weak_linkage ");
        if (variable.is_threadlocal and !o.dg.mod.single_threaded) try w.write_all("zig_threadlocal ");
        if (decl.@"linksection".to_slice(&zcu.intern_pool)) |s|
            try w.print("zig_linksection({s}) ", .{fmt_string_literal(s, null)});
        const decl_c_value = .{ .decl = decl_index };
        try o.dg.render_type_and_name(w, decl_ty, decl_c_value, .{}, decl.alignment, .complete);
        try w.write_all(" = ");
        try o.dg.render_value(w, Value.from_interned(variable.init), .StaticInitializer);
        try w.write_byte(';');
        try o.indent_writer.insert_newline();
    } else {
        const is_global = o.dg.zcu.decl_exports.contains(decl_index);
        const decl_c_value = .{ .decl = decl_index };
        try gen_decl_value(o, decl.val, is_global, decl_c_value, decl.alignment, decl.@"linksection");
    }
}

pub fn gen_decl_value(
    o: *Object,
    val: Value,
    is_global: bool,
    decl_c_value: CValue,
    alignment: Alignment,
    @"linksection": InternPool.OptionalNullTerminatedString,
) !void {
    const zcu = o.dg.zcu;
    const fwd_decl_writer = o.dg.fwd_decl_writer();

    const ty = val.type_of(zcu);

    try fwd_decl_writer.write_all(if (is_global) "zig_extern " else "static ");
    try o.dg.render_type_and_name(fwd_decl_writer, ty, decl_c_value, Const, alignment, .complete);
    switch (o.dg.pass) {
        .decl => |decl_index| {
            if (zcu.decl_exports.get(decl_index)) |exports| {
                const export_name = exports.items[0].opts.name.to_slice(&zcu.intern_pool);
                if (is_mangled_ident(export_name, true)) {
                    try fwd_decl_writer.print(" zig_mangled_final({ }, {s})", .{
                        fmt_ident(export_name), fmt_string_literal(export_name, null),
                    });
                }
            }
        },
        .anon => {},
        .flush => unreachable,
    }
    try fwd_decl_writer.write_all(";\n");
    try gen_exports(o);

    const w = o.writer();
    if (!is_global) try w.write_all("static ");
    if (@"linksection".to_slice(&zcu.intern_pool)) |s|
        try w.print("zig_linksection({s}) ", .{fmt_string_literal(s, null)});
    try o.dg.render_type_and_name(w, ty, decl_c_value, Const, alignment, .complete);
    try w.write_all(" = ");
    try o.dg.render_value(w, val, .StaticInitializer);
    try w.write_all(";\n");
}

pub fn gen_header(dg: *DeclGen) error{ AnalysisFail, OutOfMemory }!void {
    const tracy = trace(@src());
    defer tracy.end();

    const zcu = dg.zcu;
    const decl_index = dg.pass.decl;
    const decl = zcu.decl_ptr(decl_index);
    const writer = dg.fwd_decl_writer();

    switch (decl.type_of(zcu).zig_type_tag(zcu)) {
        .Fn => if (dg.decl_is_global(decl.val)) {
            try writer.write_all("zig_extern ");
            try dg.render_function_signature(writer, dg.pass.decl, .complete, .{ .export_index = 0 });
            try dg.fwd_decl.append_slice(";\n");
        },
        else => {},
    }
}

/// Generate code for an entire body which ends with a `noreturn` instruction. The states of
/// `value_map` and `free_locals_map` are undefined after the generation, and new locals may not
/// have been added to `free_locals_map`. For a version of this function that restores this state,
/// see `gen_body_resolve_state`.
fn gen_body(f: *Function, body: []const Air.Inst.Index) error{ AnalysisFail, OutOfMemory }!void {
    const writer = f.object.writer();
    if (body.len == 0) {
        try writer.write_all("{}");
    } else {
        try writer.write_all("{\n");
        f.object.indent_writer.push_indent();
        try gen_body_inner(f, body);
        f.object.indent_writer.pop_indent();
        try writer.write_byte('}');
    }
}

/// Generate code for an entire body which ends with a `noreturn` instruction. The states of
/// `value_map` and `free_locals_map` are restored to their original values, and any non-allocated
/// locals introduced within the body are correctly added to `free_locals_map`. Operands in
/// `leading_deaths` have their deaths processed before the body is generated.
/// A scope is introduced (using braces) only if `inner` is `false`.
/// If `leading_deaths` is empty, `inst` may be `undefined`.
fn gen_body_resolve_state(f: *Function, inst: Air.Inst.Index, leading_deaths: []const Air.Inst.Index, body: []const Air.Inst.Index, inner: bool) error{ AnalysisFail, OutOfMemory }!void {
    if (body.len == 0) {
        // Don't go to the expense of cloning everything!
        if (!inner) try f.object.writer().write_all("{}");
        return;
    }

    // TODO: we can probably avoid the copies in some other common cases too.

    const gpa = f.object.dg.gpa;

    // Save the original value_map and free_locals_map so that we can restore them after the body.
    var old_value_map = try f.value_map.clone();
    defer old_value_map.deinit();
    var old_free_locals = try clone_free_locals_map(gpa, &f.free_locals_map);
    defer deinit_free_locals_map(gpa, &old_free_locals);

    // Remember how many locals there were before entering the body so that we can free any that
    // were newly introduced. Any new locals must necessarily be logically free after the then
    // branch is complete.
    const pre_locals_len = @as(LocalIndex, @int_cast(f.locals.items.len));

    for (leading_deaths) |death| {
        try die(f, inst, death.to_ref());
    }

    if (inner) {
        try gen_body_inner(f, body);
    } else {
        try gen_body(f, body);
    }

    f.value_map.deinit();
    f.value_map = old_value_map.move();
    deinit_free_locals_map(gpa, &f.free_locals_map);
    f.free_locals_map = old_free_locals.move();

    // Now, use the lengths we stored earlier to detect any locals the body generated, and free
    // them, unless they were used to store allocs.

    for (pre_locals_len..f.locals.items.len) |local_i| {
        const local_index: LocalIndex = @int_cast(local_i);
        if (f.allocs.contains(local_index)) {
            continue;
        }
        try free_local(f, inst, local_index, null);
    }
}

fn gen_body_inner(f: *Function, body: []const Air.Inst.Index) error{ AnalysisFail, OutOfMemory }!void {
    const zcu = f.object.dg.zcu;
    const ip = &zcu.intern_pool;
    const air_tags = f.air.instructions.items(.tag);
    const air_datas = f.air.instructions.items(.data);

    for (body) |inst| {
        if (f.liveness.is_unused(inst) and !f.air.must_lower(inst, ip))
            continue;

        const result_value = switch (air_tags[@int_from_enum(inst)]) {
            // zig fmt: off
            .inferred_alloc, .inferred_alloc_comptime => unreachable,

            .arg      => try air_arg(f, inst),

            .trap       => try air_trap(f, f.object.writer()),
            .breakpoint => try air_breakpoint(f.object.writer()),
            .ret_addr   => try air_ret_addr(f, inst),
            .frame_addr => try air_frame_address(f, inst),
            .unreach    => try air_unreach(f),
            .fence      => try air_fence(f, inst),

            .ptr_add => try air_ptr_add_sub(f, inst, '+'),
            .ptr_sub => try air_ptr_add_sub(f, inst, '-'),

            // TODO use a different strategy for add, sub, mul, div
            // that communicates to the optimizer that wrapping is UB.
            .add => try air_bin_op(f, inst, "+", "add", .none),
            .sub => try air_bin_op(f, inst, "-", "sub", .none),
            .mul => try air_bin_op(f, inst, "*", "mul", .none),

            .neg => try air_un_builtin_call(f, inst, air_datas[@int_from_enum(inst)].un_op, "neg", .none),
            .div_float => try air_bin_builtin_call(f, inst, "div", .none),

            .div_trunc, .div_exact => try air_bin_op(f, inst, "/", "div_trunc", .none),
            .rem => blk: {
                const bin_op = air_datas[@int_from_enum(inst)].bin_op;
                const lhs_scalar_ty = f.type_of(bin_op.lhs).scalar_type(zcu);
                // For binary operations @TypeOf(lhs)==@TypeOf(rhs),
                // so we only check one.
                break :blk if (lhs_scalar_ty.is_int(zcu))
                    try air_bin_op(f, inst, "%", "rem", .none)
                else
                    try air_bin_builtin_call(f, inst, "fmod", .none);
            },
            .div_floor => try air_bin_builtin_call(f, inst, "div_floor", .none),
            .mod       => try air_bin_builtin_call(f, inst, "mod", .none),
            .abs       => try air_un_builtin_call(f, inst, air_datas[@int_from_enum(inst)].ty_op.operand, "abs", .none),

            .add_wrap => try air_bin_builtin_call(f, inst, "addw", .bits),
            .sub_wrap => try air_bin_builtin_call(f, inst, "subw", .bits),
            .mul_wrap => try air_bin_builtin_call(f, inst, "mulw", .bits),

            .add_sat => try air_bin_builtin_call(f, inst, "adds", .bits),
            .sub_sat => try air_bin_builtin_call(f, inst, "subs", .bits),
            .mul_sat => try air_bin_builtin_call(f, inst, "muls", .bits),
            .shl_sat => try air_bin_builtin_call(f, inst, "shls", .bits),

            .sqrt        => try air_un_builtin_call(f, inst, air_datas[@int_from_enum(inst)].un_op, "sqrt", .none),
            .sin         => try air_un_builtin_call(f, inst, air_datas[@int_from_enum(inst)].un_op, "sin", .none),
            .cos         => try air_un_builtin_call(f, inst, air_datas[@int_from_enum(inst)].un_op, "cos", .none),
            .tan         => try air_un_builtin_call(f, inst, air_datas[@int_from_enum(inst)].un_op, "tan", .none),
            .exp         => try air_un_builtin_call(f, inst, air_datas[@int_from_enum(inst)].un_op, "exp", .none),
            .exp2        => try air_un_builtin_call(f, inst, air_datas[@int_from_enum(inst)].un_op, "exp2", .none),
            .log         => try air_un_builtin_call(f, inst, air_datas[@int_from_enum(inst)].un_op, "log", .none),
            .log2        => try air_un_builtin_call(f, inst, air_datas[@int_from_enum(inst)].un_op, "log2", .none),
            .log10       => try air_un_builtin_call(f, inst, air_datas[@int_from_enum(inst)].un_op, "log10", .none),
            .floor       => try air_un_builtin_call(f, inst, air_datas[@int_from_enum(inst)].un_op, "floor", .none),
            .ceil        => try air_un_builtin_call(f, inst, air_datas[@int_from_enum(inst)].un_op, "ceil", .none),
            .round       => try air_un_builtin_call(f, inst, air_datas[@int_from_enum(inst)].un_op, "round", .none),
            .trunc_float => try air_un_builtin_call(f, inst, air_datas[@int_from_enum(inst)].un_op, "trunc", .none),

            .mul_add => try air_mul_add(f, inst),

            .add_with_overflow => try air_overflow(f, inst, "add", .bits),
            .sub_with_overflow => try air_overflow(f, inst, "sub", .bits),
            .mul_with_overflow => try air_overflow(f, inst, "mul", .bits),
            .shl_with_overflow => try air_overflow(f, inst, "shl", .bits),

            .min => try air_min_max(f, inst, '<', "min"),
            .max => try air_min_max(f, inst, '>', "max"),

            .slice => try air_slice(f, inst),

            .cmp_gt  => try air_cmp_op(f, inst, air_datas[@int_from_enum(inst)].bin_op, .gt),
            .cmp_gte => try air_cmp_op(f, inst, air_datas[@int_from_enum(inst)].bin_op, .gte),
            .cmp_lt  => try air_cmp_op(f, inst, air_datas[@int_from_enum(inst)].bin_op, .lt),
            .cmp_lte => try air_cmp_op(f, inst, air_datas[@int_from_enum(inst)].bin_op, .lte),

            .cmp_eq  => try air_equality(f, inst, .eq),
            .cmp_neq => try air_equality(f, inst, .neq),

            .cmp_vector => blk: {
                const ty_pl = air_datas[@int_from_enum(inst)].ty_pl;
                const extra = f.air.extra_data(Air.VectorCmp, ty_pl.payload).data;
                break :blk try air_cmp_op(f, inst, extra, extra.compare_operator());
            },
            .cmp_lt_errors_len => try air_cmp_lt_errors_len(f, inst),

            // bool_and and bool_or are non-short-circuit operations
            .bool_and, .bit_and => try air_bin_op(f, inst, "&",  "and", .none),
            .bool_or,  .bit_or  => try air_bin_op(f, inst, "|",  "or",  .none),
            .xor                => try air_bin_op(f, inst, "^",  "xor", .none),
            .shr, .shr_exact    => try air_bin_builtin_call(f, inst, "shr", .none),
            .shl,               => try air_bin_builtin_call(f, inst, "shlw", .bits),
            .shl_exact          => try air_bin_op(f, inst, "<<", "shl", .none),
            .not                => try air_not  (f, inst),

            .optional_payload         => try air_optional_payload(f, inst, false),
            .optional_payload_ptr     => try air_optional_payload(f, inst, true),
            .optional_payload_ptr_set => try air_optional_payload_ptr_set(f, inst),
            .wrap_optional            => try air_wrap_optional(f, inst),

            .is_err          => try air_is_err(f, inst, false, "!="),
            .is_non_err      => try air_is_err(f, inst, false, "=="),
            .is_err_ptr      => try air_is_err(f, inst, true, "!="),
            .is_non_err_ptr  => try air_is_err(f, inst, true, "=="),

            .is_null         => try air_is_null(f, inst, .eq, false),
            .is_non_null     => try air_is_null(f, inst, .neq, false),
            .is_null_ptr     => try air_is_null(f, inst, .eq, true),
            .is_non_null_ptr => try air_is_null(f, inst, .neq, true),

            .alloc            => try air_alloc(f, inst),
            .ret_ptr          => try air_ret_ptr(f, inst),
            .assembly         => try air_asm(f, inst),
            .block            => try air_block(f, inst),
            .bitcast          => try air_bitcast(f, inst),
            .intcast          => try air_int_cast(f, inst),
            .trunc            => try air_trunc(f, inst),
            .int_from_bool      => try air_int_from_bool(f, inst),
            .load             => try air_load(f, inst),
            .ret              => try air_ret(f, inst, false),
            .ret_safe         => try air_ret(f, inst, false), // TODO
            .ret_load         => try air_ret(f, inst, true),
            .store            => try air_store(f, inst, false),
            .store_safe       => try air_store(f, inst, true),
            .loop             => try air_loop(f, inst),
            .cond_br          => try air_cond_br(f, inst),
            .br               => try air_br(f, inst),
            .switch_br        => try air_switch_br(f, inst),
            .struct_field_ptr => try air_struct_field_ptr(f, inst),
            .array_to_slice   => try air_array_to_slice(f, inst),
            .cmpxchg_weak     => try air_cmpxchg(f, inst, "weak"),
            .cmpxchg_strong   => try air_cmpxchg(f, inst, "strong"),
            .atomic_rmw       => try air_atomic_rmw(f, inst),
            .atomic_load      => try air_atomic_load(f, inst),
            .memset           => try air_memset(f, inst, false),
            .memset_safe      => try air_memset(f, inst, true),
            .memcpy           => try air_memcpy(f, inst),
            .set_union_tag    => try air_set_union_tag(f, inst),
            .get_union_tag    => try air_get_union_tag(f, inst),
            .clz              => try air_un_builtin_call(f, inst, air_datas[@int_from_enum(inst)].ty_op.operand, "clz", .bits),
            .ctz              => try air_un_builtin_call(f, inst, air_datas[@int_from_enum(inst)].ty_op.operand, "ctz", .bits),
            .popcount         => try air_un_builtin_call(f, inst, air_datas[@int_from_enum(inst)].ty_op.operand, "popcount", .bits),
            .byte_swap        => try air_un_builtin_call(f, inst, air_datas[@int_from_enum(inst)].ty_op.operand, "byte_swap", .bits),
            .bit_reverse      => try air_un_builtin_call(f, inst, air_datas[@int_from_enum(inst)].ty_op.operand, "bit_reverse", .bits),
            .tag_name         => try air_tag_name(f, inst),
            .error_name       => try air_error_name(f, inst),
            .splat            => try air_splat(f, inst),
            .select           => try air_select(f, inst),
            .shuffle          => try air_shuffle(f, inst),
            .reduce           => try air_reduce(f, inst),
            .aggregate_init   => try air_aggregate_init(f, inst),
            .union_init       => try air_union_init(f, inst),
            .prefetch         => try air_prefetch(f, inst),
            .addrspace_cast   => return f.fail("TODO: C backend: implement addrspace_cast", .{}),

            .@"try"  => try air_try(f, inst),
            .try_ptr => try air_try_ptr(f, inst),

            .dbg_stmt => try air_dbg_stmt(f, inst),
            .dbg_inline_block => try air_dbg_inline_block(f, inst),
            .dbg_var_ptr, .dbg_var_val => try air_dbg_var(f, inst),

            .call              => try air_call(f, inst, .auto),
            .call_always_tail  => .none,
            .call_never_tail   => try air_call(f, inst, .never_tail),
            .call_never_inline => try air_call(f, inst, .never_inline),

            .float_from_int,
            .int_from_float,
            .fptrunc,
            .fpext,
            => try air_float_cast(f, inst),

            .int_from_ptr => try air_int_from_ptr(f, inst),

            .atomic_store_unordered => try air_atomic_store(f, inst, to_memory_order(.unordered)),
            .atomic_store_monotonic => try air_atomic_store(f, inst, to_memory_order(.monotonic)),
            .atomic_store_release   => try air_atomic_store(f, inst, to_memory_order(.release)),
            .atomic_store_seq_cst   => try air_atomic_store(f, inst, to_memory_order(.seq_cst)),

            .struct_field_ptr_index_0 => try air_struct_field_ptr_index(f, inst, 0),
            .struct_field_ptr_index_1 => try air_struct_field_ptr_index(f, inst, 1),
            .struct_field_ptr_index_2 => try air_struct_field_ptr_index(f, inst, 2),
            .struct_field_ptr_index_3 => try air_struct_field_ptr_index(f, inst, 3),

            .field_parent_ptr => try air_field_parent_ptr(f, inst),

            .struct_field_val => try air_struct_field_val(f, inst),
            .slice_ptr        => try air_slice_field(f, inst, false, "ptr"),
            .slice_len        => try air_slice_field(f, inst, false, "len"),

            .ptr_slice_ptr_ptr => try air_slice_field(f, inst, true, "ptr"),
            .ptr_slice_len_ptr => try air_slice_field(f, inst, true, "len"),

            .ptr_elem_val       => try air_ptr_elem_val(f, inst),
            .ptr_elem_ptr       => try air_ptr_elem_ptr(f, inst),
            .slice_elem_val     => try air_slice_elem_val(f, inst),
            .slice_elem_ptr     => try air_slice_elem_ptr(f, inst),
            .array_elem_val     => try air_array_elem_val(f, inst),

            .unwrap_errunion_payload     => try air_unwrap_err_union_pay(f, inst, false),
            .unwrap_errunion_payload_ptr => try air_unwrap_err_union_pay(f, inst, true),
            .unwrap_errunion_err         => try air_unwrap_err_union_err(f, inst),
            .unwrap_errunion_err_ptr     => try air_unwrap_err_union_err(f, inst),
            .wrap_errunion_payload       => try air_wrap_err_union_pay(f, inst),
            .wrap_errunion_err           => try air_wrap_err_union_err(f, inst),
            .errunion_payload_ptr_set    => try air_err_union_payload_ptr_set(f, inst),
            .err_return_trace            => try air_err_return_trace(f, inst),
            .set_err_return_trace        => try air_set_err_return_trace(f, inst),
            .save_err_return_trace_index => try air_save_err_return_trace_index(f, inst),

            .wasm_memory_size => try air_wasm_memory_size(f, inst),
            .wasm_memory_grow => try air_wasm_memory_grow(f, inst),

            .add_optimized,
            .sub_optimized,
            .mul_optimized,
            .div_float_optimized,
            .div_trunc_optimized,
            .div_floor_optimized,
            .div_exact_optimized,
            .rem_optimized,
            .mod_optimized,
            .neg_optimized,
            .cmp_lt_optimized,
            .cmp_lte_optimized,
            .cmp_eq_optimized,
            .cmp_gte_optimized,
            .cmp_gt_optimized,
            .cmp_neq_optimized,
            .cmp_vector_optimized,
            .reduce_optimized,
            .int_from_float_optimized,
            => return f.fail("TODO implement optimized float mode", .{}),

            .add_safe,
            .sub_safe,
            .mul_safe,
            => return f.fail("TODO implement safety_checked_instructions", .{}),

            .is_named_enum_value => return f.fail("TODO: C backend: implement is_named_enum_value", .{}),
            .error_set_has_value => return f.fail("TODO: C backend: implement error_set_has_value", .{}),
            .vector_store_elem => return f.fail("TODO: C backend: implement vector_store_elem", .{}),

            .c_va_start => try air_cva_start(f, inst),
            .c_va_arg => try air_cva_arg(f, inst),
            .c_va_end => try air_cva_end(f, inst),
            .c_va_copy => try air_cva_copy(f, inst),

            .work_item_id,
            .work_group_size,
            .work_group_id,
            => unreachable,
            // zig fmt: on
        };
        if (result_value == .new_local) {
            log.debug("map %{d} to t{d}", .{ inst, result_value.new_local });
        }
        try f.value_map.put_no_clobber(inst.to_ref(), switch (result_value) {
            .none => continue,
            .new_local => |local_index| .{ .local = local_index },
            else => result_value,
        });
    }
}

fn air_slice_field(f: *Function, inst: Air.Inst.Index, is_ptr: bool, field_name: []const u8) !CValue {
    const ty_op = f.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

    const inst_ty = f.type_of_index(inst);
    const operand = try f.resolve_inst(ty_op.operand);
    try reap(f, inst, &.{ty_op.operand});

    const writer = f.object.writer();
    const local = try f.alloc_local(inst, inst_ty);
    const a = try Assignment.start(f, writer, try f.ctype_from_type(inst_ty, .complete));
    try f.write_cvalue(writer, local, .Other);
    try a.assign(f, writer);
    if (is_ptr) {
        try writer.write_byte('&');
        try f.write_cvalue_deref_member(writer, operand, .{ .identifier = field_name });
    } else try f.write_cvalue_member(writer, operand, .{ .identifier = field_name });
    try a.end(f, writer);
    return local;
}

fn air_ptr_elem_val(f: *Function, inst: Air.Inst.Index) !CValue {
    const zcu = f.object.dg.zcu;
    const inst_ty = f.type_of_index(inst);
    const bin_op = f.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
    if (!inst_ty.has_runtime_bits_ignore_comptime(zcu)) {
        try reap(f, inst, &.{ bin_op.lhs, bin_op.rhs });
        return .none;
    }

    const ptr = try f.resolve_inst(bin_op.lhs);
    const index = try f.resolve_inst(bin_op.rhs);
    try reap(f, inst, &.{ bin_op.lhs, bin_op.rhs });

    const writer = f.object.writer();
    const local = try f.alloc_local(inst, inst_ty);
    const a = try Assignment.start(f, writer, try f.ctype_from_type(inst_ty, .complete));
    try f.write_cvalue(writer, local, .Other);
    try a.assign(f, writer);
    try f.write_cvalue(writer, ptr, .Other);
    try writer.write_byte('[');
    try f.write_cvalue(writer, index, .Other);
    try writer.write_byte(']');
    try a.end(f, writer);
    return local;
}

fn air_ptr_elem_ptr(f: *Function, inst: Air.Inst.Index) !CValue {
    const zcu = f.object.dg.zcu;
    const ty_pl = f.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const bin_op = f.air.extra_data(Air.Bin, ty_pl.payload).data;

    const inst_ty = f.type_of_index(inst);
    const ptr_ty = f.type_of(bin_op.lhs);
    const elem_has_bits = ptr_ty.elem_type2(zcu).has_runtime_bits_ignore_comptime(zcu);

    const ptr = try f.resolve_inst(bin_op.lhs);
    const index = try f.resolve_inst(bin_op.rhs);
    try reap(f, inst, &.{ bin_op.lhs, bin_op.rhs });

    const writer = f.object.writer();
    const local = try f.alloc_local(inst, inst_ty);
    const a = try Assignment.start(f, writer, try f.ctype_from_type(inst_ty, .complete));
    try f.write_cvalue(writer, local, .Other);
    try a.assign(f, writer);
    try writer.write_byte('(');
    try f.render_type(writer, inst_ty);
    try writer.write_byte(')');
    if (elem_has_bits) try writer.write_byte('&');
    if (elem_has_bits and ptr_ty.ptr_size(zcu) == .One) {
        // It's a pointer to an array, so we need to de-reference.
        try f.write_cvalue_deref(writer, ptr);
    } else try f.write_cvalue(writer, ptr, .Other);
    if (elem_has_bits) {
        try writer.write_byte('[');
        try f.write_cvalue(writer, index, .Other);
        try writer.write_byte(']');
    }
    try a.end(f, writer);
    return local;
}

fn air_slice_elem_val(f: *Function, inst: Air.Inst.Index) !CValue {
    const zcu = f.object.dg.zcu;
    const inst_ty = f.type_of_index(inst);
    const bin_op = f.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
    if (!inst_ty.has_runtime_bits_ignore_comptime(zcu)) {
        try reap(f, inst, &.{ bin_op.lhs, bin_op.rhs });
        return .none;
    }

    const slice = try f.resolve_inst(bin_op.lhs);
    const index = try f.resolve_inst(bin_op.rhs);
    try reap(f, inst, &.{ bin_op.lhs, bin_op.rhs });

    const writer = f.object.writer();
    const local = try f.alloc_local(inst, inst_ty);
    const a = try Assignment.start(f, writer, try f.ctype_from_type(inst_ty, .complete));
    try f.write_cvalue(writer, local, .Other);
    try a.assign(f, writer);
    try f.write_cvalue_member(writer, slice, .{ .identifier = "ptr" });
    try writer.write_byte('[');
    try f.write_cvalue(writer, index, .Other);
    try writer.write_byte(']');
    try a.end(f, writer);
    return local;
}

fn air_slice_elem_ptr(f: *Function, inst: Air.Inst.Index) !CValue {
    const zcu = f.object.dg.zcu;
    const ty_pl = f.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const bin_op = f.air.extra_data(Air.Bin, ty_pl.payload).data;

    const inst_ty = f.type_of_index(inst);
    const slice_ty = f.type_of(bin_op.lhs);
    const elem_ty = slice_ty.elem_type2(zcu);
    const elem_has_bits = elem_ty.has_runtime_bits_ignore_comptime(zcu);

    const slice = try f.resolve_inst(bin_op.lhs);
    const index = try f.resolve_inst(bin_op.rhs);
    try reap(f, inst, &.{ bin_op.lhs, bin_op.rhs });

    const writer = f.object.writer();
    const local = try f.alloc_local(inst, inst_ty);
    const a = try Assignment.start(f, writer, try f.ctype_from_type(inst_ty, .complete));
    try f.write_cvalue(writer, local, .Other);
    try a.assign(f, writer);
    if (elem_has_bits) try writer.write_byte('&');
    try f.write_cvalue_member(writer, slice, .{ .identifier = "ptr" });
    if (elem_has_bits) {
        try writer.write_byte('[');
        try f.write_cvalue(writer, index, .Other);
        try writer.write_byte(']');
    }
    try a.end(f, writer);
    return local;
}

fn air_array_elem_val(f: *Function, inst: Air.Inst.Index) !CValue {
    const zcu = f.object.dg.zcu;
    const bin_op = f.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
    const inst_ty = f.type_of_index(inst);
    if (!inst_ty.has_runtime_bits_ignore_comptime(zcu)) {
        try reap(f, inst, &.{ bin_op.lhs, bin_op.rhs });
        return .none;
    }

    const array = try f.resolve_inst(bin_op.lhs);
    const index = try f.resolve_inst(bin_op.rhs);
    try reap(f, inst, &.{ bin_op.lhs, bin_op.rhs });

    const writer = f.object.writer();
    const local = try f.alloc_local(inst, inst_ty);
    const a = try Assignment.start(f, writer, try f.ctype_from_type(inst_ty, .complete));
    try f.write_cvalue(writer, local, .Other);
    try a.assign(f, writer);
    try f.write_cvalue(writer, array, .Other);
    try writer.write_byte('[');
    try f.write_cvalue(writer, index, .Other);
    try writer.write_byte(']');
    try a.end(f, writer);
    return local;
}

fn air_alloc(f: *Function, inst: Air.Inst.Index) !CValue {
    const zcu = f.object.dg.zcu;
    const inst_ty = f.type_of_index(inst);
    const elem_ty = inst_ty.child_type(zcu);
    if (!elem_ty.is_fn_or_has_runtime_bits_ignore_comptime(zcu)) return .{ .undef = inst_ty };

    const local = try f.alloc_local_value(.{
        .ctype = try f.ctype_from_type(elem_ty, .complete),
        .alignas = CType.AlignAs.from_alignment(.{
            .@"align" = inst_ty.ptr_info(zcu).flags.alignment,
            .abi = elem_ty.abi_alignment(zcu),
        }),
    });
    log.debug("%{d}: allocated unfreeable t{d}", .{ inst, local.new_local });
    const gpa = f.object.dg.zcu.gpa;
    try f.allocs.put(gpa, local.new_local, true);
    return .{ .local_ref = local.new_local };
}

fn air_ret_ptr(f: *Function, inst: Air.Inst.Index) !CValue {
    const zcu = f.object.dg.zcu;
    const inst_ty = f.type_of_index(inst);
    const elem_ty = inst_ty.child_type(zcu);
    if (!elem_ty.is_fn_or_has_runtime_bits_ignore_comptime(zcu)) return .{ .undef = inst_ty };

    const local = try f.alloc_local_value(.{
        .ctype = try f.ctype_from_type(elem_ty, .complete),
        .alignas = CType.AlignAs.from_alignment(.{
            .@"align" = inst_ty.ptr_info(zcu).flags.alignment,
            .abi = elem_ty.abi_alignment(zcu),
        }),
    });
    log.debug("%{d}: allocated unfreeable t{d}", .{ inst, local.new_local });
    const gpa = f.object.dg.zcu.gpa;
    try f.allocs.put(gpa, local.new_local, true);
    return .{ .local_ref = local.new_local };
}

fn air_arg(f: *Function, inst: Air.Inst.Index) !CValue {
    const inst_ty = f.type_of_index(inst);
    const inst_ctype = try f.ctype_from_type(inst_ty, .parameter);

    const i = f.next_arg_index;
    f.next_arg_index += 1;
    const result: CValue = if (inst_ctype.eql(try f.ctype_from_type(inst_ty, .complete)))
        .{ .arg = i }
    else
        .{ .arg_array = i };

    if (f.liveness.is_unused(inst)) {
        const writer = f.object.writer();
        try writer.write_byte('(');
        try f.render_type(writer, Type.void);
        try writer.write_byte(')');
        try f.write_cvalue(writer, result, .Other);
        try writer.write_all(";\n");
        return .none;
    }

    return result;
}

fn air_load(f: *Function, inst: Air.Inst.Index) !CValue {
    const zcu = f.object.dg.zcu;
    const ty_op = f.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

    const ptr_ty = f.type_of(ty_op.operand);
    const ptr_scalar_ty = ptr_ty.scalar_type(zcu);
    const ptr_info = ptr_scalar_ty.ptr_info(zcu);
    const src_ty = Type.from_interned(ptr_info.child);

    if (!src_ty.has_runtime_bits_ignore_comptime(zcu)) {
        try reap(f, inst, &.{ty_op.operand});
        return .none;
    }

    const operand = try f.resolve_inst(ty_op.operand);

    try reap(f, inst, &.{ty_op.operand});

    const is_aligned = if (ptr_info.flags.alignment != .none)
        ptr_info.flags.alignment.order(src_ty.abi_alignment(zcu)).compare(.gte)
    else
        true;
    const is_array = lowers_to_array(src_ty, zcu);
    const need_memcpy = !is_aligned or is_array;

    const writer = f.object.writer();
    const local = try f.alloc_local(inst, src_ty);
    const v = try Vectorize.start(f, inst, writer, ptr_ty);

    if (need_memcpy) {
        try writer.write_all("memcpy(");
        if (!is_array) try writer.write_byte('&');
        try f.write_cvalue(writer, local, .Other);
        try v.elem(f, writer);
        try writer.write_all(", (const char *)");
        try f.write_cvalue(writer, operand, .Other);
        try v.elem(f, writer);
        try writer.write_all(", sizeof(");
        try f.render_type(writer, src_ty);
        try writer.write_all("))");
    } else if (ptr_info.packed_offset.host_size > 0 and ptr_info.flags.vector_index == .none) {
        const host_bits: u16 = ptr_info.packed_offset.host_size * 8;
        const host_ty = try zcu.int_type(.unsigned, host_bits);

        const bit_offset_ty = try zcu.int_type(.unsigned, Type.smallest_unsigned_bits(host_bits - 1));
        const bit_offset_val = try zcu.int_value(bit_offset_ty, ptr_info.packed_offset.bit_offset);

        const field_ty = try zcu.int_type(.unsigned, @as(u16, @int_cast(src_ty.bit_size(zcu))));

        try f.write_cvalue(writer, local, .Other);
        try v.elem(f, writer);
        try writer.write_all(" = (");
        try f.render_type(writer, src_ty);
        try writer.write_all(")zig_wrap_");
        try f.object.dg.render_type_for_builtin_fn_name(writer, field_ty);
        try writer.write_all("((");
        try f.render_type(writer, field_ty);
        try writer.write_byte(')');
        const cant_cast = host_ty.is_int(zcu) and host_ty.bit_size(zcu) > 64;
        if (cant_cast) {
            if (field_ty.bit_size(zcu) > 64) return f.fail("TODO: C backend: implement casting between types > 64 bits", .{});
            try writer.write_all("zig_lo_");
            try f.object.dg.render_type_for_builtin_fn_name(writer, host_ty);
            try writer.write_byte('(');
        }
        try writer.write_all("zig_shr_");
        try f.object.dg.render_type_for_builtin_fn_name(writer, host_ty);
        try writer.write_byte('(');
        try f.write_cvalue_deref(writer, operand);
        try v.elem(f, writer);
        try writer.print(", {})", .{try f.fmt_int_literal(bit_offset_val)});
        if (cant_cast) try writer.write_byte(')');
        try f.object.dg.render_builtin_info(writer, field_ty, .bits);
        try writer.write_byte(')');
    } else {
        try f.write_cvalue(writer, local, .Other);
        try v.elem(f, writer);
        try writer.write_all(" = ");
        try f.write_cvalue_deref(writer, operand);
        try v.elem(f, writer);
    }
    try writer.write_all(";\n");
    try v.end(f, inst, writer);

    return local;
}

fn air_ret(f: *Function, inst: Air.Inst.Index, is_ptr: bool) !CValue {
    const zcu = f.object.dg.zcu;
    const un_op = f.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const writer = f.object.writer();
    const op_inst = un_op.to_index();
    const op_ty = f.type_of(un_op);
    const ret_ty = if (is_ptr) op_ty.child_type(zcu) else op_ty;
    const ret_ctype = try f.ctype_from_type(ret_ty, .parameter);

    if (op_inst != null and f.air.instructions.items(.tag)[@int_from_enum(op_inst.?)] == .call_always_tail) {
        try reap(f, inst, &.{un_op});
        _ = try air_call(f, op_inst.?, .always_tail);
    } else if (ret_ctype.index != .void) {
        const operand = try f.resolve_inst(un_op);
        try reap(f, inst, &.{un_op});
        var deref = is_ptr;
        const is_array = lowers_to_array(ret_ty, zcu);
        const ret_val = if (is_array) ret_val: {
            const array_local = try f.alloc_aligned_local(inst, .{
                .ctype = ret_ctype,
                .alignas = CType.AlignAs.from_abi_alignment(ret_ty.abi_alignment(f.object.dg.zcu)),
            });
            try writer.write_all("memcpy(");
            try f.write_cvalue_member(writer, array_local, .{ .identifier = "array" });
            try writer.write_all(", ");
            if (deref)
                try f.write_cvalue_deref(writer, operand)
            else
                try f.write_cvalue(writer, operand, .FunctionArgument);
            deref = false;
            try writer.write_all(", sizeof(");
            try f.render_type(writer, ret_ty);
            try writer.write_all("));\n");
            break :ret_val array_local;
        } else operand;

        try writer.write_all("return ");
        if (deref)
            try f.write_cvalue_deref(writer, ret_val)
        else
            try f.write_cvalue(writer, ret_val, .Other);
        try writer.write_all(";\n");
        if (is_array) {
            try free_local(f, inst, ret_val.new_local, null);
        }
    } else {
        try reap(f, inst, &.{un_op});
        // Not even allowed to return void in a naked function.
        if (!f.object.dg.is_naked_fn) try writer.write_all("return;\n");
    }
    return .none;
}

fn air_int_cast(f: *Function, inst: Air.Inst.Index) !CValue {
    const zcu = f.object.dg.zcu;
    const ty_op = f.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

    const operand = try f.resolve_inst(ty_op.operand);
    try reap(f, inst, &.{ty_op.operand});

    const inst_ty = f.type_of_index(inst);
    const inst_scalar_ty = inst_ty.scalar_type(zcu);
    const operand_ty = f.type_of(ty_op.operand);
    const scalar_ty = operand_ty.scalar_type(zcu);

    if (f.object.dg.int_cast_is_noop(inst_scalar_ty, scalar_ty)) return f.move_cvalue(inst, inst_ty, operand);

    const writer = f.object.writer();
    const local = try f.alloc_local(inst, inst_ty);
    const v = try Vectorize.start(f, inst, writer, operand_ty);
    const a = try Assignment.start(f, writer, try f.ctype_from_type(scalar_ty, .complete));
    try f.write_cvalue(writer, local, .Other);
    try v.elem(f, writer);
    try a.assign(f, writer);
    try f.render_int_cast(writer, inst_scalar_ty, operand, v, scalar_ty, .Other);
    try a.end(f, writer);
    try v.end(f, inst, writer);
    return local;
}

fn air_trunc(f: *Function, inst: Air.Inst.Index) !CValue {
    const zcu = f.object.dg.zcu;
    const ty_op = f.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

    const operand = try f.resolve_inst(ty_op.operand);
    try reap(f, inst, &.{ty_op.operand});

    const inst_ty = f.type_of_index(inst);
    const inst_scalar_ty = inst_ty.scalar_type(zcu);
    const dest_int_info = inst_scalar_ty.int_info(zcu);
    const dest_bits = dest_int_info.bits;
    const dest_c_bits = to_cint_bits(dest_bits) orelse
        return f.fail("TODO: C backend: implement integer types larger than 128 bits", .{});
    const operand_ty = f.type_of(ty_op.operand);
    const scalar_ty = operand_ty.scalar_type(zcu);
    const scalar_int_info = scalar_ty.int_info(zcu);

    const need_cast = dest_c_bits < 64;
    const need_lo = scalar_int_info.bits > 64 and dest_bits <= 64;
    const need_mask = dest_bits < 8 or !std.math.is_power_of_two(dest_bits);
    if (!need_cast and !need_lo and !need_mask) return f.move_cvalue(inst, inst_ty, operand);

    const writer = f.object.writer();
    const local = try f.alloc_local(inst, inst_ty);
    const v = try Vectorize.start(f, inst, writer, operand_ty);
    const a = try Assignment.start(f, writer, try f.ctype_from_type(inst_scalar_ty, .complete));
    try f.write_cvalue(writer, local, .Other);
    try v.elem(f, writer);
    try a.assign(f, writer);
    if (need_cast) {
        try writer.write_byte('(');
        try f.render_type(writer, inst_scalar_ty);
        try writer.write_byte(')');
    }
    if (need_lo) {
        try writer.write_all("zig_lo_");
        try f.object.dg.render_type_for_builtin_fn_name(writer, scalar_ty);
        try writer.write_byte('(');
    }
    if (!need_mask) {
        try f.write_cvalue(writer, operand, .Other);
        try v.elem(f, writer);
    } else switch (dest_int_info.signedness) {
        .unsigned => {
            try writer.write_all("zig_and_");
            try f.object.dg.render_type_for_builtin_fn_name(writer, scalar_ty);
            try writer.write_byte('(');
            try f.write_cvalue(writer, operand, .FunctionArgument);
            try v.elem(f, writer);
            try writer.print(", {x})", .{
                try f.fmt_int_literal(try inst_scalar_ty.max_int_scalar(zcu, scalar_ty)),
            });
        },
        .signed => {
            const c_bits = to_cint_bits(scalar_int_info.bits) orelse
                return f.fail("TODO: C backend: implement integer types larger than 128 bits", .{});
            const shift_val = try zcu.int_value(Type.u8, c_bits - dest_bits);

            try writer.write_all("zig_shr_");
            try f.object.dg.render_type_for_builtin_fn_name(writer, scalar_ty);
            if (c_bits == 128) {
                try writer.print("(zig_bitCast_i{d}(", .{c_bits});
            } else {
                try writer.print("((int{d}_t)", .{c_bits});
            }
            try writer.print("zig_shl_u{d}(", .{c_bits});
            if (c_bits == 128) {
                try writer.print("zig_bitCast_u{d}(", .{c_bits});
            } else {
                try writer.print("(uint{d}_t)", .{c_bits});
            }
            try f.write_cvalue(writer, operand, .FunctionArgument);
            try v.elem(f, writer);
            if (c_bits == 128) try writer.write_byte(')');
            try writer.print(", {})", .{try f.fmt_int_literal(shift_val)});
            if (c_bits == 128) try writer.write_byte(')');
            try writer.print(", {})", .{try f.fmt_int_literal(shift_val)});
        },
    }
    if (need_lo) try writer.write_byte(')');
    try a.end(f, writer);
    try v.end(f, inst, writer);
    return local;
}

fn air_int_from_bool(f: *Function, inst: Air.Inst.Index) !CValue {
    const un_op = f.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const operand = try f.resolve_inst(un_op);
    try reap(f, inst, &.{un_op});
    const writer = f.object.writer();
    const inst_ty = f.type_of_index(inst);
    const local = try f.alloc_local(inst, inst_ty);
    const a = try Assignment.start(f, writer, try f.ctype_from_type(inst_ty, .complete));
    try f.write_cvalue(writer, local, .Other);
    try a.assign(f, writer);
    try f.write_cvalue(writer, operand, .Other);
    try a.end(f, writer);
    return local;
}

fn air_store(f: *Function, inst: Air.Inst.Index, safety: bool) !CValue {
    const zcu = f.object.dg.zcu;
    // *a = b;
    const bin_op = f.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;

    const ptr_ty = f.type_of(bin_op.lhs);
    const ptr_scalar_ty = ptr_ty.scalar_type(zcu);
    const ptr_info = ptr_scalar_ty.ptr_info(zcu);

    const ptr_val = try f.resolve_inst(bin_op.lhs);
    const src_ty = f.type_of(bin_op.rhs);

    const val_is_undef = if (try f.air.value(bin_op.rhs, zcu)) |v| v.is_undef_deep(zcu) else false;

    if (val_is_undef) {
        try reap(f, inst, &.{ bin_op.lhs, bin_op.rhs });
        if (safety and ptr_info.packed_offset.host_size == 0) {
            const writer = f.object.writer();
            try writer.write_all("memset(");
            try f.write_cvalue(writer, ptr_val, .FunctionArgument);
            try writer.write_all(", 0xaa, sizeof(");
            try f.render_type(writer, Type.from_interned(ptr_info.child));
            try writer.write_all("));\n");
        }
        return .none;
    }

    const is_aligned = if (ptr_info.flags.alignment != .none)
        ptr_info.flags.alignment.order(src_ty.abi_alignment(zcu)).compare(.gte)
    else
        true;
    const is_array = lowers_to_array(Type.from_interned(ptr_info.child), zcu);
    const need_memcpy = !is_aligned or is_array;

    const src_val = try f.resolve_inst(bin_op.rhs);
    try reap(f, inst, &.{ bin_op.lhs, bin_op.rhs });

    const src_scalar_ctype = try f.ctype_from_type(src_ty.scalar_type(zcu), .complete);
    const writer = f.object.writer();
    if (need_memcpy) {
        // For this memcpy to safely work we need the rhs to have the same
        // underlying type as the lhs (i.e. they must both be arrays of the same underlying type).
        assert(src_ty.eql(Type.from_interned(ptr_info.child), f.object.dg.zcu));

        // If the source is a constant, write_cvalue will emit a brace initialization
        // so work around this by initializing into new local.
        // TODO this should be done by manually initializing elements of the dest array
        const array_src = if (src_val == .constant) blk: {
            const new_local = try f.alloc_local(inst, src_ty);
            try f.write_cvalue(writer, new_local, .Other);
            try writer.write_all(" = ");
            try f.write_cvalue(writer, src_val, .Initializer);
            try writer.write_all(";\n");

            break :blk new_local;
        } else src_val;

        const v = try Vectorize.start(f, inst, writer, ptr_ty);
        try writer.write_all("memcpy((char *)");
        try f.write_cvalue(writer, ptr_val, .FunctionArgument);
        try v.elem(f, writer);
        try writer.write_all(", ");
        if (!is_array) try writer.write_byte('&');
        try f.write_cvalue(writer, array_src, .FunctionArgument);
        try v.elem(f, writer);
        try writer.write_all(", sizeof(");
        try f.render_type(writer, src_ty);
        try writer.write_all("))");
        try f.free_cvalue(inst, array_src);
        try writer.write_all(";\n");
        try v.end(f, inst, writer);
    } else if (ptr_info.packed_offset.host_size > 0 and ptr_info.flags.vector_index == .none) {
        const host_bits = ptr_info.packed_offset.host_size * 8;
        const host_ty = try zcu.int_type(.unsigned, host_bits);

        const bit_offset_ty = try zcu.int_type(.unsigned, Type.smallest_unsigned_bits(host_bits - 1));
        const bit_offset_val = try zcu.int_value(bit_offset_ty, ptr_info.packed_offset.bit_offset);

        const src_bits = src_ty.bit_size(zcu);

        const ExpectedContents = [BigInt.Managed.default_capacity]BigIntLimb;
        var stack align(@alignOf(ExpectedContents)) =
            std.heap.stack_fallback(@size_of(ExpectedContents), f.object.dg.gpa);

        var mask = try BigInt.Managed.init_capacity(stack.get(), BigInt.calc_twos_comp_limb_count(host_bits));
        defer mask.deinit();

        try mask.set_twos_comp_int_limit(.max, .unsigned, @as(usize, @int_cast(src_bits)));
        try mask.shift_left(&mask, ptr_info.packed_offset.bit_offset);
        try mask.bit_not_wrap(&mask, .unsigned, host_bits);

        const mask_val = try zcu.int_value_big(host_ty, mask.to_const());

        const v = try Vectorize.start(f, inst, writer, ptr_ty);
        const a = try Assignment.start(f, writer, src_scalar_ctype);
        try f.write_cvalue_deref(writer, ptr_val);
        try v.elem(f, writer);
        try a.assign(f, writer);
        try writer.write_all("zig_or_");
        try f.object.dg.render_type_for_builtin_fn_name(writer, host_ty);
        try writer.write_all("(zig_and_");
        try f.object.dg.render_type_for_builtin_fn_name(writer, host_ty);
        try writer.write_byte('(');
        try f.write_cvalue_deref(writer, ptr_val);
        try v.elem(f, writer);
        try writer.print(", {x}), zig_shl_", .{try f.fmt_int_literal(mask_val)});
        try f.object.dg.render_type_for_builtin_fn_name(writer, host_ty);
        try writer.write_byte('(');
        const cant_cast = host_ty.is_int(zcu) and host_ty.bit_size(zcu) > 64;
        if (cant_cast) {
            if (src_ty.bit_size(zcu) > 64) return f.fail("TODO: C backend: implement casting between types > 64 bits", .{});
            try writer.write_all("zig_make_");
            try f.object.dg.render_type_for_builtin_fn_name(writer, host_ty);
            try writer.write_all("(0, ");
        } else {
            try writer.write_byte('(');
            try f.render_type(writer, host_ty);
            try writer.write_byte(')');
        }

        if (src_ty.is_ptr_at_runtime(zcu)) {
            try writer.write_byte('(');
            try f.render_type(writer, Type.usize);
            try writer.write_byte(')');
        }
        try f.write_cvalue(writer, src_val, .Other);
        try v.elem(f, writer);
        if (cant_cast) try writer.write_byte(')');
        try writer.print(", {}))", .{try f.fmt_int_literal(bit_offset_val)});
        try a.end(f, writer);
        try v.end(f, inst, writer);
    } else {
        switch (ptr_val) {
            .local_ref => |ptr_local_index| switch (src_val) {
                .new_local, .local => |src_local_index| if (ptr_local_index == src_local_index)
                    return .none,
                else => {},
            },
            else => {},
        }
        const v = try Vectorize.start(f, inst, writer, ptr_ty);
        const a = try Assignment.start(f, writer, src_scalar_ctype);
        try f.write_cvalue_deref(writer, ptr_val);
        try v.elem(f, writer);
        try a.assign(f, writer);
        try f.write_cvalue(writer, src_val, .Other);
        try v.elem(f, writer);
        try a.end(f, writer);
        try v.end(f, inst, writer);
    }
    return .none;
}

fn air_overflow(f: *Function, inst: Air.Inst.Index, operation: []const u8, info: BuiltinInfo) !CValue {
    const zcu = f.object.dg.zcu;
    const ty_pl = f.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const bin_op = f.air.extra_data(Air.Bin, ty_pl.payload).data;

    const lhs = try f.resolve_inst(bin_op.lhs);
    const rhs = try f.resolve_inst(bin_op.rhs);
    try reap(f, inst, &.{ bin_op.lhs, bin_op.rhs });

    const inst_ty = f.type_of_index(inst);
    const operand_ty = f.type_of(bin_op.lhs);
    const scalar_ty = operand_ty.scalar_type(zcu);

    const w = f.object.writer();
    const local = try f.alloc_local(inst, inst_ty);
    const v = try Vectorize.start(f, inst, w, operand_ty);
    try f.write_cvalue_member(w, local, .{ .field = 1 });
    try v.elem(f, w);
    try w.write_all(" = zig_");
    try w.write_all(operation);
    try w.write_all("o_");
    try f.object.dg.render_type_for_builtin_fn_name(w, scalar_ty);
    try w.write_all("(&");
    try f.write_cvalue_member(w, local, .{ .field = 0 });
    try v.elem(f, w);
    try w.write_all(", ");
    try f.write_cvalue(w, lhs, .FunctionArgument);
    try v.elem(f, w);
    try w.write_all(", ");
    try f.write_cvalue(w, rhs, .FunctionArgument);
    try v.elem(f, w);
    try f.object.dg.render_builtin_info(w, scalar_ty, info);
    try w.write_all(");\n");
    try v.end(f, inst, w);

    return local;
}

fn air_not(f: *Function, inst: Air.Inst.Index) !CValue {
    const zcu = f.object.dg.zcu;
    const ty_op = f.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const operand_ty = f.type_of(ty_op.operand);
    const scalar_ty = operand_ty.scalar_type(zcu);
    if (scalar_ty.to_intern() != .bool_type) return try air_un_builtin_call(f, inst, ty_op.operand, "not", .bits);

    const op = try f.resolve_inst(ty_op.operand);
    try reap(f, inst, &.{ty_op.operand});

    const inst_ty = f.type_of_index(inst);

    const writer = f.object.writer();
    const local = try f.alloc_local(inst, inst_ty);
    const v = try Vectorize.start(f, inst, writer, operand_ty);
    try f.write_cvalue(writer, local, .Other);
    try v.elem(f, writer);
    try writer.write_all(" = ");
    try writer.write_byte('!');
    try f.write_cvalue(writer, op, .Other);
    try v.elem(f, writer);
    try writer.write_all(";\n");
    try v.end(f, inst, writer);

    return local;
}

fn air_bin_op(
    f: *Function,
    inst: Air.Inst.Index,
    operator: []const u8,
    operation: []const u8,
    info: BuiltinInfo,
) !CValue {
    const zcu = f.object.dg.zcu;
    const bin_op = f.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
    const operand_ty = f.type_of(bin_op.lhs);
    const scalar_ty = operand_ty.scalar_type(zcu);
    if ((scalar_ty.is_int(zcu) and scalar_ty.bit_size(zcu) > 64) or scalar_ty.is_runtime_float())
        return try air_bin_builtin_call(f, inst, operation, info);

    const lhs = try f.resolve_inst(bin_op.lhs);
    const rhs = try f.resolve_inst(bin_op.rhs);
    try reap(f, inst, &.{ bin_op.lhs, bin_op.rhs });

    const inst_ty = f.type_of_index(inst);

    const writer = f.object.writer();
    const local = try f.alloc_local(inst, inst_ty);
    const v = try Vectorize.start(f, inst, writer, operand_ty);
    try f.write_cvalue(writer, local, .Other);
    try v.elem(f, writer);
    try writer.write_all(" = ");
    try f.write_cvalue(writer, lhs, .Other);
    try v.elem(f, writer);
    try writer.write_byte(' ');
    try writer.write_all(operator);
    try writer.write_byte(' ');
    try f.write_cvalue(writer, rhs, .Other);
    try v.elem(f, writer);
    try writer.write_all(";\n");
    try v.end(f, inst, writer);

    return local;
}

fn air_cmp_op(
    f: *Function,
    inst: Air.Inst.Index,
    data: anytype,
    operator: std.math.CompareOperator,
) !CValue {
    const zcu = f.object.dg.zcu;
    const lhs_ty = f.type_of(data.lhs);
    const scalar_ty = lhs_ty.scalar_type(zcu);

    const scalar_bits = scalar_ty.bit_size(zcu);
    if (scalar_ty.is_int(zcu) and scalar_bits > 64)
        return air_cmp_builtin_call(
            f,
            inst,
            data,
            operator,
            .cmp,
            if (scalar_bits > 128) .bits else .none,
        );
    if (scalar_ty.is_runtime_float())
        return air_cmp_builtin_call(f, inst, data, operator, .operator, .none);

    const inst_ty = f.type_of_index(inst);
    const lhs = try f.resolve_inst(data.lhs);
    const rhs = try f.resolve_inst(data.rhs);
    try reap(f, inst, &.{ data.lhs, data.rhs });

    const rhs_ty = f.type_of(data.rhs);
    const need_cast = lhs_ty.is_single_pointer(zcu) or rhs_ty.is_single_pointer(zcu);
    const writer = f.object.writer();
    const local = try f.alloc_local(inst, inst_ty);
    const v = try Vectorize.start(f, inst, writer, lhs_ty);
    try f.write_cvalue(writer, local, .Other);
    try v.elem(f, writer);
    try writer.write_all(" = ");
    if (need_cast) try writer.write_all("(void*)");
    try f.write_cvalue(writer, lhs, .Other);
    try v.elem(f, writer);
    try writer.write_all(compare_operator_c(operator));
    if (need_cast) try writer.write_all("(void*)");
    try f.write_cvalue(writer, rhs, .Other);
    try v.elem(f, writer);
    try writer.write_all(";\n");
    try v.end(f, inst, writer);

    return local;
}

fn air_equality(
    f: *Function,
    inst: Air.Inst.Index,
    operator: std.math.CompareOperator,
) !CValue {
    const zcu = f.object.dg.zcu;
    const ctype_pool = &f.object.dg.ctype_pool;
    const bin_op = f.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;

    const operand_ty = f.type_of(bin_op.lhs);
    const operand_bits = operand_ty.bit_size(zcu);
    if (operand_ty.is_abi_int(zcu) and operand_bits > 64)
        return air_cmp_builtin_call(
            f,
            inst,
            bin_op,
            operator,
            .cmp,
            if (operand_bits > 128) .bits else .none,
        );
    if (operand_ty.is_runtime_float())
        return air_cmp_builtin_call(f, inst, bin_op, operator, .operator, .none);

    const lhs = try f.resolve_inst(bin_op.lhs);
    const rhs = try f.resolve_inst(bin_op.rhs);
    try reap(f, inst, &.{ bin_op.lhs, bin_op.rhs });

    const writer = f.object.writer();
    const local = try f.alloc_local(inst, Type.bool);
    const a = try Assignment.start(f, writer, CType.bool);
    try f.write_cvalue(writer, local, .Other);
    try a.assign(f, writer);

    const operand_ctype = try f.ctype_from_type(operand_ty, .complete);
    switch (operand_ctype.info(ctype_pool)) {
        .basic, .pointer => {
            try f.write_cvalue(writer, lhs, .Other);
            try writer.write_all(compare_operator_c(operator));
            try f.write_cvalue(writer, rhs, .Other);
        },
        .aligned, .array, .vector, .fwd_decl, .function => unreachable,
        .aggregate => |aggregate| if (aggregate.fields.len == 2 and
            (aggregate.fields.at(0, ctype_pool).name.index == .is_null or
            aggregate.fields.at(1, ctype_pool).name.index == .is_null))
        {
            try f.write_cvalue_member(writer, lhs, .{ .identifier = "is_null" });
            try writer.write_all(" || ");
            try f.write_cvalue_member(writer, rhs, .{ .identifier = "is_null" });
            try writer.write_all(" ? ");
            try f.write_cvalue_member(writer, lhs, .{ .identifier = "is_null" });
            try writer.write_all(compare_operator_c(operator));
            try f.write_cvalue_member(writer, rhs, .{ .identifier = "is_null" });
            try writer.write_all(" : ");
            try f.write_cvalue_member(writer, lhs, .{ .identifier = "payload" });
            try writer.write_all(compare_operator_c(operator));
            try f.write_cvalue_member(writer, rhs, .{ .identifier = "payload" });
        } else for (0..aggregate.fields.len) |field_index| {
            if (field_index > 0) try writer.write_all(switch (operator) {
                .lt, .lte, .gte, .gt => unreachable,
                .eq => " && ",
                .neq => " || ",
            });
            const field_name: CValue = .{
                .ctype_pool_string = aggregate.fields.at(field_index, ctype_pool).name,
            };
            try f.write_cvalue_member(writer, lhs, field_name);
            try writer.write_all(compare_operator_c(operator));
            try f.write_cvalue_member(writer, rhs, field_name);
        },
    }
    try a.end(f, writer);

    return local;
}

fn air_cmp_lt_errors_len(f: *Function, inst: Air.Inst.Index) !CValue {
    const un_op = f.air.instructions.items(.data)[@int_from_enum(inst)].un_op;

    const operand = try f.resolve_inst(un_op);
    try reap(f, inst, &.{un_op});

    const writer = f.object.writer();
    const local = try f.alloc_local(inst, Type.bool);
    try f.write_cvalue(writer, local, .Other);
    try writer.write_all(" = ");
    try f.write_cvalue(writer, operand, .Other);
    try writer.print(" < sizeof({ }) / sizeof(*{0 });\n", .{fmt_ident("zig_errorName")});
    return local;
}

fn air_ptr_add_sub(f: *Function, inst: Air.Inst.Index, operator: u8) !CValue {
    const zcu = f.object.dg.zcu;
    const ty_pl = f.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const bin_op = f.air.extra_data(Air.Bin, ty_pl.payload).data;

    const lhs = try f.resolve_inst(bin_op.lhs);
    const rhs = try f.resolve_inst(bin_op.rhs);
    try reap(f, inst, &.{ bin_op.lhs, bin_op.rhs });

    const inst_ty = f.type_of_index(inst);
    const inst_scalar_ty = inst_ty.scalar_type(zcu);
    const elem_ty = inst_scalar_ty.elem_type2(zcu);
    if (!elem_ty.has_runtime_bits_ignore_comptime(zcu)) return f.move_cvalue(inst, inst_ty, lhs);
    const inst_scalar_ctype = try f.ctype_from_type(inst_scalar_ty, .complete);

    const local = try f.alloc_local(inst, inst_ty);
    const writer = f.object.writer();
    const v = try Vectorize.start(f, inst, writer, inst_ty);
    const a = try Assignment.start(f, writer, inst_scalar_ctype);
    try f.write_cvalue(writer, local, .Other);
    try v.elem(f, writer);
    try a.assign(f, writer);
    // We must convert to and from integer types to prevent UB if the operation
    // results in a NULL pointer, or if LHS is NULL. The operation is only UB
    // if the result is NULL and then dereferenced.
    try writer.write_byte('(');
    try f.render_ctype(writer, inst_scalar_ctype);
    try writer.write_all(")(((uintptr_t)");
    try f.write_cvalue(writer, lhs, .Other);
    try v.elem(f, writer);
    try writer.write_all(") ");
    try writer.write_byte(operator);
    try writer.write_all(" (");
    try f.write_cvalue(writer, rhs, .Other);
    try v.elem(f, writer);
    try writer.write_all("*sizeof(");
    try f.render_type(writer, elem_ty);
    try writer.write_all(")))");
    try a.end(f, writer);
    try v.end(f, inst, writer);
    return local;
}

fn air_min_max(f: *Function, inst: Air.Inst.Index, operator: u8, operation: []const u8) !CValue {
    const zcu = f.object.dg.zcu;
    const bin_op = f.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;

    const inst_ty = f.type_of_index(inst);
    const inst_scalar_ty = inst_ty.scalar_type(zcu);

    if ((inst_scalar_ty.is_int(zcu) and inst_scalar_ty.bit_size(zcu) > 64) or inst_scalar_ty.is_runtime_float())
        return try air_bin_builtin_call(f, inst, operation, .none);

    const lhs = try f.resolve_inst(bin_op.lhs);
    const rhs = try f.resolve_inst(bin_op.rhs);
    try reap(f, inst, &.{ bin_op.lhs, bin_op.rhs });

    const writer = f.object.writer();
    const local = try f.alloc_local(inst, inst_ty);
    const v = try Vectorize.start(f, inst, writer, inst_ty);
    try f.write_cvalue(writer, local, .Other);
    try v.elem(f, writer);
    // (lhs <> rhs) ? lhs : rhs
    try writer.write_all(" = (");
    try f.write_cvalue(writer, lhs, .Other);
    try v.elem(f, writer);
    try writer.write_byte(' ');
    try writer.write_byte(operator);
    try writer.write_byte(' ');
    try f.write_cvalue(writer, rhs, .Other);
    try v.elem(f, writer);
    try writer.write_all(") ? ");
    try f.write_cvalue(writer, lhs, .Other);
    try v.elem(f, writer);
    try writer.write_all(" : ");
    try f.write_cvalue(writer, rhs, .Other);
    try v.elem(f, writer);
    try writer.write_all(";\n");
    try v.end(f, inst, writer);

    return local;
}

fn air_slice(f: *Function, inst: Air.Inst.Index) !CValue {
    const zcu = f.object.dg.zcu;
    const ty_pl = f.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const bin_op = f.air.extra_data(Air.Bin, ty_pl.payload).data;

    const ptr = try f.resolve_inst(bin_op.lhs);
    const len = try f.resolve_inst(bin_op.rhs);
    try reap(f, inst, &.{ bin_op.lhs, bin_op.rhs });

    const inst_ty = f.type_of_index(inst);
    const ptr_ty = inst_ty.slice_ptr_field_type(zcu);

    const writer = f.object.writer();
    const local = try f.alloc_local(inst, inst_ty);
    {
        const a = try Assignment.start(f, writer, try f.ctype_from_type(ptr_ty, .complete));
        try f.write_cvalue_member(writer, local, .{ .identifier = "ptr" });
        try a.assign(f, writer);
        try f.write_cvalue(writer, ptr, .Other);
        try a.end(f, writer);
    }
    {
        const a = try Assignment.start(f, writer, CType.usize);
        try f.write_cvalue_member(writer, local, .{ .identifier = "len" });
        try a.assign(f, writer);
        try f.write_cvalue(writer, len, .Initializer);
        try a.end(f, writer);
    }
    return local;
}

fn air_call(
    f: *Function,
    inst: Air.Inst.Index,
    modifier: std.builtin.CallModifier,
) !CValue {
    const zcu = f.object.dg.zcu;
    // Not even allowed to call panic in a naked function.
    if (f.object.dg.is_naked_fn) return .none;

    const gpa = f.object.dg.gpa;
    const writer = f.object.writer();

    const pl_op = f.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
    const extra = f.air.extra_data(Air.Call, pl_op.payload);
    const args = @as([]const Air.Inst.Ref, @ptr_cast(f.air.extra[extra.end..][0..extra.data.args_len]));

    const resolved_args = try gpa.alloc(CValue, args.len);
    defer gpa.free(resolved_args);
    for (resolved_args, args) |*resolved_arg, arg| {
        const arg_ty = f.type_of(arg);
        const arg_ctype = try f.ctype_from_type(arg_ty, .parameter);
        if (arg_ctype.index == .void) {
            resolved_arg.* = .none;
            continue;
        }
        resolved_arg.* = try f.resolve_inst(arg);
        if (!arg_ctype.eql(try f.ctype_from_type(arg_ty, .complete))) {
            const array_local = try f.alloc_aligned_local(inst, .{
                .ctype = arg_ctype,
                .alignas = CType.AlignAs.from_abi_alignment(arg_ty.abi_alignment(zcu)),
            });
            try writer.write_all("memcpy(");
            try f.write_cvalue_member(writer, array_local, .{ .identifier = "array" });
            try writer.write_all(", ");
            try f.write_cvalue(writer, resolved_arg.*, .FunctionArgument);
            try writer.write_all(", sizeof(");
            try f.render_ctype(writer, arg_ctype);
            try writer.write_all("));\n");
            resolved_arg.* = array_local;
        }
    }

    const callee = try f.resolve_inst(pl_op.operand);

    {
        var bt = iterate_big_tomb(f, inst);
        try bt.feed(pl_op.operand);
        for (args) |arg| try bt.feed(arg);
    }

    const callee_ty = f.type_of(pl_op.operand);
    const fn_info = zcu.type_to_func(switch (callee_ty.zig_type_tag(zcu)) {
        .Fn => callee_ty,
        .Pointer => callee_ty.child_type(zcu),
        else => unreachable,
    }).?;
    const ret_ty = Type.from_interned(fn_info.return_type);
    const ret_ctype: CType = if (ret_ty.is_no_return(zcu))
        CType.void
    else
        try f.ctype_from_type(ret_ty, .parameter);

    const result_local = result: {
        if (modifier == .always_tail) {
            try writer.write_all("zig_always_tail return ");
            break :result .none;
        } else if (ret_ctype.index == .void) {
            break :result .none;
        } else if (f.liveness.is_unused(inst)) {
            try writer.write_byte('(');
            try f.render_ctype(writer, CType.void);
            try writer.write_byte(')');
            break :result .none;
        } else {
            const local = try f.alloc_aligned_local(inst, .{
                .ctype = ret_ctype,
                .alignas = CType.AlignAs.from_abi_alignment(ret_ty.abi_alignment(zcu)),
            });
            try f.write_cvalue(writer, local, .Other);
            try writer.write_all(" = ");
            break :result local;
        }
    };

    callee: {
        known: {
            const fn_decl = fn_decl: {
                const callee_val = (try f.air.value(pl_op.operand, zcu)) orelse break :known;
                break :fn_decl switch (zcu.intern_pool.index_to_key(callee_val.to_intern())) {
                    .extern_func => |extern_func| extern_func.decl,
                    .func => |func| func.owner_decl,
                    .ptr => |ptr| if (ptr.byte_offset == 0) switch (ptr.base_addr) {
                        .decl => |decl| decl,
                        else => break :known,
                    } else break :known,
                    else => break :known,
                };
            };
            switch (modifier) {
                .auto, .always_tail => try f.object.dg.render_decl_name(writer, fn_decl, 0),
                inline .never_tail, .never_inline => |m| try writer.write_all(try f.get_lazy_fn_name(
                    @union_init(LazyFnKey, @tag_name(m), fn_decl),
                    @union_init(LazyFnValue.Data, @tag_name(m), {}),
                )),
                else => unreachable,
            }
            break :callee;
        }
        switch (modifier) {
            .auto, .always_tail => {},
            .never_tail => return f.fail("CBE: runtime callee with never_tail attribute unsupported", .{}),
            .never_inline => return f.fail("CBE: runtime callee with never_inline attribute unsupported", .{}),
            else => unreachable,
        }
        // Fall back to function pointer call.
        try f.write_cvalue(writer, callee, .Other);
    }

    try writer.write_byte('(');
    var need_comma = false;
    for (resolved_args) |resolved_arg| {
        if (resolved_arg == .none) continue;
        if (need_comma) try writer.write_all(", ");
        need_comma = true;
        try f.write_cvalue(writer, resolved_arg, .FunctionArgument);
        try f.free_cvalue(inst, resolved_arg);
    }
    try writer.write_all(");\n");

    const result = result: {
        if (result_local == .none or !lowers_to_array(ret_ty, zcu))
            break :result result_local;

        const array_local = try f.alloc_local(inst, ret_ty);
        try writer.write_all("memcpy(");
        try f.write_cvalue(writer, array_local, .FunctionArgument);
        try writer.write_all(", ");
        try f.write_cvalue_member(writer, result_local, .{ .identifier = "array" });
        try writer.write_all(", sizeof(");
        try f.render_type(writer, ret_ty);
        try writer.write_all("));\n");
        try free_local(f, inst, result_local.new_local, null);
        break :result array_local;
    };

    return result;
}

fn air_dbg_stmt(f: *Function, inst: Air.Inst.Index) !CValue {
    const dbg_stmt = f.air.instructions.items(.data)[@int_from_enum(inst)].dbg_stmt;
    const writer = f.object.writer();
    // TODO re-evaluate whether to emit these or not. If we naively emit
    // these directives, the output file will report bogus line numbers because
    // every newline after the #line directive adds one to the line.
    // We also don't print the filename yet, so the output is strictly unhelpful.
    // If we wanted to go this route, we would need to go all the way and not output
    // newlines until the next dbg_stmt occurs.
    // Perhaps an additional compilation option is in order?
    //try writer.print("#line {d}\n", .{dbg_stmt.line + 1});
    try writer.print("/* file:{d}:{d} */\n", .{ dbg_stmt.line + 1, dbg_stmt.column + 1 });
    return .none;
}

fn air_dbg_inline_block(f: *Function, inst: Air.Inst.Index) !CValue {
    const zcu = f.object.dg.zcu;
    const ty_pl = f.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = f.air.extra_data(Air.DbgInlineBlock, ty_pl.payload);
    const owner_decl = zcu.func_owner_decl_ptr(extra.data.func);
    const writer = f.object.writer();
    try writer.write_all("/* inline:");
    try owner_decl.render_fully_qualified_name(zcu, writer);
    try writer.write_all(" */\n");
    return lower_block(f, inst, @ptr_cast(f.air.extra[extra.end..][0..extra.data.body_len]));
}

fn air_dbg_var(f: *Function, inst: Air.Inst.Index) !CValue {
    const zcu = f.object.dg.zcu;
    const pl_op = f.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
    const name = f.air.null_terminated_string(pl_op.payload);
    const operand_is_undef = if (try f.air.value(pl_op.operand, zcu)) |v| v.is_undef_deep(zcu) else false;
    if (!operand_is_undef) _ = try f.resolve_inst(pl_op.operand);

    try reap(f, inst, &.{pl_op.operand});
    const writer = f.object.writer();
    try writer.print("/* var:{s} */\n", .{name});
    return .none;
}

fn air_block(f: *Function, inst: Air.Inst.Index) !CValue {
    const ty_pl = f.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = f.air.extra_data(Air.Block, ty_pl.payload);
    return lower_block(f, inst, @ptr_cast(f.air.extra[extra.end..][0..extra.data.body_len]));
}

fn lower_block(f: *Function, inst: Air.Inst.Index, body: []const Air.Inst.Index) !CValue {
    const zcu = f.object.dg.zcu;
    const liveness_block = f.liveness.get_block(inst);

    const block_id: usize = f.next_block_index;
    f.next_block_index += 1;
    const writer = f.object.writer();

    const inst_ty = f.type_of_index(inst);
    const result = if (inst_ty.has_runtime_bits_ignore_comptime(zcu) and !f.liveness.is_unused(inst))
        try f.alloc_local(inst, inst_ty)
    else
        .none;

    try f.blocks.put_no_clobber(f.object.dg.gpa, inst, .{
        .block_id = block_id,
        .result = result,
    });

    try gen_body_resolve_state(f, inst, &.{}, body, true);

    assert(f.blocks.remove(inst));

    // The body might result in some values we had beforehand being killed
    for (liveness_block.deaths) |death| {
        try die(f, inst, death.to_ref());
    }

    try f.object.indent_writer.insert_newline();

    // noreturn blocks have no `br` instructions reaching them, so we don't want a label
    if (!f.type_of_index(inst).is_no_return(zcu)) {
        // label must be followed by an expression, include an empty one.
        try writer.print("zig_block_{d}:;\n", .{block_id});
    }

    return result;
}

fn air_try(f: *Function, inst: Air.Inst.Index) !CValue {
    const pl_op = f.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
    const extra = f.air.extra_data(Air.Try, pl_op.payload);
    const body: []const Air.Inst.Index = @ptr_cast(f.air.extra[extra.end..][0..extra.data.body_len]);
    const err_union_ty = f.type_of(pl_op.operand);
    return lower_try(f, inst, pl_op.operand, body, err_union_ty, false);
}

fn air_try_ptr(f: *Function, inst: Air.Inst.Index) !CValue {
    const zcu = f.object.dg.zcu;
    const ty_pl = f.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = f.air.extra_data(Air.TryPtr, ty_pl.payload);
    const body: []const Air.Inst.Index = @ptr_cast(f.air.extra[extra.end..][0..extra.data.body_len]);
    const err_union_ty = f.type_of(extra.data.ptr).child_type(zcu);
    return lower_try(f, inst, extra.data.ptr, body, err_union_ty, true);
}

fn lower_try(
    f: *Function,
    inst: Air.Inst.Index,
    operand: Air.Inst.Ref,
    body: []const Air.Inst.Index,
    err_union_ty: Type,
    is_ptr: bool,
) !CValue {
    const zcu = f.object.dg.zcu;
    const err_union = try f.resolve_inst(operand);
    const inst_ty = f.type_of_index(inst);
    const liveness_condbr = f.liveness.get_cond_br(inst);
    const writer = f.object.writer();
    const payload_ty = err_union_ty.error_union_payload(zcu);
    const payload_has_bits = payload_ty.has_runtime_bits_ignore_comptime(zcu);

    if (!err_union_ty.error_union_set(zcu).error_set_is_empty(zcu)) {
        try writer.write_all("if (");
        if (!payload_has_bits) {
            if (is_ptr)
                try f.write_cvalue_deref(writer, err_union)
            else
                try f.write_cvalue(writer, err_union, .Other);
        } else {
            // Reap the operand so that it can be reused inside gen_body.
            // Remember we must avoid calling reap() twice for the same operand
            // in this function.
            try reap(f, inst, &.{operand});
            if (is_ptr)
                try f.write_cvalue_deref_member(writer, err_union, .{ .identifier = "error" })
            else
                try f.write_cvalue_member(writer, err_union, .{ .identifier = "error" });
        }
        try writer.write_all(") ");

        try gen_body_resolve_state(f, inst, liveness_condbr.else_deaths, body, false);
        try f.object.indent_writer.insert_newline();
    }

    // Now we have the "then branch" (in terms of the liveness data); process any deaths.
    for (liveness_condbr.then_deaths) |death| {
        try die(f, inst, death.to_ref());
    }

    if (!payload_has_bits) {
        if (!is_ptr) {
            return .none;
        } else {
            return err_union;
        }
    }

    try reap(f, inst, &.{operand});

    if (f.liveness.is_unused(inst)) {
        return .none;
    }

    const local = try f.alloc_local(inst, inst_ty);
    const a = try Assignment.start(f, writer, try f.ctype_from_type(inst_ty, .complete));
    try f.write_cvalue(writer, local, .Other);
    try a.assign(f, writer);
    if (is_ptr) {
        try writer.write_byte('&');
        try f.write_cvalue_deref_member(writer, err_union, .{ .identifier = "payload" });
    } else try f.write_cvalue_member(writer, err_union, .{ .identifier = "payload" });
    try a.end(f, writer);
    return local;
}

fn air_br(f: *Function, inst: Air.Inst.Index) !CValue {
    const branch = f.air.instructions.items(.data)[@int_from_enum(inst)].br;
    const block = f.blocks.get(branch.block_inst).?;
    const result = block.result;
    const writer = f.object.writer();

    // If result is .none then the value of the block is unused.
    if (result != .none) {
        const operand_ty = f.type_of(branch.operand);
        const operand = try f.resolve_inst(branch.operand);
        try reap(f, inst, &.{branch.operand});

        const a = try Assignment.start(f, writer, try f.ctype_from_type(operand_ty, .complete));
        try f.write_cvalue(writer, result, .Other);
        try a.assign(f, writer);
        try f.write_cvalue(writer, operand, .Other);
        try a.end(f, writer);
    }

    try writer.print("goto zig_block_{d};\n", .{block.block_id});
    return .none;
}

fn air_bitcast(f: *Function, inst: Air.Inst.Index) !CValue {
    const ty_op = f.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const inst_ty = f.type_of_index(inst);

    const operand = try f.resolve_inst(ty_op.operand);
    const operand_ty = f.type_of(ty_op.operand);

    const bitcasted = try bitcast(f, inst_ty, operand, operand_ty);
    try reap(f, inst, &.{ty_op.operand});
    return f.move_cvalue(inst, inst_ty, bitcasted);
}

fn bitcast(f: *Function, dest_ty: Type, operand: CValue, operand_ty: Type) !CValue {
    const zcu = f.object.dg.zcu;
    const target = &f.object.dg.mod.resolved_target.result;
    const ctype_pool = &f.object.dg.ctype_pool;
    const writer = f.object.writer();

    if (operand_ty.is_abi_int(zcu) and dest_ty.is_abi_int(zcu)) {
        const src_info = dest_ty.int_info(zcu);
        const dest_info = operand_ty.int_info(zcu);
        if (src_info.signedness == dest_info.signedness and
            src_info.bits == dest_info.bits) return operand;
    }

    if (dest_ty.is_ptr_at_runtime(zcu) and operand_ty.is_ptr_at_runtime(zcu)) {
        const local = try f.alloc_local(null, dest_ty);
        try f.write_cvalue(writer, local, .Other);
        try writer.write_all(" = (");
        try f.render_type(writer, dest_ty);
        try writer.write_byte(')');
        try f.write_cvalue(writer, operand, .Other);
        try writer.write_all(";\n");
        return local;
    }

    const operand_lval = if (operand == .constant) blk: {
        const operand_local = try f.alloc_local(null, operand_ty);
        try f.write_cvalue(writer, operand_local, .Other);
        if (operand_ty.is_abi_int(zcu)) {
            try writer.write_all(" = ");
        } else {
            try writer.write_all(" = (");
            try f.render_type(writer, operand_ty);
            try writer.write_byte(')');
        }
        try f.write_cvalue(writer, operand, .Initializer);
        try writer.write_all(";\n");
        break :blk operand_local;
    } else operand;

    const local = try f.alloc_local(null, dest_ty);
    try writer.write_all("memcpy(&");
    try f.write_cvalue(writer, local, .Other);
    try writer.write_all(", &");
    try f.write_cvalue(writer, operand_lval, .Other);
    try writer.write_all(", sizeof(");
    try f.render_type(
        writer,
        if (dest_ty.abi_size(zcu) <= operand_ty.abi_size(zcu)) dest_ty else operand_ty,
    );
    try writer.write_all("));\n");

    // Ensure padding bits have the expected value.
    if (dest_ty.is_abi_int(zcu)) {
        const dest_ctype = try f.ctype_from_type(dest_ty, .complete);
        const dest_info = dest_ty.int_info(zcu);
        var bits: u16 = dest_info.bits;
        var wrap_ctype: ?CType = null;
        var need_bitcasts = false;

        try f.write_cvalue(writer, local, .Other);
        switch (dest_ctype.info(ctype_pool)) {
            else => {},
            .array => |array_info| {
                try writer.print("[{d}]", .{switch (target.cpu.arch.endian()) {
                    .little => array_info.len - 1,
                    .big => 0,
                }});
                wrap_ctype = array_info.elem_ctype.to_signedness(dest_info.signedness);
                need_bitcasts = wrap_ctype.?.index == .zig_i128;
                bits -= 1;
                bits %= @as(u16, @int_cast(f.byte_size(array_info.elem_ctype) * 8));
                bits += 1;
            },
        }
        try writer.write_all(" = ");
        if (need_bitcasts) {
            try writer.write_all("zig_bitCast_");
            try f.object.dg.render_ctype_for_builtin_fn_name(writer, wrap_ctype.?.to_unsigned());
            try writer.write_byte('(');
        }
        try writer.write_all("zig_wrap_");
        const info_ty = try zcu.int_type(dest_info.signedness, bits);
        if (wrap_ctype) |ctype|
            try f.object.dg.render_ctype_for_builtin_fn_name(writer, ctype)
        else
            try f.object.dg.render_type_for_builtin_fn_name(writer, info_ty);
        try writer.write_byte('(');
        if (need_bitcasts) {
            try writer.write_all("zig_bitCast_");
            try f.object.dg.render_ctype_for_builtin_fn_name(writer, wrap_ctype.?);
            try writer.write_byte('(');
        }
        try f.write_cvalue(writer, local, .Other);
        switch (dest_ctype.info(ctype_pool)) {
            else => {},
            .array => |array_info| try writer.print("[{d}]", .{
                switch (target.cpu.arch.endian()) {
                    .little => array_info.len - 1,
                    .big => 0,
                },
            }),
        }
        if (need_bitcasts) try writer.write_byte(')');
        try f.object.dg.render_builtin_info(writer, info_ty, .bits);
        if (need_bitcasts) try writer.write_byte(')');
        try writer.write_all(");\n");
    }

    try f.free_cvalue(null, operand_lval);
    return local;
}

fn air_trap(f: *Function, writer: anytype) !CValue {
    // Not even allowed to call trap in a naked function.
    if (f.object.dg.is_naked_fn) return .none;

    try writer.write_all("zig_trap();\n");
    return .none;
}

fn air_breakpoint(writer: anytype) !CValue {
    try writer.write_all("zig_breakpoint();\n");
    return .none;
}

fn air_ret_addr(f: *Function, inst: Air.Inst.Index) !CValue {
    const writer = f.object.writer();
    const local = try f.alloc_local(inst, Type.usize);
    try f.write_cvalue(writer, local, .Other);
    try writer.write_all(" = (");
    try f.render_type(writer, Type.usize);
    try writer.write_all(")zig_return_address();\n");
    return local;
}

fn air_frame_address(f: *Function, inst: Air.Inst.Index) !CValue {
    const writer = f.object.writer();
    const local = try f.alloc_local(inst, Type.usize);
    try f.write_cvalue(writer, local, .Other);
    try writer.write_all(" = (");
    try f.render_type(writer, Type.usize);
    try writer.write_all(")zig_frame_address();\n");
    return local;
}

fn air_fence(f: *Function, inst: Air.Inst.Index) !CValue {
    const atomic_order = f.air.instructions.items(.data)[@int_from_enum(inst)].fence;
    const writer = f.object.writer();

    try writer.write_all("zig_fence(");
    try write_memory_order(writer, atomic_order);
    try writer.write_all(");\n");

    return .none;
}

fn air_unreach(f: *Function) !CValue {
    // Not even allowed to call unreachable in a naked function.
    if (f.object.dg.is_naked_fn) return .none;

    try f.object.writer().write_all("zig_unreachable();\n");
    return .none;
}

fn air_loop(f: *Function, inst: Air.Inst.Index) !CValue {
    const ty_pl = f.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const loop = f.air.extra_data(Air.Block, ty_pl.payload);
    const body: []const Air.Inst.Index = @ptr_cast(f.air.extra[loop.end..][0..loop.data.body_len]);
    const writer = f.object.writer();

    try writer.write_all("for (;;) ");
    try gen_body(f, body); // no need to restore state, we're noreturn
    try writer.write_byte('\n');

    return .none;
}

fn air_cond_br(f: *Function, inst: Air.Inst.Index) !CValue {
    const pl_op = f.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
    const cond = try f.resolve_inst(pl_op.operand);
    try reap(f, inst, &.{pl_op.operand});
    const extra = f.air.extra_data(Air.CondBr, pl_op.payload);
    const then_body: []const Air.Inst.Index = @ptr_cast(f.air.extra[extra.end..][0..extra.data.then_body_len]);
    const else_body: []const Air.Inst.Index = @ptr_cast(f.air.extra[extra.end + then_body.len ..][0..extra.data.else_body_len]);
    const liveness_condbr = f.liveness.get_cond_br(inst);
    const writer = f.object.writer();

    try writer.write_all("if (");
    try f.write_cvalue(writer, cond, .Other);
    try writer.write_all(") ");

    try gen_body_resolve_state(f, inst, liveness_condbr.then_deaths, then_body, false);
    try writer.write_byte('\n');

    // We don't need to use `gen_body_resolve_state` for the else block, because this instruction is
    // noreturn so must terminate a body, therefore we don't need to leave `value_map` or
    // `free_locals_map` well defined (our parent is responsible for doing that).

    for (liveness_condbr.else_deaths) |death| {
        try die(f, inst, death.to_ref());
    }

    // We never actually need an else block, because our branches are noreturn so must (for
    // instance) `br` to a block (label).

    try gen_body_inner(f, else_body);

    return .none;
}

fn air_switch_br(f: *Function, inst: Air.Inst.Index) !CValue {
    const zcu = f.object.dg.zcu;
    const pl_op = f.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
    const condition = try f.resolve_inst(pl_op.operand);
    try reap(f, inst, &.{pl_op.operand});
    const condition_ty = f.type_of(pl_op.operand);
    const switch_br = f.air.extra_data(Air.SwitchBr, pl_op.payload);
    const writer = f.object.writer();

    try writer.write_all("switch (");

    const lowered_condition_ty = if (condition_ty.to_intern() == .bool_type)
        Type.u1
    else if (condition_ty.is_ptr_at_runtime(zcu))
        Type.usize
    else
        condition_ty;
    if (condition_ty.to_intern() != lowered_condition_ty.to_intern()) {
        try writer.write_byte('(');
        try f.render_type(writer, lowered_condition_ty);
        try writer.write_byte(')');
    }
    try f.write_cvalue(writer, condition, .Other);
    try writer.write_all(") {");
    f.object.indent_writer.push_indent();

    const gpa = f.object.dg.gpa;
    const liveness = try f.liveness.get_switch_br(gpa, inst, switch_br.data.cases_len + 1);
    defer gpa.free(liveness.deaths);

    // On the final iteration we do not need to fix any state. This is because, like in the `else`
    // branch of a `cond_br`, our parent has to do it for this entire body anyway.
    const last_case_i = switch_br.data.cases_len - @int_from_bool(switch_br.data.else_body_len == 0);

    var extra_index: usize = switch_br.end;
    for (0..switch_br.data.cases_len) |case_i| {
        const case = f.air.extra_data(Air.SwitchBr.Case, extra_index);
        const items = @as([]const Air.Inst.Ref, @ptr_cast(f.air.extra[case.end..][0..case.data.items_len]));
        const case_body: []const Air.Inst.Index =
            @ptr_cast(f.air.extra[case.end + items.len ..][0..case.data.body_len]);
        extra_index = case.end + case.data.items_len + case_body.len;

        for (items) |item| {
            try f.object.indent_writer.insert_newline();
            try writer.write_all("case ");
            const item_value = try f.air.value(item, zcu);
            if (item_value.?.get_unsigned_int(zcu)) |item_int| try writer.print("{}\n", .{
                try f.fmt_int_literal(try zcu.int_value(lowered_condition_ty, item_int)),
            }) else {
                if (condition_ty.is_ptr_at_runtime(zcu)) {
                    try writer.write_byte('(');
                    try f.render_type(writer, Type.usize);
                    try writer.write_byte(')');
                }
                try f.object.dg.render_value(writer, (try f.air.value(item, zcu)).?, .Other);
            }
            try writer.write_byte(':');
        }
        try writer.write_byte(' ');

        if (case_i != last_case_i) {
            try gen_body_resolve_state(f, inst, liveness.deaths[case_i], case_body, false);
        } else {
            for (liveness.deaths[case_i]) |death| {
                try die(f, inst, death.to_ref());
            }
            try gen_body(f, case_body);
        }

        // The case body must be noreturn so we don't need to insert a break.
    }

    const else_body: []const Air.Inst.Index = @ptr_cast(f.air.extra[extra_index..][0..switch_br.data.else_body_len]);
    try f.object.indent_writer.insert_newline();
    if (else_body.len > 0) {
        // Note that this must be the last case (i.e. the `last_case_i` case was not hit above)
        for (liveness.deaths[liveness.deaths.len - 1]) |death| {
            try die(f, inst, death.to_ref());
        }
        try writer.write_all("default: ");
        try gen_body(f, else_body);
    } else {
        try writer.write_all("default: zig_unreachable();");
    }
    try f.object.indent_writer.insert_newline();

    f.object.indent_writer.pop_indent();
    try writer.write_all("}\n");
    return .none;
}

fn asm_input_needs_local(f: *Function, constraint: []const u8, value: CValue) bool {
    const target = &f.object.dg.mod.resolved_target.result;
    return switch (constraint[0]) {
        '{' => true,
        'i', 'r' => false,
        'I' => !target.cpu.arch.is_arm_or_thumb(),
        else => switch (value) {
            .constant => |val| switch (f.object.dg.zcu.intern_pool.index_to_key(val.to_intern())) {
                .ptr => |ptr| if (ptr.byte_offset == 0) switch (ptr.base_addr) {
                    .decl => false,
                    else => true,
                } else true,
                else => true,
            },
            else => false,
        },
    };
}

fn air_asm(f: *Function, inst: Air.Inst.Index) !CValue {
    const zcu = f.object.dg.zcu;
    const ty_pl = f.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = f.air.extra_data(Air.Asm, ty_pl.payload);
    const is_volatile = @as(u1, @truncate(extra.data.flags >> 31)) != 0;
    const clobbers_len = @as(u31, @truncate(extra.data.flags));
    const gpa = f.object.dg.gpa;
    var extra_i: usize = extra.end;
    const outputs = @as([]const Air.Inst.Ref, @ptr_cast(f.air.extra[extra_i..][0..extra.data.outputs_len]));
    extra_i += outputs.len;
    const inputs = @as([]const Air.Inst.Ref, @ptr_cast(f.air.extra[extra_i..][0..extra.data.inputs_len]));
    extra_i += inputs.len;

    const result = result: {
        const writer = f.object.writer();
        const inst_ty = f.type_of_index(inst);
        const inst_local = if (inst_ty.has_runtime_bits_ignore_comptime(zcu)) local: {
            const inst_local = try f.alloc_local_value(.{
                .ctype = try f.ctype_from_type(inst_ty, .complete),
                .alignas = CType.AlignAs.from_abi_alignment(inst_ty.abi_alignment(zcu)),
            });
            if (f.want_safety()) {
                try f.write_cvalue(writer, inst_local, .Other);
                try writer.write_all(" = ");
                try f.write_cvalue(writer, .{ .undef = inst_ty }, .Other);
                try writer.write_all(";\n");
            }
            break :local inst_local;
        } else .none;

        const locals_begin = @as(LocalIndex, @int_cast(f.locals.items.len));
        const constraints_extra_begin = extra_i;
        for (outputs) |output| {
            const extra_bytes = mem.slice_as_bytes(f.air.extra[extra_i..]);
            const constraint = mem.slice_to(extra_bytes, 0);
            const name = mem.slice_to(extra_bytes[constraint.len + 1 ..], 0);
            // This equation accounts for the fact that even if we have exactly 4 bytes
            // for the string, we still use the next u32 for the null terminator.
            extra_i += (constraint.len + name.len + (2 + 3)) / 4;

            if (constraint.len < 2 or constraint[0] != '=' or
                (constraint[1] == '{' and constraint[constraint.len - 1] != '}'))
            {
                return f.fail("CBE: constraint not supported: '{s}'", .{constraint});
            }

            const is_reg = constraint[1] == '{';
            if (is_reg) {
                const output_ty = if (output == .none) inst_ty else f.type_of(output).child_type(zcu);
                try writer.write_all("register ");
                const output_local = try f.alloc_local_value(.{
                    .ctype = try f.ctype_from_type(output_ty, .complete),
                    .alignas = CType.AlignAs.from_abi_alignment(output_ty.abi_alignment(zcu)),
                });
                try f.allocs.put(gpa, output_local.new_local, false);
                try f.object.dg.render_type_and_name(writer, output_ty, output_local, .{}, .none, .complete);
                try writer.write_all(" __asm(\"");
                try writer.write_all(constraint["={".len .. constraint.len - "}".len]);
                try writer.write_all("\")");
                if (f.want_safety()) {
                    try writer.write_all(" = ");
                    try f.write_cvalue(writer, .{ .undef = output_ty }, .Other);
                }
                try writer.write_all(";\n");
            }
        }
        for (inputs) |input| {
            const extra_bytes = mem.slice_as_bytes(f.air.extra[extra_i..]);
            const constraint = mem.slice_to(extra_bytes, 0);
            const name = mem.slice_to(extra_bytes[constraint.len + 1 ..], 0);
            // This equation accounts for the fact that even if we have exactly 4 bytes
            // for the string, we still use the next u32 for the null terminator.
            extra_i += (constraint.len + name.len + (2 + 3)) / 4;

            if (constraint.len < 1 or mem.index_of_scalar(u8, "=+&%", constraint[0]) != null or
                (constraint[0] == '{' and constraint[constraint.len - 1] != '}'))
            {
                return f.fail("CBE: constraint not supported: '{s}'", .{constraint});
            }

            const is_reg = constraint[0] == '{';
            const input_val = try f.resolve_inst(input);
            if (asm_input_needs_local(f, constraint, input_val)) {
                const input_ty = f.type_of(input);
                if (is_reg) try writer.write_all("register ");
                const input_local = try f.alloc_local_value(.{
                    .ctype = try f.ctype_from_type(input_ty, .complete),
                    .alignas = CType.AlignAs.from_abi_alignment(input_ty.abi_alignment(zcu)),
                });
                try f.allocs.put(gpa, input_local.new_local, false);
                try f.object.dg.render_type_and_name(writer, input_ty, input_local, Const, .none, .complete);
                if (is_reg) {
                    try writer.write_all(" __asm(\"");
                    try writer.write_all(constraint["{".len .. constraint.len - "}".len]);
                    try writer.write_all("\")");
                }
                try writer.write_all(" = ");
                try f.write_cvalue(writer, input_val, .Other);
                try writer.write_all(";\n");
            }
        }
        for (0..clobbers_len) |_| {
            const clobber = mem.slice_to(mem.slice_as_bytes(f.air.extra[extra_i..]), 0);
            // This equation accounts for the fact that even if we have exactly 4 bytes
            // for the string, we still use the next u32 for the null terminator.
            extra_i += clobber.len / 4 + 1;
        }

        {
            const asm_source = mem.slice_as_bytes(f.air.extra[extra_i..])[0..extra.data.source_len];

            var stack = std.heap.stack_fallback(256, f.object.dg.gpa);
            const allocator = stack.get();
            const fixed_asm_source = try allocator.alloc(u8, asm_source.len);
            defer allocator.free(fixed_asm_source);

            var src_i: usize = 0;
            var dst_i: usize = 0;
            while (true) {
                const literal = mem.slice_to(asm_source[src_i..], '%');
                src_i += literal.len;

                @memcpy(fixed_asm_source[dst_i..][0..literal.len], literal);
                dst_i += literal.len;

                if (src_i >= asm_source.len) break;

                src_i += 1;
                if (src_i >= asm_source.len)
                    return f.fail("CBE: invalid inline asm string '{s}'", .{asm_source});

                fixed_asm_source[dst_i] = '%';
                dst_i += 1;

                if (asm_source[src_i] != '[') {
                    // This also handles %%
                    fixed_asm_source[dst_i] = asm_source[src_i];
                    src_i += 1;
                    dst_i += 1;
                    continue;
                }

                const desc = mem.slice_to(asm_source[src_i..], ']');
                if (mem.index_of_scalar(u8, desc, ':')) |colon| {
                    const name = desc[0..colon];
                    const modifier = desc[colon + 1 ..];

                    @memcpy(fixed_asm_source[dst_i..][0..modifier.len], modifier);
                    dst_i += modifier.len;
                    @memcpy(fixed_asm_source[dst_i..][0..name.len], name);
                    dst_i += name.len;

                    src_i += desc.len;
                    if (src_i >= asm_source.len)
                        return f.fail("CBE: invalid inline asm string '{s}'", .{asm_source});
                }
            }

            try writer.write_all("__asm");
            if (is_volatile) try writer.write_all(" volatile");
            try writer.print("({s}", .{fmt_string_literal(fixed_asm_source[0..dst_i], null)});
        }

        extra_i = constraints_extra_begin;
        var locals_index = locals_begin;
        try writer.write_byte(':');
        for (outputs, 0..) |output, index| {
            const extra_bytes = mem.slice_as_bytes(f.air.extra[extra_i..]);
            const constraint = mem.slice_to(extra_bytes, 0);
            const name = mem.slice_to(extra_bytes[constraint.len + 1 ..], 0);
            // This equation accounts for the fact that even if we have exactly 4 bytes
            // for the string, we still use the next u32 for the null terminator.
            extra_i += (constraint.len + name.len + (2 + 3)) / 4;

            if (index > 0) try writer.write_byte(',');
            try writer.write_byte(' ');
            if (!mem.eql(u8, name, "_")) try writer.print("[{s}]", .{name});
            const is_reg = constraint[1] == '{';
            try writer.print("{s}(", .{fmt_string_literal(if (is_reg) "=r" else constraint, null)});
            if (is_reg) {
                try f.write_cvalue(writer, .{ .local = locals_index }, .Other);
                locals_index += 1;
            } else if (output == .none) {
                try f.write_cvalue(writer, inst_local, .FunctionArgument);
            } else {
                try f.write_cvalue_deref(writer, try f.resolve_inst(output));
            }
            try writer.write_byte(')');
        }
        try writer.write_byte(':');
        for (inputs, 0..) |input, index| {
            const extra_bytes = mem.slice_as_bytes(f.air.extra[extra_i..]);
            const constraint = mem.slice_to(extra_bytes, 0);
            const name = mem.slice_to(extra_bytes[constraint.len + 1 ..], 0);
            // This equation accounts for the fact that even if we have exactly 4 bytes
            // for the string, we still use the next u32 for the null terminator.
            extra_i += (constraint.len + name.len + (2 + 3)) / 4;

            if (index > 0) try writer.write_byte(',');
            try writer.write_byte(' ');
            if (!mem.eql(u8, name, "_")) try writer.print("[{s}]", .{name});

            const is_reg = constraint[0] == '{';
            const input_val = try f.resolve_inst(input);
            try writer.print("{s}(", .{fmt_string_literal(if (is_reg) "r" else constraint, null)});
            try f.write_cvalue(writer, if (asm_input_needs_local(f, constraint, input_val)) local: {
                const input_local = .{ .local = locals_index };
                locals_index += 1;
                break :local input_local;
            } else input_val, .Other);
            try writer.write_byte(')');
        }
        try writer.write_byte(':');
        for (0..clobbers_len) |clobber_i| {
            const clobber = mem.slice_to(mem.slice_as_bytes(f.air.extra[extra_i..]), 0);
            // This equation accounts for the fact that even if we have exactly 4 bytes
            // for the string, we still use the next u32 for the null terminator.
            extra_i += clobber.len / 4 + 1;

            if (clobber.len == 0) continue;

            if (clobber_i > 0) try writer.write_byte(',');
            try writer.print(" {s}", .{fmt_string_literal(clobber, null)});
        }
        try writer.write_all(");\n");

        extra_i = constraints_extra_begin;
        locals_index = locals_begin;
        for (outputs) |output| {
            const extra_bytes = mem.slice_as_bytes(f.air.extra[extra_i..]);
            const constraint = mem.slice_to(extra_bytes, 0);
            const name = mem.slice_to(extra_bytes[constraint.len + 1 ..], 0);
            // This equation accounts for the fact that even if we have exactly 4 bytes
            // for the string, we still use the next u32 for the null terminator.
            extra_i += (constraint.len + name.len + (2 + 3)) / 4;

            const is_reg = constraint[1] == '{';
            if (is_reg) {
                try f.write_cvalue_deref(writer, if (output == .none)
                    .{ .local_ref = inst_local.new_local }
                else
                    try f.resolve_inst(output));
                try writer.write_all(" = ");
                try f.write_cvalue(writer, .{ .local = locals_index }, .Other);
                locals_index += 1;
                try writer.write_all(";\n");
            }
        }

        break :result if (f.liveness.is_unused(inst)) .none else inst_local;
    };

    var bt = iterate_big_tomb(f, inst);
    for (outputs) |output| {
        if (output == .none) continue;
        try bt.feed(output);
    }
    for (inputs) |input| {
        try bt.feed(input);
    }

    return result;
}

fn air_is_null(
    f: *Function,
    inst: Air.Inst.Index,
    operator: std.math.CompareOperator,
    is_ptr: bool,
) !CValue {
    const zcu = f.object.dg.zcu;
    const ctype_pool = &f.object.dg.ctype_pool;
    const un_op = f.air.instructions.items(.data)[@int_from_enum(inst)].un_op;

    const writer = f.object.writer();
    const operand = try f.resolve_inst(un_op);
    try reap(f, inst, &.{un_op});

    const local = try f.alloc_local(inst, Type.bool);
    const a = try Assignment.start(f, writer, CType.bool);
    try f.write_cvalue(writer, local, .Other);
    try a.assign(f, writer);

    const operand_ty = f.type_of(un_op);
    const optional_ty = if (is_ptr) operand_ty.child_type(zcu) else operand_ty;
    const opt_ctype = try f.ctype_from_type(optional_ty, .complete);
    const rhs = switch (opt_ctype.info(ctype_pool)) {
        .basic, .pointer => rhs: {
            if (is_ptr)
                try f.write_cvalue_deref(writer, operand)
            else
                try f.write_cvalue(writer, operand, .Other);
            break :rhs if (opt_ctype.is_bool())
                "true"
            else if (opt_ctype.is_integer())
                "0"
            else
                "NULL";
        },
        .aligned, .array, .vector, .fwd_decl, .function => unreachable,
        .aggregate => |aggregate| switch (aggregate.fields.at(0, ctype_pool).name.index) {
            .is_null, .payload => rhs: {
                if (is_ptr)
                    try f.write_cvalue_deref_member(writer, operand, .{ .identifier = "is_null" })
                else
                    try f.write_cvalue_member(writer, operand, .{ .identifier = "is_null" });
                break :rhs "true";
            },
            .ptr, .len => rhs: {
                if (is_ptr)
                    try f.write_cvalue_deref_member(writer, operand, .{ .identifier = "ptr" })
                else
                    try f.write_cvalue_member(writer, operand, .{ .identifier = "ptr" });
                break :rhs "NULL";
            },
            else => unreachable,
        },
    };
    try writer.write_all(compare_operator_c(operator));
    try writer.write_all(rhs);
    try a.end(f, writer);
    return local;
}

fn air_optional_payload(f: *Function, inst: Air.Inst.Index, is_ptr: bool) !CValue {
    const zcu = f.object.dg.zcu;
    const ctype_pool = &f.object.dg.ctype_pool;
    const ty_op = f.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

    const inst_ty = f.type_of_index(inst);
    const operand_ty = f.type_of(ty_op.operand);
    const opt_ty = if (is_ptr) operand_ty.child_type(zcu) else operand_ty;
    const opt_ctype = try f.ctype_from_type(opt_ty, .complete);
    if (opt_ctype.is_bool()) return if (is_ptr) .{ .undef = inst_ty } else .none;

    const operand = try f.resolve_inst(ty_op.operand);
    switch (opt_ctype.info(ctype_pool)) {
        .basic, .pointer => return f.move_cvalue(inst, inst_ty, operand),
        .aligned, .array, .vector, .fwd_decl, .function => unreachable,
        .aggregate => |aggregate| switch (aggregate.fields.at(0, ctype_pool).name.index) {
            .is_null, .payload => {
                const writer = f.object.writer();
                const local = try f.alloc_local(inst, inst_ty);
                const a = try Assignment.start(f, writer, try f.ctype_from_type(inst_ty, .complete));
                try f.write_cvalue(writer, local, .Other);
                try a.assign(f, writer);
                if (is_ptr) {
                    try writer.write_byte('&');
                    try f.write_cvalue_deref_member(writer, operand, .{ .identifier = "payload" });
                } else try f.write_cvalue_member(writer, operand, .{ .identifier = "payload" });
                try a.end(f, writer);
                return local;
            },
            .ptr, .len => return f.move_cvalue(inst, inst_ty, operand),
            else => unreachable,
        },
    }
}

fn air_optional_payload_ptr_set(f: *Function, inst: Air.Inst.Index) !CValue {
    const zcu = f.object.dg.zcu;
    const ty_op = f.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const writer = f.object.writer();
    const operand = try f.resolve_inst(ty_op.operand);
    try reap(f, inst, &.{ty_op.operand});
    const operand_ty = f.type_of(ty_op.operand);

    const inst_ty = f.type_of_index(inst);
    const opt_ctype = try f.ctype_from_type(operand_ty.child_type(zcu), .complete);
    switch (opt_ctype.info(&f.object.dg.ctype_pool)) {
        .basic => {
            const a = try Assignment.start(f, writer, opt_ctype);
            try f.write_cvalue_deref(writer, operand);
            try a.assign(f, writer);
            try f.object.dg.render_value(writer, Value.false, .Initializer);
            try a.end(f, writer);
            return .none;
        },
        .pointer => {
            if (f.liveness.is_unused(inst)) return .none;
            const local = try f.alloc_local(inst, inst_ty);
            const a = try Assignment.start(f, writer, opt_ctype);
            try f.write_cvalue(writer, local, .Other);
            try a.assign(f, writer);
            try f.write_cvalue(writer, operand, .Other);
            try a.end(f, writer);
            return local;
        },
        .aligned, .array, .vector, .fwd_decl, .function => unreachable,
        .aggregate => {
            {
                const a = try Assignment.start(f, writer, opt_ctype);
                try f.write_cvalue_deref_member(writer, operand, .{ .identifier = "is_null" });
                try a.assign(f, writer);
                try f.object.dg.render_value(writer, Value.false, .Initializer);
                try a.end(f, writer);
            }
            if (f.liveness.is_unused(inst)) return .none;
            const local = try f.alloc_local(inst, inst_ty);
            const a = try Assignment.start(f, writer, opt_ctype);
            try f.write_cvalue(writer, local, .Other);
            try a.assign(f, writer);
            try writer.write_byte('&');
            try f.write_cvalue_deref_member(writer, operand, .{ .identifier = "payload" });
            try a.end(f, writer);
            return local;
        },
    }
}

fn field_location(
    container_ptr_ty: Type,
    field_ptr_ty: Type,
    field_index: u32,
    zcu: *Zcu,
) union(enum) {
    begin: void,
    field: CValue,
    byte_offset: u64,
} {
    const ip = &zcu.intern_pool;
    const container_ty = Type.from_interned(ip.index_to_key(container_ptr_ty.to_intern()).ptr_type.child);
    switch (ip.index_to_key(container_ty.to_intern())) {
        .struct_type => {
            const loaded_struct = ip.load_struct_type(container_ty.to_intern());
            return switch (loaded_struct.layout) {
                .auto, .@"extern" => if (!container_ty.has_runtime_bits_ignore_comptime(zcu))
                    .begin
                else if (!field_ptr_ty.child_type(zcu).has_runtime_bits_ignore_comptime(zcu))
                    .{ .byte_offset = loaded_struct.offsets.get(ip)[field_index] }
                else
                    .{ .field = if (loaded_struct.field_name(ip, field_index).unwrap()) |field_name|
                        .{ .identifier = field_name.to_slice(ip) }
                    else
                        .{ .field = field_index } },
                .@"packed" => if (field_ptr_ty.ptr_info(zcu).packed_offset.host_size == 0)
                    .{ .byte_offset = @div_exact(zcu.struct_packed_field_bit_offset(loaded_struct, field_index) +
                        container_ptr_ty.ptr_info(zcu).packed_offset.bit_offset, 8) }
                else
                    .begin,
            };
        },
        .anon_struct_type => |anon_struct_info| return if (!container_ty.has_runtime_bits_ignore_comptime(zcu))
            .begin
        else if (!field_ptr_ty.child_type(zcu).has_runtime_bits_ignore_comptime(zcu))
            .{ .byte_offset = container_ty.struct_field_offset(field_index, zcu) }
        else
            .{ .field = if (anon_struct_info.field_name(ip, field_index).unwrap()) |field_name|
                .{ .identifier = field_name.to_slice(ip) }
            else
                .{ .field = field_index } },
        .union_type => {
            const loaded_union = ip.load_union_type(container_ty.to_intern());
            switch (loaded_union.get_layout(ip)) {
                .auto, .@"extern" => {
                    const field_ty = Type.from_interned(loaded_union.field_types.get(ip)[field_index]);
                    if (!field_ty.has_runtime_bits_ignore_comptime(zcu))
                        return if (loaded_union.has_tag(ip) and !container_ty.union_has_all_zero_bit_field_types(zcu))
                            .{ .field = .{ .identifier = "payload" } }
                        else
                            .begin;
                    const field_name = loaded_union.load_tag_type(ip).names.get(ip)[field_index];
                    return .{ .field = if (loaded_union.has_tag(ip))
                        .{ .payload_identifier = field_name.to_slice(ip) }
                    else
                        .{ .identifier = field_name.to_slice(ip) } };
                },
                .@"packed" => return .begin,
            }
        },
        .ptr_type => |ptr_info| switch (ptr_info.flags.size) {
            .One, .Many, .C => unreachable,
            .Slice => switch (field_index) {
                0 => return .{ .field = .{ .identifier = "ptr" } },
                1 => return .{ .field = .{ .identifier = "len" } },
                else => unreachable,
            },
        },
        else => unreachable,
    }
}

fn air_struct_field_ptr(f: *Function, inst: Air.Inst.Index) !CValue {
    const ty_pl = f.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = f.air.extra_data(Air.StructField, ty_pl.payload).data;

    const container_ptr_val = try f.resolve_inst(extra.struct_operand);
    try reap(f, inst, &.{extra.struct_operand});
    const container_ptr_ty = f.type_of(extra.struct_operand);
    return field_ptr(f, inst, container_ptr_ty, container_ptr_val, extra.field_index);
}

fn air_struct_field_ptr_index(f: *Function, inst: Air.Inst.Index, index: u8) !CValue {
    const ty_op = f.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

    const container_ptr_val = try f.resolve_inst(ty_op.operand);
    try reap(f, inst, &.{ty_op.operand});
    const container_ptr_ty = f.type_of(ty_op.operand);
    return field_ptr(f, inst, container_ptr_ty, container_ptr_val, index);
}

fn air_field_parent_ptr(f: *Function, inst: Air.Inst.Index) !CValue {
    const zcu = f.object.dg.zcu;
    const ty_pl = f.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = f.air.extra_data(Air.FieldParentPtr, ty_pl.payload).data;

    const container_ptr_ty = f.type_of_index(inst);
    const container_ty = container_ptr_ty.child_type(zcu);

    const field_ptr_ty = f.type_of(extra.field_ptr);
    const field_ptr_val = try f.resolve_inst(extra.field_ptr);
    try reap(f, inst, &.{extra.field_ptr});

    const writer = f.object.writer();
    const local = try f.alloc_local(inst, container_ptr_ty);
    try f.write_cvalue(writer, local, .Other);
    try writer.write_all(" = (");
    try f.render_type(writer, container_ptr_ty);
    try writer.write_byte(')');

    switch (field_location(container_ptr_ty, field_ptr_ty, extra.field_index, zcu)) {
        .begin => try f.write_cvalue(writer, field_ptr_val, .Initializer),
        .field => |field| {
            const u8_ptr_ty = try zcu.adjust_ptr_type_child(field_ptr_ty, Type.u8);

            try writer.write_all("((");
            try f.render_type(writer, u8_ptr_ty);
            try writer.write_byte(')');
            try f.write_cvalue(writer, field_ptr_val, .Other);
            try writer.write_all(" - offsetof(");
            try f.render_type(writer, container_ty);
            try writer.write_all(", ");
            try f.write_cvalue(writer, field, .Other);
            try writer.write_all("))");
        },
        .byte_offset => |byte_offset| {
            const u8_ptr_ty = try zcu.adjust_ptr_type_child(field_ptr_ty, Type.u8);

            try writer.write_all("((");
            try f.render_type(writer, u8_ptr_ty);
            try writer.write_byte(')');
            try f.write_cvalue(writer, field_ptr_val, .Other);
            try writer.print(" - {})", .{
                try f.fmt_int_literal(try zcu.int_value(Type.usize, byte_offset)),
            });
        },
    }

    try writer.write_all(";\n");
    return local;
}

fn field_ptr(
    f: *Function,
    inst: Air.Inst.Index,
    container_ptr_ty: Type,
    container_ptr_val: CValue,
    field_index: u32,
) !CValue {
    const zcu = f.object.dg.zcu;
    const container_ty = container_ptr_ty.child_type(zcu);
    const field_ptr_ty = f.type_of_index(inst);

    // Ensure complete type definition is visible before accessing fields.
    _ = try f.ctype_from_type(container_ty, .complete);

    const writer = f.object.writer();
    const local = try f.alloc_local(inst, field_ptr_ty);
    try f.write_cvalue(writer, local, .Other);
    try writer.write_all(" = (");
    try f.render_type(writer, field_ptr_ty);
    try writer.write_byte(')');

    switch (field_location(container_ptr_ty, field_ptr_ty, field_index, zcu)) {
        .begin => try f.write_cvalue(writer, container_ptr_val, .Initializer),
        .field => |field| {
            try writer.write_byte('&');
            try f.write_cvalue_deref_member(writer, container_ptr_val, field);
        },
        .byte_offset => |byte_offset| {
            const u8_ptr_ty = try zcu.adjust_ptr_type_child(field_ptr_ty, Type.u8);

            try writer.write_all("((");
            try f.render_type(writer, u8_ptr_ty);
            try writer.write_byte(')');
            try f.write_cvalue(writer, container_ptr_val, .Other);
            try writer.print(" + {})", .{
                try f.fmt_int_literal(try zcu.int_value(Type.usize, byte_offset)),
            });
        },
    }

    try writer.write_all(";\n");
    return local;
}

fn air_struct_field_val(f: *Function, inst: Air.Inst.Index) !CValue {
    const zcu = f.object.dg.zcu;
    const ip = &zcu.intern_pool;
    const ty_pl = f.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = f.air.extra_data(Air.StructField, ty_pl.payload).data;

    const inst_ty = f.type_of_index(inst);
    if (!inst_ty.has_runtime_bits_ignore_comptime(zcu)) {
        try reap(f, inst, &.{extra.struct_operand});
        return .none;
    }

    const struct_byval = try f.resolve_inst(extra.struct_operand);
    try reap(f, inst, &.{extra.struct_operand});
    const struct_ty = f.type_of(extra.struct_operand);
    const writer = f.object.writer();

    // Ensure complete type definition is visible before accessing fields.
    _ = try f.ctype_from_type(struct_ty, .complete);

    const field_name: CValue = switch (ip.index_to_key(struct_ty.to_intern())) {
        .struct_type => field_name: {
            const loaded_struct = ip.load_struct_type(struct_ty.to_intern());
            switch (loaded_struct.layout) {
                .auto, .@"extern" => break :field_name if (loaded_struct.field_name(ip, extra.field_index).unwrap()) |field_name|
                    .{ .identifier = field_name.to_slice(ip) }
                else
                    .{ .field = extra.field_index },
                .@"packed" => {
                    const int_info = struct_ty.int_info(zcu);

                    const bit_offset_ty = try zcu.int_type(.unsigned, Type.smallest_unsigned_bits(int_info.bits - 1));

                    const bit_offset = zcu.struct_packed_field_bit_offset(loaded_struct, extra.field_index);

                    const field_int_signedness = if (inst_ty.is_abi_int(zcu))
                        inst_ty.int_info(zcu).signedness
                    else
                        .unsigned;
                    const field_int_ty = try zcu.int_type(field_int_signedness, @as(u16, @int_cast(inst_ty.bit_size(zcu))));

                    const temp_local = try f.alloc_local(inst, field_int_ty);
                    try f.write_cvalue(writer, temp_local, .Other);
                    try writer.write_all(" = zig_wrap_");
                    try f.object.dg.render_type_for_builtin_fn_name(writer, field_int_ty);
                    try writer.write_all("((");
                    try f.render_type(writer, field_int_ty);
                    try writer.write_byte(')');
                    const cant_cast = int_info.bits > 64;
                    if (cant_cast) {
                        if (field_int_ty.bit_size(zcu) > 64) return f.fail("TODO: C backend: implement casting between types > 64 bits", .{});
                        try writer.write_all("zig_lo_");
                        try f.object.dg.render_type_for_builtin_fn_name(writer, struct_ty);
                        try writer.write_byte('(');
                    }
                    if (bit_offset > 0) {
                        try writer.write_all("zig_shr_");
                        try f.object.dg.render_type_for_builtin_fn_name(writer, struct_ty);
                        try writer.write_byte('(');
                    }
                    try f.write_cvalue(writer, struct_byval, .Other);
                    if (bit_offset > 0) try writer.print(", {})", .{
                        try f.fmt_int_literal(try zcu.int_value(bit_offset_ty, bit_offset)),
                    });
                    if (cant_cast) try writer.write_byte(')');
                    try f.object.dg.render_builtin_info(writer, field_int_ty, .bits);
                    try writer.write_all(");\n");
                    if (inst_ty.eql(field_int_ty, f.object.dg.zcu)) return temp_local;

                    const local = try f.alloc_local(inst, inst_ty);
                    if (local.new_local != temp_local.new_local) {
                        try writer.write_all("memcpy(");
                        try f.write_cvalue(writer, .{ .local_ref = local.new_local }, .FunctionArgument);
                        try writer.write_all(", ");
                        try f.write_cvalue(writer, .{ .local_ref = temp_local.new_local }, .FunctionArgument);
                        try writer.write_all(", sizeof(");
                        try f.render_type(writer, inst_ty);
                        try writer.write_all("));\n");
                    }
                    try free_local(f, inst, temp_local.new_local, null);
                    return local;
                },
            }
        },
        .anon_struct_type => |anon_struct_info| if (anon_struct_info.field_name(ip, extra.field_index).unwrap()) |field_name|
            .{ .identifier = field_name.to_slice(ip) }
        else
            .{ .field = extra.field_index },
        .union_type => field_name: {
            const loaded_union = ip.load_union_type(struct_ty.to_intern());
            switch (loaded_union.get_layout(ip)) {
                .auto, .@"extern" => {
                    const name = loaded_union.load_tag_type(ip).names.get(ip)[extra.field_index];
                    break :field_name if (loaded_union.has_tag(ip))
                        .{ .payload_identifier = name.to_slice(ip) }
                    else
                        .{ .identifier = name.to_slice(ip) };
                },
                .@"packed" => {
                    const operand_lval = if (struct_byval == .constant) blk: {
                        const operand_local = try f.alloc_local(inst, struct_ty);
                        try f.write_cvalue(writer, operand_local, .Other);
                        try writer.write_all(" = ");
                        try f.write_cvalue(writer, struct_byval, .Initializer);
                        try writer.write_all(";\n");
                        break :blk operand_local;
                    } else struct_byval;
                    const local = try f.alloc_local(inst, inst_ty);
                    if (switch (local) {
                        .new_local, .local => |local_index| switch (operand_lval) {
                            .new_local, .local => |operand_local_index| local_index != operand_local_index,
                            else => true,
                        },
                        else => true,
                    }) {
                        try writer.write_all("memcpy(&");
                        try f.write_cvalue(writer, local, .Other);
                        try writer.write_all(", &");
                        try f.write_cvalue(writer, operand_lval, .Other);
                        try writer.write_all(", sizeof(");
                        try f.render_type(writer, inst_ty);
                        try writer.write_all("));\n");
                    }
                    try f.free_cvalue(inst, operand_lval);
                    return local;
                },
            }
        },
        else => unreachable,
    };

    const local = try f.alloc_local(inst, inst_ty);
    const a = try Assignment.start(f, writer, try f.ctype_from_type(inst_ty, .complete));
    try f.write_cvalue(writer, local, .Other);
    try a.assign(f, writer);
    try f.write_cvalue_member(writer, struct_byval, field_name);
    try a.end(f, writer);
    return local;
}

/// *(E!T) -> E
/// Note that the result is never a pointer.
fn air_unwrap_err_union_err(f: *Function, inst: Air.Inst.Index) !CValue {
    const zcu = f.object.dg.zcu;
    const ty_op = f.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

    const inst_ty = f.type_of_index(inst);
    const operand = try f.resolve_inst(ty_op.operand);
    const operand_ty = f.type_of(ty_op.operand);
    try reap(f, inst, &.{ty_op.operand});

    const operand_is_ptr = operand_ty.zig_type_tag(zcu) == .Pointer;
    const error_union_ty = if (operand_is_ptr) operand_ty.child_type(zcu) else operand_ty;
    const error_ty = error_union_ty.error_union_set(zcu);
    const payload_ty = error_union_ty.error_union_payload(zcu);
    const local = try f.alloc_local(inst, inst_ty);

    if (!payload_ty.has_runtime_bits(zcu) and operand == .local and operand.local == local.new_local) {
        // The store will be 'x = x'; elide it.
        return local;
    }

    const writer = f.object.writer();
    try f.write_cvalue(writer, local, .Other);
    try writer.write_all(" = ");

    if (!payload_ty.has_runtime_bits(zcu))
        try f.write_cvalue(writer, operand, .Other)
    else if (error_ty.error_set_is_empty(zcu))
        try writer.print("{}", .{
            try f.fmt_int_literal(try zcu.int_value(try zcu.error_int_type(), 0)),
        })
    else if (operand_is_ptr)
        try f.write_cvalue_deref_member(writer, operand, .{ .identifier = "error" })
    else
        try f.write_cvalue_member(writer, operand, .{ .identifier = "error" });
    try writer.write_all(";\n");
    return local;
}

fn air_unwrap_err_union_pay(f: *Function, inst: Air.Inst.Index, is_ptr: bool) !CValue {
    const zcu = f.object.dg.zcu;
    const ty_op = f.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

    const inst_ty = f.type_of_index(inst);
    const operand = try f.resolve_inst(ty_op.operand);
    try reap(f, inst, &.{ty_op.operand});
    const operand_ty = f.type_of(ty_op.operand);
    const error_union_ty = if (is_ptr) operand_ty.child_type(zcu) else operand_ty;

    const writer = f.object.writer();
    if (!error_union_ty.error_union_payload(zcu).has_runtime_bits(zcu)) {
        if (!is_ptr) return .none;

        const local = try f.alloc_local(inst, inst_ty);
        try f.write_cvalue(writer, local, .Other);
        try writer.write_all(" = (");
        try f.render_type(writer, inst_ty);
        try writer.write_byte(')');
        try f.write_cvalue(writer, operand, .Initializer);
        try writer.write_all(";\n");
        return local;
    }

    const local = try f.alloc_local(inst, inst_ty);
    const a = try Assignment.start(f, writer, try f.ctype_from_type(inst_ty, .complete));
    try f.write_cvalue(writer, local, .Other);
    try a.assign(f, writer);
    if (is_ptr) {
        try writer.write_byte('&');
        try f.write_cvalue_deref_member(writer, operand, .{ .identifier = "payload" });
    } else try f.write_cvalue_member(writer, operand, .{ .identifier = "payload" });
    try a.end(f, writer);
    return local;
}

fn air_wrap_optional(f: *Function, inst: Air.Inst.Index) !CValue {
    const ctype_pool = &f.object.dg.ctype_pool;
    const ty_op = f.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

    const inst_ty = f.type_of_index(inst);
    const inst_ctype = try f.ctype_from_type(inst_ty, .complete);
    if (inst_ctype.is_bool()) return .{ .constant = Value.true };

    const operand = try f.resolve_inst(ty_op.operand);
    switch (inst_ctype.info(ctype_pool)) {
        .basic, .pointer => return f.move_cvalue(inst, inst_ty, operand),
        .aligned, .array, .vector, .fwd_decl, .function => unreachable,
        .aggregate => |aggregate| switch (aggregate.fields.at(0, ctype_pool).name.index) {
            .is_null, .payload => {
                const operand_ctype = try f.ctype_from_type(f.type_of(ty_op.operand), .complete);
                const writer = f.object.writer();
                const local = try f.alloc_local(inst, inst_ty);
                {
                    const a = try Assignment.start(f, writer, CType.bool);
                    try f.write_cvalue_member(writer, local, .{ .identifier = "is_null" });
                    try a.assign(f, writer);
                    try writer.write_all("false");
                    try a.end(f, writer);
                }
                {
                    const a = try Assignment.start(f, writer, operand_ctype);
                    try f.write_cvalue_member(writer, local, .{ .identifier = "payload" });
                    try a.assign(f, writer);
                    try f.write_cvalue(writer, operand, .Initializer);
                    try a.end(f, writer);
                }
                return local;
            },
            .ptr, .len => return f.move_cvalue(inst, inst_ty, operand),
            else => unreachable,
        },
    }
}

fn air_wrap_err_union_err(f: *Function, inst: Air.Inst.Index) !CValue {
    const zcu = f.object.dg.zcu;
    const ty_op = f.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

    const inst_ty = f.type_of_index(inst);
    const payload_ty = inst_ty.error_union_payload(zcu);
    const repr_is_err = !payload_ty.has_runtime_bits_ignore_comptime(zcu);
    const err_ty = inst_ty.error_union_set(zcu);
    const err = try f.resolve_inst(ty_op.operand);
    try reap(f, inst, &.{ty_op.operand});

    const writer = f.object.writer();
    const local = try f.alloc_local(inst, inst_ty);

    if (repr_is_err and err == .local and err.local == local.new_local) {
        // The store will be 'x = x'; elide it.
        return local;
    }

    if (!repr_is_err) {
        const a = try Assignment.start(f, writer, try f.ctype_from_type(payload_ty, .complete));
        try f.write_cvalue_member(writer, local, .{ .identifier = "payload" });
        try a.assign(f, writer);
        try f.object.dg.render_undef_value(writer, payload_ty, .Other);
        try a.end(f, writer);
    }
    {
        const a = try Assignment.start(f, writer, try f.ctype_from_type(err_ty, .complete));
        if (repr_is_err)
            try f.write_cvalue(writer, local, .Other)
        else
            try f.write_cvalue_member(writer, local, .{ .identifier = "error" });
        try a.assign(f, writer);
        try f.write_cvalue(writer, err, .Other);
        try a.end(f, writer);
    }
    return local;
}

fn air_err_union_payload_ptr_set(f: *Function, inst: Air.Inst.Index) !CValue {
    const zcu = f.object.dg.zcu;
    const writer = f.object.writer();
    const ty_op = f.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const inst_ty = f.type_of_index(inst);
    const operand = try f.resolve_inst(ty_op.operand);
    const operand_ty = f.type_of(ty_op.operand);
    const error_union_ty = operand_ty.child_type(zcu);

    const payload_ty = error_union_ty.error_union_payload(zcu);
    const err_int_ty = try zcu.error_int_type();
    const no_err = try zcu.int_value(err_int_ty, 0);
    try reap(f, inst, &.{ty_op.operand});

    // First, set the non-error value.
    if (!payload_ty.has_runtime_bits_ignore_comptime(zcu)) {
        const a = try Assignment.start(f, writer, try f.ctype_from_type(operand_ty, .complete));
        try f.write_cvalue_deref(writer, operand);
        try a.assign(f, writer);
        try writer.print("{}", .{try f.fmt_int_literal(no_err)});
        try a.end(f, writer);
        return .none;
    }
    {
        const a = try Assignment.start(f, writer, try f.ctype_from_type(err_int_ty, .complete));
        try f.write_cvalue_deref_member(writer, operand, .{ .identifier = "error" });
        try a.assign(f, writer);
        try writer.print("{}", .{try f.fmt_int_literal(no_err)});
        try a.end(f, writer);
    }

    // Then return the payload pointer (only if it is used)
    if (f.liveness.is_unused(inst)) return .none;

    const local = try f.alloc_local(inst, inst_ty);
    const a = try Assignment.start(f, writer, try f.ctype_from_type(inst_ty, .complete));
    try f.write_cvalue(writer, local, .Other);
    try a.assign(f, writer);
    try writer.write_byte('&');
    try f.write_cvalue_deref_member(writer, operand, .{ .identifier = "payload" });
    try a.end(f, writer);
    return local;
}

fn air_err_return_trace(f: *Function, inst: Air.Inst.Index) !CValue {
    _ = inst;
    return f.fail("TODO: C backend: implement air_err_return_trace", .{});
}

fn air_set_err_return_trace(f: *Function, inst: Air.Inst.Index) !CValue {
    _ = inst;
    return f.fail("TODO: C backend: implement air_set_err_return_trace", .{});
}

fn air_save_err_return_trace_index(f: *Function, inst: Air.Inst.Index) !CValue {
    _ = inst;
    return f.fail("TODO: C backend: implement air_save_err_return_trace_index", .{});
}

fn air_wrap_err_union_pay(f: *Function, inst: Air.Inst.Index) !CValue {
    const zcu = f.object.dg.zcu;
    const ty_op = f.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

    const inst_ty = f.type_of_index(inst);
    const payload_ty = inst_ty.error_union_payload(zcu);
    const payload = try f.resolve_inst(ty_op.operand);
    const repr_is_err = !payload_ty.has_runtime_bits_ignore_comptime(zcu);
    const err_ty = inst_ty.error_union_set(zcu);
    try reap(f, inst, &.{ty_op.operand});

    const writer = f.object.writer();
    const local = try f.alloc_local(inst, inst_ty);
    if (!repr_is_err) {
        const a = try Assignment.start(f, writer, try f.ctype_from_type(payload_ty, .complete));
        try f.write_cvalue_member(writer, local, .{ .identifier = "payload" });
        try a.assign(f, writer);
        try f.write_cvalue(writer, payload, .Other);
        try a.end(f, writer);
    }
    {
        const a = try Assignment.start(f, writer, try f.ctype_from_type(err_ty, .complete));
        if (repr_is_err)
            try f.write_cvalue(writer, local, .Other)
        else
            try f.write_cvalue_member(writer, local, .{ .identifier = "error" });
        try a.assign(f, writer);
        try f.object.dg.render_value(writer, try zcu.int_value(try zcu.error_int_type(), 0), .Other);
        try a.end(f, writer);
    }
    return local;
}

fn air_is_err(f: *Function, inst: Air.Inst.Index, is_ptr: bool, operator: []const u8) !CValue {
    const zcu = f.object.dg.zcu;
    const un_op = f.air.instructions.items(.data)[@int_from_enum(inst)].un_op;

    const writer = f.object.writer();
    const operand = try f.resolve_inst(un_op);
    try reap(f, inst, &.{un_op});
    const operand_ty = f.type_of(un_op);
    const local = try f.alloc_local(inst, Type.bool);
    const err_union_ty = if (is_ptr) operand_ty.child_type(zcu) else operand_ty;
    const payload_ty = err_union_ty.error_union_payload(zcu);
    const error_ty = err_union_ty.error_union_set(zcu);

    const a = try Assignment.start(f, writer, CType.bool);
    try f.write_cvalue(writer, local, .Other);
    try a.assign(f, writer);
    const err_int_ty = try zcu.error_int_type();
    if (!error_ty.error_set_is_empty(zcu))
        if (payload_ty.has_runtime_bits(zcu))
            if (is_ptr)
                try f.write_cvalue_deref_member(writer, operand, .{ .identifier = "error" })
            else
                try f.write_cvalue_member(writer, operand, .{ .identifier = "error" })
        else
            try f.write_cvalue(writer, operand, .Other)
    else
        try f.object.dg.render_value(writer, try zcu.int_value(err_int_ty, 0), .Other);
    try writer.write_byte(' ');
    try writer.write_all(operator);
    try writer.write_byte(' ');
    try f.object.dg.render_value(writer, try zcu.int_value(err_int_ty, 0), .Other);
    try a.end(f, writer);
    return local;
}

fn air_array_to_slice(f: *Function, inst: Air.Inst.Index) !CValue {
    const zcu = f.object.dg.zcu;
    const ctype_pool = &f.object.dg.ctype_pool;
    const ty_op = f.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

    const operand = try f.resolve_inst(ty_op.operand);
    try reap(f, inst, &.{ty_op.operand});
    const inst_ty = f.type_of_index(inst);
    const ptr_ty = inst_ty.slice_ptr_field_type(zcu);
    const writer = f.object.writer();
    const local = try f.alloc_local(inst, inst_ty);
    const operand_ty = f.type_of(ty_op.operand);
    const array_ty = operand_ty.child_type(zcu);

    {
        const a = try Assignment.start(f, writer, try f.ctype_from_type(ptr_ty, .complete));
        try f.write_cvalue_member(writer, local, .{ .identifier = "ptr" });
        try a.assign(f, writer);
        if (operand == .undef) {
            try f.write_cvalue(writer, .{ .undef = inst_ty.slice_ptr_field_type(zcu) }, .Initializer);
        } else {
            const ptr_ctype = try f.ctype_from_type(ptr_ty, .complete);
            const ptr_child_ctype = ptr_ctype.info(ctype_pool).pointer.elem_ctype;
            const elem_ty = array_ty.child_type(zcu);
            const elem_ctype = try f.ctype_from_type(elem_ty, .complete);
            if (!ptr_child_ctype.eql(elem_ctype)) {
                try writer.write_byte('(');
                try f.render_ctype(writer, ptr_ctype);
                try writer.write_byte(')');
            }
            const operand_ctype = try f.ctype_from_type(operand_ty, .complete);
            const operand_child_ctype = operand_ctype.info(ctype_pool).pointer.elem_ctype;
            if (operand_child_ctype.info(ctype_pool) == .array) {
                try writer.write_byte('&');
                try f.write_cvalue_deref(writer, operand);
                try writer.print("[{}]", .{try f.fmt_int_literal(try zcu.int_value(Type.usize, 0))});
            } else try f.write_cvalue(writer, operand, .Initializer);
        }
        try a.end(f, writer);
    }
    {
        const a = try Assignment.start(f, writer, CType.usize);
        try f.write_cvalue_member(writer, local, .{ .identifier = "len" });
        try a.assign(f, writer);
        try writer.print("{}", .{
            try f.fmt_int_literal(try zcu.int_value(Type.usize, array_ty.array_len(zcu))),
        });
        try a.end(f, writer);
    }

    return local;
}

fn air_float_cast(f: *Function, inst: Air.Inst.Index) !CValue {
    const zcu = f.object.dg.zcu;
    const ty_op = f.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

    const inst_ty = f.type_of_index(inst);
    const inst_scalar_ty = inst_ty.scalar_type(zcu);
    const operand = try f.resolve_inst(ty_op.operand);
    try reap(f, inst, &.{ty_op.operand});
    const operand_ty = f.type_of(ty_op.operand);
    const scalar_ty = operand_ty.scalar_type(zcu);
    const target = &f.object.dg.mod.resolved_target.result;
    const operation = if (inst_scalar_ty.is_runtime_float() and scalar_ty.is_runtime_float())
        if (inst_scalar_ty.float_bits(target.*) < scalar_ty.float_bits(target.*)) "trunc" else "extend"
    else if (inst_scalar_ty.is_int(zcu) and scalar_ty.is_runtime_float())
        if (inst_scalar_ty.is_signed_int(zcu)) "fix" else "fixuns"
    else if (inst_scalar_ty.is_runtime_float() and scalar_ty.is_int(zcu))
        if (scalar_ty.is_signed_int(zcu)) "float" else "floatun"
    else
        unreachable;

    const writer = f.object.writer();
    const local = try f.alloc_local(inst, inst_ty);
    const v = try Vectorize.start(f, inst, writer, operand_ty);
    const a = try Assignment.start(f, writer, try f.ctype_from_type(scalar_ty, .complete));
    try f.write_cvalue(writer, local, .Other);
    try v.elem(f, writer);
    try a.assign(f, writer);
    if (inst_scalar_ty.is_int(zcu) and scalar_ty.is_runtime_float()) {
        try writer.write_all("zig_wrap_");
        try f.object.dg.render_type_for_builtin_fn_name(writer, inst_scalar_ty);
        try writer.write_byte('(');
    }
    try writer.write_all("zig_");
    try writer.write_all(operation);
    try writer.write_all(compiler_rt_abbrev(scalar_ty, zcu, target.*));
    try writer.write_all(compiler_rt_abbrev(inst_scalar_ty, zcu, target.*));
    try writer.write_byte('(');
    try f.write_cvalue(writer, operand, .FunctionArgument);
    try v.elem(f, writer);
    try writer.write_byte(')');
    if (inst_scalar_ty.is_int(zcu) and scalar_ty.is_runtime_float()) {
        try f.object.dg.render_builtin_info(writer, inst_scalar_ty, .bits);
        try writer.write_byte(')');
    }
    try a.end(f, writer);
    try v.end(f, inst, writer);

    return local;
}

fn air_int_from_ptr(f: *Function, inst: Air.Inst.Index) !CValue {
    const zcu = f.object.dg.zcu;
    const un_op = f.air.instructions.items(.data)[@int_from_enum(inst)].un_op;

    const operand = try f.resolve_inst(un_op);
    const operand_ty = f.type_of(un_op);
    try reap(f, inst, &.{un_op});
    const inst_ty = f.type_of_index(inst);
    const writer = f.object.writer();
    const local = try f.alloc_local(inst, inst_ty);
    try f.write_cvalue(writer, local, .Other);

    try writer.write_all(" = (");
    try f.render_type(writer, inst_ty);
    try writer.write_byte(')');
    if (operand_ty.is_slice(zcu))
        try f.write_cvalue_member(writer, operand, .{ .identifier = "ptr" })
    else
        try f.write_cvalue(writer, operand, .Other);
    try writer.write_all(";\n");
    return local;
}

fn air_un_builtin_call(
    f: *Function,
    inst: Air.Inst.Index,
    operand_ref: Air.Inst.Ref,
    operation: []const u8,
    info: BuiltinInfo,
) !CValue {
    const zcu = f.object.dg.zcu;

    const operand = try f.resolve_inst(operand_ref);
    try reap(f, inst, &.{operand_ref});
    const inst_ty = f.type_of_index(inst);
    const inst_scalar_ty = inst_ty.scalar_type(zcu);
    const operand_ty = f.type_of(operand_ref);
    const scalar_ty = operand_ty.scalar_type(zcu);

    const inst_scalar_ctype = try f.ctype_from_type(inst_scalar_ty, .complete);
    const ref_ret = inst_scalar_ctype.info(&f.object.dg.ctype_pool) == .array;

    const writer = f.object.writer();
    const local = try f.alloc_local(inst, inst_ty);
    const v = try Vectorize.start(f, inst, writer, operand_ty);
    if (!ref_ret) {
        try f.write_cvalue(writer, local, .Other);
        try v.elem(f, writer);
        try writer.write_all(" = ");
    }
    try writer.print("zig_{s}_", .{operation});
    try f.object.dg.render_type_for_builtin_fn_name(writer, scalar_ty);
    try writer.write_byte('(');
    if (ref_ret) {
        try f.write_cvalue(writer, local, .FunctionArgument);
        try v.elem(f, writer);
        try writer.write_all(", ");
    }
    try f.write_cvalue(writer, operand, .FunctionArgument);
    try v.elem(f, writer);
    try f.object.dg.render_builtin_info(writer, scalar_ty, info);
    try writer.write_all(");\n");
    try v.end(f, inst, writer);

    return local;
}

fn air_bin_builtin_call(
    f: *Function,
    inst: Air.Inst.Index,
    operation: []const u8,
    info: BuiltinInfo,
) !CValue {
    const zcu = f.object.dg.zcu;
    const bin_op = f.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;

    const operand_ty = f.type_of(bin_op.lhs);
    const operand_ctype = try f.ctype_from_type(operand_ty, .complete);
    const is_big = operand_ctype.info(&f.object.dg.ctype_pool) == .array;

    const lhs = try f.resolve_inst(bin_op.lhs);
    const rhs = try f.resolve_inst(bin_op.rhs);
    if (!is_big) try reap(f, inst, &.{ bin_op.lhs, bin_op.rhs });

    const inst_ty = f.type_of_index(inst);
    const inst_scalar_ty = inst_ty.scalar_type(zcu);
    const scalar_ty = operand_ty.scalar_type(zcu);

    const inst_scalar_ctype = try f.ctype_from_type(inst_scalar_ty, .complete);
    const ref_ret = inst_scalar_ctype.info(&f.object.dg.ctype_pool) == .array;

    const writer = f.object.writer();
    const local = try f.alloc_local(inst, inst_ty);
    if (is_big) try reap(f, inst, &.{ bin_op.lhs, bin_op.rhs });
    const v = try Vectorize.start(f, inst, writer, operand_ty);
    if (!ref_ret) {
        try f.write_cvalue(writer, local, .Other);
        try v.elem(f, writer);
        try writer.write_all(" = ");
    }
    try writer.print("zig_{s}_", .{operation});
    try f.object.dg.render_type_for_builtin_fn_name(writer, scalar_ty);
    try writer.write_byte('(');
    if (ref_ret) {
        try f.write_cvalue(writer, local, .FunctionArgument);
        try v.elem(f, writer);
        try writer.write_all(", ");
    }
    try f.write_cvalue(writer, lhs, .FunctionArgument);
    try v.elem(f, writer);
    try writer.write_all(", ");
    try f.write_cvalue(writer, rhs, .FunctionArgument);
    try v.elem(f, writer);
    try f.object.dg.render_builtin_info(writer, scalar_ty, info);
    try writer.write_all(");\n");
    try v.end(f, inst, writer);

    return local;
}

fn air_cmp_builtin_call(
    f: *Function,
    inst: Air.Inst.Index,
    data: anytype,
    operator: std.math.CompareOperator,
    operation: enum { cmp, operator },
    info: BuiltinInfo,
) !CValue {
    const zcu = f.object.dg.zcu;
    const lhs = try f.resolve_inst(data.lhs);
    const rhs = try f.resolve_inst(data.rhs);
    try reap(f, inst, &.{ data.lhs, data.rhs });

    const inst_ty = f.type_of_index(inst);
    const inst_scalar_ty = inst_ty.scalar_type(zcu);
    const operand_ty = f.type_of(data.lhs);
    const scalar_ty = operand_ty.scalar_type(zcu);

    const inst_scalar_ctype = try f.ctype_from_type(inst_scalar_ty, .complete);
    const ref_ret = inst_scalar_ctype.info(&f.object.dg.ctype_pool) == .array;

    const writer = f.object.writer();
    const local = try f.alloc_local(inst, inst_ty);
    const v = try Vectorize.start(f, inst, writer, operand_ty);
    if (!ref_ret) {
        try f.write_cvalue(writer, local, .Other);
        try v.elem(f, writer);
        try writer.write_all(" = ");
    }
    try writer.print("zig_{s}_", .{switch (operation) {
        else => @tag_name(operation),
        .operator => compare_operator_abbrev(operator),
    }});
    try f.object.dg.render_type_for_builtin_fn_name(writer, scalar_ty);
    try writer.write_byte('(');
    if (ref_ret) {
        try f.write_cvalue(writer, local, .FunctionArgument);
        try v.elem(f, writer);
        try writer.write_all(", ");
    }
    try f.write_cvalue(writer, lhs, .FunctionArgument);
    try v.elem(f, writer);
    try writer.write_all(", ");
    try f.write_cvalue(writer, rhs, .FunctionArgument);
    try v.elem(f, writer);
    try f.object.dg.render_builtin_info(writer, scalar_ty, info);
    try writer.write_byte(')');
    if (!ref_ret) try writer.print("{s}{}", .{
        compare_operator_c(operator),
        try f.fmt_int_literal(try zcu.int_value(Type.i32, 0)),
    });
    try writer.write_all(";\n");
    try v.end(f, inst, writer);

    return local;
}

fn air_cmpxchg(f: *Function, inst: Air.Inst.Index, flavor: [*:0]const u8) !CValue {
    const zcu = f.object.dg.zcu;
    const ty_pl = f.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = f.air.extra_data(Air.Cmpxchg, ty_pl.payload).data;
    const inst_ty = f.type_of_index(inst);
    const ptr = try f.resolve_inst(extra.ptr);
    const expected_value = try f.resolve_inst(extra.expected_value);
    const new_value = try f.resolve_inst(extra.new_value);
    const ptr_ty = f.type_of(extra.ptr);
    const ty = ptr_ty.child_type(zcu);
    const ctype = try f.ctype_from_type(ty, .complete);

    const writer = f.object.writer();
    const new_value_mat = try Materialize.start(f, inst, ty, new_value);
    try reap(f, inst, &.{ extra.ptr, extra.expected_value, extra.new_value });

    const repr_ty = if (ty.is_runtime_float())
        zcu.int_type(.unsigned, @as(u16, @int_cast(ty.abi_size(zcu) * 8))) catch unreachable
    else
        ty;

    const local = try f.alloc_local(inst, inst_ty);
    if (inst_ty.is_ptr_like_optional(zcu)) {
        {
            const a = try Assignment.start(f, writer, ctype);
            try f.write_cvalue(writer, local, .Other);
            try a.assign(f, writer);
            try f.write_cvalue(writer, expected_value, .Other);
            try a.end(f, writer);
        }

        try writer.write_all("if (");
        try writer.print("zig_cmpxchg_{s}((zig_atomic(", .{flavor});
        try f.render_type(writer, ty);
        try writer.write_byte(')');
        if (ptr_ty.is_volatile_ptr(zcu)) try writer.write_all(" volatile");
        try writer.write_all(" *)");
        try f.write_cvalue(writer, ptr, .Other);
        try writer.write_all(", ");
        try f.write_cvalue(writer, local, .FunctionArgument);
        try writer.write_all(", ");
        try new_value_mat.mat(f, writer);
        try writer.write_all(", ");
        try write_memory_order(writer, extra.success_order());
        try writer.write_all(", ");
        try write_memory_order(writer, extra.failure_order());
        try writer.write_all(", ");
        try f.object.dg.render_type_for_builtin_fn_name(writer, ty);
        try writer.write_all(", ");
        try f.render_type(writer, repr_ty);
        try writer.write_byte(')');
        try writer.write_all(") {\n");
        f.object.indent_writer.push_indent();
        {
            const a = try Assignment.start(f, writer, ctype);
            try f.write_cvalue(writer, local, .Other);
            try a.assign(f, writer);
            try writer.write_all("NULL");
            try a.end(f, writer);
        }
        f.object.indent_writer.pop_indent();
        try writer.write_all("}\n");
    } else {
        {
            const a = try Assignment.start(f, writer, ctype);
            try f.write_cvalue_member(writer, local, .{ .identifier = "payload" });
            try a.assign(f, writer);
            try f.write_cvalue(writer, expected_value, .Other);
            try a.end(f, writer);
        }
        {
            const a = try Assignment.start(f, writer, CType.bool);
            try f.write_cvalue_member(writer, local, .{ .identifier = "is_null" });
            try a.assign(f, writer);
            try writer.print("zig_cmpxchg_{s}((zig_atomic(", .{flavor});
            try f.render_type(writer, ty);
            try writer.write_byte(')');
            if (ptr_ty.is_volatile_ptr(zcu)) try writer.write_all(" volatile");
            try writer.write_all(" *)");
            try f.write_cvalue(writer, ptr, .Other);
            try writer.write_all(", ");
            try f.write_cvalue_member(writer, local, .{ .identifier = "payload" });
            try writer.write_all(", ");
            try new_value_mat.mat(f, writer);
            try writer.write_all(", ");
            try write_memory_order(writer, extra.success_order());
            try writer.write_all(", ");
            try write_memory_order(writer, extra.failure_order());
            try writer.write_all(", ");
            try f.object.dg.render_type_for_builtin_fn_name(writer, ty);
            try writer.write_all(", ");
            try f.render_type(writer, repr_ty);
            try writer.write_byte(')');
            try a.end(f, writer);
        }
    }
    try new_value_mat.end(f, inst);

    if (f.liveness.is_unused(inst)) {
        try free_local(f, inst, local.new_local, null);
        return .none;
    }

    return local;
}

fn air_atomic_rmw(f: *Function, inst: Air.Inst.Index) !CValue {
    const zcu = f.object.dg.zcu;
    const pl_op = f.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
    const extra = f.air.extra_data(Air.AtomicRmw, pl_op.payload).data;
    const inst_ty = f.type_of_index(inst);
    const ptr_ty = f.type_of(pl_op.operand);
    const ty = ptr_ty.child_type(zcu);
    const ptr = try f.resolve_inst(pl_op.operand);
    const operand = try f.resolve_inst(extra.operand);

    const writer = f.object.writer();
    const operand_mat = try Materialize.start(f, inst, ty, operand);
    try reap(f, inst, &.{ pl_op.operand, extra.operand });

    const repr_bits = @as(u16, @int_cast(ty.abi_size(zcu) * 8));
    const is_float = ty.is_runtime_float();
    const is_128 = repr_bits == 128;
    const repr_ty = if (is_float) zcu.int_type(.unsigned, repr_bits) catch unreachable else ty;

    const local = try f.alloc_local(inst, inst_ty);
    try writer.print("zig_atomicrmw_{s}", .{to_atomic_rmw_suffix(extra.op())});
    if (is_float) try writer.write_all("_float") else if (is_128) try writer.write_all("_int128");
    try writer.write_byte('(');
    try f.write_cvalue(writer, local, .Other);
    try writer.write_all(", (");
    const use_atomic = switch (extra.op()) {
        else => true,
        // These are missing from stdatomic.h, so no atomic types unless a fallback is used.
        .Nand, .Min, .Max => is_float or is_128,
    };
    if (use_atomic) try writer.write_all("zig_atomic(");
    try f.render_type(writer, ty);
    if (use_atomic) try writer.write_byte(')');
    if (ptr_ty.is_volatile_ptr(zcu)) try writer.write_all(" volatile");
    try writer.write_all(" *)");
    try f.write_cvalue(writer, ptr, .Other);
    try writer.write_all(", ");
    try operand_mat.mat(f, writer);
    try writer.write_all(", ");
    try write_memory_order(writer, extra.ordering());
    try writer.write_all(", ");
    try f.object.dg.render_type_for_builtin_fn_name(writer, ty);
    try writer.write_all(", ");
    try f.render_type(writer, repr_ty);
    try writer.write_all(");\n");
    try operand_mat.end(f, inst);

    if (f.liveness.is_unused(inst)) {
        try free_local(f, inst, local.new_local, null);
        return .none;
    }

    return local;
}

fn air_atomic_load(f: *Function, inst: Air.Inst.Index) !CValue {
    const zcu = f.object.dg.zcu;
    const atomic_load = f.air.instructions.items(.data)[@int_from_enum(inst)].atomic_load;
    const ptr = try f.resolve_inst(atomic_load.ptr);
    try reap(f, inst, &.{atomic_load.ptr});
    const ptr_ty = f.type_of(atomic_load.ptr);
    const ty = ptr_ty.child_type(zcu);

    const repr_ty = if (ty.is_runtime_float())
        zcu.int_type(.unsigned, @as(u16, @int_cast(ty.abi_size(zcu) * 8))) catch unreachable
    else
        ty;

    const inst_ty = f.type_of_index(inst);
    const writer = f.object.writer();
    const local = try f.alloc_local(inst, inst_ty);

    try writer.write_all("zig_atomic_load(");
    try f.write_cvalue(writer, local, .Other);
    try writer.write_all(", (zig_atomic(");
    try f.render_type(writer, ty);
    try writer.write_byte(')');
    if (ptr_ty.is_volatile_ptr(zcu)) try writer.write_all(" volatile");
    try writer.write_all(" *)");
    try f.write_cvalue(writer, ptr, .Other);
    try writer.write_all(", ");
    try write_memory_order(writer, atomic_load.order);
    try writer.write_all(", ");
    try f.object.dg.render_type_for_builtin_fn_name(writer, ty);
    try writer.write_all(", ");
    try f.render_type(writer, repr_ty);
    try writer.write_all(");\n");

    return local;
}

fn air_atomic_store(f: *Function, inst: Air.Inst.Index, order: [*:0]const u8) !CValue {
    const zcu = f.object.dg.zcu;
    const bin_op = f.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
    const ptr_ty = f.type_of(bin_op.lhs);
    const ty = ptr_ty.child_type(zcu);
    const ptr = try f.resolve_inst(bin_op.lhs);
    const element = try f.resolve_inst(bin_op.rhs);

    const writer = f.object.writer();
    const element_mat = try Materialize.start(f, inst, ty, element);
    try reap(f, inst, &.{ bin_op.lhs, bin_op.rhs });

    const repr_ty = if (ty.is_runtime_float())
        zcu.int_type(.unsigned, @as(u16, @int_cast(ty.abi_size(zcu) * 8))) catch unreachable
    else
        ty;

    try writer.write_all("zig_atomic_store((zig_atomic(");
    try f.render_type(writer, ty);
    try writer.write_byte(')');
    if (ptr_ty.is_volatile_ptr(zcu)) try writer.write_all(" volatile");
    try writer.write_all(" *)");
    try f.write_cvalue(writer, ptr, .Other);
    try writer.write_all(", ");
    try element_mat.mat(f, writer);
    try writer.print(", {s}, ", .{order});
    try f.object.dg.render_type_for_builtin_fn_name(writer, ty);
    try writer.write_all(", ");
    try f.render_type(writer, repr_ty);
    try writer.write_all(");\n");
    try element_mat.end(f, inst);

    return .none;
}

fn write_slice_or_ptr(f: *Function, writer: anytype, ptr: CValue, ptr_ty: Type) !void {
    const zcu = f.object.dg.zcu;
    if (ptr_ty.is_slice(zcu)) {
        try f.write_cvalue_member(writer, ptr, .{ .identifier = "ptr" });
    } else {
        try f.write_cvalue(writer, ptr, .FunctionArgument);
    }
}

fn air_memset(f: *Function, inst: Air.Inst.Index, safety: bool) !CValue {
    const zcu = f.object.dg.zcu;
    const bin_op = f.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
    const dest_ty = f.type_of(bin_op.lhs);
    const dest_slice = try f.resolve_inst(bin_op.lhs);
    const value = try f.resolve_inst(bin_op.rhs);
    const elem_ty = f.type_of(bin_op.rhs);
    const elem_abi_size = elem_ty.abi_size(zcu);
    const val_is_undef = if (try f.air.value(bin_op.rhs, zcu)) |val| val.is_undef_deep(zcu) else false;
    const writer = f.object.writer();

    if (val_is_undef) {
        if (!safety) {
            try reap(f, inst, &.{ bin_op.lhs, bin_op.rhs });
            return .none;
        }

        try writer.write_all("memset(");
        switch (dest_ty.ptr_size(zcu)) {
            .Slice => {
                try f.write_cvalue_member(writer, dest_slice, .{ .identifier = "ptr" });
                try writer.write_all(", 0xaa, ");
                try f.write_cvalue_member(writer, dest_slice, .{ .identifier = "len" });
                if (elem_abi_size > 1) {
                    try writer.print(" * {d});\n", .{elem_abi_size});
                } else {
                    try writer.write_all(");\n");
                }
            },
            .One => {
                const array_ty = dest_ty.child_type(zcu);
                const len = array_ty.array_len(zcu) * elem_abi_size;

                try f.write_cvalue(writer, dest_slice, .FunctionArgument);
                try writer.print(", 0xaa, {d});\n", .{len});
            },
            .Many, .C => unreachable,
        }
        try reap(f, inst, &.{ bin_op.lhs, bin_op.rhs });
        return .none;
    }

    if (elem_abi_size > 1 or dest_ty.is_volatile_ptr(zcu)) {
        // For the assignment in this loop, the array pointer needs to get
        // casted to a regular pointer, otherwise an error like this occurs:
        // error: array type 'uint32_t[20]' (aka 'unsigned int[20]') is not assignable
        const elem_ptr_ty = try zcu.ptr_type(.{
            .child = elem_ty.to_intern(),
            .flags = .{
                .size = .C,
            },
        });

        const index = try f.alloc_local(inst, Type.usize);

        try writer.write_all("for (");
        try f.write_cvalue(writer, index, .Other);
        try writer.write_all(" = ");
        try f.object.dg.render_value(writer, try zcu.int_value(Type.usize, 0), .Initializer);
        try writer.write_all("; ");
        try f.write_cvalue(writer, index, .Other);
        try writer.write_all(" != ");
        switch (dest_ty.ptr_size(zcu)) {
            .Slice => {
                try f.write_cvalue_member(writer, dest_slice, .{ .identifier = "len" });
            },
            .One => {
                const array_ty = dest_ty.child_type(zcu);
                try writer.print("{d}", .{array_ty.array_len(zcu)});
            },
            .Many, .C => unreachable,
        }
        try writer.write_all("; ++");
        try f.write_cvalue(writer, index, .Other);
        try writer.write_all(") ");

        const a = try Assignment.start(f, writer, try f.ctype_from_type(elem_ty, .complete));
        try writer.write_all("((");
        try f.render_type(writer, elem_ptr_ty);
        try writer.write_byte(')');
        try write_slice_or_ptr(f, writer, dest_slice, dest_ty);
        try writer.write_all(")[");
        try f.write_cvalue(writer, index, .Other);
        try writer.write_byte(']');
        try a.assign(f, writer);
        try f.write_cvalue(writer, value, .Other);
        try a.end(f, writer);

        try reap(f, inst, &.{ bin_op.lhs, bin_op.rhs });
        try free_local(f, inst, index.new_local, null);

        return .none;
    }

    const bitcasted = try bitcast(f, Type.u8, value, elem_ty);

    try writer.write_all("memset(");
    switch (dest_ty.ptr_size(zcu)) {
        .Slice => {
            try f.write_cvalue_member(writer, dest_slice, .{ .identifier = "ptr" });
            try writer.write_all(", ");
            try f.write_cvalue(writer, bitcasted, .FunctionArgument);
            try writer.write_all(", ");
            try f.write_cvalue_member(writer, dest_slice, .{ .identifier = "len" });
            try writer.write_all(");\n");
        },
        .One => {
            const array_ty = dest_ty.child_type(zcu);
            const len = array_ty.array_len(zcu) * elem_abi_size;

            try f.write_cvalue(writer, dest_slice, .FunctionArgument);
            try writer.write_all(", ");
            try f.write_cvalue(writer, bitcasted, .FunctionArgument);
            try writer.print(", {d});\n", .{len});
        },
        .Many, .C => unreachable,
    }
    try f.free_cvalue(inst, bitcasted);
    try reap(f, inst, &.{ bin_op.lhs, bin_op.rhs });
    return .none;
}

fn air_memcpy(f: *Function, inst: Air.Inst.Index) !CValue {
    const zcu = f.object.dg.zcu;
    const bin_op = f.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
    const dest_ptr = try f.resolve_inst(bin_op.lhs);
    const src_ptr = try f.resolve_inst(bin_op.rhs);
    const dest_ty = f.type_of(bin_op.lhs);
    const src_ty = f.type_of(bin_op.rhs);
    const writer = f.object.writer();

    if (dest_ty.ptr_size(zcu) != .One) {
        try writer.write_all("if (");
        try write_array_len(f, writer, dest_ptr, dest_ty);
        try writer.write_all(" != 0) ");
    }
    try writer.write_all("memcpy(");
    try write_slice_or_ptr(f, writer, dest_ptr, dest_ty);
    try writer.write_all(", ");
    try write_slice_or_ptr(f, writer, src_ptr, src_ty);
    try writer.write_all(", ");
    try write_array_len(f, writer, dest_ptr, dest_ty);
    try writer.write_all(" * sizeof(");
    try f.render_type(writer, dest_ty.elem_type2(zcu));
    try writer.write_all("));\n");

    try reap(f, inst, &.{ bin_op.lhs, bin_op.rhs });
    return .none;
}

fn write_array_len(f: *Function, writer: ArrayListWriter, dest_ptr: CValue, dest_ty: Type) !void {
    const zcu = f.object.dg.zcu;
    switch (dest_ty.ptr_size(zcu)) {
        .One => try writer.print("{}", .{
            try f.fmt_int_literal(try zcu.int_value(Type.usize, dest_ty.child_type(zcu).array_len(zcu))),
        }),
        .Many, .C => unreachable,
        .Slice => try f.write_cvalue_member(writer, dest_ptr, .{ .identifier = "len" }),
    }
}

fn air_set_union_tag(f: *Function, inst: Air.Inst.Index) !CValue {
    const zcu = f.object.dg.zcu;
    const bin_op = f.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
    const union_ptr = try f.resolve_inst(bin_op.lhs);
    const new_tag = try f.resolve_inst(bin_op.rhs);
    try reap(f, inst, &.{ bin_op.lhs, bin_op.rhs });

    const union_ty = f.type_of(bin_op.lhs).child_type(zcu);
    const layout = union_ty.union_get_layout(zcu);
    if (layout.tag_size == 0) return .none;
    const tag_ty = union_ty.union_tag_type_safety(zcu).?;

    const writer = f.object.writer();
    const a = try Assignment.start(f, writer, try f.ctype_from_type(tag_ty, .complete));
    try f.write_cvalue_deref_member(writer, union_ptr, .{ .identifier = "tag" });
    try a.assign(f, writer);
    try f.write_cvalue(writer, new_tag, .Other);
    try a.end(f, writer);
    return .none;
}

fn air_get_union_tag(f: *Function, inst: Air.Inst.Index) !CValue {
    const zcu = f.object.dg.zcu;
    const ty_op = f.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

    const operand = try f.resolve_inst(ty_op.operand);
    try reap(f, inst, &.{ty_op.operand});

    const union_ty = f.type_of(ty_op.operand);
    const layout = union_ty.union_get_layout(zcu);
    if (layout.tag_size == 0) return .none;

    const inst_ty = f.type_of_index(inst);
    const writer = f.object.writer();
    const local = try f.alloc_local(inst, inst_ty);
    const a = try Assignment.start(f, writer, try f.ctype_from_type(inst_ty, .complete));
    try f.write_cvalue(writer, local, .Other);
    try a.assign(f, writer);
    try f.write_cvalue_member(writer, operand, .{ .identifier = "tag" });
    try a.end(f, writer);
    return local;
}

fn air_tag_name(f: *Function, inst: Air.Inst.Index) !CValue {
    const zcu = f.object.dg.zcu;
    const un_op = f.air.instructions.items(.data)[@int_from_enum(inst)].un_op;

    const inst_ty = f.type_of_index(inst);
    const enum_ty = f.type_of(un_op);
    const operand = try f.resolve_inst(un_op);
    try reap(f, inst, &.{un_op});

    const writer = f.object.writer();
    const local = try f.alloc_local(inst, inst_ty);
    try f.write_cvalue(writer, local, .Other);
    try writer.print(" = {s}(", .{
        try f.get_lazy_fn_name(.{ .tag_name = enum_ty.get_owner_decl(zcu) }, .{ .tag_name = enum_ty }),
    });
    try f.write_cvalue(writer, operand, .Other);
    try writer.write_all(");\n");

    return local;
}

fn air_error_name(f: *Function, inst: Air.Inst.Index) !CValue {
    const un_op = f.air.instructions.items(.data)[@int_from_enum(inst)].un_op;

    const writer = f.object.writer();
    const inst_ty = f.type_of_index(inst);
    const operand = try f.resolve_inst(un_op);
    try reap(f, inst, &.{un_op});
    const local = try f.alloc_local(inst, inst_ty);
    try f.write_cvalue(writer, local, .Other);

    try writer.write_all(" = zig_errorName[");
    try f.write_cvalue(writer, operand, .Other);
    try writer.write_all("];\n");
    return local;
}

fn air_splat(f: *Function, inst: Air.Inst.Index) !CValue {
    const zcu = f.object.dg.zcu;
    const ty_op = f.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

    const operand = try f.resolve_inst(ty_op.operand);
    try reap(f, inst, &.{ty_op.operand});

    const inst_ty = f.type_of_index(inst);
    const inst_scalar_ty = inst_ty.scalar_type(zcu);

    const writer = f.object.writer();
    const local = try f.alloc_local(inst, inst_ty);
    const v = try Vectorize.start(f, inst, writer, inst_ty);
    const a = try Assignment.start(f, writer, try f.ctype_from_type(inst_scalar_ty, .complete));
    try f.write_cvalue(writer, local, .Other);
    try v.elem(f, writer);
    try a.assign(f, writer);
    try f.write_cvalue(writer, operand, .Other);
    try a.end(f, writer);
    try v.end(f, inst, writer);

    return local;
}

fn air_select(f: *Function, inst: Air.Inst.Index) !CValue {
    const pl_op = f.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
    const extra = f.air.extra_data(Air.Bin, pl_op.payload).data;

    const pred = try f.resolve_inst(pl_op.operand);
    const lhs = try f.resolve_inst(extra.lhs);
    const rhs = try f.resolve_inst(extra.rhs);
    try reap(f, inst, &.{ pl_op.operand, extra.lhs, extra.rhs });

    const inst_ty = f.type_of_index(inst);

    const writer = f.object.writer();
    const local = try f.alloc_local(inst, inst_ty);
    const v = try Vectorize.start(f, inst, writer, inst_ty);
    try f.write_cvalue(writer, local, .Other);
    try v.elem(f, writer);
    try writer.write_all(" = ");
    try f.write_cvalue(writer, pred, .Other);
    try v.elem(f, writer);
    try writer.write_all(" ? ");
    try f.write_cvalue(writer, lhs, .Other);
    try v.elem(f, writer);
    try writer.write_all(" : ");
    try f.write_cvalue(writer, rhs, .Other);
    try v.elem(f, writer);
    try writer.write_all(";\n");
    try v.end(f, inst, writer);

    return local;
}

fn air_shuffle(f: *Function, inst: Air.Inst.Index) !CValue {
    const zcu = f.object.dg.zcu;
    const ty_pl = f.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = f.air.extra_data(Air.Shuffle, ty_pl.payload).data;

    const mask = Value.from_interned(extra.mask);
    const lhs = try f.resolve_inst(extra.a);
    const rhs = try f.resolve_inst(extra.b);

    const inst_ty = f.type_of_index(inst);

    const writer = f.object.writer();
    const local = try f.alloc_local(inst, inst_ty);
    try reap(f, inst, &.{ extra.a, extra.b }); // local cannot alias operands
    for (0..extra.mask_len) |index| {
        try f.write_cvalue(writer, local, .Other);
        try writer.write_byte('[');
        try f.object.dg.render_value(writer, try zcu.int_value(Type.usize, index), .Other);
        try writer.write_all("] = ");

        const mask_elem = (try mask.elem_value(zcu, index)).to_signed_int(zcu);
        const src_val = try zcu.int_value(Type.usize, @as(u64, @int_cast(mask_elem ^ mask_elem >> 63)));

        try f.write_cvalue(writer, if (mask_elem >= 0) lhs else rhs, .Other);
        try writer.write_byte('[');
        try f.object.dg.render_value(writer, src_val, .Other);
        try writer.write_all("];\n");
    }

    return local;
}

fn air_reduce(f: *Function, inst: Air.Inst.Index) !CValue {
    const zcu = f.object.dg.zcu;
    const reduce = f.air.instructions.items(.data)[@int_from_enum(inst)].reduce;

    const scalar_ty = f.type_of_index(inst);
    const operand = try f.resolve_inst(reduce.operand);
    try reap(f, inst, &.{reduce.operand});
    const operand_ty = f.type_of(reduce.operand);
    const writer = f.object.writer();

    const use_operator = scalar_ty.bit_size(zcu) <= 64;
    const op: union(enum) {
        const Func = struct { operation: []const u8, info: BuiltinInfo = .none };
        builtin: Func,
        infix: []const u8,
        ternary: []const u8,
    } = switch (reduce.operation) {
        .And => if (use_operator) .{ .infix = " &= " } else .{ .builtin = .{ .operation = "and" } },
        .Or => if (use_operator) .{ .infix = " |= " } else .{ .builtin = .{ .operation = "or" } },
        .Xor => if (use_operator) .{ .infix = " ^= " } else .{ .builtin = .{ .operation = "xor" } },
        .Min => switch (scalar_ty.zig_type_tag(zcu)) {
            .Int => if (use_operator) .{ .ternary = " < " } else .{ .builtin = .{ .operation = "min" } },
            .Float => .{ .builtin = .{ .operation = "min" } },
            else => unreachable,
        },
        .Max => switch (scalar_ty.zig_type_tag(zcu)) {
            .Int => if (use_operator) .{ .ternary = " > " } else .{ .builtin = .{ .operation = "max" } },
            .Float => .{ .builtin = .{ .operation = "max" } },
            else => unreachable,
        },
        .Add => switch (scalar_ty.zig_type_tag(zcu)) {
            .Int => if (use_operator) .{ .infix = " += " } else .{ .builtin = .{ .operation = "addw", .info = .bits } },
            .Float => .{ .builtin = .{ .operation = "add" } },
            else => unreachable,
        },
        .Mul => switch (scalar_ty.zig_type_tag(zcu)) {
            .Int => if (use_operator) .{ .infix = " *= " } else .{ .builtin = .{ .operation = "mulw", .info = .bits } },
            .Float => .{ .builtin = .{ .operation = "mul" } },
            else => unreachable,
        },
    };

    // Reduce a vector by repeatedly applying a function to produce an
    // accumulated result.
    //
    // Equivalent to:
    //   reduce: {
    //     var accum: T = init;
    //     for (vec) |elem| {
    //       accum = func(accum, elem);
    //     }
    //     break :reduce accum;
    //   }

    const accum = try f.alloc_local(inst, scalar_ty);
    try f.write_cvalue(writer, accum, .Other);
    try writer.write_all(" = ");

    try f.object.dg.render_value(writer, switch (reduce.operation) {
        .Or, .Xor => switch (scalar_ty.zig_type_tag(zcu)) {
            .Bool => Value.false,
            .Int => try zcu.int_value(scalar_ty, 0),
            else => unreachable,
        },
        .And => switch (scalar_ty.zig_type_tag(zcu)) {
            .Bool => Value.true,
            .Int => switch (scalar_ty.int_info(zcu).signedness) {
                .unsigned => try scalar_ty.max_int_scalar(zcu, scalar_ty),
                .signed => try zcu.int_value(scalar_ty, -1),
            },
            else => unreachable,
        },
        .Add => switch (scalar_ty.zig_type_tag(zcu)) {
            .Int => try zcu.int_value(scalar_ty, 0),
            .Float => try zcu.float_value(scalar_ty, 0.0),
            else => unreachable,
        },
        .Mul => switch (scalar_ty.zig_type_tag(zcu)) {
            .Int => try zcu.int_value(scalar_ty, 1),
            .Float => try zcu.float_value(scalar_ty, 1.0),
            else => unreachable,
        },
        .Min => switch (scalar_ty.zig_type_tag(zcu)) {
            .Bool => Value.true,
            .Int => try scalar_ty.max_int_scalar(zcu, scalar_ty),
            .Float => try zcu.float_value(scalar_ty, std.math.nan(f128)),
            else => unreachable,
        },
        .Max => switch (scalar_ty.zig_type_tag(zcu)) {
            .Bool => Value.false,
            .Int => try scalar_ty.min_int_scalar(zcu, scalar_ty),
            .Float => try zcu.float_value(scalar_ty, std.math.nan(f128)),
            else => unreachable,
        },
    }, .Initializer);
    try writer.write_all(";\n");

    const v = try Vectorize.start(f, inst, writer, operand_ty);
    try f.write_cvalue(writer, accum, .Other);
    switch (op) {
        .builtin => |func| {
            try writer.print(" = zig_{s}_", .{func.operation});
            try f.object.dg.render_type_for_builtin_fn_name(writer, scalar_ty);
            try writer.write_byte('(');
            try f.write_cvalue(writer, accum, .FunctionArgument);
            try writer.write_all(", ");
            try f.write_cvalue(writer, operand, .Other);
            try v.elem(f, writer);
            try f.object.dg.render_builtin_info(writer, scalar_ty, func.info);
            try writer.write_byte(')');
        },
        .infix => |ass| {
            try writer.write_all(ass);
            try f.write_cvalue(writer, operand, .Other);
            try v.elem(f, writer);
        },
        .ternary => |cmp| {
            try writer.write_all(" = ");
            try f.write_cvalue(writer, accum, .Other);
            try writer.write_all(cmp);
            try f.write_cvalue(writer, operand, .Other);
            try v.elem(f, writer);
            try writer.write_all(" ? ");
            try f.write_cvalue(writer, accum, .Other);
            try writer.write_all(" : ");
            try f.write_cvalue(writer, operand, .Other);
            try v.elem(f, writer);
        },
    }
    try writer.write_all(";\n");
    try v.end(f, inst, writer);

    return accum;
}

fn air_aggregate_init(f: *Function, inst: Air.Inst.Index) !CValue {
    const zcu = f.object.dg.zcu;
    const ip = &zcu.intern_pool;
    const ty_pl = f.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const inst_ty = f.type_of_index(inst);
    const len = @as(usize, @int_cast(inst_ty.array_len(zcu)));
    const elements = @as([]const Air.Inst.Ref, @ptr_cast(f.air.extra[ty_pl.payload..][0..len]));
    const gpa = f.object.dg.gpa;
    const resolved_elements = try gpa.alloc(CValue, elements.len);
    defer gpa.free(resolved_elements);
    for (resolved_elements, elements) |*resolved_element, element| {
        resolved_element.* = try f.resolve_inst(element);
    }
    {
        var bt = iterate_big_tomb(f, inst);
        for (elements) |element| {
            try bt.feed(element);
        }
    }

    const writer = f.object.writer();
    const local = try f.alloc_local(inst, inst_ty);
    switch (ip.index_to_key(inst_ty.to_intern())) {
        inline .array_type, .vector_type => |info, tag| {
            const a: Assignment = .{
                .ctype = try f.ctype_from_type(Type.from_interned(info.child), .complete),
            };
            for (resolved_elements, 0..) |element, i| {
                try a.restart(f, writer);
                try f.write_cvalue(writer, local, .Other);
                try writer.print("[{d}]", .{i});
                try a.assign(f, writer);
                try f.write_cvalue(writer, element, .Other);
                try a.end(f, writer);
            }
            if (tag == .array_type and info.sentinel != .none) {
                try a.restart(f, writer);
                try f.write_cvalue(writer, local, .Other);
                try writer.print("[{d}]", .{info.len});
                try a.assign(f, writer);
                try f.object.dg.render_value(writer, Value.from_interned(info.sentinel), .Other);
                try a.end(f, writer);
            }
        },
        .struct_type => {
            const loaded_struct = ip.load_struct_type(inst_ty.to_intern());
            switch (loaded_struct.layout) {
                .auto, .@"extern" => {
                    var field_it = loaded_struct.iterate_runtime_order(ip);
                    while (field_it.next()) |field_index| {
                        const field_ty = Type.from_interned(loaded_struct.field_types.get(ip)[field_index]);
                        if (!field_ty.has_runtime_bits_ignore_comptime(zcu)) continue;

                        const a = try Assignment.start(f, writer, try f.ctype_from_type(field_ty, .complete));
                        try f.write_cvalue_member(writer, local, if (loaded_struct.field_name(ip, field_index).unwrap()) |field_name|
                            .{ .identifier = field_name.to_slice(ip) }
                        else
                            .{ .field = field_index });
                        try a.assign(f, writer);
                        try f.write_cvalue(writer, resolved_elements[field_index], .Other);
                        try a.end(f, writer);
                    }
                },
                .@"packed" => {
                    try f.write_cvalue(writer, local, .Other);
                    try writer.write_all(" = ");
                    const int_info = inst_ty.int_info(zcu);

                    const bit_offset_ty = try zcu.int_type(.unsigned, Type.smallest_unsigned_bits(int_info.bits - 1));

                    var bit_offset: u64 = 0;

                    var empty = true;
                    for (0..elements.len) |field_index| {
                        if (inst_ty.struct_field_is_comptime(field_index, zcu)) continue;
                        const field_ty = inst_ty.struct_field_type(field_index, zcu);
                        if (!field_ty.has_runtime_bits_ignore_comptime(zcu)) continue;

                        if (!empty) {
                            try writer.write_all("zig_or_");
                            try f.object.dg.render_type_for_builtin_fn_name(writer, inst_ty);
                            try writer.write_byte('(');
                        }
                        empty = false;
                    }
                    empty = true;
                    for (resolved_elements, 0..) |element, field_index| {
                        if (inst_ty.struct_field_is_comptime(field_index, zcu)) continue;
                        const field_ty = inst_ty.struct_field_type(field_index, zcu);
                        if (!field_ty.has_runtime_bits_ignore_comptime(zcu)) continue;

                        if (!empty) try writer.write_all(", ");
                        // TODO: Skip this entire shift if val is 0?
                        try writer.write_all("zig_shlw_");
                        try f.object.dg.render_type_for_builtin_fn_name(writer, inst_ty);
                        try writer.write_byte('(');

                        if (inst_ty.is_abi_int(zcu) and (field_ty.is_abi_int(zcu) or field_ty.is_ptr_at_runtime(zcu))) {
                            try f.render_int_cast(writer, inst_ty, element, .{}, field_ty, .FunctionArgument);
                        } else {
                            try writer.write_byte('(');
                            try f.render_type(writer, inst_ty);
                            try writer.write_byte(')');
                            if (field_ty.is_ptr_at_runtime(zcu)) {
                                try writer.write_byte('(');
                                try f.render_type(writer, switch (int_info.signedness) {
                                    .unsigned => Type.usize,
                                    .signed => Type.isize,
                                });
                                try writer.write_byte(')');
                            }
                            try f.write_cvalue(writer, element, .Other);
                        }

                        try writer.print(", {}", .{
                            try f.fmt_int_literal(try zcu.int_value(bit_offset_ty, bit_offset)),
                        });
                        try f.object.dg.render_builtin_info(writer, inst_ty, .bits);
                        try writer.write_byte(')');
                        if (!empty) try writer.write_byte(')');

                        bit_offset += field_ty.bit_size(zcu);
                        empty = false;
                    }
                    try writer.write_all(";\n");
                },
            }
        },
        .anon_struct_type => |anon_struct_info| for (0..anon_struct_info.types.len) |field_index| {
            if (anon_struct_info.values.get(ip)[field_index] != .none) continue;
            const field_ty = Type.from_interned(anon_struct_info.types.get(ip)[field_index]);
            if (!field_ty.has_runtime_bits_ignore_comptime(zcu)) continue;

            const a = try Assignment.start(f, writer, try f.ctype_from_type(field_ty, .complete));
            try f.write_cvalue_member(writer, local, if (anon_struct_info.field_name(ip, field_index).unwrap()) |field_name|
                .{ .identifier = field_name.to_slice(ip) }
            else
                .{ .field = field_index });
            try a.assign(f, writer);
            try f.write_cvalue(writer, resolved_elements[field_index], .Other);
            try a.end(f, writer);
        },
        else => unreachable,
    }

    return local;
}

fn air_union_init(f: *Function, inst: Air.Inst.Index) !CValue {
    const zcu = f.object.dg.zcu;
    const ip = &zcu.intern_pool;
    const ty_pl = f.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = f.air.extra_data(Air.UnionInit, ty_pl.payload).data;

    const union_ty = f.type_of_index(inst);
    const loaded_union = ip.load_union_type(union_ty.to_intern());
    const field_name = loaded_union.load_tag_type(ip).names.get(ip)[extra.field_index];
    const payload_ty = f.type_of(extra.init);
    const payload = try f.resolve_inst(extra.init);
    try reap(f, inst, &.{extra.init});

    const writer = f.object.writer();
    const local = try f.alloc_local(inst, union_ty);
    if (loaded_union.get_layout(ip) == .@"packed") return f.move_cvalue(inst, union_ty, payload);

    const field: CValue = if (union_ty.union_tag_type_safety(zcu)) |tag_ty| field: {
        const layout = union_ty.union_get_layout(zcu);
        if (layout.tag_size != 0) {
            const field_index = tag_ty.enum_field_index(field_name, zcu).?;
            const tag_val = try zcu.enum_value_field_index(tag_ty, field_index);

            const a = try Assignment.start(f, writer, try f.ctype_from_type(tag_ty, .complete));
            try f.write_cvalue_member(writer, local, .{ .identifier = "tag" });
            try a.assign(f, writer);
            try writer.print("{}", .{try f.fmt_int_literal(try tag_val.int_from_enum(tag_ty, zcu))});
            try a.end(f, writer);
        }
        break :field .{ .payload_identifier = field_name.to_slice(ip) };
    } else .{ .identifier = field_name.to_slice(ip) };

    const a = try Assignment.start(f, writer, try f.ctype_from_type(payload_ty, .complete));
    try f.write_cvalue_member(writer, local, field);
    try a.assign(f, writer);
    try f.write_cvalue(writer, payload, .Other);
    try a.end(f, writer);
    return local;
}

fn air_prefetch(f: *Function, inst: Air.Inst.Index) !CValue {
    const zcu = f.object.dg.zcu;
    const prefetch = f.air.instructions.items(.data)[@int_from_enum(inst)].prefetch;

    const ptr_ty = f.type_of(prefetch.ptr);
    const ptr = try f.resolve_inst(prefetch.ptr);
    try reap(f, inst, &.{prefetch.ptr});

    const writer = f.object.writer();
    switch (prefetch.cache) {
        .data => {
            try writer.write_all("zig_prefetch(");
            if (ptr_ty.is_slice(zcu))
                try f.write_cvalue_member(writer, ptr, .{ .identifier = "ptr" })
            else
                try f.write_cvalue(writer, ptr, .FunctionArgument);
            try writer.print(", {d}, {d});\n", .{ @int_from_enum(prefetch.rw), prefetch.locality });
        },
        // The available prefetch intrinsics do not accept a cache argument; only
        // address, rw, and locality.
        .instruction => {},
    }

    return .none;
}

fn air_wasm_memory_size(f: *Function, inst: Air.Inst.Index) !CValue {
    const pl_op = f.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;

    const writer = f.object.writer();
    const inst_ty = f.type_of_index(inst);
    const local = try f.alloc_local(inst, inst_ty);
    try f.write_cvalue(writer, local, .Other);

    try writer.write_all(" = ");
    try writer.print("zig_wasm_memory_size({d});\n", .{pl_op.payload});

    return local;
}

fn air_wasm_memory_grow(f: *Function, inst: Air.Inst.Index) !CValue {
    const pl_op = f.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;

    const writer = f.object.writer();
    const inst_ty = f.type_of_index(inst);
    const operand = try f.resolve_inst(pl_op.operand);
    try reap(f, inst, &.{pl_op.operand});
    const local = try f.alloc_local(inst, inst_ty);
    try f.write_cvalue(writer, local, .Other);

    try writer.write_all(" = ");
    try writer.print("zig_wasm_memory_grow({d}, ", .{pl_op.payload});
    try f.write_cvalue(writer, operand, .FunctionArgument);
    try writer.write_all(");\n");
    return local;
}

fn air_mul_add(f: *Function, inst: Air.Inst.Index) !CValue {
    const zcu = f.object.dg.zcu;
    const pl_op = f.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
    const bin_op = f.air.extra_data(Air.Bin, pl_op.payload).data;

    const mulend1 = try f.resolve_inst(bin_op.lhs);
    const mulend2 = try f.resolve_inst(bin_op.rhs);
    const addend = try f.resolve_inst(pl_op.operand);
    try reap(f, inst, &.{ bin_op.lhs, bin_op.rhs, pl_op.operand });

    const inst_ty = f.type_of_index(inst);
    const inst_scalar_ty = inst_ty.scalar_type(zcu);

    const writer = f.object.writer();
    const local = try f.alloc_local(inst, inst_ty);
    const v = try Vectorize.start(f, inst, writer, inst_ty);
    try f.write_cvalue(writer, local, .Other);
    try v.elem(f, writer);
    try writer.write_all(" = zig_fma_");
    try f.object.dg.render_type_for_builtin_fn_name(writer, inst_scalar_ty);
    try writer.write_byte('(');
    try f.write_cvalue(writer, mulend1, .FunctionArgument);
    try v.elem(f, writer);
    try writer.write_all(", ");
    try f.write_cvalue(writer, mulend2, .FunctionArgument);
    try v.elem(f, writer);
    try writer.write_all(", ");
    try f.write_cvalue(writer, addend, .FunctionArgument);
    try v.elem(f, writer);
    try writer.write_all(");\n");
    try v.end(f, inst, writer);

    return local;
}

fn air_cva_start(f: *Function, inst: Air.Inst.Index) !CValue {
    const zcu = f.object.dg.zcu;
    const inst_ty = f.type_of_index(inst);
    const decl_index = f.object.dg.pass.decl;
    const decl = zcu.decl_ptr(decl_index);
    const function_ctype = try f.ctype_from_type(decl.type_of(zcu), .complete);
    const params_len = function_ctype.info(&f.object.dg.ctype_pool).function.param_ctypes.len;

    const writer = f.object.writer();
    const local = try f.alloc_local(inst, inst_ty);
    try writer.write_all("va_start(*(va_list *)&");
    try f.write_cvalue(writer, local, .Other);
    if (params_len > 0) {
        try writer.write_all(", ");
        try f.write_cvalue(writer, .{ .arg = params_len - 1 }, .FunctionArgument);
    }
    try writer.write_all(");\n");
    return local;
}

fn air_cva_arg(f: *Function, inst: Air.Inst.Index) !CValue {
    const ty_op = f.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

    const inst_ty = f.type_of_index(inst);
    const va_list = try f.resolve_inst(ty_op.operand);
    try reap(f, inst, &.{ty_op.operand});

    const writer = f.object.writer();
    const local = try f.alloc_local(inst, inst_ty);
    try f.write_cvalue(writer, local, .Other);
    try writer.write_all(" = va_arg(*(va_list *)");
    try f.write_cvalue(writer, va_list, .Other);
    try writer.write_all(", ");
    try f.render_type(writer, ty_op.ty.to_type());
    try writer.write_all(");\n");
    return local;
}

fn air_cva_end(f: *Function, inst: Air.Inst.Index) !CValue {
    const un_op = f.air.instructions.items(.data)[@int_from_enum(inst)].un_op;

    const va_list = try f.resolve_inst(un_op);
    try reap(f, inst, &.{un_op});

    const writer = f.object.writer();
    try writer.write_all("va_end(*(va_list *)");
    try f.write_cvalue(writer, va_list, .Other);
    try writer.write_all(");\n");
    return .none;
}

fn air_cva_copy(f: *Function, inst: Air.Inst.Index) !CValue {
    const ty_op = f.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

    const inst_ty = f.type_of_index(inst);
    const va_list = try f.resolve_inst(ty_op.operand);
    try reap(f, inst, &.{ty_op.operand});

    const writer = f.object.writer();
    const local = try f.alloc_local(inst, inst_ty);
    try writer.write_all("va_copy(*(va_list *)&");
    try f.write_cvalue(writer, local, .Other);
    try writer.write_all(", *(va_list *)");
    try f.write_cvalue(writer, va_list, .Other);
    try writer.write_all(");\n");
    return local;
}

fn to_memory_order(order: std.builtin.AtomicOrder) [:0]const u8 {
    return switch (order) {
        // Note: unordered is actually even less atomic than relaxed
        .unordered, .monotonic => "zig_memory_order_relaxed",
        .acquire => "zig_memory_order_acquire",
        .release => "zig_memory_order_release",
        .acq_rel => "zig_memory_order_acq_rel",
        .seq_cst => "zig_memory_order_seq_cst",
    };
}

fn write_memory_order(w: anytype, order: std.builtin.AtomicOrder) !void {
    return w.write_all(to_memory_order(order));
}

fn to_calling_convention(call_conv: std.builtin.CallingConvention) ?[]const u8 {
    return switch (call_conv) {
        .Stdcall => "stdcall",
        .Fastcall => "fastcall",
        .Vectorcall => "vectorcall",
        else => null,
    };
}

fn to_atomic_rmw_suffix(order: std.builtin.AtomicRmwOp) []const u8 {
    return switch (order) {
        .Xchg => "xchg",
        .Add => "add",
        .Sub => "sub",
        .And => "and",
        .Nand => "nand",
        .Or => "or",
        .Xor => "xor",
        .Max => "max",
        .Min => "min",
    };
}

const ArrayListWriter = ErrorOnlyGenericWriter(std.ArrayList(u8).Writer.Error);

fn array_list_writer(list: *std.ArrayList(u8)) ArrayListWriter {
    return .{ .context = .{
        .context = list,
        .write_fn = struct {
            fn write(context: *const anyopaque, bytes: []const u8) anyerror!usize {
                const l: *std.ArrayList(u8) = @align_cast(@constCast(@ptr_cast(context)));
                return l.writer().write(bytes);
            }
        }.write,
    } };
}

fn IndentWriter(comptime UnderlyingWriter: type) type {
    return struct {
        const Self = @This();
        pub const Error = UnderlyingWriter.Error;
        pub const Writer = ErrorOnlyGenericWriter(Error);

        pub const indent_delta = 1;

        underlying_writer: UnderlyingWriter,
        indent_count: usize = 0,
        current_line_empty: bool = true,

        pub fn writer(self: *Self) Writer {
            return .{ .context = .{
                .context = self,
                .write_fn = write_any,
            } };
        }

        pub fn write(self: *Self, bytes: []const u8) Error!usize {
            if (bytes.len == 0) return @as(usize, 0);

            const current_indent = self.indent_count * Self.indent_delta;
            if (self.current_line_empty and current_indent > 0) {
                try self.underlying_writer.write_byte_ntimes(' ', current_indent);
            }
            self.current_line_empty = false;

            return self.write_no_indent(bytes);
        }

        fn write_any(context: *const anyopaque, bytes: []const u8) anyerror!usize {
            const self: *Self = @align_cast(@constCast(@ptr_cast(context)));
            return self.write(bytes);
        }

        pub fn insert_newline(self: *Self) Error!void {
            _ = try self.write_no_indent("\n");
        }

        pub fn push_indent(self: *Self) void {
            self.indent_count += 1;
        }

        pub fn pop_indent(self: *Self) void {
            assert(self.indent_count != 0);
            self.indent_count -= 1;
        }

        fn write_no_indent(self: *Self, bytes: []const u8) Error!usize {
            if (bytes.len == 0) return @as(usize, 0);

            try self.underlying_writer.write_all(bytes);
            if (bytes[bytes.len - 1] == '\n') {
                self.current_line_empty = true;
            }
            return bytes.len;
        }
    };
}

/// A wrapper around `std.io.AnyWriter` that maintains a generic error set while
/// erasing the rest of the implementation. This is intended to avoid duplicate
/// generic instantiations for writer types which share the same error set, while
/// maintaining ease of error handling.
fn ErrorOnlyGenericWriter(comptime Error: type) type {
    return std.io.GenericWriter(std.io.AnyWriter, Error, struct {
        fn write(context: std.io.AnyWriter, bytes: []const u8) Error!usize {
            return @errorCast(context.write(bytes));
        }
    }.write);
}

fn to_cint_bits(zig_bits: u32) ?u32 {
    for (&[_]u8{ 8, 16, 32, 64, 128 }) |c_bits| {
        if (zig_bits <= c_bits) {
            return c_bits;
        }
    }
    return null;
}

fn sign_abbrev(signedness: std.builtin.Signedness) u8 {
    return switch (signedness) {
        .signed => 'i',
        .unsigned => 'u',
    };
}

fn compiler_rt_abbrev(ty: Type, zcu: *Zcu, target: std.Target) []const u8 {
    return if (ty.is_int(zcu)) switch (ty.int_info(zcu).bits) {
        1...32 => "si",
        33...64 => "di",
        65...128 => "ti",
        else => unreachable,
    } else if (ty.is_runtime_float()) switch (ty.float_bits(target)) {
        16 => "hf",
        32 => "sf",
        64 => "df",
        80 => "xf",
        128 => "tf",
        else => unreachable,
    } else unreachable;
}

fn compare_operator_abbrev(operator: std.math.CompareOperator) []const u8 {
    return switch (operator) {
        .lt => "lt",
        .lte => "le",
        .eq => "eq",
        .gte => "ge",
        .gt => "gt",
        .neq => "ne",
    };
}

fn compare_operator_c(operator: std.math.CompareOperator) []const u8 {
    return switch (operator) {
        .lt => " < ",
        .lte => " <= ",
        .eq => " == ",
        .gte => " >= ",
        .gt => " > ",
        .neq => " != ",
    };
}

fn StringLiteral(comptime WriterType: type) type {
    // MSVC throws C2078 if an array of size 65536 or greater is initialized with a string literal,
    // regardless of the length of the string literal initializing it. Array initializer syntax is
    // used instead.
    // C99 only requires 4095.
    const max_string_initializer_len = @min(65535, 4095);

    // MSVC has a length limit of 16380 per string literal (before concatenation)
    // C99 only requires 4095.
    const max_char_len = 4;
    const max_literal_len = @min(16380 - max_char_len, 4095);

    return struct {
        len: u64,
        cur_len: u64 = 0,
        counting_writer: std.io.CountingWriter(WriterType),

        pub const Error = WriterType.Error;

        const Self = @This();

        pub fn start(self: *Self) Error!void {
            const writer = self.counting_writer.writer();
            if (self.len <= max_string_initializer_len) {
                try writer.write_byte('\"');
            } else {
                try writer.write_byte('{');
            }
        }

        pub fn end(self: *Self) Error!void {
            const writer = self.counting_writer.writer();
            if (self.len <= max_string_initializer_len) {
                try writer.write_byte('\"');
            } else {
                try writer.write_byte('}');
            }
        }

        fn write_string_literal_char(writer: anytype, c: u8) !void {
            switch (c) {
                7 => try writer.write_all("\\a"),
                8 => try writer.write_all("\\b"),
                '\t' => try writer.write_all("\\t"),
                '\n' => try writer.write_all("\\n"),
                11 => try writer.write_all("\\v"),
                12 => try writer.write_all("\\f"),
                '\r' => try writer.write_all("\\r"),
                '"', '\'', '?', '\\' => try writer.print("\\{c}", .{c}),
                else => switch (c) {
                    ' '...'~' => try writer.write_byte(c),
                    else => try writer.print("\\{o:0>3}", .{c}),
                },
            }
        }

        pub fn write_char(self: *Self, c: u8) Error!void {
            const writer = self.counting_writer.writer();
            if (self.len <= max_string_initializer_len) {
                if (self.cur_len == 0 and self.counting_writer.bytes_written > 1)
                    try writer.write_all("\"\"");

                const len = self.counting_writer.bytes_written;
                try write_string_literal_char(writer, c);

                const char_length = self.counting_writer.bytes_written - len;
                assert(char_length <= max_char_len);
                self.cur_len += char_length;

                if (self.cur_len >= max_literal_len) self.cur_len = 0;
            } else {
                if (self.counting_writer.bytes_written > 1) try writer.write_byte(',');
                try writer.print("'\\x{x}'", .{c});
            }
        }
    };
}

fn string_literal(
    child_stream: anytype,
    len: u64,
) StringLiteral(@TypeOf(child_stream)) {
    return .{
        .len = len,
        .counting_writer = std.io.counting_writer(child_stream),
    };
}

const FormatStringContext = struct { str: []const u8, sentinel: ?u8 };
fn format_string_literal(
    data: FormatStringContext,
    comptime fmt: []const u8,
    _: std.fmt.FormatOptions,
    writer: anytype,
) @TypeOf(writer).Error!void {
    if (fmt.len != 1 or fmt[0] != 's') @compile_error("Invalid fmt: " ++ fmt);

    var literal = string_literal(writer, data.str.len + @int_from_bool(data.sentinel != null));
    try literal.start();
    for (data.str) |c| try literal.write_char(c);
    if (data.sentinel) |sentinel| if (sentinel != 0) try literal.write_char(sentinel);
    try literal.end();
}

fn fmt_string_literal(str: []const u8, sentinel: ?u8) std.fmt.Formatter(format_string_literal) {
    return .{ .data = .{ .str = str, .sentinel = sentinel } };
}

fn undef_pattern(comptime IntType: type) IntType {
    const int_info = @typeInfo(IntType).Int;
    const UnsignedType = std.meta.Int(.unsigned, int_info.bits);
    return @as(IntType, @bit_cast(@as(UnsignedType, (1 << (int_info.bits | 1)) / 3)));
}

const FormatIntLiteralContext = struct {
    dg: *DeclGen,
    int_info: InternPool.Key.IntType,
    kind: CType.Kind,
    ctype: CType,
    val: Value,
};
fn format_int_literal(
    data: FormatIntLiteralContext,
    comptime fmt: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) @TypeOf(writer).Error!void {
    const zcu = data.dg.zcu;
    const target = &data.dg.mod.resolved_target.result;
    const ctype_pool = &data.dg.ctype_pool;

    const ExpectedContents = struct {
        const base = 10;
        const bits = 128;
        const limbs_count = BigInt.calc_twos_comp_limb_count(bits);

        undef_limbs: [limbs_count]BigIntLimb,
        wrap_limbs: [limbs_count]BigIntLimb,
        to_string_buf: [bits]u8,
        to_string_limbs: [BigInt.calc_to_string_limbs_buffer_len(limbs_count, base)]BigIntLimb,
    };
    var stack align(@alignOf(ExpectedContents)) =
        std.heap.stack_fallback(@size_of(ExpectedContents), data.dg.gpa);
    const allocator = stack.get();

    var undef_limbs: []BigIntLimb = &.{};
    defer allocator.free(undef_limbs);

    var int_buf: Value.BigIntSpace = undefined;
    const int = if (data.val.is_undef_deep(zcu)) blk: {
        undef_limbs = try allocator.alloc(BigIntLimb, BigInt.calc_twos_comp_limb_count(data.int_info.bits));
        @memset(undef_limbs, undef_pattern(BigIntLimb));

        var undef_int = BigInt.Mutable{
            .limbs = undef_limbs,
            .len = undef_limbs.len,
            .positive = true,
        };
        undef_int.truncate(undef_int.to_const(), data.int_info.signedness, data.int_info.bits);
        break :blk undef_int.to_const();
    } else data.val.to_big_int(&int_buf, zcu);
    assert(int.fits_in_twos_comp(data.int_info.signedness, data.int_info.bits));

    const c_bits: usize = @int_cast(data.ctype.byte_size(ctype_pool, data.dg.mod) * 8);
    var one_limbs: [BigInt.calc_limb_len(1)]BigIntLimb = undefined;
    const one = BigInt.Mutable.init(&one_limbs, 1).to_const();

    var wrap = BigInt.Mutable{
        .limbs = try allocator.alloc(BigIntLimb, BigInt.calc_twos_comp_limb_count(c_bits)),
        .len = undefined,
        .positive = undefined,
    };
    defer allocator.free(wrap.limbs);

    const c_limb_info: struct {
        ctype: CType,
        count: usize,
        endian: std.builtin.Endian,
        homogeneous: bool,
    } = switch (data.ctype.info(ctype_pool)) {
        .basic => |basic_info| switch (basic_info) {
            else => .{
                .ctype = CType.void,
                .count = 1,
                .endian = .little,
                .homogeneous = true,
            },
            .zig_u128, .zig_i128 => .{
                .ctype = CType.u64,
                .count = 2,
                .endian = .big,
                .homogeneous = false,
            },
        },
        .array => |array_info| .{
            .ctype = array_info.elem_ctype,
            .count = @int_cast(array_info.len),
            .endian = target.cpu.arch.endian(),
            .homogeneous = true,
        },
        else => unreachable,
    };
    if (c_limb_info.count == 1) {
        if (wrap.add_wrap(int, one, data.int_info.signedness, c_bits) or
            data.int_info.signedness == .signed and wrap.sub_wrap(int, one, data.int_info.signedness, c_bits))
            return writer.print("{s}_{s}", .{
                data.ctype.get_standard_define_abbrev() orelse return writer.print("zig_{s}Int_{c}{d}", .{
                    if (int.positive) "max" else "min", sign_abbrev(data.int_info.signedness), c_bits,
                }),
                if (int.positive) "MAX" else "MIN",
            });

        if (!int.positive) try writer.write_byte('-');
        try data.ctype.render_literal_prefix(writer, data.kind, ctype_pool);

        const style: struct { base: u8, case: std.fmt.Case = undefined } = switch (fmt.len) {
            0 => .{ .base = 10 },
            1 => switch (fmt[0]) {
                'b' => style: {
                    try writer.write_all("0b");
                    break :style .{ .base = 2 };
                },
                'o' => style: {
                    try writer.write_byte('0');
                    break :style .{ .base = 8 };
                },
                'd' => .{ .base = 10 },
                'x', 'X' => |base| style: {
                    try writer.write_all("0x");
                    break :style .{ .base = 16, .case = switch (base) {
                        'x' => .lower,
                        'X' => .upper,
                        else => unreachable,
                    } };
                },
                else => @compile_error("Invalid fmt: " ++ fmt),
            },
            else => @compile_error("Invalid fmt: " ++ fmt),
        };

        const string = try int.abs().to_string_alloc(allocator, style.base, style.case);
        defer allocator.free(string);
        try writer.write_all(string);
    } else {
        try data.ctype.render_literal_prefix(writer, data.kind, ctype_pool);
        wrap.convert_to_twos_complement(int, data.int_info.signedness, c_bits);
        @memset(wrap.limbs[wrap.len..], 0);
        wrap.len = wrap.limbs.len;
        const limbs_per_c_limb = @div_exact(wrap.len, c_limb_info.count);

        var c_limb_int_info = std.builtin.Type.Int{
            .signedness = undefined,
            .bits = @as(u16, @int_cast(@div_exact(c_bits, c_limb_info.count))),
        };
        var c_limb_ctype: CType = undefined;

        var limb_offset: usize = 0;
        const most_significant_limb_i = wrap.len - limbs_per_c_limb;
        while (limb_offset < wrap.len) : (limb_offset += limbs_per_c_limb) {
            const limb_i = switch (c_limb_info.endian) {
                .little => limb_offset,
                .big => most_significant_limb_i - limb_offset,
            };
            var c_limb_mut = BigInt.Mutable{
                .limbs = wrap.limbs[limb_i..][0..limbs_per_c_limb],
                .len = undefined,
                .positive = true,
            };
            c_limb_mut.normalize(limbs_per_c_limb);

            if (limb_i == most_significant_limb_i and
                !c_limb_info.homogeneous and data.int_info.signedness == .signed)
            {
                // most significant limb is actually signed
                c_limb_int_info.signedness = .signed;
                c_limb_ctype = c_limb_info.ctype.to_signed();

                c_limb_mut.positive = wrap.positive;
                c_limb_mut.truncate(
                    c_limb_mut.to_const(),
                    .signed,
                    data.int_info.bits - limb_i * @bitSizeOf(BigIntLimb),
                );
            } else {
                c_limb_int_info.signedness = .unsigned;
                c_limb_ctype = c_limb_info.ctype;
            }

            if (limb_offset > 0) try writer.write_all(", ");
            try format_int_literal(.{
                .dg = data.dg,
                .int_info = c_limb_int_info,
                .kind = data.kind,
                .ctype = c_limb_ctype,
                .val = try zcu.int_value_big(Type.comptime_int, c_limb_mut.to_const()),
            }, fmt, options, writer);
        }
    }
    try data.ctype.render_literal_suffix(writer, ctype_pool);
}

const Materialize = struct {
    local: CValue,

    pub fn start(f: *Function, inst: Air.Inst.Index, ty: Type, value: CValue) !Materialize {
        return .{ .local = switch (value) {
            .local_ref, .constant, .decl_ref, .undef => try f.move_cvalue(inst, ty, value),
            .new_local => |local| .{ .local = local },
            else => value,
        } };
    }

    pub fn mat(self: Materialize, f: *Function, writer: anytype) !void {
        try f.write_cvalue(writer, self.local, .Other);
    }

    pub fn end(self: Materialize, f: *Function, inst: Air.Inst.Index) !void {
        try f.free_cvalue(inst, self.local);
    }
};

const Assignment = struct {
    ctype: CType,

    pub fn start(f: *Function, writer: anytype, ctype: CType) !Assignment {
        const self: Assignment = .{ .ctype = ctype };
        try self.restart(f, writer);
        return self;
    }

    pub fn restart(self: Assignment, f: *Function, writer: anytype) !void {
        switch (self.strategy(f)) {
            .assign => {},
            .memcpy => try writer.write_all("memcpy("),
        }
    }

    pub fn assign(self: Assignment, f: *Function, writer: anytype) !void {
        switch (self.strategy(f)) {
            .assign => try writer.write_all(" = "),
            .memcpy => try writer.write_all(", "),
        }
    }

    pub fn end(self: Assignment, f: *Function, writer: anytype) !void {
        switch (self.strategy(f)) {
            .assign => {},
            .memcpy => {
                try writer.write_all(", sizeof(");
                try f.render_ctype(writer, self.ctype);
                try writer.write_all("))");
            },
        }
        try writer.write_all(";\n");
    }

    fn strategy(self: Assignment, f: *Function) enum { assign, memcpy } {
        return switch (self.ctype.info(&f.object.dg.ctype_pool)) {
            else => .assign,
            .array, .vector => .memcpy,
        };
    }
};

const Vectorize = struct {
    index: CValue = .none,

    pub fn start(f: *Function, inst: Air.Inst.Index, writer: anytype, ty: Type) !Vectorize {
        const zcu = f.object.dg.zcu;
        return if (ty.zig_type_tag(zcu) == .Vector) index: {
            const local = try f.alloc_local(inst, Type.usize);

            try writer.write_all("for (");
            try f.write_cvalue(writer, local, .Other);
            try writer.print(" = {d}; ", .{try f.fmt_int_literal(try zcu.int_value(Type.usize, 0))});
            try f.write_cvalue(writer, local, .Other);
            try writer.print(" < {d}; ", .{try f.fmt_int_literal(try zcu.int_value(Type.usize, ty.vector_len(zcu)))});
            try f.write_cvalue(writer, local, .Other);
            try writer.print(" += {d}) {{\n", .{try f.fmt_int_literal(try zcu.int_value(Type.usize, 1))});
            f.object.indent_writer.push_indent();

            break :index .{ .index = local };
        } else .{};
    }

    pub fn elem(self: Vectorize, f: *Function, writer: anytype) !void {
        if (self.index != .none) {
            try writer.write_byte('[');
            try f.write_cvalue(writer, self.index, .Other);
            try writer.write_byte(']');
        }
    }

    pub fn end(self: Vectorize, f: *Function, inst: Air.Inst.Index, writer: anytype) !void {
        if (self.index != .none) {
            f.object.indent_writer.pop_indent();
            try writer.write_all("}\n");
            try free_local(f, inst, self.index.new_local, null);
        }
    }
};

fn lowers_to_array(ty: Type, zcu: *Zcu) bool {
    return switch (ty.zig_type_tag(zcu)) {
        .Array, .Vector => return true,
        else => return ty.is_abi_int(zcu) and to_cint_bits(@as(u32, @int_cast(ty.bit_size(zcu)))) == null,
    };
}

fn reap(f: *Function, inst: Air.Inst.Index, operands: []const Air.Inst.Ref) !void {
    assert(operands.len <= Liveness.bpi - 1);
    var tomb_bits = f.liveness.get_tomb_bits(inst);
    for (operands) |operand| {
        const dies = @as(u1, @truncate(tomb_bits)) != 0;
        tomb_bits >>= 1;
        if (!dies) continue;
        try die(f, inst, operand);
    }
}

fn die(f: *Function, inst: Air.Inst.Index, ref: Air.Inst.Ref) !void {
    const ref_inst = ref.to_index() orelse return;
    const c_value = (f.value_map.fetch_remove(ref) orelse return).value;
    const local_index = switch (c_value) {
        .new_local, .local => |l| l,
        else => return,
    };
    try free_local(f, inst, local_index, ref_inst);
}

fn free_local(f: *Function, inst: ?Air.Inst.Index, local_index: LocalIndex, ref_inst: ?Air.Inst.Index) !void {
    const gpa = f.object.dg.gpa;
    const local = &f.locals.items[local_index];
    if (inst) |i| {
        if (ref_inst) |operand| {
            log.debug("%{d}: freeing t{d} (operand %{d})", .{ @int_from_enum(i), local_index, operand });
        } else {
            log.debug("%{d}: freeing t{d}", .{ @int_from_enum(i), local_index });
        }
    } else {
        if (ref_inst) |operand| {
            log.debug("freeing t{d} (operand %{d})", .{ local_index, operand });
        } else {
            log.debug("freeing t{d}", .{local_index});
        }
    }
    const gop = try f.free_locals_map.get_or_put(gpa, local.get_type());
    if (!gop.found_existing) gop.value_ptr.* = .{};
    if (std.debug.runtime_safety) {
        // If this trips, an unfreeable allocation was attempted to be freed.
        assert(!f.allocs.contains(local_index));
    }
    // If this trips, it means a local is being inserted into the
    // free_locals map while it already exists in the map, which is not
    // allowed.
    try gop.value_ptr.put_no_clobber(gpa, local_index, {});
}

const BigTomb = struct {
    f: *Function,
    inst: Air.Inst.Index,
    lbt: Liveness.BigTomb,

    fn feed(bt: *BigTomb, op_ref: Air.Inst.Ref) !void {
        const dies = bt.lbt.feed();
        if (!dies) return;
        try die(bt.f, bt.inst, op_ref);
    }
};

fn iterate_big_tomb(f: *Function, inst: Air.Inst.Index) BigTomb {
    return .{
        .f = f,
        .inst = inst,
        .lbt = f.liveness.iterate_big_tomb(inst),
    };
}

/// A naive clone of this map would create copies of the ArrayList which is
/// stored in the values. This function additionally clones the values.
fn clone_free_locals_map(gpa: mem.Allocator, map: *LocalsMap) !LocalsMap {
    var cloned = try map.clone(gpa);
    const values = cloned.values();
    var i: usize = 0;
    errdefer {
        cloned.deinit(gpa);
        while (i > 0) {
            i -= 1;
            values[i].deinit(gpa);
        }
    }
    while (i < values.len) : (i += 1) {
        values[i] = try values[i].clone(gpa);
    }
    return cloned;
}

fn deinit_free_locals_map(gpa: mem.Allocator, map: *LocalsMap) void {
    for (map.values()) |*value| {
        value.deinit(gpa);
    }
    map.deinit(gpa);
}
