//! This type exists only for legacy purposes, and will be removed in the future.
//! It is a thin wrapper around a `Value` which also, redundantly, stores its `Type`.

const std = @import("std");
const Type = @import("type.zig").Type;
const Value = @import("Value.zig");
const Zcu = @import("Module.zig");
const Module = Zcu;
const Sema = @import("Sema.zig");
const InternPool = @import("InternPool.zig");
const Allocator = std.mem.Allocator;
const Target = std.Target;

const max_aggregate_items = 100;
const max_string_len = 256;

pub const FormatContext = struct {
    val: Value,
    mod: *Module,
    opt_sema: ?*Sema,
    depth: u8,
};

pub fn format(
    ctx: FormatContext,
    comptime fmt: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = options;
    comptime std.debug.assert(fmt.len == 0);
    return print(ctx.val, writer, ctx.depth, ctx.mod, ctx.opt_sema) catch |err| switch (err) {
        error.OutOfMemory => @panic("OOM"), // We're not allowed to return this from a format function
        error.ComptimeBreak, error.ComptimeReturn => unreachable,
        error.AnalysisFail, error.NeededSourceLocation => unreachable, // TODO: re-evaluate when we use `opt_sema` more fully
        else => |e| return e,
    };
}

pub fn print(
    val: Value,
    writer: anytype,
    level: u8,
    mod: *Module,
    /// If this `Sema` is provided, we will recurse through pointers where possible to provide friendly output.
    opt_sema: ?*Sema,
) (@TypeOf(writer).Error || Module.CompileError)!void {
    const ip = &mod.intern_pool;
    switch (ip.index_to_key(val.to_intern())) {
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
        => try Type.print(val.to_type(), writer, mod),
        .undef => try writer.write_all("undefined"),
        .simple_value => |simple_value| switch (simple_value) {
            .void => try writer.write_all("{}"),
            .empty_struct => try writer.write_all(".{}"),
            .generic_poison => try writer.write_all("(generic poison)"),
            else => try writer.write_all(@tag_name(simple_value)),
        },
        .variable => try writer.write_all("(variable)"),
        .extern_func => |extern_func| try writer.print("(extern function '{}')", .{
            mod.decl_ptr(extern_func.decl).name.fmt(ip),
        }),
        .func => |func| try writer.print("(function '{}')", .{
            mod.decl_ptr(func.owner_decl).name.fmt(ip),
        }),
        .int => |int| switch (int.storage) {
            inline .u64, .i64, .big_int => |x| try writer.print("{}", .{x}),
            .lazy_align => |ty| if (opt_sema) |sema| {
                const a = (try Type.from_interned(ty).abi_alignment_advanced(mod, .{ .sema = sema })).scalar;
                try writer.print("{}", .{a.to_byte_units() orelse 0});
            } else try writer.print("@alignOf({})", .{Type.from_interned(ty).fmt(mod)}),
            .lazy_size => |ty| if (opt_sema) |sema| {
                const s = (try Type.from_interned(ty).abi_size_advanced(mod, .{ .sema = sema })).scalar;
                try writer.print("{}", .{s});
            } else try writer.print("@size_of({})", .{Type.from_interned(ty).fmt(mod)}),
        },
        .err => |err| try writer.print("error.{}", .{
            err.name.fmt(ip),
        }),
        .error_union => |error_union| switch (error_union.val) {
            .err_name => |err_name| try writer.print("error.{}", .{
                err_name.fmt(ip),
            }),
            .payload => |payload| try print(Value.from_interned(payload), writer, level, mod, opt_sema),
        },
        .enum_literal => |enum_literal| try writer.print(".{}", .{
            enum_literal.fmt(ip),
        }),
        .enum_tag => |enum_tag| {
            const enum_type = ip.load_enum_type(val.type_of(mod).to_intern());
            if (enum_type.tag_value_index(ip, val.to_intern())) |tag_index| {
                return writer.print(".{i}", .{enum_type.names.get(ip)[tag_index].fmt(ip)});
            }
            if (level == 0) {
                return writer.write_all("@enumFromInt(...)");
            }
            try writer.write_all("@enumFromInt(");
            try print(Value.from_interned(enum_tag.int), writer, level - 1, mod, opt_sema);
            try writer.write_all(")");
        },
        .empty_enum_value => try writer.write_all("(empty enum value)"),
        .float => |float| switch (float.storage) {
            inline else => |x| try writer.print("{d}", .{@as(f64, @float_cast(x))}),
        },
        .slice => |slice| {
            const print_contents = switch (ip.get_backing_addr_tag(slice.ptr).?) {
                .field, .arr_elem, .eu_payload, .opt_payload => unreachable,
                .anon_decl, .comptime_alloc, .comptime_field => true,
                .decl, .int => false,
            };
            if (print_contents) {
                // TODO: eventually we want to load the slice as an array with `opt_sema`, but that's
                // currently not possible without e.g. triggering compile errors.
            }
            try print_ptr(Value.from_interned(slice.ptr), writer, level, mod, opt_sema);
            try writer.write_all("[0..");
            if (level == 0) {
                try writer.write_all("(...)");
            } else {
                try print(Value.from_interned(slice.len), writer, level - 1, mod, opt_sema);
            }
            try writer.write_all("]");
        },
        .ptr => {
            const print_contents = switch (ip.get_backing_addr_tag(val.to_intern()).?) {
                .field, .arr_elem, .eu_payload, .opt_payload => unreachable,
                .anon_decl, .comptime_alloc, .comptime_field => true,
                .decl, .int => false,
            };
            if (print_contents) {
                // TODO: eventually we want to load the pointer with `opt_sema`, but that's
                // currently not possible without e.g. triggering compile errors.
            }
            try print_ptr(val, writer, level, mod, opt_sema);
        },
        .opt => |opt| switch (opt.val) {
            .none => try writer.write_all("null"),
            else => |payload| try print(Value.from_interned(payload), writer, level, mod, opt_sema),
        },
        .aggregate => |aggregate| try print_aggregate(val, aggregate, false, writer, level, mod, opt_sema),
        .un => |un| {
            if (level == 0) {
                try writer.write_all(".{ ... }");
                return;
            }
            if (un.tag == .none) {
                const backing_ty = try val.type_of(mod).union_backing_type(mod);
                try writer.print("@bit_cast(@as({}, ", .{backing_ty.fmt(mod)});
                try print(Value.from_interned(un.val), writer, level - 1, mod, opt_sema);
                try writer.write_all("))");
            } else {
                try writer.write_all(".{ ");
                try print(Value.from_interned(un.tag), writer, level - 1, mod, opt_sema);
                try writer.write_all(" = ");
                try print(Value.from_interned(un.val), writer, level - 1, mod, opt_sema);
                try writer.write_all(" }");
            }
        },
        .memoized_call => unreachable,
    }
}

fn print_aggregate(
    val: Value,
    aggregate: InternPool.Key.Aggregate,
    is_ref: bool,
    writer: anytype,
    level: u8,
    zcu: *Zcu,
    opt_sema: ?*Sema,
) (@TypeOf(writer).Error || Module.CompileError)!void {
    if (level == 0) {
        if (is_ref) try writer.write_byte('&');
        return writer.write_all(".{ ... }");
    }
    const ip = &zcu.intern_pool;
    const ty = Type.from_interned(aggregate.ty);
    switch (ty.zig_type_tag(zcu)) {
        .Struct => if (!ty.is_tuple(zcu)) {
            if (is_ref) try writer.write_byte('&');
            if (ty.struct_field_count(zcu) == 0) {
                return writer.write_all(".{}");
            }
            try writer.write_all(".{ ");
            const max_len = @min(ty.struct_field_count(zcu), max_aggregate_items);
            for (0..max_len) |i| {
                if (i != 0) try writer.write_all(", ");
                const field_name = ty.struct_field_name(@int_cast(i), zcu).unwrap().?;
                try writer.print(".{i} = ", .{field_name.fmt(ip)});
                try print(try val.field_value(zcu, i), writer, level - 1, zcu, opt_sema);
            }
            try writer.write_all(" }");
            return;
        },
        .Array => {
            switch (aggregate.storage) {
                .bytes => |bytes| string: {
                    const len = ty.array_len_including_sentinel(zcu);
                    if (len == 0) break :string;
                    const slice = bytes.to_slice(if (bytes.at(len - 1, ip) == 0) len - 1 else len, ip);
                    try writer.print("\"{}\"", .{std.zig.fmt_escapes(slice)});
                    if (!is_ref) try writer.write_all(".*");
                    return;
                },
                .elems, .repeated_elem => {},
            }
            switch (ty.array_len(zcu)) {
                0 => {
                    if (is_ref) try writer.write_byte('&');
                    return writer.write_all(".{}");
                },
                1 => one_byte_str: {
                    // The repr isn't `bytes`, but we might still be able to print this as a string
                    if (ty.child_type(zcu).to_intern() != .u8_type) break :one_byte_str;
                    const elem_val = Value.from_interned(aggregate.storage.values()[0]);
                    if (elem_val.is_undef(zcu)) break :one_byte_str;
                    const byte = elem_val.to_unsigned_int(zcu);
                    try writer.print("\"{}\"", .{std.zig.fmt_escapes(&.{@int_cast(byte)})});
                    if (!is_ref) try writer.write_all(".*");
                    return;
                },
                else => {},
            }
        },
        .Vector => if (ty.array_len(zcu) == 0) {
            if (is_ref) try writer.write_byte('&');
            return writer.write_all(".{}");
        },
        else => unreachable,
    }

    const len = ty.array_len(zcu);

    if (is_ref) try writer.write_byte('&');
    try writer.write_all(".{ ");

    const max_len = @min(len, max_aggregate_items);
    for (0..max_len) |i| {
        if (i != 0) try writer.write_all(", ");
        try print(try val.field_value(zcu, i), writer, level - 1, zcu, opt_sema);
    }
    if (len > max_aggregate_items) {
        try writer.write_all(", ...");
    }
    return writer.write_all(" }");
}

fn print_ptr(ptr_val: Value, writer: anytype, level: u8, zcu: *Zcu, opt_sema: ?*Sema) (@TypeOf(writer).Error || Module.CompileError)!void {
    const ptr = switch (zcu.intern_pool.index_to_key(ptr_val.to_intern())) {
        .undef => return writer.write_all("undefined"),
        .ptr => |ptr| ptr,
        else => unreachable,
    };

    if (ptr.base_addr == .anon_decl) {
        // If the value is an aggregate, we can potentially print it more nicely.
        switch (zcu.intern_pool.index_to_key(ptr.base_addr.anon_decl.val)) {
            .aggregate => |agg| return print_aggregate(
                Value.from_interned(ptr.base_addr.anon_decl.val),
                agg,
                true,
                writer,
                level,
                zcu,
                opt_sema,
            ),
            else => {},
        }
    }

    var arena = std.heap.ArenaAllocator.init(zcu.gpa);
    defer arena.deinit();
    const derivation = try ptr_val.pointer_derivation_advanced(arena.allocator(), zcu, opt_sema);
    try print_ptr_derivation(derivation, writer, level, zcu, opt_sema);
}

/// Print `derivation` as an lvalue, i.e. such that writing `&` before this gives the pointer value.
fn print_ptr_derivation(derivation: Value.PointerDeriveStep, writer: anytype, level: u8, zcu: *Zcu, opt_sema: ?*Sema) (@TypeOf(writer).Error || Module.CompileError)!void {
    const ip = &zcu.intern_pool;
    switch (derivation) {
        .int => |int| try writer.print("@as({}, @ptrFromInt({x})).*", .{
            int.ptr_ty.fmt(zcu),
            int.addr,
        }),
        .decl_ptr => |decl| {
            try zcu.decl_ptr(decl).render_fully_qualified_name(zcu, writer);
        },
        .anon_decl_ptr => |anon| {
            const ty = Value.from_interned(anon.val).type_of(zcu);
            try writer.print("@as({}, ", .{ty.fmt(zcu)});
            try print(Value.from_interned(anon.val), writer, level - 1, zcu, opt_sema);
            try writer.write_byte(')');
        },
        .comptime_alloc_ptr => |info| {
            try writer.print("@as({}, ", .{info.val.type_of(zcu).fmt(zcu)});
            try print(info.val, writer, level - 1, zcu, opt_sema);
            try writer.write_byte(')');
        },
        .comptime_field_ptr => |val| {
            const ty = val.type_of(zcu);
            try writer.print("@as({}, ", .{ty.fmt(zcu)});
            try print(val, writer, level - 1, zcu, opt_sema);
            try writer.write_byte(')');
        },
        .eu_payload_ptr => |info| {
            try writer.write_byte('(');
            try print_ptr_derivation(info.parent.*, writer, level, zcu, opt_sema);
            try writer.write_all(" catch unreachable)");
        },
        .opt_payload_ptr => |info| {
            try print_ptr_derivation(info.parent.*, writer, level, zcu, opt_sema);
            try writer.write_all(".?");
        },
        .field_ptr => |field| {
            try print_ptr_derivation(field.parent.*, writer, level, zcu, opt_sema);
            const agg_ty = (try field.parent.ptr_type(zcu)).child_type(zcu);
            switch (agg_ty.zig_type_tag(zcu)) {
                .Struct => if (agg_ty.struct_field_name(field.field_idx, zcu).unwrap()) |field_name| {
                    try writer.print(".{i}", .{field_name.fmt(ip)});
                } else {
                    try writer.print("[{d}]", .{field.field_idx});
                },
                .Union => {
                    const tag_ty = agg_ty.union_tag_type_hypothetical(zcu);
                    const field_name = tag_ty.enum_field_name(field.field_idx, zcu);
                    try writer.print(".{i}", .{field_name.fmt(ip)});
                },
                .Pointer => switch (field.field_idx) {
                    Value.slice_ptr_index => try writer.write_all(".ptr"),
                    Value.slice_len_index => try writer.write_all(".len"),
                    else => unreachable,
                },
                else => unreachable,
            }
        },
        .elem_ptr => |elem| {
            try print_ptr_derivation(elem.parent.*, writer, level, zcu, opt_sema);
            try writer.print("[{d}]", .{elem.elem_idx});
        },
        .offset_and_cast => |oac| if (oac.byte_offset == 0) {
            try writer.print("@as({}, @ptr_cast(", .{oac.new_ptr_ty.fmt(zcu)});
            try print_ptr_derivation(oac.parent.*, writer, level, zcu, opt_sema);
            try writer.write_all("))");
        } else {
            try writer.print("@as({}, @ptrFromInt(@int_from_ptr(", .{oac.new_ptr_ty.fmt(zcu)});
            try print_ptr_derivation(oac.parent.*, writer, level, zcu, opt_sema);
            try writer.print(") + {d}))", .{oac.byte_offset});
        },
    }
}
