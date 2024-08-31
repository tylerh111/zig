//! This file contains logic for bit-casting arbitrary values at comptime, including splicing
//! bits together for comptime stores of bit-pointers. The strategy is to "flatten" values to
//! a sequence of values in *packed* memory, and then unflatten through a combination of special
//! cases (particularly for pointers and `undefined` values) and in-memory buffer reinterprets.
//!
//! This is a little awkward on big-endian targets, as non-packed datastructures (e.g. `extern struct`)
//! have their fields reversed when represented as packed memory on such targets.

/// If `host_bits` is `0`, attempts to convert the memory at offset
/// `byte_offset` into `val` to a non-packed value of type `dest_ty`,
/// ignoring `bit_offset`.
///
/// Otherwise, `byte_offset` is an offset in bytes into `val` to a
/// non-packed value consisting of `host_bits` bits. A value of type
/// `dest_ty` will be interpreted at a packed offset of `bit_offset`
/// into this value.
///
/// Returns `null` if the operation must be performed at runtime.
pub fn bit_cast(
    sema: *Sema,
    val: Value,
    dest_ty: Type,
    byte_offset: u64,
    host_bits: u64,
    bit_offset: u64,
) CompileError!?Value {
    return bit_cast_inner(sema, val, dest_ty, byte_offset, host_bits, bit_offset) catch |err| switch (err) {
        error.ReinterpretDeclRef => return null,
        error.IllDefinedMemoryLayout => unreachable,
        error.Unimplemented => @panic("unimplemented bitcast"),
        else => |e| return e,
    };
}

/// Uses bitcasting to splice the value `splice_val` into `val`,
/// replacing overlapping bits and returning the modified value.
///
/// If `host_bits` is `0`, splices `splice_val` at an offset
/// `byte_offset` bytes into the virtual memory of `val`, ignoring
/// `bit_offset`.
///
/// Otherwise, `byte_offset` is an offset into bytes into `val` to
/// a non-packed value consisting of `host_bits` bits. The value
/// `splice_val` will be placed at a packed offset of `bit_offset`
/// into this value.
pub fn bit_cast_splice(
    sema: *Sema,
    val: Value,
    splice_val: Value,
    byte_offset: u64,
    host_bits: u64,
    bit_offset: u64,
) CompileError!?Value {
    return bit_cast_splice_inner(sema, val, splice_val, byte_offset, host_bits, bit_offset) catch |err| switch (err) {
        error.ReinterpretDeclRef => return null,
        error.IllDefinedMemoryLayout => unreachable,
        error.Unimplemented => @panic("unimplemented bitcast"),
        else => |e| return e,
    };
}

const BitCastError = CompileError || error{ ReinterpretDeclRef, IllDefinedMemoryLayout, Unimplemented };

fn bit_cast_inner(
    sema: *Sema,
    val: Value,
    dest_ty: Type,
    byte_offset: u64,
    host_bits: u64,
    bit_offset: u64,
) BitCastError!Value {
    const zcu = sema.mod;
    const endian = zcu.get_target().cpu.arch.endian();

    if (dest_ty.to_intern() == val.type_of(zcu).to_intern() and bit_offset == 0) {
        return val;
    }

    const val_ty = val.type_of(zcu);

    try sema.resolve_type_layout(val_ty);
    try sema.resolve_type_layout(dest_ty);

    assert(val_ty.has_well_defined_layout(zcu));

    const abi_pad_bits, const host_pad_bits = if (host_bits > 0)
        .{ val_ty.abi_size(zcu) * 8 - host_bits, host_bits - val_ty.bit_size(zcu) }
    else
        .{ val_ty.abi_size(zcu) * 8 - val_ty.bit_size(zcu), 0 };

    const skip_bits = switch (endian) {
        .little => bit_offset + byte_offset * 8,
        .big => if (host_bits > 0)
            val_ty.abi_size(zcu) * 8 - byte_offset * 8 - host_bits + bit_offset
        else
            val_ty.abi_size(zcu) * 8 - byte_offset * 8 - dest_ty.bit_size(zcu),
    };

    var unpack: UnpackValueBits = .{
        .zcu = zcu,
        .arena = sema.arena,
        .skip_bits = skip_bits,
        .remaining_bits = dest_ty.bit_size(zcu),
        .unpacked = std.ArrayList(InternPool.Index).init(sema.arena),
    };
    switch (endian) {
        .little => {
            try unpack.add(val);
            try unpack.padding(abi_pad_bits);
        },
        .big => {
            try unpack.padding(abi_pad_bits);
            try unpack.add(val);
        },
    }
    try unpack.padding(host_pad_bits);

    var pack: PackValueBits = .{
        .zcu = zcu,
        .arena = sema.arena,
        .unpacked = unpack.unpacked.items,
    };
    return pack.get(dest_ty);
}

fn bit_cast_splice_inner(
    sema: *Sema,
    val: Value,
    splice_val: Value,
    byte_offset: u64,
    host_bits: u64,
    bit_offset: u64,
) BitCastError!Value {
    const zcu = sema.mod;
    const endian = zcu.get_target().cpu.arch.endian();
    const val_ty = val.type_of(zcu);
    const splice_val_ty = splice_val.type_of(zcu);

    try sema.resolve_type_layout(val_ty);
    try sema.resolve_type_layout(splice_val_ty);

    const splice_bits = splice_val_ty.bit_size(zcu);

    const splice_offset = switch (endian) {
        .little => bit_offset + byte_offset * 8,
        .big => if (host_bits > 0)
            val_ty.abi_size(zcu) * 8 - byte_offset * 8 - host_bits + bit_offset
        else
            val_ty.abi_size(zcu) * 8 - byte_offset * 8 - splice_bits,
    };

    assert(splice_offset + splice_bits <= val_ty.abi_size(zcu) * 8);

    const abi_pad_bits, const host_pad_bits = if (host_bits > 0)
        .{ val_ty.abi_size(zcu) * 8 - host_bits, host_bits - val_ty.bit_size(zcu) }
    else
        .{ val_ty.abi_size(zcu) * 8 - val_ty.bit_size(zcu), 0 };

    var unpack: UnpackValueBits = .{
        .zcu = zcu,
        .arena = sema.arena,
        .skip_bits = 0,
        .remaining_bits = splice_offset,
        .unpacked = std.ArrayList(InternPool.Index).init(sema.arena),
    };
    switch (endian) {
        .little => {
            try unpack.add(val);
            try unpack.padding(abi_pad_bits);
        },
        .big => {
            try unpack.padding(abi_pad_bits);
            try unpack.add(val);
        },
    }
    try unpack.padding(host_pad_bits);

    unpack.remaining_bits = splice_bits;
    try unpack.add(splice_val);

    unpack.skip_bits = splice_offset + splice_bits;
    unpack.remaining_bits = val_ty.abi_size(zcu) * 8 - splice_offset - splice_bits;
    switch (endian) {
        .little => {
            try unpack.add(val);
            try unpack.padding(abi_pad_bits);
        },
        .big => {
            try unpack.padding(abi_pad_bits);
            try unpack.add(val);
        },
    }
    try unpack.padding(host_pad_bits);

    var pack: PackValueBits = .{
        .zcu = zcu,
        .arena = sema.arena,
        .unpacked = unpack.unpacked.items,
    };
    switch (endian) {
        .little => {},
        .big => try pack.padding(abi_pad_bits),
    }
    return pack.get(val_ty);
}

/// Recurses through struct fields, array elements, etc, to get a sequence of "primitive" values
/// which are bit-packed in memory to represent a single value. `unpacked` represents a series
/// of values in *packed* memory - therefore, on big-endian targets, the first element of this
/// list contains bits from the *final* byte of the value.
const UnpackValueBits = struct {
    zcu: *Zcu,
    arena: Allocator,
    skip_bits: u64,
    remaining_bits: u64,
    extra_bits: u64 = undefined,
    unpacked: std.ArrayList(InternPool.Index),

    fn add(unpack: *UnpackValueBits, val: Value) BitCastError!void {
        const zcu = unpack.zcu;
        const endian = zcu.get_target().cpu.arch.endian();
        const ip = &zcu.intern_pool;

        if (unpack.remaining_bits == 0) {
            return;
        }

        const ty = val.type_of(zcu);
        const bit_size = ty.bit_size(zcu);

        if (unpack.skip_bits >= bit_size) {
            unpack.skip_bits -= bit_size;
            return;
        }

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
            .variable,
            .extern_func,
            .func,
            .err,
            .error_union,
            .enum_literal,
            .slice,
            .memoized_call,
            => unreachable, // ill-defined layout or not real values

            .undef,
            .int,
            .enum_tag,
            .simple_value,
            .empty_enum_value,
            .float,
            .ptr,
            .opt,
            => try unpack.primitive(val),

            .aggregate => switch (ty.zig_type_tag(zcu)) {
                .Vector => {
                    const len: usize = @int_cast(ty.array_len(zcu));
                    for (0..len) |i| {
                        // We reverse vector elements in packed memory on BE targets.
                        const real_idx = switch (endian) {
                            .little => i,
                            .big => len - i - 1,
                        };
                        const elem_val = try val.elem_value(zcu, real_idx);
                        try unpack.add(elem_val);
                    }
                },
                .Array => {
                    // Each element is padded up to its ABI size. Padding bits are undefined.
                    // The final element does not have trailing padding.
                    // Elements are reversed in packed memory on BE targets.
                    const elem_ty = ty.child_type(zcu);
                    const pad_bits = elem_ty.abi_size(zcu) * 8 - elem_ty.bit_size(zcu);
                    const len = ty.array_len(zcu);
                    const maybe_sent = ty.sentinel(zcu);

                    if (endian == .big) if (maybe_sent) |s| {
                        try unpack.add(s);
                        if (len != 0) try unpack.padding(pad_bits);
                    };

                    for (0..@int_cast(len)) |i| {
                        // We reverse array elements in packed memory on BE targets.
                        const real_idx = switch (endian) {
                            .little => i,
                            .big => len - i - 1,
                        };
                        const elem_val = try val.elem_value(zcu, @int_cast(real_idx));
                        try unpack.add(elem_val);
                        if (i != len - 1) try unpack.padding(pad_bits);
                    }

                    if (endian == .little) if (maybe_sent) |s| {
                        if (len != 0) try unpack.padding(pad_bits);
                        try unpack.add(s);
                    };
                },
                .Struct => switch (ty.container_layout(zcu)) {
                    .auto => unreachable, // ill-defined layout
                    .@"extern" => switch (endian) {
                        .little => {
                            var cur_bit_off: u64 = 0;
                            var it = zcu.type_to_struct(ty).?.iterate_runtime_order(ip);
                            while (it.next()) |field_idx| {
                                const want_bit_off = ty.struct_field_offset(field_idx, zcu) * 8;
                                const pad_bits = want_bit_off - cur_bit_off;
                                const field_val = try val.field_value(zcu, field_idx);
                                try unpack.padding(pad_bits);
                                try unpack.add(field_val);
                                cur_bit_off = want_bit_off + field_val.type_of(zcu).bit_size(zcu);
                            }
                            // Add trailing padding bits.
                            try unpack.padding(bit_size - cur_bit_off);
                        },
                        .big => {
                            var cur_bit_off: u64 = bit_size;
                            var it = zcu.type_to_struct(ty).?.iterate_runtime_order_reverse(ip);
                            while (it.next()) |field_idx| {
                                const field_val = try val.field_value(zcu, field_idx);
                                const field_ty = field_val.type_of(zcu);
                                const want_bit_off = ty.struct_field_offset(field_idx, zcu) * 8 + field_ty.bit_size(zcu);
                                const pad_bits = cur_bit_off - want_bit_off;
                                try unpack.padding(pad_bits);
                                try unpack.add(field_val);
                                cur_bit_off = want_bit_off - field_ty.bit_size(zcu);
                            }
                            assert(cur_bit_off == 0);
                        },
                    },
                    .@"packed" => {
                        // Just add all fields in order. There are no padding bits.
                        // This is identical between LE and BE targets.
                        for (0..ty.struct_field_count(zcu)) |i| {
                            const field_val = try val.field_value(zcu, i);
                            try unpack.add(field_val);
                        }
                    },
                },
                else => unreachable,
            },

            .un => |un| {
                // We actually don't care about the tag here!
                // Instead, we just need to write the payload value, plus any necessary padding.
                // This correctly handles the case where `tag == .none`, since the payload is then
                // either an integer or a byte array, both of which we can unpack.
                const payload_val = Value.from_interned(un.val);
                const pad_bits = bit_size - payload_val.type_of(zcu).bit_size(zcu);
                if (endian == .little or ty.container_layout(zcu) == .@"packed") {
                    try unpack.add(payload_val);
                    try unpack.padding(pad_bits);
                } else {
                    try unpack.padding(pad_bits);
                    try unpack.add(payload_val);
                }
            },
        }
    }

    fn padding(unpack: *UnpackValueBits, pad_bits: u64) BitCastError!void {
        if (pad_bits == 0) return;
        const zcu = unpack.zcu;
        // Figure out how many full bytes and leftover bits there are.
        const bytes = pad_bits / 8;
        const bits = pad_bits % 8;
        // Add undef u8 values for the bytes...
        const undef_u8 = try zcu.undef_value(Type.u8);
        for (0..@int_cast(bytes)) |_| {
            try unpack.primitive(undef_u8);
        }
        // ...and an undef int for the leftover bits.
        if (bits == 0) return;
        const bits_ty = try zcu.int_type(.unsigned, @int_cast(bits));
        const bits_val = try zcu.undef_value(bits_ty);
        try unpack.primitive(bits_val);
    }

    fn primitive(unpack: *UnpackValueBits, val: Value) BitCastError!void {
        const zcu = unpack.zcu;

        if (unpack.remaining_bits == 0) {
            return;
        }

        const ty = val.type_of(zcu);
        const bit_size = ty.bit_size(zcu);

        // Note that this skips all zero-bit types.
        if (unpack.skip_bits >= bit_size) {
            unpack.skip_bits -= bit_size;
            return;
        }

        if (unpack.skip_bits > 0) {
            const skip = unpack.skip_bits;
            unpack.skip_bits = 0;
            return unpack.split_primitive(val, skip, bit_size - skip);
        }

        if (unpack.remaining_bits < bit_size) {
            return unpack.split_primitive(val, 0, unpack.remaining_bits);
        }

        unpack.remaining_bits -|= bit_size;

        try unpack.unpacked.append(val.to_intern());
    }

    fn split_primitive(unpack: *UnpackValueBits, val: Value, bit_offset: u64, bit_count: u64) BitCastError!void {
        const zcu = unpack.zcu;
        const ty = val.type_of(zcu);

        const val_bits = ty.bit_size(zcu);
        assert(bit_offset + bit_count <= val_bits);

        switch (zcu.intern_pool.index_to_key(val.to_intern())) {
            // In the `ptr` case, this will return `error.ReinterpretDeclRef`
            // if we're trying to split a non-integer pointer value.
            .int, .float, .enum_tag, .ptr, .opt => {
                // This @int_cast is okay because no primitive can exceed the size of a u16.
                const int_ty = try zcu.int_type(.unsigned, @int_cast(bit_count));
                const buf = try unpack.arena.alloc(u8, @int_cast((val_bits + 7) / 8));
                try val.write_to_packed_memory(ty, zcu, buf, 0);
                const sub_val = try Value.read_from_packed_memory(int_ty, zcu, buf, @int_cast(bit_offset), unpack.arena);
                try unpack.primitive(sub_val);
            },
            .undef => try unpack.padding(bit_count),
            // The only values here with runtime bits are `true` and `false.
            // These are both 1 bit, so will never need truncating.
            .simple_value => unreachable,
            .empty_enum_value => unreachable, // zero-bit
            else => unreachable, // zero-bit or not primitives
        }
    }
};

/// Given a sequence of bit-packed values in packed memory (see `UnpackValueBits`),
/// reconstructs a value of an arbitrary type, with correct handling of `undefined`
/// values and of pointers which align in virtual memory.
const PackValueBits = struct {
    zcu: *Zcu,
    arena: Allocator,
    bit_offset: u64 = 0,
    unpacked: []const InternPool.Index,

    fn get(pack: *PackValueBits, ty: Type) BitCastError!Value {
        const zcu = pack.zcu;
        const endian = zcu.get_target().cpu.arch.endian();
        const ip = &zcu.intern_pool;
        const arena = pack.arena;
        switch (ty.zig_type_tag(zcu)) {
            .Vector => {
                // Elements are bit-packed.
                const len = ty.array_len(zcu);
                const elem_ty = ty.child_type(zcu);
                const elems = try arena.alloc(InternPool.Index, @int_cast(len));
                // We reverse vector elements in packed memory on BE targets.
                switch (endian) {
                    .little => for (elems) |*elem| {
                        elem.* = (try pack.get(elem_ty)).to_intern();
                    },
                    .big => {
                        var i = elems.len;
                        while (i > 0) {
                            i -= 1;
                            elems[i] = (try pack.get(elem_ty)).to_intern();
                        }
                    },
                }
                return Value.from_interned(try zcu.intern(.{ .aggregate = .{
                    .ty = ty.to_intern(),
                    .storage = .{ .elems = elems },
                } }));
            },
            .Array => {
                // Each element is padded up to its ABI size. The final element does not have trailing padding.
                const len = ty.array_len(zcu);
                const elem_ty = ty.child_type(zcu);
                const maybe_sent = ty.sentinel(zcu);
                const pad_bits = elem_ty.abi_size(zcu) * 8 - elem_ty.bit_size(zcu);
                const elems = try arena.alloc(InternPool.Index, @int_cast(len));

                if (endian == .big and maybe_sent != null) {
                    // TODO: validate sentinel was preserved!
                    try pack.padding(elem_ty.bit_size(zcu));
                    if (len != 0) try pack.padding(pad_bits);
                }

                for (0..elems.len) |i| {
                    const real_idx = switch (endian) {
                        .little => i,
                        .big => len - i - 1,
                    };
                    elems[@int_cast(real_idx)] = (try pack.get(elem_ty)).to_intern();
                    if (i != len - 1) try pack.padding(pad_bits);
                }

                if (endian == .little and maybe_sent != null) {
                    // TODO: validate sentinel was preserved!
                    if (len != 0) try pack.padding(pad_bits);
                    try pack.padding(elem_ty.bit_size(zcu));
                }

                return Value.from_interned(try zcu.intern(.{ .aggregate = .{
                    .ty = ty.to_intern(),
                    .storage = .{ .elems = elems },
                } }));
            },
            .Struct => switch (ty.container_layout(zcu)) {
                .auto => unreachable, // ill-defined layout
                .@"extern" => {
                    const elems = try arena.alloc(InternPool.Index, ty.struct_field_count(zcu));
                    @memset(elems, .none);
                    switch (endian) {
                        .little => {
                            var cur_bit_off: u64 = 0;
                            var it = zcu.type_to_struct(ty).?.iterate_runtime_order(ip);
                            while (it.next()) |field_idx| {
                                const want_bit_off = ty.struct_field_offset(field_idx, zcu) * 8;
                                try pack.padding(want_bit_off - cur_bit_off);
                                const field_ty = ty.struct_field_type(field_idx, zcu);
                                elems[field_idx] = (try pack.get(field_ty)).to_intern();
                                cur_bit_off = want_bit_off + field_ty.bit_size(zcu);
                            }
                            try pack.padding(ty.bit_size(zcu) - cur_bit_off);
                        },
                        .big => {
                            var cur_bit_off: u64 = ty.bit_size(zcu);
                            var it = zcu.type_to_struct(ty).?.iterate_runtime_order_reverse(ip);
                            while (it.next()) |field_idx| {
                                const field_ty = ty.struct_field_type(field_idx, zcu);
                                const want_bit_off = ty.struct_field_offset(field_idx, zcu) * 8 + field_ty.bit_size(zcu);
                                try pack.padding(cur_bit_off - want_bit_off);
                                elems[field_idx] = (try pack.get(field_ty)).to_intern();
                                cur_bit_off = want_bit_off - field_ty.bit_size(zcu);
                            }
                            assert(cur_bit_off == 0);
                        },
                    }
                    // Any fields which do not have runtime bits should be OPV or comptime fields.
                    // Fill those values now.
                    for (elems, 0..) |*elem, field_idx| {
                        if (elem.* != .none) continue;
                        const val = (try ty.struct_field_value_comptime(zcu, field_idx)).?;
                        elem.* = val.to_intern();
                    }
                    return Value.from_interned(try zcu.intern(.{ .aggregate = .{
                        .ty = ty.to_intern(),
                        .storage = .{ .elems = elems },
                    } }));
                },
                .@"packed" => {
                    // All fields are in order with no padding.
                    // This is identical between LE and BE targets.
                    const elems = try arena.alloc(InternPool.Index, ty.struct_field_count(zcu));
                    for (elems, 0..) |*elem, i| {
                        const field_ty = ty.struct_field_type(i, zcu);
                        elem.* = (try pack.get(field_ty)).to_intern();
                    }
                    return Value.from_interned(try zcu.intern(.{ .aggregate = .{
                        .ty = ty.to_intern(),
                        .storage = .{ .elems = elems },
                    } }));
                },
            },
            .Union => {
                // We will attempt to read as the backing representation. If this emits
                // `error.ReinterpretDeclRef`, we will try each union field, preferring larger ones.
                // We will also attempt smaller fields when we get `undefined`, as if some bits are
                // defined we want to include them.
                // TODO: this is very very bad. We need a more sophisticated union representation.

                const prev_unpacked = pack.unpacked;
                const prev_bit_offset = pack.bit_offset;

                const backing_ty = try ty.union_backing_type(zcu);

                backing: {
                    const backing_val = pack.get(backing_ty) catch |err| switch (err) {
                        error.ReinterpretDeclRef => {
                            pack.unpacked = prev_unpacked;
                            pack.bit_offset = prev_bit_offset;
                            break :backing;
                        },
                        else => |e| return e,
                    };
                    if (backing_val.is_undef(zcu)) {
                        pack.unpacked = prev_unpacked;
                        pack.bit_offset = prev_bit_offset;
                        break :backing;
                    }
                    return Value.from_interned(try zcu.intern(.{ .un = .{
                        .ty = ty.to_intern(),
                        .tag = .none,
                        .val = backing_val.to_intern(),
                    } }));
                }

                const field_order = try pack.arena.alloc(u32, ty.union_tag_type_hypothetical(zcu).enum_field_count(zcu));
                for (field_order, 0..) |*f, i| f.* = @int_cast(i);
                // Sort `field_order` to put the fields with the largest bit sizes first.
                const SizeSortCtx = struct {
                    zcu: *Zcu,
                    field_types: []const InternPool.Index,
                    fn less_than(ctx: @This(), a_idx: u32, b_idx: u32) bool {
                        const a_ty = Type.from_interned(ctx.field_types[a_idx]);
                        const b_ty = Type.from_interned(ctx.field_types[b_idx]);
                        return a_ty.bit_size(ctx.zcu) > b_ty.bit_size(ctx.zcu);
                    }
                };
                std.mem.sort_unstable(u32, field_order, SizeSortCtx{
                    .zcu = zcu,
                    .field_types = zcu.type_to_union(ty).?.field_types.get(ip),
                }, SizeSortCtx.less_than);

                const padding_after = endian == .little or ty.container_layout(zcu) == .@"packed";

                for (field_order) |field_idx| {
                    const field_ty = Type.from_interned(zcu.type_to_union(ty).?.field_types.get(ip)[field_idx]);
                    const pad_bits = ty.bit_size(zcu) - field_ty.bit_size(zcu);
                    if (!padding_after) try pack.padding(pad_bits);
                    const field_val = pack.get(field_ty) catch |err| switch (err) {
                        error.ReinterpretDeclRef => {
                            pack.unpacked = prev_unpacked;
                            pack.bit_offset = prev_bit_offset;
                            continue;
                        },
                        else => |e| return e,
                    };
                    if (padding_after) try pack.padding(pad_bits);
                    if (field_val.is_undef(zcu)) {
                        pack.unpacked = prev_unpacked;
                        pack.bit_offset = prev_bit_offset;
                        continue;
                    }
                    const tag_val = try zcu.enum_value_field_index(ty.union_tag_type_hypothetical(zcu), field_idx);
                    return Value.from_interned(try zcu.intern(.{ .un = .{
                        .ty = ty.to_intern(),
                        .tag = tag_val.to_intern(),
                        .val = field_val.to_intern(),
                    } }));
                }

                // No field could represent the value. Just do whatever happens when we try to read
                // the backing type - either `undefined` or `error.ReinterpretDeclRef`.
                const backing_val = try pack.get(backing_ty);
                return Value.from_interned(try zcu.intern(.{ .un = .{
                    .ty = ty.to_intern(),
                    .tag = .none,
                    .val = backing_val.to_intern(),
                } }));
            },
            else => return pack.primitive(ty),
        }
    }

    fn padding(pack: *PackValueBits, pad_bits: u64) BitCastError!void {
        _ = pack.prepare_bits(pad_bits);
    }

    fn primitive(pack: *PackValueBits, want_ty: Type) BitCastError!Value {
        const zcu = pack.zcu;
        const vals, const bit_offset = pack.prepare_bits(want_ty.bit_size(zcu));

        for (vals) |val| {
            if (!Value.from_interned(val).is_undef(zcu)) break;
        } else {
            // All bits of the value are `undefined`.
            return zcu.undef_value(want_ty);
        }

        // TODO: we need to decide how to handle partially-undef values here.
        // Currently, a value with some undefined bits becomes `0xAA` so that we
        // preserve the well-defined bits, because we can't currently represent
        // a partially-undefined primitive (e.g. an int with some undef bits).
        // In future, we probably want to take one of these two routes:
        // * Define that if any bits are `undefined`, the entire value is `undefined`.
        //   This is a major breaking change, and probably a footgun.
        // * Introduce tracking for partially-undef values at comptime.
        //   This would complicate a lot of operations in Sema, such as basic
        //   arithmetic.
        // This design complexity is tracked by #19634.

        ptr_cast: {
            if (vals.len != 1) break :ptr_cast;
            const val = Value.from_interned(vals[0]);
            if (!val.type_of(zcu).is_ptr_at_runtime(zcu)) break :ptr_cast;
            if (!want_ty.is_ptr_at_runtime(zcu)) break :ptr_cast;
            return zcu.get_coerced(val, want_ty);
        }

        // Reinterpret via an in-memory buffer.

        var buf_bits: u64 = 0;
        for (vals) |ip_val| {
            const val = Value.from_interned(ip_val);
            const ty = val.type_of(zcu);
            buf_bits += ty.bit_size(zcu);
        }

        const buf = try pack.arena.alloc(u8, @int_cast((buf_bits + 7) / 8));
        // We will skip writing undefined values, so mark the buffer as `0xAA` so we get "undefined" bits.
        @memset(buf, 0xAA);
        var cur_bit_off: usize = 0;
        for (vals) |ip_val| {
            const val = Value.from_interned(ip_val);
            const ty = val.type_of(zcu);
            if (!val.is_undef(zcu)) {
                try val.write_to_packed_memory(ty, zcu, buf, cur_bit_off);
            }
            cur_bit_off += @int_cast(ty.bit_size(zcu));
        }

        return Value.read_from_packed_memory(want_ty, zcu, buf, @int_cast(bit_offset), pack.arena);
    }

    fn prepare_bits(pack: *PackValueBits, need_bits: u64) struct { []const InternPool.Index, u64 } {
        if (need_bits == 0) return .{ &.{}, 0 };

        const zcu = pack.zcu;

        var bits: u64 = 0;
        var len: usize = 0;
        while (bits < pack.bit_offset + need_bits) {
            bits += Value.from_interned(pack.unpacked[len]).type_of(zcu).bit_size(zcu);
            len += 1;
        }

        const result_vals = pack.unpacked[0..len];
        const result_offset = pack.bit_offset;

        const extra_bits = bits - pack.bit_offset - need_bits;
        if (extra_bits == 0) {
            pack.unpacked = pack.unpacked[len..];
            pack.bit_offset = 0;
        } else {
            pack.unpacked = pack.unpacked[len - 1 ..];
            pack.bit_offset = Value.from_interned(pack.unpacked[0]).type_of(zcu).bit_size(zcu) - extra_bits;
        }

        return .{ result_vals, result_offset };
    }
};

const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

const Sema = @import("../Sema.zig");
const Zcu = @import("../Module.zig");
const InternPool = @import("../InternPool.zig");
const Type = @import("../type.zig").Type;
const Value = @import("../Value.zig");
const CompileError = Zcu.CompileError;
