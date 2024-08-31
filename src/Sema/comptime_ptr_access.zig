pub const ComptimeLoadResult = union(enum) {
    success: MutableValue,

    runtime_load,
    undef,
    err_payload: InternPool.NullTerminatedString,
    null_payload,
    inactive_union_field,
    needed_well_defined: Type,
    out_of_bounds: Type,
    exceeds_host_size,
};

pub fn load_comptime_ptr(sema: *Sema, block: *Block, src: LazySrcLoc, ptr: Value) !ComptimeLoadResult {
    const zcu = sema.mod;
    const ptr_info = ptr.type_of(zcu).ptr_info(zcu);
    // TODO: host size for vectors is terrible
    const host_bits = switch (ptr_info.flags.vector_index) {
        .none => ptr_info.packed_offset.host_size * 8,
        else => ptr_info.packed_offset.host_size * Type.from_interned(ptr_info.child).bit_size(zcu),
    };
    const bit_offset = if (host_bits != 0) bit_offset: {
        const child_bits = Type.from_interned(ptr_info.child).bit_size(zcu);
        const bit_offset = ptr_info.packed_offset.bit_offset + switch (ptr_info.flags.vector_index) {
            .none => 0,
            .runtime => return .runtime_load,
            else => |idx| switch (zcu.get_target().cpu.arch.endian()) {
                .little => child_bits * @int_from_enum(idx),
                .big => host_bits - child_bits * (@int_from_enum(idx) + 1), // element order reversed on big endian
            },
        };
        if (child_bits + bit_offset > host_bits) {
            return .exceeds_host_size;
        }
        break :bit_offset bit_offset;
    } else 0;
    return load_comptime_ptr_inner(sema, block, src, ptr, bit_offset, host_bits, Type.from_interned(ptr_info.child), 0);
}

pub const ComptimeStoreResult = union(enum) {
    success,

    runtime_store,
    comptime_field_mismatch: Value,
    undef,
    err_payload: InternPool.NullTerminatedString,
    null_payload,
    inactive_union_field,
    needed_well_defined: Type,
    out_of_bounds: Type,
    exceeds_host_size,
};

/// Perform a comptime load of value `store_val` to a pointer.
/// The pointer's type is ignored.
pub fn store_comptime_ptr(
    sema: *Sema,
    block: *Block,
    src: LazySrcLoc,
    ptr: Value,
    store_val: Value,
) !ComptimeStoreResult {
    const zcu = sema.mod;
    const ptr_info = ptr.type_of(zcu).ptr_info(zcu);
    assert(store_val.type_of(zcu).to_intern() == ptr_info.child);
    // TODO: host size for vectors is terrible
    const host_bits = switch (ptr_info.flags.vector_index) {
        .none => ptr_info.packed_offset.host_size * 8,
        else => ptr_info.packed_offset.host_size * Type.from_interned(ptr_info.child).bit_size(zcu),
    };
    const bit_offset = ptr_info.packed_offset.bit_offset + switch (ptr_info.flags.vector_index) {
        .none => 0,
        .runtime => return .runtime_store,
        else => |idx| switch (zcu.get_target().cpu.arch.endian()) {
            .little => Type.from_interned(ptr_info.child).bit_size(zcu) * @int_from_enum(idx),
            .big => host_bits - Type.from_interned(ptr_info.child).bit_size(zcu) * (@int_from_enum(idx) + 1), // element order reversed on big endian
        },
    };
    const pseudo_store_ty = if (host_bits > 0) t: {
        const need_bits = Type.from_interned(ptr_info.child).bit_size(zcu);
        if (need_bits + bit_offset > host_bits) {
            return .exceeds_host_size;
        }
        break :t try zcu.int_type(.unsigned, @int_cast(host_bits));
    } else Type.from_interned(ptr_info.child);

    const strat = try prepare_comptime_ptr_store(sema, block, src, ptr, pseudo_store_ty, 0);

    // Propagate errors and handle comptime fields.
    switch (strat) {
        .direct, .index, .flat_index, .reinterpret => {},
        .comptime_field => {
            // To "store" to a comptime field, just perform a load of the field
            // and see if the store value matches.
            const expected_mv = switch (try load_comptime_ptr(sema, block, src, ptr)) {
                .success => |mv| mv,
                .runtime_load => unreachable, // this is a comptime field
                .exceeds_host_size => unreachable, // checked above
                .undef => return .undef,
                .err_payload => |err| return .{ .err_payload = err },
                .null_payload => return .null_payload,
                .inactive_union_field => return .inactive_union_field,
                .needed_well_defined => |ty| return .{ .needed_well_defined = ty },
                .out_of_bounds => |ty| return .{ .out_of_bounds = ty },
            };
            const expected = try expected_mv.intern(zcu, sema.arena);
            if (store_val.to_intern() != expected.to_intern()) {
                return .{ .comptime_field_mismatch = expected };
            }
            return .success;
        },
        .runtime_store => return .runtime_store,
        .undef => return .undef,
        .err_payload => |err| return .{ .err_payload = err },
        .null_payload => return .null_payload,
        .inactive_union_field => return .inactive_union_field,
        .needed_well_defined => |ty| return .{ .needed_well_defined = ty },
        .out_of_bounds => |ty| return .{ .out_of_bounds = ty },
    }

    // Check the store is not inside a runtime condition
    try check_comptime_var_store(sema, block, src, strat.alloc());

    if (host_bits == 0) {
        // We can attempt a direct store depending on the strategy.
        switch (strat) {
            .direct => |direct| {
                const want_ty = direct.val.type_of(zcu);
                const coerced_store_val = try zcu.get_coerced(store_val, want_ty);
                direct.val.* = .{ .interned = coerced_store_val.to_intern() };
                return .success;
            },
            .index => |index| {
                const want_ty = index.val.type_of(zcu).child_type(zcu);
                const coerced_store_val = try zcu.get_coerced(store_val, want_ty);
                try index.val.set_elem(zcu, sema.arena, @int_cast(index.elem_index), .{ .interned = coerced_store_val.to_intern() });
                return .success;
            },
            .flat_index => |flat| {
                const store_elems = store_val.type_of(zcu).array_base(zcu)[1];
                const flat_elems = try sema.arena.alloc(InternPool.Index, @int_cast(store_elems));
                {
                    var next_idx: u64 = 0;
                    var skip: u64 = 0;
                    try flatten_array(sema, .{ .interned = store_val.to_intern() }, &skip, &next_idx, flat_elems);
                }
                for (flat_elems, 0..) |elem, idx| {
                    // TODO: recursive_index in a loop does a lot of redundant work!
                    // Better would be to gather all the store targets into an array.
                    var index: u64 = flat.flat_elem_index + idx;
                    const val_ptr, const final_idx = (try recursive_index(sema, flat.val, &index)).?;
                    try val_ptr.set_elem(zcu, sema.arena, @int_cast(final_idx), .{ .interned = elem });
                }
                return .success;
            },
            .reinterpret => {},
            else => unreachable,
        }
    }

    // Either there is a bit offset, or the strategy required reinterpreting.
    // Therefore, we must perform a bitcast.

    const val_ptr: *MutableValue, const byte_offset: u64 = switch (strat) {
        .direct => |direct| .{ direct.val, 0 },
        .index => |index| .{
            index.val,
            index.elem_index * index.val.type_of(zcu).child_type(zcu).abi_size(zcu),
        },
        .flat_index => |flat| .{ flat.val, flat.flat_elem_index * flat.val.type_of(zcu).array_base(zcu)[0].abi_size(zcu) },
        .reinterpret => |reinterpret| .{ reinterpret.val, reinterpret.byte_offset },
        else => unreachable,
    };

    if (!val_ptr.type_of(zcu).has_well_defined_layout(zcu)) {
        return .{ .needed_well_defined = val_ptr.type_of(zcu) };
    }

    if (!store_val.type_of(zcu).has_well_defined_layout(zcu)) {
        return .{ .needed_well_defined = store_val.type_of(zcu) };
    }

    const new_val = try sema.bitCastSpliceVal(
        try val_ptr.intern(zcu, sema.arena),
        store_val,
        byte_offset,
        host_bits,
        bit_offset,
    ) orelse return .runtime_store;
    val_ptr.* = .{ .interned = new_val.to_intern() };
    return .success;
}

/// Perform a comptime load of type `load_ty` from a pointer.
/// The pointer's type is ignored.
fn load_comptime_ptr_inner(
    sema: *Sema,
    block: *Block,
    src: LazySrcLoc,
    ptr_val: Value,
    bit_offset: u64,
    host_bits: u64,
    load_ty: Type,
    /// If `load_ty` is an array, this is the number of array elements to skip
    /// before `load_ty`. Otherwise, it is ignored and may be `undefined`.
    array_offset: u64,
) !ComptimeLoadResult {
    const zcu = sema.mod;
    const ip = &zcu.intern_pool;

    const ptr = switch (ip.index_to_key(ptr_val.to_intern())) {
        .undef => return .undef,
        .ptr => |ptr| ptr,
        else => unreachable,
    };

    const base_val: MutableValue = switch (ptr.base_addr) {
        .decl => |decl_index| val: {
            try sema.declare_dependency(.{ .decl_val = decl_index });
            try sema.ensure_decl_analyzed(decl_index);
            const decl = zcu.decl_ptr(decl_index);
            if (decl.val.get_variable(zcu) != null) return .runtime_load;
            break :val .{ .interned = decl.val.to_intern() };
        },
        .comptime_alloc => |alloc_index| sema.get_comptime_alloc(alloc_index).val,
        .anon_decl => |anon_decl| .{ .interned = anon_decl.val },
        .comptime_field => |val| .{ .interned = val },
        .int => return .runtime_load,
        .eu_payload => |base_ptr_ip| val: {
            const base_ptr = Value.from_interned(base_ptr_ip);
            const base_ty = base_ptr.type_of(zcu).child_type(zcu);
            switch (try load_comptime_ptr_inner(sema, block, src, base_ptr, 0, 0, base_ty, undefined)) {
                .success => |eu_val| switch (eu_val.unpack_error_union(zcu)) {
                    .undef => return .undef,
                    .err => |err| return .{ .err_payload = err },
                    .payload => |payload| break :val payload,
                },
                else => |err| return err,
            }
        },
        .opt_payload => |base_ptr_ip| val: {
            const base_ptr = Value.from_interned(base_ptr_ip);
            const base_ty = base_ptr.type_of(zcu).child_type(zcu);
            switch (try load_comptime_ptr_inner(sema, block, src, base_ptr, 0, 0, base_ty, undefined)) {
                .success => |eu_val| switch (eu_val.unpack_optional(zcu)) {
                    .undef => return .undef,
                    .null => return .null_payload,
                    .payload => |payload| break :val payload,
                },
                else => |err| return err,
            }
        },
        .arr_elem => |base_index| val: {
            const base_ptr = Value.from_interned(base_index.base);
            const base_ty = base_ptr.type_of(zcu).child_type(zcu);

            // We have a comptime-only array. This case is a little nasty.
            // To avoid loading too much data, we want to figure out how many elements we need.
            // If `load_ty` and the array share a base type, we'll load the correct number of elements.
            // Otherwise, we'll be reinterpreting (which we can't do, since it's comptime-only); just
            // load a single element and let the logic below emit its error.

            const load_one_ty, const load_count = load_ty.array_base(zcu);
            const count = if (load_one_ty.to_intern() == base_ty.to_intern()) load_count else 1;

            const want_ty = try zcu.array_type(.{
                .len = count,
                .child = base_ty.to_intern(),
            });

            switch (try load_comptime_ptr_inner(sema, block, src, base_ptr, 0, 0, want_ty, base_index.index)) {
                .success => |arr_val| break :val arr_val,
                else => |err| return err,
            }
        },
        .field => |base_index| val: {
            const base_ptr = Value.from_interned(base_index.base);
            const base_ty = base_ptr.type_of(zcu).child_type(zcu);

            // Field of a slice, or of an auto-layout struct or union.
            const agg_val = switch (try load_comptime_ptr_inner(sema, block, src, base_ptr, 0, 0, base_ty, undefined)) {
                .success => |val| val,
                else => |err| return err,
            };

            const agg_ty = agg_val.type_of(zcu);
            switch (agg_ty.zig_type_tag(zcu)) {
                .Struct, .Pointer => break :val try agg_val.get_elem(zcu, @int_cast(base_index.index)),
                .Union => {
                    const tag_val: Value, const payload_mv: MutableValue = switch (agg_val) {
                        .un => |un| .{ Value.from_interned(un.tag), un.payload.* },
                        .interned => |ip_index| switch (ip.index_to_key(ip_index)) {
                            .undef => return .undef,
                            .un => |un| .{ Value.from_interned(un.tag), .{ .interned = un.val } },
                            else => unreachable,
                        },
                        else => unreachable,
                    };
                    const tag_ty = agg_ty.union_tag_type_hypothetical(zcu);
                    if (tag_ty.enum_tag_field_index(tag_val, zcu).? != base_index.index) {
                        return .inactive_union_field;
                    }
                    break :val payload_mv;
                },
                else => unreachable,
            }

            break :val try agg_val.get_elem(zcu, base_index.index);
        },
    };

    if (ptr.byte_offset == 0 and host_bits == 0) {
        if (load_ty.zig_type_tag(zcu) != .Array or array_offset == 0) {
            if (.ok == try sema.coerce_in_memory_allowed(
                block,
                load_ty,
                base_val.type_of(zcu),
                false,
                zcu.get_target(),
                src,
                src,
            )) {
                // We already have a value which is IMC to the desired type.
                return .{ .success = base_val };
            }
        }
    }

    restructure_array: {
        if (host_bits != 0) break :restructure_array;

        // We might also be changing the length of an array, or restructuring it.
        // e.g. [1][2][3]T -> [3][2]T.
        // This case is important because it's permitted for types with ill-defined layouts.

        const load_one_ty, const load_count = load_ty.array_base(zcu);

        const extra_base_index: u64 = if (ptr.byte_offset == 0) 0 else idx: {
            if (try sema.type_requires_comptime(load_one_ty)) break :restructure_array;
            const elem_len = try sema.type_abi_size(load_one_ty);
            if (ptr.byte_offset % elem_len != 0) break :restructure_array;
            break :idx @div_exact(ptr.byte_offset, elem_len);
        };

        const val_one_ty, const val_count = base_val.type_of(zcu).array_base(zcu);
        if (.ok == try sema.coerce_in_memory_allowed(
            block,
            load_one_ty,
            val_one_ty,
            false,
            zcu.get_target(),
            src,
            src,
        )) {
            // Changing the length of an array.
            const skip_base: u64 = extra_base_index + if (load_ty.zig_type_tag(zcu) == .Array) skip: {
                break :skip load_ty.child_type(zcu).array_base(zcu)[1] * array_offset;
            } else 0;
            if (skip_base + load_count > val_count) return .{ .out_of_bounds = base_val.type_of(zcu) };
            const elems = try sema.arena.alloc(InternPool.Index, @int_cast(load_count));
            var skip: u64 = skip_base;
            var next_idx: u64 = 0;
            try flatten_array(sema, base_val, &skip, &next_idx, elems);
            next_idx = 0;
            const val = try unflatten_array(sema, load_ty, elems, &next_idx);
            return .{ .success = .{ .interned = val.to_intern() } };
        }
    }

    // We need to reinterpret memory, which is only possible if neither the load
    // type nor the type of the base value are comptime-only.

    if (!load_ty.has_well_defined_layout(zcu)) {
        return .{ .needed_well_defined = load_ty };
    }

    if (!base_val.type_of(zcu).has_well_defined_layout(zcu)) {
        return .{ .needed_well_defined = base_val.type_of(zcu) };
    }

    var cur_val = base_val;
    var cur_offset = ptr.byte_offset;

    if (load_ty.zig_type_tag(zcu) == .Array and array_offset > 0) {
        cur_offset += try sema.type_abi_size(load_ty.child_type(zcu)) * array_offset;
    }

    const need_bytes = if (host_bits > 0) (host_bits + 7) / 8 else try sema.type_abi_size(load_ty);

    if (cur_offset + need_bytes > try sema.type_abi_size(cur_val.type_of(zcu))) {
        return .{ .out_of_bounds = cur_val.type_of(zcu) };
    }

    // In the worst case, we can reinterpret the entire value - however, that's
    // pretty wasteful. If the memory region we're interested in refers to one
    // field or array element, let's just look at that.
    while (true) {
        const cur_ty = cur_val.type_of(zcu);
        switch (cur_ty.zig_type_tag(zcu)) {
            .NoReturn,
            .Type,
            .ComptimeInt,
            .ComptimeFloat,
            .Null,
            .Undefined,
            .EnumLiteral,
            .Opaque,
            .Fn,
            .ErrorUnion,
            => unreachable, // ill-defined layout
            .Int,
            .Float,
            .Bool,
            .Void,
            .Pointer,
            .ErrorSet,
            .AnyFrame,
            .Frame,
            .Enum,
            .Vector,
            => break, // terminal types (no sub-values)
            .Optional => break, // this can only be a pointer-like optional so is terminal
            .Array => {
                const elem_ty = cur_ty.child_type(zcu);
                const elem_size = try sema.type_abi_size(elem_ty);
                const elem_idx = cur_offset / elem_size;
                const next_elem_off = elem_size * (elem_idx + 1);
                if (cur_offset + need_bytes <= next_elem_off) {
                    // We can look at a single array element.
                    cur_val = try cur_val.get_elem(zcu, @int_cast(elem_idx));
                    cur_offset -= elem_idx * elem_size;
                } else {
                    break;
                }
            },
            .Struct => switch (cur_ty.container_layout(zcu)) {
                .auto => unreachable, // ill-defined layout
                .@"packed" => break, // let the bitcast logic handle this
                .@"extern" => for (0..cur_ty.struct_field_count(zcu)) |field_idx| {
                    const start_off = cur_ty.struct_field_offset(field_idx, zcu);
                    const end_off = start_off + try sema.type_abi_size(cur_ty.struct_field_type(field_idx, zcu));
                    if (cur_offset >= start_off and cur_offset + need_bytes <= end_off) {
                        cur_val = try cur_val.get_elem(zcu, field_idx);
                        cur_offset -= start_off;
                        break;
                    }
                } else break, // pointer spans multiple fields
            },
            .Union => switch (cur_ty.container_layout(zcu)) {
                .auto => unreachable, // ill-defined layout
                .@"packed" => break, // let the bitcast logic handle this
                .@"extern" => {
                    // TODO: we have to let bitcast logic handle this for now.
                    // Otherwise, we might traverse into a union field which doesn't allow pointers.
                    // Figure out a solution!
                    if (true) break;
                    const payload: MutableValue = switch (cur_val) {
                        .un => |un| un.payload.*,
                        .interned => |ip_index| switch (ip.index_to_key(ip_index)) {
                            .un => |un| .{ .interned = un.val },
                            .undef => return .undef,
                            else => unreachable,
                        },
                        else => unreachable,
                    };
                    // The payload always has offset 0. If it's big enough
                    // to represent the whole load type, we can use it.
                    if (try sema.type_abi_size(payload.type_of(zcu)) >= need_bytes) {
                        cur_val = payload;
                    } else {
                        break;
                    }
                },
            },
        }
    }

    // Fast path: check again if we're now at the type we want to load.
    // If so, just return the loaded value.
    if (cur_offset == 0 and host_bits == 0 and cur_val.type_of(zcu).to_intern() == load_ty.to_intern()) {
        return .{ .success = cur_val };
    }

    const result_val = try sema.bitCastVal(
        try cur_val.intern(zcu, sema.arena),
        load_ty,
        cur_offset,
        host_bits,
        bit_offset,
    ) orelse return .runtime_load;
    return .{ .success = .{ .interned = result_val.to_intern() } };
}

const ComptimeStoreStrategy = union(enum) {
    /// The store should be performed directly to this value, which `store_ty`
    /// is in-memory coercible to.
    direct: struct {
        alloc: ComptimeAllocIndex,
        val: *MutableValue,
    },
    /// The store should be performed at the index `elem_index` into `val`,
    /// which is an array.
    /// This strategy exists to avoid the need to convert the parent value
    /// to the `aggregate` representation when `repeated` or `bytes` may
    /// suffice.
    index: struct {
        alloc: ComptimeAllocIndex,
        val: *MutableValue,
        elem_index: u64,
    },
    /// The store should be performed on this array value, but it is being
    /// restructured, e.g. [3][2][1]T -> [2][3]T.
    /// This includes the case where it is a sub-array, e.g. [3]T -> [2]T.
    /// This is only returned if `store_ty` is an array type, and its array
    /// base type is IMC to that of the type of `val`.
    flat_index: struct {
        alloc: ComptimeAllocIndex,
        val: *MutableValue,
        flat_elem_index: u64,
    },
    /// This value should be reinterpreted using bitcast logic to perform the
    /// store. Only returned if `store_ty` and the type of `val` both have
    /// well-defined layouts.
    reinterpret: struct {
        alloc: ComptimeAllocIndex,
        val: *MutableValue,
        byte_offset: u64,
    },

    comptime_field,
    runtime_store,
    undef,
    err_payload: InternPool.NullTerminatedString,
    null_payload,
    inactive_union_field,
    needed_well_defined: Type,
    out_of_bounds: Type,

    fn alloc(strat: ComptimeStoreStrategy) ComptimeAllocIndex {
        return switch (strat) {
            inline .direct, .index, .flat_index, .reinterpret => |info| info.alloc,
            .comptime_field,
            .runtime_store,
            .undef,
            .err_payload,
            .null_payload,
            .inactive_union_field,
            .needed_well_defined,
            .out_of_bounds,
            => unreachable,
        };
    }
};

/// Decide the strategy we will use to perform a comptime store of type `store_ty` to a pointer.
/// The pointer's type is ignored.
fn prepare_comptime_ptr_store(
    sema: *Sema,
    block: *Block,
    src: LazySrcLoc,
    ptr_val: Value,
    store_ty: Type,
    /// If `store_ty` is an array, this is the number of array elements to skip
    /// before `store_ty`. Otherwise, it is ignored and may be `undefined`.
    array_offset: u64,
) !ComptimeStoreStrategy {
    const zcu = sema.mod;
    const ip = &zcu.intern_pool;

    const ptr = switch (ip.index_to_key(ptr_val.to_intern())) {
        .undef => return .undef,
        .ptr => |ptr| ptr,
        else => unreachable,
    };

    // `base_strat` will not be an error case.
    const base_strat: ComptimeStoreStrategy = switch (ptr.base_addr) {
        .decl, .anon_decl, .int => return .runtime_store,
        .comptime_field => return .comptime_field,
        .comptime_alloc => |alloc_index| .{ .direct = .{
            .alloc = alloc_index,
            .val = &sema.get_comptime_alloc(alloc_index).val,
        } },
        .eu_payload => |base_ptr_ip| base_val: {
            const base_ptr = Value.from_interned(base_ptr_ip);
            const base_ty = base_ptr.type_of(zcu).child_type(zcu);
            const eu_val_ptr, const alloc = switch (try prepare_comptime_ptr_store(sema, block, src, base_ptr, base_ty, undefined)) {
                .direct => |direct| .{ direct.val, direct.alloc },
                .index => |index| .{
                    try index.val.elem(zcu, sema.arena, @int_cast(index.elem_index)),
                    index.alloc,
                },
                .flat_index => unreachable, // base_ty is not an array
                .reinterpret => unreachable, // base_ty has ill-defined layout
                else => |err| return err,
            };
            try eu_val_ptr.unintern(zcu, sema.arena, false, false);
            switch (eu_val_ptr.*) {
                .interned => |ip_index| switch (ip.index_to_key(ip_index)) {
                    .undef => return .undef,
                    .error_union => |eu| return .{ .err_payload = eu.val.err_name },
                    else => unreachable,
                },
                .eu_payload => |data| break :base_val .{ .direct = .{
                    .val = data.child,
                    .alloc = alloc,
                } },
                else => unreachable,
            }
        },
        .opt_payload => |base_ptr_ip| base_val: {
            const base_ptr = Value.from_interned(base_ptr_ip);
            const base_ty = base_ptr.type_of(zcu).child_type(zcu);
            const opt_val_ptr, const alloc = switch (try prepare_comptime_ptr_store(sema, block, src, base_ptr, base_ty, undefined)) {
                .direct => |direct| .{ direct.val, direct.alloc },
                .index => |index| .{
                    try index.val.elem(zcu, sema.arena, @int_cast(index.elem_index)),
                    index.alloc,
                },
                .flat_index => unreachable, // base_ty is not an array
                .reinterpret => unreachable, // base_ty has ill-defined layout
                else => |err| return err,
            };
            try opt_val_ptr.unintern(zcu, sema.arena, false, false);
            switch (opt_val_ptr.*) {
                .interned => |ip_index| switch (ip.index_to_key(ip_index)) {
                    .undef => return .undef,
                    .opt => return .null_payload,
                    else => unreachable,
                },
                .opt_payload => |data| break :base_val .{ .direct = .{
                    .val = data.child,
                    .alloc = alloc,
                } },
                else => unreachable,
            }
        },
        .arr_elem => |base_index| base_val: {
            const base_ptr = Value.from_interned(base_index.base);
            const base_ty = base_ptr.type_of(zcu).child_type(zcu);

            // We have a comptime-only array. This case is a little nasty.
            // To avoid messing with too much data, we want to figure out how many elements we need to store.
            // If `store_ty` and the array share a base type, we'll store the correct number of elements.
            // Otherwise, we'll be reinterpreting (which we can't do, since it's comptime-only); just
            // load a single element and let the logic below emit its error.

            const store_one_ty, const store_count = store_ty.array_base(zcu);
            const count = if (store_one_ty.to_intern() == base_ty.to_intern()) store_count else 1;

            const want_ty = try zcu.array_type(.{
                .len = count,
                .child = base_ty.to_intern(),
            });

            const result = try prepare_comptime_ptr_store(sema, block, src, base_ptr, want_ty, base_index.index);
            switch (result) {
                .direct, .index, .flat_index => break :base_val result,
                .reinterpret => unreachable, // comptime-only array so ill-defined layout
                else => |err| return err,
            }
        },
        .field => |base_index| strat: {
            const base_ptr = Value.from_interned(base_index.base);
            const base_ty = base_ptr.type_of(zcu).child_type(zcu);

            // Field of a slice, or of an auto-layout struct or union.
            const agg_val, const alloc = switch (try prepare_comptime_ptr_store(sema, block, src, base_ptr, base_ty, undefined)) {
                .direct => |direct| .{ direct.val, direct.alloc },
                .index => |index| .{
                    try index.val.elem(zcu, sema.arena, @int_cast(index.elem_index)),
                    index.alloc,
                },
                .flat_index => unreachable, // base_ty is not an array
                .reinterpret => unreachable, // base_ty has ill-defined layout
                else => |err| return err,
            };

            const agg_ty = agg_val.type_of(zcu);
            switch (agg_ty.zig_type_tag(zcu)) {
                .Struct, .Pointer => break :strat .{ .direct = .{
                    .val = try agg_val.elem(zcu, sema.arena, @int_cast(base_index.index)),
                    .alloc = alloc,
                } },
                .Union => {
                    if (agg_val.* == .interned and Value.from_interned(agg_val.interned).is_undef(zcu)) {
                        return .undef;
                    }
                    try agg_val.unintern(zcu, sema.arena, false, false);
                    const un = agg_val.un;
                    const tag_ty = agg_ty.union_tag_type_hypothetical(zcu);
                    if (tag_ty.enum_tag_field_index(Value.from_interned(un.tag), zcu).? != base_index.index) {
                        return .inactive_union_field;
                    }
                    break :strat .{ .direct = .{
                        .val = un.payload,
                        .alloc = alloc,
                    } };
                },
                else => unreachable,
            }
        },
    };

    if (ptr.byte_offset == 0) {
        if (store_ty.zig_type_tag(zcu) != .Array or array_offset == 0) direct: {
            const base_val_ty = switch (base_strat) {
                .direct => |direct| direct.val.type_of(zcu),
                .index => |index| index.val.type_of(zcu).child_type(zcu),
                .flat_index, .reinterpret => break :direct,
                else => unreachable,
            };
            if (.ok == try sema.coerce_in_memory_allowed(
                block,
                base_val_ty,
                store_ty,
                true,
                zcu.get_target(),
                src,
                src,
            )) {
                // The base strategy already gets us a value which the desired type is IMC to.
                return base_strat;
            }
        }
    }

    restructure_array: {
        // We might also be changing the length of an array, or restructuring it.
        // e.g. [1][2][3]T -> [3][2]T.
        // This case is important because it's permitted for types with ill-defined layouts.

        const store_one_ty, const store_count = store_ty.array_base(zcu);
        const extra_base_index: u64 = if (ptr.byte_offset == 0) 0 else idx: {
            if (try sema.type_requires_comptime(store_one_ty)) break :restructure_array;
            const elem_len = try sema.type_abi_size(store_one_ty);
            if (ptr.byte_offset % elem_len != 0) break :restructure_array;
            break :idx @div_exact(ptr.byte_offset, elem_len);
        };

        const base_val, const base_elem_offset, const oob_ty = switch (base_strat) {
            .direct => |direct| .{ direct.val, 0, direct.val.type_of(zcu) },
            .index => |index| restructure_info: {
                const elem_ty = index.val.type_of(zcu).child_type(zcu);
                const elem_off = elem_ty.array_base(zcu)[1] * index.elem_index;
                break :restructure_info .{ index.val, elem_off, elem_ty };
            },
            .flat_index => |flat| .{ flat.val, flat.flat_elem_index, flat.val.type_of(zcu) },
            .reinterpret => break :restructure_array,
            else => unreachable,
        };
        const val_one_ty, const val_count = base_val.type_of(zcu).array_base(zcu);
        if (.ok != try sema.coerce_in_memory_allowed(block, val_one_ty, store_one_ty, true, zcu.get_target(), src, src)) {
            break :restructure_array;
        }
        if (base_elem_offset + extra_base_index + store_count > val_count) return .{ .out_of_bounds = oob_ty };

        if (store_ty.zig_type_tag(zcu) == .Array) {
            const skip = store_ty.child_type(zcu).array_base(zcu)[1] * array_offset;
            return .{ .flat_index = .{
                .alloc = base_strat.alloc(),
                .val = base_val,
                .flat_elem_index = skip + base_elem_offset + extra_base_index,
            } };
        }

        // `base_val` must be an array, since otherwise the "direct reinterpret" logic above noticed it.
        assert(base_val.type_of(zcu).zig_type_tag(zcu) == .Array);

        var index: u64 = base_elem_offset + extra_base_index;
        const arr_val, const arr_index = (try recursive_index(sema, base_val, &index)).?;
        return .{ .index = .{
            .alloc = base_strat.alloc(),
            .val = arr_val,
            .elem_index = arr_index,
        } };
    }

    // We need to reinterpret memory, which is only possible if neither the store
    // type nor the type of the base value have an ill-defined layout.

    if (!store_ty.has_well_defined_layout(zcu)) {
        return .{ .needed_well_defined = store_ty };
    }

    var cur_val: *MutableValue, var cur_offset: u64 = switch (base_strat) {
        .direct => |direct| .{ direct.val, 0 },
        // It's okay to do `abi_size` - the comptime-only case will be caught below.
        .index => |index| .{ index.val, index.elem_index * try sema.type_abi_size(index.val.type_of(zcu).child_type(zcu)) },
        .flat_index => |flat_index| .{
            flat_index.val,
            // It's okay to do `abi_size` - the comptime-only case will be caught below.
            flat_index.flat_elem_index * try sema.type_abi_size(flat_index.val.type_of(zcu).array_base(zcu)[0]),
        },
        .reinterpret => |r| .{ r.val, r.byte_offset },
        else => unreachable,
    };
    cur_offset += ptr.byte_offset;

    if (!cur_val.type_of(zcu).has_well_defined_layout(zcu)) {
        return .{ .needed_well_defined = cur_val.type_of(zcu) };
    }

    if (store_ty.zig_type_tag(zcu) == .Array and array_offset > 0) {
        cur_offset += try sema.type_abi_size(store_ty.child_type(zcu)) * array_offset;
    }

    const need_bytes = try sema.type_abi_size(store_ty);

    if (cur_offset + need_bytes > try sema.type_abi_size(cur_val.type_of(zcu))) {
        return .{ .out_of_bounds = cur_val.type_of(zcu) };
    }

    // In the worst case, we can reinterpret the entire value - however, that's
    // pretty wasteful. If the memory region we're interested in refers to one
    // field or array element, let's just look at that.
    while (true) {
        const cur_ty = cur_val.type_of(zcu);
        switch (cur_ty.zig_type_tag(zcu)) {
            .NoReturn,
            .Type,
            .ComptimeInt,
            .ComptimeFloat,
            .Null,
            .Undefined,
            .EnumLiteral,
            .Opaque,
            .Fn,
            .ErrorUnion,
            => unreachable, // ill-defined layout
            .Int,
            .Float,
            .Bool,
            .Void,
            .Pointer,
            .ErrorSet,
            .AnyFrame,
            .Frame,
            .Enum,
            .Vector,
            => break, // terminal types (no sub-values)
            .Optional => break, // this can only be a pointer-like optional so is terminal
            .Array => {
                const elem_ty = cur_ty.child_type(zcu);
                const elem_size = try sema.type_abi_size(elem_ty);
                const elem_idx = cur_offset / elem_size;
                const next_elem_off = elem_size * (elem_idx + 1);
                if (cur_offset + need_bytes <= next_elem_off) {
                    // We can look at a single array element.
                    cur_val = try cur_val.elem(zcu, sema.arena, @int_cast(elem_idx));
                    cur_offset -= elem_idx * elem_size;
                } else {
                    break;
                }
            },
            .Struct => switch (cur_ty.container_layout(zcu)) {
                .auto => unreachable, // ill-defined layout
                .@"packed" => break, // let the bitcast logic handle this
                .@"extern" => for (0..cur_ty.struct_field_count(zcu)) |field_idx| {
                    const start_off = cur_ty.struct_field_offset(field_idx, zcu);
                    const end_off = start_off + try sema.type_abi_size(cur_ty.struct_field_type(field_idx, zcu));
                    if (cur_offset >= start_off and cur_offset + need_bytes <= end_off) {
                        cur_val = try cur_val.elem(zcu, sema.arena, field_idx);
                        cur_offset -= start_off;
                        break;
                    }
                } else break, // pointer spans multiple fields
            },
            .Union => switch (cur_ty.container_layout(zcu)) {
                .auto => unreachable, // ill-defined layout
                .@"packed" => break, // let the bitcast logic handle this
                .@"extern" => {
                    // TODO: we have to let bitcast logic handle this for now.
                    // Otherwise, we might traverse into a union field which doesn't allow pointers.
                    // Figure out a solution!
                    if (true) break;
                    try cur_val.unintern(zcu, sema.arena, false, false);
                    const payload = switch (cur_val.*) {
                        .un => |un| un.payload,
                        else => unreachable,
                    };
                    // The payload always has offset 0. If it's big enough
                    // to represent the whole load type, we can use it.
                    if (try sema.type_abi_size(payload.type_of(zcu)) >= need_bytes) {
                        cur_val = payload;
                    } else {
                        break;
                    }
                },
            },
        }
    }

    // Fast path: check again if we're now at the type we want to store.
    // If so, we can use the `direct` strategy.
    if (cur_offset == 0 and cur_val.type_of(zcu).to_intern() == store_ty.to_intern()) {
        return .{ .direct = .{
            .alloc = base_strat.alloc(),
            .val = cur_val,
        } };
    }

    return .{ .reinterpret = .{
        .alloc = base_strat.alloc(),
        .val = cur_val,
        .byte_offset = cur_offset,
    } };
}

/// Given a potentially-nested array value, recursively flatten all of its elements into the given
/// output array. The result can be used by `unflatten_array` to restructure array values.
fn flatten_array(
    sema: *Sema,
    val: MutableValue,
    skip: *u64,
    next_idx: *u64,
    out: []InternPool.Index,
) Allocator.Error!void {
    if (next_idx.* == out.len) return;

    const zcu = sema.mod;

    const ty = val.type_of(zcu);
    const base_elem_count = ty.array_base(zcu)[1];
    if (skip.* >= base_elem_count) {
        skip.* -= base_elem_count;
        return;
    }

    if (ty.zig_type_tag(zcu) != .Array) {
        out[@int_cast(next_idx.*)] = (try val.intern(zcu, sema.arena)).to_intern();
        next_idx.* += 1;
        return;
    }

    const arr_base_elem_count = ty.child_type(zcu).array_base(zcu)[1];
    for (0..@int_cast(ty.array_len(zcu))) |elem_idx| {
        // Optimization: the `get_elem` here may be expensive since we might intern an
        // element of the `bytes` representation, so avoid doing it unnecessarily.
        if (next_idx.* == out.len) return;
        if (skip.* >= arr_base_elem_count) {
            skip.* -= arr_base_elem_count;
            continue;
        }
        try flatten_array(sema, try val.get_elem(zcu, elem_idx), skip, next_idx, out);
    }
    if (ty.sentinel(zcu)) |s| {
        try flatten_array(sema, .{ .interned = s.to_intern() }, skip, next_idx, out);
    }
}

/// Given a sequence of non-array elements, "unflatten" them into the given array type.
/// Asserts that values of `elems` are in-memory coercible to the array base type of `ty`.
fn unflatten_array(
    sema: *Sema,
    ty: Type,
    elems: []const InternPool.Index,
    next_idx: *u64,
) Allocator.Error!Value {
    const zcu = sema.mod;
    const arena = sema.arena;

    if (ty.zig_type_tag(zcu) != .Array) {
        const val = Value.from_interned(elems[@int_cast(next_idx.*)]);
        next_idx.* += 1;
        return zcu.get_coerced(val, ty);
    }

    const elem_ty = ty.child_type(zcu);
    const buf = try arena.alloc(InternPool.Index, @int_cast(ty.array_len(zcu)));
    for (buf) |*elem| {
        elem.* = (try unflatten_array(sema, elem_ty, elems, next_idx)).to_intern();
    }
    if (ty.sentinel(zcu) != null) {
        // TODO: validate sentinel
        _ = try unflatten_array(sema, elem_ty, elems, next_idx);
    }
    return Value.from_interned(try zcu.intern(.{ .aggregate = .{
        .ty = ty.to_intern(),
        .storage = .{ .elems = buf },
    } }));
}

/// Given a `MutableValue` representing a potentially-nested array, treats `index` as an index into
/// the array's base type. For instance, given a [3][3]T, the index 5 represents 'val[1][2]'.
/// The final level of array is not dereferenced. This allows use sites to use `set_elem` to prevent
/// unnecessary `MutableValue` representation changes.
fn recursive_index(
    sema: *Sema,
    mv: *MutableValue,
    index: *u64,
) !?struct { *MutableValue, u64 } {
    const zcu = sema.mod;

    const ty = mv.type_of(zcu);
    assert(ty.zig_type_tag(zcu) == .Array);

    const ty_base_elems = ty.array_base(zcu)[1];
    if (index.* >= ty_base_elems) {
        index.* -= ty_base_elems;
        return null;
    }

    const elem_ty = ty.child_type(zcu);
    if (elem_ty.zig_type_tag(zcu) != .Array) {
        assert(index.* < ty.array_len_including_sentinel(zcu)); // should be handled by initial check
        return .{ mv, index.* };
    }

    for (0..@int_cast(ty.array_len_including_sentinel(zcu))) |elem_index| {
        if (try recursive_index(sema, try mv.elem(zcu, sema.arena, elem_index), index)) |result| {
            return result;
        }
    }
    unreachable; // should be handled by initial check
}

fn check_comptime_var_store(
    sema: *Sema,
    block: *Block,
    src: LazySrcLoc,
    alloc_index: ComptimeAllocIndex,
) !void {
    const runtime_index = sema.get_comptime_alloc(alloc_index).runtime_index;
    if (@int_from_enum(runtime_index) < @int_from_enum(block.runtime_index)) {
        if (block.runtime_cond) |cond_src| {
            const msg = msg: {
                const msg = try sema.err_msg(block, src, "store to comptime variable depends on runtime condition", .{});
                errdefer msg.destroy(sema.gpa);
                try sema.mod.err_note_non_lazy(cond_src, msg, "runtime condition here", .{});
                break :msg msg;
            };
            return sema.fail_with_owned_error_msg(block, msg);
        }
        if (block.runtime_loop) |loop_src| {
            const msg = msg: {
                const msg = try sema.err_msg(block, src, "cannot store to comptime variable in non-inline loop", .{});
                errdefer msg.destroy(sema.gpa);
                try sema.mod.err_note_non_lazy(loop_src, msg, "non-inline loop here", .{});
                break :msg msg;
            };
            return sema.fail_with_owned_error_msg(block, msg);
        }
        unreachable;
    }
}

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const LazySrcLoc = std.zig.LazySrcLoc;

const InternPool = @import("../InternPool.zig");
const ComptimeAllocIndex = InternPool.ComptimeAllocIndex;
const Sema = @import("../Sema.zig");
const Block = Sema.Block;
const MutableValue = @import("../mutable_value.zig").MutableValue;
const Type = @import("../type.zig").Type;
const Value = @import("../Value.zig");
