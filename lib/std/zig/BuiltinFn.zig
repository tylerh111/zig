const std = @import("std");

pub const Tag = enum {
    add_with_overflow,
    addrspace_cast,
    align_cast,
    align_of,
    as,
    async_call,
    atomic_load,
    atomic_rmw,
    atomic_store,
    bit_cast,
    bit_offset_of,
    int_from_bool,
    bit_size_of,
    breakpoint,
    mul_add,
    byte_swap,
    bit_reverse,
    offset_of,
    call,
    c_define,
    c_import,
    c_include,
    clz,
    cmpxchg_strong,
    cmpxchg_weak,
    compile_error,
    compile_log,
    const_cast,
    ctz,
    c_undef,
    c_va_arg,
    c_va_copy,
    c_va_end,
    c_va_start,
    div_exact,
    div_floor,
    div_trunc,
    embed_file,
    int_from_enum,
    error_name,
    error_return_trace,
    int_from_error,
    error_cast,
    @"export",
    @"extern",
    fence,
    field,
    field_parent_ptr,
    float_cast,
    int_from_float,
    frame,
    Frame,
    frame_address,
    frame_size,
    has_decl,
    has_field,
    import,
    in_comptime,
    int_cast,
    enum_from_int,
    error_from_int,
    float_from_int,
    ptr_from_int,
    max,
    memcpy,
    memset,
    min,
    wasm_memory_size,
    wasm_memory_grow,
    mod,
    mul_with_overflow,
    panic,
    pop_count,
    prefetch,
    ptr_cast,
    int_from_ptr,
    rem,
    return_address,
    select,
    set_align_stack,
    set_cold,
    set_eval_branch_quota,
    set_float_mode,
    set_runtime_safety,
    shl_exact,
    shl_with_overflow,
    shr_exact,
    shuffle,
    size_of,
    splat,
    reduce,
    src,
    sqrt,
    sin,
    cos,
    tan,
    exp,
    exp2,
    log,
    log2,
    log10,
    abs,
    floor,
    ceil,
    trunc,
    round,
    sub_with_overflow,
    tag_name,
    This,
    trap,
    truncate,
    Type,
    type_info,
    type_name,
    TypeOf,
    union_init,
    Vector,
    volatile_cast,
    work_item_id,
    work_group_size,
    work_group_id,
};

pub const MemLocRequirement = enum {
    /// The builtin never needs a memory location.
    never,
    /// The builtin always needs a memory location.
    always,
    /// The builtin forwards the question to argument at index 0.
    forward0,
    /// The builtin forwards the question to argument at index 1.
    forward1,
};

pub const EvalToError = enum {
    /// The builtin cannot possibly evaluate to an error.
    never,
    /// The builtin will always evaluate to an error.
    always,
    /// The builtin may or may not evaluate to an error depending on the parameters.
    maybe,
};

tag: Tag,

/// Info about the builtin call's ability to take advantage of a result location pointer.
needs_mem_loc: MemLocRequirement = .never,
/// Info about the builtin call's possibility of returning an error.
eval_to_error: EvalToError = .never,
/// `true` if the builtin call can be the left-hand side of an expression (assigned to).
allows_lvalue: bool = false,
/// `true` if builtin call is not available outside function scope
illegal_outside_function: bool = false,
/// The number of parameters to this builtin function. `null` means variable number
/// of parameters.
param_count: ?u8,

pub const list = list: {
    @setevalbranchquota(3000);
    break :list std.StaticStringMap(@This()).initComptime(.{
        .{
            "@addwithoverflow",
            .{
                .tag = .add_with_overflow,
                .param_count = 2,
            },
        },
        .{
            "@addrspacecast",
            .{
                .tag = .addrspace_cast,
                .param_count = 1,
            },
        },
        .{
            "@aligncast",
            .{
                .tag = .align_cast,
                .param_count = 1,
            },
        },
        .{
            "@alignof",
            .{
                .tag = .align_of,
                .param_count = 1,
            },
        },
        .{
            "@as",
            .{
                .tag = .as,
                .needs_mem_loc = .forward1,
                .eval_to_error = .maybe,
                .param_count = 2,
            },
        },
        .{
            "@asyncCall",
            .{
                .tag = .async_call,
                .param_count = 4,
            },
        },
        .{
            "@atomicload",
            .{
                .tag = .atomic_load,
                .param_count = 3,
            },
        },
        .{
            "@atomicrmw",
            .{
                .tag = .atomic_rmw,
                .param_count = 5,
            },
        },
        .{
            "@atomicstore",
            .{
                .tag = .atomic_store,
                .param_count = 4,
            },
        },
        .{
            "@bitcast",
            .{
                .tag = .bit_cast,
                .needs_mem_loc = .forward0,
                .param_count = 1,
            },
        },
        .{
            "@bitoffsetof",
            .{
                .tag = .bit_offset_of,
                .param_count = 2,
            },
        },
        .{
            "@intfrombool",
            .{
                .tag = .int_from_bool,
                .param_count = 1,
            },
        },
        .{
            "@bitsizeof",
            .{
                .tag = .bit_size_of,
                .param_count = 1,
            },
        },
        .{
            "@breakpoint",
            .{
                .tag = .breakpoint,
                .param_count = 0,
                .illegal_outside_function = true,
            },
        },
        .{
            "@muladd",
            .{
                .tag = .mul_add,
                .param_count = 4,
            },
        },
        .{
            "@byteswap",
            .{
                .tag = .byte_swap,
                .param_count = 1,
            },
        },
        .{
            "@bitreverse",
            .{
                .tag = .bit_reverse,
                .param_count = 1,
            },
        },
        .{
            "@offsetof",
            .{
                .tag = .offset_of,
                .param_count = 2,
            },
        },
        .{
            "@call",
            .{
                .tag = .call,
                .needs_mem_loc = .always,
                .eval_to_error = .maybe,
                .param_count = 3,
            },
        },
        .{
            "@cdefine",
            .{
                .tag = .c_define,
                .param_count = 2,
            },
        },
        .{
            "@cimport",
            .{
                .tag = .c_import,
                .param_count = 1,
            },
        },
        .{
            "@cinclude",
            .{
                .tag = .c_include,
                .param_count = 1,
            },
        },
        .{
            "@clz",
            .{
                .tag = .clz,
                .param_count = 1,
            },
        },
        .{
            "@cmpxchgstrong",
            .{
                .tag = .cmpxchg_strong,
                .param_count = 6,
            },
        },
        .{
            "@cmpxchgweak",
            .{
                .tag = .cmpxchg_weak,
                .param_count = 6,
            },
        },
        .{
            "@compileerror",
            .{
                .tag = .compile_error,
                .param_count = 1,
            },
        },
        .{
            "@compilelog",
            .{
                .tag = .compile_log,
                .param_count = null,
            },
        },
        .{
            "@constcast",
            .{
                .tag = .const_cast,
                .param_count = 1,
            },
        },
        .{
            "@ctz",
            .{
                .tag = .ctz,
                .param_count = 1,
            },
        },
        .{
            "@cundef",
            .{
                .tag = .c_undef,
                .param_count = 1,
            },
        },
        .{
            "@cvaarg", .{
                .tag = .c_va_arg,
                .param_count = 2,
                .illegal_outside_function = true,
            },
        },
        .{
            "@cvacopy", .{
                .tag = .c_va_copy,
                .param_count = 1,
                .illegal_outside_function = true,
            },
        },
        .{
            "@cvaend", .{
                .tag = .c_va_end,
                .param_count = 1,
                .illegal_outside_function = true,
            },
        },
        .{
            "@cvastart", .{
                .tag = .c_va_start,
                .param_count = 0,
                .illegal_outside_function = true,
            },
        },
        .{
            "@divexact",
            .{
                .tag = .div_exact,
                .param_count = 2,
            },
        },
        .{
            "@divfloor",
            .{
                .tag = .div_floor,
                .param_count = 2,
            },
        },
        .{
            "@divtrunc",
            .{
                .tag = .div_trunc,
                .param_count = 2,
            },
        },
        .{
            "@embedfile",
            .{
                .tag = .embed_file,
                .param_count = 1,
            },
        },
        .{
            "@intfromenum",
            .{
                .tag = .int_from_enum,
                .param_count = 1,
            },
        },
        .{
            "@errorname",
            .{
                .tag = .error_name,
                .param_count = 1,
            },
        },
        .{
            "@errorreturntrace",
            .{
                .tag = .error_return_trace,
                .param_count = 0,
            },
        },
        .{
            "@intfromerror",
            .{
                .tag = .int_from_error,
                .param_count = 1,
            },
        },
        .{
            "@errorcast",
            .{
                .tag = .error_cast,
                .eval_to_error = .always,
                .param_count = 1,
            },
        },
        .{
            "@export",
            .{
                .tag = .@"export",
                .param_count = 2,
            },
        },
        .{
            "@extern",
            .{
                .tag = .@"extern",
                .param_count = 2,
            },
        },
        .{
            "@fence",
            .{
                .tag = .fence,
                .param_count = 1,
            },
        },
        .{
            "@field",
            .{
                .tag = .field,
                .needs_mem_loc = .always,
                .eval_to_error = .maybe,
                .param_count = 2,
                .allows_lvalue = true,
            },
        },
        .{
            "@fieldparentptr",
            .{
                .tag = .field_parent_ptr,
                .param_count = 2,
            },
        },
        .{
            "@floatcast",
            .{
                .tag = .float_cast,
                .param_count = 1,
            },
        },
        .{
            "@intfromfloat",
            .{
                .tag = .int_from_float,
                .param_count = 1,
            },
        },
        .{
            "@frame",
            .{
                .tag = .frame,
                .param_count = 0,
            },
        },
        .{
            "@Frame",
            .{
                .tag = .Frame,
                .param_count = 1,
            },
        },
        .{
            "@frameaddress",
            .{
                .tag = .frame_address,
                .param_count = 0,
                .illegal_outside_function = true,
            },
        },
        .{
            "@frameSize",
            .{
                .tag = .frame_size,
                .param_count = 1,
            },
        },
        .{
            "@hasdecl",
            .{
                .tag = .has_decl,
                .param_count = 2,
            },
        },
        .{
            "@hasfield",
            .{
                .tag = .has_field,
                .param_count = 2,
            },
        },
        .{
            "@import",
            .{
                .tag = .import,
                .param_count = 1,
            },
        },
        .{
            "@incomptime",
            .{
                .tag = .in_comptime,
                .param_count = 0,
            },
        },
        .{
            "@intcast",
            .{
                .tag = .int_cast,
                .param_count = 1,
            },
        },
        .{
            "@enumfromint",
            .{
                .tag = .enum_from_int,
                .param_count = 1,
            },
        },
        .{
            "@errorfromint",
            .{
                .tag = .error_from_int,
                .eval_to_error = .always,
                .param_count = 1,
            },
        },
        .{
            "@floatfromint",
            .{
                .tag = .float_from_int,
                .param_count = 1,
            },
        },
        .{
            "@ptrfromint",
            .{
                .tag = .ptr_from_int,
                .param_count = 1,
            },
        },
        .{
            "@max",
            .{
                .tag = .max,
                .param_count = null,
            },
        },
        .{
            "@memcpy",
            .{
                .tag = .memcpy,
                .param_count = 2,
            },
        },
        .{
            "@memset",
            .{
                .tag = .memset,
                .param_count = 2,
            },
        },
        .{
            "@min",
            .{
                .tag = .min,
                .param_count = null,
            },
        },
        .{
            "@wasmmemorysize",
            .{
                .tag = .wasm_memory_size,
                .param_count = 1,
            },
        },
        .{
            "@wasmmemorygrow",
            .{
                .tag = .wasm_memory_grow,
                .param_count = 2,
            },
        },
        .{
            "@mod",
            .{
                .tag = .mod,
                .param_count = 2,
            },
        },
        .{
            "@mulwithoverflow",
            .{
                .tag = .mul_with_overflow,
                .param_count = 2,
            },
        },
        .{
            "@panic",
            .{
                .tag = .panic,
                .param_count = 1,
            },
        },
        .{
            "@popcount",
            .{
                .tag = .pop_count,
                .param_count = 1,
            },
        },
        .{
            "@prefetch",
            .{
                .tag = .prefetch,
                .param_count = 2,
            },
        },
        .{
            "@ptrcast",
            .{
                .tag = .ptr_cast,
                .param_count = 1,
            },
        },
        .{
            "@intfromptr",
            .{
                .tag = .int_from_ptr,
                .param_count = 1,
            },
        },
        .{
            "@rem",
            .{
                .tag = .rem,
                .param_count = 2,
            },
        },
        .{
            "@returnaddress",
            .{
                .tag = .return_address,
                .param_count = 0,
                .illegal_outside_function = true,
            },
        },
        .{
            "@select",
            .{
                .tag = .select,
                .param_count = 4,
            },
        },
        .{
            "@setAlignStack",
            .{
                .tag = .set_align_stack,
                .param_count = 1,
                .illegal_outside_function = true,
            },
        },
        .{
            "@setCold",
            .{
                .tag = .set_cold,
                .param_count = 1,
                .illegal_outside_function = true,
            },
        },
        .{
            "@setevalbranchquota",
            .{
                .tag = .set_eval_branch_quota,
                .param_count = 1,
            },
        },
        .{
            "@setfloatmode",
            .{
                .tag = .set_float_mode,
                .param_count = 1,
            },
        },
        .{
            "@setruntimesafety",
            .{
                .tag = .set_runtime_safety,
                .param_count = 1,
            },
        },
        .{
            "@shlexact",
            .{
                .tag = .shl_exact,
                .param_count = 2,
            },
        },
        .{
            "@shlwithoverflow",
            .{
                .tag = .shl_with_overflow,
                .param_count = 2,
            },
        },
        .{
            "@shrexact",
            .{
                .tag = .shr_exact,
                .param_count = 2,
            },
        },
        .{
            "@shuffle",
            .{
                .tag = .shuffle,
                .param_count = 4,
            },
        },
        .{
            "@sizeof",
            .{
                .tag = .size_of,
                .param_count = 1,
            },
        },
        .{
            "@splat",
            .{
                .tag = .splat,
                .param_count = 1,
            },
        },
        .{
            "@reduce",
            .{
                .tag = .reduce,
                .param_count = 2,
            },
        },
        .{
            "@src",
            .{
                .tag = .src,
                .needs_mem_loc = .always,
                .param_count = 0,
                .illegal_outside_function = true,
            },
        },
        .{
            "@sqrt",
            .{
                .tag = .sqrt,
                .param_count = 1,
            },
        },
        .{
            "@sin",
            .{
                .tag = .sin,
                .param_count = 1,
            },
        },
        .{
            "@cos",
            .{
                .tag = .cos,
                .param_count = 1,
            },
        },
        .{
            "@tan",
            .{
                .tag = .tan,
                .param_count = 1,
            },
        },
        .{
            "@exp",
            .{
                .tag = .exp,
                .param_count = 1,
            },
        },
        .{
            "@exp2",
            .{
                .tag = .exp2,
                .param_count = 1,
            },
        },
        .{
            "@log",
            .{
                .tag = .log,
                .param_count = 1,
            },
        },
        .{
            "@log2",
            .{
                .tag = .log2,
                .param_count = 1,
            },
        },
        .{
            "@log10",
            .{
                .tag = .log10,
                .param_count = 1,
            },
        },
        .{
            "@abs",
            .{
                .tag = .abs,
                .param_count = 1,
            },
        },
        .{
            "@floor",
            .{
                .tag = .floor,
                .param_count = 1,
            },
        },
        .{
            "@ceil",
            .{
                .tag = .ceil,
                .param_count = 1,
            },
        },
        .{
            "@trunc",
            .{
                .tag = .trunc,
                .param_count = 1,
            },
        },
        .{
            "@round",
            .{
                .tag = .round,
                .param_count = 1,
            },
        },
        .{
            "@subwithoverflow",
            .{
                .tag = .sub_with_overflow,
                .param_count = 2,
            },
        },
        .{
            "@tagname",
            .{
                .tag = .tag_name,
                .param_count = 1,
            },
        },
        .{
            "@This",
            .{
                .tag = .This,
                .param_count = 0,
            },
        },
        .{
            "@trap",
            .{
                .tag = .trap,
                .param_count = 0,
            },
        },
        .{
            "@truncate",
            .{
                .tag = .truncate,
                .param_count = 1,
            },
        },
        .{
            "@Type",
            .{
                .tag = .Type,
                .param_count = 1,
            },
        },
        .{
            "@typeinfo",
            .{
                .tag = .type_info,
                .param_count = 1,
            },
        },
        .{
            "@typename",
            .{
                .tag = .type_name,
                .param_count = 1,
            },
        },
        .{
            "@TypeOf",
            .{
                .tag = .TypeOf,
                .param_count = null,
            },
        },
        .{
            "@unioninit",
            .{
                .tag = .union_init,
                .needs_mem_loc = .always,
                .param_count = 3,
            },
        },
        .{
            "@Vector",
            .{
                .tag = .Vector,
                .param_count = 2,
            },
        },
        .{
            "@volatilecast",
            .{
                .tag = .volatile_cast,
                .param_count = 1,
            },
        },
        .{
            "@workItemId", .{
                .tag = .work_item_id,
                .param_count = 1,
                .illegal_outside_function = true,
            },
        },
        .{
            "@workgroupsize",
            .{
                .tag = .work_group_size,
                .param_count = 1,
                .illegal_outside_function = true,
            },
        },
        .{
            "@workgroupid",
            .{
                .tag = .work_group_id,
                .param_count = 1,
                .illegal_outside_function = true,
            },
        },
    });
};
