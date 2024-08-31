const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const assert = std.debug.assert;
const testing = std.testing;
const leb = std.leb;
const mem = std.mem;
const wasm = std.wasm;
const log = std.log.scoped(.codegen);

const codegen = @import("../../codegen.zig");
const Module = @import("../../Module.zig");
const InternPool = @import("../../InternPool.zig");
const Decl = Module.Decl;
const Type = @import("../../type.zig").Type;
const Value = @import("../../Value.zig");
const Compilation = @import("../../Compilation.zig");
const LazySrcLoc = std.zig.LazySrcLoc;
const link = @import("../../link.zig");
const Air = @import("../../Air.zig");
const Liveness = @import("../../Liveness.zig");
const target_util = @import("../../target.zig");
const Mir = @import("Mir.zig");
const Emit = @import("Emit.zig");
const abi = @import("abi.zig");
const Alignment = InternPool.Alignment;
const err_union_payload_offset = codegen.err_union_payload_offset;
const err_union_error_offset = codegen.err_union_error_offset;

/// Wasm Value, created when generating an instruction
const WValue = union(enum) {
    /// `WValue` which has been freed and may no longer hold
    /// any references.
    dead: void,
    /// May be referenced but is unused
    none: void,
    /// The value lives on top of the stack
    stack: void,
    /// Index of the local
    local: struct {
        /// Contains the index to the local
        value: u32,
        /// The amount of instructions referencing this `WValue`
        references: u32,
    },
    /// An immediate 32bit value
    imm32: u32,
    /// An immediate 64bit value
    imm64: u64,
    /// Index into the list of simd128 immediates. This `WValue` is
    /// only possible in very rare cases, therefore it would be
    /// a waste of memory to store the value in a 128 bit integer.
    imm128: u32,
    /// A constant 32bit float value
    float32: f32,
    /// A constant 64bit float value
    float64: f64,
    /// A value that represents a pointer to the data section
    /// Note: The value contains the symbol index, rather than the actual address
    /// as we use this to perform the relocation.
    memory: u32,
    /// A value that represents a parent pointer and an offset
    /// from that pointer. i.e. when slicing with constant values.
    memory_offset: struct {
        /// The symbol of the parent pointer
        pointer: u32,
        /// Offset will be set as addend when relocating
        offset: u32,
    },
    /// Represents a function pointer
    /// In wasm function pointers are indexes into a function table,
    /// rather than an address in the data section.
    function_index: u32,
    /// Offset from the bottom of the virtual stack, with the offset
    /// pointing to where the value lives.
    stack_offset: struct {
        /// Contains the actual value of the offset
        value: u32,
        /// The amount of instructions referencing this `WValue`
        references: u32,
    },

    /// Returns the offset from the bottom of the stack. This is useful when
    /// we use the load or store instruction to ensure we retrieve the value
    /// from the correct position, rather than the value that lives at the
    /// bottom of the stack. For instances where `WValue` is not `stack_value`
    /// this will return 0, which allows us to simply call this function for all
    /// loads and stores without requiring checks everywhere.
    fn offset(value: WValue) u32 {
        switch (value) {
            .stack_offset => |stack_offset| return stack_offset.value,
            .dead => unreachable,
            else => return 0,
        }
    }

    /// Promotes a `WValue` to a local when given value is on top of the stack.
    /// When encountering a `local` or `stack_offset` this is essentially a no-op.
    /// All other tags are illegal.
    fn to_local(value: WValue, gen: *CodeGen, ty: Type) InnerError!WValue {
        switch (value) {
            .stack => {
                const new_local = try gen.alloc_local(ty);
                try gen.add_label(.local_set, new_local.local.value);
                return new_local;
            },
            .local, .stack_offset => return value,
            else => unreachable,
        }
    }

    /// Marks a local as no longer being referenced and essentially allows
    /// us to re-use it somewhere else within the function.
    /// The valtype of the local is deducted by using the index of the given `WValue`.
    fn free(value: *WValue, gen: *CodeGen) void {
        if (value.* != .local) return;
        const local_value = value.local.value;
        const reserved = gen.args.len + @int_from_bool(gen.return_value != .none);
        if (local_value < reserved + 2) return; // reserved locals may never be re-used. Also accounts for 2 stack locals.

        const index = local_value - reserved;
        const valtype = @as(wasm.Valtype, @enumFromInt(gen.locals.items[index]));
        switch (valtype) {
            .i32 => gen.free_locals_i32.append(gen.gpa, local_value) catch return, // It's ok to fail any of those, a new local can be allocated instead
            .i64 => gen.free_locals_i64.append(gen.gpa, local_value) catch return,
            .f32 => gen.free_locals_f32.append(gen.gpa, local_value) catch return,
            .f64 => gen.free_locals_f64.append(gen.gpa, local_value) catch return,
            .v128 => gen.free_locals_v128.append(gen.gpa, local_value) catch return,
        }
        log.debug("freed local ({d}) of type {}", .{ local_value, valtype });
        value.* = .dead;
    }
};

/// Wasm ops, but without input/output/signedness information
/// Used for `build_opcode`
const Op = enum {
    @"unreachable",
    nop,
    block,
    loop,
    @"if",
    @"else",
    end,
    br,
    br_if,
    br_table,
    @"return",
    call,
    call_indirect,
    drop,
    select,
    local_get,
    local_set,
    local_tee,
    global_get,
    global_set,
    load,
    store,
    memory_size,
    memory_grow,
    @"const",
    eqz,
    eq,
    ne,
    lt,
    gt,
    le,
    ge,
    clz,
    ctz,
    popcnt,
    add,
    sub,
    mul,
    div,
    rem,
    @"and",
    @"or",
    xor,
    shl,
    shr,
    rotl,
    rotr,
    abs,
    neg,
    ceil,
    floor,
    trunc,
    nearest,
    sqrt,
    min,
    max,
    copysign,
    wrap,
    convert,
    demote,
    promote,
    reinterpret,
    extend,
};

/// Contains the settings needed to create an `Opcode` using `build_opcode`.
///
/// The fields correspond to the opcode name. Here is an example
///          i32_trunc_f32_s
///          ^   ^     ^   ^
///          |   |     |   |
///   valtype1   |     |   |
///     = .i32   |     |   |
///              |     |   |
///             op     |   |
///       = .trunc     |   |
///                    |   |
///             valtype2   |
///               = .f32   |
///                        |
///                width   |
///               = null   |
///                        |
///                   signed
///                   = true
///
/// There can be missing fields, here are some more examples:
///   i64_load8_u
///     --> .{ .valtype1 = .i64, .op = .load, .width = 8, signed = false }
///   i32_mul
///     --> .{ .valtype1 = .i32, .op = .trunc }
///   nop
///     --> .{ .op = .nop }
const OpcodeBuildArguments = struct {
    /// First valtype in the opcode (usually represents the type of the output)
    valtype1: ?wasm.Valtype = null,
    /// The operation (e.g. call, unreachable, div, min, sqrt, etc.)
    op: Op,
    /// Width of the operation (e.g. 8 for i32_load8_s, 16 for i64_extend16_i32_s)
    width: ?u8 = null,
    /// Second valtype in the opcode name (usually represents the type of the input)
    valtype2: ?wasm.Valtype = null,
    /// Signedness of the op
    signedness: ?std.builtin.Signedness = null,
};

/// Helper function that builds an Opcode given the arguments needed
fn build_opcode(args: OpcodeBuildArguments) wasm.Opcode {
    switch (args.op) {
        .@"unreachable" => return .@"unreachable",
        .nop => return .nop,
        .block => return .block,
        .loop => return .loop,
        .@"if" => return .@"if",
        .@"else" => return .@"else",
        .end => return .end,
        .br => return .br,
        .br_if => return .br_if,
        .br_table => return .br_table,
        .@"return" => return .@"return",
        .call => return .call,
        .call_indirect => return .call_indirect,
        .drop => return .drop,
        .select => return .select,
        .local_get => return .local_get,
        .local_set => return .local_set,
        .local_tee => return .local_tee,
        .global_get => return .global_get,
        .global_set => return .global_set,

        .load => if (args.width) |width| switch (width) {
            8 => switch (args.valtype1.?) {
                .i32 => if (args.signedness.? == .signed) return .i32_load8_s else return .i32_load8_u,
                .i64 => if (args.signedness.? == .signed) return .i64_load8_s else return .i64_load8_u,
                .f32, .f64, .v128 => unreachable,
            },
            16 => switch (args.valtype1.?) {
                .i32 => if (args.signedness.? == .signed) return .i32_load16_s else return .i32_load16_u,
                .i64 => if (args.signedness.? == .signed) return .i64_load16_s else return .i64_load16_u,
                .f32, .f64, .v128 => unreachable,
            },
            32 => switch (args.valtype1.?) {
                .i64 => if (args.signedness.? == .signed) return .i64_load32_s else return .i64_load32_u,
                .i32 => return .i32_load,
                .f32 => return .f32_load,
                .f64, .v128 => unreachable,
            },
            64 => switch (args.valtype1.?) {
                .i64 => return .i64_load,
                .f64 => return .f64_load,
                else => unreachable,
            },
            else => unreachable,
        } else switch (args.valtype1.?) {
            .i32 => return .i32_load,
            .i64 => return .i64_load,
            .f32 => return .f32_load,
            .f64 => return .f64_load,
            .v128 => unreachable, // handled independently
        },
        .store => if (args.width) |width| {
            switch (width) {
                8 => switch (args.valtype1.?) {
                    .i32 => return .i32_store8,
                    .i64 => return .i64_store8,
                    .f32, .f64, .v128 => unreachable,
                },
                16 => switch (args.valtype1.?) {
                    .i32 => return .i32_store16,
                    .i64 => return .i64_store16,
                    .f32, .f64, .v128 => unreachable,
                },
                32 => switch (args.valtype1.?) {
                    .i64 => return .i64_store32,
                    .i32 => return .i32_store,
                    .f32 => return .f32_store,
                    .f64, .v128 => unreachable,
                },
                64 => switch (args.valtype1.?) {
                    .i64 => return .i64_store,
                    .f64 => return .f64_store,
                    else => unreachable,
                },
                else => unreachable,
            }
        } else {
            switch (args.valtype1.?) {
                .i32 => return .i32_store,
                .i64 => return .i64_store,
                .f32 => return .f32_store,
                .f64 => return .f64_store,
                .v128 => unreachable, // handled independently
            }
        },

        .memory_size => return .memory_size,
        .memory_grow => return .memory_grow,

        .@"const" => switch (args.valtype1.?) {
            .i32 => return .i32_const,
            .i64 => return .i64_const,
            .f32 => return .f32_const,
            .f64 => return .f64_const,
            .v128 => unreachable, // handled independently
        },

        .eqz => switch (args.valtype1.?) {
            .i32 => return .i32_eqz,
            .i64 => return .i64_eqz,
            .f32, .f64, .v128 => unreachable,
        },
        .eq => switch (args.valtype1.?) {
            .i32 => return .i32_eq,
            .i64 => return .i64_eq,
            .f32 => return .f32_eq,
            .f64 => return .f64_eq,
            .v128 => unreachable, // handled independently
        },
        .ne => switch (args.valtype1.?) {
            .i32 => return .i32_ne,
            .i64 => return .i64_ne,
            .f32 => return .f32_ne,
            .f64 => return .f64_ne,
            .v128 => unreachable, // handled independently
        },

        .lt => switch (args.valtype1.?) {
            .i32 => if (args.signedness.? == .signed) return .i32_lt_s else return .i32_lt_u,
            .i64 => if (args.signedness.? == .signed) return .i64_lt_s else return .i64_lt_u,
            .f32 => return .f32_lt,
            .f64 => return .f64_lt,
            .v128 => unreachable, // handled independently
        },
        .gt => switch (args.valtype1.?) {
            .i32 => if (args.signedness.? == .signed) return .i32_gt_s else return .i32_gt_u,
            .i64 => if (args.signedness.? == .signed) return .i64_gt_s else return .i64_gt_u,
            .f32 => return .f32_gt,
            .f64 => return .f64_gt,
            .v128 => unreachable, // handled independently
        },
        .le => switch (args.valtype1.?) {
            .i32 => if (args.signedness.? == .signed) return .i32_le_s else return .i32_le_u,
            .i64 => if (args.signedness.? == .signed) return .i64_le_s else return .i64_le_u,
            .f32 => return .f32_le,
            .f64 => return .f64_le,
            .v128 => unreachable, // handled independently
        },
        .ge => switch (args.valtype1.?) {
            .i32 => if (args.signedness.? == .signed) return .i32_ge_s else return .i32_ge_u,
            .i64 => if (args.signedness.? == .signed) return .i64_ge_s else return .i64_ge_u,
            .f32 => return .f32_ge,
            .f64 => return .f64_ge,
            .v128 => unreachable, // handled independently
        },

        .clz => switch (args.valtype1.?) {
            .i32 => return .i32_clz,
            .i64 => return .i64_clz,
            .f32, .f64 => unreachable,
            .v128 => unreachable, // handled independently
        },
        .ctz => switch (args.valtype1.?) {
            .i32 => return .i32_ctz,
            .i64 => return .i64_ctz,
            .f32, .f64 => unreachable,
            .v128 => unreachable, // handled independently
        },
        .popcnt => switch (args.valtype1.?) {
            .i32 => return .i32_popcnt,
            .i64 => return .i64_popcnt,
            .f32, .f64 => unreachable,
            .v128 => unreachable, // handled independently
        },

        .add => switch (args.valtype1.?) {
            .i32 => return .i32_add,
            .i64 => return .i64_add,
            .f32 => return .f32_add,
            .f64 => return .f64_add,
            .v128 => unreachable, // handled independently
        },
        .sub => switch (args.valtype1.?) {
            .i32 => return .i32_sub,
            .i64 => return .i64_sub,
            .f32 => return .f32_sub,
            .f64 => return .f64_sub,
            .v128 => unreachable, // handled independently
        },
        .mul => switch (args.valtype1.?) {
            .i32 => return .i32_mul,
            .i64 => return .i64_mul,
            .f32 => return .f32_mul,
            .f64 => return .f64_mul,
            .v128 => unreachable, // handled independently
        },

        .div => switch (args.valtype1.?) {
            .i32 => if (args.signedness.? == .signed) return .i32_div_s else return .i32_div_u,
            .i64 => if (args.signedness.? == .signed) return .i64_div_s else return .i64_div_u,
            .f32 => return .f32_div,
            .f64 => return .f64_div,
            .v128 => unreachable, // handled independently
        },
        .rem => switch (args.valtype1.?) {
            .i32 => if (args.signedness.? == .signed) return .i32_rem_s else return .i32_rem_u,
            .i64 => if (args.signedness.? == .signed) return .i64_rem_s else return .i64_rem_u,
            .f32, .f64 => unreachable,
            .v128 => unreachable, // handled independently
        },

        .@"and" => switch (args.valtype1.?) {
            .i32 => return .i32_and,
            .i64 => return .i64_and,
            .f32, .f64 => unreachable,
            .v128 => unreachable, // handled independently
        },
        .@"or" => switch (args.valtype1.?) {
            .i32 => return .i32_or,
            .i64 => return .i64_or,
            .f32, .f64 => unreachable,
            .v128 => unreachable, // handled independently
        },
        .xor => switch (args.valtype1.?) {
            .i32 => return .i32_xor,
            .i64 => return .i64_xor,
            .f32, .f64 => unreachable,
            .v128 => unreachable, // handled independently
        },

        .shl => switch (args.valtype1.?) {
            .i32 => return .i32_shl,
            .i64 => return .i64_shl,
            .f32, .f64 => unreachable,
            .v128 => unreachable, // handled independently
        },
        .shr => switch (args.valtype1.?) {
            .i32 => if (args.signedness.? == .signed) return .i32_shr_s else return .i32_shr_u,
            .i64 => if (args.signedness.? == .signed) return .i64_shr_s else return .i64_shr_u,
            .f32, .f64 => unreachable,
            .v128 => unreachable, // handled independently
        },
        .rotl => switch (args.valtype1.?) {
            .i32 => return .i32_rotl,
            .i64 => return .i64_rotl,
            .f32, .f64 => unreachable,
            .v128 => unreachable, // handled independently
        },
        .rotr => switch (args.valtype1.?) {
            .i32 => return .i32_rotr,
            .i64 => return .i64_rotr,
            .f32, .f64 => unreachable,
            .v128 => unreachable, // handled independently
        },

        .abs => switch (args.valtype1.?) {
            .i32, .i64 => unreachable,
            .f32 => return .f32_abs,
            .f64 => return .f64_abs,
            .v128 => unreachable, // handled independently
        },
        .neg => switch (args.valtype1.?) {
            .i32, .i64 => unreachable,
            .f32 => return .f32_neg,
            .f64 => return .f64_neg,
            .v128 => unreachable, // handled independently
        },
        .ceil => switch (args.valtype1.?) {
            .i64 => unreachable,
            .i32 => return .f32_ceil, // when valtype is f16, we store it in i32.
            .f32 => return .f32_ceil,
            .f64 => return .f64_ceil,
            .v128 => unreachable, // handled independently
        },
        .floor => switch (args.valtype1.?) {
            .i64 => unreachable,
            .i32 => return .f32_floor, // when valtype is f16, we store it in i32.
            .f32 => return .f32_floor,
            .f64 => return .f64_floor,
            .v128 => unreachable, // handled independently
        },
        .trunc => switch (args.valtype1.?) {
            .i32 => if (args.valtype2) |valty| switch (valty) {
                .i32 => unreachable,
                .i64 => unreachable,
                .f32 => if (args.signedness.? == .signed) return .i32_trunc_f32_s else return .i32_trunc_f32_u,
                .f64 => if (args.signedness.? == .signed) return .i32_trunc_f64_s else return .i32_trunc_f64_u,
                .v128 => unreachable, // handled independently
            } else return .f32_trunc, // when no valtype2, it's an f16 instead which is stored in an i32.
            .i64 => switch (args.valtype2.?) {
                .i32 => unreachable,
                .i64 => unreachable,
                .f32 => if (args.signedness.? == .signed) return .i64_trunc_f32_s else return .i64_trunc_f32_u,
                .f64 => if (args.signedness.? == .signed) return .i64_trunc_f64_s else return .i64_trunc_f64_u,
                .v128 => unreachable, // handled independently
            },
            .f32 => return .f32_trunc,
            .f64 => return .f64_trunc,
            .v128 => unreachable, // handled independently
        },
        .nearest => switch (args.valtype1.?) {
            .i32, .i64 => unreachable,
            .f32 => return .f32_nearest,
            .f64 => return .f64_nearest,
            .v128 => unreachable, // handled independently
        },
        .sqrt => switch (args.valtype1.?) {
            .i32, .i64 => unreachable,
            .f32 => return .f32_sqrt,
            .f64 => return .f64_sqrt,
            .v128 => unreachable, // handled independently
        },
        .min => switch (args.valtype1.?) {
            .i32, .i64 => unreachable,
            .f32 => return .f32_min,
            .f64 => return .f64_min,
            .v128 => unreachable, // handled independently
        },
        .max => switch (args.valtype1.?) {
            .i32, .i64 => unreachable,
            .f32 => return .f32_max,
            .f64 => return .f64_max,
            .v128 => unreachable, // handled independently
        },
        .copysign => switch (args.valtype1.?) {
            .i32, .i64 => unreachable,
            .f32 => return .f32_copysign,
            .f64 => return .f64_copysign,
            .v128 => unreachable, // handled independently
        },

        .wrap => switch (args.valtype1.?) {
            .i32 => switch (args.valtype2.?) {
                .i32 => unreachable,
                .i64 => return .i32_wrap_i64,
                .f32, .f64 => unreachable,
                .v128 => unreachable, // handled independently
            },
            .i64, .f32, .f64 => unreachable,
            .v128 => unreachable, // handled independently
        },
        .convert => switch (args.valtype1.?) {
            .i32, .i64 => unreachable,
            .f32 => switch (args.valtype2.?) {
                .i32 => if (args.signedness.? == .signed) return .f32_convert_i32_s else return .f32_convert_i32_u,
                .i64 => if (args.signedness.? == .signed) return .f32_convert_i64_s else return .f32_convert_i64_u,
                .f32, .f64 => unreachable,
                .v128 => unreachable, // handled independently
            },
            .f64 => switch (args.valtype2.?) {
                .i32 => if (args.signedness.? == .signed) return .f64_convert_i32_s else return .f64_convert_i32_u,
                .i64 => if (args.signedness.? == .signed) return .f64_convert_i64_s else return .f64_convert_i64_u,
                .f32, .f64 => unreachable,
                .v128 => unreachable, // handled independently
            },
            .v128 => unreachable, // handled independently
        },
        .demote => if (args.valtype1.? == .f32 and args.valtype2.? == .f64) return .f32_demote_f64 else unreachable,
        .promote => if (args.valtype1.? == .f64 and args.valtype2.? == .f32) return .f64_promote_f32 else unreachable,
        .reinterpret => switch (args.valtype1.?) {
            .i32 => if (args.valtype2.? == .f32) return .i32_reinterpret_f32 else unreachable,
            .i64 => if (args.valtype2.? == .f64) return .i64_reinterpret_f64 else unreachable,
            .f32 => if (args.valtype2.? == .i32) return .f32_reinterpret_i32 else unreachable,
            .f64 => if (args.valtype2.? == .i64) return .f64_reinterpret_i64 else unreachable,
            .v128 => unreachable, // handled independently
        },
        .extend => switch (args.valtype1.?) {
            .i32 => switch (args.width.?) {
                8 => if (args.signedness.? == .signed) return .i32_extend8_s else unreachable,
                16 => if (args.signedness.? == .signed) return .i32_extend16_s else unreachable,
                else => unreachable,
            },
            .i64 => switch (args.width.?) {
                8 => if (args.signedness.? == .signed) return .i64_extend8_s else unreachable,
                16 => if (args.signedness.? == .signed) return .i64_extend16_s else unreachable,
                32 => if (args.signedness.? == .signed) return .i64_extend32_s else unreachable,
                else => unreachable,
            },
            .f32, .f64 => unreachable,
            .v128 => unreachable, // handled independently
        },
    }
}

test "Wasm - build_opcode" {
    // Make sure build_opcode is referenced, and test some examples
    const i32_const = build_opcode(.{ .op = .@"const", .valtype1 = .i32 });
    const end = build_opcode(.{ .op = .end });
    const local_get = build_opcode(.{ .op = .local_get });
    const i64_extend32_s = build_opcode(.{ .op = .extend, .valtype1 = .i64, .width = 32, .signedness = .signed });
    const f64_reinterpret_i64 = build_opcode(.{ .op = .reinterpret, .valtype1 = .f64, .valtype2 = .i64 });

    try testing.expect_equal(@as(wasm.Opcode, .i32_const), i32_const);
    try testing.expect_equal(@as(wasm.Opcode, .end), end);
    try testing.expect_equal(@as(wasm.Opcode, .local_get), local_get);
    try testing.expect_equal(@as(wasm.Opcode, .i64_extend32_s), i64_extend32_s);
    try testing.expect_equal(@as(wasm.Opcode, .f64_reinterpret_i64), f64_reinterpret_i64);
}

/// Hashmap to store generated `WValue` for each `Air.Inst.Ref`
pub const ValueTable = std.AutoArrayHashMapUnmanaged(Air.Inst.Ref, WValue);

const CodeGen = @This();

/// Reference to the function declaration the code
/// section belongs to
decl: *Decl,
decl_index: InternPool.DeclIndex,
/// Current block depth. Used to calculate the relative difference between a break
/// and block
block_depth: u32 = 0,
air: Air,
liveness: Liveness,
gpa: mem.Allocator,
debug_output: codegen.DebugInfoOutput,
func_index: InternPool.Index,
/// Contains a list of current branches.
/// When we return from a branch, the branch will be popped from this list,
/// which means branches can only contain references from within its own branch,
/// or a branch higher (lower index) in the tree.
branches: std.ArrayListUnmanaged(Branch) = .{},
/// Table to save `WValue`'s generated by an `Air.Inst`
// values: ValueTable,
/// Mapping from Air.Inst.Index to block ids
blocks: std.AutoArrayHashMapUnmanaged(Air.Inst.Index, struct {
    label: u32,
    value: WValue,
}) = .{},
/// `bytes` contains the wasm bytecode belonging to the 'code' section.
code: *ArrayList(u8),
/// The index the next local generated will have
/// NOTE: arguments share the index with locals therefore the first variable
/// will have the index that comes after the last argument's index
local_index: u32 = 0,
/// The index of the current argument.
/// Used to track which argument is being referenced in `air_arg`.
arg_index: u32 = 0,
/// If codegen fails, an error messages will be allocated and saved in `err_msg`
err_msg: *Module.ErrorMsg,
/// List of all locals' types generated throughout this declaration
/// used to emit locals count at start of 'code' section.
locals: std.ArrayListUnmanaged(u8),
/// List of simd128 immediates. Each value is stored as an array of bytes.
/// This list will only be populated for 128bit-simd values when the target features
/// are enabled also.
simd_immediates: std.ArrayListUnmanaged([16]u8) = .{},
/// The Target we're emitting (used to call int_info)
target: std.Target,
/// Represents the wasm binary file that is being linked.
bin_file: *link.File.Wasm,
/// List of MIR Instructions
mir_instructions: std.MultiArrayList(Mir.Inst) = .{},
/// Contains extra data for MIR
mir_extra: std.ArrayListUnmanaged(u32) = .{},
/// When a function is executing, we store the the current stack pointer's value within this local.
/// This value is then used to restore the stack pointer to the original value at the return of the function.
initial_stack_value: WValue = .none,
/// The current stack pointer substracted with the stack size. From this value, we will calculate
/// all offsets of the stack values.
bottom_stack_value: WValue = .none,
/// Arguments of this function declaration
/// This will be set after `resolve_calling_convention_values`
args: []WValue = &.{},
/// This will only be `.none` if the function returns void, or returns an immediate.
/// When it returns a pointer to the stack, the `.local` tag will be active and must be populated
/// before this function returns its execution to the caller.
return_value: WValue = .none,
/// The size of the stack this function occupies. In the function prologue
/// we will move the stack pointer by this number, forward aligned with the `stack_alignment`.
stack_size: u32 = 0,
/// The stack alignment, which is 16 bytes by default. This is specified by the
/// tool-conventions: https://github.com/WebAssembly/tool-conventions/blob/main/BasicCABI.md
/// and also what the llvm backend will emit.
/// However, local variables or the usage of `@setAlignStack` can overwrite this default.
stack_alignment: Alignment = .@"16",

// For each individual Wasm valtype we store a seperate free list which
// allows us to re-use locals that are no longer used. e.g. a temporary local.
/// A list of indexes which represents a local of valtype `i32`.
/// It is illegal to store a non-i32 valtype in this list.
free_locals_i32: std.ArrayListUnmanaged(u32) = .{},
/// A list of indexes which represents a local of valtype `i64`.
/// It is illegal to store a non-i64 valtype in this list.
free_locals_i64: std.ArrayListUnmanaged(u32) = .{},
/// A list of indexes which represents a local of valtype `f32`.
/// It is illegal to store a non-f32 valtype in this list.
free_locals_f32: std.ArrayListUnmanaged(u32) = .{},
/// A list of indexes which represents a local of valtype `f64`.
/// It is illegal to store a non-f64 valtype in this list.
free_locals_f64: std.ArrayListUnmanaged(u32) = .{},
/// A list of indexes which represents a local of valtype `v127`.
/// It is illegal to store a non-v128 valtype in this list.
free_locals_v128: std.ArrayListUnmanaged(u32) = .{},

/// When in debug mode, this tracks if no `finish_air` was missed.
/// Forgetting to call `finish_air` will cause the result to not be
/// stored in our `values` map and therefore cause bugs.
air_bookkeeping: @TypeOf(bookkeeping_init) = bookkeeping_init,

const bookkeeping_init = if (std.debug.runtime_safety) @as(usize, 0) else {};

const InnerError = error{
    OutOfMemory,
    /// An error occurred when trying to lower AIR to MIR.
    CodegenFail,
    /// Compiler implementation could not handle a large integer.
    Overflow,
};

pub fn deinit(func: *CodeGen) void {
    // in case of an error and we still have branches
    for (func.branches.items) |*branch| {
        branch.deinit(func.gpa);
    }
    func.branches.deinit(func.gpa);
    func.blocks.deinit(func.gpa);
    func.locals.deinit(func.gpa);
    func.simd_immediates.deinit(func.gpa);
    func.mir_instructions.deinit(func.gpa);
    func.mir_extra.deinit(func.gpa);
    func.free_locals_i32.deinit(func.gpa);
    func.free_locals_i64.deinit(func.gpa);
    func.free_locals_f32.deinit(func.gpa);
    func.free_locals_f64.deinit(func.gpa);
    func.free_locals_v128.deinit(func.gpa);
    func.* = undefined;
}

/// Sets `err_msg` on `CodeGen` and returns `error.CodegenFail` which is caught in link/Wasm.zig
fn fail(func: *CodeGen, comptime fmt: []const u8, args: anytype) InnerError {
    const mod = func.bin_file.base.comp.module.?;
    const src_loc = func.decl.src_loc(mod);
    func.err_msg = try Module.ErrorMsg.create(func.gpa, src_loc, fmt, args);
    return error.CodegenFail;
}

/// Resolves the `WValue` for the given instruction `inst`
/// When the given instruction has a `Value`, it returns a constant instead
fn resolve_inst(func: *CodeGen, ref: Air.Inst.Ref) InnerError!WValue {
    var branch_index = func.branches.items.len;
    while (branch_index > 0) : (branch_index -= 1) {
        const branch = func.branches.items[branch_index - 1];
        if (branch.values.get(ref)) |value| {
            return value;
        }
    }

    // when we did not find an existing instruction, it
    // means we must generate it from a constant.
    // We always store constants in the most outer branch as they must never
    // be removed. The most outer branch is always at index 0.
    const gop = try func.branches.items[0].values.get_or_put(func.gpa, ref);
    assert(!gop.found_existing);

    const mod = func.bin_file.base.comp.module.?;
    const val = (try func.air.value(ref, mod)).?;
    const ty = func.type_of(ref);
    if (!ty.has_runtime_bits_ignore_comptime(mod) and !ty.is_int(mod) and !ty.is_error(mod)) {
        gop.value_ptr.* = WValue{ .none = {} };
        return gop.value_ptr.*;
    }

    // When we need to pass the value by reference (such as a struct), we will
    // leverage `generate_symbol` to lower the constant to bytes and emit it
    // to the 'rodata' section. We then return the index into the section as `WValue`.
    //
    // In the other cases, we will simply lower the constant to a value that fits
    // into a single local (such as a pointer, integer, bool, etc).
    const result = if (is_by_ref(ty, mod)) blk: {
        const sym_index = try func.bin_file.lower_unnamed_const(val, func.decl_index);
        break :blk WValue{ .memory = sym_index };
    } else try func.lower_constant(val, ty);

    gop.value_ptr.* = result;
    return result;
}

fn finish_air(func: *CodeGen, inst: Air.Inst.Index, result: WValue, operands: []const Air.Inst.Ref) void {
    assert(operands.len <= Liveness.bpi - 1);
    var tomb_bits = func.liveness.get_tomb_bits(inst);
    for (operands) |operand| {
        const dies = @as(u1, @truncate(tomb_bits)) != 0;
        tomb_bits >>= 1;
        if (!dies) continue;
        process_death(func, operand);
    }

    // results of `none` can never be referenced.
    if (result != .none) {
        assert(result != .stack); // it's illegal to store a stack value as we cannot track its position
        const branch = func.current_branch();
        branch.values.put_assume_capacity_no_clobber(inst.to_ref(), result);
    }

    if (std.debug.runtime_safety) {
        func.air_bookkeeping += 1;
    }
}

const Branch = struct {
    values: ValueTable = .{},

    fn deinit(branch: *Branch, gpa: Allocator) void {
        branch.values.deinit(gpa);
        branch.* = undefined;
    }
};

inline fn current_branch(func: *CodeGen) *Branch {
    return &func.branches.items[func.branches.items.len - 1];
}

const BigTomb = struct {
    gen: *CodeGen,
    inst: Air.Inst.Index,
    lbt: Liveness.BigTomb,

    fn feed(bt: *BigTomb, op_ref: Air.Inst.Ref) void {
        const dies = bt.lbt.feed();
        if (!dies) return;
        // This will be a nop for interned constants.
        process_death(bt.gen, op_ref);
    }

    fn finish_air(bt: *BigTomb, result: WValue) void {
        assert(result != .stack);
        if (result != .none) {
            bt.gen.current_branch().values.put_assume_capacity_no_clobber(bt.inst.to_ref(), result);
        }

        if (std.debug.runtime_safety) {
            bt.gen.air_bookkeeping += 1;
        }
    }
};

fn iterate_big_tomb(func: *CodeGen, inst: Air.Inst.Index, operand_count: usize) !BigTomb {
    try func.current_branch().values.ensure_unused_capacity(func.gpa, operand_count + 1);
    return BigTomb{
        .gen = func,
        .inst = inst,
        .lbt = func.liveness.iterate_big_tomb(inst),
    };
}

fn process_death(func: *CodeGen, ref: Air.Inst.Ref) void {
    if (ref.to_index() == null) return;
    // Branches are currently only allowed to free locals allocated
    // within their own branch.
    // TODO: Upon branch consolidation free any locals if needed.
    const value = func.current_branch().values.get_ptr(ref) orelse return;
    if (value.* != .local) return;
    const reserved_indexes = func.args.len + @int_from_bool(func.return_value != .none);
    if (value.local.value < reserved_indexes) {
        return; // function arguments can never be re-used
    }
    log.debug("Decreasing reference for ref: %{d}, using local '{d}'", .{ @int_from_enum(ref.to_index().?), value.local.value });
    value.local.references -= 1; // if this panics, a call to `reuse_operand` was forgotten by the developer
    if (value.local.references == 0) {
        value.free(func);
    }
}

/// Appends a MIR instruction and returns its index within the list of instructions
fn add_inst(func: *CodeGen, inst: Mir.Inst) error{OutOfMemory}!void {
    try func.mir_instructions.append(func.gpa, inst);
}

fn add_tag(func: *CodeGen, tag: Mir.Inst.Tag) error{OutOfMemory}!void {
    try func.add_inst(.{ .tag = tag, .data = .{ .tag = {} } });
}

fn add_extended(func: *CodeGen, opcode: wasm.MiscOpcode) error{OutOfMemory}!void {
    const extra_index = @as(u32, @int_cast(func.mir_extra.items.len));
    try func.mir_extra.append(func.gpa, @int_from_enum(opcode));
    try func.add_inst(.{ .tag = .misc_prefix, .data = .{ .payload = extra_index } });
}

fn add_label(func: *CodeGen, tag: Mir.Inst.Tag, label: u32) error{OutOfMemory}!void {
    try func.add_inst(.{ .tag = tag, .data = .{ .label = label } });
}

fn add_imm32(func: *CodeGen, imm: i32) error{OutOfMemory}!void {
    try func.add_inst(.{ .tag = .i32_const, .data = .{ .imm32 = imm } });
}

/// Accepts an unsigned 64bit integer rather than a signed integer to
/// prevent us from having to bitcast multiple times as most values
/// within codegen are represented as unsigned rather than signed.
fn add_imm64(func: *CodeGen, imm: u64) error{OutOfMemory}!void {
    const extra_index = try func.add_extra(Mir.Imm64.from_u64(imm));
    try func.add_inst(.{ .tag = .i64_const, .data = .{ .payload = extra_index } });
}

/// Accepts the index into the list of 128bit-immediates
fn add_imm128(func: *CodeGen, index: u32) error{OutOfMemory}!void {
    const simd_values = func.simd_immediates.items[index];
    const extra_index = @as(u32, @int_cast(func.mir_extra.items.len));
    // tag + 128bit value
    try func.mir_extra.ensure_unused_capacity(func.gpa, 5);
    func.mir_extra.append_assume_capacity(std.wasm.simd_opcode(.v128_const));
    func.mir_extra.append_slice_assume_capacity(@align_cast(mem.bytes_as_slice(u32, &simd_values)));
    try func.add_inst(.{ .tag = .simd_prefix, .data = .{ .payload = extra_index } });
}

fn add_float64(func: *CodeGen, float: f64) error{OutOfMemory}!void {
    const extra_index = try func.add_extra(Mir.Float64.from_float64(float));
    try func.add_inst(.{ .tag = .f64_const, .data = .{ .payload = extra_index } });
}

/// Inserts an instruction to load/store from/to wasm's linear memory dependent on the given `tag`.
fn add_mem_arg(func: *CodeGen, tag: Mir.Inst.Tag, mem_arg: Mir.MemArg) error{OutOfMemory}!void {
    const extra_index = try func.add_extra(mem_arg);
    try func.add_inst(.{ .tag = tag, .data = .{ .payload = extra_index } });
}

/// Inserts an instruction from the 'atomics' feature which accesses wasm's linear memory dependent on the
/// given `tag`.
fn add_atomic_mem_arg(func: *CodeGen, tag: wasm.AtomicsOpcode, mem_arg: Mir.MemArg) error{OutOfMemory}!void {
    const extra_index = try func.add_extra(@as(struct { val: u32 }, .{ .val = wasm.atomics_opcode(tag) }));
    _ = try func.add_extra(mem_arg);
    try func.add_inst(.{ .tag = .atomics_prefix, .data = .{ .payload = extra_index } });
}

/// Helper function to emit atomic mir opcodes.
fn add_atomic_tag(func: *CodeGen, tag: wasm.AtomicsOpcode) error{OutOfMemory}!void {
    const extra_index = try func.add_extra(@as(struct { val: u32 }, .{ .val = wasm.atomics_opcode(tag) }));
    try func.add_inst(.{ .tag = .atomics_prefix, .data = .{ .payload = extra_index } });
}

/// Appends entries to `mir_extra` based on the type of `extra`.
/// Returns the index into `mir_extra`
fn add_extra(func: *CodeGen, extra: anytype) error{OutOfMemory}!u32 {
    const fields = std.meta.fields(@TypeOf(extra));
    try func.mir_extra.ensure_unused_capacity(func.gpa, fields.len);
    return func.add_extra_assume_capacity(extra);
}

/// Appends entries to `mir_extra` based on the type of `extra`.
/// Returns the index into `mir_extra`
fn add_extra_assume_capacity(func: *CodeGen, extra: anytype) error{OutOfMemory}!u32 {
    const fields = std.meta.fields(@TypeOf(extra));
    const result = @as(u32, @int_cast(func.mir_extra.items.len));
    inline for (fields) |field| {
        func.mir_extra.append_assume_capacity(switch (field.type) {
            u32 => @field(extra, field.name),
            else => |field_type| @compile_error("Unsupported field type " ++ @type_name(field_type)),
        });
    }
    return result;
}

/// Using a given `Type`, returns the corresponding type
fn type_to_valtype(ty: Type, mod: *Module) wasm.Valtype {
    const target = mod.get_target();
    const ip = &mod.intern_pool;
    return switch (ty.zig_type_tag(mod)) {
        .Float => switch (ty.float_bits(target)) {
            16 => wasm.Valtype.i32, // stored/loaded as u16
            32 => wasm.Valtype.f32,
            64 => wasm.Valtype.f64,
            80, 128 => wasm.Valtype.i64,
            else => unreachable,
        },
        .Int, .Enum => blk: {
            const info = ty.int_info(mod);
            if (info.bits <= 32) break :blk wasm.Valtype.i32;
            if (info.bits > 32 and info.bits <= 128) break :blk wasm.Valtype.i64;
            break :blk wasm.Valtype.i32; // represented as pointer to stack
        },
        .Struct => {
            if (mod.type_to_packed_struct(ty)) |packed_struct| {
                return type_to_valtype(Type.from_interned(packed_struct.backing_int_type(ip).*), mod);
            } else {
                return wasm.Valtype.i32;
            }
        },
        .Vector => switch (determine_simd_store_strategy(ty, mod)) {
            .direct => wasm.Valtype.v128,
            .unrolled => wasm.Valtype.i32,
        },
        .Union => switch (ty.container_layout(mod)) {
            .@"packed" => {
                const int_ty = mod.int_type(.unsigned, @as(u16, @int_cast(ty.bit_size(mod)))) catch @panic("out of memory");
                return type_to_valtype(int_ty, mod);
            },
            else => wasm.Valtype.i32,
        },
        else => wasm.Valtype.i32, // all represented as reference/immediate
    };
}

/// Using a given `Type`, returns the byte representation of its wasm value type
fn gen_valtype(ty: Type, mod: *Module) u8 {
    return wasm.valtype(type_to_valtype(ty, mod));
}

/// Using a given `Type`, returns the corresponding wasm value type
/// Differently from `gen_valtype` this also allows `void` to create a block
/// with no return type
fn gen_block_type(ty: Type, mod: *Module) u8 {
    return switch (ty.ip_index) {
        .void_type, .noreturn_type => wasm.block_empty,
        else => gen_valtype(ty, mod),
    };
}

/// Writes the bytecode depending on the given `WValue` in `val`
fn emit_wvalue(func: *CodeGen, value: WValue) InnerError!void {
    switch (value) {
        .dead => unreachable, // reference to free'd `WValue` (missing reuse_operand?)
        .none, .stack => {}, // no-op
        .local => |idx| try func.add_label(.local_get, idx.value),
        .imm32 => |val| try func.add_imm32(@as(i32, @bit_cast(val))),
        .imm64 => |val| try func.add_imm64(val),
        .imm128 => |val| try func.add_imm128(val),
        .float32 => |val| try func.add_inst(.{ .tag = .f32_const, .data = .{ .float32 = val } }),
        .float64 => |val| try func.add_float64(val),
        .memory => |ptr| {
            const extra_index = try func.add_extra(Mir.Memory{ .pointer = ptr, .offset = 0 });
            try func.add_inst(.{ .tag = .memory_address, .data = .{ .payload = extra_index } });
        },
        .memory_offset => |mem_off| {
            const extra_index = try func.add_extra(Mir.Memory{ .pointer = mem_off.pointer, .offset = mem_off.offset });
            try func.add_inst(.{ .tag = .memory_address, .data = .{ .payload = extra_index } });
        },
        .function_index => |index| try func.add_label(.function_index, index), // write function index and generate relocation
        .stack_offset => try func.add_label(.local_get, func.bottom_stack_value.local.value), // caller must ensure to address the offset
    }
}

/// If given a local or stack-offset, increases the reference count by 1.
/// The old `WValue` found at instruction `ref` is then replaced by the
/// modified `WValue` and returned. When given a non-local or non-stack-offset,
/// returns the given `operand` itfunc instead.
fn reuse_operand(func: *CodeGen, ref: Air.Inst.Ref, operand: WValue) WValue {
    if (operand != .local and operand != .stack_offset) return operand;
    var new_value = operand;
    switch (new_value) {
        .local => |*local| local.references += 1,
        .stack_offset => |*stack_offset| stack_offset.references += 1,
        else => unreachable,
    }
    const old_value = func.get_resolved_inst(ref);
    old_value.* = new_value;
    return new_value;
}

/// From a reference, returns its resolved `WValue`.
/// It's illegal to provide a `Air.Inst.Ref` that hasn't been resolved yet.
fn get_resolved_inst(func: *CodeGen, ref: Air.Inst.Ref) *WValue {
    var index = func.branches.items.len;
    while (index > 0) : (index -= 1) {
        const branch = func.branches.items[index - 1];
        if (branch.values.get_ptr(ref)) |value| {
            return value;
        }
    }
    unreachable; // developer-error: This can only be called on resolved instructions. Use `resolve_inst` instead.
}

/// Creates one locals for a given `Type`.
/// Returns a corresponding `Wvalue` with `local` as active tag
fn alloc_local(func: *CodeGen, ty: Type) InnerError!WValue {
    const mod = func.bin_file.base.comp.module.?;
    const valtype = type_to_valtype(ty, mod);
    switch (valtype) {
        .i32 => if (func.free_locals_i32.pop_or_null()) |index| {
            log.debug("reusing local ({d}) of type {}", .{ index, valtype });
            return WValue{ .local = .{ .value = index, .references = 1 } };
        },
        .i64 => if (func.free_locals_i64.pop_or_null()) |index| {
            log.debug("reusing local ({d}) of type {}", .{ index, valtype });
            return WValue{ .local = .{ .value = index, .references = 1 } };
        },
        .f32 => if (func.free_locals_f32.pop_or_null()) |index| {
            log.debug("reusing local ({d}) of type {}", .{ index, valtype });
            return WValue{ .local = .{ .value = index, .references = 1 } };
        },
        .f64 => if (func.free_locals_f64.pop_or_null()) |index| {
            log.debug("reusing local ({d}) of type {}", .{ index, valtype });
            return WValue{ .local = .{ .value = index, .references = 1 } };
        },
        .v128 => if (func.free_locals_v128.pop_or_null()) |index| {
            log.debug("reusing local ({d}) of type {}", .{ index, valtype });
            return WValue{ .local = .{ .value = index, .references = 1 } };
        },
    }
    log.debug("new local of type {}", .{valtype});
    // no local was free to be re-used, so allocate a new local instead
    return func.ensure_alloc_local(ty);
}

/// Ensures a new local will be created. This is useful when it's useful
/// to use a zero-initialized local.
fn ensure_alloc_local(func: *CodeGen, ty: Type) InnerError!WValue {
    const mod = func.bin_file.base.comp.module.?;
    try func.locals.append(func.gpa, gen_valtype(ty, mod));
    const initial_index = func.local_index;
    func.local_index += 1;
    return WValue{ .local = .{ .value = initial_index, .references = 1 } };
}

/// Generates a `wasm.Type` from a given function type.
/// Memory is owned by the caller.
fn gen_functype(
    gpa: Allocator,
    cc: std.builtin.CallingConvention,
    params: []const InternPool.Index,
    return_type: Type,
    mod: *Module,
) !wasm.Type {
    var temp_params = std.ArrayList(wasm.Valtype).init(gpa);
    defer temp_params.deinit();
    var returns = std.ArrayList(wasm.Valtype).init(gpa);
    defer returns.deinit();

    if (first_param_sret(cc, return_type, mod)) {
        try temp_params.append(.i32); // memory address is always a 32-bit handle
    } else if (return_type.has_runtime_bits_ignore_comptime(mod)) {
        if (cc == .C) {
            const res_classes = abi.classify_type(return_type, mod);
            assert(res_classes[0] == .direct and res_classes[1] == .none);
            const scalar_type = abi.scalar_type(return_type, mod);
            try returns.append(type_to_valtype(scalar_type, mod));
        } else {
            try returns.append(type_to_valtype(return_type, mod));
        }
    } else if (return_type.is_error(mod)) {
        try returns.append(.i32);
    }

    // param types
    for (params) |param_type_ip| {
        const param_type = Type.from_interned(param_type_ip);
        if (!param_type.has_runtime_bits_ignore_comptime(mod)) continue;

        switch (cc) {
            .C => {
                const param_classes = abi.classify_type(param_type, mod);
                for (param_classes) |class| {
                    if (class == .none) continue;
                    if (class == .direct) {
                        const scalar_type = abi.scalar_type(param_type, mod);
                        try temp_params.append(type_to_valtype(scalar_type, mod));
                    } else {
                        try temp_params.append(type_to_valtype(param_type, mod));
                    }
                }
            },
            else => if (is_by_ref(param_type, mod))
                try temp_params.append(.i32)
            else
                try temp_params.append(type_to_valtype(param_type, mod)),
        }
    }

    return wasm.Type{
        .params = try temp_params.to_owned_slice(),
        .returns = try returns.to_owned_slice(),
    };
}

pub fn generate(
    bin_file: *link.File,
    src_loc: Module.SrcLoc,
    func_index: InternPool.Index,
    air: Air,
    liveness: Liveness,
    code: *std.ArrayList(u8),
    debug_output: codegen.DebugInfoOutput,
) codegen.CodeGenError!codegen.Result {
    _ = src_loc;
    const comp = bin_file.comp;
    const gpa = comp.gpa;
    const mod = comp.module.?;
    const func = mod.func_info(func_index);
    const decl = mod.decl_ptr(func.owner_decl);
    const namespace = mod.namespace_ptr(decl.src_namespace);
    const target = namespace.file_scope.mod.resolved_target.result;
    var code_gen: CodeGen = .{
        .gpa = gpa,
        .air = air,
        .liveness = liveness,
        .code = code,
        .decl_index = func.owner_decl,
        .decl = decl,
        .err_msg = undefined,
        .locals = .{},
        .target = target,
        .bin_file = bin_file.cast(link.File.Wasm).?,
        .debug_output = debug_output,
        .func_index = func_index,
    };
    defer code_gen.deinit();

    gen_func(&code_gen) catch |err| switch (err) {
        error.CodegenFail => return codegen.Result{ .fail = code_gen.err_msg },
        else => |e| return e,
    };

    return codegen.Result.ok;
}

fn gen_func(func: *CodeGen) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const ip = &mod.intern_pool;
    const fn_info = mod.type_to_func(func.decl.type_of(mod)).?;
    var func_type = try gen_functype(func.gpa, fn_info.cc, fn_info.param_types.get(ip), Type.from_interned(fn_info.return_type), mod);
    defer func_type.deinit(func.gpa);
    _ = try func.bin_file.store_decl_type(func.decl_index, func_type);

    var cc_result = try func.resolve_calling_convention_values(func.decl.type_of(mod));
    defer cc_result.deinit(func.gpa);

    func.args = cc_result.args;
    func.return_value = cc_result.return_value;

    try func.add_tag(.dbg_prologue_end);

    try func.branches.append(func.gpa, .{});
    // clean up outer branch
    defer {
        var outer_branch = func.branches.pop();
        outer_branch.deinit(func.gpa);
        assert(func.branches.items.len == 0); // missing branch merge
    }
    // Generate MIR for function body
    try func.gen_body(func.air.get_main_body());

    // In case we have a return value, but the last instruction is a noreturn (such as a while loop)
    // we emit an unreachable instruction to tell the stack validator that part will never be reached.
    if (func_type.returns.len != 0 and func.air.instructions.len > 0) {
        const inst: Air.Inst.Index = @enumFromInt(func.air.instructions.len - 1);
        const last_inst_ty = func.type_of_index(inst);
        if (!last_inst_ty.has_runtime_bits_ignore_comptime(mod) or last_inst_ty.is_no_return(mod)) {
            try func.add_tag(.@"unreachable");
        }
    }
    // End of function body
    try func.add_tag(.end);

    try func.add_tag(.dbg_epilogue_begin);

    // check if we have to initialize and allocate anything into the stack frame.
    // If so, create enough stack space and insert the instructions at the front of the list.
    if (func.initial_stack_value != .none) {
        var prologue = std.ArrayList(Mir.Inst).init(func.gpa);
        defer prologue.deinit();

        const sp = @int_from_enum(func.bin_file.zig_object_ptr().?.stack_pointer_sym);
        // load stack pointer
        try prologue.append(.{ .tag = .global_get, .data = .{ .label = sp } });
        // store stack pointer so we can restore it when we return from the function
        try prologue.append(.{ .tag = .local_tee, .data = .{ .label = func.initial_stack_value.local.value } });
        // get the total stack size
        const aligned_stack = func.stack_alignment.forward(func.stack_size);
        try prologue.append(.{ .tag = .i32_const, .data = .{ .imm32 = @int_cast(aligned_stack) } });
        // subtract it from the current stack pointer
        try prologue.append(.{ .tag = .i32_sub, .data = .{ .tag = {} } });
        // Get negative stack aligment
        try prologue.append(.{ .tag = .i32_const, .data = .{ .imm32 = @as(i32, @int_cast(func.stack_alignment.to_byte_units().?)) * -1 } });
        // Bitwise-and the value to get the new stack pointer to ensure the pointers are aligned with the abi alignment
        try prologue.append(.{ .tag = .i32_and, .data = .{ .tag = {} } });
        // store the current stack pointer as the bottom, which will be used to calculate all stack pointer offsets
        try prologue.append(.{ .tag = .local_tee, .data = .{ .label = func.bottom_stack_value.local.value } });
        // Store the current stack pointer value into the global stack pointer so other function calls will
        // start from this value instead and not overwrite the current stack.
        try prologue.append(.{ .tag = .global_set, .data = .{ .label = sp } });

        // reserve space and insert all prologue instructions at the front of the instruction list
        // We insert them in reserve order as there is no insert_slice in multiArrayList.
        try func.mir_instructions.ensure_unused_capacity(func.gpa, prologue.items.len);
        for (prologue.items, 0..) |_, index| {
            const inst = prologue.items[prologue.items.len - 1 - index];
            func.mir_instructions.insert_assume_capacity(0, inst);
        }
    }

    var mir: Mir = .{
        .instructions = func.mir_instructions.to_owned_slice(),
        .extra = try func.mir_extra.to_owned_slice(func.gpa),
    };
    defer mir.deinit(func.gpa);

    var emit: Emit = .{
        .mir = mir,
        .bin_file = func.bin_file,
        .code = func.code,
        .locals = func.locals.items,
        .decl_index = func.decl_index,
        .dbg_output = func.debug_output,
        .prev_di_line = 0,
        .prev_di_column = 0,
        .prev_di_offset = 0,
    };

    emit.emit_mir() catch |err| switch (err) {
        error.EmitFail => {
            func.err_msg = emit.error_msg.?;
            return error.CodegenFail;
        },
        else => |e| return e,
    };
}

const CallWValues = struct {
    args: []WValue,
    return_value: WValue,

    fn deinit(values: *CallWValues, gpa: Allocator) void {
        gpa.free(values.args);
        values.* = undefined;
    }
};

fn resolve_calling_convention_values(func: *CodeGen, fn_ty: Type) InnerError!CallWValues {
    const mod = func.bin_file.base.comp.module.?;
    const ip = &mod.intern_pool;
    const fn_info = mod.type_to_func(fn_ty).?;
    const cc = fn_info.cc;
    var result: CallWValues = .{
        .args = &.{},
        .return_value = .none,
    };
    if (cc == .Naked) return result;

    var args = std.ArrayList(WValue).init(func.gpa);
    defer args.deinit();

    // Check if we store the result as a pointer to the stack rather than
    // by value
    if (first_param_sret(fn_info.cc, Type.from_interned(fn_info.return_type), mod)) {
        // the sret arg will be passed as first argument, therefore we
        // set the `return_value` before allocating locals for regular args.
        result.return_value = .{ .local = .{ .value = func.local_index, .references = 1 } };
        func.local_index += 1;
    }

    switch (cc) {
        .Unspecified => {
            for (fn_info.param_types.get(ip)) |ty| {
                if (!Type.from_interned(ty).has_runtime_bits_ignore_comptime(mod)) {
                    continue;
                }

                try args.append(.{ .local = .{ .value = func.local_index, .references = 1 } });
                func.local_index += 1;
            }
        },
        .C => {
            for (fn_info.param_types.get(ip)) |ty| {
                const ty_classes = abi.classify_type(Type.from_interned(ty), mod);
                for (ty_classes) |class| {
                    if (class == .none) continue;
                    try args.append(.{ .local = .{ .value = func.local_index, .references = 1 } });
                    func.local_index += 1;
                }
            }
        },
        else => return func.fail("calling convention '{s}' not supported for Wasm", .{@tag_name(cc)}),
    }
    result.args = try args.to_owned_slice();
    return result;
}

fn first_param_sret(cc: std.builtin.CallingConvention, return_type: Type, mod: *Module) bool {
    switch (cc) {
        .Unspecified, .Inline => return is_by_ref(return_type, mod),
        .C => {
            const ty_classes = abi.classify_type(return_type, mod);
            if (ty_classes[0] == .indirect) return true;
            if (ty_classes[0] == .direct and ty_classes[1] == .direct) return true;
            return false;
        },
        else => return false,
    }
}

/// Lowers a Zig type and its value based on a given calling convention to ensure
/// it matches the ABI.
fn lower_arg(func: *CodeGen, cc: std.builtin.CallingConvention, ty: Type, value: WValue) !void {
    if (cc != .C) {
        return func.lower_to_stack(value);
    }

    const mod = func.bin_file.base.comp.module.?;
    const ty_classes = abi.classify_type(ty, mod);
    assert(ty_classes[0] != .none);
    switch (ty.zig_type_tag(mod)) {
        .Struct, .Union => {
            if (ty_classes[0] == .indirect) {
                return func.lower_to_stack(value);
            }
            assert(ty_classes[0] == .direct);
            const scalar_type = abi.scalar_type(ty, mod);
            switch (value) {
                .memory,
                .memory_offset,
                .stack_offset,
                => _ = try func.load(value, scalar_type, 0),
                .dead => unreachable,
                else => try func.emit_wvalue(value),
            }
        },
        .Int, .Float => {
            if (ty_classes[1] == .none) {
                return func.lower_to_stack(value);
            }
            assert(ty_classes[0] == .direct and ty_classes[1] == .direct);
            assert(ty.abi_size(mod) == 16);
            // in this case we have an integer or float that must be lowered as 2 i64's.
            try func.emit_wvalue(value);
            try func.add_mem_arg(.i64_load, .{ .offset = value.offset(), .alignment = 8 });
            try func.emit_wvalue(value);
            try func.add_mem_arg(.i64_load, .{ .offset = value.offset() + 8, .alignment = 8 });
        },
        else => return func.lower_to_stack(value),
    }
}

/// Lowers a `WValue` to the stack. This means when the `value` results in
/// `.stack_offset` we calculate the pointer of this offset and use that.
/// The value is left on the stack, and not stored in any temporary.
fn lower_to_stack(func: *CodeGen, value: WValue) !void {
    switch (value) {
        .stack_offset => |offset| {
            try func.emit_wvalue(value);
            if (offset.value > 0) {
                switch (func.arch()) {
                    .wasm32 => {
                        try func.add_imm32(@as(i32, @bit_cast(offset.value)));
                        try func.add_tag(.i32_add);
                    },
                    .wasm64 => {
                        try func.add_imm64(offset.value);
                        try func.add_tag(.i64_add);
                    },
                    else => unreachable,
                }
            }
        },
        else => try func.emit_wvalue(value),
    }
}

/// Creates a local for the initial stack value
/// Asserts `initial_stack_value` is `.none`
fn initialize_stack(func: *CodeGen) !void {
    assert(func.initial_stack_value == .none);
    // Reserve a local to store the current stack pointer
    // We can later use this local to set the stack pointer back to the value
    // we have stored here.
    func.initial_stack_value = try func.ensure_alloc_local(Type.usize);
    // Also reserve a local to store the bottom stack value
    func.bottom_stack_value = try func.ensure_alloc_local(Type.usize);
}

/// Reads the stack pointer from `Context.initial_stack_value` and writes it
/// to the global stack pointer variable
fn restore_stack_pointer(func: *CodeGen) !void {
    // only restore the pointer if it was initialized
    if (func.initial_stack_value == .none) return;
    // Get the original stack pointer's value
    try func.emit_wvalue(func.initial_stack_value);

    // save its value in the global stack pointer
    try func.add_label(.global_set, @int_from_enum(func.bin_file.zig_object_ptr().?.stack_pointer_sym));
}

/// From a given type, will create space on the virtual stack to store the value of such type.
/// This returns a `WValue` with its active tag set to `local`, containing the index to the local
/// that points to the position on the virtual stack. This function should be used instead of
/// moveStack unless a local was already created to store the pointer.
///
/// Asserts Type has codegenbits
fn alloc_stack(func: *CodeGen, ty: Type) !WValue {
    const mod = func.bin_file.base.comp.module.?;
    assert(ty.has_runtime_bits_ignore_comptime(mod));
    if (func.initial_stack_value == .none) {
        try func.initialize_stack();
    }

    const abi_size = std.math.cast(u32, ty.abi_size(mod)) orelse {
        return func.fail("Type {} with ABI size of {d} exceeds stack frame size", .{
            ty.fmt(mod), ty.abi_size(mod),
        });
    };
    const abi_align = ty.abi_alignment(mod);

    func.stack_alignment = func.stack_alignment.max(abi_align);

    const offset: u32 = @int_cast(abi_align.forward(func.stack_size));
    defer func.stack_size = offset + abi_size;

    return WValue{ .stack_offset = .{ .value = offset, .references = 1 } };
}

/// From a given AIR instruction generates a pointer to the stack where
/// the value of its type will live.
/// This is different from alloc_stack where this will use the pointer's alignment
/// if it is set, to ensure the stack alignment will be set correctly.
fn alloc_stack_ptr(func: *CodeGen, inst: Air.Inst.Index) !WValue {
    const mod = func.bin_file.base.comp.module.?;
    const ptr_ty = func.type_of_index(inst);
    const pointee_ty = ptr_ty.child_type(mod);

    if (func.initial_stack_value == .none) {
        try func.initialize_stack();
    }

    if (!pointee_ty.has_runtime_bits_ignore_comptime(mod)) {
        return func.alloc_stack(Type.usize); // create a value containing just the stack pointer.
    }

    const abi_alignment = ptr_ty.ptr_alignment(mod);
    const abi_size = std.math.cast(u32, pointee_ty.abi_size(mod)) orelse {
        return func.fail("Type {} with ABI size of {d} exceeds stack frame size", .{
            pointee_ty.fmt(mod), pointee_ty.abi_size(mod),
        });
    };
    func.stack_alignment = func.stack_alignment.max(abi_alignment);

    const offset: u32 = @int_cast(abi_alignment.forward(func.stack_size));
    defer func.stack_size = offset + abi_size;

    return WValue{ .stack_offset = .{ .value = offset, .references = 1 } };
}

/// From given zig bitsize, returns the wasm bitsize
fn to_wasm_bits(bits: u16) ?u16 {
    return for ([_]u16{ 32, 64, 128 }) |wasm_bits| {
        if (bits <= wasm_bits) return wasm_bits;
    } else null;
}

/// Performs a copy of bytes for a given type. Copying all bytes
/// from rhs to lhs.
fn memcpy(func: *CodeGen, dst: WValue, src: WValue, len: WValue) !void {
    // When bulk_memory is enabled, we lower it to wasm's memcpy instruction.
    // If not, we lower it ourselves manually
    if (std.Target.wasm.feature_set_has(func.target.cpu.features, .bulk_memory)) {
        try func.lower_to_stack(dst);
        try func.lower_to_stack(src);
        try func.emit_wvalue(len);
        try func.add_extended(.memory_copy);
        return;
    }

    // when the length is comptime-known, rather than a runtime value, we can optimize the generated code by having
    // the loop during codegen, rather than inserting a runtime loop into the binary.
    switch (len) {
        .imm32, .imm64 => blk: {
            const length = switch (len) {
                .imm32 => |val| val,
                .imm64 => |val| val,
                else => unreachable,
            };
            // if the size (length) is more than 32 bytes, we use a runtime loop instead to prevent
            // binary size bloat.
            if (length > 32) break :blk;
            var offset: u32 = 0;
            const lhs_base = dst.offset();
            const rhs_base = src.offset();
            while (offset < length) : (offset += 1) {
                // get dst's address to store the result
                try func.emit_wvalue(dst);
                // load byte from src's address
                try func.emit_wvalue(src);
                switch (func.arch()) {
                    .wasm32 => {
                        try func.add_mem_arg(.i32_load8_u, .{ .offset = rhs_base + offset, .alignment = 1 });
                        try func.add_mem_arg(.i32_store8, .{ .offset = lhs_base + offset, .alignment = 1 });
                    },
                    .wasm64 => {
                        try func.add_mem_arg(.i64_load8_u, .{ .offset = rhs_base + offset, .alignment = 1 });
                        try func.add_mem_arg(.i64_store8, .{ .offset = lhs_base + offset, .alignment = 1 });
                    },
                    else => unreachable,
                }
            }
            return;
        },
        else => {},
    }

    // allocate a local for the offset, and set it to 0.
    // This to ensure that inside loops we correctly re-set the counter.
    var offset = try func.alloc_local(Type.usize); // local for counter
    defer offset.free(func);
    switch (func.arch()) {
        .wasm32 => try func.add_imm32(0),
        .wasm64 => try func.add_imm64(0),
        else => unreachable,
    }
    try func.add_label(.local_set, offset.local.value);

    // outer block to jump to when loop is done
    try func.start_block(.block, wasm.block_empty);
    try func.start_block(.loop, wasm.block_empty);

    // loop condition (offset == length -> break)
    {
        try func.emit_wvalue(offset);
        try func.emit_wvalue(len);
        switch (func.arch()) {
            .wasm32 => try func.add_tag(.i32_eq),
            .wasm64 => try func.add_tag(.i64_eq),
            else => unreachable,
        }
        try func.add_label(.br_if, 1); // jump out of loop into outer block (finished)
    }

    // get dst ptr
    {
        try func.emit_wvalue(dst);
        try func.emit_wvalue(offset);
        switch (func.arch()) {
            .wasm32 => try func.add_tag(.i32_add),
            .wasm64 => try func.add_tag(.i64_add),
            else => unreachable,
        }
    }

    // get src value and also store in dst
    {
        try func.emit_wvalue(src);
        try func.emit_wvalue(offset);
        switch (func.arch()) {
            .wasm32 => {
                try func.add_tag(.i32_add);
                try func.add_mem_arg(.i32_load8_u, .{ .offset = src.offset(), .alignment = 1 });
                try func.add_mem_arg(.i32_store8, .{ .offset = dst.offset(), .alignment = 1 });
            },
            .wasm64 => {
                try func.add_tag(.i64_add);
                try func.add_mem_arg(.i64_load8_u, .{ .offset = src.offset(), .alignment = 1 });
                try func.add_mem_arg(.i64_store8, .{ .offset = dst.offset(), .alignment = 1 });
            },
            else => unreachable,
        }
    }

    // increment loop counter
    {
        try func.emit_wvalue(offset);
        switch (func.arch()) {
            .wasm32 => {
                try func.add_imm32(1);
                try func.add_tag(.i32_add);
            },
            .wasm64 => {
                try func.add_imm64(1);
                try func.add_tag(.i64_add);
            },
            else => unreachable,
        }
        try func.add_label(.local_set, offset.local.value);
        try func.add_label(.br, 0); // jump to start of loop
    }
    try func.end_block(); // close off loop block
    try func.end_block(); // close off outer block
}

fn ptr_size(func: *const CodeGen) u16 {
    return @div_exact(func.target.ptr_bit_width(), 8);
}

fn arch(func: *const CodeGen) std.Target.Cpu.Arch {
    return func.target.cpu.arch;
}

/// For a given `Type`, will return true when the type will be passed
/// by reference, rather than by value
fn is_by_ref(ty: Type, mod: *Module) bool {
    const ip = &mod.intern_pool;
    const target = mod.get_target();
    switch (ty.zig_type_tag(mod)) {
        .Type,
        .ComptimeInt,
        .ComptimeFloat,
        .EnumLiteral,
        .Undefined,
        .Null,
        .Opaque,
        => unreachable,

        .NoReturn,
        .Void,
        .Bool,
        .ErrorSet,
        .Fn,
        .Enum,
        .AnyFrame,
        => return false,

        .Array,
        .Frame,
        => return ty.has_runtime_bits_ignore_comptime(mod),
        .Union => {
            if (mod.type_to_union(ty)) |union_obj| {
                if (union_obj.get_layout(ip) == .@"packed") {
                    return ty.abi_size(mod) > 8;
                }
            }
            return ty.has_runtime_bits_ignore_comptime(mod);
        },
        .Struct => {
            if (mod.type_to_packed_struct(ty)) |packed_struct| {
                return is_by_ref(Type.from_interned(packed_struct.backing_int_type(ip).*), mod);
            }
            return ty.has_runtime_bits_ignore_comptime(mod);
        },
        .Vector => return determine_simd_store_strategy(ty, mod) == .unrolled,
        .Int => return ty.int_info(mod).bits > 64,
        .Float => return ty.float_bits(target) > 64,
        .ErrorUnion => {
            const pl_ty = ty.error_union_payload(mod);
            if (!pl_ty.has_runtime_bits_ignore_comptime(mod)) {
                return false;
            }
            return true;
        },
        .Optional => {
            if (ty.is_ptr_like_optional(mod)) return false;
            const pl_type = ty.optional_child(mod);
            if (pl_type.zig_type_tag(mod) == .ErrorSet) return false;
            return pl_type.has_runtime_bits_ignore_comptime(mod);
        },
        .Pointer => {
            // Slices act like struct and will be passed by reference
            if (ty.is_slice(mod)) return true;
            return false;
        },
    }
}

const SimdStoreStrategy = enum {
    direct,
    unrolled,
};

/// For a given vector type, returns the `SimdStoreStrategy`.
/// This means when a given type is 128 bits and either the simd128 or relaxed-simd
/// features are enabled, the function will return `.direct`. This would allow to store
/// it using a instruction, rather than an unrolled version.
fn determine_simd_store_strategy(ty: Type, mod: *Module) SimdStoreStrategy {
    std.debug.assert(ty.zig_type_tag(mod) == .Vector);
    if (ty.bit_size(mod) != 128) return .unrolled;
    const has_feature = std.Target.wasm.feature_set_has;
    const target = mod.get_target();
    const features = target.cpu.features;
    if (has_feature(features, .relaxed_simd) or has_feature(features, .simd128)) {
        return .direct;
    }
    return .unrolled;
}

/// Creates a new local for a pointer that points to memory with given offset.
/// This can be used to get a pointer to a struct field, error payload, etc.
/// By providing `modify` as action, it will modify the given `ptr_value` instead of making a new
/// local value to store the pointer. This allows for local re-use and improves binary size.
fn build_pointer_offset(func: *CodeGen, ptr_value: WValue, offset: u64, action: enum { modify, new }) InnerError!WValue {
    // do not perform arithmetic when offset is 0.
    if (offset == 0 and ptr_value.offset() == 0 and action == .modify) return ptr_value;
    const result_ptr: WValue = switch (action) {
        .new => try func.ensure_alloc_local(Type.usize),
        .modify => ptr_value,
    };
    try func.emit_wvalue(ptr_value);
    if (offset + ptr_value.offset() > 0) {
        switch (func.arch()) {
            .wasm32 => {
                try func.add_imm32(@as(i32, @bit_cast(@as(u32, @int_cast(offset + ptr_value.offset())))));
                try func.add_tag(.i32_add);
            },
            .wasm64 => {
                try func.add_imm64(offset + ptr_value.offset());
                try func.add_tag(.i64_add);
            },
            else => unreachable,
        }
    }
    try func.add_label(.local_set, result_ptr.local.value);
    return result_ptr;
}

fn gen_inst(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const air_tags = func.air.instructions.items(.tag);
    return switch (air_tags[@int_from_enum(inst)]) {
        .inferred_alloc, .inferred_alloc_comptime => unreachable,

        .add => func.air_bin_op(inst, .add),
        .add_sat => func.air_sat_bin_op(inst, .add),
        .add_wrap => func.air_wrap_bin_op(inst, .add),
        .sub => func.air_bin_op(inst, .sub),
        .sub_sat => func.air_sat_bin_op(inst, .sub),
        .sub_wrap => func.air_wrap_bin_op(inst, .sub),
        .mul => func.air_bin_op(inst, .mul),
        .mul_wrap => func.air_wrap_bin_op(inst, .mul),
        .div_float, .div_exact => func.air_div(inst),
        .div_trunc => func.air_div_trunc(inst),
        .div_floor => func.air_div_floor(inst),
        .bit_and => func.air_bin_op(inst, .@"and"),
        .bit_or => func.air_bin_op(inst, .@"or"),
        .bool_and => func.air_bin_op(inst, .@"and"),
        .bool_or => func.air_bin_op(inst, .@"or"),
        .rem => func.air_bin_op(inst, .rem),
        .mod => func.air_mod(inst),
        .shl => func.air_wrap_bin_op(inst, .shl),
        .shl_exact => func.air_bin_op(inst, .shl),
        .shl_sat => func.air_shl_sat(inst),
        .shr, .shr_exact => func.air_bin_op(inst, .shr),
        .xor => func.air_bin_op(inst, .xor),
        .max => func.air_max_min(inst, .max),
        .min => func.air_max_min(inst, .min),
        .mul_add => func.air_mul_add(inst),

        .sqrt => func.air_unary_float_op(inst, .sqrt),
        .sin => func.air_unary_float_op(inst, .sin),
        .cos => func.air_unary_float_op(inst, .cos),
        .tan => func.air_unary_float_op(inst, .tan),
        .exp => func.air_unary_float_op(inst, .exp),
        .exp2 => func.air_unary_float_op(inst, .exp2),
        .log => func.air_unary_float_op(inst, .log),
        .log2 => func.air_unary_float_op(inst, .log2),
        .log10 => func.air_unary_float_op(inst, .log10),
        .floor => func.air_unary_float_op(inst, .floor),
        .ceil => func.air_unary_float_op(inst, .ceil),
        .round => func.air_unary_float_op(inst, .round),
        .trunc_float => func.air_unary_float_op(inst, .trunc),
        .neg => func.air_unary_float_op(inst, .neg),

        .abs => func.air_abs(inst),

        .add_with_overflow => func.air_add_sub_with_overflow(inst, .add),
        .sub_with_overflow => func.air_add_sub_with_overflow(inst, .sub),
        .shl_with_overflow => func.air_shl_with_overflow(inst),
        .mul_with_overflow => func.air_mul_with_overflow(inst),

        .clz => func.air_clz(inst),
        .ctz => func.air_ctz(inst),

        .cmp_eq => func.air_cmp(inst, .eq),
        .cmp_gte => func.air_cmp(inst, .gte),
        .cmp_gt => func.air_cmp(inst, .gt),
        .cmp_lte => func.air_cmp(inst, .lte),
        .cmp_lt => func.air_cmp(inst, .lt),
        .cmp_neq => func.air_cmp(inst, .neq),

        .cmp_vector => func.air_cmp_vector(inst),
        .cmp_lt_errors_len => func.air_cmp_lt_errors_len(inst),

        .array_elem_val => func.air_array_elem_val(inst),
        .array_to_slice => func.air_array_to_slice(inst),
        .alloc => func.air_alloc(inst),
        .arg => func.air_arg(inst),
        .bitcast => func.air_bitcast(inst),
        .block => func.air_block(inst),
        .trap => func.air_trap(inst),
        .breakpoint => func.air_breakpoint(inst),
        .br => func.air_br(inst),
        .int_from_bool => func.air_int_from_bool(inst),
        .cond_br => func.air_cond_br(inst),
        .intcast => func.air_intcast(inst),
        .fptrunc => func.air_fptrunc(inst),
        .fpext => func.air_fpext(inst),
        .int_from_float => func.air_int_from_float(inst),
        .float_from_int => func.air_float_from_int(inst),
        .get_union_tag => func.air_get_union_tag(inst),

        .@"try" => func.air_try(inst),
        .try_ptr => func.air_try_ptr(inst),

        .dbg_stmt => func.air_dbg_stmt(inst),
        .dbg_inline_block => func.air_dbg_inline_block(inst),
        .dbg_var_ptr => func.air_dbg_var(inst, true),
        .dbg_var_val => func.air_dbg_var(inst, false),

        .call => func.air_call(inst, .auto),
        .call_always_tail => func.air_call(inst, .always_tail),
        .call_never_tail => func.air_call(inst, .never_tail),
        .call_never_inline => func.air_call(inst, .never_inline),

        .is_err => func.air_is_err(inst, .i32_ne),
        .is_non_err => func.air_is_err(inst, .i32_eq),

        .is_null => func.air_is_null(inst, .i32_eq, .value),
        .is_non_null => func.air_is_null(inst, .i32_ne, .value),
        .is_null_ptr => func.air_is_null(inst, .i32_eq, .ptr),
        .is_non_null_ptr => func.air_is_null(inst, .i32_ne, .ptr),

        .load => func.air_load(inst),
        .loop => func.air_loop(inst),
        .memset => func.air_memset(inst, false),
        .memset_safe => func.air_memset(inst, true),
        .not => func.air_not(inst),
        .optional_payload => func.air_optional_payload(inst),
        .optional_payload_ptr => func.air_optional_payload_ptr(inst),
        .optional_payload_ptr_set => func.air_optional_payload_ptr_set(inst),
        .ptr_add => func.air_ptr_bin_op(inst, .add),
        .ptr_sub => func.air_ptr_bin_op(inst, .sub),
        .ptr_elem_ptr => func.air_ptr_elem_ptr(inst),
        .ptr_elem_val => func.air_ptr_elem_val(inst),
        .int_from_ptr => func.air_int_from_ptr(inst),
        .ret => func.air_ret(inst),
        .ret_safe => func.air_ret(inst), // TODO
        .ret_ptr => func.air_ret_ptr(inst),
        .ret_load => func.air_ret_load(inst),
        .splat => func.air_splat(inst),
        .select => func.air_select(inst),
        .shuffle => func.air_shuffle(inst),
        .reduce => func.air_reduce(inst),
        .aggregate_init => func.air_aggregate_init(inst),
        .union_init => func.air_union_init(inst),
        .prefetch => func.air_prefetch(inst),
        .popcount => func.air_popcount(inst),
        .byte_swap => func.air_byte_swap(inst),

        .slice => func.air_slice(inst),
        .slice_len => func.air_slice_len(inst),
        .slice_elem_val => func.air_slice_elem_val(inst),
        .slice_elem_ptr => func.air_slice_elem_ptr(inst),
        .slice_ptr => func.air_slice_ptr(inst),
        .ptr_slice_len_ptr => func.air_ptr_slice_field_ptr(inst, func.ptr_size()),
        .ptr_slice_ptr_ptr => func.air_ptr_slice_field_ptr(inst, 0),
        .store => func.air_store(inst, false),
        .store_safe => func.air_store(inst, true),

        .set_union_tag => func.air_set_union_tag(inst),
        .struct_field_ptr => func.air_struct_field_ptr(inst),
        .struct_field_ptr_index_0 => func.air_struct_field_ptr_index(inst, 0),
        .struct_field_ptr_index_1 => func.air_struct_field_ptr_index(inst, 1),
        .struct_field_ptr_index_2 => func.air_struct_field_ptr_index(inst, 2),
        .struct_field_ptr_index_3 => func.air_struct_field_ptr_index(inst, 3),
        .struct_field_val => func.air_struct_field_val(inst),
        .field_parent_ptr => func.air_field_parent_ptr(inst),

        .switch_br => func.air_switch_br(inst),
        .trunc => func.air_trunc(inst),
        .unreach => func.air_unreachable(inst),

        .wrap_optional => func.air_wrap_optional(inst),
        .unwrap_errunion_payload => func.air_unwrap_err_union_payload(inst, false),
        .unwrap_errunion_payload_ptr => func.air_unwrap_err_union_payload(inst, true),
        .unwrap_errunion_err => func.air_unwrap_err_union_error(inst, false),
        .unwrap_errunion_err_ptr => func.air_unwrap_err_union_error(inst, true),
        .wrap_errunion_payload => func.air_wrap_err_union_payload(inst),
        .wrap_errunion_err => func.air_wrap_err_union_err(inst),
        .errunion_payload_ptr_set => func.air_err_union_payload_ptr_set(inst),
        .error_name => func.air_error_name(inst),

        .wasm_memory_size => func.air_wasm_memory_size(inst),
        .wasm_memory_grow => func.air_wasm_memory_grow(inst),

        .memcpy => func.air_memcpy(inst),

        .ret_addr => func.air_ret_addr(inst),
        .tag_name => func.air_tag_name(inst),

        .error_set_has_value => func.air_error_set_has_value(inst),
        .frame_addr => func.air_frame_address(inst),

        .mul_sat,
        .assembly,
        .bit_reverse,
        .is_err_ptr,
        .is_non_err_ptr,

        .err_return_trace,
        .set_err_return_trace,
        .save_err_return_trace_index,
        .is_named_enum_value,
        .addrspace_cast,
        .vector_store_elem,
        .c_va_arg,
        .c_va_copy,
        .c_va_end,
        .c_va_start,
        => |tag| return func.fail("TODO: Implement wasm inst: {s}", .{@tag_name(tag)}),

        .atomic_load => func.air_atomic_load(inst),
        .atomic_store_unordered,
        .atomic_store_monotonic,
        .atomic_store_release,
        .atomic_store_seq_cst,
        // in WebAssembly, all atomic instructions are sequentially ordered.
        => func.air_atomic_store(inst),
        .atomic_rmw => func.air_atomic_rmw(inst),
        .cmpxchg_weak => func.air_cmpxchg(inst),
        .cmpxchg_strong => func.air_cmpxchg(inst),
        .fence => func.air_fence(inst),

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
        => return func.fail("TODO implement optimized float mode", .{}),

        .add_safe,
        .sub_safe,
        .mul_safe,
        => return func.fail("TODO implement safety_checked_instructions", .{}),

        .work_item_id,
        .work_group_size,
        .work_group_id,
        => unreachable,
    };
}

fn gen_body(func: *CodeGen, body: []const Air.Inst.Index) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const ip = &mod.intern_pool;

    for (body) |inst| {
        if (func.liveness.is_unused(inst) and !func.air.must_lower(inst, ip)) {
            continue;
        }
        const old_bookkeeping_value = func.air_bookkeeping;
        try func.current_branch().values.ensure_unused_capacity(func.gpa, Liveness.bpi);
        try func.gen_inst(inst);

        if (std.debug.runtime_safety and func.air_bookkeeping < old_bookkeeping_value + 1) {
            std.debug.panic("Missing call to `finish_air` in AIR instruction %{d} ('{}')", .{
                inst,
                func.air.instructions.items(.tag)[@int_from_enum(inst)],
            });
        }
    }
}

fn air_ret(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const un_op = func.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const operand = try func.resolve_inst(un_op);
    const fn_info = mod.type_to_func(func.decl.type_of(mod)).?;
    const ret_ty = Type.from_interned(fn_info.return_type);

    // result must be stored in the stack and we return a pointer
    // to the stack instead
    if (func.return_value != .none) {
        try func.store(func.return_value, operand, ret_ty, 0);
    } else if (fn_info.cc == .C and ret_ty.has_runtime_bits_ignore_comptime(mod)) {
        switch (ret_ty.zig_type_tag(mod)) {
            // Aggregate types can be lowered as a singular value
            .Struct, .Union => {
                const scalar_type = abi.scalar_type(ret_ty, mod);
                try func.emit_wvalue(operand);
                const opcode = build_opcode(.{
                    .op = .load,
                    .width = @as(u8, @int_cast(scalar_type.abi_size(mod) * 8)),
                    .signedness = if (scalar_type.is_signed_int(mod)) .signed else .unsigned,
                    .valtype1 = type_to_valtype(scalar_type, mod),
                });
                try func.add_mem_arg(Mir.Inst.Tag.from_opcode(opcode), .{
                    .offset = operand.offset(),
                    .alignment = @int_cast(scalar_type.abi_alignment(mod).to_byte_units().?),
                });
            },
            else => try func.emit_wvalue(operand),
        }
    } else {
        if (!ret_ty.has_runtime_bits_ignore_comptime(mod) and ret_ty.is_error(mod)) {
            try func.add_imm32(0);
        } else {
            try func.emit_wvalue(operand);
        }
    }
    try func.restore_stack_pointer();
    try func.add_tag(.@"return");

    func.finish_air(inst, .none, &.{un_op});
}

fn air_ret_ptr(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const child_type = func.type_of_index(inst).child_type(mod);

    const result = result: {
        if (!child_type.is_fn_or_has_runtime_bits_ignore_comptime(mod)) {
            break :result try func.alloc_stack(Type.usize); // create pointer to void
        }

        const fn_info = mod.type_to_func(func.decl.type_of(mod)).?;
        if (first_param_sret(fn_info.cc, Type.from_interned(fn_info.return_type), mod)) {
            break :result func.return_value;
        }

        break :result try func.alloc_stack_ptr(inst);
    };

    func.finish_air(inst, result, &.{});
}

fn air_ret_load(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const un_op = func.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const operand = try func.resolve_inst(un_op);
    const ret_ty = func.type_of(un_op).child_type(mod);

    const fn_info = mod.type_to_func(func.decl.type_of(mod)).?;
    if (!ret_ty.has_runtime_bits_ignore_comptime(mod)) {
        if (ret_ty.is_error(mod)) {
            try func.add_imm32(0);
        }
    } else if (!first_param_sret(fn_info.cc, Type.from_interned(fn_info.return_type), mod)) {
        // leave on the stack
        _ = try func.load(operand, ret_ty, 0);
    }

    try func.restore_stack_pointer();
    try func.add_tag(.@"return");
    return func.finish_air(inst, .none, &.{un_op});
}

fn air_call(func: *CodeGen, inst: Air.Inst.Index, modifier: std.builtin.CallModifier) InnerError!void {
    if (modifier == .always_tail) return func.fail("TODO implement tail calls for wasm", .{});
    const pl_op = func.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
    const extra = func.air.extra_data(Air.Call, pl_op.payload);
    const args = @as([]const Air.Inst.Ref, @ptr_cast(func.air.extra[extra.end..][0..extra.data.args_len]));
    const ty = func.type_of(pl_op.operand);

    const mod = func.bin_file.base.comp.module.?;
    const ip = &mod.intern_pool;
    const fn_ty = switch (ty.zig_type_tag(mod)) {
        .Fn => ty,
        .Pointer => ty.child_type(mod),
        else => unreachable,
    };
    const ret_ty = fn_ty.fn_return_type(mod);
    const fn_info = mod.type_to_func(fn_ty).?;
    const first_param_sret = first_param_sret(fn_info.cc, Type.from_interned(fn_info.return_type), mod);

    const callee: ?InternPool.DeclIndex = blk: {
        const func_val = (try func.air.value(pl_op.operand, mod)) orelse break :blk null;

        if (func_val.get_function(mod)) |function| {
            _ = try func.bin_file.get_or_create_atom_for_decl(function.owner_decl);
            break :blk function.owner_decl;
        } else if (func_val.get_extern_func(mod)) |extern_func| {
            const ext_decl = mod.decl_ptr(extern_func.decl);
            const ext_info = mod.type_to_func(ext_decl.type_of(mod)).?;
            var func_type = try gen_functype(func.gpa, ext_info.cc, ext_info.param_types.get(ip), Type.from_interned(ext_info.return_type), mod);
            defer func_type.deinit(func.gpa);
            const atom_index = try func.bin_file.get_or_create_atom_for_decl(extern_func.decl);
            const atom = func.bin_file.get_atom_ptr(atom_index);
            const type_index = try func.bin_file.store_decl_type(extern_func.decl, func_type);
            try func.bin_file.add_or_update_import(
                ext_decl.name.to_slice(&mod.intern_pool),
                atom.sym_index,
                ext_decl.get_owned_extern_func(mod).?.lib_name.to_slice(&mod.intern_pool),
                type_index,
            );
            break :blk extern_func.decl;
        } else switch (mod.intern_pool.index_to_key(func_val.ip_index)) {
            .ptr => |ptr| if (ptr.byte_offset == 0) switch (ptr.base_addr) {
                .decl => |decl| {
                    _ = try func.bin_file.get_or_create_atom_for_decl(decl);
                    break :blk decl;
                },
                else => {},
            },
            else => {},
        }
        return func.fail("Expected a function, but instead found '{s}'", .{@tag_name(ip.index_to_key(func_val.to_intern()))});
    };

    const sret = if (first_param_sret) blk: {
        const sret_local = try func.alloc_stack(ret_ty);
        try func.lower_to_stack(sret_local);
        break :blk sret_local;
    } else WValue{ .none = {} };

    for (args) |arg| {
        const arg_val = try func.resolve_inst(arg);

        const arg_ty = func.type_of(arg);
        if (!arg_ty.has_runtime_bits_ignore_comptime(mod)) continue;

        try func.lower_arg(mod.type_to_func(fn_ty).?.cc, arg_ty, arg_val);
    }

    if (callee) |direct| {
        const atom_index = func.bin_file.zig_object_ptr().?.decls_map.get(direct).?.atom;
        try func.add_label(.call, @int_from_enum(func.bin_file.get_atom(atom_index).sym_index));
    } else {
        // in this case we call a function pointer
        // so load its value onto the stack
        std.debug.assert(ty.zig_type_tag(mod) == .Pointer);
        const operand = try func.resolve_inst(pl_op.operand);
        try func.emit_wvalue(operand);

        var fn_type = try gen_functype(func.gpa, fn_info.cc, fn_info.param_types.get(ip), Type.from_interned(fn_info.return_type), mod);
        defer fn_type.deinit(func.gpa);

        const fn_type_index = try func.bin_file.zig_object_ptr().?.put_or_get_func_type(func.gpa, fn_type);
        try func.add_label(.call_indirect, fn_type_index);
    }

    const result_value = result_value: {
        if (!ret_ty.has_runtime_bits_ignore_comptime(mod) and !ret_ty.is_error(mod)) {
            break :result_value WValue{ .none = {} };
        } else if (ret_ty.is_no_return(mod)) {
            try func.add_tag(.@"unreachable");
            break :result_value WValue{ .none = {} };
        } else if (first_param_sret) {
            break :result_value sret;
            // TODO: Make this less fragile and optimize
        } else if (mod.type_to_func(fn_ty).?.cc == .C and ret_ty.zig_type_tag(mod) == .Struct or ret_ty.zig_type_tag(mod) == .Union) {
            const result_local = try func.alloc_local(ret_ty);
            try func.add_label(.local_set, result_local.local.value);
            const scalar_type = abi.scalar_type(ret_ty, mod);
            const result = try func.alloc_stack(scalar_type);
            try func.store(result, result_local, scalar_type, 0);
            break :result_value result;
        } else {
            const result_local = try func.alloc_local(ret_ty);
            try func.add_label(.local_set, result_local.local.value);
            break :result_value result_local;
        }
    };

    var bt = try func.iterate_big_tomb(inst, 1 + args.len);
    bt.feed(pl_op.operand);
    for (args) |arg| bt.feed(arg);
    return bt.finish_air(result_value);
}

fn air_alloc(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const value = try func.alloc_stack_ptr(inst);
    func.finish_air(inst, value, &.{});
}

fn air_store(func: *CodeGen, inst: Air.Inst.Index, safety: bool) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    if (safety) {
        // TODO if the value is undef, write 0xaa bytes to dest
    } else {
        // TODO if the value is undef, don't lower this instruction
    }
    const bin_op = func.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;

    const lhs = try func.resolve_inst(bin_op.lhs);
    const rhs = try func.resolve_inst(bin_op.rhs);
    const ptr_ty = func.type_of(bin_op.lhs);
    const ptr_info = ptr_ty.ptr_info(mod);
    const ty = ptr_ty.child_type(mod);

    if (ptr_info.packed_offset.host_size == 0) {
        try func.store(lhs, rhs, ty, 0);
    } else {
        // at this point we have a non-natural alignment, we must
        // load the value, and then shift+or the rhs into the result location.
        const int_elem_ty = try mod.int_type(.unsigned, ptr_info.packed_offset.host_size * 8);

        if (is_by_ref(int_elem_ty, mod)) {
            return func.fail("TODO: air_store for pointers to bitfields with backing type larger than 64bits", .{});
        }

        var mask = @as(u64, @int_cast((@as(u65, 1) << @as(u7, @int_cast(ty.bit_size(mod)))) - 1));
        mask <<= @as(u6, @int_cast(ptr_info.packed_offset.bit_offset));
        mask ^= ~@as(u64, 0);
        const shift_val = if (ptr_info.packed_offset.host_size <= 4)
            WValue{ .imm32 = ptr_info.packed_offset.bit_offset }
        else
            WValue{ .imm64 = ptr_info.packed_offset.bit_offset };
        const mask_val = if (ptr_info.packed_offset.host_size <= 4)
            WValue{ .imm32 = @as(u32, @truncate(mask)) }
        else
            WValue{ .imm64 = mask };

        try func.emit_wvalue(lhs);
        const loaded = try func.load(lhs, int_elem_ty, 0);
        const anded = try func.bin_op(loaded, mask_val, int_elem_ty, .@"and");
        const extended_value = try func.intcast(rhs, ty, int_elem_ty);
        const shifted_value = if (ptr_info.packed_offset.bit_offset > 0) shifted: {
            break :shifted try func.bin_op(extended_value, shift_val, int_elem_ty, .shl);
        } else extended_value;
        const result = try func.bin_op(anded, shifted_value, int_elem_ty, .@"or");
        // lhs is still on the stack
        try func.store(.stack, result, int_elem_ty, lhs.offset());
    }

    func.finish_air(inst, .none, &.{ bin_op.lhs, bin_op.rhs });
}

fn store(func: *CodeGen, lhs: WValue, rhs: WValue, ty: Type, offset: u32) InnerError!void {
    assert(!(lhs != .stack and rhs == .stack));
    const mod = func.bin_file.base.comp.module.?;
    const abi_size = ty.abi_size(mod);
    switch (ty.zig_type_tag(mod)) {
        .ErrorUnion => {
            const pl_ty = ty.error_union_payload(mod);
            if (!pl_ty.has_runtime_bits_ignore_comptime(mod)) {
                return func.store(lhs, rhs, Type.anyerror, 0);
            }

            const len = @as(u32, @int_cast(abi_size));
            return func.memcpy(lhs, rhs, .{ .imm32 = len });
        },
        .Optional => {
            if (ty.is_ptr_like_optional(mod)) {
                return func.store(lhs, rhs, Type.usize, 0);
            }
            const pl_ty = ty.optional_child(mod);
            if (!pl_ty.has_runtime_bits_ignore_comptime(mod)) {
                return func.store(lhs, rhs, Type.u8, 0);
            }
            if (pl_ty.zig_type_tag(mod) == .ErrorSet) {
                return func.store(lhs, rhs, Type.anyerror, 0);
            }

            const len = @as(u32, @int_cast(abi_size));
            return func.memcpy(lhs, rhs, .{ .imm32 = len });
        },
        .Struct, .Array, .Union => if (is_by_ref(ty, mod)) {
            const len = @as(u32, @int_cast(abi_size));
            return func.memcpy(lhs, rhs, .{ .imm32 = len });
        },
        .Vector => switch (determine_simd_store_strategy(ty, mod)) {
            .unrolled => {
                const len: u32 = @int_cast(abi_size);
                return func.memcpy(lhs, rhs, .{ .imm32 = len });
            },
            .direct => {
                try func.emit_wvalue(lhs);
                try func.lower_to_stack(rhs);
                // TODO: Add helper functions for simd opcodes
                const extra_index: u32 = @int_cast(func.mir_extra.items.len);
                // stores as := opcode, offset, alignment (opcode::memarg)
                try func.mir_extra.append_slice(func.gpa, &[_]u32{
                    std.wasm.simd_opcode(.v128_store),
                    offset + lhs.offset(),
                    @int_cast(ty.abi_alignment(mod).to_byte_units() orelse 0),
                });
                return func.add_inst(.{ .tag = .simd_prefix, .data = .{ .payload = extra_index } });
            },
        },
        .Pointer => {
            if (ty.is_slice(mod)) {
                // store pointer first
                // lower it to the stack so we do not have to store rhs into a local first
                try func.emit_wvalue(lhs);
                const ptr_local = try func.load(rhs, Type.usize, 0);
                try func.store(.{ .stack = {} }, ptr_local, Type.usize, 0 + lhs.offset());

                // retrieve length from rhs, and store that alongside lhs as well
                try func.emit_wvalue(lhs);
                const len_local = try func.load(rhs, Type.usize, func.ptr_size());
                try func.store(.{ .stack = {} }, len_local, Type.usize, func.ptr_size() + lhs.offset());
                return;
            }
        },
        .Int, .Float => if (abi_size > 8 and abi_size <= 16) {
            try func.emit_wvalue(lhs);
            const lsb = try func.load(rhs, Type.u64, 0);
            try func.store(.{ .stack = {} }, lsb, Type.u64, 0 + lhs.offset());

            try func.emit_wvalue(lhs);
            const msb = try func.load(rhs, Type.u64, 8);
            try func.store(.{ .stack = {} }, msb, Type.u64, 8 + lhs.offset());
            return;
        } else if (abi_size > 16) {
            try func.memcpy(lhs, rhs, .{ .imm32 = @as(u32, @int_cast(ty.abi_size(mod))) });
        },
        else => if (abi_size > 8) {
            return func.fail("TODO: `store` for type `{}` with abisize `{d}`", .{
                ty.fmt(func.bin_file.base.comp.module.?),
                abi_size,
            });
        },
    }
    try func.emit_wvalue(lhs);
    // In this case we're actually interested in storing the stack position
    // into lhs, so we calculate that and emit that instead
    try func.lower_to_stack(rhs);

    const valtype = type_to_valtype(ty, mod);
    const opcode = build_opcode(.{
        .valtype1 = valtype,
        .width = @as(u8, @int_cast(abi_size * 8)),
        .op = .store,
    });

    // store rhs value at stack pointer's location in memory
    try func.add_mem_arg(
        Mir.Inst.Tag.from_opcode(opcode),
        .{
            .offset = offset + lhs.offset(),
            .alignment = @int_cast(ty.abi_alignment(mod).to_byte_units().?),
        },
    );
}

fn air_load(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const ty_op = func.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const operand = try func.resolve_inst(ty_op.operand);
    const ty = ty_op.ty.to_type();
    const ptr_ty = func.type_of(ty_op.operand);
    const ptr_info = ptr_ty.ptr_info(mod);

    if (!ty.has_runtime_bits_ignore_comptime(mod)) return func.finish_air(inst, .none, &.{ty_op.operand});

    const result = result: {
        if (is_by_ref(ty, mod)) {
            const new_local = try func.alloc_stack(ty);
            try func.store(new_local, operand, ty, 0);
            break :result new_local;
        }

        if (ptr_info.packed_offset.host_size == 0) {
            const stack_loaded = try func.load(operand, ty, 0);
            break :result try stack_loaded.to_local(func, ty);
        }

        // at this point we have a non-natural alignment, we must
        // shift the value to obtain the correct bit.
        const int_elem_ty = try mod.int_type(.unsigned, ptr_info.packed_offset.host_size * 8);
        const shift_val = if (ptr_info.packed_offset.host_size <= 4)
            WValue{ .imm32 = ptr_info.packed_offset.bit_offset }
        else if (ptr_info.packed_offset.host_size <= 8)
            WValue{ .imm64 = ptr_info.packed_offset.bit_offset }
        else
            return func.fail("TODO: air_load where ptr to bitfield exceeds 64 bits", .{});

        const stack_loaded = try func.load(operand, int_elem_ty, 0);
        const shifted = try func.bin_op(stack_loaded, shift_val, int_elem_ty, .shr);
        const result = try func.trunc(shifted, ty, int_elem_ty);
        // const wrapped = try func.wrap_operand(shifted, ty);
        break :result try result.to_local(func, ty);
    };
    func.finish_air(inst, result, &.{ty_op.operand});
}

/// Loads an operand from the linear memory section.
/// NOTE: Leaves the value on the stack.
fn load(func: *CodeGen, operand: WValue, ty: Type, offset: u32) InnerError!WValue {
    const mod = func.bin_file.base.comp.module.?;
    // load local's value from memory by its stack position
    try func.emit_wvalue(operand);

    if (ty.zig_type_tag(mod) == .Vector) {
        // TODO: Add helper functions for simd opcodes
        const extra_index = @as(u32, @int_cast(func.mir_extra.items.len));
        // stores as := opcode, offset, alignment (opcode::memarg)
        try func.mir_extra.append_slice(func.gpa, &[_]u32{
            std.wasm.simd_opcode(.v128_load),
            offset + operand.offset(),
            @int_cast(ty.abi_alignment(mod).to_byte_units().?),
        });
        try func.add_inst(.{ .tag = .simd_prefix, .data = .{ .payload = extra_index } });
        return WValue{ .stack = {} };
    }

    const abi_size: u8 = @int_cast(ty.abi_size(mod));
    const opcode = build_opcode(.{
        .valtype1 = type_to_valtype(ty, mod),
        .width = abi_size * 8,
        .op = .load,
        .signedness = .unsigned,
    });

    try func.add_mem_arg(
        Mir.Inst.Tag.from_opcode(opcode),
        .{
            .offset = offset + operand.offset(),
            .alignment = @int_cast(ty.abi_alignment(mod).to_byte_units().?),
        },
    );

    return WValue{ .stack = {} };
}

fn air_arg(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const arg_index = func.arg_index;
    const arg = func.args[arg_index];
    const cc = mod.type_to_func(func.decl.type_of(mod)).?.cc;
    const arg_ty = func.type_of_index(inst);
    if (cc == .C) {
        const arg_classes = abi.classify_type(arg_ty, mod);
        for (arg_classes) |class| {
            if (class != .none) {
                func.arg_index += 1;
            }
        }

        // When we have an argument that's passed using more than a single parameter,
        // we combine them into a single stack value
        if (arg_classes[0] == .direct and arg_classes[1] == .direct) {
            if (arg_ty.zig_type_tag(mod) != .Int and arg_ty.zig_type_tag(mod) != .Float) {
                return func.fail(
                    "TODO: Implement C-ABI argument for type '{}'",
                    .{arg_ty.fmt(func.bin_file.base.comp.module.?)},
                );
            }
            const result = try func.alloc_stack(arg_ty);
            try func.store(result, arg, Type.u64, 0);
            try func.store(result, func.args[arg_index + 1], Type.u64, 8);
            return func.finish_air(inst, result, &.{});
        }
    } else {
        func.arg_index += 1;
    }

    switch (func.debug_output) {
        .dwarf => |dwarf| {
            const src_index = func.air.instructions.items(.data)[@int_from_enum(inst)].arg.src_index;
            const name = mod.get_param_name(func.func_index, src_index);
            try dwarf.gen_arg_dbg_info(name, arg_ty, mod.func_owner_decl_index(func.func_index), .{
                .wasm_local = arg.local.value,
            });
        },
        else => {},
    }

    func.finish_air(inst, arg, &.{});
}

fn air_bin_op(func: *CodeGen, inst: Air.Inst.Index, op: Op) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const bin_op = func.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
    const lhs = try func.resolve_inst(bin_op.lhs);
    const rhs = try func.resolve_inst(bin_op.rhs);
    const lhs_ty = func.type_of(bin_op.lhs);
    const rhs_ty = func.type_of(bin_op.rhs);

    // For certain operations, such as shifting, the types are different.
    // When converting this to a WebAssembly type, they *must* match to perform
    // an operation. For this reason we verify if the WebAssembly type is different, in which
    // case we first coerce the operands to the same type before performing the operation.
    // For big integers we can ignore this as we will call into compiler-rt which handles this.
    const result = switch (op) {
        .shr, .shl => res: {
            const lhs_wasm_bits = to_wasm_bits(@as(u16, @int_cast(lhs_ty.bit_size(mod)))) orelse {
                return func.fail("TODO: implement '{s}' for types larger than 128 bits", .{@tag_name(op)});
            };
            const rhs_wasm_bits = to_wasm_bits(@as(u16, @int_cast(rhs_ty.bit_size(mod)))).?;
            const new_rhs = if (lhs_wasm_bits != rhs_wasm_bits and lhs_wasm_bits != 128) blk: {
                const tmp = try func.intcast(rhs, rhs_ty, lhs_ty);
                break :blk try tmp.to_local(func, lhs_ty);
            } else rhs;
            const stack_result = try func.bin_op(lhs, new_rhs, lhs_ty, op);
            break :res try stack_result.to_local(func, lhs_ty);
        },
        else => res: {
            const stack_result = try func.bin_op(lhs, rhs, lhs_ty, op);
            break :res try stack_result.to_local(func, lhs_ty);
        },
    };

    func.finish_air(inst, result, &.{ bin_op.lhs, bin_op.rhs });
}

/// Performs a binary operation on the given `WValue`'s
/// NOTE: THis leaves the value on top of the stack.
fn bin_op(func: *CodeGen, lhs: WValue, rhs: WValue, ty: Type, op: Op) InnerError!WValue {
    const mod = func.bin_file.base.comp.module.?;
    assert(!(lhs != .stack and rhs == .stack));

    if (ty.is_any_float()) {
        const float_op = FloatOp.from_op(op);
        return func.float_op(float_op, ty, &.{ lhs, rhs });
    }

    if (is_by_ref(ty, mod)) {
        if (ty.zig_type_tag(mod) == .Int) {
            return func.bin_op_big_int(lhs, rhs, ty, op);
        } else {
            return func.fail(
                "TODO: Implement binary operation for type: {}",
                .{ty.fmt(func.bin_file.base.comp.module.?)},
            );
        }
    }

    const opcode: wasm.Opcode = build_opcode(.{
        .op = op,
        .valtype1 = type_to_valtype(ty, mod),
        .signedness = if (ty.is_signed_int(mod)) .signed else .unsigned,
    });
    try func.emit_wvalue(lhs);
    try func.emit_wvalue(rhs);

    try func.add_tag(Mir.Inst.Tag.from_opcode(opcode));

    return WValue{ .stack = {} };
}

fn bin_op_big_int(func: *CodeGen, lhs: WValue, rhs: WValue, ty: Type, op: Op) InnerError!WValue {
    const mod = func.bin_file.base.comp.module.?;
    const int_info = ty.int_info(mod);
    if (int_info.bits > 128) {
        return func.fail("TODO: Implement binary operation for big integers larger than 128 bits", .{});
    }

    switch (op) {
        .mul => return func.call_intrinsic("__multi3", &.{ ty.to_intern(), ty.to_intern() }, ty, &.{ lhs, rhs }),
        .div => switch (int_info.signedness) {
            .signed => return func.call_intrinsic("__udivti3", &.{ ty.to_intern(), ty.to_intern() }, ty, &.{ lhs, rhs }),
            .unsigned => return func.call_intrinsic("__divti3", &.{ ty.to_intern(), ty.to_intern() }, ty, &.{ lhs, rhs }),
        },
        .rem => return func.call_intrinsic("__umodti3", &.{ ty.to_intern(), ty.to_intern() }, ty, &.{ lhs, rhs }),
        .shr => return func.call_intrinsic("__lshrti3", &.{ ty.to_intern(), .i32_type }, ty, &.{ lhs, rhs }),
        .shl => return func.call_intrinsic("__ashlti3", &.{ ty.to_intern(), .i32_type }, ty, &.{ lhs, rhs }),
        .@"and", .@"or", .xor => {
            const result = try func.alloc_stack(ty);
            try func.emit_wvalue(result);
            const lhs_high_bit = try func.load(lhs, Type.u64, 0);
            const rhs_high_bit = try func.load(rhs, Type.u64, 0);
            const op_high_bit = try func.bin_op(lhs_high_bit, rhs_high_bit, Type.u64, op);
            try func.store(.stack, op_high_bit, Type.u64, result.offset());

            try func.emit_wvalue(result);
            const lhs_low_bit = try func.load(lhs, Type.u64, 8);
            const rhs_low_bit = try func.load(rhs, Type.u64, 8);
            const op_low_bit = try func.bin_op(lhs_low_bit, rhs_low_bit, Type.u64, op);
            try func.store(.stack, op_low_bit, Type.u64, result.offset() + 8);
            return result;
        },
        .add, .sub => {
            const result = try func.alloc_stack(ty);
            var lhs_high_bit = try (try func.load(lhs, Type.u64, 0)).to_local(func, Type.u64);
            defer lhs_high_bit.free(func);
            var rhs_high_bit = try (try func.load(rhs, Type.u64, 0)).to_local(func, Type.u64);
            defer rhs_high_bit.free(func);
            var high_op_res = try (try func.bin_op(lhs_high_bit, rhs_high_bit, Type.u64, op)).to_local(func, Type.u64);
            defer high_op_res.free(func);

            const lhs_low_bit = try func.load(lhs, Type.u64, 8);
            const rhs_low_bit = try func.load(rhs, Type.u64, 8);
            const low_op_res = try func.bin_op(lhs_low_bit, rhs_low_bit, Type.u64, op);

            const lt = if (op == .add) blk: {
                break :blk try func.cmp(high_op_res, rhs_high_bit, Type.u64, .lt);
            } else if (op == .sub) blk: {
                break :blk try func.cmp(lhs_high_bit, rhs_high_bit, Type.u64, .lt);
            } else unreachable;
            const tmp = try func.intcast(lt, Type.u32, Type.u64);
            var tmp_op = try (try func.bin_op(low_op_res, tmp, Type.u64, op)).to_local(func, Type.u64);
            defer tmp_op.free(func);

            try func.store(result, high_op_res, Type.u64, 0);
            try func.store(result, tmp_op, Type.u64, 8);
            return result;
        },
        else => return func.fail("TODO: Implement binary operation for big integers: '{s}'", .{@tag_name(op)}),
    }
}

const FloatOp = enum {
    add,
    ceil,
    cos,
    div,
    exp,
    exp2,
    fabs,
    floor,
    fma,
    fmax,
    fmin,
    fmod,
    log,
    log10,
    log2,
    mul,
    neg,
    round,
    sin,
    sqrt,
    sub,
    tan,
    trunc,

    pub fn from_op(op: Op) FloatOp {
        return switch (op) {
            .add => .add,
            .ceil => .ceil,
            .div => .div,
            .abs => .fabs,
            .floor => .floor,
            .max => .fmax,
            .min => .fmin,
            .mul => .mul,
            .neg => .neg,
            .nearest => .round,
            .sqrt => .sqrt,
            .sub => .sub,
            .trunc => .trunc,
            else => unreachable,
        };
    }

    pub fn to_op(float_op: FloatOp) ?Op {
        return switch (float_op) {
            .add => .add,
            .ceil => .ceil,
            .div => .div,
            .fabs => .abs,
            .floor => .floor,
            .fmax => .max,
            .fmin => .min,
            .mul => .mul,
            .neg => .neg,
            .round => .nearest,
            .sqrt => .sqrt,
            .sub => .sub,
            .trunc => .trunc,

            .cos,
            .exp,
            .exp2,
            .fma,
            .fmod,
            .log,
            .log10,
            .log2,
            .sin,
            .tan,
            => null,
        };
    }
};

fn air_abs(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const ty_op = func.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const operand = try func.resolve_inst(ty_op.operand);
    const ty = func.type_of(ty_op.operand);
    const scalar_ty = ty.scalar_type(mod);

    switch (scalar_ty.zig_type_tag(mod)) {
        .Int => if (ty.zig_type_tag(mod) == .Vector) {
            return func.fail("TODO implement air_abs for {}", .{ty.fmt(mod)});
        } else {
            const int_bits = ty.int_info(mod).bits;
            const wasm_bits = to_wasm_bits(int_bits) orelse {
                return func.fail("TODO: air_abs for signed integers larger than '{d}' bits", .{int_bits});
            };

            const op = try operand.to_local(func, ty);

            try func.emit_wvalue(op);
            switch (wasm_bits) {
                32 => {
                    if (wasm_bits != int_bits) {
                        try func.add_imm32(wasm_bits - int_bits);
                        try func.add_tag(.i32_shl);
                    }
                    try func.add_imm32(31);
                    try func.add_tag(.i32_shr_s);

                    const tmp = try func.alloc_local(ty);
                    try func.add_label(.local_tee, tmp.local.value);

                    try func.emit_wvalue(op);
                    try func.add_tag(.i32_xor);
                    try func.emit_wvalue(tmp);
                    try func.add_tag(.i32_sub);

                    if (int_bits != wasm_bits) {
                        try func.emit_wvalue(WValue{ .imm32 = (@as(u32, 1) << @int_cast(int_bits)) - 1 });
                        try func.add_tag(.i32_and);
                    }
                },
                64 => {
                    if (wasm_bits != int_bits) {
                        try func.add_imm64(wasm_bits - int_bits);
                        try func.add_tag(.i64_shl);
                    }
                    try func.add_imm64(63);
                    try func.add_tag(.i64_shr_s);

                    const tmp = try func.alloc_local(ty);
                    try func.add_label(.local_tee, tmp.local.value);

                    try func.emit_wvalue(op);
                    try func.add_tag(.i64_xor);
                    try func.emit_wvalue(tmp);
                    try func.add_tag(.i64_sub);

                    if (int_bits != wasm_bits) {
                        try func.emit_wvalue(WValue{ .imm64 = (@as(u64, 1) << @int_cast(int_bits)) - 1 });
                        try func.add_tag(.i64_and);
                    }
                },
                else => return func.fail("TODO: Implement air_abs for {}", .{ty.fmt(mod)}),
            }

            const result = try (WValue{ .stack = {} }).to_local(func, ty);
            func.finish_air(inst, result, &.{ty_op.operand});
        },
        .Float => {
            const result = try (try func.float_op(.fabs, ty, &.{operand})).to_local(func, ty);
            func.finish_air(inst, result, &.{ty_op.operand});
        },
        else => unreachable,
    }
}

fn air_unary_float_op(func: *CodeGen, inst: Air.Inst.Index, op: FloatOp) InnerError!void {
    const un_op = func.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const operand = try func.resolve_inst(un_op);
    const ty = func.type_of(un_op);

    const result = try (try func.float_op(op, ty, &.{operand})).to_local(func, ty);
    func.finish_air(inst, result, &.{un_op});
}

fn float_op(func: *CodeGen, float_op: FloatOp, ty: Type, args: []const WValue) InnerError!WValue {
    const mod = func.bin_file.base.comp.module.?;
    if (ty.zig_type_tag(mod) == .Vector) {
        return func.fail("TODO: Implement floatOps for vectors", .{});
    }

    const float_bits = ty.float_bits(func.target);

    if (float_op == .neg) {
        return func.float_neg(ty, args[0]);
    }

    if (float_bits == 32 or float_bits == 64) {
        if (float_op.to_op()) |op| {
            for (args) |operand| {
                try func.emit_wvalue(operand);
            }
            const opcode = build_opcode(.{ .op = op, .valtype1 = type_to_valtype(ty, mod) });
            try func.add_tag(Mir.Inst.Tag.from_opcode(opcode));
            return .stack;
        }
    }

    var fn_name_buf: [64]u8 = undefined;
    const fn_name = switch (float_op) {
        .add,
        .sub,
        .div,
        .mul,
        => std.fmt.buf_print(&fn_name_buf, "__{s}{s}f3", .{
            @tag_name(float_op), target_util.compiler_rt_float_abbrev(float_bits),
        }) catch unreachable,

        .ceil,
        .cos,
        .exp,
        .exp2,
        .fabs,
        .floor,
        .fma,
        .fmax,
        .fmin,
        .fmod,
        .log,
        .log10,
        .log2,
        .round,
        .sin,
        .sqrt,
        .tan,
        .trunc,
        => std.fmt.buf_print(&fn_name_buf, "{s}{s}{s}", .{
            target_util.libc_float_prefix(float_bits), @tag_name(float_op), target_util.libc_float_suffix(float_bits),
        }) catch unreachable,
        .neg => unreachable, // handled above
    };

    // fma requires three operands
    var param_types_buffer: [3]InternPool.Index = .{ ty.ip_index, ty.ip_index, ty.ip_index };
    const param_types = param_types_buffer[0..args.len];
    return func.call_intrinsic(fn_name, param_types, ty, args);
}

/// NOTE: The result value remains on top of the stack.
fn float_neg(func: *CodeGen, ty: Type, arg: WValue) InnerError!WValue {
    const float_bits = ty.float_bits(func.target);
    switch (float_bits) {
        16 => {
            try func.emit_wvalue(arg);
            try func.add_imm32(std.math.min_int(i16));
            try func.add_tag(.i32_xor);
            return .stack;
        },
        32, 64 => {
            try func.emit_wvalue(arg);
            const val_type: wasm.Valtype = if (float_bits == 32) .f32 else .f64;
            const opcode = build_opcode(.{ .op = .neg, .valtype1 = val_type });
            try func.add_tag(Mir.Inst.Tag.from_opcode(opcode));
            return .stack;
        },
        80, 128 => {
            const result = try func.alloc_stack(ty);
            try func.emit_wvalue(result);
            try func.emit_wvalue(arg);
            try func.add_mem_arg(.i64_load, .{ .offset = 0 + arg.offset(), .alignment = 2 });
            try func.add_mem_arg(.i64_store, .{ .offset = 0 + result.offset(), .alignment = 2 });

            try func.emit_wvalue(result);
            try func.emit_wvalue(arg);
            try func.add_mem_arg(.i64_load, .{ .offset = 8 + arg.offset(), .alignment = 2 });

            if (float_bits == 80) {
                try func.add_imm64(0x8000);
                try func.add_tag(.i64_xor);
                try func.add_mem_arg(.i64_store16, .{ .offset = 8 + result.offset(), .alignment = 2 });
            } else {
                try func.add_imm64(0x8000000000000000);
                try func.add_tag(.i64_xor);
                try func.add_mem_arg(.i64_store, .{ .offset = 8 + result.offset(), .alignment = 2 });
            }
            return result;
        },
        else => unreachable,
    }
}

fn air_wrap_bin_op(func: *CodeGen, inst: Air.Inst.Index, op: Op) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const bin_op = func.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;

    const lhs = try func.resolve_inst(bin_op.lhs);
    const rhs = try func.resolve_inst(bin_op.rhs);
    const lhs_ty = func.type_of(bin_op.lhs);
    const rhs_ty = func.type_of(bin_op.rhs);

    if (lhs_ty.zig_type_tag(mod) == .Vector or rhs_ty.zig_type_tag(mod) == .Vector) {
        return func.fail("TODO: Implement wrapping arithmetic for vectors", .{});
    }

    // For certain operations, such as shifting, the types are different.
    // When converting this to a WebAssembly type, they *must* match to perform
    // an operation. For this reason we verify if the WebAssembly type is different, in which
    // case we first coerce the operands to the same type before performing the operation.
    // For big integers we can ignore this as we will call into compiler-rt which handles this.
    const result = switch (op) {
        .shr, .shl => res: {
            const lhs_wasm_bits = to_wasm_bits(@as(u16, @int_cast(lhs_ty.bit_size(mod)))) orelse {
                return func.fail("TODO: implement '{s}' for types larger than 128 bits", .{@tag_name(op)});
            };
            const rhs_wasm_bits = to_wasm_bits(@as(u16, @int_cast(rhs_ty.bit_size(mod)))).?;
            const new_rhs = if (lhs_wasm_bits != rhs_wasm_bits and lhs_wasm_bits != 128) blk: {
                const tmp = try func.intcast(rhs, rhs_ty, lhs_ty);
                break :blk try tmp.to_local(func, lhs_ty);
            } else rhs;
            const stack_result = try func.wrap_bin_op(lhs, new_rhs, lhs_ty, op);
            break :res try stack_result.to_local(func, lhs_ty);
        },
        else => res: {
            const stack_result = try func.wrap_bin_op(lhs, rhs, lhs_ty, op);
            break :res try stack_result.to_local(func, lhs_ty);
        },
    };

    return func.finish_air(inst, result, &.{ bin_op.lhs, bin_op.rhs });
}

/// Performs a wrapping binary operation.
/// Asserts rhs is not a stack value when lhs also isn't.
/// NOTE: Leaves the result on the stack when its Type is <= 64 bits
fn wrap_bin_op(func: *CodeGen, lhs: WValue, rhs: WValue, ty: Type, op: Op) InnerError!WValue {
    const bin_local = try func.bin_op(lhs, rhs, ty, op);
    return func.wrap_operand(bin_local, ty);
}

/// Wraps an operand based on a given type's bitsize.
/// Asserts `Type` is <= 128 bits.
/// NOTE: When the Type is <= 64 bits, leaves the value on top of the stack.
fn wrap_operand(func: *CodeGen, operand: WValue, ty: Type) InnerError!WValue {
    const mod = func.bin_file.base.comp.module.?;
    assert(ty.abi_size(mod) <= 16);
    const bitsize = @as(u16, @int_cast(ty.bit_size(mod)));
    const wasm_bits = to_wasm_bits(bitsize) orelse {
        return func.fail("TODO: Implement wrap_operand for bitsize '{d}'", .{bitsize});
    };

    if (wasm_bits == bitsize) return operand;

    if (wasm_bits == 128) {
        assert(operand != .stack);
        const lsb = try func.load(operand, Type.u64, 8);

        const result_ptr = try func.alloc_stack(ty);
        try func.emit_wvalue(result_ptr);
        try func.store(.{ .stack = {} }, lsb, Type.u64, 8 + result_ptr.offset());
        const result = (@as(u64, 1) << @as(u6, @int_cast(64 - (wasm_bits - bitsize)))) - 1;
        try func.emit_wvalue(result_ptr);
        _ = try func.load(operand, Type.u64, 0);
        try func.add_imm64(result);
        try func.add_tag(.i64_and);
        try func.add_mem_arg(.i64_store, .{ .offset = result_ptr.offset(), .alignment = 8 });
        return result_ptr;
    }

    const result = (@as(u64, 1) << @as(u6, @int_cast(bitsize))) - 1;
    try func.emit_wvalue(operand);
    if (bitsize <= 32) {
        try func.add_imm32(@as(i32, @bit_cast(@as(u32, @int_cast(result)))));
        try func.add_tag(.i32_and);
    } else if (bitsize <= 64) {
        try func.add_imm64(result);
        try func.add_tag(.i64_and);
    } else unreachable;

    return WValue{ .stack = {} };
}

fn lower_ptr(func: *CodeGen, ptr_val: InternPool.Index, prev_offset: u64) InnerError!WValue {
    const zcu = func.bin_file.base.comp.module.?;
    const ptr = zcu.intern_pool.index_to_key(ptr_val).ptr;
    const offset: u64 = prev_offset + ptr.byte_offset;
    return switch (ptr.base_addr) {
        .decl => |decl| return func.lower_decl_ref_value(decl, @int_cast(offset)),
        .anon_decl => |ad| return func.lower_anon_decl_ref(ad, @int_cast(offset)),
        .int => return func.lower_constant(try zcu.int_value(Type.usize, offset), Type.usize),
        .eu_payload => return func.fail("Wasm TODO: lower error union payload pointer", .{}),
        .opt_payload => |opt_ptr| return func.lower_ptr(opt_ptr, offset),
        .field => |field| {
            const base_ptr = Value.from_interned(field.base);
            const base_ty = base_ptr.type_of(zcu).child_type(zcu);
            const field_off: u64 = switch (base_ty.zig_type_tag(zcu)) {
                .Pointer => off: {
                    assert(base_ty.is_slice(zcu));
                    break :off switch (field.index) {
                        Value.slice_ptr_index => 0,
                        Value.slice_len_index => @div_exact(zcu.get_target().ptr_bit_width(), 8),
                        else => unreachable,
                    };
                },
                .Struct => switch (base_ty.container_layout(zcu)) {
                    .auto => base_ty.struct_field_offset(@int_cast(field.index), zcu),
                    .@"extern", .@"packed" => unreachable,
                },
                .Union => switch (base_ty.container_layout(zcu)) {
                    .auto => off: {
                        // Keep in sync with the `un` case of `generate_symbol`.
                        const layout = base_ty.union_get_layout(zcu);
                        if (layout.payload_size == 0) break :off 0;
                        if (layout.tag_size == 0) break :off 0;
                        if (layout.tag_align.compare(.gte, layout.payload_align)) {
                            // Tag first.
                            break :off layout.tag_size;
                        } else {
                            // Payload first.
                            break :off 0;
                        }
                    },
                    .@"extern", .@"packed" => unreachable,
                },
                else => unreachable,
            };
            return func.lower_ptr(field.base, offset + field_off);
        },
        .arr_elem, .comptime_field, .comptime_alloc => unreachable,
    };
}

fn lower_anon_decl_ref(
    func: *CodeGen,
    anon_decl: InternPool.Key.Ptr.BaseAddr.AnonDecl,
    offset: u32,
) InnerError!WValue {
    const mod = func.bin_file.base.comp.module.?;
    const decl_val = anon_decl.val;
    const ty = Type.from_interned(mod.intern_pool.type_of(decl_val));

    const is_fn_body = ty.zig_type_tag(mod) == .Fn;
    if (!is_fn_body and !ty.has_runtime_bits_ignore_comptime(mod)) {
        return WValue{ .imm32 = 0xaaaaaaaa };
    }

    const decl_align = mod.intern_pool.index_to_key(anon_decl.orig_ty).ptr_type.flags.alignment;
    const res = try func.bin_file.lower_anon_decl(decl_val, decl_align, func.decl.src_loc(mod));
    switch (res) {
        .ok => {},
        .fail => |em| {
            func.err_msg = em;
            return error.CodegenFail;
        },
    }
    const target_atom_index = func.bin_file.zig_object_ptr().?.anon_decls.get(decl_val).?;
    const target_sym_index = @int_from_enum(func.bin_file.get_atom(target_atom_index).sym_index);
    if (is_fn_body) {
        return WValue{ .function_index = target_sym_index };
    } else if (offset == 0) {
        return WValue{ .memory = target_sym_index };
    } else return WValue{ .memory_offset = .{ .pointer = target_sym_index, .offset = offset } };
}

fn lower_decl_ref_value(func: *CodeGen, decl_index: InternPool.DeclIndex, offset: u32) InnerError!WValue {
    const mod = func.bin_file.base.comp.module.?;

    const decl = mod.decl_ptr(decl_index);
    // check if decl is an alias to a function, in which case we
    // want to lower the actual decl, rather than the alias itself.
    if (decl.val.get_function(mod)) |func_val| {
        if (func_val.owner_decl != decl_index) {
            return func.lower_decl_ref_value(func_val.owner_decl, offset);
        }
    } else if (decl.val.get_extern_func(mod)) |func_val| {
        if (func_val.decl != decl_index) {
            return func.lower_decl_ref_value(func_val.decl, offset);
        }
    }
    const decl_ty = decl.type_of(mod);
    if (decl_ty.zig_type_tag(mod) != .Fn and !decl_ty.has_runtime_bits_ignore_comptime(mod)) {
        return WValue{ .imm32 = 0xaaaaaaaa };
    }

    const atom_index = try func.bin_file.get_or_create_atom_for_decl(decl_index);
    const atom = func.bin_file.get_atom(atom_index);

    const target_sym_index = @int_from_enum(atom.sym_index);
    if (decl_ty.zig_type_tag(mod) == .Fn) {
        return WValue{ .function_index = target_sym_index };
    } else if (offset == 0) {
        return WValue{ .memory = target_sym_index };
    } else return WValue{ .memory_offset = .{ .pointer = target_sym_index, .offset = offset } };
}

/// Converts a signed integer to its 2's complement form and returns
/// an unsigned integer instead.
/// Asserts bitsize <= 64
fn to_twos_complement(value: anytype, bits: u7) std.meta.Int(.unsigned, @typeInfo(@TypeOf(value)).Int.bits) {
    const T = @TypeOf(value);
    comptime assert(@typeInfo(T) == .Int);
    comptime assert(@typeInfo(T).Int.signedness == .signed);
    assert(bits <= 64);
    const WantedT = std.meta.Int(.unsigned, @typeInfo(T).Int.bits);
    if (value >= 0) return @as(WantedT, @bit_cast(value));
    const max_value = @as(u64, @int_cast((@as(u65, 1) << bits) - 1));
    const flipped = @as(T, @int_cast((~-@as(i65, value)) + 1));
    const result = @as(WantedT, @bit_cast(flipped)) & max_value;
    return @as(WantedT, @int_cast(result));
}

/// This function is intended to assert that `is_by_ref` returns `false` for `ty`.
/// However such an assertion fails on the behavior tests currently.
fn lower_constant(func: *CodeGen, val: Value, ty: Type) InnerError!WValue {
    const mod = func.bin_file.base.comp.module.?;
    // TODO: enable this assertion
    //assert(!is_by_ref(ty, mod));
    const ip = &mod.intern_pool;
    if (val.is_undef_deep(mod)) return func.emit_undefined(ty);

    switch (ip.index_to_key(val.ip_index)) {
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
        => unreachable, // types, not values

        .undef => unreachable, // handled above
        .simple_value => |simple_value| switch (simple_value) {
            .undefined,
            .void,
            .null,
            .empty_struct,
            .@"unreachable",
            .generic_poison,
            => unreachable, // non-runtime values
            .false, .true => return WValue{ .imm32 = switch (simple_value) {
                .false => 0,
                .true => 1,
                else => unreachable,
            } },
        },
        .variable,
        .extern_func,
        .func,
        .enum_literal,
        .empty_enum_value,
        => unreachable, // non-runtime values
        .int => {
            const int_info = ty.int_info(mod);
            switch (int_info.signedness) {
                .signed => switch (int_info.bits) {
                    0...32 => return WValue{ .imm32 = @as(u32, @int_cast(to_twos_complement(
                        val.to_signed_int(mod),
                        @as(u6, @int_cast(int_info.bits)),
                    ))) },
                    33...64 => return WValue{ .imm64 = to_twos_complement(
                        val.to_signed_int(mod),
                        @as(u7, @int_cast(int_info.bits)),
                    ) },
                    else => unreachable,
                },
                .unsigned => switch (int_info.bits) {
                    0...32 => return WValue{ .imm32 = @as(u32, @int_cast(val.to_unsigned_int(mod))) },
                    33...64 => return WValue{ .imm64 = val.to_unsigned_int(mod) },
                    else => unreachable,
                },
            }
        },
        .err => |err| {
            const int = try mod.get_error_value(err.name);
            return WValue{ .imm32 = int };
        },
        .error_union => |error_union| {
            const err_int_ty = try mod.error_int_type();
            const err_ty, const err_val = switch (error_union.val) {
                .err_name => |err_name| .{
                    ty.error_union_set(mod),
                    Value.from_interned((try mod.intern(.{ .err = .{
                        .ty = ty.error_union_set(mod).to_intern(),
                        .name = err_name,
                    } }))),
                },
                .payload => .{
                    err_int_ty,
                    try mod.int_value(err_int_ty, 0),
                },
            };
            const payload_type = ty.error_union_payload(mod);
            if (!payload_type.has_runtime_bits_ignore_comptime(mod)) {
                // We use the error type directly as the type.
                return func.lower_constant(err_val, err_ty);
            }

            return func.fail("Wasm TODO: lower_constant error union with non-zero-bit payload type", .{});
        },
        .enum_tag => |enum_tag| {
            const int_tag_ty = ip.type_of(enum_tag.int);
            return func.lower_constant(Value.from_interned(enum_tag.int), Type.from_interned(int_tag_ty));
        },
        .float => |float| switch (float.storage) {
            .f16 => |f16_val| return WValue{ .imm32 = @as(u16, @bit_cast(f16_val)) },
            .f32 => |f32_val| return WValue{ .float32 = f32_val },
            .f64 => |f64_val| return WValue{ .float64 = f64_val },
            else => unreachable,
        },
        .slice => |slice| {
            var ptr = ip.index_to_key(slice.ptr).ptr;
            const owner_decl = while (true) switch (ptr.base_addr) {
                .decl => |decl| break decl,
                .int, .anon_decl => return func.fail("Wasm TODO: lower slice where ptr is not owned by decl", .{}),
                .opt_payload, .eu_payload => |base| ptr = ip.index_to_key(base).ptr,
                .field => |base_index| ptr = ip.index_to_key(base_index.base).ptr,
                .arr_elem, .comptime_field, .comptime_alloc => unreachable,
            };
            return .{ .memory = try func.bin_file.lower_unnamed_const(val, owner_decl) };
        },
        .ptr => return func.lower_ptr(val.to_intern(), 0),
        .opt => if (ty.optional_repr_is_payload(mod)) {
            const pl_ty = ty.optional_child(mod);
            if (val.optional_value(mod)) |payload| {
                return func.lower_constant(payload, pl_ty);
            } else {
                return WValue{ .imm32 = 0 };
            }
        } else {
            return WValue{ .imm32 = @int_from_bool(!val.is_null(mod)) };
        },
        .aggregate => switch (ip.index_to_key(ty.ip_index)) {
            .array_type => return func.fail("Wasm TODO: LowerConstant for {}", .{ty.fmt(mod)}),
            .vector_type => {
                assert(determine_simd_store_strategy(ty, mod) == .direct);
                var buf: [16]u8 = undefined;
                val.write_to_memory(ty, mod, &buf) catch unreachable;
                return func.store_simd_immd(buf);
            },
            .struct_type => {
                const struct_type = ip.load_struct_type(ty.to_intern());
                // non-packed structs are not handled in this function because they
                // are by-ref types.
                assert(struct_type.layout == .@"packed");
                var buf: [8]u8 = .{0} ** 8; // zero the buffer so we do not read 0xaa as integer
                val.write_to_packed_memory(ty, mod, &buf, 0) catch unreachable;
                const backing_int_ty = Type.from_interned(struct_type.backing_int_type(ip).*);
                const int_val = try mod.int_value(
                    backing_int_ty,
                    mem.read_int(u64, &buf, .little),
                );
                return func.lower_constant(int_val, backing_int_ty);
            },
            else => unreachable,
        },
        .un => |un| {
            // in this case we have a packed union which will not be passed by reference.
            const constant_ty = if (un.tag == .none)
                try ty.union_backing_type(mod)
            else field_ty: {
                const union_obj = mod.type_to_union(ty).?;
                const field_index = mod.union_tag_field_index(union_obj, Value.from_interned(un.tag)).?;
                break :field_ty Type.from_interned(union_obj.field_types.get(ip)[field_index]);
            };
            return func.lower_constant(Value.from_interned(un.val), constant_ty);
        },
        .memoized_call => unreachable,
    }
}

/// Stores the value as a 128bit-immediate value by storing it inside
/// the list and returning the index into this list as `WValue`.
fn store_simd_immd(func: *CodeGen, value: [16]u8) !WValue {
    const index = @as(u32, @int_cast(func.simd_immediates.items.len));
    try func.simd_immediates.append(func.gpa, value);
    return WValue{ .imm128 = index };
}

fn emit_undefined(func: *CodeGen, ty: Type) InnerError!WValue {
    const mod = func.bin_file.base.comp.module.?;
    const ip = &mod.intern_pool;
    switch (ty.zig_type_tag(mod)) {
        .Bool, .ErrorSet => return WValue{ .imm32 = 0xaaaaaaaa },
        .Int, .Enum => switch (ty.int_info(mod).bits) {
            0...32 => return WValue{ .imm32 = 0xaaaaaaaa },
            33...64 => return WValue{ .imm64 = 0xaaaaaaaaaaaaaaaa },
            else => unreachable,
        },
        .Float => switch (ty.float_bits(func.target)) {
            16 => return WValue{ .imm32 = 0xaaaaaaaa },
            32 => return WValue{ .float32 = @as(f32, @bit_cast(@as(u32, 0xaaaaaaaa))) },
            64 => return WValue{ .float64 = @as(f64, @bit_cast(@as(u64, 0xaaaaaaaaaaaaaaaa))) },
            else => unreachable,
        },
        .Pointer => switch (func.arch()) {
            .wasm32 => return WValue{ .imm32 = 0xaaaaaaaa },
            .wasm64 => return WValue{ .imm64 = 0xaaaaaaaaaaaaaaaa },
            else => unreachable,
        },
        .Optional => {
            const pl_ty = ty.optional_child(mod);
            if (ty.optional_repr_is_payload(mod)) {
                return func.emit_undefined(pl_ty);
            }
            return WValue{ .imm32 = 0xaaaaaaaa };
        },
        .ErrorUnion => {
            return WValue{ .imm32 = 0xaaaaaaaa };
        },
        .Struct => {
            const packed_struct = mod.type_to_packed_struct(ty).?;
            return func.emit_undefined(Type.from_interned(packed_struct.backing_int_type(ip).*));
        },
        else => return func.fail("Wasm TODO: emit_undefined for type: {}\n", .{ty.zig_type_tag(mod)}),
    }
}

/// Returns a `Value` as a signed 32 bit value.
/// It's illegal to provide a value with a type that cannot be represented
/// as an integer value.
fn value_as_i32(func: *const CodeGen, val: Value, ty: Type) i32 {
    const mod = func.bin_file.base.comp.module.?;

    switch (val.ip_index) {
        .none => {},
        .bool_true => return 1,
        .bool_false => return 0,
        else => return switch (mod.intern_pool.index_to_key(val.ip_index)) {
            .enum_tag => |enum_tag| int_index_as_i32(&mod.intern_pool, enum_tag.int, mod),
            .int => |int| int_storage_as_i32(int.storage, mod),
            .ptr => |ptr| {
                assert(ptr.base_addr == .int);
                return @int_cast(ptr.byte_offset);
            },
            .err => |err| @as(i32, @bit_cast(@as(Module.ErrorInt, @int_cast(mod.global_error_set.get_index(err.name).?)))),
            else => unreachable,
        },
    }

    return switch (ty.zig_type_tag(mod)) {
        .ErrorSet => @as(i32, @bit_cast(val.get_error_int(mod))),
        else => unreachable, // Programmer called this function for an illegal type
    };
}

fn int_index_as_i32(ip: *const InternPool, int: InternPool.Index, mod: *Module) i32 {
    return int_storage_as_i32(ip.index_to_key(int).int.storage, mod);
}

fn int_storage_as_i32(storage: InternPool.Key.Int.Storage, mod: *Module) i32 {
    return switch (storage) {
        .i64 => |x| @as(i32, @int_cast(x)),
        .u64 => |x| @as(i32, @bit_cast(@as(u32, @int_cast(x)))),
        .big_int => unreachable,
        .lazy_align => |ty| @as(i32, @bit_cast(@as(u32, @int_cast(Type.from_interned(ty).abi_alignment(mod).to_byte_units() orelse 0)))),
        .lazy_size => |ty| @as(i32, @bit_cast(@as(u32, @int_cast(Type.from_interned(ty).abi_size(mod))))),
    };
}

fn air_block(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const ty_pl = func.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = func.air.extra_data(Air.Block, ty_pl.payload);
    try func.lower_block(inst, ty_pl.ty.to_type(), @ptr_cast(func.air.extra[extra.end..][0..extra.data.body_len]));
}

fn lower_block(func: *CodeGen, inst: Air.Inst.Index, block_ty: Type, body: []const Air.Inst.Index) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const wasm_block_ty = gen_block_type(block_ty, mod);

    // if wasm_block_ty is non-empty, we create a register to store the temporary value
    const block_result: WValue = if (wasm_block_ty != wasm.block_empty) blk: {
        const ty: Type = if (is_by_ref(block_ty, mod)) Type.u32 else block_ty;
        break :blk try func.ensure_alloc_local(ty); // make sure it's a clean local as it may never get overwritten
    } else WValue.none;

    try func.start_block(.block, wasm.block_empty);
    // Here we set the current block idx, so breaks know the depth to jump
    // to when breaking out.
    try func.blocks.put_no_clobber(func.gpa, inst, .{
        .label = func.block_depth,
        .value = block_result,
    });

    try func.gen_body(body);
    try func.end_block();

    const liveness = func.liveness.get_block(inst);
    try func.current_branch().values.ensure_unused_capacity(func.gpa, liveness.deaths.len);

    func.finish_air(inst, block_result, &.{});
}

/// appends a new wasm block to the code section and increases the `block_depth` by 1
fn start_block(func: *CodeGen, block_tag: wasm.Opcode, valtype: u8) !void {
    func.block_depth += 1;
    try func.add_inst(.{
        .tag = Mir.Inst.Tag.from_opcode(block_tag),
        .data = .{ .block_type = valtype },
    });
}

/// Ends the current wasm block and decreases the `block_depth` by 1
fn end_block(func: *CodeGen) !void {
    try func.add_tag(.end);
    func.block_depth -= 1;
}

fn air_loop(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const ty_pl = func.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const loop = func.air.extra_data(Air.Block, ty_pl.payload);
    const body: []const Air.Inst.Index = @ptr_cast(func.air.extra[loop.end..][0..loop.data.body_len]);

    // result type of loop is always 'noreturn', meaning we can always
    // emit the wasm type 'block_empty'.
    try func.start_block(.loop, wasm.block_empty);
    try func.gen_body(body);

    // breaking to the index of a loop block will continue the loop instead
    try func.add_label(.br, 0);
    try func.end_block();

    func.finish_air(inst, .none, &.{});
}

fn air_cond_br(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const pl_op = func.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
    const condition = try func.resolve_inst(pl_op.operand);
    const extra = func.air.extra_data(Air.CondBr, pl_op.payload);
    const then_body: []const Air.Inst.Index = @ptr_cast(func.air.extra[extra.end..][0..extra.data.then_body_len]);
    const else_body: []const Air.Inst.Index = @ptr_cast(func.air.extra[extra.end + then_body.len ..][0..extra.data.else_body_len]);
    const liveness_condbr = func.liveness.get_cond_br(inst);

    // result type is always noreturn, so use `block_empty` as type.
    try func.start_block(.block, wasm.block_empty);
    // emit the conditional value
    try func.emit_wvalue(condition);

    // we inserted the block in front of the condition
    // so now check if condition matches. If not, break outside this block
    // and continue with the then codepath
    try func.add_label(.br_if, 0);

    try func.branches.ensure_unused_capacity(func.gpa, 2);
    {
        func.branches.append_assume_capacity(.{});
        try func.current_branch().values.ensure_unused_capacity(func.gpa, @as(u32, @int_cast(liveness_condbr.else_deaths.len)));
        defer {
            var else_stack = func.branches.pop();
            else_stack.deinit(func.gpa);
        }
        try func.gen_body(else_body);
        try func.end_block();
    }

    // Outer block that matches the condition
    {
        func.branches.append_assume_capacity(.{});
        try func.current_branch().values.ensure_unused_capacity(func.gpa, @as(u32, @int_cast(liveness_condbr.then_deaths.len)));
        defer {
            var then_stack = func.branches.pop();
            then_stack.deinit(func.gpa);
        }
        try func.gen_body(then_body);
    }

    func.finish_air(inst, .none, &.{});
}

fn air_cmp(func: *CodeGen, inst: Air.Inst.Index, op: std.math.CompareOperator) InnerError!void {
    const bin_op = func.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;

    const lhs = try func.resolve_inst(bin_op.lhs);
    const rhs = try func.resolve_inst(bin_op.rhs);
    const operand_ty = func.type_of(bin_op.lhs);
    const result = try (try func.cmp(lhs, rhs, operand_ty, op)).to_local(func, Type.u32); // comparison result is always 32 bits
    func.finish_air(inst, result, &.{ bin_op.lhs, bin_op.rhs });
}

/// Compares two operands.
/// Asserts rhs is not a stack value when the lhs isn't a stack value either
/// NOTE: This leaves the result on top of the stack, rather than a new local.
fn cmp(func: *CodeGen, lhs: WValue, rhs: WValue, ty: Type, op: std.math.CompareOperator) InnerError!WValue {
    assert(!(lhs != .stack and rhs == .stack));
    const mod = func.bin_file.base.comp.module.?;
    if (ty.zig_type_tag(mod) == .Optional and !ty.optional_repr_is_payload(mod)) {
        const payload_ty = ty.optional_child(mod);
        if (payload_ty.has_runtime_bits_ignore_comptime(mod)) {
            // When we hit this case, we must check the value of optionals
            // that are not pointers. This means first checking against non-null for
            // both lhs and rhs, as well as checking the payload are matching of lhs and rhs
            return func.cmp_optionals(lhs, rhs, ty, op);
        }
    } else if (ty.is_any_float()) {
        return func.cmp_float(ty, lhs, rhs, op);
    } else if (is_by_ref(ty, mod)) {
        return func.cmp_big_int(lhs, rhs, ty, op);
    }

    const signedness: std.builtin.Signedness = blk: {
        // by default we tell the operand type is unsigned (i.e. bools and enum values)
        if (ty.zig_type_tag(mod) != .Int) break :blk .unsigned;

        // incase of an actual integer, we emit the correct signedness
        break :blk ty.int_info(mod).signedness;
    };
    const extend_sign = blk: {
        // do we need to extend the sign bit?
        if (signedness != .signed) break :blk false;
        if (op == .eq or op == .neq) break :blk false;
        const int_bits = ty.int_info(mod).bits;
        const wasm_bits = to_wasm_bits(int_bits) orelse unreachable;
        break :blk (wasm_bits != int_bits);
    };

    const lhs_wasm = if (extend_sign)
        try func.sign_extend_int(lhs, ty)
    else
        lhs;

    const rhs_wasm = if (extend_sign)
        try func.sign_extend_int(rhs, ty)
    else
        rhs;

    // ensure that when we compare pointers, we emit
    // the true pointer of a stack value, rather than the stack pointer.
    try func.lower_to_stack(lhs_wasm);
    try func.lower_to_stack(rhs_wasm);

    const opcode: wasm.Opcode = build_opcode(.{
        .valtype1 = type_to_valtype(ty, mod),
        .op = switch (op) {
            .lt => .lt,
            .lte => .le,
            .eq => .eq,
            .neq => .ne,
            .gte => .ge,
            .gt => .gt,
        },
        .signedness = signedness,
    });
    try func.add_tag(Mir.Inst.Tag.from_opcode(opcode));

    return WValue{ .stack = {} };
}

/// Compares two floats.
/// NOTE: Leaves the result of the comparison on top of the stack.
fn cmp_float(func: *CodeGen, ty: Type, lhs: WValue, rhs: WValue, cmp_op: std.math.CompareOperator) InnerError!WValue {
    const float_bits = ty.float_bits(func.target);

    const op: Op = switch (cmp_op) {
        .lt => .lt,
        .lte => .le,
        .eq => .eq,
        .neq => .ne,
        .gte => .ge,
        .gt => .gt,
    };

    switch (float_bits) {
        16 => {
            _ = try func.fpext(lhs, Type.f16, Type.f32);
            _ = try func.fpext(rhs, Type.f16, Type.f32);
            const opcode = build_opcode(.{ .op = op, .valtype1 = .f32 });
            try func.add_tag(Mir.Inst.Tag.from_opcode(opcode));
            return .stack;
        },
        32, 64 => {
            try func.emit_wvalue(lhs);
            try func.emit_wvalue(rhs);
            const val_type: wasm.Valtype = if (float_bits == 32) .f32 else .f64;
            const opcode = build_opcode(.{ .op = op, .valtype1 = val_type });
            try func.add_tag(Mir.Inst.Tag.from_opcode(opcode));
            return .stack;
        },
        80, 128 => {
            var fn_name_buf: [32]u8 = undefined;
            const fn_name = std.fmt.buf_print(&fn_name_buf, "__{s}{s}f2", .{
                @tag_name(op), target_util.compiler_rt_float_abbrev(float_bits),
            }) catch unreachable;

            const result = try func.call_intrinsic(fn_name, &.{ ty.ip_index, ty.ip_index }, Type.bool, &.{ lhs, rhs });
            return func.cmp(result, WValue{ .imm32 = 0 }, Type.i32, cmp_op);
        },
        else => unreachable,
    }
}

fn air_cmp_vector(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    _ = inst;
    return func.fail("TODO implement air_cmp_vector for wasm", .{});
}

fn air_cmp_lt_errors_len(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const un_op = func.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const operand = try func.resolve_inst(un_op);
    const sym_index = try func.bin_file.get_global_symbol("__zig_errors_len", null);
    const errors_len = WValue{ .memory = @int_from_enum(sym_index) };

    try func.emit_wvalue(operand);
    const mod = func.bin_file.base.comp.module.?;
    const err_int_ty = try mod.error_int_type();
    const errors_len_val = try func.load(errors_len, err_int_ty, 0);
    const result = try func.cmp(.stack, errors_len_val, err_int_ty, .lt);

    return func.finish_air(inst, try result.to_local(func, Type.bool), &.{un_op});
}

fn air_br(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const br = func.air.instructions.items(.data)[@int_from_enum(inst)].br;
    const block = func.blocks.get(br.block_inst).?;

    // if operand has codegen bits we should break with a value
    if (func.type_of(br.operand).has_runtime_bits_ignore_comptime(mod)) {
        const operand = try func.resolve_inst(br.operand);
        try func.lower_to_stack(operand);

        if (block.value != .none) {
            try func.add_label(.local_set, block.value.local.value);
        }
    }

    // We map every block to its block index.
    // We then determine how far we have to jump to it by subtracting it from current block depth
    const idx: u32 = func.block_depth - block.label;
    try func.add_label(.br, idx);

    func.finish_air(inst, .none, &.{br.operand});
}

fn air_not(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const ty_op = func.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

    const operand = try func.resolve_inst(ty_op.operand);
    const operand_ty = func.type_of(ty_op.operand);
    const mod = func.bin_file.base.comp.module.?;

    const result = result: {
        if (operand_ty.zig_type_tag(mod) == .Bool) {
            try func.emit_wvalue(operand);
            try func.add_tag(.i32_eqz);
            const not_tmp = try func.alloc_local(operand_ty);
            try func.add_label(.local_set, not_tmp.local.value);
            break :result not_tmp;
        } else {
            const operand_bits = operand_ty.int_info(mod).bits;
            const wasm_bits = to_wasm_bits(operand_bits) orelse {
                return func.fail("TODO: Implement binary NOT for integer with bitsize '{d}'", .{operand_bits});
            };

            switch (wasm_bits) {
                32 => {
                    const bin_op = try func.bin_op(operand, .{ .imm32 = ~@as(u32, 0) }, operand_ty, .xor);
                    break :result try (try func.wrap_operand(bin_op, operand_ty)).to_local(func, operand_ty);
                },
                64 => {
                    const bin_op = try func.bin_op(operand, .{ .imm64 = ~@as(u64, 0) }, operand_ty, .xor);
                    break :result try (try func.wrap_operand(bin_op, operand_ty)).to_local(func, operand_ty);
                },
                128 => {
                    const result_ptr = try func.alloc_stack(operand_ty);
                    try func.emit_wvalue(result_ptr);
                    const msb = try func.load(operand, Type.u64, 0);
                    const msb_xor = try func.bin_op(msb, .{ .imm64 = ~@as(u64, 0) }, Type.u64, .xor);
                    try func.store(.{ .stack = {} }, msb_xor, Type.u64, 0 + result_ptr.offset());

                    try func.emit_wvalue(result_ptr);
                    const lsb = try func.load(operand, Type.u64, 8);
                    const lsb_xor = try func.bin_op(lsb, .{ .imm64 = ~@as(u64, 0) }, Type.u64, .xor);
                    try func.store(result_ptr, lsb_xor, Type.u64, 8 + result_ptr.offset());
                    break :result result_ptr;
                },
                else => unreachable,
            }
        }
    };
    func.finish_air(inst, result, &.{ty_op.operand});
}

fn air_trap(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    try func.add_tag(.@"unreachable");
    func.finish_air(inst, .none, &.{});
}

fn air_breakpoint(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    // unsupported by wasm itfunc. Can be implemented once we support DWARF
    // for wasm
    try func.add_tag(.@"unreachable");
    func.finish_air(inst, .none, &.{});
}

fn air_unreachable(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    try func.add_tag(.@"unreachable");
    func.finish_air(inst, .none, &.{});
}

fn air_bitcast(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const ty_op = func.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result = result: {
        const operand = try func.resolve_inst(ty_op.operand);
        const wanted_ty = func.type_of_index(inst);
        const given_ty = func.type_of(ty_op.operand);
        if (given_ty.is_any_float() or wanted_ty.is_any_float()) {
            const bitcast_result = try func.bitcast(wanted_ty, given_ty, operand);
            break :result try bitcast_result.to_local(func, wanted_ty);
        }
        const mod = func.bin_file.base.comp.module.?;
        if (is_by_ref(given_ty, mod) and !is_by_ref(wanted_ty, mod)) {
            const loaded_memory = try func.load(operand, wanted_ty, 0);
            break :result try loaded_memory.to_local(func, wanted_ty);
        }
        if (!is_by_ref(given_ty, mod) and is_by_ref(wanted_ty, mod)) {
            const stack_memory = try func.alloc_stack(wanted_ty);
            try func.store(stack_memory, operand, given_ty, 0);
            break :result stack_memory;
        }
        break :result func.reuse_operand(ty_op.operand, operand);
    };
    func.finish_air(inst, result, &.{ty_op.operand});
}

fn bitcast(func: *CodeGen, wanted_ty: Type, given_ty: Type, operand: WValue) InnerError!WValue {
    const mod = func.bin_file.base.comp.module.?;
    // if we bitcast a float to or from an integer we must use the 'reinterpret' instruction
    if (!(wanted_ty.is_any_float() or given_ty.is_any_float())) return operand;
    if (wanted_ty.ip_index == .f16_type or given_ty.ip_index == .f16_type) return operand;
    if (wanted_ty.bit_size(mod) > 64) return operand;
    assert((wanted_ty.is_int(mod) and given_ty.is_any_float()) or (wanted_ty.is_any_float() and given_ty.is_int(mod)));

    const opcode = build_opcode(.{
        .op = .reinterpret,
        .valtype1 = type_to_valtype(wanted_ty, mod),
        .valtype2 = type_to_valtype(given_ty, mod),
    });
    try func.emit_wvalue(operand);
    try func.add_tag(Mir.Inst.Tag.from_opcode(opcode));
    return WValue{ .stack = {} };
}

fn air_struct_field_ptr(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const ty_pl = func.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = func.air.extra_data(Air.StructField, ty_pl.payload);

    const struct_ptr = try func.resolve_inst(extra.data.struct_operand);
    const struct_ptr_ty = func.type_of(extra.data.struct_operand);
    const struct_ty = struct_ptr_ty.child_type(mod);
    const result = try func.struct_field_ptr(inst, extra.data.struct_operand, struct_ptr, struct_ptr_ty, struct_ty, extra.data.field_index);
    func.finish_air(inst, result, &.{extra.data.struct_operand});
}

fn air_struct_field_ptr_index(func: *CodeGen, inst: Air.Inst.Index, index: u32) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const ty_op = func.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const struct_ptr = try func.resolve_inst(ty_op.operand);
    const struct_ptr_ty = func.type_of(ty_op.operand);
    const struct_ty = struct_ptr_ty.child_type(mod);

    const result = try func.struct_field_ptr(inst, ty_op.operand, struct_ptr, struct_ptr_ty, struct_ty, index);
    func.finish_air(inst, result, &.{ty_op.operand});
}

fn struct_field_ptr(
    func: *CodeGen,
    inst: Air.Inst.Index,
    ref: Air.Inst.Ref,
    struct_ptr: WValue,
    struct_ptr_ty: Type,
    struct_ty: Type,
    index: u32,
) InnerError!WValue {
    const mod = func.bin_file.base.comp.module.?;
    const result_ty = func.type_of_index(inst);
    const struct_ptr_ty_info = struct_ptr_ty.ptr_info(mod);

    const offset = switch (struct_ty.container_layout(mod)) {
        .@"packed" => switch (struct_ty.zig_type_tag(mod)) {
            .Struct => offset: {
                if (result_ty.ptr_info(mod).packed_offset.host_size != 0) {
                    break :offset @as(u32, 0);
                }
                const struct_type = mod.type_to_struct(struct_ty).?;
                break :offset @div_exact(mod.struct_packed_field_bit_offset(struct_type, index) + struct_ptr_ty_info.packed_offset.bit_offset, 8);
            },
            .Union => 0,
            else => unreachable,
        },
        else => struct_ty.struct_field_offset(index, mod),
    };
    // save a load and store when we can simply reuse the operand
    if (offset == 0) {
        return func.reuse_operand(ref, struct_ptr);
    }
    switch (struct_ptr) {
        .stack_offset => |stack_offset| {
            return WValue{ .stack_offset = .{ .value = stack_offset.value + @as(u32, @int_cast(offset)), .references = 1 } };
        },
        else => return func.build_pointer_offset(struct_ptr, offset, .new),
    }
}

fn air_struct_field_val(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const ip = &mod.intern_pool;
    const ty_pl = func.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const struct_field = func.air.extra_data(Air.StructField, ty_pl.payload).data;

    const struct_ty = func.type_of(struct_field.struct_operand);
    const operand = try func.resolve_inst(struct_field.struct_operand);
    const field_index = struct_field.field_index;
    const field_ty = struct_ty.struct_field_type(field_index, mod);
    if (!field_ty.has_runtime_bits_ignore_comptime(mod)) return func.finish_air(inst, .none, &.{struct_field.struct_operand});

    const result = switch (struct_ty.container_layout(mod)) {
        .@"packed" => switch (struct_ty.zig_type_tag(mod)) {
            .Struct => result: {
                const packed_struct = mod.type_to_packed_struct(struct_ty).?;
                const offset = mod.struct_packed_field_bit_offset(packed_struct, field_index);
                const backing_ty = Type.from_interned(packed_struct.backing_int_type(ip).*);
                const wasm_bits = to_wasm_bits(backing_ty.int_info(mod).bits) orelse {
                    return func.fail("TODO: air_struct_field_val for packed structs larger than 128 bits", .{});
                };
                const const_wvalue = if (wasm_bits == 32)
                    WValue{ .imm32 = offset }
                else if (wasm_bits == 64)
                    WValue{ .imm64 = offset }
                else
                    return func.fail("TODO: air_struct_field_val for packed structs larger than 64 bits", .{});

                // for first field we don't require any shifting
                const shifted_value = if (offset == 0)
                    operand
                else
                    try func.bin_op(operand, const_wvalue, backing_ty, .shr);

                if (field_ty.zig_type_tag(mod) == .Float) {
                    const int_type = try mod.int_type(.unsigned, @as(u16, @int_cast(field_ty.bit_size(mod))));
                    const truncated = try func.trunc(shifted_value, int_type, backing_ty);
                    const bitcasted = try func.bitcast(field_ty, int_type, truncated);
                    break :result try bitcasted.to_local(func, field_ty);
                } else if (field_ty.is_ptr_at_runtime(mod) and packed_struct.field_types.len == 1) {
                    // In this case we do not have to perform any transformations,
                    // we can simply reuse the operand.
                    break :result func.reuse_operand(struct_field.struct_operand, operand);
                } else if (field_ty.is_ptr_at_runtime(mod)) {
                    const int_type = try mod.int_type(.unsigned, @as(u16, @int_cast(field_ty.bit_size(mod))));
                    const truncated = try func.trunc(shifted_value, int_type, backing_ty);
                    break :result try truncated.to_local(func, field_ty);
                }
                const truncated = try func.trunc(shifted_value, field_ty, backing_ty);
                break :result try truncated.to_local(func, field_ty);
            },
            .Union => result: {
                if (is_by_ref(struct_ty, mod)) {
                    if (!is_by_ref(field_ty, mod)) {
                        const val = try func.load(operand, field_ty, 0);
                        break :result try val.to_local(func, field_ty);
                    } else {
                        const new_stack_val = try func.alloc_stack(field_ty);
                        try func.store(new_stack_val, operand, field_ty, 0);
                        break :result new_stack_val;
                    }
                }

                const union_int_type = try mod.int_type(.unsigned, @as(u16, @int_cast(struct_ty.bit_size(mod))));
                if (field_ty.zig_type_tag(mod) == .Float) {
                    const int_type = try mod.int_type(.unsigned, @as(u16, @int_cast(field_ty.bit_size(mod))));
                    const truncated = try func.trunc(operand, int_type, union_int_type);
                    const bitcasted = try func.bitcast(field_ty, int_type, truncated);
                    break :result try bitcasted.to_local(func, field_ty);
                } else if (field_ty.is_ptr_at_runtime(mod)) {
                    const int_type = try mod.int_type(.unsigned, @as(u16, @int_cast(field_ty.bit_size(mod))));
                    const truncated = try func.trunc(operand, int_type, union_int_type);
                    break :result try truncated.to_local(func, field_ty);
                }
                const truncated = try func.trunc(operand, field_ty, union_int_type);
                break :result try truncated.to_local(func, field_ty);
            },
            else => unreachable,
        },
        else => result: {
            const offset = std.math.cast(u32, struct_ty.struct_field_offset(field_index, mod)) orelse {
                return func.fail("Field type '{}' too big to fit into stack frame", .{field_ty.fmt(mod)});
            };
            if (is_by_ref(field_ty, mod)) {
                switch (operand) {
                    .stack_offset => |stack_offset| {
                        break :result WValue{ .stack_offset = .{ .value = stack_offset.value + offset, .references = 1 } };
                    },
                    else => break :result try func.build_pointer_offset(operand, offset, .new),
                }
            }
            const field = try func.load(operand, field_ty, offset);
            break :result try field.to_local(func, field_ty);
        },
    };

    func.finish_air(inst, result, &.{struct_field.struct_operand});
}

fn air_switch_br(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    // result type is always 'noreturn'
    const blocktype = wasm.block_empty;
    const pl_op = func.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
    const target = try func.resolve_inst(pl_op.operand);
    const target_ty = func.type_of(pl_op.operand);
    const switch_br = func.air.extra_data(Air.SwitchBr, pl_op.payload);
    const liveness = try func.liveness.get_switch_br(func.gpa, inst, switch_br.data.cases_len + 1);
    defer func.gpa.free(liveness.deaths);

    var extra_index: usize = switch_br.end;
    var case_i: u32 = 0;

    // a list that maps each value with its value and body based on the order inside the list.
    const CaseValue = struct { integer: i32, value: Value };
    var case_list = try std.ArrayList(struct {
        values: []const CaseValue,
        body: []const Air.Inst.Index,
    }).init_capacity(func.gpa, switch_br.data.cases_len);
    defer for (case_list.items) |case| {
        func.gpa.free(case.values);
    } else case_list.deinit();

    var lowest_maybe: ?i32 = null;
    var highest_maybe: ?i32 = null;
    while (case_i < switch_br.data.cases_len) : (case_i += 1) {
        const case = func.air.extra_data(Air.SwitchBr.Case, extra_index);
        const items: []const Air.Inst.Ref = @ptr_cast(func.air.extra[case.end..][0..case.data.items_len]);
        const case_body: []const Air.Inst.Index = @ptr_cast(func.air.extra[case.end + items.len ..][0..case.data.body_len]);
        extra_index = case.end + items.len + case_body.len;
        const values = try func.gpa.alloc(CaseValue, items.len);
        errdefer func.gpa.free(values);

        for (items, 0..) |ref, i| {
            const item_val = (try func.air.value(ref, mod)).?;
            const int_val = func.value_as_i32(item_val, target_ty);
            if (lowest_maybe == null or int_val < lowest_maybe.?) {
                lowest_maybe = int_val;
            }
            if (highest_maybe == null or int_val > highest_maybe.?) {
                highest_maybe = int_val;
            }
            values[i] = .{ .integer = int_val, .value = item_val };
        }

        case_list.append_assume_capacity(.{ .values = values, .body = case_body });
        try func.start_block(.block, blocktype);
    }

    // When highest and lowest are null, we have no cases and can use a jump table
    const lowest = lowest_maybe orelse 0;
    const highest = highest_maybe orelse 0;
    // When the highest and lowest values are seperated by '50',
    // we define it as sparse and use an if/else-chain, rather than a jump table.
    // When the target is an integer size larger than u32, we have no way to use the value
    // as an index, therefore we also use an if/else-chain for those cases.
    // TODO: Benchmark this to find a proper value, LLVM seems to draw the line at '40~45'.
    const is_sparse = highest - lowest > 50 or target_ty.bit_size(mod) > 32;

    const else_body: []const Air.Inst.Index = @ptr_cast(func.air.extra[extra_index..][0..switch_br.data.else_body_len]);
    const has_else_body = else_body.len != 0;
    if (has_else_body) {
        try func.start_block(.block, blocktype);
    }

    if (!is_sparse) {
        // Generate the jump table 'br_table' when the prongs are not sparse.
        // The value 'target' represents the index into the table.
        // Each index in the table represents a label to the branch
        // to jump to.
        try func.start_block(.block, blocktype);
        try func.emit_wvalue(target);
        if (lowest < 0) {
            // since br_table works using indexes, starting from '0', we must ensure all values
            // we put inside, are atleast 0.
            try func.add_imm32(lowest * -1);
            try func.add_tag(.i32_add);
        } else if (lowest > 0) {
            // make the index start from 0 by substracting the lowest value
            try func.add_imm32(lowest);
            try func.add_tag(.i32_sub);
        }

        // Account for default branch so always add '1'
        const depth = @as(u32, @int_cast(highest - lowest + @int_from_bool(has_else_body))) + 1;
        const jump_table: Mir.JumpTable = .{ .length = depth };
        const table_extra_index = try func.add_extra(jump_table);
        try func.add_inst(.{ .tag = .br_table, .data = .{ .payload = table_extra_index } });
        try func.mir_extra.ensure_unused_capacity(func.gpa, depth);
        var value = lowest;
        while (value <= highest) : (value += 1) {
            // idx represents the branch we jump to
            const idx = blk: {
                for (case_list.items, 0..) |case, idx| {
                    for (case.values) |case_value| {
                        if (case_value.integer == value) break :blk @as(u32, @int_cast(idx));
                    }
                }
                // error sets are almost always sparse so we use the default case
                // for errors that are not present in any branch. This is fine as this default
                // case will never be hit for those cases but we do save runtime cost and size
                // by using a jump table for this instead of if-else chains.
                break :blk if (has_else_body or target_ty.zig_type_tag(mod) == .ErrorSet) case_i else unreachable;
            };
            func.mir_extra.append_assume_capacity(idx);
        } else if (has_else_body) {
            func.mir_extra.append_assume_capacity(case_i); // default branch
        }
        try func.end_block();
    }

    const signedness: std.builtin.Signedness = blk: {
        // by default we tell the operand type is unsigned (i.e. bools and enum values)
        if (target_ty.zig_type_tag(mod) != .Int) break :blk .unsigned;

        // incase of an actual integer, we emit the correct signedness
        break :blk target_ty.int_info(mod).signedness;
    };

    try func.branches.ensure_unused_capacity(func.gpa, case_list.items.len + @int_from_bool(has_else_body));
    for (case_list.items, 0..) |case, index| {
        // when sparse, we use if/else-chain, so emit conditional checks
        if (is_sparse) {
            // for single value prong we can emit a simple if
            if (case.values.len == 1) {
                try func.emit_wvalue(target);
                const val = try func.lower_constant(case.values[0].value, target_ty);
                try func.emit_wvalue(val);
                const opcode = build_opcode(.{
                    .valtype1 = type_to_valtype(target_ty, mod),
                    .op = .ne, // not equal, because we want to jump out of this block if it does not match the condition.
                    .signedness = signedness,
                });
                try func.add_tag(Mir.Inst.Tag.from_opcode(opcode));
                try func.add_label(.br_if, 0);
            } else {
                // in multi-value prongs we must check if any prongs match the target value.
                try func.start_block(.block, blocktype);
                for (case.values) |value| {
                    try func.emit_wvalue(target);
                    const val = try func.lower_constant(value.value, target_ty);
                    try func.emit_wvalue(val);
                    const opcode = build_opcode(.{
                        .valtype1 = type_to_valtype(target_ty, mod),
                        .op = .eq,
                        .signedness = signedness,
                    });
                    try func.add_tag(Mir.Inst.Tag.from_opcode(opcode));
                    try func.add_label(.br_if, 0);
                }
                // value did not match any of the prong values
                try func.add_label(.br, 1);
                try func.end_block();
            }
        }
        func.branches.append_assume_capacity(.{});
        try func.current_branch().values.ensure_unused_capacity(func.gpa, liveness.deaths[index].len);
        defer {
            var case_branch = func.branches.pop();
            case_branch.deinit(func.gpa);
        }
        try func.gen_body(case.body);
        try func.end_block();
    }

    if (has_else_body) {
        func.branches.append_assume_capacity(.{});
        const else_deaths = liveness.deaths.len - 1;
        try func.current_branch().values.ensure_unused_capacity(func.gpa, liveness.deaths[else_deaths].len);
        defer {
            var else_branch = func.branches.pop();
            else_branch.deinit(func.gpa);
        }
        try func.gen_body(else_body);
        try func.end_block();
    }
    func.finish_air(inst, .none, &.{});
}

fn air_is_err(func: *CodeGen, inst: Air.Inst.Index, opcode: wasm.Opcode) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const un_op = func.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const operand = try func.resolve_inst(un_op);
    const err_union_ty = func.type_of(un_op);
    const pl_ty = err_union_ty.error_union_payload(mod);

    const result = result: {
        if (err_union_ty.error_union_set(mod).error_set_is_empty(mod)) {
            switch (opcode) {
                .i32_ne => break :result WValue{ .imm32 = 0 },
                .i32_eq => break :result WValue{ .imm32 = 1 },
                else => unreachable,
            }
        }

        try func.emit_wvalue(operand);
        if (pl_ty.has_runtime_bits_ignore_comptime(mod)) {
            try func.add_mem_arg(.i32_load16_u, .{
                .offset = operand.offset() + @as(u32, @int_cast(err_union_error_offset(pl_ty, mod))),
                .alignment = @int_cast(Type.anyerror.abi_alignment(mod).to_byte_units().?),
            });
        }

        // Compare the error value with '0'
        try func.add_imm32(0);
        try func.add_tag(Mir.Inst.Tag.from_opcode(opcode));

        const is_err_tmp = try func.alloc_local(Type.i32);
        try func.add_label(.local_set, is_err_tmp.local.value);
        break :result is_err_tmp;
    };
    func.finish_air(inst, result, &.{un_op});
}

fn air_unwrap_err_union_payload(func: *CodeGen, inst: Air.Inst.Index, op_is_ptr: bool) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const ty_op = func.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

    const operand = try func.resolve_inst(ty_op.operand);
    const op_ty = func.type_of(ty_op.operand);
    const err_ty = if (op_is_ptr) op_ty.child_type(mod) else op_ty;
    const payload_ty = err_ty.error_union_payload(mod);

    const result = result: {
        if (!payload_ty.has_runtime_bits_ignore_comptime(mod)) {
            if (op_is_ptr) {
                break :result func.reuse_operand(ty_op.operand, operand);
            }
            break :result WValue{ .none = {} };
        }

        const pl_offset = @as(u32, @int_cast(err_union_payload_offset(payload_ty, mod)));
        if (op_is_ptr or is_by_ref(payload_ty, mod)) {
            break :result try func.build_pointer_offset(operand, pl_offset, .new);
        }

        const payload = try func.load(operand, payload_ty, pl_offset);
        break :result try payload.to_local(func, payload_ty);
    };
    func.finish_air(inst, result, &.{ty_op.operand});
}

fn air_unwrap_err_union_error(func: *CodeGen, inst: Air.Inst.Index, op_is_ptr: bool) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const ty_op = func.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

    const operand = try func.resolve_inst(ty_op.operand);
    const op_ty = func.type_of(ty_op.operand);
    const err_ty = if (op_is_ptr) op_ty.child_type(mod) else op_ty;
    const payload_ty = err_ty.error_union_payload(mod);

    const result = result: {
        if (err_ty.error_union_set(mod).error_set_is_empty(mod)) {
            break :result WValue{ .imm32 = 0 };
        }

        if (op_is_ptr or !payload_ty.has_runtime_bits_ignore_comptime(mod)) {
            break :result func.reuse_operand(ty_op.operand, operand);
        }

        const error_val = try func.load(operand, Type.anyerror, @as(u32, @int_cast(err_union_error_offset(payload_ty, mod))));
        break :result try error_val.to_local(func, Type.anyerror);
    };
    func.finish_air(inst, result, &.{ty_op.operand});
}

fn air_wrap_err_union_payload(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const ty_op = func.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

    const operand = try func.resolve_inst(ty_op.operand);
    const err_ty = func.type_of_index(inst);

    const pl_ty = func.type_of(ty_op.operand);
    const result = result: {
        if (!pl_ty.has_runtime_bits_ignore_comptime(mod)) {
            break :result func.reuse_operand(ty_op.operand, operand);
        }

        const err_union = try func.alloc_stack(err_ty);
        const payload_ptr = try func.build_pointer_offset(err_union, @as(u32, @int_cast(err_union_payload_offset(pl_ty, mod))), .new);
        try func.store(payload_ptr, operand, pl_ty, 0);

        // ensure we also write '0' to the error part, so any present stack value gets overwritten by it.
        try func.emit_wvalue(err_union);
        try func.add_imm32(0);
        const err_val_offset = @as(u32, @int_cast(err_union_error_offset(pl_ty, mod)));
        try func.add_mem_arg(.i32_store16, .{
            .offset = err_union.offset() + err_val_offset,
            .alignment = 2,
        });
        break :result err_union;
    };
    func.finish_air(inst, result, &.{ty_op.operand});
}

fn air_wrap_err_union_err(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const ty_op = func.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

    const operand = try func.resolve_inst(ty_op.operand);
    const err_ty = ty_op.ty.to_type();
    const pl_ty = err_ty.error_union_payload(mod);

    const result = result: {
        if (!pl_ty.has_runtime_bits_ignore_comptime(mod)) {
            break :result func.reuse_operand(ty_op.operand, operand);
        }

        const err_union = try func.alloc_stack(err_ty);
        // store error value
        try func.store(err_union, operand, Type.anyerror, @as(u32, @int_cast(err_union_error_offset(pl_ty, mod))));

        // write 'undefined' to the payload
        const payload_ptr = try func.build_pointer_offset(err_union, @as(u32, @int_cast(err_union_payload_offset(pl_ty, mod))), .new);
        const len = @as(u32, @int_cast(err_ty.error_union_payload(mod).abi_size(mod)));
        try func.memset(Type.u8, payload_ptr, .{ .imm32 = len }, .{ .imm32 = 0xaa });

        break :result err_union;
    };
    func.finish_air(inst, result, &.{ty_op.operand});
}

fn air_intcast(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const ty_op = func.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

    const ty = ty_op.ty.to_type();
    const operand = try func.resolve_inst(ty_op.operand);
    const operand_ty = func.type_of(ty_op.operand);
    const mod = func.bin_file.base.comp.module.?;
    if (ty.zig_type_tag(mod) == .Vector or operand_ty.zig_type_tag(mod) == .Vector) {
        return func.fail("todo Wasm intcast for vectors", .{});
    }
    if (ty.abi_size(mod) > 16 or operand_ty.abi_size(mod) > 16) {
        return func.fail("todo Wasm intcast for bitsize > 128", .{});
    }

    const op_bits = to_wasm_bits(@as(u16, @int_cast(operand_ty.bit_size(mod)))).?;
    const wanted_bits = to_wasm_bits(@as(u16, @int_cast(ty.bit_size(mod)))).?;
    const result = if (op_bits == wanted_bits and !ty.is_signed_int(mod))
        func.reuse_operand(ty_op.operand, operand)
    else
        try (try func.intcast(operand, operand_ty, ty)).to_local(func, ty);

    func.finish_air(inst, result, &.{});
}

/// Upcasts or downcasts an integer based on the given and wanted types,
/// and stores the result in a new operand.
/// Asserts type's bitsize <= 128
/// NOTE: May leave the result on the top of the stack.
fn intcast(func: *CodeGen, operand: WValue, given: Type, wanted: Type) InnerError!WValue {
    const mod = func.bin_file.base.comp.module.?;
    const given_bitsize = @as(u16, @int_cast(given.bit_size(mod)));
    const wanted_bitsize = @as(u16, @int_cast(wanted.bit_size(mod)));
    assert(given_bitsize <= 128);
    assert(wanted_bitsize <= 128);

    const op_bits = to_wasm_bits(given_bitsize).?;
    const wanted_bits = to_wasm_bits(wanted_bitsize).?;
    if (op_bits == wanted_bits) {
        if (given.is_signed_int(mod)) {
            if (given_bitsize < wanted_bitsize) {
                // signed integers are stored as two's complement,
                // when we upcast from a smaller integer to larger
                // integers, we must get its absolute value similar to
                // i64_extend_i32_s instruction.
                return func.sign_extend_int(operand, given);
            }
            return func.wrap_operand(operand, wanted);
        }
        return operand;
    }

    if (op_bits > 32 and op_bits <= 64 and wanted_bits == 32) {
        try func.emit_wvalue(operand);
        try func.add_tag(.i32_wrap_i64);
        if (given.is_signed_int(mod) and wanted_bitsize < 32)
            return func.wrap_operand(.{ .stack = {} }, wanted)
        else
            return WValue{ .stack = {} };
    } else if (op_bits == 32 and wanted_bits > 32 and wanted_bits <= 64) {
        const operand32 = if (given_bitsize < 32 and wanted.is_signed_int(mod))
            try func.sign_extend_int(operand, given)
        else
            operand;
        try func.emit_wvalue(operand32);
        try func.add_tag(if (wanted.is_signed_int(mod)) .i64_extend_i32_s else .i64_extend_i32_u);
        if (given.is_signed_int(mod) and wanted_bitsize < 64)
            return func.wrap_operand(.{ .stack = {} }, wanted)
        else
            return WValue{ .stack = {} };
    } else if (wanted_bits == 128) {
        // for 128bit integers we store the integer in the virtual stack, rather than a local
        const stack_ptr = try func.alloc_stack(wanted);
        try func.emit_wvalue(stack_ptr);

        // for 32 bit integers, we first coerce the value into a 64 bit integer before storing it
        // meaning less store operations are required.
        const lhs = if (op_bits == 32) blk: {
            break :blk try func.intcast(operand, given, if (wanted.is_signed_int(mod)) Type.i64 else Type.u64);
        } else operand;

        // store msb first
        try func.store(.{ .stack = {} }, lhs, Type.u64, 0 + stack_ptr.offset());

        // For signed integers we shift msb by 63 (64bit integer - 1 sign bit) and store remaining value
        if (wanted.is_signed_int(mod)) {
            try func.emit_wvalue(stack_ptr);
            const shr = try func.bin_op(lhs, .{ .imm64 = 63 }, Type.i64, .shr);
            try func.store(.{ .stack = {} }, shr, Type.u64, 8 + stack_ptr.offset());
        } else {
            // Ensure memory of lsb is zero'd
            try func.store(stack_ptr, .{ .imm64 = 0 }, Type.u64, 8);
        }
        return stack_ptr;
    } else return func.load(operand, wanted, 0);
}

fn air_is_null(func: *CodeGen, inst: Air.Inst.Index, opcode: wasm.Opcode, op_kind: enum { value, ptr }) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const un_op = func.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const operand = try func.resolve_inst(un_op);

    const op_ty = func.type_of(un_op);
    const optional_ty = if (op_kind == .ptr) op_ty.child_type(mod) else op_ty;
    const is_null = try func.is_null(operand, optional_ty, opcode);
    const result = try is_null.to_local(func, optional_ty);
    func.finish_air(inst, result, &.{un_op});
}

/// For a given type and operand, checks if it's considered `null`.
/// NOTE: Leaves the result on the stack
fn is_null(func: *CodeGen, operand: WValue, optional_ty: Type, opcode: wasm.Opcode) InnerError!WValue {
    const mod = func.bin_file.base.comp.module.?;
    try func.emit_wvalue(operand);
    const payload_ty = optional_ty.optional_child(mod);
    if (!optional_ty.optional_repr_is_payload(mod)) {
        // When payload is zero-bits, we can treat operand as a value, rather than
        // a pointer to the stack value
        if (payload_ty.has_runtime_bits_ignore_comptime(mod)) {
            const offset = std.math.cast(u32, payload_ty.abi_size(mod)) orelse {
                return func.fail("Optional type {} too big to fit into stack frame", .{optional_ty.fmt(mod)});
            };
            try func.add_mem_arg(.i32_load8_u, .{ .offset = operand.offset() + offset, .alignment = 1 });
        }
    } else if (payload_ty.is_slice(mod)) {
        switch (func.arch()) {
            .wasm32 => try func.add_mem_arg(.i32_load, .{ .offset = operand.offset(), .alignment = 4 }),
            .wasm64 => try func.add_mem_arg(.i64_load, .{ .offset = operand.offset(), .alignment = 8 }),
            else => unreachable,
        }
    }

    // Compare the null value with '0'
    try func.add_imm32(0);
    try func.add_tag(Mir.Inst.Tag.from_opcode(opcode));

    return WValue{ .stack = {} };
}

fn air_optional_payload(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const ty_op = func.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const opt_ty = func.type_of(ty_op.operand);
    const payload_ty = func.type_of_index(inst);
    if (!payload_ty.has_runtime_bits_ignore_comptime(mod)) {
        return func.finish_air(inst, .none, &.{ty_op.operand});
    }

    const result = result: {
        const operand = try func.resolve_inst(ty_op.operand);
        if (opt_ty.optional_repr_is_payload(mod)) break :result func.reuse_operand(ty_op.operand, operand);

        if (is_by_ref(payload_ty, mod)) {
            break :result try func.build_pointer_offset(operand, 0, .new);
        }

        const payload = try func.load(operand, payload_ty, 0);
        break :result try payload.to_local(func, payload_ty);
    };
    func.finish_air(inst, result, &.{ty_op.operand});
}

fn air_optional_payload_ptr(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const ty_op = func.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const operand = try func.resolve_inst(ty_op.operand);
    const opt_ty = func.type_of(ty_op.operand).child_type(mod);

    const result = result: {
        const payload_ty = opt_ty.optional_child(mod);
        if (!payload_ty.has_runtime_bits_ignore_comptime(mod) or opt_ty.optional_repr_is_payload(mod)) {
            break :result func.reuse_operand(ty_op.operand, operand);
        }

        break :result try func.build_pointer_offset(operand, 0, .new);
    };
    func.finish_air(inst, result, &.{ty_op.operand});
}

fn air_optional_payload_ptr_set(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const ty_op = func.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const operand = try func.resolve_inst(ty_op.operand);
    const opt_ty = func.type_of(ty_op.operand).child_type(mod);
    const payload_ty = opt_ty.optional_child(mod);
    if (!payload_ty.has_runtime_bits_ignore_comptime(mod)) {
        return func.fail("TODO: Implement OptionalPayloadPtrSet for optional with zero-sized type {}", .{payload_ty.fmt_debug()});
    }

    if (opt_ty.optional_repr_is_payload(mod)) {
        return func.finish_air(inst, operand, &.{ty_op.operand});
    }

    const offset = std.math.cast(u32, payload_ty.abi_size(mod)) orelse {
        return func.fail("Optional type {} too big to fit into stack frame", .{opt_ty.fmt(mod)});
    };

    try func.emit_wvalue(operand);
    try func.add_imm32(1);
    try func.add_mem_arg(.i32_store8, .{ .offset = operand.offset() + offset, .alignment = 1 });

    const result = try func.build_pointer_offset(operand, 0, .new);
    return func.finish_air(inst, result, &.{ty_op.operand});
}

fn air_wrap_optional(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const ty_op = func.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const payload_ty = func.type_of(ty_op.operand);
    const mod = func.bin_file.base.comp.module.?;

    const result = result: {
        if (!payload_ty.has_runtime_bits_ignore_comptime(mod)) {
            const non_null_bit = try func.alloc_stack(Type.u1);
            try func.emit_wvalue(non_null_bit);
            try func.add_imm32(1);
            try func.add_mem_arg(.i32_store8, .{ .offset = non_null_bit.offset(), .alignment = 1 });
            break :result non_null_bit;
        }

        const operand = try func.resolve_inst(ty_op.operand);
        const op_ty = func.type_of_index(inst);
        if (op_ty.optional_repr_is_payload(mod)) {
            break :result func.reuse_operand(ty_op.operand, operand);
        }
        const offset = std.math.cast(u32, payload_ty.abi_size(mod)) orelse {
            return func.fail("Optional type {} too big to fit into stack frame", .{op_ty.fmt(mod)});
        };

        // Create optional type, set the non-null bit, and store the operand inside the optional type
        const result_ptr = try func.alloc_stack(op_ty);
        try func.emit_wvalue(result_ptr);
        try func.add_imm32(1);
        try func.add_mem_arg(.i32_store8, .{ .offset = result_ptr.offset() + offset, .alignment = 1 });

        const payload_ptr = try func.build_pointer_offset(result_ptr, 0, .new);
        try func.store(payload_ptr, operand, payload_ty, 0);
        break :result result_ptr;
    };

    func.finish_air(inst, result, &.{ty_op.operand});
}

fn air_slice(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const ty_pl = func.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const bin_op = func.air.extra_data(Air.Bin, ty_pl.payload).data;

    const lhs = try func.resolve_inst(bin_op.lhs);
    const rhs = try func.resolve_inst(bin_op.rhs);
    const slice_ty = func.type_of_index(inst);

    const slice = try func.alloc_stack(slice_ty);
    try func.store(slice, lhs, Type.usize, 0);
    try func.store(slice, rhs, Type.usize, func.ptr_size());

    func.finish_air(inst, slice, &.{ bin_op.lhs, bin_op.rhs });
}

fn air_slice_len(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const ty_op = func.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

    const operand = try func.resolve_inst(ty_op.operand);
    func.finish_air(inst, try func.slice_len(operand), &.{ty_op.operand});
}

fn air_slice_elem_val(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const bin_op = func.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;

    const slice_ty = func.type_of(bin_op.lhs);
    const slice = try func.resolve_inst(bin_op.lhs);
    const index = try func.resolve_inst(bin_op.rhs);
    const elem_ty = slice_ty.child_type(mod);
    const elem_size = elem_ty.abi_size(mod);

    // load pointer onto stack
    _ = try func.load(slice, Type.usize, 0);

    // calculate index into slice
    try func.emit_wvalue(index);
    try func.add_imm32(@as(i32, @bit_cast(@as(u32, @int_cast(elem_size)))));
    try func.add_tag(.i32_mul);
    try func.add_tag(.i32_add);

    const result_ptr = try func.alloc_local(Type.usize);
    try func.add_label(.local_set, result_ptr.local.value);

    const result = if (!is_by_ref(elem_ty, mod)) result: {
        const elem_val = try func.load(result_ptr, elem_ty, 0);
        break :result try elem_val.to_local(func, elem_ty);
    } else result_ptr;

    func.finish_air(inst, result, &.{ bin_op.lhs, bin_op.rhs });
}

fn air_slice_elem_ptr(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const ty_pl = func.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const bin_op = func.air.extra_data(Air.Bin, ty_pl.payload).data;

    const elem_ty = ty_pl.ty.to_type().child_type(mod);
    const elem_size = elem_ty.abi_size(mod);

    const slice = try func.resolve_inst(bin_op.lhs);
    const index = try func.resolve_inst(bin_op.rhs);

    _ = try func.load(slice, Type.usize, 0);

    // calculate index into slice
    try func.emit_wvalue(index);
    try func.add_imm32(@as(i32, @bit_cast(@as(u32, @int_cast(elem_size)))));
    try func.add_tag(.i32_mul);
    try func.add_tag(.i32_add);

    const result = try func.alloc_local(Type.i32);
    try func.add_label(.local_set, result.local.value);
    func.finish_air(inst, result, &.{ bin_op.lhs, bin_op.rhs });
}

fn air_slice_ptr(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const ty_op = func.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const operand = try func.resolve_inst(ty_op.operand);
    func.finish_air(inst, try func.slice_ptr(operand), &.{ty_op.operand});
}

fn slice_ptr(func: *CodeGen, operand: WValue) InnerError!WValue {
    const ptr = try func.load(operand, Type.usize, 0);
    return ptr.to_local(func, Type.usize);
}

fn slice_len(func: *CodeGen, operand: WValue) InnerError!WValue {
    const len = try func.load(operand, Type.usize, func.ptr_size());
    return len.to_local(func, Type.usize);
}

fn air_trunc(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const ty_op = func.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

    const operand = try func.resolve_inst(ty_op.operand);
    const wanted_ty = ty_op.ty.to_type();
    const op_ty = func.type_of(ty_op.operand);

    const result = try func.trunc(operand, wanted_ty, op_ty);
    func.finish_air(inst, try result.to_local(func, wanted_ty), &.{ty_op.operand});
}

/// Truncates a given operand to a given type, discarding any overflown bits.
/// NOTE: Resulting value is left on the stack.
fn trunc(func: *CodeGen, operand: WValue, wanted_ty: Type, given_ty: Type) InnerError!WValue {
    const mod = func.bin_file.base.comp.module.?;
    const given_bits = @as(u16, @int_cast(given_ty.bit_size(mod)));
    if (to_wasm_bits(given_bits) == null) {
        return func.fail("TODO: Implement wasm integer truncation for integer bitsize: {d}", .{given_bits});
    }

    var result = try func.intcast(operand, given_ty, wanted_ty);
    const wanted_bits = @as(u16, @int_cast(wanted_ty.bit_size(mod)));
    const wasm_bits = to_wasm_bits(wanted_bits).?;
    if (wasm_bits != wanted_bits) {
        result = try func.wrap_operand(result, wanted_ty);
    }
    return result;
}

fn air_int_from_bool(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const un_op = func.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const operand = try func.resolve_inst(un_op);
    const result = func.reuse_operand(un_op, operand);

    func.finish_air(inst, result, &.{un_op});
}

fn air_array_to_slice(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const ty_op = func.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

    const operand = try func.resolve_inst(ty_op.operand);
    const array_ty = func.type_of(ty_op.operand).child_type(mod);
    const slice_ty = ty_op.ty.to_type();

    // create a slice on the stack
    const slice_local = try func.alloc_stack(slice_ty);

    // store the array ptr in the slice
    if (array_ty.has_runtime_bits_ignore_comptime(mod)) {
        try func.store(slice_local, operand, Type.usize, 0);
    }

    // store the length of the array in the slice
    const len = WValue{ .imm32 = @as(u32, @int_cast(array_ty.array_len(mod))) };
    try func.store(slice_local, len, Type.usize, func.ptr_size());

    func.finish_air(inst, slice_local, &.{ty_op.operand});
}

fn air_int_from_ptr(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const un_op = func.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const operand = try func.resolve_inst(un_op);
    const ptr_ty = func.type_of(un_op);
    const result = if (ptr_ty.is_slice(mod))
        try func.slice_ptr(operand)
    else switch (operand) {
        // for stack offset, return a pointer to this offset.
        .stack_offset => try func.build_pointer_offset(operand, 0, .new),
        else => func.reuse_operand(un_op, operand),
    };
    func.finish_air(inst, result, &.{un_op});
}

fn air_ptr_elem_val(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const bin_op = func.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;

    const ptr_ty = func.type_of(bin_op.lhs);
    const ptr = try func.resolve_inst(bin_op.lhs);
    const index = try func.resolve_inst(bin_op.rhs);
    const elem_ty = ptr_ty.child_type(mod);
    const elem_size = elem_ty.abi_size(mod);

    // load pointer onto the stack
    if (ptr_ty.is_slice(mod)) {
        _ = try func.load(ptr, Type.usize, 0);
    } else {
        try func.lower_to_stack(ptr);
    }

    // calculate index into slice
    try func.emit_wvalue(index);
    try func.add_imm32(@as(i32, @bit_cast(@as(u32, @int_cast(elem_size)))));
    try func.add_tag(.i32_mul);
    try func.add_tag(.i32_add);

    const elem_result = val: {
        var result = try func.alloc_local(Type.usize);
        try func.add_label(.local_set, result.local.value);
        if (is_by_ref(elem_ty, mod)) {
            break :val result;
        }
        defer result.free(func); // only free if it's not returned like above

        const elem_val = try func.load(result, elem_ty, 0);
        break :val try elem_val.to_local(func, elem_ty);
    };
    func.finish_air(inst, elem_result, &.{ bin_op.lhs, bin_op.rhs });
}

fn air_ptr_elem_ptr(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const ty_pl = func.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const bin_op = func.air.extra_data(Air.Bin, ty_pl.payload).data;

    const ptr_ty = func.type_of(bin_op.lhs);
    const elem_ty = ty_pl.ty.to_type().child_type(mod);
    const elem_size = elem_ty.abi_size(mod);

    const ptr = try func.resolve_inst(bin_op.lhs);
    const index = try func.resolve_inst(bin_op.rhs);

    // load pointer onto the stack
    if (ptr_ty.is_slice(mod)) {
        _ = try func.load(ptr, Type.usize, 0);
    } else {
        try func.lower_to_stack(ptr);
    }

    // calculate index into ptr
    try func.emit_wvalue(index);
    try func.add_imm32(@as(i32, @bit_cast(@as(u32, @int_cast(elem_size)))));
    try func.add_tag(.i32_mul);
    try func.add_tag(.i32_add);

    const result = try func.alloc_local(Type.i32);
    try func.add_label(.local_set, result.local.value);
    func.finish_air(inst, result, &.{ bin_op.lhs, bin_op.rhs });
}

fn air_ptr_bin_op(func: *CodeGen, inst: Air.Inst.Index, op: Op) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const ty_pl = func.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const bin_op = func.air.extra_data(Air.Bin, ty_pl.payload).data;

    const ptr = try func.resolve_inst(bin_op.lhs);
    const offset = try func.resolve_inst(bin_op.rhs);
    const ptr_ty = func.type_of(bin_op.lhs);
    const pointee_ty = switch (ptr_ty.ptr_size(mod)) {
        .One => ptr_ty.child_type(mod).child_type(mod), // ptr to array, so get array element type
        else => ptr_ty.child_type(mod),
    };

    const valtype = type_to_valtype(Type.usize, mod);
    const mul_opcode = build_opcode(.{ .valtype1 = valtype, .op = .mul });
    const bin_opcode = build_opcode(.{ .valtype1 = valtype, .op = op });

    try func.lower_to_stack(ptr);
    try func.emit_wvalue(offset);
    try func.add_imm32(@as(i32, @bit_cast(@as(u32, @int_cast(pointee_ty.abi_size(mod))))));
    try func.add_tag(Mir.Inst.Tag.from_opcode(mul_opcode));
    try func.add_tag(Mir.Inst.Tag.from_opcode(bin_opcode));

    const result = try func.alloc_local(Type.usize);
    try func.add_label(.local_set, result.local.value);
    func.finish_air(inst, result, &.{ bin_op.lhs, bin_op.rhs });
}

fn air_memset(func: *CodeGen, inst: Air.Inst.Index, safety: bool) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    if (safety) {
        // TODO if the value is undef, write 0xaa bytes to dest
    } else {
        // TODO if the value is undef, don't lower this instruction
    }
    const bin_op = func.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;

    const ptr = try func.resolve_inst(bin_op.lhs);
    const ptr_ty = func.type_of(bin_op.lhs);
    const value = try func.resolve_inst(bin_op.rhs);
    const len = switch (ptr_ty.ptr_size(mod)) {
        .Slice => try func.slice_len(ptr),
        .One => @as(WValue, .{ .imm32 = @as(u32, @int_cast(ptr_ty.child_type(mod).array_len(mod))) }),
        .C, .Many => unreachable,
    };

    const elem_ty = if (ptr_ty.ptr_size(mod) == .One)
        ptr_ty.child_type(mod).child_type(mod)
    else
        ptr_ty.child_type(mod);

    const dst_ptr = try func.slice_or_array_ptr(ptr, ptr_ty);
    try func.memset(elem_ty, dst_ptr, len, value);

    func.finish_air(inst, .none, &.{ bin_op.lhs, bin_op.rhs });
}

/// Sets a region of memory at `ptr` to the value of `value`
/// When the user has enabled the bulk_memory feature, we lower
/// this to wasm's memset instruction. When the feature is not present,
/// we implement it manually.
fn memset(func: *CodeGen, elem_ty: Type, ptr: WValue, len: WValue, value: WValue) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const abi_size = @as(u32, @int_cast(elem_ty.abi_size(mod)));

    // When bulk_memory is enabled, we lower it to wasm's memset instruction.
    // If not, we lower it ourselves.
    if (std.Target.wasm.feature_set_has(func.target.cpu.features, .bulk_memory) and abi_size == 1) {
        try func.lower_to_stack(ptr);
        try func.emit_wvalue(value);
        try func.emit_wvalue(len);
        try func.add_extended(.memory_fill);
        return;
    }

    const final_len = switch (len) {
        .imm32 => |val| WValue{ .imm32 = val * abi_size },
        .imm64 => |val| WValue{ .imm64 = val * abi_size },
        else => if (abi_size != 1) blk: {
            const new_len = try func.ensure_alloc_local(Type.usize);
            try func.emit_wvalue(len);
            switch (func.arch()) {
                .wasm32 => {
                    try func.emit_wvalue(.{ .imm32 = abi_size });
                    try func.add_tag(.i32_mul);
                },
                .wasm64 => {
                    try func.emit_wvalue(.{ .imm64 = abi_size });
                    try func.add_tag(.i64_mul);
                },
                else => unreachable,
            }
            try func.add_label(.local_set, new_len.local.value);
            break :blk new_len;
        } else len,
    };

    var end_ptr = try func.alloc_local(Type.usize);
    defer end_ptr.free(func);
    var new_ptr = try func.build_pointer_offset(ptr, 0, .new);
    defer new_ptr.free(func);

    // get the loop conditional: if current pointer address equals final pointer's address
    try func.lower_to_stack(ptr);
    try func.emit_wvalue(final_len);
    switch (func.arch()) {
        .wasm32 => try func.add_tag(.i32_add),
        .wasm64 => try func.add_tag(.i64_add),
        else => unreachable,
    }
    try func.add_label(.local_set, end_ptr.local.value);

    // outer block to jump to when loop is done
    try func.start_block(.block, wasm.block_empty);
    try func.start_block(.loop, wasm.block_empty);

    // check for codition for loop end
    try func.emit_wvalue(new_ptr);
    try func.emit_wvalue(end_ptr);
    switch (func.arch()) {
        .wasm32 => try func.add_tag(.i32_eq),
        .wasm64 => try func.add_tag(.i64_eq),
        else => unreachable,
    }
    try func.add_label(.br_if, 1); // jump out of loop into outer block (finished)

    // store the value at the current position of the pointer
    try func.store(new_ptr, value, elem_ty, 0);

    // move the pointer to the next element
    try func.emit_wvalue(new_ptr);
    switch (func.arch()) {
        .wasm32 => {
            try func.emit_wvalue(.{ .imm32 = abi_size });
            try func.add_tag(.i32_add);
        },
        .wasm64 => {
            try func.emit_wvalue(.{ .imm64 = abi_size });
            try func.add_tag(.i64_add);
        },
        else => unreachable,
    }
    try func.add_label(.local_set, new_ptr.local.value);

    // end of loop
    try func.add_label(.br, 0); // jump to start of loop
    try func.end_block();
    try func.end_block();
}

fn air_array_elem_val(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const bin_op = func.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;

    const array_ty = func.type_of(bin_op.lhs);
    const array = try func.resolve_inst(bin_op.lhs);
    const index = try func.resolve_inst(bin_op.rhs);
    const elem_ty = array_ty.child_type(mod);
    const elem_size = elem_ty.abi_size(mod);

    if (is_by_ref(array_ty, mod)) {
        try func.lower_to_stack(array);
        try func.emit_wvalue(index);
        try func.add_imm32(@as(i32, @bit_cast(@as(u32, @int_cast(elem_size)))));
        try func.add_tag(.i32_mul);
        try func.add_tag(.i32_add);
    } else {
        std.debug.assert(array_ty.zig_type_tag(mod) == .Vector);

        switch (index) {
            inline .imm32, .imm64 => |lane| {
                const opcode: wasm.SimdOpcode = switch (elem_ty.bit_size(mod)) {
                    8 => if (elem_ty.is_signed_int(mod)) .i8x16_extract_lane_s else .i8x16_extract_lane_u,
                    16 => if (elem_ty.is_signed_int(mod)) .i16x8_extract_lane_s else .i16x8_extract_lane_u,
                    32 => if (elem_ty.is_int(mod)) .i32x4_extract_lane else .f32x4_extract_lane,
                    64 => if (elem_ty.is_int(mod)) .i64x2_extract_lane else .f64x2_extract_lane,
                    else => unreachable,
                };

                var operands = [_]u32{ std.wasm.simd_opcode(opcode), @as(u8, @int_cast(lane)) };

                try func.emit_wvalue(array);

                const extra_index = @as(u32, @int_cast(func.mir_extra.items.len));
                try func.mir_extra.append_slice(func.gpa, &operands);
                try func.add_inst(.{ .tag = .simd_prefix, .data = .{ .payload = extra_index } });

                return func.finish_air(inst, try WValue.to_local(.stack, func, elem_ty), &.{ bin_op.lhs, bin_op.rhs });
            },
            else => {
                const stack_vec = try func.alloc_stack(array_ty);
                try func.store(stack_vec, array, array_ty, 0);

                // Is a non-unrolled vector (v128)
                try func.lower_to_stack(stack_vec);
                try func.emit_wvalue(index);
                try func.add_imm32(@as(i32, @bit_cast(@as(u32, @int_cast(elem_size)))));
                try func.add_tag(.i32_mul);
                try func.add_tag(.i32_add);
            },
        }
    }

    const elem_result = val: {
        var result = try func.alloc_local(Type.usize);
        try func.add_label(.local_set, result.local.value);

        if (is_by_ref(elem_ty, mod)) {
            break :val result;
        }
        defer result.free(func); // only free if no longer needed and not returned like above

        const elem_val = try func.load(result, elem_ty, 0);
        break :val try elem_val.to_local(func, elem_ty);
    };

    func.finish_air(inst, elem_result, &.{ bin_op.lhs, bin_op.rhs });
}

fn air_int_from_float(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const ty_op = func.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

    const operand = try func.resolve_inst(ty_op.operand);
    const op_ty = func.type_of(ty_op.operand);
    const op_bits = op_ty.float_bits(func.target);

    const dest_ty = func.type_of_index(inst);
    const dest_info = dest_ty.int_info(mod);

    if (dest_info.bits > 128) {
        return func.fail("TODO: int_from_float for integers/floats with bitsize {}", .{dest_info.bits});
    }

    if ((op_bits != 32 and op_bits != 64) or dest_info.bits > 64) {
        const dest_bitsize = if (dest_info.bits <= 16) 16 else std.math.ceil_power_of_two_assert(u16, dest_info.bits);

        var fn_name_buf: [16]u8 = undefined;
        const fn_name = std.fmt.buf_print(&fn_name_buf, "__fix{s}{s}f{s}i", .{
            switch (dest_info.signedness) {
                .signed => "",
                .unsigned => "uns",
            },
            target_util.compiler_rt_float_abbrev(op_bits),
            target_util.compiler_rt_int_abbrev(dest_bitsize),
        }) catch unreachable;

        const result = try (try func.call_intrinsic(fn_name, &.{op_ty.ip_index}, dest_ty, &.{operand})).to_local(func, dest_ty);
        return func.finish_air(inst, result, &.{ty_op.operand});
    }

    try func.emit_wvalue(operand);
    const op = build_opcode(.{
        .op = .trunc,
        .valtype1 = type_to_valtype(dest_ty, mod),
        .valtype2 = type_to_valtype(op_ty, mod),
        .signedness = dest_info.signedness,
    });
    try func.add_tag(Mir.Inst.Tag.from_opcode(op));
    const wrapped = try func.wrap_operand(.{ .stack = {} }, dest_ty);
    const result = try wrapped.to_local(func, dest_ty);
    func.finish_air(inst, result, &.{ty_op.operand});
}

fn air_float_from_int(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const ty_op = func.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

    const operand = try func.resolve_inst(ty_op.operand);
    const op_ty = func.type_of(ty_op.operand);
    const op_info = op_ty.int_info(mod);

    const dest_ty = func.type_of_index(inst);
    const dest_bits = dest_ty.float_bits(func.target);

    if (op_info.bits > 128) {
        return func.fail("TODO: float_from_int for integers/floats with bitsize {d} bits", .{op_info.bits});
    }

    if (op_info.bits > 64 or (dest_bits > 64 or dest_bits < 32)) {
        const op_bitsize = if (op_info.bits <= 16) 16 else std.math.ceil_power_of_two_assert(u16, op_info.bits);

        var fn_name_buf: [16]u8 = undefined;
        const fn_name = std.fmt.buf_print(&fn_name_buf, "__float{s}{s}i{s}f", .{
            switch (op_info.signedness) {
                .signed => "",
                .unsigned => "un",
            },
            target_util.compiler_rt_int_abbrev(op_bitsize),
            target_util.compiler_rt_float_abbrev(dest_bits),
        }) catch unreachable;

        const result = try (try func.call_intrinsic(fn_name, &.{op_ty.ip_index}, dest_ty, &.{operand})).to_local(func, dest_ty);
        return func.finish_air(inst, result, &.{ty_op.operand});
    }

    try func.emit_wvalue(operand);
    const op = build_opcode(.{
        .op = .convert,
        .valtype1 = type_to_valtype(dest_ty, mod),
        .valtype2 = type_to_valtype(op_ty, mod),
        .signedness = op_info.signedness,
    });
    try func.add_tag(Mir.Inst.Tag.from_opcode(op));

    const result = try func.alloc_local(dest_ty);
    try func.add_label(.local_set, result.local.value);
    func.finish_air(inst, result, &.{ty_op.operand});
}

fn air_splat(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const ty_op = func.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const operand = try func.resolve_inst(ty_op.operand);
    const ty = func.type_of_index(inst);
    const elem_ty = ty.child_type(mod);

    if (determine_simd_store_strategy(ty, mod) == .direct) blk: {
        switch (operand) {
            // when the operand lives in the linear memory section, we can directly
            // load and splat the value at once. Meaning we do not first have to load
            // the scalar value onto the stack.
            .stack_offset, .memory, .memory_offset => {
                const opcode = switch (elem_ty.bit_size(mod)) {
                    8 => std.wasm.simd_opcode(.v128_load8_splat),
                    16 => std.wasm.simd_opcode(.v128_load16_splat),
                    32 => std.wasm.simd_opcode(.v128_load32_splat),
                    64 => std.wasm.simd_opcode(.v128_load64_splat),
                    else => break :blk, // Cannot make use of simd-instructions
                };
                const result = try func.alloc_local(ty);
                try func.emit_wvalue(operand);
                // TODO: Add helper functions for simd opcodes
                const extra_index = @as(u32, @int_cast(func.mir_extra.items.len));
                // stores as := opcode, offset, alignment (opcode::memarg)
                try func.mir_extra.append_slice(func.gpa, &[_]u32{
                    opcode,
                    operand.offset(),
                    @int_cast(elem_ty.abi_alignment(mod).to_byte_units().?),
                });
                try func.add_inst(.{ .tag = .simd_prefix, .data = .{ .payload = extra_index } });
                try func.add_label(.local_set, result.local.value);
                return func.finish_air(inst, result, &.{ty_op.operand});
            },
            .local => {
                const opcode = switch (elem_ty.bit_size(mod)) {
                    8 => std.wasm.simd_opcode(.i8x16_splat),
                    16 => std.wasm.simd_opcode(.i16x8_splat),
                    32 => if (elem_ty.is_int(mod)) std.wasm.simd_opcode(.i32x4_splat) else std.wasm.simd_opcode(.f32x4_splat),
                    64 => if (elem_ty.is_int(mod)) std.wasm.simd_opcode(.i64x2_splat) else std.wasm.simd_opcode(.f64x2_splat),
                    else => break :blk, // Cannot make use of simd-instructions
                };
                const result = try func.alloc_local(ty);
                try func.emit_wvalue(operand);
                const extra_index = @as(u32, @int_cast(func.mir_extra.items.len));
                try func.mir_extra.append(func.gpa, opcode);
                try func.add_inst(.{ .tag = .simd_prefix, .data = .{ .payload = extra_index } });
                try func.add_label(.local_set, result.local.value);
                return func.finish_air(inst, result, &.{ty_op.operand});
            },
            else => unreachable,
        }
    }
    const elem_size = elem_ty.bit_size(mod);
    const vector_len = @as(usize, @int_cast(ty.vector_len(mod)));
    if ((!std.math.is_power_of_two(elem_size) or elem_size % 8 != 0) and vector_len > 1) {
        return func.fail("TODO: WebAssembly `@splat` for arbitrary element bitsize {d}", .{elem_size});
    }

    const result = try func.alloc_stack(ty);
    const elem_byte_size = @as(u32, @int_cast(elem_ty.abi_size(mod)));
    var index: usize = 0;
    var offset: u32 = 0;
    while (index < vector_len) : (index += 1) {
        try func.store(result, operand, elem_ty, offset);
        offset += elem_byte_size;
    }

    return func.finish_air(inst, result, &.{ty_op.operand});
}

fn air_select(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const pl_op = func.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
    const operand = try func.resolve_inst(pl_op.operand);

    _ = operand;
    return func.fail("TODO: Implement wasm air_select", .{});
}

fn air_shuffle(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const inst_ty = func.type_of_index(inst);
    const ty_pl = func.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = func.air.extra_data(Air.Shuffle, ty_pl.payload).data;

    const a = try func.resolve_inst(extra.a);
    const b = try func.resolve_inst(extra.b);
    const mask = Value.from_interned(extra.mask);
    const mask_len = extra.mask_len;

    const child_ty = inst_ty.child_type(mod);
    const elem_size = child_ty.abi_size(mod);

    // TODO: One of them could be by ref; handle in loop
    if (is_by_ref(func.type_of(extra.a), mod) or is_by_ref(inst_ty, mod)) {
        const result = try func.alloc_stack(inst_ty);

        for (0..mask_len) |index| {
            const value = (try mask.elem_value(mod, index)).to_signed_int(mod);

            try func.emit_wvalue(result);

            const loaded = if (value >= 0)
                try func.load(a, child_ty, @as(u32, @int_cast(@as(i64, @int_cast(elem_size)) * value)))
            else
                try func.load(b, child_ty, @as(u32, @int_cast(@as(i64, @int_cast(elem_size)) * ~value)));

            try func.store(.stack, loaded, child_ty, result.stack_offset.value + @as(u32, @int_cast(elem_size)) * @as(u32, @int_cast(index)));
        }

        return func.finish_air(inst, result, &.{ extra.a, extra.b });
    } else {
        var operands = [_]u32{
            std.wasm.simd_opcode(.i8x16_shuffle),
        } ++ [1]u32{undefined} ** 4;

        var lanes = mem.as_bytes(operands[1..]);
        for (0..@as(usize, @int_cast(mask_len))) |index| {
            const mask_elem = (try mask.elem_value(mod, index)).to_signed_int(mod);
            const base_index = if (mask_elem >= 0)
                @as(u8, @int_cast(@as(i64, @int_cast(elem_size)) * mask_elem))
            else
                16 + @as(u8, @int_cast(@as(i64, @int_cast(elem_size)) * ~mask_elem));

            for (0..@as(usize, @int_cast(elem_size))) |byte_offset| {
                lanes[index * @as(usize, @int_cast(elem_size)) + byte_offset] = base_index + @as(u8, @int_cast(byte_offset));
            }
        }

        try func.emit_wvalue(a);
        try func.emit_wvalue(b);

        const extra_index = @as(u32, @int_cast(func.mir_extra.items.len));
        try func.mir_extra.append_slice(func.gpa, &operands);
        try func.add_inst(.{ .tag = .simd_prefix, .data = .{ .payload = extra_index } });

        return func.finish_air(inst, try WValue.to_local(.stack, func, inst_ty), &.{ extra.a, extra.b });
    }
}

fn air_reduce(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const reduce = func.air.instructions.items(.data)[@int_from_enum(inst)].reduce;
    const operand = try func.resolve_inst(reduce.operand);

    _ = operand;
    return func.fail("TODO: Implement wasm air_reduce", .{});
}

fn air_aggregate_init(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const ip = &mod.intern_pool;
    const ty_pl = func.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const result_ty = func.type_of_index(inst);
    const len = @as(usize, @int_cast(result_ty.array_len(mod)));
    const elements = @as([]const Air.Inst.Ref, @ptr_cast(func.air.extra[ty_pl.payload..][0..len]));

    const result: WValue = result_value: {
        switch (result_ty.zig_type_tag(mod)) {
            .Array => {
                const result = try func.alloc_stack(result_ty);
                const elem_ty = result_ty.child_type(mod);
                const elem_size = @as(u32, @int_cast(elem_ty.abi_size(mod)));
                const sentinel = if (result_ty.sentinel(mod)) |sent| blk: {
                    break :blk try func.lower_constant(sent, elem_ty);
                } else null;

                // When the element type is by reference, we must copy the entire
                // value. It is therefore safer to move the offset pointer and store
                // each value individually, instead of using store offsets.
                if (is_by_ref(elem_ty, mod)) {
                    // copy stack pointer into a temporary local, which is
                    // moved for each element to store each value in the right position.
                    const offset = try func.build_pointer_offset(result, 0, .new);
                    for (elements, 0..) |elem, elem_index| {
                        const elem_val = try func.resolve_inst(elem);
                        try func.store(offset, elem_val, elem_ty, 0);

                        if (elem_index < elements.len - 1 and sentinel == null) {
                            _ = try func.build_pointer_offset(offset, elem_size, .modify);
                        }
                    }
                    if (sentinel) |sent| {
                        try func.store(offset, sent, elem_ty, 0);
                    }
                } else {
                    var offset: u32 = 0;
                    for (elements) |elem| {
                        const elem_val = try func.resolve_inst(elem);
                        try func.store(result, elem_val, elem_ty, offset);
                        offset += elem_size;
                    }
                    if (sentinel) |sent| {
                        try func.store(result, sent, elem_ty, offset);
                    }
                }
                break :result_value result;
            },
            .Struct => switch (result_ty.container_layout(mod)) {
                .@"packed" => {
                    if (is_by_ref(result_ty, mod)) {
                        return func.fail("TODO: air_aggregate_init for packed structs larger than 64 bits", .{});
                    }
                    const packed_struct = mod.type_to_packed_struct(result_ty).?;
                    const field_types = packed_struct.field_types;
                    const backing_type = Type.from_interned(packed_struct.backing_int_type(ip).*);

                    // ensure the result is zero'd
                    const result = try func.alloc_local(backing_type);
                    if (backing_type.bit_size(mod) <= 32)
                        try func.add_imm32(0)
                    else
                        try func.add_imm64(0);
                    try func.add_label(.local_set, result.local.value);

                    var current_bit: u16 = 0;
                    for (elements, 0..) |elem, elem_index| {
                        const field_ty = Type.from_interned(field_types.get(ip)[elem_index]);
                        if (!field_ty.has_runtime_bits_ignore_comptime(mod)) continue;

                        const shift_val = if (backing_type.bit_size(mod) <= 32)
                            WValue{ .imm32 = current_bit }
                        else
                            WValue{ .imm64 = current_bit };

                        const value = try func.resolve_inst(elem);
                        const value_bit_size: u16 = @int_cast(field_ty.bit_size(mod));
                        const int_ty = try mod.int_type(.unsigned, value_bit_size);

                        // load our current result on stack so we can perform all transformations
                        // using only stack values. Saving the cost of loads and stores.
                        try func.emit_wvalue(result);
                        const bitcasted = try func.bitcast(int_ty, field_ty, value);
                        const extended_val = try func.intcast(bitcasted, int_ty, backing_type);
                        // no need to shift any values when the current offset is 0
                        const shifted = if (current_bit != 0) shifted: {
                            break :shifted try func.bin_op(extended_val, shift_val, backing_type, .shl);
                        } else extended_val;
                        // we ignore the result as we keep it on the stack to assign it directly to `result`
                        _ = try func.bin_op(.stack, shifted, backing_type, .@"or");
                        try func.add_label(.local_set, result.local.value);
                        current_bit += value_bit_size;
                    }
                    break :result_value result;
                },
                else => {
                    const result = try func.alloc_stack(result_ty);
                    const offset = try func.build_pointer_offset(result, 0, .new); // pointer to offset
                    var prev_field_offset: u64 = 0;
                    for (elements, 0..) |elem, elem_index| {
                        if ((try result_ty.struct_field_value_comptime(mod, elem_index)) != null) continue;

                        const elem_ty = result_ty.struct_field_type(elem_index, mod);
                        const field_offset = result_ty.struct_field_offset(elem_index, mod);
                        _ = try func.build_pointer_offset(offset, @int_cast(field_offset - prev_field_offset), .modify);
                        prev_field_offset = field_offset;

                        const value = try func.resolve_inst(elem);
                        try func.store(offset, value, elem_ty, 0);
                    }

                    break :result_value result;
                },
            },
            .Vector => return func.fail("TODO: Wasm backend: implement air_aggregate_init for vectors", .{}),
            else => unreachable,
        }
    };

    if (elements.len <= Liveness.bpi - 1) {
        var buf = [1]Air.Inst.Ref{.none} ** (Liveness.bpi - 1);
        @memcpy(buf[0..elements.len], elements);
        return func.finish_air(inst, result, &buf);
    }
    var bt = try func.iterate_big_tomb(inst, elements.len);
    for (elements) |arg| bt.feed(arg);
    return bt.finish_air(result);
}

fn air_union_init(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const ip = &mod.intern_pool;
    const ty_pl = func.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = func.air.extra_data(Air.UnionInit, ty_pl.payload).data;

    const result = result: {
        const union_ty = func.type_of_index(inst);
        const layout = union_ty.union_get_layout(mod);
        const union_obj = mod.type_to_union(union_ty).?;
        const field_ty = Type.from_interned(union_obj.field_types.get(ip)[extra.field_index]);
        const field_name = union_obj.load_tag_type(ip).names.get(ip)[extra.field_index];

        const tag_int = blk: {
            const tag_ty = union_ty.union_tag_type_hypothetical(mod);
            const enum_field_index = tag_ty.enum_field_index(field_name, mod).?;
            const tag_val = try mod.enum_value_field_index(tag_ty, enum_field_index);
            break :blk try func.lower_constant(tag_val, tag_ty);
        };
        if (layout.payload_size == 0) {
            if (layout.tag_size == 0) {
                break :result WValue{ .none = {} };
            }
            assert(!is_by_ref(union_ty, mod));
            break :result tag_int;
        }

        if (is_by_ref(union_ty, mod)) {
            const result_ptr = try func.alloc_stack(union_ty);
            const payload = try func.resolve_inst(extra.init);
            if (layout.tag_align.compare(.gte, layout.payload_align)) {
                if (is_by_ref(field_ty, mod)) {
                    const payload_ptr = try func.build_pointer_offset(result_ptr, layout.tag_size, .new);
                    try func.store(payload_ptr, payload, field_ty, 0);
                } else {
                    try func.store(result_ptr, payload, field_ty, @int_cast(layout.tag_size));
                }

                if (layout.tag_size > 0) {
                    try func.store(result_ptr, tag_int, Type.from_interned(union_obj.enum_tag_ty), 0);
                }
            } else {
                try func.store(result_ptr, payload, field_ty, 0);
                if (layout.tag_size > 0) {
                    try func.store(
                        result_ptr,
                        tag_int,
                        Type.from_interned(union_obj.enum_tag_ty),
                        @int_cast(layout.payload_size),
                    );
                }
            }
            break :result result_ptr;
        } else {
            const operand = try func.resolve_inst(extra.init);
            const union_int_type = try mod.int_type(.unsigned, @as(u16, @int_cast(union_ty.bit_size(mod))));
            if (field_ty.zig_type_tag(mod) == .Float) {
                const int_type = try mod.int_type(.unsigned, @int_cast(field_ty.bit_size(mod)));
                const bitcasted = try func.bitcast(field_ty, int_type, operand);
                const casted = try func.trunc(bitcasted, int_type, union_int_type);
                break :result try casted.to_local(func, field_ty);
            } else if (field_ty.is_ptr_at_runtime(mod)) {
                const int_type = try mod.int_type(.unsigned, @int_cast(field_ty.bit_size(mod)));
                const casted = try func.intcast(operand, int_type, union_int_type);
                break :result try casted.to_local(func, field_ty);
            }
            const casted = try func.intcast(operand, field_ty, union_int_type);
            break :result try casted.to_local(func, field_ty);
        }
    };

    return func.finish_air(inst, result, &.{extra.init});
}

fn air_prefetch(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const prefetch = func.air.instructions.items(.data)[@int_from_enum(inst)].prefetch;
    func.finish_air(inst, .none, &.{prefetch.ptr});
}

fn air_wasm_memory_size(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const pl_op = func.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;

    const result = try func.alloc_local(func.type_of_index(inst));
    try func.add_label(.memory_size, pl_op.payload);
    try func.add_label(.local_set, result.local.value);
    func.finish_air(inst, result, &.{pl_op.operand});
}

fn air_wasm_memory_grow(func: *CodeGen, inst: Air.Inst.Index) !void {
    const pl_op = func.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;

    const operand = try func.resolve_inst(pl_op.operand);
    const result = try func.alloc_local(func.type_of_index(inst));
    try func.emit_wvalue(operand);
    try func.add_label(.memory_grow, pl_op.payload);
    try func.add_label(.local_set, result.local.value);
    func.finish_air(inst, result, &.{pl_op.operand});
}

fn cmp_optionals(func: *CodeGen, lhs: WValue, rhs: WValue, operand_ty: Type, op: std.math.CompareOperator) InnerError!WValue {
    const mod = func.bin_file.base.comp.module.?;
    assert(operand_ty.has_runtime_bits_ignore_comptime(mod));
    assert(op == .eq or op == .neq);
    const payload_ty = operand_ty.optional_child(mod);

    // We store the final result in here that will be validated
    // if the optional is truly equal.
    var result = try func.ensure_alloc_local(Type.i32);
    defer result.free(func);

    try func.start_block(.block, wasm.block_empty);
    _ = try func.is_null(lhs, operand_ty, .i32_eq);
    _ = try func.is_null(rhs, operand_ty, .i32_eq);
    try func.add_tag(.i32_ne); // inverse so we can exit early
    try func.add_label(.br_if, 0);

    _ = try func.load(lhs, payload_ty, 0);
    _ = try func.load(rhs, payload_ty, 0);
    const opcode = build_opcode(.{ .op = .ne, .valtype1 = type_to_valtype(payload_ty, mod) });
    try func.add_tag(Mir.Inst.Tag.from_opcode(opcode));
    try func.add_label(.br_if, 0);

    try func.add_imm32(1);
    try func.add_label(.local_set, result.local.value);
    try func.end_block();

    try func.emit_wvalue(result);
    try func.add_imm32(0);
    try func.add_tag(if (op == .eq) .i32_ne else .i32_eq);
    return WValue{ .stack = {} };
}

/// Compares big integers by checking both its high bits and low bits.
/// NOTE: Leaves the result of the comparison on top of the stack.
/// TODO: Lower this to compiler_rt call when bitsize > 128
fn cmp_big_int(func: *CodeGen, lhs: WValue, rhs: WValue, operand_ty: Type, op: std.math.CompareOperator) InnerError!WValue {
    const mod = func.bin_file.base.comp.module.?;
    assert(operand_ty.abi_size(mod) >= 16);
    assert(!(lhs != .stack and rhs == .stack));
    if (operand_ty.bit_size(mod) > 128) {
        return func.fail("TODO: Support cmp_big_int for integer bitsize: '{d}'", .{operand_ty.bit_size(mod)});
    }

    var lhs_high_bit = try (try func.load(lhs, Type.u64, 0)).to_local(func, Type.u64);
    defer lhs_high_bit.free(func);
    var rhs_high_bit = try (try func.load(rhs, Type.u64, 0)).to_local(func, Type.u64);
    defer rhs_high_bit.free(func);

    switch (op) {
        .eq, .neq => {
            const xor_high = try func.bin_op(lhs_high_bit, rhs_high_bit, Type.u64, .xor);
            const lhs_low_bit = try func.load(lhs, Type.u64, 8);
            const rhs_low_bit = try func.load(rhs, Type.u64, 8);
            const xor_low = try func.bin_op(lhs_low_bit, rhs_low_bit, Type.u64, .xor);
            const or_result = try func.bin_op(xor_high, xor_low, Type.u64, .@"or");

            switch (op) {
                .eq => return func.cmp(or_result, .{ .imm64 = 0 }, Type.u64, .eq),
                .neq => return func.cmp(or_result, .{ .imm64 = 0 }, Type.u64, .neq),
                else => unreachable,
            }
        },
        else => {
            const ty = if (operand_ty.is_signed_int(mod)) Type.i64 else Type.u64;
            // leave those value on top of the stack for '.select'
            const lhs_low_bit = try func.load(lhs, Type.u64, 8);
            const rhs_low_bit = try func.load(rhs, Type.u64, 8);
            _ = try func.cmp(lhs_low_bit, rhs_low_bit, ty, op);
            _ = try func.cmp(lhs_high_bit, rhs_high_bit, ty, op);
            _ = try func.cmp(lhs_high_bit, rhs_high_bit, ty, .eq);
            try func.add_tag(.select);
        },
    }

    return WValue{ .stack = {} };
}

fn air_set_union_tag(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const bin_op = func.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
    const un_ty = func.type_of(bin_op.lhs).child_type(mod);
    const tag_ty = func.type_of(bin_op.rhs);
    const layout = un_ty.union_get_layout(mod);
    if (layout.tag_size == 0) return func.finish_air(inst, .none, &.{ bin_op.lhs, bin_op.rhs });

    const union_ptr = try func.resolve_inst(bin_op.lhs);
    const new_tag = try func.resolve_inst(bin_op.rhs);
    if (layout.payload_size == 0) {
        try func.store(union_ptr, new_tag, tag_ty, 0);
        return func.finish_air(inst, .none, &.{ bin_op.lhs, bin_op.rhs });
    }

    // when the tag alignment is smaller than the payload, the field will be stored
    // after the payload.
    const offset: u32 = if (layout.tag_align.compare(.lt, layout.payload_align)) blk: {
        break :blk @int_cast(layout.payload_size);
    } else 0;
    try func.store(union_ptr, new_tag, tag_ty, offset);
    func.finish_air(inst, .none, &.{ bin_op.lhs, bin_op.rhs });
}

fn air_get_union_tag(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const ty_op = func.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

    const un_ty = func.type_of(ty_op.operand);
    const tag_ty = func.type_of_index(inst);
    const layout = un_ty.union_get_layout(mod);
    if (layout.tag_size == 0) return func.finish_air(inst, .none, &.{ty_op.operand});

    const operand = try func.resolve_inst(ty_op.operand);
    // when the tag alignment is smaller than the payload, the field will be stored
    // after the payload.
    const offset: u32 = if (layout.tag_align.compare(.lt, layout.payload_align)) blk: {
        break :blk @int_cast(layout.payload_size);
    } else 0;
    const tag = try func.load(operand, tag_ty, offset);
    const result = try tag.to_local(func, tag_ty);
    func.finish_air(inst, result, &.{ty_op.operand});
}

fn air_fpext(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const ty_op = func.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

    const dest_ty = func.type_of_index(inst);
    const operand = try func.resolve_inst(ty_op.operand);
    const extended = try func.fpext(operand, func.type_of(ty_op.operand), dest_ty);
    const result = try extended.to_local(func, dest_ty);
    func.finish_air(inst, result, &.{ty_op.operand});
}

/// Extends a float from a given `Type` to a larger wanted `Type`
/// NOTE: Leaves the result on the stack
fn fpext(func: *CodeGen, operand: WValue, given: Type, wanted: Type) InnerError!WValue {
    const given_bits = given.float_bits(func.target);
    const wanted_bits = wanted.float_bits(func.target);

    if (wanted_bits == 64 and given_bits == 32) {
        try func.emit_wvalue(operand);
        try func.add_tag(.f64_promote_f32);
        return WValue{ .stack = {} };
    } else if (given_bits == 16 and wanted_bits <= 64) {
        // call __extendhfsf2(f16) f32
        const f32_result = try func.call_intrinsic(
            "__extendhfsf2",
            &.{.f16_type},
            Type.f32,
            &.{operand},
        );
        std.debug.assert(f32_result == .stack);

        if (wanted_bits == 64) {
            try func.add_tag(.f64_promote_f32);
        }
        return WValue{ .stack = {} };
    }

    var fn_name_buf: [13]u8 = undefined;
    const fn_name = std.fmt.buf_print(&fn_name_buf, "__extend{s}f{s}f2", .{
        target_util.compiler_rt_float_abbrev(given_bits),
        target_util.compiler_rt_float_abbrev(wanted_bits),
    }) catch unreachable;

    return func.call_intrinsic(fn_name, &.{given.ip_index}, wanted, &.{operand});
}

fn air_fptrunc(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const ty_op = func.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

    const dest_ty = func.type_of_index(inst);
    const operand = try func.resolve_inst(ty_op.operand);
    const truncated = try func.fptrunc(operand, func.type_of(ty_op.operand), dest_ty);
    const result = try truncated.to_local(func, dest_ty);
    func.finish_air(inst, result, &.{ty_op.operand});
}

/// Truncates a float from a given `Type` to its wanted `Type`
/// NOTE: The result value remains on the stack
fn fptrunc(func: *CodeGen, operand: WValue, given: Type, wanted: Type) InnerError!WValue {
    const given_bits = given.float_bits(func.target);
    const wanted_bits = wanted.float_bits(func.target);

    if (wanted_bits == 32 and given_bits == 64) {
        try func.emit_wvalue(operand);
        try func.add_tag(.f32_demote_f64);
        return WValue{ .stack = {} };
    } else if (wanted_bits == 16 and given_bits <= 64) {
        const op: WValue = if (given_bits == 64) blk: {
            try func.emit_wvalue(operand);
            try func.add_tag(.f32_demote_f64);
            break :blk WValue{ .stack = {} };
        } else operand;

        // call __truncsfhf2(f32) f16
        return func.call_intrinsic("__truncsfhf2", &.{.f32_type}, Type.f16, &.{op});
    }

    var fn_name_buf: [12]u8 = undefined;
    const fn_name = std.fmt.buf_print(&fn_name_buf, "__trunc{s}f{s}f2", .{
        target_util.compiler_rt_float_abbrev(given_bits),
        target_util.compiler_rt_float_abbrev(wanted_bits),
    }) catch unreachable;

    return func.call_intrinsic(fn_name, &.{given.ip_index}, wanted, &.{operand});
}

fn air_err_union_payload_ptr_set(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const ty_op = func.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

    const err_set_ty = func.type_of(ty_op.operand).child_type(mod);
    const payload_ty = err_set_ty.error_union_payload(mod);
    const operand = try func.resolve_inst(ty_op.operand);

    // set error-tag to '0' to annotate error union is non-error
    try func.store(
        operand,
        .{ .imm32 = 0 },
        Type.anyerror,
        @as(u32, @int_cast(err_union_error_offset(payload_ty, mod))),
    );

    const result = result: {
        if (!payload_ty.has_runtime_bits_ignore_comptime(mod)) {
            break :result func.reuse_operand(ty_op.operand, operand);
        }

        break :result try func.build_pointer_offset(operand, @as(u32, @int_cast(err_union_payload_offset(payload_ty, mod))), .new);
    };
    func.finish_air(inst, result, &.{ty_op.operand});
}

fn air_field_parent_ptr(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const ty_pl = func.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = func.air.extra_data(Air.FieldParentPtr, ty_pl.payload).data;

    const field_ptr = try func.resolve_inst(extra.field_ptr);
    const parent_ty = ty_pl.ty.to_type().child_type(mod);
    const field_offset = parent_ty.struct_field_offset(extra.field_index, mod);

    const result = if (field_offset != 0) result: {
        const base = try func.build_pointer_offset(field_ptr, 0, .new);
        try func.add_label(.local_get, base.local.value);
        try func.add_imm32(@as(i32, @bit_cast(@as(u32, @int_cast(field_offset)))));
        try func.add_tag(.i32_sub);
        try func.add_label(.local_set, base.local.value);
        break :result base;
    } else func.reuse_operand(extra.field_ptr, field_ptr);

    func.finish_air(inst, result, &.{extra.field_ptr});
}

fn slice_or_array_ptr(func: *CodeGen, ptr: WValue, ptr_ty: Type) InnerError!WValue {
    const mod = func.bin_file.base.comp.module.?;
    if (ptr_ty.is_slice(mod)) {
        return func.slice_ptr(ptr);
    } else {
        return ptr;
    }
}

fn air_memcpy(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const bin_op = func.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
    const dst = try func.resolve_inst(bin_op.lhs);
    const dst_ty = func.type_of(bin_op.lhs);
    const ptr_elem_ty = dst_ty.child_type(mod);
    const src = try func.resolve_inst(bin_op.rhs);
    const src_ty = func.type_of(bin_op.rhs);
    const len = switch (dst_ty.ptr_size(mod)) {
        .Slice => blk: {
            const slice_len = try func.slice_len(dst);
            if (ptr_elem_ty.abi_size(mod) != 1) {
                try func.emit_wvalue(slice_len);
                try func.emit_wvalue(.{ .imm32 = @as(u32, @int_cast(ptr_elem_ty.abi_size(mod))) });
                try func.add_tag(.i32_mul);
                try func.add_label(.local_set, slice_len.local.value);
            }
            break :blk slice_len;
        },
        .One => @as(WValue, .{
            .imm32 = @as(u32, @int_cast(ptr_elem_ty.array_len(mod) * ptr_elem_ty.child_type(mod).abi_size(mod))),
        }),
        .C, .Many => unreachable,
    };
    const dst_ptr = try func.slice_or_array_ptr(dst, dst_ty);
    const src_ptr = try func.slice_or_array_ptr(src, src_ty);
    try func.memcpy(dst_ptr, src_ptr, len);

    func.finish_air(inst, .none, &.{ bin_op.lhs, bin_op.rhs });
}

fn air_ret_addr(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    // TODO: Implement this properly once stack serialization is solved
    func.finish_air(inst, switch (func.arch()) {
        .wasm32 => .{ .imm32 = 0 },
        .wasm64 => .{ .imm64 = 0 },
        else => unreachable,
    }, &.{});
}

fn air_popcount(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const ty_op = func.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

    const operand = try func.resolve_inst(ty_op.operand);
    const op_ty = func.type_of(ty_op.operand);
    const result_ty = func.type_of_index(inst);

    if (op_ty.zig_type_tag(mod) == .Vector) {
        return func.fail("TODO: Implement @pop_count for vectors", .{});
    }

    const int_info = op_ty.int_info(mod);
    const bits = int_info.bits;
    const wasm_bits = to_wasm_bits(bits) orelse {
        return func.fail("TODO: Implement @pop_count for integers with bitsize '{d}'", .{bits});
    };

    switch (wasm_bits) {
        128 => {
            _ = try func.load(operand, Type.u64, 0);
            try func.add_tag(.i64_popcnt);
            _ = try func.load(operand, Type.u64, 8);
            try func.add_tag(.i64_popcnt);
            try func.add_tag(.i64_add);
            try func.add_tag(.i32_wrap_i64);
        },
        else => {
            try func.emit_wvalue(operand);
            switch (wasm_bits) {
                32 => try func.add_tag(.i32_popcnt),
                64 => {
                    try func.add_tag(.i64_popcnt);
                    try func.add_tag(.i32_wrap_i64);
                },
                else => unreachable,
            }
        },
    }

    const result = try func.alloc_local(result_ty);
    try func.add_label(.local_set, result.local.value);
    func.finish_air(inst, result, &.{ty_op.operand});
}

fn air_error_name(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const un_op = func.air.instructions.items(.data)[@int_from_enum(inst)].un_op;

    const operand = try func.resolve_inst(un_op);
    // First retrieve the symbol index to the error name table
    // that will be used to emit a relocation for the pointer
    // to the error name table.
    //
    // Each entry to this table is a slice (ptr+len).
    // The operand in this instruction represents the index within this table.
    // This means to get the final name, we emit the base pointer and then perform
    // pointer arithmetic to find the pointer to this slice and return that.
    //
    // As the names are global and the slice elements are constant, we do not have
    // to make a copy of the ptr+value but can point towards them directly.
    const error_table_symbol = try func.bin_file.get_error_table_symbol();
    const name_ty = Type.slice_const_u8_sentinel_0;
    const mod = func.bin_file.base.comp.module.?;
    const abi_size = name_ty.abi_size(mod);

    const error_name_value: WValue = .{ .memory = error_table_symbol }; // emitting this will create a relocation
    try func.emit_wvalue(error_name_value);
    try func.emit_wvalue(operand);
    switch (func.arch()) {
        .wasm32 => {
            try func.add_imm32(@as(i32, @bit_cast(@as(u32, @int_cast(abi_size)))));
            try func.add_tag(.i32_mul);
            try func.add_tag(.i32_add);
        },
        .wasm64 => {
            try func.add_imm64(abi_size);
            try func.add_tag(.i64_mul);
            try func.add_tag(.i64_add);
        },
        else => unreachable,
    }

    const result_ptr = try func.alloc_local(Type.usize);
    try func.add_label(.local_set, result_ptr.local.value);
    func.finish_air(inst, result_ptr, &.{un_op});
}

fn air_ptr_slice_field_ptr(func: *CodeGen, inst: Air.Inst.Index, offset: u32) InnerError!void {
    const ty_op = func.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const slice_ptr = try func.resolve_inst(ty_op.operand);
    const result = try func.build_pointer_offset(slice_ptr, offset, .new);
    func.finish_air(inst, result, &.{ty_op.operand});
}

fn air_add_sub_with_overflow(func: *CodeGen, inst: Air.Inst.Index, op: Op) InnerError!void {
    assert(op == .add or op == .sub);
    const ty_pl = func.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = func.air.extra_data(Air.Bin, ty_pl.payload).data;

    const lhs_op = try func.resolve_inst(extra.lhs);
    const rhs_op = try func.resolve_inst(extra.rhs);
    const lhs_ty = func.type_of(extra.lhs);
    const mod = func.bin_file.base.comp.module.?;

    if (lhs_ty.zig_type_tag(mod) == .Vector) {
        return func.fail("TODO: Implement overflow arithmetic for vectors", .{});
    }

    const int_info = lhs_ty.int_info(mod);
    const is_signed = int_info.signedness == .signed;
    const wasm_bits = to_wasm_bits(int_info.bits) orelse {
        return func.fail("TODO: Implement {{add/sub}}_with_overflow for integer bitsize: {d}", .{int_info.bits});
    };

    if (wasm_bits == 128) {
        const result = try func.add_sub_with_overflow_big_int(lhs_op, rhs_op, lhs_ty, func.type_of_index(inst), op);
        return func.finish_air(inst, result, &.{ extra.lhs, extra.rhs });
    }

    const zero = switch (wasm_bits) {
        32 => WValue{ .imm32 = 0 },
        64 => WValue{ .imm64 = 0 },
        else => unreachable,
    };

    // for signed integers, we first apply signed shifts by the difference in bits
    // to get the signed value, as we store it internally as 2's complement.
    var lhs = if (wasm_bits != int_info.bits and is_signed) blk: {
        break :blk try (try func.sign_extend_int(lhs_op, lhs_ty)).to_local(func, lhs_ty);
    } else lhs_op;
    var rhs = if (wasm_bits != int_info.bits and is_signed) blk: {
        break :blk try (try func.sign_extend_int(rhs_op, lhs_ty)).to_local(func, lhs_ty);
    } else rhs_op;

    // in this case, we performed a sign_extend_int which created a temporary local
    // so let's free this so it can be re-used instead.
    // In the other case we do not want to free it, because that would free the
    // resolved instructions which may be referenced by other instructions.
    defer if (wasm_bits != int_info.bits and is_signed) {
        lhs.free(func);
        rhs.free(func);
    };

    const bin_op = try (try func.bin_op(lhs, rhs, lhs_ty, op)).to_local(func, lhs_ty);
    var result = if (wasm_bits != int_info.bits) blk: {
        break :blk try (try func.wrap_operand(bin_op, lhs_ty)).to_local(func, lhs_ty);
    } else bin_op;
    defer result.free(func);

    const cmp_op: std.math.CompareOperator = if (op == .sub) .gt else .lt;
    const overflow_bit: WValue = if (is_signed) blk: {
        if (wasm_bits == int_info.bits) {
            const cmp_zero = try func.cmp(rhs, zero, lhs_ty, cmp_op);
            const lt = try func.cmp(bin_op, lhs, lhs_ty, .lt);
            break :blk try func.bin_op(cmp_zero, lt, Type.u32, .xor);
        }
        const abs = try func.sign_extend_int(bin_op, lhs_ty);
        break :blk try func.cmp(abs, bin_op, lhs_ty, .neq);
    } else if (wasm_bits == int_info.bits)
        try func.cmp(bin_op, lhs, lhs_ty, cmp_op)
    else
        try func.cmp(bin_op, result, lhs_ty, .neq);
    var overflow_local = try overflow_bit.to_local(func, Type.u32);
    defer overflow_local.free(func);

    const result_ptr = try func.alloc_stack(func.type_of_index(inst));
    try func.store(result_ptr, result, lhs_ty, 0);
    const offset = @as(u32, @int_cast(lhs_ty.abi_size(mod)));
    try func.store(result_ptr, overflow_local, Type.u1, offset);

    func.finish_air(inst, result_ptr, &.{ extra.lhs, extra.rhs });
}

fn add_sub_with_overflow_big_int(func: *CodeGen, lhs: WValue, rhs: WValue, ty: Type, result_ty: Type, op: Op) InnerError!WValue {
    const mod = func.bin_file.base.comp.module.?;
    assert(op == .add or op == .sub);
    const int_info = ty.int_info(mod);
    const is_signed = int_info.signedness == .signed;
    if (int_info.bits != 128) {
        return func.fail("TODO: Implement @{{add/sub}}WithOverflow for integer bitsize '{d}'", .{int_info.bits});
    }

    var lhs_high_bit = try (try func.load(lhs, Type.u64, 0)).to_local(func, Type.u64);
    defer lhs_high_bit.free(func);
    var lhs_low_bit = try (try func.load(lhs, Type.u64, 8)).to_local(func, Type.u64);
    defer lhs_low_bit.free(func);
    var rhs_high_bit = try (try func.load(rhs, Type.u64, 0)).to_local(func, Type.u64);
    defer rhs_high_bit.free(func);
    var rhs_low_bit = try (try func.load(rhs, Type.u64, 8)).to_local(func, Type.u64);
    defer rhs_low_bit.free(func);

    var low_op_res = try (try func.bin_op(lhs_low_bit, rhs_low_bit, Type.u64, op)).to_local(func, Type.u64);
    defer low_op_res.free(func);
    var high_op_res = try (try func.bin_op(lhs_high_bit, rhs_high_bit, Type.u64, op)).to_local(func, Type.u64);
    defer high_op_res.free(func);

    var lt = if (op == .add) blk: {
        break :blk try (try func.cmp(high_op_res, lhs_high_bit, Type.u64, .lt)).to_local(func, Type.u32);
    } else if (op == .sub) blk: {
        break :blk try (try func.cmp(lhs_high_bit, rhs_high_bit, Type.u64, .lt)).to_local(func, Type.u32);
    } else unreachable;
    defer lt.free(func);
    var tmp = try (try func.intcast(lt, Type.u32, Type.u64)).to_local(func, Type.u64);
    defer tmp.free(func);
    var tmp_op = try (try func.bin_op(low_op_res, tmp, Type.u64, op)).to_local(func, Type.u64);
    defer tmp_op.free(func);

    const overflow_bit = if (is_signed) blk: {
        const xor_low = try func.bin_op(lhs_low_bit, rhs_low_bit, Type.u64, .xor);
        const to_wrap = if (op == .add) wrap: {
            break :wrap try func.bin_op(xor_low, .{ .imm64 = ~@as(u64, 0) }, Type.u64, .xor);
        } else xor_low;
        const xor_op = try func.bin_op(lhs_low_bit, tmp_op, Type.u64, .xor);
        const wrap = try func.bin_op(to_wrap, xor_op, Type.u64, .@"and");
        break :blk try func.cmp(wrap, .{ .imm64 = 0 }, Type.i64, .lt); // i64 because signed
    } else blk: {
        const first_arg = if (op == .sub) arg: {
            break :arg try func.cmp(high_op_res, lhs_high_bit, Type.u64, .gt);
        } else lt;

        try func.emit_wvalue(first_arg);
        _ = try func.cmp(tmp_op, lhs_low_bit, Type.u64, if (op == .add) .lt else .gt);
        _ = try func.cmp(tmp_op, lhs_low_bit, Type.u64, .eq);
        try func.add_tag(.select);

        break :blk WValue{ .stack = {} };
    };
    var overflow_local = try overflow_bit.to_local(func, Type.u1);
    defer overflow_local.free(func);

    const result_ptr = try func.alloc_stack(result_ty);
    try func.store(result_ptr, high_op_res, Type.u64, 0);
    try func.store(result_ptr, tmp_op, Type.u64, 8);
    try func.store(result_ptr, overflow_local, Type.u1, 16);

    return result_ptr;
}

fn air_shl_with_overflow(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const ty_pl = func.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = func.air.extra_data(Air.Bin, ty_pl.payload).data;

    const lhs = try func.resolve_inst(extra.lhs);
    const rhs = try func.resolve_inst(extra.rhs);
    const lhs_ty = func.type_of(extra.lhs);
    const rhs_ty = func.type_of(extra.rhs);

    if (lhs_ty.zig_type_tag(mod) == .Vector) {
        return func.fail("TODO: Implement overflow arithmetic for vectors", .{});
    }

    const int_info = lhs_ty.int_info(mod);
    const is_signed = int_info.signedness == .signed;
    const wasm_bits = to_wasm_bits(int_info.bits) orelse {
        return func.fail("TODO: Implement shl_with_overflow for integer bitsize: {d}", .{int_info.bits});
    };

    // Ensure rhs is coerced to lhs as they must have the same WebAssembly types
    // before we can perform any binary operation.
    const rhs_wasm_bits = to_wasm_bits(rhs_ty.int_info(mod).bits).?;
    const rhs_final = if (wasm_bits != rhs_wasm_bits) blk: {
        const rhs_casted = try func.intcast(rhs, rhs_ty, lhs_ty);
        break :blk try rhs_casted.to_local(func, lhs_ty);
    } else rhs;

    var shl = try (try func.bin_op(lhs, rhs_final, lhs_ty, .shl)).to_local(func, lhs_ty);
    defer shl.free(func);
    var result = if (wasm_bits != int_info.bits) blk: {
        break :blk try (try func.wrap_operand(shl, lhs_ty)).to_local(func, lhs_ty);
    } else shl;
    defer result.free(func); // it's a no-op to free the same local twice (when wasm_bits == int_info.bits)

    const overflow_bit = if (wasm_bits != int_info.bits and is_signed) blk: {
        // emit lhs to stack to we can keep 'wrapped' on the stack also
        try func.emit_wvalue(lhs);
        const abs = try func.sign_extend_int(shl, lhs_ty);
        const wrapped = try func.wrap_bin_op(abs, rhs_final, lhs_ty, .shr);
        break :blk try func.cmp(.{ .stack = {} }, wrapped, lhs_ty, .neq);
    } else blk: {
        try func.emit_wvalue(lhs);
        const shr = try func.bin_op(result, rhs_final, lhs_ty, .shr);
        break :blk try func.cmp(.{ .stack = {} }, shr, lhs_ty, .neq);
    };
    var overflow_local = try overflow_bit.to_local(func, Type.u1);
    defer overflow_local.free(func);

    const result_ptr = try func.alloc_stack(func.type_of_index(inst));
    try func.store(result_ptr, result, lhs_ty, 0);
    const offset = @as(u32, @int_cast(lhs_ty.abi_size(mod)));
    try func.store(result_ptr, overflow_local, Type.u1, offset);

    func.finish_air(inst, result_ptr, &.{ extra.lhs, extra.rhs });
}

fn air_mul_with_overflow(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const ty_pl = func.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = func.air.extra_data(Air.Bin, ty_pl.payload).data;

    const lhs = try func.resolve_inst(extra.lhs);
    const rhs = try func.resolve_inst(extra.rhs);
    const lhs_ty = func.type_of(extra.lhs);
    const mod = func.bin_file.base.comp.module.?;

    if (lhs_ty.zig_type_tag(mod) == .Vector) {
        return func.fail("TODO: Implement overflow arithmetic for vectors", .{});
    }

    // We store the bit if it's overflowed or not in this. As it's zero-initialized
    // we only need to update it if an overflow (or underflow) occurred.
    var overflow_bit = try func.ensure_alloc_local(Type.u1);
    defer overflow_bit.free(func);

    const int_info = lhs_ty.int_info(mod);
    const wasm_bits = to_wasm_bits(int_info.bits) orelse {
        return func.fail("TODO: Implement `@mulWithOverflow` for integer bitsize: {d}", .{int_info.bits});
    };

    const zero = switch (wasm_bits) {
        32 => WValue{ .imm32 = 0 },
        64, 128 => WValue{ .imm64 = 0 },
        else => unreachable,
    };

    // for 32 bit integers we upcast it to a 64bit integer
    const bin_op = if (int_info.bits == 32) blk: {
        const new_ty = if (int_info.signedness == .signed) Type.i64 else Type.u64;
        const lhs_upcast = try func.intcast(lhs, lhs_ty, new_ty);
        const rhs_upcast = try func.intcast(rhs, lhs_ty, new_ty);
        const bin_op = try (try func.bin_op(lhs_upcast, rhs_upcast, new_ty, .mul)).to_local(func, new_ty);
        if (int_info.signedness == .unsigned) {
            const shr = try func.bin_op(bin_op, .{ .imm64 = int_info.bits }, new_ty, .shr);
            const wrap = try func.intcast(shr, new_ty, lhs_ty);
            _ = try func.cmp(wrap, zero, lhs_ty, .neq);
            try func.add_label(.local_set, overflow_bit.local.value);
            break :blk try func.intcast(bin_op, new_ty, lhs_ty);
        } else {
            const down_cast = try (try func.intcast(bin_op, new_ty, lhs_ty)).to_local(func, lhs_ty);
            var shr = try (try func.bin_op(down_cast, .{ .imm32 = int_info.bits - 1 }, lhs_ty, .shr)).to_local(func, lhs_ty);
            defer shr.free(func);

            const shr_res = try func.bin_op(bin_op, .{ .imm64 = int_info.bits }, new_ty, .shr);
            const down_shr_res = try func.intcast(shr_res, new_ty, lhs_ty);
            _ = try func.cmp(down_shr_res, shr, lhs_ty, .neq);
            try func.add_label(.local_set, overflow_bit.local.value);
            break :blk down_cast;
        }
    } else if (int_info.signedness == .signed and wasm_bits == 32) blk: {
        const lhs_abs = try func.sign_extend_int(lhs, lhs_ty);
        const rhs_abs = try func.sign_extend_int(rhs, lhs_ty);
        const bin_op = try (try func.bin_op(lhs_abs, rhs_abs, lhs_ty, .mul)).to_local(func, lhs_ty);
        const mul_abs = try func.sign_extend_int(bin_op, lhs_ty);
        _ = try func.cmp(mul_abs, bin_op, lhs_ty, .neq);
        try func.add_label(.local_set, overflow_bit.local.value);
        break :blk try func.wrap_operand(bin_op, lhs_ty);
    } else if (wasm_bits == 32) blk: {
        var bin_op = try (try func.bin_op(lhs, rhs, lhs_ty, .mul)).to_local(func, lhs_ty);
        defer bin_op.free(func);
        const shift_imm = if (wasm_bits == 32)
            WValue{ .imm32 = int_info.bits }
        else
            WValue{ .imm64 = int_info.bits };
        const shr = try func.bin_op(bin_op, shift_imm, lhs_ty, .shr);
        _ = try func.cmp(shr, zero, lhs_ty, .neq);
        try func.add_label(.local_set, overflow_bit.local.value);
        break :blk try func.wrap_operand(bin_op, lhs_ty);
    } else if (int_info.bits == 64 and int_info.signedness == .unsigned) blk: {
        const new_ty = Type.u128;
        var lhs_upcast = try (try func.intcast(lhs, lhs_ty, new_ty)).to_local(func, lhs_ty);
        defer lhs_upcast.free(func);
        var rhs_upcast = try (try func.intcast(rhs, lhs_ty, new_ty)).to_local(func, lhs_ty);
        defer rhs_upcast.free(func);
        const bin_op = try func.bin_op(lhs_upcast, rhs_upcast, new_ty, .mul);
        const lsb = try func.load(bin_op, lhs_ty, 8);
        _ = try func.cmp(lsb, zero, lhs_ty, .neq);
        try func.add_label(.local_set, overflow_bit.local.value);

        break :blk try func.load(bin_op, lhs_ty, 0);
    } else if (int_info.bits == 64 and int_info.signedness == .signed) blk: {
        const shift_val: WValue = .{ .imm64 = 63 };
        var lhs_shifted = try (try func.bin_op(lhs, shift_val, lhs_ty, .shr)).to_local(func, lhs_ty);
        defer lhs_shifted.free(func);
        var rhs_shifted = try (try func.bin_op(rhs, shift_val, lhs_ty, .shr)).to_local(func, lhs_ty);
        defer rhs_shifted.free(func);

        const bin_op = try func.call_intrinsic(
            "__multi3",
            &[_]InternPool.Index{.i64_type} ** 4,
            Type.i128,
            &.{ lhs, lhs_shifted, rhs, rhs_shifted },
        );
        const res = try func.alloc_local(lhs_ty);
        const msb = try func.load(bin_op, lhs_ty, 0);
        try func.add_label(.local_tee, res.local.value);
        const msb_shifted = try func.bin_op(msb, shift_val, lhs_ty, .shr);
        const lsb = try func.load(bin_op, lhs_ty, 8);
        _ = try func.cmp(lsb, msb_shifted, lhs_ty, .neq);
        try func.add_label(.local_set, overflow_bit.local.value);
        break :blk res;
    } else if (int_info.bits == 128 and int_info.signedness == .unsigned) blk: {
        var lhs_msb = try (try func.load(lhs, Type.u64, 0)).to_local(func, Type.u64);
        defer lhs_msb.free(func);
        var lhs_lsb = try (try func.load(lhs, Type.u64, 8)).to_local(func, Type.u64);
        defer lhs_lsb.free(func);
        var rhs_msb = try (try func.load(rhs, Type.u64, 0)).to_local(func, Type.u64);
        defer rhs_msb.free(func);
        var rhs_lsb = try (try func.load(rhs, Type.u64, 8)).to_local(func, Type.u64);
        defer rhs_lsb.free(func);

        const mul1 = try func.call_intrinsic(
            "__multi3",
            &[_]InternPool.Index{.i64_type} ** 4,
            Type.i128,
            &.{ lhs_lsb, zero, rhs_msb, zero },
        );
        const mul2 = try func.call_intrinsic(
            "__multi3",
            &[_]InternPool.Index{.i64_type} ** 4,
            Type.i128,
            &.{ rhs_lsb, zero, lhs_msb, zero },
        );
        const mul3 = try func.call_intrinsic(
            "__multi3",
            &[_]InternPool.Index{.i64_type} ** 4,
            Type.i128,
            &.{ lhs_msb, zero, rhs_msb, zero },
        );

        const rhs_lsb_not_zero = try func.cmp(rhs_lsb, zero, Type.u64, .neq);
        const lhs_lsb_not_zero = try func.cmp(lhs_lsb, zero, Type.u64, .neq);
        const lsb_and = try func.bin_op(rhs_lsb_not_zero, lhs_lsb_not_zero, Type.bool, .@"and");
        const mul1_lsb = try func.load(mul1, Type.u64, 8);
        const mul1_lsb_not_zero = try func.cmp(mul1_lsb, zero, Type.u64, .neq);
        const lsb_or1 = try func.bin_op(lsb_and, mul1_lsb_not_zero, Type.bool, .@"or");
        const mul2_lsb = try func.load(mul2, Type.u64, 8);
        const mul2_lsb_not_zero = try func.cmp(mul2_lsb, zero, Type.u64, .neq);
        const lsb_or = try func.bin_op(lsb_or1, mul2_lsb_not_zero, Type.bool, .@"or");

        const mul1_msb = try func.load(mul1, Type.u64, 0);
        const mul2_msb = try func.load(mul2, Type.u64, 0);
        const mul_add1 = try func.bin_op(mul1_msb, mul2_msb, Type.u64, .add);

        var mul3_lsb = try (try func.load(mul3, Type.u64, 8)).to_local(func, Type.u64);
        defer mul3_lsb.free(func);
        var mul_add2 = try (try func.bin_op(mul_add1, mul3_lsb, Type.u64, .add)).to_local(func, Type.u64);
        defer mul_add2.free(func);
        const mul_add_lt = try func.cmp(mul_add2, mul3_lsb, Type.u64, .lt);

        // result for overflow bit
        _ = try func.bin_op(lsb_or, mul_add_lt, Type.bool, .@"or");
        try func.add_label(.local_set, overflow_bit.local.value);

        const tmp_result = try func.alloc_stack(Type.u128);
        try func.emit_wvalue(tmp_result);
        const mul3_msb = try func.load(mul3, Type.u64, 0);
        try func.store(.stack, mul3_msb, Type.u64, tmp_result.offset());
        try func.store(tmp_result, mul_add2, Type.u64, 8);
        break :blk tmp_result;
    } else return func.fail("TODO: @mulWithOverflow for integers between 32 and 64 bits", .{});
    var bin_op_local = try bin_op.to_local(func, lhs_ty);
    defer bin_op_local.free(func);

    const result_ptr = try func.alloc_stack(func.type_of_index(inst));
    try func.store(result_ptr, bin_op_local, lhs_ty, 0);
    const offset = @as(u32, @int_cast(lhs_ty.abi_size(mod)));
    try func.store(result_ptr, overflow_bit, Type.u1, offset);

    func.finish_air(inst, result_ptr, &.{ extra.lhs, extra.rhs });
}

fn air_max_min(func: *CodeGen, inst: Air.Inst.Index, op: Op) InnerError!void {
    assert(op == .max or op == .min);
    const mod = func.bin_file.base.comp.module.?;
    const target = mod.get_target();
    const bin_op = func.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;

    const ty = func.type_of_index(inst);
    if (ty.zig_type_tag(mod) == .Vector) {
        return func.fail("TODO: `@maximum` and `@minimum` for vectors", .{});
    }

    if (ty.abi_size(mod) > 16) {
        return func.fail("TODO: `@maximum` and `@minimum` for types larger than 16 bytes", .{});
    }

    const lhs = try func.resolve_inst(bin_op.lhs);
    const rhs = try func.resolve_inst(bin_op.rhs);

    if (ty.zig_type_tag(mod) == .Float) {
        var fn_name_buf: [64]u8 = undefined;
        const float_bits = ty.float_bits(target);
        const fn_name = std.fmt.buf_print(&fn_name_buf, "{s}f{s}{s}", .{
            target_util.libc_float_prefix(float_bits),
            @tag_name(op),
            target_util.libc_float_suffix(float_bits),
        }) catch unreachable;
        const result = try func.call_intrinsic(fn_name, &.{ ty.ip_index, ty.ip_index }, ty, &.{ lhs, rhs });
        try func.lower_to_stack(result);
    } else {
        // operands to select from
        try func.lower_to_stack(lhs);
        try func.lower_to_stack(rhs);
        _ = try func.cmp(lhs, rhs, ty, if (op == .max) .gt else .lt);

        // based on the result from comparison, return operand 0 or 1.
        try func.add_tag(.select);
    }

    // store result in local
    const result_ty = if (is_by_ref(ty, mod)) Type.u32 else ty;
    const result = try func.alloc_local(result_ty);
    try func.add_label(.local_set, result.local.value);
    func.finish_air(inst, result, &.{ bin_op.lhs, bin_op.rhs });
}

fn air_mul_add(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const pl_op = func.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
    const bin_op = func.air.extra_data(Air.Bin, pl_op.payload).data;

    const ty = func.type_of_index(inst);
    if (ty.zig_type_tag(mod) == .Vector) {
        return func.fail("TODO: `@mul_add` for vectors", .{});
    }

    const addend = try func.resolve_inst(pl_op.operand);
    const lhs = try func.resolve_inst(bin_op.lhs);
    const rhs = try func.resolve_inst(bin_op.rhs);

    const result = if (ty.float_bits(func.target) == 16) fl_result: {
        const rhs_ext = try func.fpext(rhs, ty, Type.f32);
        const lhs_ext = try func.fpext(lhs, ty, Type.f32);
        const addend_ext = try func.fpext(addend, ty, Type.f32);
        // call to compiler-rt `fn fmaf(f32, f32, f32) f32`
        const result = try func.call_intrinsic(
            "fmaf",
            &.{ .f32_type, .f32_type, .f32_type },
            Type.f32,
            &.{ rhs_ext, lhs_ext, addend_ext },
        );
        break :fl_result try (try func.fptrunc(result, Type.f32, ty)).to_local(func, ty);
    } else result: {
        const mul_result = try func.bin_op(lhs, rhs, ty, .mul);
        break :result try (try func.bin_op(mul_result, addend, ty, .add)).to_local(func, ty);
    };

    func.finish_air(inst, result, &.{ bin_op.lhs, bin_op.rhs, pl_op.operand });
}

fn air_clz(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const ty_op = func.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

    const ty = func.type_of(ty_op.operand);
    const result_ty = func.type_of_index(inst);
    if (ty.zig_type_tag(mod) == .Vector) {
        return func.fail("TODO: `@clz` for vectors", .{});
    }

    const operand = try func.resolve_inst(ty_op.operand);
    const int_info = ty.int_info(mod);
    const wasm_bits = to_wasm_bits(int_info.bits) orelse {
        return func.fail("TODO: `@clz` for integers with bitsize '{d}'", .{int_info.bits});
    };

    switch (wasm_bits) {
        32 => {
            try func.emit_wvalue(operand);
            try func.add_tag(.i32_clz);
        },
        64 => {
            try func.emit_wvalue(operand);
            try func.add_tag(.i64_clz);
            try func.add_tag(.i32_wrap_i64);
        },
        128 => {
            var lsb = try (try func.load(operand, Type.u64, 8)).to_local(func, Type.u64);
            defer lsb.free(func);

            try func.emit_wvalue(lsb);
            try func.add_tag(.i64_clz);
            _ = try func.load(operand, Type.u64, 0);
            try func.add_tag(.i64_clz);
            try func.emit_wvalue(.{ .imm64 = 64 });
            try func.add_tag(.i64_add);
            _ = try func.cmp(lsb, .{ .imm64 = 0 }, Type.u64, .neq);
            try func.add_tag(.select);
            try func.add_tag(.i32_wrap_i64);
        },
        else => unreachable,
    }

    if (wasm_bits != int_info.bits) {
        try func.emit_wvalue(.{ .imm32 = wasm_bits - int_info.bits });
        try func.add_tag(.i32_sub);
    }

    const result = try func.alloc_local(result_ty);
    try func.add_label(.local_set, result.local.value);
    func.finish_air(inst, result, &.{ty_op.operand});
}

fn air_ctz(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const ty_op = func.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

    const ty = func.type_of(ty_op.operand);
    const result_ty = func.type_of_index(inst);

    if (ty.zig_type_tag(mod) == .Vector) {
        return func.fail("TODO: `@ctz` for vectors", .{});
    }

    const operand = try func.resolve_inst(ty_op.operand);
    const int_info = ty.int_info(mod);
    const wasm_bits = to_wasm_bits(int_info.bits) orelse {
        return func.fail("TODO: `@clz` for integers with bitsize '{d}'", .{int_info.bits});
    };

    switch (wasm_bits) {
        32 => {
            if (wasm_bits != int_info.bits) {
                const val: u32 = @as(u32, 1) << @as(u5, @int_cast(int_info.bits));
                // leave value on the stack
                _ = try func.bin_op(operand, .{ .imm32 = val }, ty, .@"or");
            } else try func.emit_wvalue(operand);
            try func.add_tag(.i32_ctz);
        },
        64 => {
            if (wasm_bits != int_info.bits) {
                const val: u64 = @as(u64, 1) << @as(u6, @int_cast(int_info.bits));
                // leave value on the stack
                _ = try func.bin_op(operand, .{ .imm64 = val }, ty, .@"or");
            } else try func.emit_wvalue(operand);
            try func.add_tag(.i64_ctz);
            try func.add_tag(.i32_wrap_i64);
        },
        128 => {
            var msb = try (try func.load(operand, Type.u64, 0)).to_local(func, Type.u64);
            defer msb.free(func);

            try func.emit_wvalue(msb);
            try func.add_tag(.i64_ctz);
            _ = try func.load(operand, Type.u64, 8);
            if (wasm_bits != int_info.bits) {
                try func.add_imm64(@as(u64, 1) << @as(u6, @int_cast(int_info.bits - 64)));
                try func.add_tag(.i64_or);
            }
            try func.add_tag(.i64_ctz);
            try func.add_imm64(64);
            if (wasm_bits != int_info.bits) {
                try func.add_tag(.i64_or);
            } else {
                try func.add_tag(.i64_add);
            }
            _ = try func.cmp(msb, .{ .imm64 = 0 }, Type.u64, .neq);
            try func.add_tag(.select);
            try func.add_tag(.i32_wrap_i64);
        },
        else => unreachable,
    }

    const result = try func.alloc_local(result_ty);
    try func.add_label(.local_set, result.local.value);
    func.finish_air(inst, result, &.{ty_op.operand});
}

fn air_dbg_stmt(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    if (func.debug_output != .dwarf) return func.finish_air(inst, .none, &.{});

    const dbg_stmt = func.air.instructions.items(.data)[@int_from_enum(inst)].dbg_stmt;
    try func.add_inst(.{ .tag = .dbg_line, .data = .{
        .payload = try func.add_extra(Mir.DbgLineColumn{
            .line = dbg_stmt.line,
            .column = dbg_stmt.column,
        }),
    } });
    func.finish_air(inst, .none, &.{});
}

fn air_dbg_inline_block(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const ty_pl = func.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = func.air.extra_data(Air.DbgInlineBlock, ty_pl.payload);
    // TODO
    try func.lower_block(inst, ty_pl.ty.to_type(), @ptr_cast(func.air.extra[extra.end..][0..extra.data.body_len]));
}

fn air_dbg_var(func: *CodeGen, inst: Air.Inst.Index, is_ptr: bool) InnerError!void {
    if (func.debug_output != .dwarf) return func.finish_air(inst, .none, &.{});

    const mod = func.bin_file.base.comp.module.?;
    const pl_op = func.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
    const ty = func.type_of(pl_op.operand);
    const operand = try func.resolve_inst(pl_op.operand);

    log.debug("air_dbg_var: %{d}: {}, {}", .{ inst, ty.fmt_debug(), operand });

    const name = func.air.null_terminated_string(pl_op.payload);
    log.debug(" var name = ({s})", .{name});

    const loc: link.File.Dwarf.DeclState.DbgInfoLoc = switch (operand) {
        .local => |local| .{ .wasm_local = local.value },
        else => blk: {
            log.debug("TODO generate debug info for {}", .{operand});
            break :blk .nop;
        },
    };
    try func.debug_output.dwarf.gen_var_dbg_info(name, ty, mod.func_owner_decl_index(func.func_index), is_ptr, loc);

    func.finish_air(inst, .none, &.{});
}

fn air_try(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const pl_op = func.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
    const err_union = try func.resolve_inst(pl_op.operand);
    const extra = func.air.extra_data(Air.Try, pl_op.payload);
    const body: []const Air.Inst.Index = @ptr_cast(func.air.extra[extra.end..][0..extra.data.body_len]);
    const err_union_ty = func.type_of(pl_op.operand);
    const result = try lower_try(func, inst, err_union, body, err_union_ty, false);
    func.finish_air(inst, result, &.{pl_op.operand});
}

fn air_try_ptr(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const ty_pl = func.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = func.air.extra_data(Air.TryPtr, ty_pl.payload);
    const err_union_ptr = try func.resolve_inst(extra.data.ptr);
    const body: []const Air.Inst.Index = @ptr_cast(func.air.extra[extra.end..][0..extra.data.body_len]);
    const err_union_ty = func.type_of(extra.data.ptr).child_type(mod);
    const result = try lower_try(func, inst, err_union_ptr, body, err_union_ty, true);
    func.finish_air(inst, result, &.{extra.data.ptr});
}

fn lower_try(
    func: *CodeGen,
    inst: Air.Inst.Index,
    err_union: WValue,
    body: []const Air.Inst.Index,
    err_union_ty: Type,
    operand_is_ptr: bool,
) InnerError!WValue {
    const mod = func.bin_file.base.comp.module.?;
    if (operand_is_ptr) {
        return func.fail("TODO: lower_try for pointers", .{});
    }

    const pl_ty = err_union_ty.error_union_payload(mod);
    const pl_has_bits = pl_ty.has_runtime_bits_ignore_comptime(mod);

    if (!err_union_ty.error_union_set(mod).error_set_is_empty(mod)) {
        // Block we can jump out of when error is not set
        try func.start_block(.block, wasm.block_empty);

        // check if the error tag is set for the error union.
        try func.emit_wvalue(err_union);
        if (pl_has_bits) {
            const err_offset = @as(u32, @int_cast(err_union_error_offset(pl_ty, mod)));
            try func.add_mem_arg(.i32_load16_u, .{
                .offset = err_union.offset() + err_offset,
                .alignment = @int_cast(Type.anyerror.abi_alignment(mod).to_byte_units().?),
            });
        }
        try func.add_tag(.i32_eqz);
        try func.add_label(.br_if, 0); // jump out of block when error is '0'

        const liveness = func.liveness.get_cond_br(inst);
        try func.branches.append(func.gpa, .{});
        try func.current_branch().values.ensure_unused_capacity(func.gpa, liveness.else_deaths.len + liveness.then_deaths.len);
        defer {
            var branch = func.branches.pop();
            branch.deinit(func.gpa);
        }
        try func.gen_body(body);
        try func.end_block();
    }

    // if we reach here it means error was not set, and we want the payload
    if (!pl_has_bits) {
        return WValue{ .none = {} };
    }

    const pl_offset = @as(u32, @int_cast(err_union_payload_offset(pl_ty, mod)));
    if (is_by_ref(pl_ty, mod)) {
        return build_pointer_offset(func, err_union, pl_offset, .new);
    }
    const payload = try func.load(err_union, pl_ty, pl_offset);
    return payload.to_local(func, pl_ty);
}

fn air_byte_swap(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const ty_op = func.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

    const ty = func.type_of_index(inst);
    const operand = try func.resolve_inst(ty_op.operand);

    if (ty.zig_type_tag(mod) == .Vector) {
        return func.fail("TODO: @byte_swap for vectors", .{});
    }
    const int_info = ty.int_info(mod);

    // bytes are no-op
    if (int_info.bits == 8) {
        return func.finish_air(inst, func.reuse_operand(ty_op.operand, operand), &.{ty_op.operand});
    }

    const result = result: {
        switch (int_info.bits) {
            16 => {
                const shl_res = try func.bin_op(operand, .{ .imm32 = 8 }, ty, .shl);
                const lhs = try func.bin_op(shl_res, .{ .imm32 = 0xFF00 }, ty, .@"and");
                const shr_res = try func.bin_op(operand, .{ .imm32 = 8 }, ty, .shr);
                const res = if (int_info.signedness == .signed) blk: {
                    break :blk try func.wrap_operand(shr_res, Type.u8);
                } else shr_res;
                break :result try (try func.bin_op(lhs, res, ty, .@"or")).to_local(func, ty);
            },
            24 => {
                var msb = try (try func.wrap_operand(operand, Type.u16)).to_local(func, Type.u16);
                defer msb.free(func);

                const shl_res = try func.bin_op(msb, .{ .imm32 = 8 }, Type.u16, .shl);
                const lhs = try func.bin_op(shl_res, .{ .imm32 = 0xFF0000 }, Type.u16, .@"and");
                const shr_res = try func.bin_op(msb, .{ .imm32 = 8 }, ty, .shr);

                const res = if (int_info.signedness == .signed) blk: {
                    break :blk try func.wrap_operand(shr_res, Type.u8);
                } else shr_res;
                const lhs_tmp = try func.bin_op(lhs, res, ty, .@"or");
                const lhs_result = try func.bin_op(lhs_tmp, .{ .imm32 = 8 }, ty, .shr);
                const rhs_wrap = try func.wrap_operand(msb, Type.u8);
                const rhs_result = try func.bin_op(rhs_wrap, .{ .imm32 = 16 }, ty, .shl);

                const lsb = try func.wrap_bin_op(operand, .{ .imm32 = 16 }, Type.u8, .shr);
                const tmp = try func.bin_op(lhs_result, rhs_result, ty, .@"or");
                break :result try (try func.bin_op(tmp, lsb, ty, .@"or")).to_local(func, ty);
            },
            32 => {
                const shl_tmp = try func.bin_op(operand, .{ .imm32 = 8 }, Type.u32, .shl);
                const lhs = try func.bin_op(shl_tmp, .{ .imm32 = 0xFF00FF00 }, Type.u32, .@"and");
                const shr_tmp = try func.bin_op(operand, .{ .imm32 = 8 }, Type.u32, .shr);
                const rhs = try func.bin_op(shr_tmp, .{ .imm32 = 0x00FF00FF }, Type.u32, .@"and");
                var tmp_or = try (try func.bin_op(lhs, rhs, Type.u32, .@"or")).to_local(func, Type.u32);

                const shl = try func.bin_op(tmp_or, .{ .imm32 = 16 }, Type.u32, .shl);
                const shr = try func.bin_op(tmp_or, .{ .imm32 = 16 }, Type.u32, .shr);

                tmp_or.free(func);

                break :result try (try func.bin_op(shl, shr, Type.u32, .@"or")).to_local(func, Type.u32);
            },
            64 => {
                const shl_tmp_1 = try func.bin_op(operand, .{ .imm64 = 8 }, Type.u64, .shl);
                const lhs_1 = try func.bin_op(shl_tmp_1, .{ .imm64 = 0xFF00FF00FF00FF00 }, Type.u64, .@"and");

                const shr_tmp_1 = try func.bin_op(operand, .{ .imm64 = 8 }, Type.u64, .shr);
                const rhs_1 = try func.bin_op(shr_tmp_1, .{ .imm64 = 0x00FF00FF00FF00FF }, Type.u64, .@"and");

                var tmp_or_1 = try (try func.bin_op(lhs_1, rhs_1, Type.u64, .@"or")).to_local(func, Type.u64);

                const shl_tmp_2 = try func.bin_op(tmp_or_1, .{ .imm64 = 16 }, Type.u64, .shl);
                const lhs_2 = try func.bin_op(shl_tmp_2, .{ .imm64 = 0xFFFF0000FFFF0000 }, Type.u64, .@"and");

                const shr_tmp_2 = try func.bin_op(tmp_or_1, .{ .imm64 = 16 }, Type.u64, .shr);
                tmp_or_1.free(func);
                const rhs_2 = try func.bin_op(shr_tmp_2, .{ .imm64 = 0x0000FFFF0000FFFF }, Type.u64, .@"and");

                var tmp_or_2 = try (try func.bin_op(lhs_2, rhs_2, Type.u64, .@"or")).to_local(func, Type.u64);

                const shl = try func.bin_op(tmp_or_2, .{ .imm64 = 32 }, Type.u64, .shl);
                const shr = try func.bin_op(tmp_or_2, .{ .imm64 = 32 }, Type.u64, .shr);
                tmp_or_2.free(func);

                break :result try (try func.bin_op(shl, shr, Type.u64, .@"or")).to_local(func, Type.u64);
            },
            else => return func.fail("TODO: @byte_swap for integers with bitsize {d}", .{int_info.bits}),
        }
    };
    func.finish_air(inst, result, &.{ty_op.operand});
}

fn air_div(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const bin_op = func.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;

    const ty = func.type_of_index(inst);
    const lhs = try func.resolve_inst(bin_op.lhs);
    const rhs = try func.resolve_inst(bin_op.rhs);

    const result = if (ty.is_signed_int(mod))
        try func.div_signed(lhs, rhs, ty)
    else
        try (try func.bin_op(lhs, rhs, ty, .div)).to_local(func, ty);
    func.finish_air(inst, result, &.{ bin_op.lhs, bin_op.rhs });
}

fn air_div_trunc(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const bin_op = func.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;

    const ty = func.type_of_index(inst);
    const lhs = try func.resolve_inst(bin_op.lhs);
    const rhs = try func.resolve_inst(bin_op.rhs);

    const div_result = if (ty.is_signed_int(mod))
        try func.div_signed(lhs, rhs, ty)
    else
        try (try func.bin_op(lhs, rhs, ty, .div)).to_local(func, ty);

    if (ty.is_any_float()) {
        const trunc_result = try (try func.float_op(.trunc, ty, &.{div_result})).to_local(func, ty);
        return func.finish_air(inst, trunc_result, &.{ bin_op.lhs, bin_op.rhs });
    }

    return func.finish_air(inst, div_result, &.{ bin_op.lhs, bin_op.rhs });
}

fn air_div_floor(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const bin_op = func.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;

    const mod = func.bin_file.base.comp.module.?;
    const ty = func.type_of_index(inst);
    const lhs = try func.resolve_inst(bin_op.lhs);
    const rhs = try func.resolve_inst(bin_op.rhs);

    if (ty.is_unsigned_int(mod)) {
        _ = try func.bin_op(lhs, rhs, ty, .div);
    } else if (ty.is_signed_int(mod)) {
        const int_bits = ty.int_info(mod).bits;
        const wasm_bits = to_wasm_bits(int_bits) orelse {
            return func.fail("TODO: `@div_floor` for signed integers larger than 64 bits ({d} bits requested)", .{int_bits});
        };

        if (wasm_bits > 64) {
            return func.fail("TODO: `@div_floor` for signed integers larger than 64 bits ({d} bits requested)", .{int_bits});
        }

        const lhs_wasm = if (wasm_bits != int_bits)
            try (try func.sign_extend_int(lhs, ty)).to_local(func, ty)
        else
            lhs;

        const rhs_wasm = if (wasm_bits != int_bits)
            try (try func.sign_extend_int(rhs, ty)).to_local(func, ty)
        else
            rhs;

        const zero = switch (wasm_bits) {
            32 => WValue{ .imm32 = 0 },
            64 => WValue{ .imm64 = 0 },
            else => unreachable,
        };

        // tee leaves the value on the stack and stores it in a local.
        const quotient = try func.alloc_local(ty);
        _ = try func.bin_op(lhs_wasm, rhs_wasm, ty, .div);
        try func.add_label(.local_tee, quotient.local.value);

        // select takes a 32 bit value as the condition, so in the 64 bit case we use eqz to narrow
        // the 64 bit value we want to use as the condition to 32 bits.
        // This also inverts the condition (non 0 => 0, 0 => 1), so we put the adjusted and
        // non-adjusted quotients on the stack in the opposite order for 32 vs 64 bits.
        if (wasm_bits == 64) {
            try func.emit_wvalue(quotient);
        }

        // 0 if the signs of rhs_wasm and lhs_wasm are the same, 1 otherwise.
        _ = try func.bin_op(lhs_wasm, rhs_wasm, ty, .xor);
        _ = try func.cmp(.stack, zero, ty, .lt);

        switch (wasm_bits) {
            32 => {
                try func.add_tag(.i32_sub);
                try func.emit_wvalue(quotient);
            },
            64 => {
                try func.add_tag(.i64_extend_i32_u);
                try func.add_tag(.i64_sub);
            },
            else => unreachable,
        }

        _ = try func.bin_op(lhs_wasm, rhs_wasm, ty, .rem);

        if (wasm_bits == 64) {
            try func.add_tag(.i64_eqz);
        }

        try func.add_tag(.select);

        // We need to zero the high bits because N bit comparisons consider all 32 or 64 bits, and
        // expect all but the lowest N bits to be 0.
        // TODO: Should we be zeroing the high bits here or should we be ignoring the high bits
        // when performing comparisons?
        if (int_bits != wasm_bits) {
            _ = try func.wrap_operand(.{ .stack = {} }, ty);
        }
    } else {
        const float_bits = ty.float_bits(func.target);
        if (float_bits > 64) {
            return func.fail("TODO: `@div_floor` for floats with bitsize: {d}", .{float_bits});
        }
        const is_f16 = float_bits == 16;

        const lhs_wasm = if (is_f16) try func.fpext(lhs, Type.f16, Type.f32) else lhs;
        const rhs_wasm = if (is_f16) try func.fpext(rhs, Type.f16, Type.f32) else rhs;

        try func.emit_wvalue(lhs_wasm);
        try func.emit_wvalue(rhs_wasm);

        switch (float_bits) {
            16, 32 => {
                try func.add_tag(.f32_div);
                try func.add_tag(.f32_floor);
            },
            64 => {
                try func.add_tag(.f64_div);
                try func.add_tag(.f64_floor);
            },
            else => unreachable,
        }

        if (is_f16) {
            _ = try func.fptrunc(.{ .stack = {} }, Type.f32, Type.f16);
        }
    }

    const result = try func.alloc_local(ty);
    try func.add_label(.local_set, result.local.value);
    func.finish_air(inst, result, &.{ bin_op.lhs, bin_op.rhs });
}

fn div_signed(func: *CodeGen, lhs: WValue, rhs: WValue, ty: Type) InnerError!WValue {
    const mod = func.bin_file.base.comp.module.?;
    const int_bits = ty.int_info(mod).bits;
    const wasm_bits = to_wasm_bits(int_bits) orelse {
        return func.fail("TODO: Implement signed division for integers with bitsize '{d}'", .{int_bits});
    };

    if (wasm_bits == 128) {
        return func.fail("TODO: Implement signed division for 128-bit integerrs", .{});
    }

    if (wasm_bits != int_bits) {
        // Leave both values on the stack
        _ = try func.sign_extend_int(lhs, ty);
        _ = try func.sign_extend_int(rhs, ty);
    } else {
        try func.emit_wvalue(lhs);
        try func.emit_wvalue(rhs);
    }
    try func.add_tag(.i32_div_s);

    const result = try func.alloc_local(ty);
    try func.add_label(.local_set, result.local.value);
    return result;
}

/// Remainder after floor division, defined by:
/// @div_floor(a, b) * b + @mod(a, b) = a
fn air_mod(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const bin_op = func.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;

    const mod = func.bin_file.base.comp.module.?;
    const ty = func.type_of_index(inst);
    const lhs = try func.resolve_inst(bin_op.lhs);
    const rhs = try func.resolve_inst(bin_op.rhs);

    if (ty.is_unsigned_int(mod)) {
        _ = try func.bin_op(lhs, rhs, ty, .rem);
    } else if (ty.is_signed_int(mod)) {
        // The wasm rem instruction gives the remainder after truncating division (rounding towards
        // 0), equivalent to @rem.
        // We make use of the fact that:
        // @mod(a, b) = @rem(@rem(a, b) + b, b)
        const int_bits = ty.int_info(mod).bits;
        const wasm_bits = to_wasm_bits(int_bits) orelse {
            return func.fail("TODO: `@mod` for signed integers larger than 64 bits ({d} bits requested)", .{int_bits});
        };

        if (wasm_bits > 64) {
            return func.fail("TODO: `@mod` for signed integers larger than 64 bits ({d} bits requested)", .{int_bits});
        }

        const lhs_wasm = if (wasm_bits != int_bits)
            try (try func.sign_extend_int(lhs, ty)).to_local(func, ty)
        else
            lhs;

        const rhs_wasm = if (wasm_bits != int_bits)
            try (try func.sign_extend_int(rhs, ty)).to_local(func, ty)
        else
            rhs;

        _ = try func.bin_op(lhs_wasm, rhs_wasm, ty, .rem);
        _ = try func.bin_op(.stack, rhs_wasm, ty, .add);
        _ = try func.bin_op(.stack, rhs_wasm, ty, .rem);
    } else {
        return func.fail("TODO: implement `@mod` on floating point types for {}", .{func.target.cpu.arch});
    }

    const result = try func.alloc_local(ty);
    try func.add_label(.local_set, result.local.value);
    func.finish_air(inst, result, &.{ bin_op.lhs, bin_op.rhs });
}

/// Sign extends an N bit signed integer and pushes the result to the stack.
/// The result will be sign extended to 32 bits if N <= 32 or 64 bits if N <= 64.
/// Support for integers wider than 64 bits has not yet been implemented.
fn sign_extend_int(func: *CodeGen, operand: WValue, ty: Type) InnerError!WValue {
    const mod = func.bin_file.base.comp.module.?;
    const int_bits = ty.int_info(mod).bits;
    const wasm_bits = to_wasm_bits(int_bits) orelse {
        return func.fail("TODO: sign_extend_int for signed integers larger than '{d}' bits", .{int_bits});
    };

    const shift_val = switch (wasm_bits) {
        32 => WValue{ .imm32 = wasm_bits - int_bits },
        64 => WValue{ .imm64 = wasm_bits - int_bits },
        else => return func.fail("TODO: sign_extend_int for i128", .{}),
    };

    try func.emit_wvalue(operand);
    switch (wasm_bits) {
        32 => {
            try func.emit_wvalue(shift_val);
            try func.add_tag(.i32_shl);
            try func.emit_wvalue(shift_val);
            try func.add_tag(.i32_shr_s);
        },
        64 => {
            try func.emit_wvalue(shift_val);
            try func.add_tag(.i64_shl);
            try func.emit_wvalue(shift_val);
            try func.add_tag(.i64_shr_s);
        },
        else => unreachable,
    }

    return WValue{ .stack = {} };
}

fn air_sat_bin_op(func: *CodeGen, inst: Air.Inst.Index, op: Op) InnerError!void {
    assert(op == .add or op == .sub);
    const bin_op = func.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;

    const mod = func.bin_file.base.comp.module.?;
    const ty = func.type_of_index(inst);
    const lhs = try func.resolve_inst(bin_op.lhs);
    const rhs = try func.resolve_inst(bin_op.rhs);

    const int_info = ty.int_info(mod);
    const is_signed = int_info.signedness == .signed;

    if (int_info.bits > 64) {
        return func.fail("TODO: saturating arithmetic for integers with bitsize '{d}'", .{int_info.bits});
    }

    if (is_signed) {
        const result = try signed_sat(func, lhs, rhs, ty, op);
        return func.finish_air(inst, result, &.{ bin_op.lhs, bin_op.rhs });
    }

    const wasm_bits = to_wasm_bits(int_info.bits).?;
    var bin_result = try (try func.bin_op(lhs, rhs, ty, op)).to_local(func, ty);
    defer bin_result.free(func);
    if (wasm_bits != int_info.bits and op == .add) {
        const val: u64 = @as(u64, @int_cast((@as(u65, 1) << @as(u7, @int_cast(int_info.bits))) - 1));
        const imm_val = switch (wasm_bits) {
            32 => WValue{ .imm32 = @as(u32, @int_cast(val)) },
            64 => WValue{ .imm64 = val },
            else => unreachable,
        };

        try func.emit_wvalue(bin_result);
        try func.emit_wvalue(imm_val);
        _ = try func.cmp(bin_result, imm_val, ty, .lt);
    } else {
        switch (wasm_bits) {
            32 => try func.add_imm32(if (op == .add) @as(i32, -1) else 0),
            64 => try func.add_imm64(if (op == .add) @as(u64, @bit_cast(@as(i64, -1))) else 0),
            else => unreachable,
        }
        try func.emit_wvalue(bin_result);
        _ = try func.cmp(bin_result, lhs, ty, if (op == .add) .lt else .gt);
    }

    try func.add_tag(.select);
    const result = try func.alloc_local(ty);
    try func.add_label(.local_set, result.local.value);
    return func.finish_air(inst, result, &.{ bin_op.lhs, bin_op.rhs });
}

fn signed_sat(func: *CodeGen, lhs_operand: WValue, rhs_operand: WValue, ty: Type, op: Op) InnerError!WValue {
    const mod = func.bin_file.base.comp.module.?;
    const int_info = ty.int_info(mod);
    const wasm_bits = to_wasm_bits(int_info.bits).?;
    const is_wasm_bits = wasm_bits == int_info.bits;
    const ext_ty = if (!is_wasm_bits) try mod.int_type(int_info.signedness, wasm_bits) else ty;

    var lhs = if (!is_wasm_bits) lhs: {
        break :lhs try (try func.sign_extend_int(lhs_operand, ty)).to_local(func, ext_ty);
    } else lhs_operand;
    var rhs = if (!is_wasm_bits) rhs: {
        break :rhs try (try func.sign_extend_int(rhs_operand, ty)).to_local(func, ext_ty);
    } else rhs_operand;

    const max_val: u64 = @as(u64, @int_cast((@as(u65, 1) << @as(u7, @int_cast(int_info.bits - 1))) - 1));
    const min_val: i64 = (-@as(i64, @int_cast(@as(u63, @int_cast(max_val))))) - 1;
    const max_wvalue = switch (wasm_bits) {
        32 => WValue{ .imm32 = @as(u32, @truncate(max_val)) },
        64 => WValue{ .imm64 = max_val },
        else => unreachable,
    };
    const min_wvalue = switch (wasm_bits) {
        32 => WValue{ .imm32 = @as(u32, @bit_cast(@as(i32, @truncate(min_val)))) },
        64 => WValue{ .imm64 = @as(u64, @bit_cast(min_val)) },
        else => unreachable,
    };

    var bin_result = try (try func.bin_op(lhs, rhs, ext_ty, op)).to_local(func, ext_ty);
    if (!is_wasm_bits) {
        defer bin_result.free(func); // not returned in this branch
        defer lhs.free(func); // uses temporary local for absvalue
        defer rhs.free(func); // uses temporary local for absvalue
        try func.emit_wvalue(bin_result);
        try func.emit_wvalue(max_wvalue);
        _ = try func.cmp(bin_result, max_wvalue, ext_ty, .lt);
        try func.add_tag(.select);
        try func.add_label(.local_set, bin_result.local.value); // re-use local

        try func.emit_wvalue(bin_result);
        try func.emit_wvalue(min_wvalue);
        _ = try func.cmp(bin_result, min_wvalue, ext_ty, .gt);
        try func.add_tag(.select);
        try func.add_label(.local_set, bin_result.local.value); // re-use local
        return (try func.wrap_operand(bin_result, ty)).to_local(func, ty);
    } else {
        const zero = switch (wasm_bits) {
            32 => WValue{ .imm32 = 0 },
            64 => WValue{ .imm64 = 0 },
            else => unreachable,
        };
        try func.emit_wvalue(max_wvalue);
        try func.emit_wvalue(min_wvalue);
        _ = try func.cmp(bin_result, zero, ty, .lt);
        try func.add_tag(.select);
        try func.emit_wvalue(bin_result);
        // leave on stack
        const cmp_zero_result = try func.cmp(rhs, zero, ty, if (op == .add) .lt else .gt);
        const cmp_bin_result = try func.cmp(bin_result, lhs, ty, .lt);
        _ = try func.bin_op(cmp_zero_result, cmp_bin_result, Type.u32, .xor); // comparisons always return i32, so provide u32 as type to xor.
        try func.add_tag(.select);
        try func.add_label(.local_set, bin_result.local.value); // re-use local
        return bin_result;
    }
}

fn air_shl_sat(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const bin_op = func.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;

    const mod = func.bin_file.base.comp.module.?;
    const ty = func.type_of_index(inst);
    const int_info = ty.int_info(mod);
    const is_signed = int_info.signedness == .signed;
    if (int_info.bits > 64) {
        return func.fail("TODO: Saturating shifting left for integers with bitsize '{d}'", .{int_info.bits});
    }

    const lhs = try func.resolve_inst(bin_op.lhs);
    const rhs = try func.resolve_inst(bin_op.rhs);
    const wasm_bits = to_wasm_bits(int_info.bits).?;
    const result = try func.alloc_local(ty);

    if (wasm_bits == int_info.bits) outer_blk: {
        var shl = try (try func.bin_op(lhs, rhs, ty, .shl)).to_local(func, ty);
        defer shl.free(func);
        var shr = try (try func.bin_op(shl, rhs, ty, .shr)).to_local(func, ty);
        defer shr.free(func);

        switch (wasm_bits) {
            32 => blk: {
                if (!is_signed) {
                    try func.add_imm32(-1);
                    break :blk;
                }
                try func.add_imm32(std.math.min_int(i32));
                try func.add_imm32(std.math.max_int(i32));
                _ = try func.cmp(lhs, .{ .imm32 = 0 }, ty, .lt);
                try func.add_tag(.select);
            },
            64 => blk: {
                if (!is_signed) {
                    try func.add_imm64(@as(u64, @bit_cast(@as(i64, -1))));
                    break :blk;
                }
                try func.add_imm64(@as(u64, @bit_cast(@as(i64, std.math.min_int(i64)))));
                try func.add_imm64(@as(u64, @bit_cast(@as(i64, std.math.max_int(i64)))));
                _ = try func.cmp(lhs, .{ .imm64 = 0 }, ty, .lt);
                try func.add_tag(.select);
            },
            else => unreachable,
        }
        try func.emit_wvalue(shl);
        _ = try func.cmp(lhs, shr, ty, .neq);
        try func.add_tag(.select);
        try func.add_label(.local_set, result.local.value);
        break :outer_blk;
    } else {
        const shift_size = wasm_bits - int_info.bits;
        const shift_value = switch (wasm_bits) {
            32 => WValue{ .imm32 = shift_size },
            64 => WValue{ .imm64 = shift_size },
            else => unreachable,
        };
        const ext_ty = try mod.int_type(int_info.signedness, wasm_bits);

        var shl_res = try (try func.bin_op(lhs, shift_value, ext_ty, .shl)).to_local(func, ext_ty);
        defer shl_res.free(func);
        var shl = try (try func.bin_op(shl_res, rhs, ext_ty, .shl)).to_local(func, ext_ty);
        defer shl.free(func);
        var shr = try (try func.bin_op(shl, rhs, ext_ty, .shr)).to_local(func, ext_ty);
        defer shr.free(func);

        switch (wasm_bits) {
            32 => blk: {
                if (!is_signed) {
                    try func.add_imm32(-1);
                    break :blk;
                }

                try func.add_imm32(std.math.min_int(i32));
                try func.add_imm32(std.math.max_int(i32));
                _ = try func.cmp(shl_res, .{ .imm32 = 0 }, ext_ty, .lt);
                try func.add_tag(.select);
            },
            64 => blk: {
                if (!is_signed) {
                    try func.add_imm64(@as(u64, @bit_cast(@as(i64, -1))));
                    break :blk;
                }

                try func.add_imm64(@as(u64, @bit_cast(@as(i64, std.math.min_int(i64)))));
                try func.add_imm64(@as(u64, @bit_cast(@as(i64, std.math.max_int(i64)))));
                _ = try func.cmp(shl_res, .{ .imm64 = 0 }, ext_ty, .lt);
                try func.add_tag(.select);
            },
            else => unreachable,
        }
        try func.emit_wvalue(shl);
        _ = try func.cmp(shl_res, shr, ext_ty, .neq);
        try func.add_tag(.select);
        try func.add_label(.local_set, result.local.value);
        var shift_result = try func.bin_op(result, shift_value, ext_ty, .shr);
        if (is_signed) {
            shift_result = try func.wrap_operand(shift_result, ty);
        }
        try func.add_label(.local_set, result.local.value);
    }

    return func.finish_air(inst, result, &.{ bin_op.lhs, bin_op.rhs });
}

/// Calls a compiler-rt intrinsic by creating an undefined symbol,
/// then lowering the arguments and calling the symbol as a function call.
/// This function call assumes the C-ABI.
/// Asserts arguments are not stack values when the return value is
/// passed as the first parameter.
/// May leave the return value on the stack.
fn call_intrinsic(
    func: *CodeGen,
    name: []const u8,
    param_types: []const InternPool.Index,
    return_type: Type,
    args: []const WValue,
) InnerError!WValue {
    assert(param_types.len == args.len);
    const symbol_index = func.bin_file.get_global_symbol(name, null) catch |err| {
        return func.fail("Could not find or create global symbol '{s}'", .{@errorName(err)});
    };

    // Always pass over C-ABI
    const mod = func.bin_file.base.comp.module.?;
    var func_type = try gen_functype(func.gpa, .C, param_types, return_type, mod);
    defer func_type.deinit(func.gpa);
    const func_type_index = try func.bin_file.zig_object_ptr().?.put_or_get_func_type(func.gpa, func_type);
    try func.bin_file.add_or_update_import(name, symbol_index, null, func_type_index);

    const want_sret_param = first_param_sret(.C, return_type, mod);
    // if we want return as first param, we allocate a pointer to stack,
    // and emit it as our first argument
    const sret = if (want_sret_param) blk: {
        const sret_local = try func.alloc_stack(return_type);
        try func.lower_to_stack(sret_local);
        break :blk sret_local;
    } else WValue{ .none = {} };

    // Lower all arguments to the stack before we call our function
    for (args, 0..) |arg, arg_i| {
        assert(!(want_sret_param and arg == .stack));
        assert(Type.from_interned(param_types[arg_i]).has_runtime_bits_ignore_comptime(mod));
        try func.lower_arg(.C, Type.from_interned(param_types[arg_i]), arg);
    }

    // Actually call our intrinsic
    try func.add_label(.call, @int_from_enum(symbol_index));

    if (!return_type.has_runtime_bits_ignore_comptime(mod)) {
        return WValue.none;
    } else if (return_type.is_no_return(mod)) {
        try func.add_tag(.@"unreachable");
        return WValue.none;
    } else if (want_sret_param) {
        return sret;
    } else {
        return WValue{ .stack = {} };
    }
}

fn air_tag_name(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const un_op = func.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const operand = try func.resolve_inst(un_op);
    const enum_ty = func.type_of(un_op);

    const func_sym_index = try func.get_tag_name_function(enum_ty);

    const result_ptr = try func.alloc_stack(func.type_of_index(inst));
    try func.lower_to_stack(result_ptr);
    try func.emit_wvalue(operand);
    try func.add_label(.call, func_sym_index);

    return func.finish_air(inst, result_ptr, &.{un_op});
}

fn get_tag_name_function(func: *CodeGen, enum_ty: Type) InnerError!u32 {
    const mod = func.bin_file.base.comp.module.?;
    const ip = &mod.intern_pool;
    const enum_decl_index = enum_ty.get_owner_decl(mod);

    var arena_allocator = std.heap.ArenaAllocator.init(func.gpa);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    const fqn = try mod.decl_ptr(enum_decl_index).fully_qualified_name(mod);
    const func_name = try std.fmt.alloc_print_z(arena, "__zig_tag_name_{}", .{fqn.fmt(ip)});

    // check if we already generated code for this.
    if (func.bin_file.find_global_symbol(func_name)) |loc| {
        return @int_from_enum(loc.index);
    }

    const int_tag_ty = enum_ty.int_tag_type(mod);

    if (int_tag_ty.bit_size(mod) > 64) {
        return func.fail("TODO: Implement @tag_name for enums with tag size larger than 64 bits", .{});
    }

    var relocs = std.ArrayList(link.File.Wasm.Relocation).init(func.gpa);
    defer relocs.deinit();

    var body_list = std.ArrayList(u8).init(func.gpa);
    defer body_list.deinit();
    var writer = body_list.writer();

    // The locals of the function body (always 0)
    try leb.write_uleb128(writer, @as(u32, 0));

    // outer block
    try writer.write_byte(std.wasm.opcode(.block));
    try writer.write_byte(std.wasm.block_empty);

    // TODO: Make switch implementation generic so we can use a jump table for this when the tags are not sparse.
    // generate an if-else chain for each tag value as well as constant.
    const tag_names = enum_ty.enum_fields(mod);
    for (0..tag_names.len) |tag_index| {
        const tag_name = tag_names.get(ip)[tag_index];
        const tag_name_len = tag_name.length(ip);
        // for each tag name, create an unnamed const,
        // and then get a pointer to its value.
        const name_ty = try mod.array_type(.{
            .len = tag_name_len,
            .child = .u8_type,
            .sentinel = .zero_u8,
        });
        const name_val = try mod.intern(.{ .aggregate = .{
            .ty = name_ty.to_intern(),
            .storage = .{ .bytes = tag_name.to_string() },
        } });
        const tag_sym_index = try func.bin_file.lower_unnamed_const(
            Value.from_interned(name_val),
            enum_decl_index,
        );

        // block for this if case
        try writer.write_byte(std.wasm.opcode(.block));
        try writer.write_byte(std.wasm.block_empty);

        // get actual tag value (stored in 2nd parameter);
        try writer.write_byte(std.wasm.opcode(.local_get));
        try leb.write_uleb128(writer, @as(u32, 1));

        const tag_val = try mod.enum_value_field_index(enum_ty, @int_cast(tag_index));
        const tag_value = try func.lower_constant(tag_val, enum_ty);

        switch (tag_value) {
            .imm32 => |value| {
                try writer.write_byte(std.wasm.opcode(.i32_const));
                try leb.write_ileb128(writer, @as(i32, @bit_cast(value)));
                try writer.write_byte(std.wasm.opcode(.i32_ne));
            },
            .imm64 => |value| {
                try writer.write_byte(std.wasm.opcode(.i64_const));
                try leb.write_ileb128(writer, @as(i64, @bit_cast(value)));
                try writer.write_byte(std.wasm.opcode(.i64_ne));
            },
            else => unreachable,
        }
        // if they're not equal, break out of current branch
        try writer.write_byte(std.wasm.opcode(.br_if));
        try leb.write_uleb128(writer, @as(u32, 0));

        // store the address of the tagname in the pointer field of the slice
        // get the address twice so we can also store the length.
        try writer.write_byte(std.wasm.opcode(.local_get));
        try leb.write_uleb128(writer, @as(u32, 0));
        try writer.write_byte(std.wasm.opcode(.local_get));
        try leb.write_uleb128(writer, @as(u32, 0));

        // get address of tagname and emit a relocation to it
        if (func.arch() == .wasm32) {
            const encoded_alignment = @ctz(@as(u32, 4));
            try writer.write_byte(std.wasm.opcode(.i32_const));
            try relocs.append(.{
                .relocation_type = .R_WASM_MEMORY_ADDR_LEB,
                .offset = @as(u32, @int_cast(body_list.items.len)),
                .index = tag_sym_index,
            });
            try writer.write_all(&[_]u8{0} ** 5); // will be relocated

            // store pointer
            try writer.write_byte(std.wasm.opcode(.i32_store));
            try leb.write_uleb128(writer, encoded_alignment);
            try leb.write_uleb128(writer, @as(u32, 0));

            // store length
            try writer.write_byte(std.wasm.opcode(.i32_const));
            try leb.write_uleb128(writer, @as(u32, @int_cast(tag_name_len)));
            try writer.write_byte(std.wasm.opcode(.i32_store));
            try leb.write_uleb128(writer, encoded_alignment);
            try leb.write_uleb128(writer, @as(u32, 4));
        } else {
            const encoded_alignment = @ctz(@as(u32, 8));
            try writer.write_byte(std.wasm.opcode(.i64_const));
            try relocs.append(.{
                .relocation_type = .R_WASM_MEMORY_ADDR_LEB64,
                .offset = @as(u32, @int_cast(body_list.items.len)),
                .index = tag_sym_index,
            });
            try writer.write_all(&[_]u8{0} ** 10); // will be relocated

            // store pointer
            try writer.write_byte(std.wasm.opcode(.i64_store));
            try leb.write_uleb128(writer, encoded_alignment);
            try leb.write_uleb128(writer, @as(u32, 0));

            // store length
            try writer.write_byte(std.wasm.opcode(.i64_const));
            try leb.write_uleb128(writer, @as(u64, @int_cast(tag_name_len)));
            try writer.write_byte(std.wasm.opcode(.i64_store));
            try leb.write_uleb128(writer, encoded_alignment);
            try leb.write_uleb128(writer, @as(u32, 8));
        }

        // break outside blocks
        try writer.write_byte(std.wasm.opcode(.br));
        try leb.write_uleb128(writer, @as(u32, 1));

        // end the block for this case
        try writer.write_byte(std.wasm.opcode(.end));
    }

    try writer.write_byte(std.wasm.opcode(.@"unreachable")); // tag value does not have a name
    // finish outer block
    try writer.write_byte(std.wasm.opcode(.end));
    // finish function body
    try writer.write_byte(std.wasm.opcode(.end));

    const slice_ty = Type.slice_const_u8_sentinel_0;
    const func_type = try gen_functype(arena, .Unspecified, &.{int_tag_ty.ip_index}, slice_ty, mod);
    const sym_index = try func.bin_file.create_function(func_name, func_type, &body_list, &relocs);
    return @int_from_enum(sym_index);
}

fn air_error_set_has_value(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const ip = &mod.intern_pool;
    const ty_op = func.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

    const operand = try func.resolve_inst(ty_op.operand);
    const error_set_ty = ty_op.ty.to_type();
    const result = try func.alloc_local(Type.bool);

    const names = error_set_ty.error_set_names(mod);
    var values = try std.ArrayList(u32).init_capacity(func.gpa, names.len);
    defer values.deinit();

    var lowest: ?u32 = null;
    var highest: ?u32 = null;
    for (0..names.len) |name_index| {
        const err_int: Module.ErrorInt = @int_cast(mod.global_error_set.get_index(names.get(ip)[name_index]).?);
        if (lowest) |*l| {
            if (err_int < l.*) {
                l.* = err_int;
            }
        } else {
            lowest = err_int;
        }
        if (highest) |*h| {
            if (err_int > h.*) {
                highest = err_int;
            }
        } else {
            highest = err_int;
        }

        values.append_assume_capacity(err_int);
    }

    // start block for 'true' branch
    try func.start_block(.block, wasm.block_empty);
    // start block for 'false' branch
    try func.start_block(.block, wasm.block_empty);
    // block for the jump table itself
    try func.start_block(.block, wasm.block_empty);

    // lower operand to determine jump table target
    try func.emit_wvalue(operand);
    try func.add_imm32(@as(i32, @int_cast(lowest.?)));
    try func.add_tag(.i32_sub);

    // Account for default branch so always add '1'
    const depth = @as(u32, @int_cast(highest.? - lowest.? + 1));
    const jump_table: Mir.JumpTable = .{ .length = depth };
    const table_extra_index = try func.add_extra(jump_table);
    try func.add_inst(.{ .tag = .br_table, .data = .{ .payload = table_extra_index } });
    try func.mir_extra.ensure_unused_capacity(func.gpa, depth);

    var value: u32 = lowest.?;
    while (value <= highest.?) : (value += 1) {
        const idx: u32 = blk: {
            for (values.items) |val| {
                if (val == value) break :blk 1;
            }
            break :blk 0;
        };
        func.mir_extra.append_assume_capacity(idx);
    }
    try func.end_block();

    // 'false' branch (i.e. error set does not have value
    // ensure we set local to 0 in case the local was re-used.
    try func.add_imm32(0);
    try func.add_label(.local_set, result.local.value);
    try func.add_label(.br, 1);
    try func.end_block();

    // 'true' branch
    try func.add_imm32(1);
    try func.add_label(.local_set, result.local.value);
    try func.add_label(.br, 0);
    try func.end_block();

    return func.finish_air(inst, result, &.{ty_op.operand});
}

inline fn use_atomic_feature(func: *const CodeGen) bool {
    return std.Target.wasm.feature_set_has(func.target.cpu.features, .atomics);
}

fn air_cmpxchg(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const ty_pl = func.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = func.air.extra_data(Air.Cmpxchg, ty_pl.payload).data;

    const ptr_ty = func.type_of(extra.ptr);
    const ty = ptr_ty.child_type(mod);
    const result_ty = func.type_of_index(inst);

    const ptr_operand = try func.resolve_inst(extra.ptr);
    const expected_val = try func.resolve_inst(extra.expected_value);
    const new_val = try func.resolve_inst(extra.new_value);

    const cmp_result = try func.alloc_local(Type.bool);

    const ptr_val = if (func.use_atomic_feature()) val: {
        const val_local = try func.alloc_local(ty);
        try func.emit_wvalue(ptr_operand);
        try func.lower_to_stack(expected_val);
        try func.lower_to_stack(new_val);
        try func.add_atomic_mem_arg(switch (ty.abi_size(mod)) {
            1 => .i32_atomic_rmw8_cmpxchg_u,
            2 => .i32_atomic_rmw16_cmpxchg_u,
            4 => .i32_atomic_rmw_cmpxchg,
            8 => .i32_atomic_rmw_cmpxchg,
            else => |size| return func.fail("TODO: implement `@cmpxchg` for types with abi size '{d}'", .{size}),
        }, .{
            .offset = ptr_operand.offset(),
            .alignment = @int_cast(ty.abi_alignment(mod).to_byte_units().?),
        });
        try func.add_label(.local_tee, val_local.local.value);
        _ = try func.cmp(.stack, expected_val, ty, .eq);
        try func.add_label(.local_set, cmp_result.local.value);
        break :val val_local;
    } else val: {
        if (ty.abi_size(mod) > 8) {
            return func.fail("TODO: Implement `@cmpxchg` for types larger than abi size of 8 bytes", .{});
        }
        const ptr_val = try WValue.to_local(try func.load(ptr_operand, ty, 0), func, ty);

        try func.lower_to_stack(ptr_operand);
        try func.lower_to_stack(new_val);
        try func.emit_wvalue(ptr_val);
        _ = try func.cmp(ptr_val, expected_val, ty, .eq);
        try func.add_label(.local_tee, cmp_result.local.value);
        try func.add_tag(.select);
        try func.store(.stack, .stack, ty, 0);

        break :val ptr_val;
    };

    const result_ptr = if (is_by_ref(result_ty, mod)) val: {
        try func.emit_wvalue(cmp_result);
        try func.add_imm32(-1);
        try func.add_tag(.i32_xor);
        try func.add_imm32(1);
        try func.add_tag(.i32_and);
        const and_result = try WValue.to_local(.stack, func, Type.bool);
        const result_ptr = try func.alloc_stack(result_ty);
        try func.store(result_ptr, and_result, Type.bool, @as(u32, @int_cast(ty.abi_size(mod))));
        try func.store(result_ptr, ptr_val, ty, 0);
        break :val result_ptr;
    } else val: {
        try func.add_imm32(0);
        try func.emit_wvalue(ptr_val);
        try func.emit_wvalue(cmp_result);
        try func.add_tag(.select);
        break :val try WValue.to_local(.stack, func, result_ty);
    };

    return func.finish_air(inst, result_ptr, &.{ extra.ptr, extra.expected_value, extra.new_value });
}

fn air_atomic_load(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const atomic_load = func.air.instructions.items(.data)[@int_from_enum(inst)].atomic_load;
    const ptr = try func.resolve_inst(atomic_load.ptr);
    const ty = func.type_of_index(inst);

    if (func.use_atomic_feature()) {
        const tag: wasm.AtomicsOpcode = switch (ty.abi_size(mod)) {
            1 => .i32_atomic_load8_u,
            2 => .i32_atomic_load16_u,
            4 => .i32_atomic_load,
            8 => .i64_atomic_load,
            else => |size| return func.fail("TODO: @atomicLoad for types with abi size {d}", .{size}),
        };
        try func.emit_wvalue(ptr);
        try func.add_atomic_mem_arg(tag, .{
            .offset = ptr.offset(),
            .alignment = @int_cast(ty.abi_alignment(mod).to_byte_units().?),
        });
    } else {
        _ = try func.load(ptr, ty, 0);
    }

    const result = try WValue.to_local(.stack, func, ty);
    return func.finish_air(inst, result, &.{atomic_load.ptr});
}

fn air_atomic_rmw(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const pl_op = func.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
    const extra = func.air.extra_data(Air.AtomicRmw, pl_op.payload).data;

    const ptr = try func.resolve_inst(pl_op.operand);
    const operand = try func.resolve_inst(extra.operand);
    const ty = func.type_of_index(inst);
    const op: std.builtin.AtomicRmwOp = extra.op();

    if (func.use_atomic_feature()) {
        switch (op) {
            .Max,
            .Min,
            .Nand,
            => {
                const tmp = try func.load(ptr, ty, 0);
                const value = try tmp.to_local(func, ty);

                // create a loop to cmpxchg the new value
                try func.start_block(.loop, wasm.block_empty);

                try func.emit_wvalue(ptr);
                try func.emit_wvalue(value);
                if (op == .Nand) {
                    const wasm_bits = to_wasm_bits(@as(u16, @int_cast(ty.bit_size(mod)))).?;

                    const and_res = try func.bin_op(value, operand, ty, .@"and");
                    if (wasm_bits == 32)
                        try func.add_imm32(-1)
                    else if (wasm_bits == 64)
                        try func.add_imm64(@as(u64, @bit_cast(@as(i64, -1))))
                    else
                        return func.fail("TODO: `@atomicRmw` with operator `Nand` for types larger than 64 bits", .{});
                    _ = try func.bin_op(and_res, .stack, ty, .xor);
                } else {
                    try func.emit_wvalue(value);
                    try func.emit_wvalue(operand);
                    _ = try func.cmp(value, operand, ty, if (op == .Max) .gt else .lt);
                    try func.add_tag(.select);
                }
                try func.add_atomic_mem_arg(
                    switch (ty.abi_size(mod)) {
                        1 => .i32_atomic_rmw8_cmpxchg_u,
                        2 => .i32_atomic_rmw16_cmpxchg_u,
                        4 => .i32_atomic_rmw_cmpxchg,
                        8 => .i64_atomic_rmw_cmpxchg,
                        else => return func.fail("TODO: implement `@atomicRmw` with operation `{s}` for types larger than 64 bits", .{@tag_name(op)}),
                    },
                    .{
                        .offset = ptr.offset(),
                        .alignment = @int_cast(ty.abi_alignment(mod).to_byte_units().?),
                    },
                );
                const select_res = try func.alloc_local(ty);
                try func.add_label(.local_tee, select_res.local.value);
                _ = try func.cmp(.stack, value, ty, .neq); // leave on stack so we can use it for br_if

                try func.emit_wvalue(select_res);
                try func.add_label(.local_set, value.local.value);

                try func.add_label(.br_if, 0);
                try func.end_block();
                return func.finish_air(inst, value, &.{ pl_op.operand, extra.operand });
            },

            // the other operations have their own instructions for Wasm.
            else => {
                try func.emit_wvalue(ptr);
                try func.emit_wvalue(operand);
                const tag: wasm.AtomicsOpcode = switch (ty.abi_size(mod)) {
                    1 => switch (op) {
                        .Xchg => .i32_atomic_rmw8_xchg_u,
                        .Add => .i32_atomic_rmw8_add_u,
                        .Sub => .i32_atomic_rmw8_sub_u,
                        .And => .i32_atomic_rmw8_and_u,
                        .Or => .i32_atomic_rmw8_or_u,
                        .Xor => .i32_atomic_rmw8_xor_u,
                        else => unreachable,
                    },
                    2 => switch (op) {
                        .Xchg => .i32_atomic_rmw16_xchg_u,
                        .Add => .i32_atomic_rmw16_add_u,
                        .Sub => .i32_atomic_rmw16_sub_u,
                        .And => .i32_atomic_rmw16_and_u,
                        .Or => .i32_atomic_rmw16_or_u,
                        .Xor => .i32_atomic_rmw16_xor_u,
                        else => unreachable,
                    },
                    4 => switch (op) {
                        .Xchg => .i32_atomic_rmw_xchg,
                        .Add => .i32_atomic_rmw_add,
                        .Sub => .i32_atomic_rmw_sub,
                        .And => .i32_atomic_rmw_and,
                        .Or => .i32_atomic_rmw_or,
                        .Xor => .i32_atomic_rmw_xor,
                        else => unreachable,
                    },
                    8 => switch (op) {
                        .Xchg => .i64_atomic_rmw_xchg,
                        .Add => .i64_atomic_rmw_add,
                        .Sub => .i64_atomic_rmw_sub,
                        .And => .i64_atomic_rmw_and,
                        .Or => .i64_atomic_rmw_or,
                        .Xor => .i64_atomic_rmw_xor,
                        else => unreachable,
                    },
                    else => |size| return func.fail("TODO: Implement `@atomicRmw` for types with abi size {d}", .{size}),
                };
                try func.add_atomic_mem_arg(tag, .{
                    .offset = ptr.offset(),
                    .alignment = @int_cast(ty.abi_alignment(mod).to_byte_units().?),
                });
                const result = try WValue.to_local(.stack, func, ty);
                return func.finish_air(inst, result, &.{ pl_op.operand, extra.operand });
            },
        }
    } else {
        const loaded = try func.load(ptr, ty, 0);
        const result = try loaded.to_local(func, ty);

        switch (op) {
            .Xchg => {
                try func.store(ptr, operand, ty, 0);
            },
            .Add,
            .Sub,
            .And,
            .Or,
            .Xor,
            => {
                try func.emit_wvalue(ptr);
                _ = try func.bin_op(result, operand, ty, switch (op) {
                    .Add => .add,
                    .Sub => .sub,
                    .And => .@"and",
                    .Or => .@"or",
                    .Xor => .xor,
                    else => unreachable,
                });
                if (ty.is_int(mod) and (op == .Add or op == .Sub)) {
                    _ = try func.wrap_operand(.stack, ty);
                }
                try func.store(.stack, .stack, ty, ptr.offset());
            },
            .Max,
            .Min,
            => {
                try func.emit_wvalue(ptr);
                try func.emit_wvalue(result);
                try func.emit_wvalue(operand);
                _ = try func.cmp(result, operand, ty, if (op == .Max) .gt else .lt);
                try func.add_tag(.select);
                try func.store(.stack, .stack, ty, ptr.offset());
            },
            .Nand => {
                const wasm_bits = to_wasm_bits(@as(u16, @int_cast(ty.bit_size(mod)))).?;

                try func.emit_wvalue(ptr);
                const and_res = try func.bin_op(result, operand, ty, .@"and");
                if (wasm_bits == 32)
                    try func.add_imm32(-1)
                else if (wasm_bits == 64)
                    try func.add_imm64(@as(u64, @bit_cast(@as(i64, -1))))
                else
                    return func.fail("TODO: `@atomicRmw` with operator `Nand` for types larger than 64 bits", .{});
                _ = try func.bin_op(and_res, .stack, ty, .xor);
                try func.store(.stack, .stack, ty, ptr.offset());
            },
        }

        return func.finish_air(inst, result, &.{ pl_op.operand, extra.operand });
    }
}

fn air_fence(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const zcu = func.bin_file.base.comp.module.?;
    // Only when the atomic feature is enabled, and we're not building
    // for a single-threaded build, can we emit the `fence` instruction.
    // In all other cases, we emit no instructions for a fence.
    const func_namespace = zcu.namespace_ptr(func.decl.src_namespace);
    const single_threaded = func_namespace.file_scope.mod.single_threaded;
    if (func.use_atomic_feature() and !single_threaded) {
        try func.add_atomic_tag(.atomic_fence);
    }

    return func.finish_air(inst, .none, &.{});
}

fn air_atomic_store(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    const mod = func.bin_file.base.comp.module.?;
    const bin_op = func.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;

    const ptr = try func.resolve_inst(bin_op.lhs);
    const operand = try func.resolve_inst(bin_op.rhs);
    const ptr_ty = func.type_of(bin_op.lhs);
    const ty = ptr_ty.child_type(mod);

    if (func.use_atomic_feature()) {
        const tag: wasm.AtomicsOpcode = switch (ty.abi_size(mod)) {
            1 => .i32_atomic_store8,
            2 => .i32_atomic_store16,
            4 => .i32_atomic_store,
            8 => .i64_atomic_store,
            else => |size| return func.fail("TODO: @atomicLoad for types with abi size {d}", .{size}),
        };
        try func.emit_wvalue(ptr);
        try func.lower_to_stack(operand);
        try func.add_atomic_mem_arg(tag, .{
            .offset = ptr.offset(),
            .alignment = @int_cast(ty.abi_alignment(mod).to_byte_units().?),
        });
    } else {
        try func.store(ptr, operand, ty, 0);
    }

    return func.finish_air(inst, .none, &.{ bin_op.lhs, bin_op.rhs });
}

fn air_frame_address(func: *CodeGen, inst: Air.Inst.Index) InnerError!void {
    if (func.initial_stack_value == .none) {
        try func.initialize_stack();
    }
    try func.emit_wvalue(func.bottom_stack_value);
    const result = try WValue.to_local(.stack, func, Type.usize);
    return func.finish_air(inst, result, &.{});
}

fn type_of(func: *CodeGen, inst: Air.Inst.Ref) Type {
    const mod = func.bin_file.base.comp.module.?;
    return func.air.type_of(inst, &mod.intern_pool);
}

fn type_of_index(func: *CodeGen, inst: Air.Inst.Index) Type {
    const mod = func.bin_file.base.comp.module.?;
    return func.air.type_of_index(inst, &mod.intern_pool);
}
