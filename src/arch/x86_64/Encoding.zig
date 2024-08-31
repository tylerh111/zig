const Encoding = @This();

const std = @import("std");
const assert = std.debug.assert;
const math = std.math;

const bits = @import("bits.zig");
const encoder = @import("encoder.zig");
const Instruction = encoder.Instruction;
const Operand = Instruction.Operand;
const Prefix = Instruction.Prefix;
const Register = bits.Register;
const Rex = encoder.Rex;
const LegacyPrefixes = encoder.LegacyPrefixes;

mnemonic: Mnemonic,
data: Data,

const Data = struct {
    op_en: OpEn,
    ops: [4]Op,
    opc_len: u3,
    opc: [7]u8,
    modrm_ext: u3,
    mode: Mode,
    feature: Feature,
};

pub fn find_by_mnemonic(
    prefix: Instruction.Prefix,
    mnemonic: Mnemonic,
    ops: []const Instruction.Operand,
) !?Encoding {
    var input_ops = [1]Op{.none} ** 4;
    for (input_ops[0..ops.len], ops) |*input_op, op| input_op.* = Op.from_operand(op);

    const rex_required = for (ops) |op| switch (op) {
        .reg => |r| switch (r) {
            .spl, .bpl, .sil, .dil => break true,
            else => {},
        },
        else => {},
    } else false;
    const rex_invalid = for (ops) |op| switch (op) {
        .reg => |r| switch (r) {
            .ah, .bh, .ch, .dh => break true,
            else => {},
        },
        else => {},
    } else false;
    const rex_extended = for (ops) |op| {
        if (op.is_base_extended() or op.is_index_extended()) break true;
    } else false;

    if ((rex_required or rex_extended) and rex_invalid) return error.CannotEncode;

    var shortest_enc: ?Encoding = null;
    var shortest_len: ?usize = null;
    next: for (mnemonic_to_encodings_map[@int_from_enum(mnemonic)]) |data| {
        switch (data.mode) {
            .none, .short => if (rex_required) continue,
            .rex, .rex_short => if (!rex_required) continue,
            else => {},
        }
        for (input_ops, data.ops) |input_op, data_op| if (!input_op.is_subset(data_op)) continue :next;

        const enc = Encoding{ .mnemonic = mnemonic, .data = data };
        if (shortest_enc) |previous_shortest_enc| {
            const len = estimate_instruction_length(prefix, enc, ops);
            const previous_shortest_len = shortest_len orelse
                estimate_instruction_length(prefix, previous_shortest_enc, ops);
            if (len < previous_shortest_len) {
                shortest_enc = enc;
                shortest_len = len;
            } else shortest_len = previous_shortest_len;
        } else shortest_enc = enc;
    }
    return shortest_enc;
}

/// Returns first matching encoding by opcode.
pub fn find_by_opcode(opc: []const u8, prefixes: struct {
    legacy: LegacyPrefixes,
    rex: Rex,
}, modrm_ext: ?u3) ?Encoding {
    for (mnemonic_to_encodings_map, 0..) |encs, mnemonic_int| for (encs) |data| {
        const enc = Encoding{ .mnemonic = @as(Mnemonic, @enumFromInt(mnemonic_int)), .data = data };
        if (modrm_ext) |ext| if (ext != data.modrm_ext) continue;
        if (!std.mem.eql(u8, opc, enc.opcode())) continue;
        if (prefixes.rex.w) {
            if (!data.mode.is_long()) continue;
        } else if (prefixes.rex.present and !prefixes.rex.is_set()) {
            if (!data.mode.is_rex()) continue;
        } else if (prefixes.legacy.prefix_66) {
            if (!data.mode.is_short()) continue;
        } else {
            if (data.mode.is_short()) continue;
        }
        return enc;
    };
    return null;
}

pub fn opcode(encoding: *const Encoding) []const u8 {
    return encoding.data.opc[0..encoding.data.opc_len];
}

pub fn mandatory_prefix(encoding: *const Encoding) ?u8 {
    const prefix = encoding.data.opc[0];
    return switch (prefix) {
        0x66, 0xf2, 0xf3 => prefix,
        else => null,
    };
}

pub fn mod_rm_ext(encoding: Encoding) u3 {
    return switch (encoding.data.op_en) {
        .m, .mi, .m1, .mc, .vmi => encoding.data.modrm_ext,
        else => unreachable,
    };
}

pub fn format(
    encoding: Encoding,
    comptime fmt: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = options;
    _ = fmt;

    var opc = encoding.opcode();
    if (encoding.data.mode.is_vex()) {
        try writer.write_all("VEX.");

        try writer.write_all(switch (encoding.data.mode) {
            .vex_128_w0, .vex_128_w1, .vex_128_wig => "128",
            .vex_256_w0, .vex_256_w1, .vex_256_wig => "256",
            .vex_lig_w0, .vex_lig_w1, .vex_lig_wig => "LIG",
            .vex_lz_w0, .vex_lz_w1, .vex_lz_wig => "LZ",
            else => unreachable,
        });

        switch (opc[0]) {
            else => {},
            0x66, 0xf3, 0xf2 => {
                try writer.print(".{X:0>2}", .{opc[0]});
                opc = opc[1..];
            },
        }

        try writer.print(".{}", .{std.fmt.fmt_slice_hex_upper(opc[0 .. opc.len - 1])});
        opc = opc[opc.len - 1 ..];

        try writer.write_all(".W");
        try writer.write_all(switch (encoding.data.mode) {
            .vex_128_w0, .vex_256_w0, .vex_lig_w0, .vex_lz_w0 => "0",
            .vex_128_w1, .vex_256_w1, .vex_lig_w1, .vex_lz_w1 => "1",
            .vex_128_wig, .vex_256_wig, .vex_lig_wig, .vex_lz_wig => "IG",
            else => unreachable,
        });

        try writer.write_byte(' ');
    } else if (encoding.data.mode.is_long()) try writer.write_all("REX.W + ");
    for (opc) |byte| try writer.print("{x:0>2} ", .{byte});

    switch (encoding.data.op_en) {
        .zo, .fd, .td, .i, .zi, .d => {},
        .o, .oi => {
            const tag = switch (encoding.data.ops[0]) {
                .r8 => "rb",
                .r16 => "rw",
                .r32 => "rd",
                .r64 => "rd",
                else => unreachable,
            };
            try writer.print("+{s} ", .{tag});
        },
        .m, .mi, .m1, .mc, .vmi => try writer.print("/{d} ", .{encoding.mod_rm_ext()}),
        .mr, .rm, .rmi, .mri, .mrc, .rm0, .rvm, .rvmr, .rvmi, .mvr => try writer.write_all("/r "),
    }

    switch (encoding.data.op_en) {
        .i, .d, .zi, .oi, .mi, .rmi, .mri, .vmi, .rvmi => {
            const op = switch (encoding.data.op_en) {
                .i, .d => encoding.data.ops[0],
                .zi, .oi, .mi => encoding.data.ops[1],
                .rmi, .mri, .vmi => encoding.data.ops[2],
                .rvmi => encoding.data.ops[3],
                else => unreachable,
            };
            const tag = switch (op) {
                .imm8, .imm8s => "ib",
                .imm16, .imm16s => "iw",
                .imm32, .imm32s => "id",
                .imm64 => "io",
                .rel8 => "cb",
                .rel16 => "cw",
                .rel32 => "cd",
                else => unreachable,
            };
            try writer.print("{s} ", .{tag});
        },
        .rvmr => try writer.write_all("/is4 "),
        .zo, .fd, .td, .o, .m, .m1, .mc, .mr, .rm, .mrc, .rm0, .rvm, .mvr => {},
    }

    try writer.print("{s} ", .{@tag_name(encoding.mnemonic)});

    for (encoding.data.ops) |op| switch (op) {
        .none, .o16, .o32, .o64 => break,
        else => try writer.print("{s} ", .{@tag_name(op)}),
    };

    const op_en = switch (encoding.data.op_en) {
        .zi => .i,
        else => |op_en| op_en,
    };
    try writer.print("{s}", .{@tag_name(op_en)});
}

pub const Mnemonic = enum {
    // zig fmt: off
    // General-purpose
    adc, add, @"and",
    bsf, bsr, bswap, bt, btc, btr, bts,
    call, cbw, cdq, cdqe, clflush,
    cmova, cmovae, cmovb, cmovbe, cmovc, cmove, cmovg, cmovge, cmovl, cmovle, cmovna,
    cmovnae, cmovnb, cmovnbe, cmovnc, cmovne, cmovng, cmovnge, cmovnl, cmovnle, cmovno,
    cmovnp, cmovns, cmovnz, cmovo, cmovp, cmovpe, cmovpo, cmovs, cmovz,
    cmp,
    cmps, cmpsb, cmpsd, cmpsq, cmpsw,
    cmpxchg, cmpxchg8b, cmpxchg16b,
    cpuid, cqo, cwd, cwde,
    dec, div, idiv, imul, inc, int3,
    ja, jae, jb, jbe, jc, jrcxz, je, jg, jge, jl, jle, jna, jnae, jnb, jnbe,
    jnc, jne, jng, jnge, jnl, jnle, jno, jnp, jns, jnz, jo, jp, jpe, jpo, js, jz,
    jmp, 
    lea, lfence,
    lods, lodsb, lodsd, lodsq, lodsw,
    lzcnt,
    mfence, mov, movbe,
    movs, movsb, movsd, movsq, movsw,
    movsx, movsxd, movzx, mul,
    neg, nop, not,
    @"or",
    pause, pop, popcnt, popfq, push, pushfq,
    rcl, rcr, ret, rol, ror,
    sal, sar, sbb,
    scas, scasb, scasd, scasq, scasw,
    shl, shld, shr, shrd, sub, syscall,
    seta, setae, setb, setbe, setc, sete, setg, setge, setl, setle, setna, setnae,
    setnb, setnbe, setnc, setne, setng, setnge, setnl, setnle, setno, setnp, setns,
    setnz, seto, setp, setpe, setpo, sets, setz,
    sfence,
    stos, stosb, stosd, stosq, stosw,
    @"test", tzcnt,
    ud2,
    xadd, xchg, xgetbv, xor,
    // X87
    fabs, fchs, ffree, fisttp, fld, fldenv, fnstenv, fst, fstenv, fstp,
    // MMX
    movd, movq,
    packssdw, packsswb, packuswb,
    paddb, paddd, paddq, paddsb, paddsw, paddusb, paddusw, paddw,
    pand, pandn, por, pxor,
    pcmpeqb, pcmpeqd, pcmpeqw,
    pcmpgtb, pcmpgtd, pcmpgtw,
    pmulhw, pmullw,
    pslld, psllq, psllw,
    psrad, psraw,
    psrld, psrlq, psrlw,
    psubb, psubd, psubq, psubsb, psubsw, psubusb, psubusw, psubw,
    // SSE
    addps, addss,
    andps,
    andnps,
    cmpps, cmpss,
    cvtpi2ps, cvtps2pi, cvtsi2ss, cvtss2si, cvttps2pi, cvttss2si,
    divps, divss,
    ldmxcsr,
    maxps, maxss,
    minps, minss,
    movaps, movhlps, movlhps,
    movmskps,
    movss, movups,
    mulps, mulss,
    orps,
    pextrw, pinsrw,
    pmaxsw, pmaxub, pminsw, pminub, pmovmskb,
    shufps,
    sqrtps, sqrtss,
    stmxcsr,
    subps, subss,
    ucomiss,
    xorps,
    // SSE2
    addpd, addsd,
    andpd,
    andnpd,
    cmppd, //cmpsd,
    cvtdq2pd, cvtdq2ps, cvtpd2dq, cvtpd2pi, cvtpd2ps, cvtpi2pd,
    cvtps2dq, cvtps2pd, cvtsd2si, cvtsd2ss, cvtsi2sd, cvtss2sd,
    cvttpd2dq, cvttpd2pi, cvttps2dq, cvttsd2si,
    divpd, divsd,
    maxpd, maxsd,
    minpd, minsd,
    movapd,
    movdqa, movdqu,
    movmskpd,
    //movsd,
    movupd,
    mulpd, mulsd,
    orpd,
    pshufd, pshufhw, pshuflw,
    pslldq, psrldq,
    punpckhbw, punpckhdq, punpckhqdq, punpckhwd,
    punpcklbw, punpckldq, punpcklqdq, punpcklwd,
    shufpd,
    sqrtpd, sqrtsd,
    subpd, subsd,
    ucomisd,
    xorpd,
    // SSE3
    movddup, movshdup, movsldup,
    // SSSE3
    pabsb, pabsd, pabsw, palignr, pshufb,
    // SSE4.1
    blendpd, blendps, blendvpd, blendvps,
    extractps,
    insertps,
    packusdw,
    pblendvb, pblendw,
    pcmpeqq,
    pextrb, pextrd, pextrq,
    pinsrb, pinsrd, pinsrq,
    pmaxsb, pmaxsd, pmaxud, pmaxuw, pminsb, pminsd, pminud, pminuw,
    pmovsxbd, pmovsxbq, pmovsxbw, pmovsxdq, pmovsxwd, pmovsxwq,
    pmovzxbd, pmovzxbq, pmovzxbw, pmovzxdq, pmovzxwd, pmovzxwq,
    pmulld,
    roundpd, roundps, roundsd, roundss,
    // SSE4.2
    pcmpgtq,
    // PCLMUL
    pclmulqdq,
    // AES
    aesdec, aesdeclast, aesenc, aesenclast, aesimc, aeskeygenassist,
    // SHA
    sha256msg1, sha256msg2, sha256rnds2,
    // AVX
    vaddpd, vaddps, vaddsd, vaddss,
    vaesdec, vaesdeclast, vaesenc, vaesenclast, vaesimc, vaeskeygenassist,
    vandnpd, vandnps, vandpd, vandps,
    vblendpd, vblendps, vblendvpd, vblendvps,
    vbroadcastf128, vbroadcastsd, vbroadcastss,
    vcmppd, vcmpps, vcmpsd, vcmpss,
    vcvtdq2pd, vcvtdq2ps, vcvtpd2dq, vcvtpd2ps,
    vcvtps2dq, vcvtps2pd, vcvtsd2si, vcvtsd2ss,
    vcvtsi2sd, vcvtsi2ss, vcvtss2sd, vcvtss2si,
    vcvttpd2dq, vcvttps2dq, vcvttsd2si, vcvttss2si,
    vdivpd, vdivps, vdivsd, vdivss,
    vextractf128, vextractps,
    vinsertf128, vinsertps,
    vldmxcsr,
    vmaxpd, vmaxps, vmaxsd, vmaxss,
    vminpd, vminps, vminsd, vminss,
    vmovapd, vmovaps,
    vmovd,
    vmovddup,
    vmovdqa, vmovdqu,
    vmovhlps, vmovlhps,
    vmovmskpd, vmovmskps,
    vmovq,
    vmovsd,
    vmovshdup, vmovsldup,
    vmovss,
    vmovupd, vmovups,
    vmulpd, vmulps, vmulsd, vmulss,
    vorpd, vorps,
    vpabsb, vpabsd, vpabsw,
    vpackssdw, vpacksswb, vpackusdw, vpackuswb,
    vpaddb, vpaddd, vpaddq, vpaddsb, vpaddsw, vpaddusb, vpaddusw, vpaddw,
    vpalignr, vpand, vpandn,
    vpblendvb, vpblendw, vpclmulqdq,
    vpcmpeqb, vpcmpeqd, vpcmpeqq, vpcmpeqw,
    vpcmpgtb, vpcmpgtd, vpcmpgtq, vpcmpgtw,
    vpextrb, vpextrd, vpextrq, vpextrw,
    vpinsrb, vpinsrd, vpinsrq, vpinsrw,
    vpmaxsb, vpmaxsd, vpmaxsw, vpmaxub, vpmaxud, vpmaxuw,
    vpminsb, vpminsd, vpminsw, vpminub, vpminud, vpminuw,
    vpmovmskb,
    vpmovsxbd, vpmovsxbq, vpmovsxbw, vpmovsxdq, vpmovsxwd, vpmovsxwq,
    vpmovzxbd, vpmovzxbq, vpmovzxbw, vpmovzxdq, vpmovzxwd, vpmovzxwq,
    vpmulhw, vpmulld, vpmullw,
    vpor,
    vpshufb, vpshufd, vpshufhw, vpshuflw,
    vpslld, vpslldq, vpsllq, vpsllw,
    vpsrad, vpsraq, vpsraw,
    vpsrld, vpsrldq, vpsrlq, vpsrlw,
    vpsubb, vpsubd, vpsubq, vpsubsb, vpsubsw, vpsubusb, vpsubusw, vpsubw,
    vpunpckhbw, vpunpckhdq, vpunpckhqdq, vpunpckhwd,
    vpunpcklbw, vpunpckldq, vpunpcklqdq, vpunpcklwd,
    vpxor,
    vroundpd, vroundps, vroundsd, vroundss,
    vshufpd, vshufps,
    vsqrtpd, vsqrtps, vsqrtsd, vsqrtss,
    vstmxcsr,
    vsubpd, vsubps, vsubsd, vsubss,
    vxorpd, vxorps,
    // F16C
    vcvtph2ps, vcvtps2ph,
    // FMA
    vfmadd132pd, vfmadd213pd, vfmadd231pd,
    vfmadd132ps, vfmadd213ps, vfmadd231ps,
    vfmadd132sd, vfmadd213sd, vfmadd231sd,
    vfmadd132ss, vfmadd213ss, vfmadd231ss,
    // AVX2
    vbroadcasti128, vpbroadcastb, vpbroadcastd, vpbroadcastq, vpbroadcastw,
    vextracti128, vinserti128, vpblendd,
    // zig fmt: on
};

pub const OpEn = enum {
    // zig fmt: off
    zo,
    o, oi,
    i, zi,
    d, m,
    fd, td,
    m1, mc, mi, mr, rm,
    rmi, mri, mrc,
    rm0, vmi, rvm, rvmr, rvmi, mvr,
    // zig fmt: on
};

pub const Op = enum {
    // zig fmt: off
    none,
    o16, o32, o64,
    unity,
    imm8, imm16, imm32, imm64,
    imm8s, imm16s, imm32s,
    al, ax, eax, rax,
    cl,
    r8, r16, r32, r64,
    rm8, rm16, rm32, rm64,
    r32_m8, r32_m16, r64_m16,
    m8, m16, m32, m64, m80, m128, m256,
    rel8, rel16, rel32,
    m,
    moffs,
    sreg,
    st, mm, mm_m64,
    xmm0, xmm, xmm_m8, xmm_m16, xmm_m32, xmm_m64, xmm_m128,
    ymm, ymm_m256,
    // zig fmt: on

    pub fn from_operand(operand: Instruction.Operand) Op {
        return switch (operand) {
            .none => .none,

            .reg => |reg| switch (reg.class()) {
                .general_purpose => if (reg.to64() == .rax)
                    switch (reg) {
                        .al => .al,
                        .ax => .ax,
                        .eax => .eax,
                        .rax => .rax,
                        else => unreachable,
                    }
                else if (reg == .cl)
                    .cl
                else switch (reg.bit_size()) {
                    8 => .r8,
                    16 => .r16,
                    32 => .r32,
                    64 => .r64,
                    else => unreachable,
                },
                .segment => .sreg,
                .x87 => .st,
                .mmx => .mm,
                .sse => if (reg == .xmm0)
                    .xmm0
                else switch (reg.bit_size()) {
                    128 => .xmm,
                    256 => .ymm,
                    else => unreachable,
                },
            },

            .mem => |mem| switch (mem) {
                .moffs => .moffs,
                .sib, .rip => switch (mem.bit_size()) {
                    0 => .m,
                    8 => .m8,
                    16 => .m16,
                    32 => .m32,
                    64 => .m64,
                    80 => .m80,
                    128 => .m128,
                    256 => .m256,
                    else => unreachable,
                },
            },

            .imm => |imm| switch (imm) {
                .signed => |x| if (x == 1)
                    .unity
                else if (math.cast(i8, x)) |_|
                    .imm8s
                else if (math.cast(i16, x)) |_|
                    .imm16s
                else
                    .imm32s,
                .unsigned => |x| if (x == 1)
                    .unity
                else if (math.cast(i8, x)) |_|
                    .imm8s
                else if (math.cast(u8, x)) |_|
                    .imm8
                else if (math.cast(i16, x)) |_|
                    .imm16s
                else if (math.cast(u16, x)) |_|
                    .imm16
                else if (math.cast(i32, x)) |_|
                    .imm32s
                else if (math.cast(u32, x)) |_|
                    .imm32
                else
                    .imm64,
            },
        };
    }

    pub fn imm_bit_size(op: Op) u64 {
        return switch (op) {
            .none, .o16, .o32, .o64, .moffs, .m, .sreg => unreachable,
            .al, .cl, .r8, .rm8, .r32_m8 => unreachable,
            .ax, .r16, .rm16 => unreachable,
            .eax, .r32, .rm32, .r32_m16 => unreachable,
            .rax, .r64, .rm64, .r64_m16 => unreachable,
            .st, .mm, .mm_m64 => unreachable,
            .xmm0, .xmm, .xmm_m8, .xmm_m16, .xmm_m32, .xmm_m64, .xmm_m128 => unreachable,
            .ymm, .ymm_m256 => unreachable,
            .m8, .m16, .m32, .m64, .m80, .m128, .m256 => unreachable,
            .unity => 1,
            .imm8, .imm8s, .rel8 => 8,
            .imm16, .imm16s, .rel16 => 16,
            .imm32, .imm32s, .rel32 => 32,
            .imm64 => 64,
        };
    }

    pub fn reg_bit_size(op: Op) u64 {
        return switch (op) {
            .none, .o16, .o32, .o64, .moffs, .m, .sreg => unreachable,
            .unity, .imm8, .imm8s, .imm16, .imm16s, .imm32, .imm32s, .imm64 => unreachable,
            .rel8, .rel16, .rel32 => unreachable,
            .m8, .m16, .m32, .m64, .m80, .m128, .m256 => unreachable,
            .al, .cl, .r8, .rm8 => 8,
            .ax, .r16, .rm16 => 16,
            .eax, .r32, .rm32, .r32_m8, .r32_m16 => 32,
            .rax, .r64, .rm64, .r64_m16, .mm, .mm_m64 => 64,
            .st => 80,
            .xmm0, .xmm, .xmm_m8, .xmm_m16, .xmm_m32, .xmm_m64, .xmm_m128 => 128,
            .ymm, .ymm_m256 => 256,
        };
    }

    pub fn mem_bit_size(op: Op) u64 {
        return switch (op) {
            .none, .o16, .o32, .o64, .moffs, .m, .sreg => unreachable,
            .unity, .imm8, .imm8s, .imm16, .imm16s, .imm32, .imm32s, .imm64 => unreachable,
            .rel8, .rel16, .rel32 => unreachable,
            .al, .cl, .r8, .ax, .r16, .eax, .r32, .rax, .r64 => unreachable,
            .st, .mm, .xmm0, .xmm, .ymm => unreachable,
            .m8, .rm8, .r32_m8, .xmm_m8 => 8,
            .m16, .rm16, .r32_m16, .r64_m16, .xmm_m16 => 16,
            .m32, .rm32, .xmm_m32 => 32,
            .m64, .rm64, .mm_m64, .xmm_m64 => 64,
            .m80 => 80,
            .m128, .xmm_m128 => 128,
            .m256, .ymm_m256 => 256,
        };
    }

    pub fn is_signed(op: Op) bool {
        return switch (op) {
            .unity, .imm8, .imm16, .imm32, .imm64 => false,
            .imm8s, .imm16s, .imm32s => true,
            .rel8, .rel16, .rel32 => true,
            else => unreachable,
        };
    }

    pub fn is_unsigned(op: Op) bool {
        return !op.is_signed();
    }

    pub fn is_register(op: Op) bool {
        // zig fmt: off
        return switch (op) {
            .cl,
            .al, .ax, .eax, .rax,
            .r8, .r16, .r32, .r64,
            .rm8, .rm16, .rm32, .rm64,
            .r32_m8, .r32_m16, .r64_m16,
            .st, .mm, .mm_m64,
            .xmm0, .xmm, .xmm_m8, .xmm_m16, .xmm_m32, .xmm_m64, .xmm_m128,
            .ymm, .ymm_m256,
            => true,
            else => false,
        };
        // zig fmt: on
    }

    pub fn is_immediate(op: Op) bool {
        // zig fmt: off
        return switch (op) {
            .imm8, .imm16, .imm32, .imm64, 
            .imm8s, .imm16s, .imm32s,
            .rel8, .rel16, .rel32,
            .unity,
            => true,
            else => false,
        };
        // zig fmt: on
    }

    pub fn is_memory(op: Op) bool {
        // zig fmt: off
        return switch (op) {
            .rm8, .rm16, .rm32, .rm64,
            .r32_m8, .r32_m16, .r64_m16,
            .m8, .m16, .m32, .m64, .m80, .m128, .m256,
            .m,
            .mm_m64,
            .xmm_m8, .xmm_m16, .xmm_m32, .xmm_m64, .xmm_m128,
            .ymm_m256,
            => true,
            else => false,
        };
        // zig fmt: on
    }

    pub fn is_segment_register(op: Op) bool {
        return switch (op) {
            .moffs, .sreg => true,
            else => false,
        };
    }

    pub fn class(op: Op) bits.Register.Class {
        return switch (op) {
            else => unreachable,
            .al, .ax, .eax, .rax, .cl => .general_purpose,
            .r8, .r16, .r32, .r64 => .general_purpose,
            .rm8, .rm16, .rm32, .rm64 => .general_purpose,
            .r32_m8, .r32_m16, .r64_m16 => .general_purpose,
            .sreg => .segment,
            .st => .x87,
            .mm, .mm_m64 => .mmx,
            .xmm0, .xmm, .xmm_m8, .xmm_m16, .xmm_m32, .xmm_m64, .xmm_m128 => .sse,
            .ymm, .ymm_m256 => .sse,
        };
    }

    /// Given an operand `op` checks if `target` is a subset for the purposes of the encoding.
    pub fn is_subset(op: Op, target: Op) bool {
        switch (op) {
            .o16, .o32, .o64 => unreachable,
            .moffs, .sreg => return op == target,
            .none => switch (target) {
                .o16, .o32, .o64, .none => return true,
                else => return false,
            },
            else => {
                if (op.is_register() and target.is_register()) {
                    return switch (target) {
                        .cl, .al, .ax, .eax, .rax, .xmm0 => op == target,
                        else => op.class() == target.class() and op.reg_bit_size() == target.reg_bit_size(),
                    };
                }
                if (op.is_memory() and target.is_memory()) {
                    switch (target) {
                        .m => return true,
                        else => return op.mem_bit_size() == target.mem_bit_size(),
                    }
                }
                if (op.is_immediate() and target.is_immediate()) {
                    switch (target) {
                        .imm64 => if (op.imm_bit_size() <= 64) return true,
                        .imm32s, .rel32 => if (op.imm_bit_size() < 32 or (op.imm_bit_size() == 32 and op.is_signed()))
                            return true,
                        .imm32 => if (op.imm_bit_size() <= 32) return true,
                        .imm16s, .rel16 => if (op.imm_bit_size() < 16 or (op.imm_bit_size() == 16 and op.is_signed()))
                            return true,
                        .imm16 => if (op.imm_bit_size() <= 16) return true,
                        .imm8s, .rel8 => if (op.imm_bit_size() < 8 or (op.imm_bit_size() == 8 and op.is_signed()))
                            return true,
                        .imm8 => if (op.imm_bit_size() <= 8) return true,
                        else => {},
                    }
                    return op == target;
                }
                return false;
            },
        }
    }
};

pub const Mode = enum {
    // zig fmt: off
    none,
    short, long,
    rex, rex_short,
    vex_128_w0, vex_128_w1, vex_128_wig,
    vex_256_w0, vex_256_w1, vex_256_wig,
    vex_lig_w0, vex_lig_w1, vex_lig_wig,
    vex_lz_w0,  vex_lz_w1,  vex_lz_wig,
    // zig fmt: on

    pub fn is_short(mode: Mode) bool {
        return switch (mode) {
            .short, .rex_short => true,
            else => false,
        };
    }

    pub fn is_long(mode: Mode) bool {
        return switch (mode) {
            .long,
            .vex_128_w1,
            .vex_256_w1,
            .vex_lig_w1,
            .vex_lz_w1,
            => true,
            else => false,
        };
    }

    pub fn is_rex(mode: Mode) bool {
        return switch (mode) {
            else => false,
            .rex, .rex_short => true,
        };
    }

    pub fn is_vex(mode: Mode) bool {
        return switch (mode) {
            // zig fmt: off
            else => false,
            .vex_128_w0, .vex_128_w1, .vex_128_wig,
            .vex_256_w0, .vex_256_w1, .vex_256_wig,
            .vex_lig_w0, .vex_lig_w1, .vex_lig_wig,
            .vex_lz_w0,  .vex_lz_w1,  .vex_lz_wig,
            => true,
            // zig fmt: on
        };
    }

    pub fn is_vec_long(mode: Mode) bool {
        return switch (mode) {
            // zig fmt: off
            else => unreachable,
            .vex_128_w0, .vex_128_w1, .vex_128_wig,
            .vex_lig_w0, .vex_lig_w1, .vex_lig_wig,
            .vex_lz_w0,  .vex_lz_w1,  .vex_lz_wig,
            => false,
            .vex_256_w0, .vex_256_w1, .vex_256_wig,
            => true,
            // zig fmt: on
        };
    }
};

pub const Feature = enum {
    none,
    aes,
    @"aes avx",
    avx,
    avx2,
    bmi,
    f16c,
    fma,
    lzcnt,
    movbe,
    pclmul,
    @"pclmul avx",
    popcnt,
    sse,
    sse2,
    sse3,
    sse4_1,
    sse4_2,
    ssse3,
    sha,
    vaes,
    vpclmulqdq,
    x87,
};

fn estimate_instruction_length(prefix: Prefix, encoding: Encoding, ops: []const Operand) usize {
    var inst = Instruction{
        .prefix = prefix,
        .encoding = encoding,
        .ops = [1]Operand{.none} ** 4,
    };
    @memcpy(inst.ops[0..ops.len], ops);

    var cwriter = std.io.counting_writer(std.io.null_writer);
    inst.encode(cwriter.writer(), .{
        .allow_frame_locs = true,
        .allow_symbols = true,
    }) catch unreachable; // Not allowed to fail here unless OOM.
    return @as(usize, @int_cast(cwriter.bytes_written));
}

const mnemonic_to_encodings_map = init: {
    @setEvalBranchQuota(5_000);
    const mnemonic_count = @typeInfo(Mnemonic).Enum.fields.len;
    var mnemonic_map: [mnemonic_count][]Data = .{&.{}} ** mnemonic_count;
    const encodings = @import("encodings.zig");
    for (encodings.table) |entry| mnemonic_map[@int_from_enum(entry[0])].len += 1;
    var data_storage: [encodings.table.len]Data = undefined;
    var storage_i: usize = 0;
    for (&mnemonic_map) |*value| {
        value.ptr = data_storage[storage_i..].ptr;
        storage_i += value.len;
    }
    var mnemonic_i: [mnemonic_count]usize = .{0} ** mnemonic_count;
    const ops_len = @typeInfo(std.meta.FieldType(Data, .ops)).Array.len;
    const opc_len = @typeInfo(std.meta.FieldType(Data, .opc)).Array.len;
    for (encodings.table) |entry| {
        const i = &mnemonic_i[@int_from_enum(entry[0])];
        mnemonic_map[@int_from_enum(entry[0])][i.*] = .{
            .op_en = entry[1],
            .ops = (entry[2] ++ .{.none} ** (ops_len - entry[2].len)).*,
            .opc_len = entry[3].len,
            .opc = (entry[3] ++ .{undefined} ** (opc_len - entry[3].len)).*,
            .modrm_ext = entry[4],
            .mode = entry[5],
            .feature = entry[6],
        };
        i.* += 1;
    }
    const final_storage = data_storage;
    var final_map: [mnemonic_count][]const Data = .{&.{}} ** mnemonic_count;
    storage_i = 0;
    for (&final_map, mnemonic_map) |*final_value, value| {
        final_value.* = final_storage[storage_i..][0..value.len];
        storage_i += value.len;
    }
    break :init final_map;
};
