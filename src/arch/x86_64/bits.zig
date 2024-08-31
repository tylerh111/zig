const std = @import("std");
const assert = std.debug.assert;
const expect = std.testing.expect;

const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const DW = std.dwarf;

/// EFLAGS condition codes
pub const Condition = enum(u5) {
    /// above
    a,
    /// above or equal
    ae,
    /// below
    b,
    /// below or equal
    be,
    /// carry
    c,
    /// equal
    e,
    /// greater
    g,
    /// greater or equal
    ge,
    /// less
    l,
    /// less or equal
    le,
    /// not above
    na,
    /// not above or equal
    nae,
    /// not below
    nb,
    /// not below or equal
    nbe,
    /// not carry
    nc,
    /// not equal
    ne,
    /// not greater
    ng,
    /// not greater or equal
    nge,
    /// not less
    nl,
    /// not less or equal
    nle,
    /// not overflow
    no,
    /// not parity
    np,
    /// not sign
    ns,
    /// not zero
    nz,
    /// overflow
    o,
    /// parity
    p,
    /// parity even
    pe,
    /// parity odd
    po,
    /// sign
    s,
    /// zero
    z,

    // Pseudo conditions
    /// zero and not parity
    z_and_np,
    /// not zero or parity
    nz_or_p,

    /// Converts a std.math.CompareOperator into a condition flag,
    /// i.e. returns the condition that is true iff the result of the
    /// comparison is true. Assumes signed comparison
    pub fn from_compare_operator_signed(op: std.math.CompareOperator) Condition {
        return switch (op) {
            .gte => .ge,
            .gt => .g,
            .neq => .ne,
            .lt => .l,
            .lte => .le,
            .eq => .e,
        };
    }

    /// Converts a std.math.CompareOperator into a condition flag,
    /// i.e. returns the condition that is true iff the result of the
    /// comparison is true. Assumes unsigned comparison
    pub fn from_compare_operator_unsigned(op: std.math.CompareOperator) Condition {
        return switch (op) {
            .gte => .ae,
            .gt => .a,
            .neq => .ne,
            .lt => .b,
            .lte => .be,
            .eq => .e,
        };
    }

    pub fn from_compare_operator(
        signedness: std.builtin.Signedness,
        op: std.math.CompareOperator,
    ) Condition {
        return switch (signedness) {
            .signed => from_compare_operator_signed(op),
            .unsigned => from_compare_operator_unsigned(op),
        };
    }

    /// Returns the condition which is true iff the given condition is false
    pub fn negate(cond: Condition) Condition {
        return switch (cond) {
            .a => .na,
            .ae => .nae,
            .b => .nb,
            .be => .nbe,
            .c => .nc,
            .e => .ne,
            .g => .ng,
            .ge => .nge,
            .l => .nl,
            .le => .nle,
            .na => .a,
            .nae => .ae,
            .nb => .b,
            .nbe => .be,
            .nc => .c,
            .ne => .e,
            .ng => .g,
            .nge => .ge,
            .nl => .l,
            .nle => .le,
            .no => .o,
            .np => .p,
            .ns => .s,
            .nz => .z,
            .o => .no,
            .p => .np,
            .pe => .po,
            .po => .pe,
            .s => .ns,
            .z => .nz,

            .z_and_np => .nz_or_p,
            .nz_or_p => .z_and_np,
        };
    }
};

pub const Register = enum(u7) {
    // zig fmt: off
    rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi,
    r8, r9, r10, r11, r12, r13, r14, r15,

    eax, ecx, edx, ebx, esp, ebp, esi, edi,
    r8d, r9d, r10d, r11d, r12d, r13d, r14d, r15d,

    ax, cx, dx, bx, sp, bp, si, di,
    r8w, r9w, r10w, r11w, r12w, r13w, r14w, r15w,

    al, cl, dl, bl, spl, bpl, sil, dil,
    r8b, r9b, r10b, r11b, r12b, r13b, r14b, r15b,

    ah, ch, dh, bh,

    ymm0, ymm1, ymm2,  ymm3,  ymm4,  ymm5,  ymm6,  ymm7,
    ymm8, ymm9, ymm10, ymm11, ymm12, ymm13, ymm14, ymm15,

    xmm0, xmm1, xmm2,  xmm3,  xmm4,  xmm5,  xmm6,  xmm7,
    xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15,

    mm0, mm1, mm2, mm3, mm4, mm5, mm6, mm7,

    st0, st1, st2, st3, st4, st5, st6, st7,

    es, cs, ss, ds, fs, gs,

    rip, eip, ip,

    none,
    // zig fmt: on

    pub const Class = enum {
        general_purpose,
        segment,
        x87,
        mmx,
        sse,
    };

    pub fn class(reg: Register) Class {
        return switch (@int_from_enum(reg)) {
            // zig fmt: off
            @int_from_enum(Register.rax)  ... @int_from_enum(Register.r15)   => .general_purpose,
            @int_from_enum(Register.eax)  ... @int_from_enum(Register.r15d)  => .general_purpose,
            @int_from_enum(Register.ax)   ... @int_from_enum(Register.r15w)  => .general_purpose,
            @int_from_enum(Register.al)   ... @int_from_enum(Register.r15b)  => .general_purpose,
            @int_from_enum(Register.ah)   ... @int_from_enum(Register.bh)    => .general_purpose,

            @int_from_enum(Register.ymm0) ... @int_from_enum(Register.ymm15) => .sse,
            @int_from_enum(Register.xmm0) ... @int_from_enum(Register.xmm15) => .sse,
            @int_from_enum(Register.mm0)  ... @int_from_enum(Register.mm7)   => .mmx,
            @int_from_enum(Register.st0)  ... @int_from_enum(Register.st7)   => .x87,

            @int_from_enum(Register.es)   ... @int_from_enum(Register.gs)    => .segment,

            else => unreachable,
            // zig fmt: on
        };
    }

    pub fn id(reg: Register) u6 {
        const base = switch (@int_from_enum(reg)) {
            // zig fmt: off
            @int_from_enum(Register.rax)  ... @int_from_enum(Register.r15)   => @int_from_enum(Register.rax),
            @int_from_enum(Register.eax)  ... @int_from_enum(Register.r15d)  => @int_from_enum(Register.eax),
            @int_from_enum(Register.ax)   ... @int_from_enum(Register.r15w)  => @int_from_enum(Register.ax),
            @int_from_enum(Register.al)   ... @int_from_enum(Register.r15b)  => @int_from_enum(Register.al),
            @int_from_enum(Register.ah)   ... @int_from_enum(Register.bh)    => @int_from_enum(Register.ah),

            @int_from_enum(Register.ymm0) ... @int_from_enum(Register.ymm15) => @int_from_enum(Register.ymm0) - 16,
            @int_from_enum(Register.xmm0) ... @int_from_enum(Register.xmm15) => @int_from_enum(Register.xmm0) - 16,
            @int_from_enum(Register.mm0)  ... @int_from_enum(Register.mm7)   => @int_from_enum(Register.mm0) - 32,
            @int_from_enum(Register.st0)  ... @int_from_enum(Register.st7)   => @int_from_enum(Register.st0) - 40,

            @int_from_enum(Register.es)   ... @int_from_enum(Register.gs)    => @int_from_enum(Register.es) - 48,

            else => unreachable,
            // zig fmt: on
        };
        return @int_cast(@int_from_enum(reg) - base);
    }

    pub fn bit_size(reg: Register) u10 {
        return switch (@int_from_enum(reg)) {
            // zig fmt: off
            @int_from_enum(Register.rax)  ... @int_from_enum(Register.r15)   => 64,
            @int_from_enum(Register.eax)  ... @int_from_enum(Register.r15d)  => 32,
            @int_from_enum(Register.ax)   ... @int_from_enum(Register.r15w)  => 16,
            @int_from_enum(Register.al)   ... @int_from_enum(Register.r15b)  => 8,
            @int_from_enum(Register.ah)   ... @int_from_enum(Register.bh)    => 8,

            @int_from_enum(Register.ymm0) ... @int_from_enum(Register.ymm15) => 256,
            @int_from_enum(Register.xmm0) ... @int_from_enum(Register.xmm15) => 128,
            @int_from_enum(Register.mm0)  ... @int_from_enum(Register.mm7)   => 64,
            @int_from_enum(Register.st0)  ... @int_from_enum(Register.st7)   => 80,

            @int_from_enum(Register.es)   ... @int_from_enum(Register.gs)    => 16,

            else => unreachable,
            // zig fmt: on
        };
    }

    pub fn is_extended(reg: Register) bool {
        return switch (@int_from_enum(reg)) {
            // zig fmt: off
            @int_from_enum(Register.r8)  ... @int_from_enum(Register.r15)    => true,
            @int_from_enum(Register.r8d) ... @int_from_enum(Register.r15d)   => true,
            @int_from_enum(Register.r8w) ... @int_from_enum(Register.r15w)   => true,
            @int_from_enum(Register.r8b) ... @int_from_enum(Register.r15b)   => true,

            @int_from_enum(Register.ymm8) ... @int_from_enum(Register.ymm15) => true,
            @int_from_enum(Register.xmm8) ... @int_from_enum(Register.xmm15) => true,

            else => false,
            // zig fmt: on
        };
    }

    pub fn enc(reg: Register) u4 {
        const base = switch (@int_from_enum(reg)) {
            // zig fmt: off
            @int_from_enum(Register.rax)  ... @int_from_enum(Register.r15)   => @int_from_enum(Register.rax),
            @int_from_enum(Register.eax)  ... @int_from_enum(Register.r15d)  => @int_from_enum(Register.eax),
            @int_from_enum(Register.ax)   ... @int_from_enum(Register.r15w)  => @int_from_enum(Register.ax),
            @int_from_enum(Register.al)   ... @int_from_enum(Register.r15b)  => @int_from_enum(Register.al),
            @int_from_enum(Register.ah)   ... @int_from_enum(Register.bh)    => @int_from_enum(Register.ah) - 4,

            @int_from_enum(Register.ymm0) ... @int_from_enum(Register.ymm15) => @int_from_enum(Register.ymm0),
            @int_from_enum(Register.xmm0) ... @int_from_enum(Register.xmm15) => @int_from_enum(Register.xmm0),
            @int_from_enum(Register.mm0)  ... @int_from_enum(Register.mm7)   => @int_from_enum(Register.mm0),
            @int_from_enum(Register.st0)  ... @int_from_enum(Register.st7)   => @int_from_enum(Register.st0),

            @int_from_enum(Register.es)   ... @int_from_enum(Register.gs)    => @int_from_enum(Register.es),

            else => unreachable,
            // zig fmt: on
        };
        return @truncate(@int_from_enum(reg) - base);
    }

    pub fn low_enc(reg: Register) u3 {
        return @truncate(reg.enc());
    }

    pub fn to_bit_size(reg: Register, bit_size: u64) Register {
        return switch (bit_size) {
            8 => reg.to8(),
            16 => reg.to16(),
            32 => reg.to32(),
            64 => reg.to64(),
            128 => reg.to128(),
            256 => reg.to256(),
            else => unreachable,
        };
    }

    fn gp_base(reg: Register) u7 {
        assert(reg.class() == .general_purpose);
        return switch (@int_from_enum(reg)) {
            // zig fmt: off
            @int_from_enum(Register.rax)  ... @int_from_enum(Register.r15)   => @int_from_enum(Register.rax),
            @int_from_enum(Register.eax)  ... @int_from_enum(Register.r15d)  => @int_from_enum(Register.eax),
            @int_from_enum(Register.ax)   ... @int_from_enum(Register.r15w)  => @int_from_enum(Register.ax),
            @int_from_enum(Register.al)   ... @int_from_enum(Register.r15b)  => @int_from_enum(Register.al),
            @int_from_enum(Register.ah)   ... @int_from_enum(Register.bh)    => @int_from_enum(Register.ah) - 4,
            else => unreachable,
            // zig fmt: on
        };
    }

    pub fn to64(reg: Register) Register {
        return @enumFromInt(@int_from_enum(reg) - reg.gp_base() + @int_from_enum(Register.rax));
    }

    pub fn to32(reg: Register) Register {
        return @enumFromInt(@int_from_enum(reg) - reg.gp_base() + @int_from_enum(Register.eax));
    }

    pub fn to16(reg: Register) Register {
        return @enumFromInt(@int_from_enum(reg) - reg.gp_base() + @int_from_enum(Register.ax));
    }

    pub fn to8(reg: Register) Register {
        return @enumFromInt(@int_from_enum(reg) - reg.gp_base() + @int_from_enum(Register.al));
    }

    fn sse_base(reg: Register) u7 {
        assert(reg.class() == .sse);
        return switch (@int_from_enum(reg)) {
            @int_from_enum(Register.ymm0)...@int_from_enum(Register.ymm15) => @int_from_enum(Register.ymm0),
            @int_from_enum(Register.xmm0)...@int_from_enum(Register.xmm15) => @int_from_enum(Register.xmm0),
            else => unreachable,
        };
    }

    pub fn to256(reg: Register) Register {
        return @enumFromInt(@int_from_enum(reg) - reg.sse_base() + @int_from_enum(Register.ymm0));
    }

    pub fn to128(reg: Register) Register {
        return @enumFromInt(@int_from_enum(reg) - reg.sse_base() + @int_from_enum(Register.xmm0));
    }

    /// DWARF register encoding
    pub fn dwarf_num(reg: Register) u6 {
        return switch (reg.class()) {
            .general_purpose => if (reg.is_extended())
                reg.enc()
            else
                @as(u3, @truncate(@as(u24, 0o54673120) >> @as(u5, reg.enc()) * 3)),
            .sse => 17 + @as(u6, reg.enc()),
            .x87 => 33 + @as(u6, reg.enc()),
            .mmx => 41 + @as(u6, reg.enc()),
            .segment => 50 + @as(u6, reg.enc()),
        };
    }
};

test "Register id - different classes" {
    try expect(Register.al.id() == Register.ax.id());
    try expect(Register.ah.id() == Register.spl.id());
    try expect(Register.ax.id() == Register.eax.id());
    try expect(Register.eax.id() == Register.rax.id());

    try expect(Register.ymm0.id() == 0b10000);
    try expect(Register.ymm0.id() != Register.rax.id());
    try expect(Register.xmm0.id() == Register.ymm0.id());
    try expect(Register.xmm0.id() != Register.mm0.id());
    try expect(Register.mm0.id() != Register.st0.id());

    try expect(Register.es.id() == 0b110000);
}

test "Register enc - different classes" {
    try expect(Register.al.enc() == Register.ax.enc());
    try expect(Register.ax.enc() == Register.eax.enc());
    try expect(Register.eax.enc() == Register.rax.enc());
    try expect(Register.ymm0.enc() == Register.rax.enc());
    try expect(Register.xmm0.enc() == Register.ymm0.enc());
    try expect(Register.es.enc() == Register.rax.enc());
}

test "Register classes" {
    try expect(Register.r11.class() == .general_purpose);
    try expect(Register.ymm11.class() == .sse);
    try expect(Register.mm3.class() == .mmx);
    try expect(Register.st3.class() == .x87);
    try expect(Register.fs.class() == .segment);
}

pub const FrameIndex = enum(u32) {
    // This index refers to the start of the arguments passed to this function
    args_frame,
    // This index refers to the return address pushed by a `call` and popped by a `ret`.
    ret_addr,
    // This index refers to the base pointer pushed in the prologue and popped in the epilogue.
    base_ptr,
    // This index refers to the entire stack frame.
    stack_frame,
    // This index refers to the start of the call frame for arguments passed to called functions
    call_frame,
    // Other indices are used for local variable stack slots
    _,

    pub const named_count = @typeInfo(FrameIndex).Enum.fields.len;

    pub fn is_named(fi: FrameIndex) bool {
        return @int_from_enum(fi) < named_count;
    }

    pub fn format(
        fi: FrameIndex,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        try writer.write_all("FrameIndex");
        if (fi.is_named()) {
            try writer.write_byte('.');
            try writer.write_all(@tag_name(fi));
        } else {
            try writer.write_byte('(');
            try std.fmt.format_type(@int_from_enum(fi), fmt, options, writer, 0);
            try writer.write_byte(')');
        }
    }
};

/// A linker symbol not yet allocated in VM.
pub const Symbol = struct {
    /// Index of the containing atom.
    atom_index: u32,
    /// Index into the linker's symbol table.
    sym_index: u32,

    pub fn format(
        sym: Symbol,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        try writer.write_all("Symbol(");
        try std.fmt.format_type(sym.atom_index, fmt, options, writer, 0);
        try writer.write_all(", ");
        try std.fmt.format_type(sym.sym_index, fmt, options, writer, 0);
        try writer.write_byte(')');
    }
};

pub const Memory = struct {
    base: Base,
    mod: Mod,

    pub const Base = union(enum(u2)) {
        none,
        reg: Register,
        frame: FrameIndex,
        reloc: Symbol,

        pub const Tag = @typeInfo(Base).Union.tag_type.?;

        pub fn is_extended(self: Base) bool {
            return switch (self) {
                .none, .frame, .reloc => false, // rsp, rbp, and rip are not extended
                .reg => |reg| reg.is_extended(),
            };
        }
    };

    pub const Mod = union(enum(u1)) {
        rm: struct {
            size: Size,
            index: Register = .none,
            scale: Scale = .@"1",
            disp: i32 = 0,
        },
        off: u64,
    };

    pub const Size = enum(u4) {
        none,
        byte,
        word,
        dword,
        qword,
        tbyte,
        xword,
        yword,
        zword,

        pub fn from_size(size: u32) Size {
            return switch (size) {
                1...1 => .byte,
                2...2 => .word,
                3...4 => .dword,
                5...8 => .qword,
                9...16 => .xword,
                17...32 => .yword,
                33...64 => .zword,
                else => unreachable,
            };
        }

        pub fn from_bit_size(bit_size: u64) Size {
            return switch (bit_size) {
                8 => .byte,
                16 => .word,
                32 => .dword,
                64 => .qword,
                80 => .tbyte,
                128 => .xword,
                256 => .yword,
                512 => .zword,
                else => unreachable,
            };
        }

        pub fn bit_size(s: Size) u64 {
            return switch (s) {
                .none => 0,
                .byte => 8,
                .word => 16,
                .dword => 32,
                .qword => 64,
                .tbyte => 80,
                .xword => 128,
                .yword => 256,
                .zword => 512,
            };
        }

        pub fn format(
            s: Size,
            comptime _: []const u8,
            _: std.fmt.FormatOptions,
            writer: anytype,
        ) @TypeOf(writer).Error!void {
            if (s == .none) return;
            try writer.write_all(@tag_name(s));
            try writer.write_all(" ptr");
        }
    };

    pub const Scale = enum(u2) { @"1", @"2", @"4", @"8" };
};

pub const Immediate = union(enum) {
    signed: i32,
    unsigned: u64,

    pub fn u(x: u64) Immediate {
        return .{ .unsigned = x };
    }

    pub fn s(x: i32) Immediate {
        return .{ .signed = x };
    }

    pub fn as_signed(imm: Immediate, bit_size: u64) i64 {
        return switch (imm) {
            .signed => |x| switch (bit_size) {
                1, 8 => @as(i8, @int_cast(x)),
                16 => @as(i16, @int_cast(x)),
                32, 64 => x,
                else => unreachable,
            },
            .unsigned => |x| switch (bit_size) {
                1, 8 => @as(i8, @bit_cast(@as(u8, @int_cast(x)))),
                16 => @as(i16, @bit_cast(@as(u16, @int_cast(x)))),
                32 => @as(i32, @bit_cast(@as(u32, @int_cast(x)))),
                64 => @bit_cast(x),
                else => unreachable,
            },
        };
    }

    pub fn as_unsigned(imm: Immediate, bit_size: u64) u64 {
        return switch (imm) {
            .signed => |x| switch (bit_size) {
                1, 8 => @as(u8, @bit_cast(@as(i8, @int_cast(x)))),
                16 => @as(u16, @bit_cast(@as(i16, @int_cast(x)))),
                32, 64 => @as(u32, @bit_cast(x)),
                else => unreachable,
            },
            .unsigned => |x| switch (bit_size) {
                1, 8 => @as(u8, @int_cast(x)),
                16 => @as(u16, @int_cast(x)),
                32 => @as(u32, @int_cast(x)),
                64 => x,
                else => unreachable,
            },
        };
    }
};
