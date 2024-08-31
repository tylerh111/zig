const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const log = std.log.scoped(.codegen);
const math = std.math;
const DW = std.dwarf;

const Builder = @import("llvm/Builder.zig");
const llvm = if (build_options.have_llvm)
    @import("llvm/bindings.zig")
else
    @compile_error("LLVM unavailable");
const link = @import("../link.zig");
const Compilation = @import("../Compilation.zig");
const build_options = @import("build_options");
const Module = @import("../Module.zig");
const Zcu = Module;
const InternPool = @import("../InternPool.zig");
const Package = @import("../Package.zig");
const Air = @import("../Air.zig");
const Liveness = @import("../Liveness.zig");
const Value = @import("../Value.zig");
const Type = @import("../type.zig").Type;
const LazySrcLoc = std.zig.LazySrcLoc;
const x86_64_abi = @import("../arch/x86_64/abi.zig");
const wasm_c_abi = @import("../arch/wasm/abi.zig");
const aarch64_c_abi = @import("../arch/aarch64/abi.zig");
const arm_c_abi = @import("../arch/arm/abi.zig");
const riscv_c_abi = @import("../arch/riscv64/abi.zig");

const target_util = @import("../target.zig");
const libc_float_prefix = target_util.libc_float_prefix;
const libc_float_suffix = target_util.libc_float_suffix;
const compiler_rt_float_abbrev = target_util.compiler_rt_float_abbrev;
const compiler_rt_int_abbrev = target_util.compiler_rt_int_abbrev;

const Error = error{ OutOfMemory, CodegenFail };

pub fn target_triple(allocator: Allocator, target: std.Target) ![]const u8 {
    var llvm_triple = std.ArrayList(u8).init(allocator);
    defer llvm_triple.deinit();

    const llvm_arch = switch (target.cpu.arch) {
        .arm => "arm",
        .armeb => "armeb",
        .aarch64 => "aarch64",
        .aarch64_be => "aarch64_be",
        .aarch64_32 => "aarch64_32",
        .arc => "arc",
        .avr => "avr",
        .bpfel => "bpfel",
        .bpfeb => "bpfeb",
        .csky => "csky",
        .dxil => "dxil",
        .hexagon => "hexagon",
        .loongarch32 => "loongarch32",
        .loongarch64 => "loongarch64",
        .m68k => "m68k",
        .mips => "mips",
        .mipsel => "mipsel",
        .mips64 => "mips64",
        .mips64el => "mips64el",
        .msp430 => "msp430",
        .powerpc => "powerpc",
        .powerpcle => "powerpcle",
        .powerpc64 => "powerpc64",
        .powerpc64le => "powerpc64le",
        .r600 => "r600",
        .amdgcn => "amdgcn",
        .riscv32 => "riscv32",
        .riscv64 => "riscv64",
        .sparc => "sparc",
        .sparc64 => "sparc64",
        .sparcel => "sparcel",
        .s390x => "s390x",
        .tce => "tce",
        .tcele => "tcele",
        .thumb => "thumb",
        .thumbeb => "thumbeb",
        .x86 => "i386",
        .x86_64 => "x86_64",
        .xcore => "xcore",
        .xtensa => "xtensa",
        .nvptx => "nvptx",
        .nvptx64 => "nvptx64",
        .le32 => "le32",
        .le64 => "le64",
        .amdil => "amdil",
        .amdil64 => "amdil64",
        .hsail => "hsail",
        .hsail64 => "hsail64",
        .spir => "spir",
        .spir64 => "spir64",
        .spirv => "spirv",
        .spirv32 => "spirv32",
        .spirv64 => "spirv64",
        .kalimba => "kalimba",
        .shave => "shave",
        .lanai => "lanai",
        .wasm32 => "wasm32",
        .wasm64 => "wasm64",
        .renderscript32 => "renderscript32",
        .renderscript64 => "renderscript64",
        .ve => "ve",
        .spu_2 => return error.@"LLVM backend does not support SPU Mark II",
    };
    try llvm_triple.append_slice(llvm_arch);
    try llvm_triple.append_slice("-unknown-");

    const llvm_os = switch (target.os.tag) {
        .freestanding => "unknown",
        .dragonfly => "dragonfly",
        .freebsd => "freebsd",
        .fuchsia => "fuchsia",
        .kfreebsd => "kfreebsd",
        .linux => "linux",
        .lv2 => "lv2",
        .netbsd => "netbsd",
        .openbsd => "openbsd",
        .solaris, .illumos => "solaris",
        .windows => "windows",
        .zos => "zos",
        .haiku => "haiku",
        .rtems => "rtems",
        .nacl => "nacl",
        .aix => "aix",
        .cuda => "cuda",
        .nvcl => "nvcl",
        .amdhsa => "amdhsa",
        .ps4 => "ps4",
        .ps5 => "ps5",
        .elfiamcu => "elfiamcu",
        .mesa3d => "mesa3d",
        .amdpal => "amdpal",
        .hermit => "hermit",
        .hurd => "hurd",
        .wasi => "wasi",
        .emscripten => "emscripten",
        .uefi => "windows",
        .macos => "macosx",
        .ios => "ios",
        .tvos => "tvos",
        .watchos => "watchos",
        .driverkit => "driverkit",
        .shadermodel => "shadermodel",
        .liteos => "liteos",
        .visionos => "xros",
        .serenity => "serenity",
        .vulkan => "vulkan",

        .opencl,
        .glsl450,
        .plan9,
        .ananas,
        .cloudabi,
        .minix,
        .contiki,
        .other,
        => "unknown",
    };
    try llvm_triple.append_slice(llvm_os);

    if (target.os.tag.is_darwin()) {
        const min_version = target.os.version_range.semver.min;
        try llvm_triple.writer().print("{d}.{d}.{d}", .{
            min_version.major,
            min_version.minor,
            min_version.patch,
        });
    }
    try llvm_triple.append('-');

    const llvm_abi = switch (target.abi) {
        .none => "unknown",
        .gnu => "gnu",
        .gnuabin32 => "gnuabin32",
        .gnuabi64 => "gnuabi64",
        .gnueabi => "gnueabi",
        .gnueabihf => "gnueabihf",
        .gnuf32 => "gnuf32",
        .gnuf64 => "gnuf64",
        .gnusf => "gnusf",
        .gnux32 => "gnux32",
        .gnuilp32 => "gnuilp32",
        .code16 => "code16",
        .eabi => "eabi",
        .eabihf => "eabihf",
        .android => "android",
        .musl => "musl",
        .musleabi => "musleabi",
        .musleabihf => "musleabihf",
        .muslx32 => "muslx32",
        .msvc => "msvc",
        .itanium => "itanium",
        .cygnus => "cygnus",
        .coreclr => "coreclr",
        .simulator => "simulator",
        .macabi => "macabi",
        .pixel => "pixel",
        .vertex => "vertex",
        .geometry => "geometry",
        .hull => "hull",
        .domain => "domain",
        .compute => "compute",
        .library => "library",
        .raygeneration => "raygeneration",
        .intersection => "intersection",
        .anyhit => "anyhit",
        .closesthit => "closesthit",
        .miss => "miss",
        .callable => "callable",
        .mesh => "mesh",
        .amplification => "amplification",
        .ohos => "ohos",
    };
    try llvm_triple.append_slice(llvm_abi);

    return llvm_triple.to_owned_slice();
}

pub fn target_os(os_tag: std.Target.Os.Tag) llvm.OSType {
    return switch (os_tag) {
        .freestanding,
        .other,
        .opencl,
        .glsl450,
        .plan9,
        .ananas,
        .cloudabi,
        .minix,
        .contiki,
        => .UnknownOS,

        .windows, .uefi => .Win32,
        .dragonfly => .DragonFly,
        .freebsd => .FreeBSD,
        .fuchsia => .Fuchsia,
        .ios => .IOS,
        .kfreebsd => .KFreeBSD,
        .linux => .Linux,
        .lv2 => .Lv2,
        .macos => .MacOSX,
        .netbsd => .NetBSD,
        .openbsd => .OpenBSD,
        .solaris, .illumos => .Solaris,
        .zos => .ZOS,
        .haiku => .Haiku,
        .rtems => .RTEMS,
        .nacl => .NaCl,
        .aix => .AIX,
        .cuda => .CUDA,
        .nvcl => .NVCL,
        .amdhsa => .AMDHSA,
        .ps4 => .PS4,
        .ps5 => .PS5,
        .elfiamcu => .ELFIAMCU,
        .tvos => .TvOS,
        .watchos => .WatchOS,
        .visionos => .XROS,
        .mesa3d => .Mesa3D,
        .amdpal => .AMDPAL,
        .hermit => .HermitCore,
        .hurd => .Hurd,
        .wasi => .WASI,
        .emscripten => .Emscripten,
        .driverkit => .DriverKit,
        .shadermodel => .ShaderModel,
        .liteos => .LiteOS,
        .vulkan => .Vulkan,
        .serenity => .Serenity,
    };
}

pub fn target_arch(arch_tag: std.Target.Cpu.Arch) llvm.ArchType {
    return switch (arch_tag) {
        .arm => .arm,
        .armeb => .armeb,
        .aarch64 => .aarch64,
        .aarch64_be => .aarch64_be,
        .aarch64_32 => .aarch64_32,
        .arc => .arc,
        .avr => .avr,
        .bpfel => .bpfel,
        .bpfeb => .bpfeb,
        .csky => .csky,
        .dxil => .dxil,
        .hexagon => .hexagon,
        .loongarch32 => .loongarch32,
        .loongarch64 => .loongarch64,
        .m68k => .m68k,
        .mips => .mips,
        .mipsel => .mipsel,
        .mips64 => .mips64,
        .mips64el => .mips64el,
        .msp430 => .msp430,
        .powerpc => .ppc,
        .powerpcle => .ppcle,
        .powerpc64 => .ppc64,
        .powerpc64le => .ppc64le,
        .r600 => .r600,
        .amdgcn => .amdgcn,
        .riscv32 => .riscv32,
        .riscv64 => .riscv64,
        .sparc => .sparc,
        .sparc64 => .sparcv9, // In LLVM, sparc64 == sparcv9.
        .sparcel => .sparcel,
        .s390x => .systemz,
        .tce => .tce,
        .tcele => .tcele,
        .thumb => .thumb,
        .thumbeb => .thumbeb,
        .x86 => .x86,
        .x86_64 => .x86_64,
        .xcore => .xcore,
        .xtensa => .xtensa,
        .nvptx => .nvptx,
        .nvptx64 => .nvptx64,
        .le32 => .le32,
        .le64 => .le64,
        .amdil => .amdil,
        .amdil64 => .amdil64,
        .hsail => .hsail,
        .hsail64 => .hsail64,
        .spir => .spir,
        .spir64 => .spir64,
        .spirv => .spirv,
        .spirv32 => .spirv32,
        .spirv64 => .spirv64,
        .kalimba => .kalimba,
        .shave => .shave,
        .lanai => .lanai,
        .wasm32 => .wasm32,
        .wasm64 => .wasm64,
        .renderscript32 => .renderscript32,
        .renderscript64 => .renderscript64,
        .ve => .ve,
        .spu_2 => .UnknownArch,
    };
}

pub fn supports_tail_call(target: std.Target) bool {
    switch (target.cpu.arch) {
        .wasm32, .wasm64 => return std.Target.wasm.feature_set_has(target.cpu.features, .tail_call),
        // Although these ISAs support tail calls, LLVM does not support tail calls on them.
        .mips, .mipsel, .mips64, .mips64el => return false,
        .powerpc, .powerpcle, .powerpc64, .powerpc64le => return false,
        else => return true,
    }
}

const DataLayoutBuilder = struct {
    target: std.Target,

    pub fn format(
        self: DataLayoutBuilder,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        try writer.write_byte(switch (self.target.cpu.arch.endian()) {
            .little => 'e',
            .big => 'E',
        });
        switch (self.target.cpu.arch) {
            .amdgcn,
            .nvptx,
            .nvptx64,
            => {},
            .avr => try writer.write_all("-P1"),
            else => try writer.print("-m:{c}", .{@as(u8, switch (self.target.cpu.arch) {
                .mips, .mipsel => 'm', // Mips mangling: Private symbols get a $ prefix.
                else => switch (self.target.ofmt) {
                    .elf => 'e', // ELF mangling: Private symbols get a `.L` prefix.
                    //.goff => 'l', // GOFF mangling: Private symbols get a `@` prefix.
                    .macho => 'o', // Mach-O mangling: Private symbols get `L` prefix.
                    // Other symbols get a `_` prefix.
                    .coff => switch (self.target.os.tag) {
                        .uefi, .windows => switch (self.target.cpu.arch) {
                            .x86 => 'x', // Windows x86 COFF mangling: Private symbols get the usual
                            // prefix. Regular C symbols get a `_` prefix. Functions with `__stdcall`,
                            //`__fastcall`, and `__vectorcall` have custom mangling that appends `@N`
                            // where N is the number of bytes used to pass parameters. C++ symbols
                            // starting with `?` are not mangled in any way.
                            else => 'w', // Windows COFF mangling: Similar to x, except that normal C
                            // symbols do not receive a `_` prefix.
                        },
                        else => 'e',
                    },
                    //.xcoff => 'a', // XCOFF mangling: Private symbols get a `L..` prefix.
                    else => 'e',
                },
            })}),
        }
        const stack_abi = self.target.stack_alignment() * 8;
        if (self.target.cpu.arch == .csky) try writer.print("-S{d}", .{stack_abi});
        var any_non_integral = false;
        const ptr_bit_width = self.target.ptr_bit_width();
        var default_info = struct { size: u16, abi: u16, pref: u16, idx: u16 }{
            .size = 64,
            .abi = 64,
            .pref = 64,
            .idx = 64,
        };
        const addr_space_info = llvm_addr_space_info(self.target);
        for (addr_space_info, 0..) |info, i| {
            assert((info.llvm == .default) == (i == 0));
            if (info.non_integral) {
                assert(info.llvm != .default);
                any_non_integral = true;
            }
            const size = info.size orelse ptr_bit_width;
            const abi = info.abi orelse ptr_bit_width;
            const pref = info.pref orelse abi;
            const idx = info.idx orelse size;
            const matches_default =
                size == default_info.size and
                abi == default_info.abi and
                pref == default_info.pref and
                idx == default_info.idx;
            if (info.llvm == .default) default_info = .{
                .size = size,
                .abi = abi,
                .pref = pref,
                .idx = idx,
            };
            if (self.target.cpu.arch == .aarch64_32) continue;
            if (!info.force_in_data_layout and matches_default and
                self.target.cpu.arch != .riscv64 and
                self.target.cpu.arch != .loongarch64 and
                !(self.target.cpu.arch == .aarch64 and
                (self.target.os.tag == .uefi or self.target.os.tag == .windows)) and
                self.target.cpu.arch != .bpfeb and self.target.cpu.arch != .bpfel) continue;
            try writer.write_all("-p");
            if (info.llvm != .default) try writer.print("{d}", .{@int_from_enum(info.llvm)});
            try writer.print(":{d}:{d}", .{ size, abi });
            if (pref != abi or idx != size or self.target.cpu.arch == .hexagon) {
                try writer.print(":{d}", .{pref});
                if (idx != size) try writer.print(":{d}", .{idx});
            }
        }
        if (self.target.cpu.arch.is_arm_or_thumb()) try writer.write_all("-Fi8") // for thumb interwork
        else if (self.target.cpu.arch == .powerpc64 and
            self.target.os.tag != .freebsd and self.target.abi != .musl)
            try writer.write_all("-Fi64")
        else if (self.target.cpu.arch.is_ppc() or self.target.cpu.arch.is_ppc64())
            try writer.write_all("-Fn32");
        if (self.target.cpu.arch != .hexagon) {
            if (self.target.cpu.arch == .arc or self.target.cpu.arch == .s390x)
                try self.type_alignment(.integer, 1, 8, 8, false, writer);
            try self.type_alignment(.integer, 8, 8, 8, false, writer);
            try self.type_alignment(.integer, 16, 16, 16, false, writer);
            try self.type_alignment(.integer, 32, 32, 32, false, writer);
            if (self.target.cpu.arch == .arc)
                try self.type_alignment(.float, 32, 32, 32, false, writer);
            try self.type_alignment(.integer, 64, 32, 64, false, writer);
            try self.type_alignment(.integer, 128, 32, 64, false, writer);
            if (backend_supports_f16(self.target))
                try self.type_alignment(.float, 16, 16, 16, false, writer);
            if (self.target.cpu.arch != .arc)
                try self.type_alignment(.float, 32, 32, 32, false, writer);
            try self.type_alignment(.float, 64, 64, 64, false, writer);
            if (self.target.cpu.arch.is_x86()) try self.type_alignment(.float, 80, 0, 0, false, writer);
            try self.type_alignment(.float, 128, 128, 128, false, writer);
        }
        switch (self.target.cpu.arch) {
            .amdgcn => {
                try self.type_alignment(.vector, 16, 16, 16, false, writer);
                try self.type_alignment(.vector, 24, 32, 32, false, writer);
                try self.type_alignment(.vector, 32, 32, 32, false, writer);
                try self.type_alignment(.vector, 48, 64, 64, false, writer);
                try self.type_alignment(.vector, 96, 128, 128, false, writer);
                try self.type_alignment(.vector, 192, 256, 256, false, writer);
                try self.type_alignment(.vector, 256, 256, 256, false, writer);
                try self.type_alignment(.vector, 512, 512, 512, false, writer);
                try self.type_alignment(.vector, 1024, 1024, 1024, false, writer);
                try self.type_alignment(.vector, 2048, 2048, 2048, false, writer);
            },
            .ve => {},
            else => {
                try self.type_alignment(.vector, 16, 32, 32, false, writer);
                try self.type_alignment(.vector, 32, 32, 32, false, writer);
                try self.type_alignment(.vector, 64, 64, 64, false, writer);
                try self.type_alignment(.vector, 128, 128, 128, true, writer);
            },
        }
        const swap_agg_nat = switch (self.target.cpu.arch) {
            .x86, .x86_64 => switch (self.target.os.tag) {
                .uefi, .windows => true,
                else => false,
            },
            .avr, .m68k => true,
            else => false,
        };
        if (!swap_agg_nat) try self.type_alignment(.aggregate, 0, 0, 64, false, writer);
        if (self.target.cpu.arch == .csky) try writer.write_all("-Fi32");
        for (@as([]const u24, switch (self.target.cpu.arch) {
            .avr => &.{8},
            .msp430 => &.{ 8, 16 },
            .arc,
            .arm,
            .armeb,
            .csky,
            .mips,
            .mipsel,
            .powerpc,
            .powerpcle,
            .riscv32,
            .sparc,
            .sparcel,
            .thumb,
            .thumbeb,
            .xtensa,
            => &.{32},
            .aarch64,
            .aarch64_be,
            .aarch64_32,
            .amdgcn,
            .bpfeb,
            .bpfel,
            .mips64,
            .mips64el,
            .powerpc64,
            .powerpc64le,
            .riscv64,
            .s390x,
            .sparc64,
            .ve,
            .wasm32,
            .wasm64,
            => &.{ 32, 64 },
            .hexagon => &.{ 16, 32 },
            .m68k,
            .x86,
            => &.{ 8, 16, 32 },
            .nvptx,
            .nvptx64,
            => &.{ 16, 32, 64 },
            .x86_64 => &.{ 8, 16, 32, 64 },
            .loongarch64 => &.{64},
            else => &.{},
        }), 0..) |natural, index| switch (index) {
            0 => try writer.print("-n{d}", .{natural}),
            else => try writer.print(":{d}", .{natural}),
        };
        if (swap_agg_nat) try self.type_alignment(.aggregate, 0, 0, 64, false, writer);
        if (self.target.cpu.arch == .hexagon) {
            try self.type_alignment(.integer, 64, 64, 64, true, writer);
            try self.type_alignment(.integer, 32, 32, 32, true, writer);
            try self.type_alignment(.integer, 16, 16, 16, true, writer);
            try self.type_alignment(.integer, 1, 8, 8, true, writer);
            try self.type_alignment(.float, 32, 32, 32, true, writer);
            try self.type_alignment(.float, 64, 64, 64, true, writer);
        }
        if (stack_abi != ptr_bit_width or self.target.cpu.arch == .msp430 or
            self.target.os.tag == .uefi or self.target.os.tag == .windows)
            try writer.print("-S{d}", .{stack_abi});
        switch (self.target.cpu.arch) {
            .hexagon, .ve => {
                try self.type_alignment(.vector, 32, 128, 128, true, writer);
                try self.type_alignment(.vector, 64, 128, 128, true, writer);
                try self.type_alignment(.vector, 128, 128, 128, true, writer);
            },
            else => {},
        }
        if (self.target.cpu.arch != .amdgcn) {
            try self.type_alignment(.vector, 256, 128, 128, true, writer);
            try self.type_alignment(.vector, 512, 128, 128, true, writer);
            try self.type_alignment(.vector, 1024, 128, 128, true, writer);
            try self.type_alignment(.vector, 2048, 128, 128, true, writer);
            try self.type_alignment(.vector, 4096, 128, 128, true, writer);
            try self.type_alignment(.vector, 8192, 128, 128, true, writer);
            try self.type_alignment(.vector, 16384, 128, 128, true, writer);
        }
        const alloca_addr_space = llvm_alloca_address_space(self.target);
        if (alloca_addr_space != .default) try writer.print("-A{d}", .{@int_from_enum(alloca_addr_space)});
        const global_addr_space = llvm_default_global_address_space(self.target);
        if (global_addr_space != .default) try writer.print("-G{d}", .{@int_from_enum(global_addr_space)});
        if (any_non_integral) {
            try writer.write_all("-ni");
            for (addr_space_info) |info| if (info.non_integral)
                try writer.print(":{d}", .{@int_from_enum(info.llvm)});
        }
    }

    fn type_alignment(
        self: DataLayoutBuilder,
        kind: enum { integer, vector, float, aggregate },
        size: u24,
        default_abi: u24,
        default_pref: u24,
        default_force_pref: bool,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        var abi = default_abi;
        var pref = default_pref;
        var force_abi = false;
        var force_pref = default_force_pref;
        if (kind == .float and size == 80) {
            abi = 128;
            pref = 128;
        }
        for (@as([]const std.Target.CType, switch (kind) {
            .integer => &.{ .char, .short, .int, .long, .longlong },
            .float => &.{ .float, .double, .longdouble },
            .vector, .aggregate => &.{},
        })) |cty| {
            if (self.target.c_type_bit_size(cty) != size) continue;
            abi = self.target.c_type_alignment(cty) * 8;
            pref = self.target.c_type_preferred_alignment(cty) * 8;
            break;
        }
        switch (kind) {
            .integer => {
                if (self.target.ptr_bit_width() <= 16 and size >= 128) return;
                abi = @min(abi, Type.max_int_alignment(self.target, true) * 8);
                switch (self.target.cpu.arch) {
                    .aarch64,
                    .aarch64_be,
                    .aarch64_32,
                    => if (size == 128) {
                        abi = size;
                        pref = size;
                    } else switch (self.target.os.tag) {
                        .macos, .ios, .watchos, .tvos, .visionos => {},
                        .uefi, .windows => {
                            pref = size;
                            force_abi = size >= 32;
                        },
                        else => pref = @max(pref, 32),
                    },
                    .arc => if (size <= 64) {
                        abi = @min((std.math.div_ceil(u24, size, 8) catch unreachable) * 8, 32);
                        pref = 32;
                        force_abi = true;
                        force_pref = size <= 32;
                    },
                    .bpfeb,
                    .bpfel,
                    .nvptx,
                    .nvptx64,
                    .riscv64,
                    => if (size == 128) {
                        abi = size;
                        pref = size;
                    },
                    .csky => if (size == 32 or size == 64) {
                        abi = 32;
                        pref = 32;
                        force_abi = true;
                        force_pref = true;
                    },
                    .hexagon => force_abi = true,
                    .m68k => if (size <= 32) {
                        abi = @min(size, 16);
                        pref = size;
                        force_abi = true;
                        force_pref = true;
                    } else if (size == 64) {
                        abi = 32;
                        pref = size;
                    },
                    .mips,
                    .mipsel,
                    .mips64,
                    .mips64el,
                    => pref = @max(pref, 32),
                    .s390x => pref = @max(pref, 16),
                    .ve => if (size == 64) {
                        abi = size;
                        pref = size;
                    },
                    .xtensa => if (size <= 64) {
                        pref = @max(size, 32);
                        abi = size;
                        force_abi = size == 64;
                    },
                    .x86 => switch (size) {
                        128 => {
                            abi = size;
                            pref = size;
                        },
                        else => {},
                    },
                    .x86_64 => switch (size) {
                        64, 128 => {
                            abi = size;
                            pref = size;
                        },
                        else => {},
                    },
                    .loongarch64 => switch (size) {
                        128 => {
                            abi = size;
                            pref = size;
                            force_abi = true;
                        },
                        else => {},
                    },
                    else => {},
                }
            },
            .vector => if (self.target.cpu.arch.is_arm_or_thumb()) {
                switch (size) {
                    128 => abi = 64,
                    else => {},
                }
            } else if ((self.target.cpu.arch.is_ppc64() and self.target.os.tag == .linux and
                (size == 256 or size == 512)) or
                (self.target.cpu.arch.is_nvptx() and (size == 16 or size == 32)))
            {
                force_abi = true;
                abi = size;
                pref = size;
            } else if (self.target.cpu.arch == .amdgcn and size <= 2048) {
                force_abi = true;
            } else if (self.target.cpu.arch == .csky and (size == 64 or size == 128)) {
                abi = 32;
                pref = 32;
                force_pref = true;
            } else if (self.target.cpu.arch == .hexagon and
                ((size >= 32 and size <= 64) or (size >= 512 and size <= 2048)))
            {
                abi = size;
                pref = size;
                force_pref = true;
            } else if (self.target.cpu.arch == .s390x and size == 128) {
                abi = 64;
                pref = 64;
                force_pref = false;
            } else if (self.target.cpu.arch == .ve and (size >= 64 and size <= 16384)) {
                abi = 64;
                pref = 64;
                force_abi = true;
                force_pref = true;
            },
            .float => switch (self.target.cpu.arch) {
                .aarch64_32, .amdgcn => if (size == 128) {
                    abi = size;
                    pref = size;
                },
                .arc => if (size == 32 or size == 64) {
                    abi = 32;
                    pref = 32;
                    force_abi = true;
                    force_pref = size == 32;
                },
                .avr, .msp430, .sparc64 => if (size != 32 and size != 64) return,
                .csky => if (size == 32 or size == 64) {
                    abi = 32;
                    pref = 32;
                    force_abi = true;
                    force_pref = true;
                },
                .hexagon => if (size == 32 or size == 64) {
                    force_abi = true;
                },
                .ve, .xtensa => if (size == 64) {
                    abi = size;
                    pref = size;
                },
                .wasm32, .wasm64 => if (self.target.os.tag == .emscripten and size == 128) {
                    abi = 64;
                    pref = 64;
                },
                else => {},
            },
            .aggregate => if (self.target.os.tag == .uefi or self.target.os.tag == .windows or
                self.target.cpu.arch.is_arm_or_thumb())
            {
                pref = @min(pref, self.target.ptr_bit_width());
            } else switch (self.target.cpu.arch) {
                .arc, .csky => {
                    abi = 0;
                    pref = 32;
                },
                .hexagon => {
                    abi = 0;
                    pref = 0;
                },
                .m68k => {
                    abi = 0;
                    pref = 16;
                },
                .msp430 => {
                    abi = 8;
                    pref = 8;
                },
                .s390x => {
                    abi = 8;
                    pref = 16;
                },
                else => {},
            },
        }
        if (kind != .vector and self.target.cpu.arch == .avr) {
            force_abi = true;
            abi = 8;
            pref = 8;
        }
        if (!force_abi and abi == default_abi and pref == default_pref) return;
        try writer.print("-{c}", .{@tag_name(kind)[0]});
        if (size != 0) try writer.print("{d}", .{size});
        try writer.print(":{d}", .{abi});
        if (pref != abi or force_pref) try writer.print(":{d}", .{pref});
    }
};

pub const Object = struct {
    gpa: Allocator,
    builder: Builder,

    module: *Module,

    debug_compile_unit: Builder.Metadata,

    debug_enums_fwd_ref: Builder.Metadata,
    debug_globals_fwd_ref: Builder.Metadata,

    debug_enums: std.ArrayListUnmanaged(Builder.Metadata),
    debug_globals: std.ArrayListUnmanaged(Builder.Metadata),

    debug_file_map: std.AutoHashMapUnmanaged(*const Module.File, Builder.Metadata),
    debug_type_map: std.AutoHashMapUnmanaged(Type, Builder.Metadata),

    debug_unresolved_namespace_scopes: std.AutoArrayHashMapUnmanaged(InternPool.NamespaceIndex, Builder.Metadata),

    target: std.Target,
    /// Ideally we would use `llvm_module.getNamedFunction` to go from *Decl to LLVM function,
    /// but that has some downsides:
    /// * we have to compute the fully qualified name every time we want to do the lookup
    /// * for externally linked functions, the name is not fully qualified, but when
    ///   a Decl goes from exported to not exported and vice-versa, we would use the wrong
    ///   version of the name and incorrectly get function not found in the llvm module.
    /// * it works for functions not all globals.
    /// Therefore, this table keeps track of the mapping.
    decl_map: std.AutoHashMapUnmanaged(InternPool.DeclIndex, Builder.Global.Index),
    /// Same deal as `decl_map` but for anonymous declarations, which are always global constants.
    anon_decl_map: std.AutoHashMapUnmanaged(InternPool.Index, Builder.Global.Index),
    /// Serves the same purpose as `decl_map` but only used for the `is_named_enum_value` instruction.
    named_enum_map: std.AutoHashMapUnmanaged(InternPool.DeclIndex, Builder.Function.Index),
    /// Maps Zig types to LLVM types. The table memory is backed by the GPA of
    /// the compiler.
    /// TODO when InternPool garbage collection is implemented, this map needs
    /// to be garbage collected as well.
    type_map: TypeMap,
    /// The LLVM global table which holds the names corresponding to Zig errors.
    /// Note that the values are not added until `emit`, when all errors in
    /// the compilation are known.
    error_name_table: Builder.Variable.Index,
    /// This map is usually very close to empty. It tracks only the cases when a
    /// second extern Decl could not be emitted with the correct name due to a
    /// name collision.
    extern_collisions: std.AutoArrayHashMapUnmanaged(InternPool.DeclIndex, void),

    /// Memoizes a null `?usize` value.
    null_opt_usize: Builder.Constant,

    /// When an LLVM struct type is created, an entry is inserted into this
    /// table for every zig source field of the struct that has a corresponding
    /// LLVM struct field. comptime fields are not included. Zero-bit fields are
    /// mapped to a field at the correct byte, which may be a padding field, or
    /// are not mapped, in which case they are sematically at the end of the
    /// struct.
    /// The value is the LLVM struct field index.
    /// This is denormalized data.
    struct_field_map: std.AutoHashMapUnmanaged(ZigStructField, c_uint),

    const ZigStructField = struct {
        struct_ty: InternPool.Index,
        field_index: u32,
    };

    pub const TypeMap = std.AutoHashMapUnmanaged(InternPool.Index, Builder.Type);

    pub fn create(arena: Allocator, comp: *Compilation) !*Object {
        if (build_options.only_c) unreachable;
        const gpa = comp.gpa;
        const target = comp.root_mod.resolved_target.result;
        const llvm_target_triple = try target_triple(arena, target);

        var builder = try Builder.init(.{
            .allocator = gpa,
            .strip = comp.config.debug_format == .strip,
            .name = comp.root_name,
            .target = target,
            .triple = llvm_target_triple,
        });
        errdefer builder.deinit();

        builder.data_layout = try builder.fmt("{}", .{DataLayoutBuilder{ .target = target }});

        const debug_compile_unit, const debug_enums_fwd_ref, const debug_globals_fwd_ref =
            if (!builder.strip)
        debug_info: {
            // We fully resolve all paths at this point to avoid lack of
            // source line info in stack traces or lack of debugging
            // information which, if relative paths were used, would be
            // very location dependent.
            // TODO: the only concern I have with this is WASI as either host or target, should
            // we leave the paths as relative then?
            // TODO: This is totally wrong. In dwarf, paths are encoded as relative to
            // a particular directory, and then the directory path is specified elsewhere.
            // In the compiler frontend we have it stored correctly in this
            // way already, but here we throw all that sweet information
            // into the garbage can by converting into absolute paths. What
            // a terrible tragedy.
            const compile_unit_dir = blk: {
                if (comp.module) |zcu| m: {
                    const d = try zcu.main_mod.root.join_string(arena, "");
                    if (d.len == 0) break :m;
                    if (std.fs.path.is_absolute(d)) break :blk d;
                    break :blk std.fs.realpath_alloc(arena, d) catch break :blk d;
                }
                break :blk try std.process.get_cwd_alloc(arena);
            };

            const debug_file = try builder.debug_file(
                try builder.metadata_string(comp.root_name),
                try builder.metadata_string(compile_unit_dir),
            );

            const debug_enums_fwd_ref = try builder.debug_forward_reference();
            const debug_globals_fwd_ref = try builder.debug_forward_reference();

            const debug_compile_unit = try builder.debug_compile_unit(
                debug_file,
                // Don't use the version string here; LLVM misparses it when it
                // includes the git revision.
                try builder.metadata_string_fmt("zig {d}.{d}.{d}", .{
                    build_options.semver.major,
                    build_options.semver.minor,
                    build_options.semver.patch,
                }),
                debug_enums_fwd_ref,
                debug_globals_fwd_ref,
                .{ .optimized = comp.root_mod.optimize_mode != .Debug },
            );

            const i32_2 = try builder.int_const(.i32, 2);
            const i32_3 = try builder.int_const(.i32, 3);
            const debug_info_version = try builder.debug_module_flag(
                try builder.debug_constant(i32_2),
                try builder.metadata_string("Debug Info Version"),
                try builder.debug_constant(i32_3),
            );

            switch (comp.config.debug_format) {
                .strip => unreachable,
                .dwarf => |f| {
                    const i32_4 = try builder.int_const(.i32, 4);
                    const dwarf_version = try builder.debug_module_flag(
                        try builder.debug_constant(i32_2),
                        try builder.metadata_string("Dwarf Version"),
                        try builder.debug_constant(i32_4),
                    );
                    switch (f) {
                        .@"32" => {
                            try builder.debug_named(try builder.metadata_string("llvm.module.flags"), &.{
                                debug_info_version,
                                dwarf_version,
                            });
                        },
                        .@"64" => {
                            const dwarf64 = try builder.debug_module_flag(
                                try builder.debug_constant(i32_2),
                                try builder.metadata_string("DWARF64"),
                                try builder.debug_constant(.@"1"),
                            );
                            try builder.debug_named(try builder.metadata_string("llvm.module.flags"), &.{
                                debug_info_version,
                                dwarf_version,
                                dwarf64,
                            });
                        },
                    }
                },
                .code_view => {
                    const code_view = try builder.debug_module_flag(
                        try builder.debug_constant(i32_2),
                        try builder.metadata_string("CodeView"),
                        try builder.debug_constant(.@"1"),
                    );
                    try builder.debug_named(try builder.metadata_string("llvm.module.flags"), &.{
                        debug_info_version,
                        code_view,
                    });
                },
            }

            try builder.debug_named(try builder.metadata_string("llvm.dbg.cu"), &.{debug_compile_unit});
            break :debug_info .{ debug_compile_unit, debug_enums_fwd_ref, debug_globals_fwd_ref };
        } else .{.none} ** 3;

        const obj = try arena.create(Object);
        obj.* = .{
            .gpa = gpa,
            .builder = builder,
            .module = comp.module.?,
            .debug_compile_unit = debug_compile_unit,
            .debug_enums_fwd_ref = debug_enums_fwd_ref,
            .debug_globals_fwd_ref = debug_globals_fwd_ref,
            .debug_enums = .{},
            .debug_globals = .{},
            .debug_file_map = .{},
            .debug_type_map = .{},
            .debug_unresolved_namespace_scopes = .{},
            .target = target,
            .decl_map = .{},
            .anon_decl_map = .{},
            .named_enum_map = .{},
            .type_map = .{},
            .error_name_table = .none,
            .extern_collisions = .{},
            .null_opt_usize = .no_init,
            .struct_field_map = .{},
        };
        return obj;
    }

    pub fn deinit(self: *Object) void {
        const gpa = self.gpa;
        self.debug_enums.deinit(gpa);
        self.debug_globals.deinit(gpa);
        self.debug_file_map.deinit(gpa);
        self.debug_type_map.deinit(gpa);
        self.debug_unresolved_namespace_scopes.deinit(gpa);
        self.decl_map.deinit(gpa);
        self.anon_decl_map.deinit(gpa);
        self.named_enum_map.deinit(gpa);
        self.type_map.deinit(gpa);
        self.extern_collisions.deinit(gpa);
        self.builder.deinit();
        self.struct_field_map.deinit(gpa);
        self.* = undefined;
    }

    fn gen_error_name_table(o: *Object) Allocator.Error!void {
        // If o.error_name_table is null, then it was not referenced by any instructions.
        if (o.error_name_table == .none) return;

        const mod = o.module;

        const error_name_list = mod.global_error_set.keys();
        const llvm_errors = try mod.gpa.alloc(Builder.Constant, error_name_list.len);
        defer mod.gpa.free(llvm_errors);

        // TODO: Address space
        const slice_ty = Type.slice_const_u8_sentinel_0;
        const llvm_usize_ty = try o.lower_type(Type.usize);
        const llvm_slice_ty = try o.lower_type(slice_ty);
        const llvm_table_ty = try o.builder.array_type(error_name_list.len, llvm_slice_ty);

        llvm_errors[0] = try o.builder.undef_const(llvm_slice_ty);
        for (llvm_errors[1..], error_name_list[1..]) |*llvm_error, name| {
            const name_string = try o.builder.string_null(name.to_slice(&mod.intern_pool));
            const name_init = try o.builder.string_const(name_string);
            const name_variable_index =
                try o.builder.add_variable(.empty, name_init.type_of(&o.builder), .default);
            try name_variable_index.set_initializer(name_init, &o.builder);
            name_variable_index.set_linkage(.private, &o.builder);
            name_variable_index.set_mutability(.constant, &o.builder);
            name_variable_index.set_unnamed_addr(.unnamed_addr, &o.builder);
            name_variable_index.set_alignment(comptime Builder.Alignment.from_byte_units(1), &o.builder);

            llvm_error.* = try o.builder.struct_const(llvm_slice_ty, &.{
                name_variable_index.to_const(&o.builder),
                try o.builder.int_const(llvm_usize_ty, name_string.slice(&o.builder).?.len - 1),
            });
        }

        const table_variable_index = try o.builder.add_variable(.empty, llvm_table_ty, .default);
        try table_variable_index.set_initializer(
            try o.builder.array_const(llvm_table_ty, llvm_errors),
            &o.builder,
        );
        table_variable_index.set_linkage(.private, &o.builder);
        table_variable_index.set_mutability(.constant, &o.builder);
        table_variable_index.set_unnamed_addr(.unnamed_addr, &o.builder);
        table_variable_index.set_alignment(
            slice_ty.abi_alignment(mod).to_llvm(),
            &o.builder,
        );

        try o.error_name_table.set_initializer(table_variable_index.to_const(&o.builder), &o.builder);
    }

    fn gen_cmp_lt_errors_len_function(o: *Object) !void {
        // If there is no such function in the module, it means the source code does not need it.
        const name = o.builder.strtab_string_if_exists(lt_errors_fn_name) orelse return;
        const llvm_fn = o.builder.get_global(name) orelse return;
        const mod = o.module;
        const errors_len = mod.global_error_set.count();

        var wip = try Builder.WipFunction.init(&o.builder, .{
            .function = llvm_fn.ptr_const(&o.builder).kind.function,
            .strip = true,
        });
        defer wip.deinit();
        wip.cursor = .{ .block = try wip.block(0, "Entry") };

        // Example source of the following LLVM IR:
        // fn __zig_lt_errors_len(index: u16) bool {
        //     return index < total_errors_len;
        // }

        const lhs = wip.arg(0);
        const rhs = try o.builder.int_value(try o.error_int_type(), errors_len);
        const is_lt = try wip.icmp(.ult, lhs, rhs, "");
        _ = try wip.ret(is_lt);
        try wip.finish();
    }

    fn gen_module_level_assembly(object: *Object) !void {
        const mod = object.module;

        const writer = object.builder.set_module_asm();
        for (mod.global_assembly.values()) |assembly| {
            try writer.print("{s}\n", .{assembly});
        }
        try object.builder.finish_module_asm();
    }

    fn resolve_export_extern_collisions(object: *Object) !void {
        const mod = object.module;

        // This map has externs with incorrect symbol names.
        for (object.extern_collisions.keys()) |decl_index| {
            const global = object.decl_map.get(decl_index) orelse continue;
            // Same logic as below but for externs instead of exports.
            const decl_name = object.builder.strtab_string_if_exists(mod.decl_ptr(decl_index).name.to_slice(&mod.intern_pool)) orelse continue;
            const other_global = object.builder.get_global(decl_name) orelse continue;
            if (other_global.to_const().get_base(&object.builder) ==
                global.to_const().get_base(&object.builder)) continue;

            try global.replace(other_global, &object.builder);
        }
        object.extern_collisions.clear_retaining_capacity();

        for (mod.decl_exports.keys(), mod.decl_exports.values()) |decl_index, export_list| {
            const global = object.decl_map.get(decl_index) orelse continue;
            try resolve_global_collisions(object, global, export_list.items);
        }

        for (mod.value_exports.keys(), mod.value_exports.values()) |val, export_list| {
            const global = object.anon_decl_map.get(val) orelse continue;
            try resolve_global_collisions(object, global, export_list.items);
        }
    }

    fn resolve_global_collisions(
        object: *Object,
        global: Builder.Global.Index,
        export_list: []const *Module.Export,
    ) !void {
        const mod = object.module;
        const global_base = global.to_const().get_base(&object.builder);
        for (export_list) |exp| {
            // Detect if the LLVM global has already been created as an extern. In such
            // case, we need to replace all uses of it with this exported global.
            const exp_name = object.builder.strtab_string_if_exists(exp.opts.name.to_slice(&mod.intern_pool)) orelse continue;

            const other_global = object.builder.get_global(exp_name) orelse continue;
            if (other_global.to_const().get_base(&object.builder) == global_base) continue;

            try global.take_name(other_global, &object.builder);
            try other_global.replace(global, &object.builder);
            // Problem: now we need to replace in the decl_map that
            // the extern decl index points to this new global. However we don't
            // know the decl index.
            // Even if we did, a future incremental update to the extern would then
            // treat the LLVM global as an extern rather than an export, so it would
            // need a way to check that.
            // This is a TODO that needs to be solved when making
            // the LLVM backend support incremental compilation.
        }
    }

    pub const EmitOptions = struct {
        pre_ir_path: ?[]const u8,
        pre_bc_path: ?[]const u8,
        bin_path: ?[*:0]const u8,
        asm_path: ?[*:0]const u8,
        post_ir_path: ?[*:0]const u8,
        post_bc_path: ?[*:0]const u8,

        is_debug: bool,
        is_small: bool,
        time_report: bool,
        sanitize_thread: bool,
        lto: bool,
    };

    pub fn emit(self: *Object, options: EmitOptions) !void {
        {
            try self.resolve_export_extern_collisions();
            try self.gen_error_name_table();
            try self.gen_cmp_lt_errors_len_function();
            try self.gen_module_level_assembly();

            if (!self.builder.strip) {
                {
                    var i: usize = 0;
                    while (i < self.debug_unresolved_namespace_scopes.count()) : (i += 1) {
                        const namespace_index = self.debug_unresolved_namespace_scopes.keys()[i];
                        const fwd_ref = self.debug_unresolved_namespace_scopes.values()[i];

                        const namespace = self.module.namespace_ptr(namespace_index);
                        const debug_type = try self.lower_debug_type(namespace.get_type(self.module));

                        self.builder.debug_forward_reference_set_type(fwd_ref, debug_type);
                    }
                }

                self.builder.debug_forward_reference_set_type(
                    self.debug_enums_fwd_ref,
                    try self.builder.debug_tuple(self.debug_enums.items),
                );

                self.builder.debug_forward_reference_set_type(
                    self.debug_globals_fwd_ref,
                    try self.builder.debug_tuple(self.debug_globals.items),
                );
            }
        }

        const target_triple_sentinel =
            try self.gpa.dupe_z(u8, self.builder.target_triple.slice(&self.builder).?);
        defer self.gpa.free(target_triple_sentinel);

        const emit_asm_msg = options.asm_path orelse "(none)";
        const emit_bin_msg = options.bin_path orelse "(none)";
        const post_llvm_ir_msg = options.post_ir_path orelse "(none)";
        const post_llvm_bc_msg = options.post_bc_path orelse "(none)";
        log.debug("emit LLVM object asm={s} bin={s} ir={s} bc={s}", .{
            emit_asm_msg, emit_bin_msg, post_llvm_ir_msg, post_llvm_bc_msg,
        });

        const context, const module = emit: {
            if (options.pre_ir_path) |path| {
                if (std.mem.eql(u8, path, "-")) {
                    self.builder.dump();
                } else {
                    _ = try self.builder.print_to_file(path);
                }
            }

            const bitcode = try self.builder.to_bitcode(self.gpa);
            defer self.gpa.free(bitcode);
            self.builder.clear_and_free();

            if (options.pre_bc_path) |path| {
                var file = try std.fs.cwd().create_file(path, .{});
                defer file.close();

                const ptr: [*]const u8 = @ptr_cast(bitcode.ptr);
                try file.write_all(ptr[0..(bitcode.len * 4)]);
            }

            if (options.asm_path == null and options.bin_path == null and
                options.post_ir_path == null and options.post_bc_path == null) return;

            if (options.post_bc_path) |path| {
                var file = try std.fs.cwd().create_file_z(path, .{});
                defer file.close();

                const ptr: [*]const u8 = @ptr_cast(bitcode.ptr);
                try file.write_all(ptr[0..(bitcode.len * 4)]);
            }

            if (!build_options.have_llvm or !self.module.comp.config.use_lib_llvm) {
                log.err("emitting without libllvm not implemented", .{});
                return error.FailedToEmit;
            }

            initialize_llvmtarget(self.module.comp.root_mod.resolved_target.result.cpu.arch);

            const context: *llvm.Context = llvm.Context.create();
            errdefer context.dispose();

            const bitcode_memory_buffer = llvm.MemoryBuffer.createMemoryBufferWithMemoryRange(
                @ptr_cast(bitcode.ptr),
                bitcode.len * 4,
                "BitcodeBuffer",
                llvm.Bool.False,
            );
            defer bitcode_memory_buffer.dispose();

            context.enableBrokenDebugInfoCheck();

            var module: *llvm.Module = undefined;
            if (context.parseBitcodeInContext2(bitcode_memory_buffer, &module).to_bool() or context.getBrokenDebugInfo()) {
                log.err("Failed to parse bitcode", .{});
                return error.FailedToEmit;
            }
            break :emit .{ context, module };
        };
        defer context.dispose();

        var target: *llvm.Target = undefined;
        var error_message: [*:0]const u8 = undefined;
        if (llvm.Target.getFromTriple(target_triple_sentinel, &target, &error_message).to_bool()) {
            defer llvm.disposeMessage(error_message);

            log.err("LLVM failed to parse '{s}': {s}", .{
                target_triple_sentinel,
                error_message,
            });
            @panic("Invalid LLVM triple");
        }

        const optimize_mode = self.module.comp.root_mod.optimize_mode;
        const pic = self.module.comp.root_mod.pic;

        const opt_level: llvm.CodeGenOptLevel = if (optimize_mode == .Debug)
            .None
        else
            .Aggressive;

        const reloc_mode: llvm.RelocMode = if (pic)
            .PIC
        else if (self.module.comp.config.link_mode == .dynamic)
            llvm.RelocMode.DynamicNoPIC
        else
            .Static;

        const code_model: llvm.CodeModel = switch (self.module.comp.root_mod.code_model) {
            .default => .Default,
            .tiny => .Tiny,
            .small => .Small,
            .kernel => .Kernel,
            .medium => .Medium,
            .large => .Large,
        };

        // TODO handle float ABI better- it should depend on the ABI portion of std.Target
        const float_abi: llvm.ABIType = .Default;

        var target_machine = llvm.TargetMachine.create(
            target,
            target_triple_sentinel,
            if (self.module.comp.root_mod.resolved_target.result.cpu.model.llvm_name) |s| s.ptr else null,
            self.module.comp.root_mod.resolved_target.llvm_cpu_features.?,
            opt_level,
            reloc_mode,
            code_model,
            self.module.comp.function_sections,
            self.module.comp.data_sections,
            float_abi,
            if (target_util.llvm_machine_abi(self.module.comp.root_mod.resolved_target.result)) |s| s.ptr else null,
        );
        errdefer target_machine.dispose();

        if (pic) module.setModulePICLevel();
        if (self.module.comp.config.pie) module.setModulePIELevel();
        if (code_model != .Default) module.setModuleCodeModel(code_model);

        if (self.module.comp.llvm_opt_bisect_limit >= 0) {
            context.setOptBisectLimit(self.module.comp.llvm_opt_bisect_limit);
        }

        // Unfortunately, LLVM shits the bed when we ask for both binary and assembly.
        // So we call the entire pipeline multiple times if this is requested.
        // var error_message: [*:0]const u8 = undefined;
        var emit_bin_path = options.bin_path;
        var post_ir_path = options.post_ir_path;
        if (options.asm_path != null and options.bin_path != null) {
            if (target_machine.emitToFile(
                module,
                &error_message,
                options.is_debug,
                options.is_small,
                options.time_report,
                options.sanitize_thread,
                options.lto,
                null,
                emit_bin_path,
                post_ir_path,
                null,
            )) {
                defer llvm.disposeMessage(error_message);

                log.err("LLVM failed to emit bin={s} ir={s}: {s}", .{
                    emit_bin_msg, post_llvm_ir_msg, error_message,
                });
                return error.FailedToEmit;
            }
            emit_bin_path = null;
            post_ir_path = null;
        }

        if (target_machine.emitToFile(
            module,
            &error_message,
            options.is_debug,
            options.is_small,
            options.time_report,
            options.sanitize_thread,
            options.lto,
            options.asm_path,
            emit_bin_path,
            post_ir_path,
            null,
        )) {
            defer llvm.disposeMessage(error_message);

            log.err("LLVM failed to emit asm={s} bin={s} ir={s} bc={s}: {s}", .{
                emit_asm_msg,  emit_bin_msg, post_llvm_ir_msg, post_llvm_bc_msg,
                error_message,
            });
            return error.FailedToEmit;
        }
    }

    pub fn update_func(
        o: *Object,
        zcu: *Module,
        func_index: InternPool.Index,
        air: Air,
        liveness: Liveness,
    ) !void {
        const comp = zcu.comp;
        const func = zcu.func_info(func_index);
        const decl_index = func.owner_decl;
        const decl = zcu.decl_ptr(decl_index);
        const namespace = zcu.namespace_ptr(decl.src_namespace);
        const owner_mod = namespace.file_scope.mod;
        const fn_info = zcu.type_to_func(decl.type_of(zcu)).?;
        const target = owner_mod.resolved_target.result;
        const ip = &zcu.intern_pool;

        var dg: DeclGen = .{
            .object = o,
            .decl_index = decl_index,
            .decl = decl,
            .err_msg = null,
        };

        const function_index = try o.resolve_llvm_function(decl_index);

        var attributes = try function_index.ptr_const(&o.builder).attributes.to_wip(&o.builder);
        defer attributes.deinit(&o.builder);

        if (func.analysis(ip).is_noinline) {
            try attributes.add_fn_attr(.@"noinline", &o.builder);
        } else {
            _ = try attributes.remove_fn_attr(.@"noinline");
        }

        const stack_alignment = func.analysis(ip).stack_alignment;
        if (stack_alignment != .none) {
            try attributes.add_fn_attr(.{ .alignstack = stack_alignment.to_llvm() }, &o.builder);
            try attributes.add_fn_attr(.@"noinline", &o.builder);
        } else {
            _ = try attributes.remove_fn_attr(.alignstack);
        }

        if (func.analysis(ip).is_cold) {
            try attributes.add_fn_attr(.cold, &o.builder);
        } else {
            _ = try attributes.remove_fn_attr(.cold);
        }

        // TODO: disable this if safety is off for the function scope
        const ssp_buf_size = owner_mod.stack_protector;
        if (ssp_buf_size != 0) {
            try attributes.add_fn_attr(.sspstrong, &o.builder);
            try attributes.add_fn_attr(.{ .string = .{
                .kind = try o.builder.string("stack-protector-buffer-size"),
                .value = try o.builder.fmt("{d}", .{ssp_buf_size}),
            } }, &o.builder);
        }

        // TODO: disable this if safety is off for the function scope
        if (owner_mod.stack_check) {
            try attributes.add_fn_attr(.{ .string = .{
                .kind = try o.builder.string("probe-stack"),
                .value = try o.builder.string("__zig_probe_stack"),
            } }, &o.builder);
        } else if (target.os.tag == .uefi) {
            try attributes.add_fn_attr(.{ .string = .{
                .kind = try o.builder.string("no-stack-arg-probe"),
                .value = .empty,
            } }, &o.builder);
        }

        if (decl.@"linksection".to_slice(ip)) |section|
            function_index.set_section(try o.builder.string(section), &o.builder);

        var deinit_wip = true;
        var wip = try Builder.WipFunction.init(&o.builder, .{
            .function = function_index,
            .strip = owner_mod.strip,
        });
        defer if (deinit_wip) wip.deinit();
        wip.cursor = .{ .block = try wip.block(0, "Entry") };

        var llvm_arg_i: u32 = 0;

        // This gets the LLVM values from the function and stores them in `dg.args`.
        const sret = first_param_sret(fn_info, zcu, target);
        const ret_ptr: Builder.Value = if (sret) param: {
            const param = wip.arg(llvm_arg_i);
            llvm_arg_i += 1;
            break :param param;
        } else .none;

        if (cc_abi_promote_int(fn_info.cc, zcu, Type.from_interned(fn_info.return_type))) |s| switch (s) {
            .signed => try attributes.add_ret_attr(.signext, &o.builder),
            .unsigned => try attributes.add_ret_attr(.zeroext, &o.builder),
        };

        const err_return_tracing = Type.from_interned(fn_info.return_type).is_error(zcu) and
            comp.config.any_error_tracing;

        const err_ret_trace: Builder.Value = if (err_return_tracing) param: {
            const param = wip.arg(llvm_arg_i);
            llvm_arg_i += 1;
            break :param param;
        } else .none;

        // This is the list of args we will use that correspond directly to the AIR arg
        // instructions. Depending on the calling convention, this list is not necessarily
        // a bijection with the actual LLVM parameters of the function.
        const gpa = o.gpa;
        var args: std.ArrayListUnmanaged(Builder.Value) = .{};
        defer args.deinit(gpa);

        {
            var it = iterate_param_types(o, fn_info);
            while (try it.next()) |lowering| {
                try args.ensure_unused_capacity(gpa, 1);

                switch (lowering) {
                    .no_bits => continue,
                    .byval => {
                        assert(!it.byval_attr);
                        const param_index = it.zig_index - 1;
                        const param_ty = Type.from_interned(fn_info.param_types.get(ip)[param_index]);
                        const param = wip.arg(llvm_arg_i);

                        if (is_by_ref(param_ty, zcu)) {
                            const alignment = param_ty.abi_alignment(zcu).to_llvm();
                            const param_llvm_ty = param.type_of_wip(&wip);
                            const arg_ptr = try build_alloca_inner(&wip, param_llvm_ty, alignment, target);
                            _ = try wip.store(.normal, param, arg_ptr, alignment);
                            args.append_assume_capacity(arg_ptr);
                        } else {
                            args.append_assume_capacity(param);

                            try o.add_by_val_param_attrs(&attributes, param_ty, param_index, fn_info, llvm_arg_i);
                        }
                        llvm_arg_i += 1;
                    },
                    .byref => {
                        const param_ty = Type.from_interned(fn_info.param_types.get(ip)[it.zig_index - 1]);
                        const param_llvm_ty = try o.lower_type(param_ty);
                        const param = wip.arg(llvm_arg_i);
                        const alignment = param_ty.abi_alignment(zcu).to_llvm();

                        try o.add_by_ref_param_attrs(&attributes, llvm_arg_i, alignment, it.byval_attr, param_llvm_ty);
                        llvm_arg_i += 1;

                        if (is_by_ref(param_ty, zcu)) {
                            args.append_assume_capacity(param);
                        } else {
                            args.append_assume_capacity(try wip.load(.normal, param_llvm_ty, param, alignment, ""));
                        }
                    },
                    .byref_mut => {
                        const param_ty = Type.from_interned(fn_info.param_types.get(ip)[it.zig_index - 1]);
                        const param_llvm_ty = try o.lower_type(param_ty);
                        const param = wip.arg(llvm_arg_i);
                        const alignment = param_ty.abi_alignment(zcu).to_llvm();

                        try attributes.add_param_attr(llvm_arg_i, .noundef, &o.builder);
                        llvm_arg_i += 1;

                        if (is_by_ref(param_ty, zcu)) {
                            args.append_assume_capacity(param);
                        } else {
                            args.append_assume_capacity(try wip.load(.normal, param_llvm_ty, param, alignment, ""));
                        }
                    },
                    .abi_sized_int => {
                        assert(!it.byval_attr);
                        const param_ty = Type.from_interned(fn_info.param_types.get(ip)[it.zig_index - 1]);
                        const param = wip.arg(llvm_arg_i);
                        llvm_arg_i += 1;

                        const param_llvm_ty = try o.lower_type(param_ty);
                        const alignment = param_ty.abi_alignment(zcu).to_llvm();
                        const arg_ptr = try build_alloca_inner(&wip, param_llvm_ty, alignment, target);
                        _ = try wip.store(.normal, param, arg_ptr, alignment);

                        args.append_assume_capacity(if (is_by_ref(param_ty, zcu))
                            arg_ptr
                        else
                            try wip.load(.normal, param_llvm_ty, arg_ptr, alignment, ""));
                    },
                    .slice => {
                        assert(!it.byval_attr);
                        const param_ty = Type.from_interned(fn_info.param_types.get(ip)[it.zig_index - 1]);
                        const ptr_info = param_ty.ptr_info(zcu);

                        if (math.cast(u5, it.zig_index - 1)) |i| {
                            if (@as(u1, @truncate(fn_info.noalias_bits >> i)) != 0) {
                                try attributes.add_param_attr(llvm_arg_i, .@"noalias", &o.builder);
                            }
                        }
                        if (param_ty.zig_type_tag(zcu) != .Optional) {
                            try attributes.add_param_attr(llvm_arg_i, .nonnull, &o.builder);
                        }
                        if (ptr_info.flags.is_const) {
                            try attributes.add_param_attr(llvm_arg_i, .readonly, &o.builder);
                        }
                        const elem_align = (if (ptr_info.flags.alignment != .none)
                            @as(InternPool.Alignment, ptr_info.flags.alignment)
                        else
                            Type.from_interned(ptr_info.child).abi_alignment(zcu).max(.@"1")).to_llvm();
                        try attributes.add_param_attr(llvm_arg_i, .{ .@"align" = elem_align }, &o.builder);
                        const ptr_param = wip.arg(llvm_arg_i);
                        llvm_arg_i += 1;
                        const len_param = wip.arg(llvm_arg_i);
                        llvm_arg_i += 1;

                        const slice_llvm_ty = try o.lower_type(param_ty);
                        args.append_assume_capacity(
                            try wip.build_aggregate(slice_llvm_ty, &.{ ptr_param, len_param }, ""),
                        );
                    },
                    .multiple_llvm_types => {
                        assert(!it.byval_attr);
                        const field_types = it.types_buffer[0..it.types_len];
                        const param_ty = Type.from_interned(fn_info.param_types.get(ip)[it.zig_index - 1]);
                        const param_llvm_ty = try o.lower_type(param_ty);
                        const param_alignment = param_ty.abi_alignment(zcu).to_llvm();
                        const arg_ptr = try build_alloca_inner(&wip, param_llvm_ty, param_alignment, target);
                        const llvm_ty = try o.builder.struct_type(.normal, field_types);
                        for (0..field_types.len) |field_i| {
                            const param = wip.arg(llvm_arg_i);
                            llvm_arg_i += 1;
                            const field_ptr = try wip.gep_struct(llvm_ty, arg_ptr, field_i, "");
                            const alignment =
                                Builder.Alignment.from_byte_units(@div_exact(target.ptr_bit_width(), 8));
                            _ = try wip.store(.normal, param, field_ptr, alignment);
                        }

                        const is_by_ref = is_by_ref(param_ty, zcu);
                        args.append_assume_capacity(if (is_by_ref)
                            arg_ptr
                        else
                            try wip.load(.normal, param_llvm_ty, arg_ptr, param_alignment, ""));
                    },
                    .as_u16 => {
                        assert(!it.byval_attr);
                        const param = wip.arg(llvm_arg_i);
                        llvm_arg_i += 1;
                        args.append_assume_capacity(try wip.cast(.bitcast, param, .half, ""));
                    },
                    .float_array => {
                        const param_ty = Type.from_interned(fn_info.param_types.get(ip)[it.zig_index - 1]);
                        const param_llvm_ty = try o.lower_type(param_ty);
                        const param = wip.arg(llvm_arg_i);
                        llvm_arg_i += 1;

                        const alignment = param_ty.abi_alignment(zcu).to_llvm();
                        const arg_ptr = try build_alloca_inner(&wip, param_llvm_ty, alignment, target);
                        _ = try wip.store(.normal, param, arg_ptr, alignment);

                        args.append_assume_capacity(if (is_by_ref(param_ty, zcu))
                            arg_ptr
                        else
                            try wip.load(.normal, param_llvm_ty, arg_ptr, alignment, ""));
                    },
                    .i32_array, .i64_array => {
                        const param_ty = Type.from_interned(fn_info.param_types.get(ip)[it.zig_index - 1]);
                        const param_llvm_ty = try o.lower_type(param_ty);
                        const param = wip.arg(llvm_arg_i);
                        llvm_arg_i += 1;

                        const alignment = param_ty.abi_alignment(zcu).to_llvm();
                        const arg_ptr = try build_alloca_inner(&wip, param_llvm_ty, alignment, target);
                        _ = try wip.store(.normal, param, arg_ptr, alignment);

                        args.append_assume_capacity(if (is_by_ref(param_ty, zcu))
                            arg_ptr
                        else
                            try wip.load(.normal, param_llvm_ty, arg_ptr, alignment, ""));
                    },
                }
            }
        }

        function_index.set_attributes(try attributes.finish(&o.builder), &o.builder);

        const file, const subprogram = if (!wip.strip) debug_info: {
            const file = try o.get_debug_file(namespace.file_scope);

            const line_number = decl.src_line + 1;
            const is_internal_linkage = decl.val.get_extern_func(zcu) == null and
                !zcu.decl_exports.contains(decl_index);
            const debug_decl_type = try o.lower_debug_type(decl.type_of(zcu));

            const subprogram = try o.builder.debug_subprogram(
                file,
                try o.builder.metadata_string(decl.name.to_slice(ip)),
                try o.builder.metadata_string_from_strtab_string(function_index.name(&o.builder)),
                line_number,
                line_number + func.lbrace_line,
                debug_decl_type,
                .{
                    .di_flags = .{
                        .StaticMember = true,
                        .NoReturn = fn_info.return_type == .noreturn_type,
                    },
                    .sp_flags = .{
                        .Optimized = owner_mod.optimize_mode != .Debug,
                        .Definition = true,
                        .LocalToUnit = is_internal_linkage,
                    },
                },
                o.debug_compile_unit,
            );
            function_index.set_subprogram(subprogram, &o.builder);
            break :debug_info .{ file, subprogram };
        } else .{.none} ** 2;

        var fg: FuncGen = .{
            .gpa = gpa,
            .air = air,
            .liveness = liveness,
            .dg = &dg,
            .wip = wip,
            .ret_ptr = ret_ptr,
            .args = args.items,
            .arg_index = 0,
            .func_inst_table = .{},
            .blocks = .{},
            .sync_scope = if (owner_mod.single_threaded) .singlethread else .system,
            .file = file,
            .scope = subprogram,
            .base_line = dg.decl.src_line,
            .prev_dbg_line = 0,
            .prev_dbg_column = 0,
            .err_ret_trace = err_ret_trace,
        };
        defer fg.deinit();
        deinit_wip = false;

        fg.gen_body(air.get_main_body()) catch |err| switch (err) {
            error.CodegenFail => {
                decl.analysis = .codegen_failure;
                try zcu.failed_decls.put(zcu.gpa, decl_index, dg.err_msg.?);
                dg.err_msg = null;
                return;
            },
            else => |e| return e,
        };

        try fg.wip.finish();

        try o.update_exports(zcu, .{ .decl_index = decl_index }, zcu.get_decl_exports(decl_index));
    }

    pub fn update_decl(self: *Object, module: *Module, decl_index: InternPool.DeclIndex) !void {
        const decl = module.decl_ptr(decl_index);
        var dg: DeclGen = .{
            .object = self,
            .decl = decl,
            .decl_index = decl_index,
            .err_msg = null,
        };
        dg.gen_decl() catch |err| switch (err) {
            error.CodegenFail => {
                decl.analysis = .codegen_failure;
                try module.failed_decls.put(module.gpa, decl_index, dg.err_msg.?);
                dg.err_msg = null;
                return;
            },
            else => |e| return e,
        };
        try self.update_exports(module, .{ .decl_index = decl_index }, module.get_decl_exports(decl_index));
    }

    pub fn update_exports(
        self: *Object,
        mod: *Module,
        exported: Module.Exported,
        exports: []const *Module.Export,
    ) link.File.UpdateExportsError!void {
        const decl_index = switch (exported) {
            .decl_index => |i| i,
            .value => |val| return update_exported_value(self, mod, val, exports),
        };
        const gpa = mod.gpa;
        const ip = &mod.intern_pool;
        // If the module does not already have the function, we ignore this function call
        // because we call `update_exports` at the end of `update_func` and `update_decl`.
        const global_index = self.decl_map.get(decl_index) orelse return;
        const decl = mod.decl_ptr(decl_index);
        const comp = mod.comp;
        if (decl.is_extern(mod)) {
            const decl_name = decl_name: {
                if (mod.get_target().is_wasm() and decl.val.type_of(mod).zig_type_tag(mod) == .Fn) {
                    if (decl.get_owned_extern_func(mod).?.lib_name.to_slice(ip)) |lib_name| {
                        if (!std.mem.eql(u8, lib_name, "c")) {
                            break :decl_name try self.builder.strtab_string_fmt("{}|{s}", .{ decl.name.fmt(ip), lib_name });
                        }
                    }
                }
                break :decl_name try self.builder.strtab_string(decl.name.to_slice(ip));
            };

            if (self.builder.get_global(decl_name)) |other_global| {
                if (other_global != global_index) {
                    try self.extern_collisions.put(gpa, decl_index, {});
                }
            }

            try global_index.rename(decl_name, &self.builder);
            global_index.set_linkage(.external, &self.builder);
            global_index.set_unnamed_addr(.default, &self.builder);
            if (comp.config.dll_export_fns)
                global_index.set_dll_storage_class(.default, &self.builder);

            if (decl.val.get_variable(mod)) |decl_var| {
                global_index.ptr_const(&self.builder).kind.variable.set_thread_local(
                    if (decl_var.is_threadlocal) .generaldynamic else .default,
                    &self.builder,
                );
                if (decl_var.is_weak_linkage) global_index.set_linkage(.extern_weak, &self.builder);
            }
        } else if (exports.len != 0) {
            const main_exp_name = try self.builder.strtab_string(exports[0].opts.name.to_slice(ip));
            try global_index.rename(main_exp_name, &self.builder);

            if (decl.val.get_variable(mod)) |decl_var| if (decl_var.is_threadlocal)
                global_index.ptr_const(&self.builder).kind
                    .variable.set_thread_local(.generaldynamic, &self.builder);

            return update_exported_global(self, mod, global_index, exports);
        } else {
            const fqn = try self.builder.strtab_string((try decl.fully_qualified_name(mod)).to_slice(ip));
            try global_index.rename(fqn, &self.builder);
            global_index.set_linkage(.internal, &self.builder);
            if (comp.config.dll_export_fns)
                global_index.set_dll_storage_class(.default, &self.builder);
            global_index.set_unnamed_addr(.unnamed_addr, &self.builder);
            if (decl.val.get_variable(mod)) |decl_var| {
                const decl_namespace = mod.namespace_ptr(decl.src_namespace);
                const single_threaded = decl_namespace.file_scope.mod.single_threaded;
                global_index.ptr_const(&self.builder).kind.variable.set_thread_local(
                    if (decl_var.is_threadlocal and !single_threaded)
                        .generaldynamic
                    else
                        .default,
                    &self.builder,
                );
            }
        }
    }

    fn update_exported_value(
        o: *Object,
        mod: *Module,
        exported_value: InternPool.Index,
        exports: []const *Module.Export,
    ) link.File.UpdateExportsError!void {
        const gpa = mod.gpa;
        const ip = &mod.intern_pool;
        const main_exp_name = try o.builder.strtab_string(exports[0].opts.name.to_slice(ip));
        const global_index = i: {
            const gop = try o.anon_decl_map.get_or_put(gpa, exported_value);
            if (gop.found_existing) {
                const global_index = gop.value_ptr.*;
                try global_index.rename(main_exp_name, &o.builder);
                break :i global_index;
            }
            const llvm_addr_space = to_llvm_address_space(.generic, o.target);
            const variable_index = try o.builder.add_variable(
                main_exp_name,
                try o.lower_type(Type.from_interned(ip.type_of(exported_value))),
                llvm_addr_space,
            );
            const global_index = variable_index.ptr_const(&o.builder).global;
            gop.value_ptr.* = global_index;
            // This line invalidates `gop`.
            const init_val = o.lower_value(exported_value) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.CodegenFail => return error.AnalysisFail,
            };
            try variable_index.set_initializer(init_val, &o.builder);
            break :i global_index;
        };
        return update_exported_global(o, mod, global_index, exports);
    }

    fn update_exported_global(
        o: *Object,
        mod: *Module,
        global_index: Builder.Global.Index,
        exports: []const *Module.Export,
    ) link.File.UpdateExportsError!void {
        const comp = mod.comp;
        const ip = &mod.intern_pool;
        global_index.set_unnamed_addr(.default, &o.builder);
        if (comp.config.dll_export_fns)
            global_index.set_dll_storage_class(.dllexport, &o.builder);
        global_index.set_linkage(switch (exports[0].opts.linkage) {
            .internal => unreachable,
            .strong => .external,
            .weak => .weak_odr,
            .link_once => .linkonce_odr,
        }, &o.builder);
        global_index.set_visibility(switch (exports[0].opts.visibility) {
            .default => .default,
            .hidden => .hidden,
            .protected => .protected,
        }, &o.builder);
        if (exports[0].opts.section.to_slice(ip)) |section|
            switch (global_index.ptr_const(&o.builder).kind) {
                .variable => |impl_index| impl_index.set_section(
                    try o.builder.string(section),
                    &o.builder,
                ),
                .function => unreachable,
                .alias => unreachable,
                .replaced => unreachable,
            };

        // If a Decl is exported more than one time (which is rare),
        // we add aliases for all but the first export.
        // TODO LLVM C API does not support deleting aliases.
        // The planned solution to this is https://github.com/ziglang/zig/issues/13265
        // Until then we iterate over existing aliases and make them point
        // to the correct decl, or otherwise add a new alias. Old aliases are leaked.
        for (exports[1..]) |exp| {
            const exp_name = try o.builder.strtab_string(exp.opts.name.to_slice(ip));
            if (o.builder.get_global(exp_name)) |global| {
                switch (global.ptr_const(&o.builder).kind) {
                    .alias => |alias| {
                        alias.set_aliasee(global_index.to_const(), &o.builder);
                        continue;
                    },
                    .variable, .function => {},
                    .replaced => unreachable,
                }
            }
            const alias_index = try o.builder.add_alias(
                .empty,
                global_index.type_of(&o.builder),
                .default,
                global_index.to_const(),
            );
            try alias_index.rename(exp_name, &o.builder);
        }
    }

    pub fn free_decl(self: *Object, decl_index: InternPool.DeclIndex) void {
        const global = self.decl_map.get(decl_index) orelse return;
        global.delete(&self.builder);
    }

    fn get_debug_file(o: *Object, file: *const Module.File) Allocator.Error!Builder.Metadata {
        const gpa = o.gpa;
        const gop = try o.debug_file_map.get_or_put(gpa, file);
        errdefer assert(o.debug_file_map.remove(file));
        if (gop.found_existing) return gop.value_ptr.*;
        gop.value_ptr.* = try o.builder.debug_file(
            try o.builder.metadata_string(std.fs.path.basename(file.sub_file_path)),
            dir_path: {
                const sub_path = std.fs.path.dirname(file.sub_file_path) orelse "";
                const dir_path = try file.mod.root.join_string(gpa, sub_path);
                defer gpa.free(dir_path);
                if (std.fs.path.is_absolute(dir_path))
                    break :dir_path try o.builder.metadata_string(dir_path);
                var abs_buffer: [std.fs.MAX_PATH_BYTES]u8 = undefined;
                const abs_path = std.fs.realpath(dir_path, &abs_buffer) catch
                    break :dir_path try o.builder.metadata_string(dir_path);
                break :dir_path try o.builder.metadata_string(abs_path);
            },
        );
        return gop.value_ptr.*;
    }

    pub fn lower_debug_type(
        o: *Object,
        ty: Type,
    ) Allocator.Error!Builder.Metadata {
        assert(!o.builder.strip);

        const gpa = o.gpa;
        const target = o.target;
        const mod = o.module;
        const ip = &mod.intern_pool;

        if (o.debug_type_map.get(ty)) |debug_type| return debug_type;

        switch (ty.zig_type_tag(mod)) {
            .Void,
            .NoReturn,
            => {
                const debug_void_type = try o.builder.debug_signed_type(
                    try o.builder.metadata_string("void"),
                    0,
                );
                try o.debug_type_map.put(gpa, ty, debug_void_type);
                return debug_void_type;
            },
            .Int => {
                const info = ty.int_info(mod);
                assert(info.bits != 0);
                const name = try o.alloc_type_name(ty);
                defer gpa.free(name);
                const builder_name = try o.builder.metadata_string(name);
                const debug_bits = ty.abi_size(mod) * 8; // lldb cannot handle non-byte sized types
                const debug_int_type = switch (info.signedness) {
                    .signed => try o.builder.debug_signed_type(builder_name, debug_bits),
                    .unsigned => try o.builder.debug_unsigned_type(builder_name, debug_bits),
                };
                try o.debug_type_map.put(gpa, ty, debug_int_type);
                return debug_int_type;
            },
            .Enum => {
                const owner_decl_index = ty.get_owner_decl(mod);
                const owner_decl = o.module.decl_ptr(owner_decl_index);

                if (!ty.has_runtime_bits_ignore_comptime(mod)) {
                    const debug_enum_type = try o.make_empty_namespace_debug_type(owner_decl_index);
                    try o.debug_type_map.put(gpa, ty, debug_enum_type);
                    return debug_enum_type;
                }

                const enum_type = ip.load_enum_type(ty.to_intern());

                const enumerators = try gpa.alloc(Builder.Metadata, enum_type.names.len);
                defer gpa.free(enumerators);

                const int_ty = Type.from_interned(enum_type.tag_ty);
                const int_info = ty.int_info(mod);
                assert(int_info.bits != 0);

                for (enum_type.names.get(ip), 0..) |field_name_ip, i| {
                    var bigint_space: Value.BigIntSpace = undefined;
                    const bigint = if (enum_type.values.len != 0)
                        Value.from_interned(enum_type.values.get(ip)[i]).to_big_int(&bigint_space, mod)
                    else
                        std.math.big.int.Mutable.init(&bigint_space.limbs, i).to_const();

                    enumerators[i] = try o.builder.debug_enumerator(
                        try o.builder.metadata_string(field_name_ip.to_slice(ip)),
                        int_info.signedness == .unsigned,
                        int_info.bits,
                        bigint,
                    );
                }

                const file = try o.get_debug_file(mod.namespace_ptr(owner_decl.src_namespace).file_scope);
                const scope = try o.namespace_to_debug_scope(owner_decl.src_namespace);

                const name = try o.alloc_type_name(ty);
                defer gpa.free(name);

                const debug_enum_type = try o.builder.debug_enumeration_type(
                    try o.builder.metadata_string(name),
                    file,
                    scope,
                    owner_decl.src_node + 1, // Line
                    try o.lower_debug_type(int_ty),
                    ty.abi_size(mod) * 8,
                    (ty.abi_alignment(mod).to_byte_units() orelse 0) * 8,
                    try o.builder.debug_tuple(enumerators),
                );

                try o.debug_type_map.put(gpa, ty, debug_enum_type);
                try o.debug_enums.append(gpa, debug_enum_type);
                return debug_enum_type;
            },
            .Float => {
                const bits = ty.float_bits(target);
                const name = try o.alloc_type_name(ty);
                defer gpa.free(name);
                const debug_float_type = try o.builder.debug_float_type(
                    try o.builder.metadata_string(name),
                    bits,
                );
                try o.debug_type_map.put(gpa, ty, debug_float_type);
                return debug_float_type;
            },
            .Bool => {
                const debug_bool_type = try o.builder.debug_bool_type(
                    try o.builder.metadata_string("bool"),
                    8, // lldb cannot handle non-byte sized types
                );
                try o.debug_type_map.put(gpa, ty, debug_bool_type);
                return debug_bool_type;
            },
            .Pointer => {
                // Normalize everything that the debug info does not represent.
                const ptr_info = ty.ptr_info(mod);

                if (ptr_info.sentinel != .none or
                    ptr_info.flags.address_space != .generic or
                    ptr_info.packed_offset.bit_offset != 0 or
                    ptr_info.packed_offset.host_size != 0 or
                    ptr_info.flags.vector_index != .none or
                    ptr_info.flags.is_allowzero or
                    ptr_info.flags.is_const or
                    ptr_info.flags.is_volatile or
                    ptr_info.flags.size == .Many or ptr_info.flags.size == .C or
                    !Type.from_interned(ptr_info.child).has_runtime_bits_ignore_comptime(mod))
                {
                    const bland_ptr_ty = try mod.ptr_type(.{
                        .child = if (!Type.from_interned(ptr_info.child).has_runtime_bits_ignore_comptime(mod))
                            .anyopaque_type
                        else
                            ptr_info.child,
                        .flags = .{
                            .alignment = ptr_info.flags.alignment,
                            .size = switch (ptr_info.flags.size) {
                                .Many, .C, .One => .One,
                                .Slice => .Slice,
                            },
                        },
                    });
                    const debug_ptr_type = try o.lower_debug_type(bland_ptr_ty);
                    try o.debug_type_map.put(gpa, ty, debug_ptr_type);
                    return debug_ptr_type;
                }

                const debug_fwd_ref = try o.builder.debug_forward_reference();

                // Set as forward reference while the type is lowered in case it references itself
                try o.debug_type_map.put(gpa, ty, debug_fwd_ref);

                if (ty.is_slice(mod)) {
                    const ptr_ty = ty.slice_ptr_field_type(mod);
                    const len_ty = Type.usize;

                    const name = try o.alloc_type_name(ty);
                    defer gpa.free(name);
                    const line = 0;

                    const ptr_size = ptr_ty.abi_size(mod);
                    const ptr_align = ptr_ty.abi_alignment(mod);
                    const len_size = len_ty.abi_size(mod);
                    const len_align = len_ty.abi_alignment(mod);

                    const len_offset = len_align.forward(ptr_size);

                    const debug_ptr_type = try o.builder.debug_member_type(
                        try o.builder.metadata_string("ptr"),
                        .none, // File
                        debug_fwd_ref,
                        0, // Line
                        try o.lower_debug_type(ptr_ty),
                        ptr_size * 8,
                        (ptr_align.to_byte_units() orelse 0) * 8,
                        0, // Offset
                    );

                    const debug_len_type = try o.builder.debug_member_type(
                        try o.builder.metadata_string("len"),
                        .none, // File
                        debug_fwd_ref,
                        0, // Line
                        try o.lower_debug_type(len_ty),
                        len_size * 8,
                        (len_align.to_byte_units() orelse 0) * 8,
                        len_offset * 8,
                    );

                    const debug_slice_type = try o.builder.debug_struct_type(
                        try o.builder.metadata_string(name),
                        .none, // File
                        o.debug_compile_unit, // Scope
                        line,
                        .none, // Underlying type
                        ty.abi_size(mod) * 8,
                        (ty.abi_alignment(mod).to_byte_units() orelse 0) * 8,
                        try o.builder.debug_tuple(&.{
                            debug_ptr_type,
                            debug_len_type,
                        }),
                    );

                    o.builder.debug_forward_reference_set_type(debug_fwd_ref, debug_slice_type);

                    // Set to real type now that it has been lowered fully
                    const map_ptr = o.debug_type_map.get_ptr(ty) orelse unreachable;
                    map_ptr.* = debug_slice_type;

                    return debug_slice_type;
                }

                const debug_elem_ty = try o.lower_debug_type(Type.from_interned(ptr_info.child));

                const name = try o.alloc_type_name(ty);
                defer gpa.free(name);

                const debug_ptr_type = try o.builder.debug_pointer_type(
                    try o.builder.metadata_string(name),
                    .none, // File
                    .none, // Scope
                    0, // Line
                    debug_elem_ty,
                    target.ptr_bit_width(),
                    (ty.ptr_alignment(mod).to_byte_units() orelse 0) * 8,
                    0, // Offset
                );

                o.builder.debug_forward_reference_set_type(debug_fwd_ref, debug_ptr_type);

                // Set to real type now that it has been lowered fully
                const map_ptr = o.debug_type_map.get_ptr(ty) orelse unreachable;
                map_ptr.* = debug_ptr_type;

                return debug_ptr_type;
            },
            .Opaque => {
                if (ty.to_intern() == .anyopaque_type) {
                    const debug_opaque_type = try o.builder.debug_signed_type(
                        try o.builder.metadata_string("anyopaque"),
                        0,
                    );
                    try o.debug_type_map.put(gpa, ty, debug_opaque_type);
                    return debug_opaque_type;
                }

                const name = try o.alloc_type_name(ty);
                defer gpa.free(name);
                const owner_decl_index = ty.get_owner_decl(mod);
                const owner_decl = o.module.decl_ptr(owner_decl_index);
                const debug_opaque_type = try o.builder.debug_struct_type(
                    try o.builder.metadata_string(name),
                    try o.get_debug_file(mod.namespace_ptr(owner_decl.src_namespace).file_scope),
                    try o.namespace_to_debug_scope(owner_decl.src_namespace),
                    owner_decl.src_node + 1, // Line
                    .none, // Underlying type
                    0, // Size
                    0, // Align
                    .none, // Fields
                );
                try o.debug_type_map.put(gpa, ty, debug_opaque_type);
                return debug_opaque_type;
            },
            .Array => {
                const debug_array_type = try o.builder.debug_array_type(
                    .none, // Name
                    .none, // File
                    .none, // Scope
                    0, // Line
                    try o.lower_debug_type(ty.child_type(mod)),
                    ty.abi_size(mod) * 8,
                    (ty.abi_alignment(mod).to_byte_units() orelse 0) * 8,
                    try o.builder.debug_tuple(&.{
                        try o.builder.debug_subrange(
                            try o.builder.debug_constant(try o.builder.int_const(.i64, 0)),
                            try o.builder.debug_constant(try o.builder.int_const(.i64, ty.array_len(mod))),
                        ),
                    }),
                );
                try o.debug_type_map.put(gpa, ty, debug_array_type);
                return debug_array_type;
            },
            .Vector => {
                const elem_ty = ty.elem_type2(mod);
                // Vector elements cannot be padded since that would make
                // @bitSizOf(elem) * len > @bitSizOf(vec).
                // Neither gdb nor lldb seem to be able to display non-byte sized
                // vectors properly.
                const debug_elem_type = switch (elem_ty.zig_type_tag(mod)) {
                    .Int => blk: {
                        const info = elem_ty.int_info(mod);
                        assert(info.bits != 0);
                        const name = try o.alloc_type_name(ty);
                        defer gpa.free(name);
                        const builder_name = try o.builder.metadata_string(name);
                        break :blk switch (info.signedness) {
                            .signed => try o.builder.debug_signed_type(builder_name, info.bits),
                            .unsigned => try o.builder.debug_unsigned_type(builder_name, info.bits),
                        };
                    },
                    .Bool => try o.builder.debug_bool_type(
                        try o.builder.metadata_string("bool"),
                        1,
                    ),
                    else => try o.lower_debug_type(ty.child_type(mod)),
                };

                const debug_vector_type = try o.builder.debug_vector_type(
                    .none, // Name
                    .none, // File
                    .none, // Scope
                    0, // Line
                    debug_elem_type,
                    ty.abi_size(mod) * 8,
                    (ty.abi_alignment(mod).to_byte_units() orelse 0) * 8,
                    try o.builder.debug_tuple(&.{
                        try o.builder.debug_subrange(
                            try o.builder.debug_constant(try o.builder.int_const(.i64, 0)),
                            try o.builder.debug_constant(try o.builder.int_const(.i64, ty.vector_len(mod))),
                        ),
                    }),
                );

                try o.debug_type_map.put(gpa, ty, debug_vector_type);
                return debug_vector_type;
            },
            .Optional => {
                const name = try o.alloc_type_name(ty);
                defer gpa.free(name);
                const child_ty = ty.optional_child(mod);
                if (!child_ty.has_runtime_bits_ignore_comptime(mod)) {
                    const debug_bool_type = try o.builder.debug_bool_type(
                        try o.builder.metadata_string(name),
                        8,
                    );
                    try o.debug_type_map.put(gpa, ty, debug_bool_type);
                    return debug_bool_type;
                }

                const debug_fwd_ref = try o.builder.debug_forward_reference();

                // Set as forward reference while the type is lowered in case it references itself
                try o.debug_type_map.put(gpa, ty, debug_fwd_ref);

                if (ty.optional_repr_is_payload(mod)) {
                    const debug_optional_type = try o.lower_debug_type(child_ty);

                    o.builder.debug_forward_reference_set_type(debug_fwd_ref, debug_optional_type);

                    // Set to real type now that it has been lowered fully
                    const map_ptr = o.debug_type_map.get_ptr(ty) orelse unreachable;
                    map_ptr.* = debug_optional_type;

                    return debug_optional_type;
                }

                const non_null_ty = Type.u8;
                const payload_size = child_ty.abi_size(mod);
                const payload_align = child_ty.abi_alignment(mod);
                const non_null_size = non_null_ty.abi_size(mod);
                const non_null_align = non_null_ty.abi_alignment(mod);
                const non_null_offset = non_null_align.forward(payload_size);

                const debug_data_type = try o.builder.debug_member_type(
                    try o.builder.metadata_string("data"),
                    .none, // File
                    debug_fwd_ref,
                    0, // Line
                    try o.lower_debug_type(child_ty),
                    payload_size * 8,
                    (payload_align.to_byte_units() orelse 0) * 8,
                    0, // Offset
                );

                const debug_some_type = try o.builder.debug_member_type(
                    try o.builder.metadata_string("some"),
                    .none,
                    debug_fwd_ref,
                    0,
                    try o.lower_debug_type(non_null_ty),
                    non_null_size * 8,
                    (non_null_align.to_byte_units() orelse 0) * 8,
                    non_null_offset * 8,
                );

                const debug_optional_type = try o.builder.debug_struct_type(
                    try o.builder.metadata_string(name),
                    .none, // File
                    o.debug_compile_unit, // Scope
                    0, // Line
                    .none, // Underlying type
                    ty.abi_size(mod) * 8,
                    (ty.abi_alignment(mod).to_byte_units() orelse 0) * 8,
                    try o.builder.debug_tuple(&.{
                        debug_data_type,
                        debug_some_type,
                    }),
                );

                o.builder.debug_forward_reference_set_type(debug_fwd_ref, debug_optional_type);

                // Set to real type now that it has been lowered fully
                const map_ptr = o.debug_type_map.get_ptr(ty) orelse unreachable;
                map_ptr.* = debug_optional_type;

                return debug_optional_type;
            },
            .ErrorUnion => {
                const payload_ty = ty.error_union_payload(mod);
                if (!payload_ty.has_runtime_bits_ignore_comptime(mod)) {
                    // TODO: Maybe remove?
                    const debug_error_union_type = try o.lower_debug_type(Type.anyerror);
                    try o.debug_type_map.put(gpa, ty, debug_error_union_type);
                    return debug_error_union_type;
                }

                const name = try o.alloc_type_name(ty);
                defer gpa.free(name);

                const error_size = Type.anyerror.abi_size(mod);
                const error_align = Type.anyerror.abi_alignment(mod);
                const payload_size = payload_ty.abi_size(mod);
                const payload_align = payload_ty.abi_alignment(mod);

                var error_index: u32 = undefined;
                var payload_index: u32 = undefined;
                var error_offset: u64 = undefined;
                var payload_offset: u64 = undefined;
                if (error_align.compare(.gt, payload_align)) {
                    error_index = 0;
                    payload_index = 1;
                    error_offset = 0;
                    payload_offset = payload_align.forward(error_size);
                } else {
                    payload_index = 0;
                    error_index = 1;
                    payload_offset = 0;
                    error_offset = error_align.forward(payload_size);
                }

                const debug_fwd_ref = try o.builder.debug_forward_reference();

                var fields: [2]Builder.Metadata = undefined;
                fields[error_index] = try o.builder.debug_member_type(
                    try o.builder.metadata_string("tag"),
                    .none, // File
                    debug_fwd_ref,
                    0, // Line
                    try o.lower_debug_type(Type.anyerror),
                    error_size * 8,
                    (error_align.to_byte_units() orelse 0) * 8,
                    error_offset * 8,
                );
                fields[payload_index] = try o.builder.debug_member_type(
                    try o.builder.metadata_string("value"),
                    .none, // File
                    debug_fwd_ref,
                    0, // Line
                    try o.lower_debug_type(payload_ty),
                    payload_size * 8,
                    (payload_align.to_byte_units() orelse 0) * 8,
                    payload_offset * 8,
                );

                const debug_error_union_type = try o.builder.debug_struct_type(
                    try o.builder.metadata_string(name),
                    .none, // File
                    o.debug_compile_unit, // Sope
                    0, // Line
                    .none, // Underlying type
                    ty.abi_size(mod) * 8,
                    (ty.abi_alignment(mod).to_byte_units() orelse 0) * 8,
                    try o.builder.debug_tuple(&fields),
                );

                o.builder.debug_forward_reference_set_type(debug_fwd_ref, debug_error_union_type);

                try o.debug_type_map.put(gpa, ty, debug_error_union_type);
                return debug_error_union_type;
            },
            .ErrorSet => {
                const debug_error_set = try o.builder.debug_unsigned_type(
                    try o.builder.metadata_string("anyerror"),
                    16,
                );
                try o.debug_type_map.put(gpa, ty, debug_error_set);
                return debug_error_set;
            },
            .Struct => {
                const name = try o.alloc_type_name(ty);
                defer gpa.free(name);

                if (mod.type_to_packed_struct(ty)) |struct_type| {
                    const backing_int_ty = struct_type.backing_int_type(ip).*;
                    if (backing_int_ty != .none) {
                        const info = Type.from_interned(backing_int_ty).int_info(mod);
                        const builder_name = try o.builder.metadata_string(name);
                        const debug_int_type = switch (info.signedness) {
                            .signed => try o.builder.debug_signed_type(builder_name, ty.abi_size(mod) * 8),
                            .unsigned => try o.builder.debug_unsigned_type(builder_name, ty.abi_size(mod) * 8),
                        };
                        try o.debug_type_map.put(gpa, ty, debug_int_type);
                        return debug_int_type;
                    }
                }

                switch (ip.index_to_key(ty.to_intern())) {
                    .anon_struct_type => |tuple| {
                        var fields: std.ArrayListUnmanaged(Builder.Metadata) = .{};
                        defer fields.deinit(gpa);

                        try fields.ensure_unused_capacity(gpa, tuple.types.len);

                        comptime assert(struct_layout_version == 2);
                        var offset: u64 = 0;

                        const debug_fwd_ref = try o.builder.debug_forward_reference();

                        for (tuple.types.get(ip), tuple.values.get(ip), 0..) |field_ty, field_val, i| {
                            if (field_val != .none or !Type.from_interned(field_ty).has_runtime_bits(mod)) continue;

                            const field_size = Type.from_interned(field_ty).abi_size(mod);
                            const field_align = Type.from_interned(field_ty).abi_alignment(mod);
                            const field_offset = field_align.forward(offset);
                            offset = field_offset + field_size;

                            const field_name = if (tuple.names.len != 0)
                                tuple.names.get(ip)[i].to_slice(ip)
                            else
                                try std.fmt.alloc_print_z(gpa, "{d}", .{i});
                            defer if (tuple.names.len == 0) gpa.free(field_name);

                            fields.append_assume_capacity(try o.builder.debug_member_type(
                                try o.builder.metadata_string(field_name),
                                .none, // File
                                debug_fwd_ref,
                                0,
                                try o.lower_debug_type(Type.from_interned(field_ty)),
                                field_size * 8,
                                (field_align.to_byte_units() orelse 0) * 8,
                                field_offset * 8,
                            ));
                        }

                        const debug_struct_type = try o.builder.debug_struct_type(
                            try o.builder.metadata_string(name),
                            .none, // File
                            o.debug_compile_unit, // Scope
                            0, // Line
                            .none, // Underlying type
                            ty.abi_size(mod) * 8,
                            (ty.abi_alignment(mod).to_byte_units() orelse 0) * 8,
                            try o.builder.debug_tuple(fields.items),
                        );

                        o.builder.debug_forward_reference_set_type(debug_fwd_ref, debug_struct_type);

                        try o.debug_type_map.put(gpa, ty, debug_struct_type);
                        return debug_struct_type;
                    },
                    .struct_type => {
                        if (!ip.load_struct_type(ty.to_intern()).have_field_types(ip)) {
                            // This can happen if a struct type makes it all the way to
                            // flush() without ever being instantiated or referenced (even
                            // via pointer). The only reason we are hearing about it now is
                            // that it is being used as a namespace to put other debug types
                            // into. Therefore we can satisfy this by making an empty namespace,
                            // rather than changing the frontend to unnecessarily resolve the
                            // struct field types.
                            const owner_decl_index = ty.get_owner_decl(mod);
                            const debug_struct_type = try o.make_empty_namespace_debug_type(owner_decl_index);
                            try o.debug_type_map.put(gpa, ty, debug_struct_type);
                            return debug_struct_type;
                        }
                    },
                    else => {},
                }

                if (!ty.has_runtime_bits_ignore_comptime(mod)) {
                    const owner_decl_index = ty.get_owner_decl(mod);
                    const debug_struct_type = try o.make_empty_namespace_debug_type(owner_decl_index);
                    try o.debug_type_map.put(gpa, ty, debug_struct_type);
                    return debug_struct_type;
                }

                const struct_type = mod.type_to_struct(ty).?;

                var fields: std.ArrayListUnmanaged(Builder.Metadata) = .{};
                defer fields.deinit(gpa);

                try fields.ensure_unused_capacity(gpa, struct_type.field_types.len);

                const debug_fwd_ref = try o.builder.debug_forward_reference();

                // Set as forward reference while the type is lowered in case it references itself
                try o.debug_type_map.put(gpa, ty, debug_fwd_ref);

                comptime assert(struct_layout_version == 2);
                var it = struct_type.iterate_runtime_order(ip);
                while (it.next()) |field_index| {
                    const field_ty = Type.from_interned(struct_type.field_types.get(ip)[field_index]);
                    if (!field_ty.has_runtime_bits_ignore_comptime(mod)) continue;
                    const field_size = field_ty.abi_size(mod);
                    const field_align = mod.struct_field_alignment(
                        struct_type.field_align(ip, field_index),
                        field_ty,
                        struct_type.layout,
                    );
                    const field_offset = ty.struct_field_offset(field_index, mod);

                    const field_name = struct_type.field_name(ip, field_index).unwrap() orelse
                        try ip.get_or_put_string_fmt(gpa, "{d}", .{field_index}, .no_embedded_nulls);

                    fields.append_assume_capacity(try o.builder.debug_member_type(
                        try o.builder.metadata_string(field_name.to_slice(ip)),
                        .none, // File
                        debug_fwd_ref,
                        0, // Line
                        try o.lower_debug_type(field_ty),
                        field_size * 8,
                        (field_align.to_byte_units() orelse 0) * 8,
                        field_offset * 8,
                    ));
                }

                const debug_struct_type = try o.builder.debug_struct_type(
                    try o.builder.metadata_string(name),
                    .none, // File
                    o.debug_compile_unit, // Scope
                    0, // Line
                    .none, // Underlying type
                    ty.abi_size(mod) * 8,
                    (ty.abi_alignment(mod).to_byte_units() orelse 0) * 8,
                    try o.builder.debug_tuple(fields.items),
                );

                o.builder.debug_forward_reference_set_type(debug_fwd_ref, debug_struct_type);

                // Set to real type now that it has been lowered fully
                const map_ptr = o.debug_type_map.get_ptr(ty) orelse unreachable;
                map_ptr.* = debug_struct_type;

                return debug_struct_type;
            },
            .Union => {
                const owner_decl_index = ty.get_owner_decl(mod);

                const name = try o.alloc_type_name(ty);
                defer gpa.free(name);

                const union_type = ip.load_union_type(ty.to_intern());
                if (!union_type.have_field_types(ip) or
                    !ty.has_runtime_bits_ignore_comptime(mod) or
                    !union_type.have_layout(ip))
                {
                    const debug_union_type = try o.make_empty_namespace_debug_type(owner_decl_index);
                    try o.debug_type_map.put(gpa, ty, debug_union_type);
                    return debug_union_type;
                }

                const layout = mod.get_union_layout(union_type);

                const debug_fwd_ref = try o.builder.debug_forward_reference();

                // Set as forward reference while the type is lowered in case it references itself
                try o.debug_type_map.put(gpa, ty, debug_fwd_ref);

                if (layout.payload_size == 0) {
                    const debug_union_type = try o.builder.debug_struct_type(
                        try o.builder.metadata_string(name),
                        .none, // File
                        o.debug_compile_unit, // Scope
                        0, // Line
                        .none, // Underlying type
                        ty.abi_size(mod) * 8,
                        (ty.abi_alignment(mod).to_byte_units() orelse 0) * 8,
                        try o.builder.debug_tuple(
                            &.{try o.lower_debug_type(Type.from_interned(union_type.enum_tag_ty))},
                        ),
                    );

                    // Set to real type now that it has been lowered fully
                    const map_ptr = o.debug_type_map.get_ptr(ty) orelse unreachable;
                    map_ptr.* = debug_union_type;

                    return debug_union_type;
                }

                var fields: std.ArrayListUnmanaged(Builder.Metadata) = .{};
                defer fields.deinit(gpa);

                try fields.ensure_unused_capacity(gpa, union_type.load_tag_type(ip).names.len);

                const debug_union_fwd_ref = if (layout.tag_size == 0)
                    debug_fwd_ref
                else
                    try o.builder.debug_forward_reference();

                const tag_type = union_type.load_tag_type(ip);

                for (0..tag_type.names.len) |field_index| {
                    const field_ty = union_type.field_types.get(ip)[field_index];
                    if (!Type.from_interned(field_ty).has_runtime_bits_ignore_comptime(mod)) continue;

                    const field_size = Type.from_interned(field_ty).abi_size(mod);
                    const field_align = mod.union_field_normal_alignment(union_type, @int_cast(field_index));

                    const field_name = tag_type.names.get(ip)[field_index];
                    fields.append_assume_capacity(try o.builder.debug_member_type(
                        try o.builder.metadata_string(field_name.to_slice(ip)),
                        .none, // File
                        debug_union_fwd_ref,
                        0, // Line
                        try o.lower_debug_type(Type.from_interned(field_ty)),
                        field_size * 8,
                        (field_align.to_byte_units() orelse 0) * 8,
                        0, // Offset
                    ));
                }

                var union_name_buf: ?[:0]const u8 = null;
                defer if (union_name_buf) |buf| gpa.free(buf);
                const union_name = if (layout.tag_size == 0) name else name: {
                    union_name_buf = try std.fmt.alloc_print_z(gpa, "{s}:Payload", .{name});
                    break :name union_name_buf.?;
                };

                const debug_union_type = try o.builder.debug_union_type(
                    try o.builder.metadata_string(union_name),
                    .none, // File
                    o.debug_compile_unit, // Scope
                    0, // Line
                    .none, // Underlying type
                    ty.abi_size(mod) * 8,
                    (ty.abi_alignment(mod).to_byte_units() orelse 0) * 8,
                    try o.builder.debug_tuple(fields.items),
                );

                o.builder.debug_forward_reference_set_type(debug_union_fwd_ref, debug_union_type);

                if (layout.tag_size == 0) {
                    // Set to real type now that it has been lowered fully
                    const map_ptr = o.debug_type_map.get_ptr(ty) orelse unreachable;
                    map_ptr.* = debug_union_type;

                    return debug_union_type;
                }

                var tag_offset: u64 = undefined;
                var payload_offset: u64 = undefined;
                if (layout.tag_align.compare(.gte, layout.payload_align)) {
                    tag_offset = 0;
                    payload_offset = layout.payload_align.forward(layout.tag_size);
                } else {
                    payload_offset = 0;
                    tag_offset = layout.tag_align.forward(layout.payload_size);
                }

                const debug_tag_type = try o.builder.debug_member_type(
                    try o.builder.metadata_string("tag"),
                    .none, // File
                    debug_fwd_ref,
                    0, // Line
                    try o.lower_debug_type(Type.from_interned(union_type.enum_tag_ty)),
                    layout.tag_size * 8,
                    (layout.tag_align.to_byte_units() orelse 0) * 8,
                    tag_offset * 8,
                );

                const debug_payload_type = try o.builder.debug_member_type(
                    try o.builder.metadata_string("payload"),
                    .none, // File
                    debug_fwd_ref,
                    0, // Line
                    debug_union_type,
                    layout.payload_size * 8,
                    (layout.payload_align.to_byte_units() orelse 0) * 8,
                    payload_offset * 8,
                );

                const full_fields: [2]Builder.Metadata =
                    if (layout.tag_align.compare(.gte, layout.payload_align))
                    .{ debug_tag_type, debug_payload_type }
                else
                    .{ debug_payload_type, debug_tag_type };

                const debug_tagged_union_type = try o.builder.debug_struct_type(
                    try o.builder.metadata_string(name),
                    .none, // File
                    o.debug_compile_unit, // Scope
                    0, // Line
                    .none, // Underlying type
                    ty.abi_size(mod) * 8,
                    (ty.abi_alignment(mod).to_byte_units() orelse 0) * 8,
                    try o.builder.debug_tuple(&full_fields),
                );

                o.builder.debug_forward_reference_set_type(debug_fwd_ref, debug_tagged_union_type);

                // Set to real type now that it has been lowered fully
                const map_ptr = o.debug_type_map.get_ptr(ty) orelse unreachable;
                map_ptr.* = debug_tagged_union_type;

                return debug_tagged_union_type;
            },
            .Fn => {
                const fn_info = mod.type_to_func(ty).?;

                var debug_param_types = std.ArrayList(Builder.Metadata).init(gpa);
                defer debug_param_types.deinit();

                try debug_param_types.ensure_unused_capacity(3 + fn_info.param_types.len);

                // Return type goes first.
                if (Type.from_interned(fn_info.return_type).has_runtime_bits_ignore_comptime(mod)) {
                    const sret = first_param_sret(fn_info, mod, target);
                    const ret_ty = if (sret) Type.void else Type.from_interned(fn_info.return_type);
                    debug_param_types.append_assume_capacity(try o.lower_debug_type(ret_ty));

                    if (sret) {
                        const ptr_ty = try mod.single_mut_ptr_type(Type.from_interned(fn_info.return_type));
                        debug_param_types.append_assume_capacity(try o.lower_debug_type(ptr_ty));
                    }
                } else {
                    debug_param_types.append_assume_capacity(try o.lower_debug_type(Type.void));
                }

                if (Type.from_interned(fn_info.return_type).is_error(mod) and
                    o.module.comp.config.any_error_tracing)
                {
                    const ptr_ty = try mod.single_mut_ptr_type(try o.get_stack_trace_type());
                    debug_param_types.append_assume_capacity(try o.lower_debug_type(ptr_ty));
                }

                for (0..fn_info.param_types.len) |i| {
                    const param_ty = Type.from_interned(fn_info.param_types.get(ip)[i]);
                    if (!param_ty.has_runtime_bits_ignore_comptime(mod)) continue;

                    if (is_by_ref(param_ty, mod)) {
                        const ptr_ty = try mod.single_mut_ptr_type(param_ty);
                        debug_param_types.append_assume_capacity(try o.lower_debug_type(ptr_ty));
                    } else {
                        debug_param_types.append_assume_capacity(try o.lower_debug_type(param_ty));
                    }
                }

                const debug_function_type = try o.builder.debug_subroutine_type(
                    try o.builder.debug_tuple(debug_param_types.items),
                );

                try o.debug_type_map.put(gpa, ty, debug_function_type);
                return debug_function_type;
            },
            .ComptimeInt => unreachable,
            .ComptimeFloat => unreachable,
            .Type => unreachable,
            .Undefined => unreachable,
            .Null => unreachable,
            .EnumLiteral => unreachable,

            .Frame => @panic("TODO implement lower_debug_type for Frame types"),
            .AnyFrame => @panic("TODO implement lower_debug_type for AnyFrame types"),
        }
    }

    fn namespace_to_debug_scope(o: *Object, namespace_index: InternPool.NamespaceIndex) !Builder.Metadata {
        const mod = o.module;
        const namespace = mod.namespace_ptr(namespace_index);
        if (namespace.parent == .none) return try o.get_debug_file(namespace.file_scope);

        const gop = try o.debug_unresolved_namespace_scopes.get_or_put(o.gpa, namespace_index);

        if (!gop.found_existing) gop.value_ptr.* = try o.builder.debug_forward_reference();

        return gop.value_ptr.*;
    }

    fn make_empty_namespace_debug_type(o: *Object, decl_index: InternPool.DeclIndex) !Builder.Metadata {
        const mod = o.module;
        const decl = mod.decl_ptr(decl_index);
        return o.builder.debug_struct_type(
            try o.builder.metadata_string(decl.name.to_slice(&mod.intern_pool)), // TODO use fully qualified name
            try o.get_debug_file(mod.namespace_ptr(decl.src_namespace).file_scope),
            try o.namespace_to_debug_scope(decl.src_namespace),
            decl.src_line + 1,
            .none,
            0,
            0,
            .none,
        );
    }

    fn get_stack_trace_type(o: *Object) Allocator.Error!Type {
        const mod = o.module;

        const std_mod = mod.std_mod;
        const std_file = (mod.import_pkg(std_mod) catch unreachable).file;

        const builtin_str = try mod.intern_pool.get_or_put_string(mod.gpa, "builtin", .no_embedded_nulls);
        const std_namespace = mod.namespace_ptr(mod.decl_ptr(std_file.root_decl.unwrap().?).src_namespace);
        const builtin_decl = std_namespace.decls.get_key_adapted(builtin_str, Module.DeclAdapter{ .zcu = mod }).?;

        const stack_trace_str = try mod.intern_pool.get_or_put_string(mod.gpa, "StackTrace", .no_embedded_nulls);
        // buffer is only used for int_type, `builtin` is a struct.
        const builtin_ty = mod.decl_ptr(builtin_decl).val.to_type();
        const builtin_namespace = mod.namespace_ptr_unwrap(builtin_ty.get_namespace_index(mod)).?;
        const stack_trace_decl_index = builtin_namespace.decls.get_key_adapted(stack_trace_str, Module.DeclAdapter{ .zcu = mod }).?;
        const stack_trace_decl = mod.decl_ptr(stack_trace_decl_index);

        // Sema should have ensured that StackTrace was analyzed.
        assert(stack_trace_decl.has_tv);
        return stack_trace_decl.val.to_type();
    }

    fn alloc_type_name(o: *Object, ty: Type) Allocator.Error![:0]const u8 {
        var buffer = std.ArrayList(u8).init(o.gpa);
        errdefer buffer.deinit();
        try ty.print(buffer.writer(), o.module);
        return buffer.to_owned_slice_sentinel(0);
    }

    /// If the llvm function does not exist, create it.
    /// Note that this can be called before the function's semantic analysis has
    /// completed, so if any attributes rely on that, they must be done in update_func, not here.
    fn resolve_llvm_function(
        o: *Object,
        decl_index: InternPool.DeclIndex,
    ) Allocator.Error!Builder.Function.Index {
        const zcu = o.module;
        const ip = &zcu.intern_pool;
        const gpa = o.gpa;
        const decl = zcu.decl_ptr(decl_index);
        const namespace = zcu.namespace_ptr(decl.src_namespace);
        const owner_mod = namespace.file_scope.mod;
        const zig_fn_type = decl.type_of(zcu);
        const gop = try o.decl_map.get_or_put(gpa, decl_index);
        if (gop.found_existing) return gop.value_ptr.ptr(&o.builder).kind.function;

        assert(decl.has_tv);
        const fn_info = zcu.type_to_func(zig_fn_type).?;
        const target = owner_mod.resolved_target.result;
        const sret = first_param_sret(fn_info, zcu, target);

        const is_extern = decl.is_extern(zcu);
        const function_index = try o.builder.add_function(
            try o.lower_type(zig_fn_type),
            try o.builder.strtab_string((if (is_extern)
                decl.name
            else
                try decl.fully_qualified_name(zcu)).to_slice(ip)),
            to_llvm_address_space(decl.@"addrspace", target),
        );
        gop.value_ptr.* = function_index.ptr_const(&o.builder).global;

        var attributes: Builder.FunctionAttributes.Wip = .{};
        defer attributes.deinit(&o.builder);

        if (!is_extern) {
            function_index.set_linkage(.internal, &o.builder);
            function_index.set_unnamed_addr(.unnamed_addr, &o.builder);
        } else {
            if (target.is_wasm()) {
                try attributes.add_fn_attr(.{ .string = .{
                    .kind = try o.builder.string("wasm-import-name"),
                    .value = try o.builder.string(decl.name.to_slice(ip)),
                } }, &o.builder);
                if (decl.get_owned_extern_func(zcu).?.lib_name.to_slice(ip)) |lib_name| {
                    if (!std.mem.eql(u8, lib_name, "c")) try attributes.add_fn_attr(.{ .string = .{
                        .kind = try o.builder.string("wasm-import-module"),
                        .value = try o.builder.string(lib_name),
                    } }, &o.builder);
                }
            }
        }

        var llvm_arg_i: u32 = 0;
        if (sret) {
            // Sret pointers must not be address 0
            try attributes.add_param_attr(llvm_arg_i, .nonnull, &o.builder);
            try attributes.add_param_attr(llvm_arg_i, .@"noalias", &o.builder);

            const raw_llvm_ret_ty = try o.lower_type(Type.from_interned(fn_info.return_type));
            try attributes.add_param_attr(llvm_arg_i, .{ .sret = raw_llvm_ret_ty }, &o.builder);

            llvm_arg_i += 1;
        }

        const err_return_tracing = Type.from_interned(fn_info.return_type).is_error(zcu) and
            zcu.comp.config.any_error_tracing;

        if (err_return_tracing) {
            try attributes.add_param_attr(llvm_arg_i, .nonnull, &o.builder);
            llvm_arg_i += 1;
        }

        switch (fn_info.cc) {
            .Unspecified, .Inline => function_index.set_call_conv(.fastcc, &o.builder),
            .Naked => try attributes.add_fn_attr(.naked, &o.builder),
            .Async => {
                function_index.set_call_conv(.fastcc, &o.builder);
                @panic("TODO: LLVM backend lower async function");
            },
            else => function_index.set_call_conv(to_llvm_call_conv(fn_info.cc, target), &o.builder),
        }

        if (decl.alignment != .none)
            function_index.set_alignment(decl.alignment.to_llvm(), &o.builder);

        // Function attributes that are independent of analysis results of the function body.
        try o.add_common_fn_attributes(&attributes, owner_mod);

        if (fn_info.return_type == .noreturn_type) try attributes.add_fn_attr(.noreturn, &o.builder);

        // Add parameter attributes. We handle only the case of extern functions (no body)
        // because functions with bodies are handled in `update_func`.
        if (is_extern) {
            var it = iterate_param_types(o, fn_info);
            it.llvm_index = llvm_arg_i;
            while (try it.next()) |lowering| switch (lowering) {
                .byval => {
                    const param_index = it.zig_index - 1;
                    const param_ty = Type.from_interned(fn_info.param_types.get(ip)[param_index]);
                    if (!is_by_ref(param_ty, zcu)) {
                        try o.add_by_val_param_attrs(&attributes, param_ty, param_index, fn_info, it.llvm_index - 1);
                    }
                },
                .byref => {
                    const param_ty = Type.from_interned(fn_info.param_types.get(ip)[it.zig_index - 1]);
                    const param_llvm_ty = try o.lower_type(param_ty);
                    const alignment = param_ty.abi_alignment(zcu);
                    try o.add_by_ref_param_attrs(&attributes, it.llvm_index - 1, alignment.to_llvm(), it.byval_attr, param_llvm_ty);
                },
                .byref_mut => try attributes.add_param_attr(it.llvm_index - 1, .noundef, &o.builder),
                // No attributes needed for these.
                .no_bits,
                .abi_sized_int,
                .multiple_llvm_types,
                .as_u16,
                .float_array,
                .i32_array,
                .i64_array,
                => continue,

                .slice => unreachable, // extern functions do not support slice types.

            };
        }

        function_index.set_attributes(try attributes.finish(&o.builder), &o.builder);
        return function_index;
    }

    fn add_common_fn_attributes(
        o: *Object,
        attributes: *Builder.FunctionAttributes.Wip,
        owner_mod: *Package.Module,
    ) Allocator.Error!void {
        const comp = o.module.comp;

        if (!owner_mod.red_zone) {
            try attributes.add_fn_attr(.noredzone, &o.builder);
        }
        if (owner_mod.omit_frame_pointer) {
            try attributes.add_fn_attr(.{ .string = .{
                .kind = try o.builder.string("frame-pointer"),
                .value = try o.builder.string("none"),
            } }, &o.builder);
        } else {
            try attributes.add_fn_attr(.{ .string = .{
                .kind = try o.builder.string("frame-pointer"),
                .value = try o.builder.string("all"),
            } }, &o.builder);
        }
        try attributes.add_fn_attr(.nounwind, &o.builder);
        if (owner_mod.unwind_tables) {
            try attributes.add_fn_attr(.{ .uwtable = Builder.Attribute.UwTable.default }, &o.builder);
        }
        if (comp.skip_linker_dependencies or comp.no_builtin) {
            // The intent here is for compiler-rt and libc functions to not generate
            // infinite recursion. For example, if we are compiling the memcpy function,
            // and llvm detects that the body is equivalent to memcpy, it may replace the
            // body of memcpy with a call to memcpy, which would then cause a stack
            // overflow instead of performing memcpy.
            try attributes.add_fn_attr(.nobuiltin, &o.builder);
        }
        if (owner_mod.optimize_mode == .ReleaseSmall) {
            try attributes.add_fn_attr(.minsize, &o.builder);
            try attributes.add_fn_attr(.optsize, &o.builder);
        }
        if (owner_mod.sanitize_thread) {
            try attributes.add_fn_attr(.sanitize_thread, &o.builder);
        }
        const target = owner_mod.resolved_target.result;
        if (target.cpu.model.llvm_name) |s| {
            try attributes.add_fn_attr(.{ .string = .{
                .kind = try o.builder.string("target-cpu"),
                .value = try o.builder.string(s),
            } }, &o.builder);
        }
        if (owner_mod.resolved_target.llvm_cpu_features) |s| {
            try attributes.add_fn_attr(.{ .string = .{
                .kind = try o.builder.string("target-features"),
                .value = try o.builder.string(std.mem.span(s)),
            } }, &o.builder);
        }
        if (target.cpu.arch.is_bpf()) {
            try attributes.add_fn_attr(.{ .string = .{
                .kind = try o.builder.string("no-builtins"),
                .value = .empty,
            } }, &o.builder);
        }
    }

    fn resolve_global_anon_decl(
        o: *Object,
        decl_val: InternPool.Index,
        llvm_addr_space: Builder.AddrSpace,
        alignment: InternPool.Alignment,
    ) Error!Builder.Variable.Index {
        assert(alignment != .none);
        // TODO: Add address space to the anon_decl_map
        const gop = try o.anon_decl_map.get_or_put(o.gpa, decl_val);
        if (gop.found_existing) {
            // Keep the greater of the two alignments.
            const variable_index = gop.value_ptr.ptr(&o.builder).kind.variable;
            const old_alignment = InternPool.Alignment.from_llvm(variable_index.get_alignment(&o.builder));
            const max_alignment = old_alignment.max_strict(alignment);
            variable_index.set_alignment(max_alignment.to_llvm(), &o.builder);
            return variable_index;
        }
        errdefer assert(o.anon_decl_map.remove(decl_val));

        const mod = o.module;
        const decl_ty = mod.intern_pool.type_of(decl_val);

        const variable_index = try o.builder.add_variable(
            try o.builder.strtab_string_fmt("__anon_{d}", .{@int_from_enum(decl_val)}),
            try o.lower_type(Type.from_interned(decl_ty)),
            llvm_addr_space,
        );
        gop.value_ptr.* = variable_index.ptr_const(&o.builder).global;

        try variable_index.set_initializer(try o.lower_value(decl_val), &o.builder);
        variable_index.set_linkage(.internal, &o.builder);
        variable_index.set_mutability(.constant, &o.builder);
        variable_index.set_unnamed_addr(.unnamed_addr, &o.builder);
        variable_index.set_alignment(alignment.to_llvm(), &o.builder);
        return variable_index;
    }

    fn resolve_global_decl(
        o: *Object,
        decl_index: InternPool.DeclIndex,
    ) Allocator.Error!Builder.Variable.Index {
        const gop = try o.decl_map.get_or_put(o.gpa, decl_index);
        if (gop.found_existing) return gop.value_ptr.ptr(&o.builder).kind.variable;
        errdefer assert(o.decl_map.remove(decl_index));

        const mod = o.module;
        const decl = mod.decl_ptr(decl_index);
        const is_extern = decl.is_extern(mod);

        const variable_index = try o.builder.add_variable(
            try o.builder.strtab_string((if (is_extern)
                decl.name
            else
                try decl.fully_qualified_name(mod)).to_slice(&mod.intern_pool)),
            try o.lower_type(decl.type_of(mod)),
            to_llvm_global_address_space(decl.@"addrspace", mod.get_target()),
        );
        gop.value_ptr.* = variable_index.ptr_const(&o.builder).global;

        // This is needed for declarations created by `@extern`.
        if (is_extern) {
            variable_index.set_linkage(.external, &o.builder);
            variable_index.set_unnamed_addr(.default, &o.builder);
            if (decl.val.get_variable(mod)) |decl_var| {
                const decl_namespace = mod.namespace_ptr(decl.src_namespace);
                const single_threaded = decl_namespace.file_scope.mod.single_threaded;
                variable_index.set_thread_local(
                    if (decl_var.is_threadlocal and !single_threaded) .generaldynamic else .default,
                    &o.builder,
                );
                if (decl_var.is_weak_linkage) variable_index.set_linkage(.extern_weak, &o.builder);
            }
        } else {
            variable_index.set_linkage(.internal, &o.builder);
            variable_index.set_unnamed_addr(.unnamed_addr, &o.builder);
        }
        return variable_index;
    }

    fn error_int_type(o: *Object) Allocator.Error!Builder.Type {
        return o.builder.int_type(o.module.error_set_bits());
    }

    fn lower_type(o: *Object, t: Type) Allocator.Error!Builder.Type {
        const mod = o.module;
        const target = mod.get_target();
        const ip = &mod.intern_pool;
        return switch (t.to_intern()) {
            .u0_type, .i0_type => unreachable,
            inline .u1_type,
            .u8_type,
            .i8_type,
            .u16_type,
            .i16_type,
            .u29_type,
            .u32_type,
            .i32_type,
            .u64_type,
            .i64_type,
            .u80_type,
            .u128_type,
            .i128_type,
            => |tag| @field(Builder.Type, "i" ++ @tag_name(tag)[1 .. @tag_name(tag).len - "_type".len]),
            .usize_type, .isize_type => try o.builder.int_type(target.ptr_bit_width()),
            inline .c_char_type,
            .c_short_type,
            .c_ushort_type,
            .c_int_type,
            .c_uint_type,
            .c_long_type,
            .c_ulong_type,
            .c_longlong_type,
            .c_ulonglong_type,
            => |tag| try o.builder.int_type(target.c_type_bit_size(
                @field(std.Target.CType, @tag_name(tag)["c_".len .. @tag_name(tag).len - "_type".len]),
            )),
            .c_longdouble_type,
            .f16_type,
            .f32_type,
            .f64_type,
            .f80_type,
            .f128_type,
            => switch (t.float_bits(target)) {
                16 => if (backend_supports_f16(target)) .half else .i16,
                32 => .float,
                64 => .double,
                80 => if (backend_supports_f80(target)) .x86_fp80 else .i80,
                128 => .fp128,
                else => unreachable,
            },
            .anyopaque_type => {
                // This is unreachable except when used as the type for an extern global.
                // For example: `@extern(*anyopaque, .{ .name = "foo"})` should produce
                // @foo = external global i8
                return .i8;
            },
            .bool_type => .i1,
            .void_type => .void,
            .type_type => unreachable,
            .anyerror_type => try o.error_int_type(),
            .comptime_int_type,
            .comptime_float_type,
            .noreturn_type,
            => unreachable,
            .anyframe_type => @panic("TODO implement lower_type for AnyFrame types"),
            .null_type,
            .undefined_type,
            .enum_literal_type,
            => unreachable,
            .manyptr_u8_type,
            .manyptr_const_u8_type,
            .manyptr_const_u8_sentinel_0_type,
            .single_const_pointer_to_comptime_int_type,
            => .ptr,
            .slice_const_u8_type,
            .slice_const_u8_sentinel_0_type,
            => try o.builder.struct_type(.normal, &.{ .ptr, try o.lower_type(Type.usize) }),
            .optional_noreturn_type => unreachable,
            .anyerror_void_error_union_type,
            .adhoc_inferred_error_set_type,
            => try o.error_int_type(),
            .generic_poison_type,
            .empty_struct_type,
            => unreachable,
            // values, not types
            .undef,
            .zero,
            .zero_usize,
            .zero_u8,
            .one,
            .one_usize,
            .one_u8,
            .four_u8,
            .negative_one,
            .calling_convention_c,
            .calling_convention_inline,
            .void_value,
            .unreachable_value,
            .null_value,
            .bool_true,
            .bool_false,
            .empty_struct,
            .generic_poison,
            .none,
            => unreachable,
            else => switch (ip.index_to_key(t.to_intern())) {
                .int_type => |int_type| try o.builder.int_type(int_type.bits),
                .ptr_type => |ptr_type| type: {
                    const ptr_ty = try o.builder.ptr_type(
                        to_llvm_address_space(ptr_type.flags.address_space, target),
                    );
                    break :type switch (ptr_type.flags.size) {
                        .One, .Many, .C => ptr_ty,
                        .Slice => try o.builder.struct_type(.normal, &.{
                            ptr_ty,
                            try o.lower_type(Type.usize),
                        }),
                    };
                },
                .array_type => |array_type| o.builder.array_type(
                    array_type.len_including_sentinel(),
                    try o.lower_type(Type.from_interned(array_type.child)),
                ),
                .vector_type => |vector_type| o.builder.vector_type(
                    .normal,
                    vector_type.len,
                    try o.lower_type(Type.from_interned(vector_type.child)),
                ),
                .opt_type => |child_ty| {
                    // Must stay in sync with `opt_payload` logic in `lower_ptr`.
                    if (!Type.from_interned(child_ty).has_runtime_bits_ignore_comptime(mod)) return .i8;

                    const payload_ty = try o.lower_type(Type.from_interned(child_ty));
                    if (t.optional_repr_is_payload(mod)) return payload_ty;

                    comptime assert(optional_layout_version == 3);
                    var fields: [3]Builder.Type = .{ payload_ty, .i8, undefined };
                    var fields_len: usize = 2;
                    const offset = Type.from_interned(child_ty).abi_size(mod) + 1;
                    const abi_size = t.abi_size(mod);
                    const padding_len = abi_size - offset;
                    if (padding_len > 0) {
                        fields[2] = try o.builder.array_type(padding_len, .i8);
                        fields_len = 3;
                    }
                    return o.builder.struct_type(.normal, fields[0..fields_len]);
                },
                .anyframe_type => @panic("TODO implement lower_type for AnyFrame types"),
                .error_union_type => |error_union_type| {
                    // Must stay in sync with `codegen.err_union_payload_offset`.
                    // See logic in `lower_ptr`.
                    const error_type = try o.error_int_type();
                    if (!Type.from_interned(error_union_type.payload_type).has_runtime_bits_ignore_comptime(mod))
                        return error_type;
                    const payload_type = try o.lower_type(Type.from_interned(error_union_type.payload_type));
                    const err_int_ty = try mod.error_int_type();

                    const payload_align = Type.from_interned(error_union_type.payload_type).abi_alignment(mod);
                    const error_align = err_int_ty.abi_alignment(mod);

                    const payload_size = Type.from_interned(error_union_type.payload_type).abi_size(mod);
                    const error_size = err_int_ty.abi_size(mod);

                    var fields: [3]Builder.Type = undefined;
                    var fields_len: usize = 2;
                    const padding_len = if (error_align.compare(.gt, payload_align)) pad: {
                        fields[0] = error_type;
                        fields[1] = payload_type;
                        const payload_end =
                            payload_align.forward(error_size) +
                            payload_size;
                        const abi_size = error_align.forward(payload_end);
                        break :pad abi_size - payload_end;
                    } else pad: {
                        fields[0] = payload_type;
                        fields[1] = error_type;
                        const error_end =
                            error_align.forward(payload_size) +
                            error_size;
                        const abi_size = payload_align.forward(error_end);
                        break :pad abi_size - error_end;
                    };
                    if (padding_len > 0) {
                        fields[2] = try o.builder.array_type(padding_len, .i8);
                        fields_len = 3;
                    }
                    return o.builder.struct_type(.normal, fields[0..fields_len]);
                },
                .simple_type => unreachable,
                .struct_type => {
                    if (o.type_map.get(t.to_intern())) |value| return value;

                    const struct_type = ip.load_struct_type(t.to_intern());

                    if (struct_type.layout == .@"packed") {
                        const int_ty = try o.lower_type(Type.from_interned(struct_type.backing_int_type(ip).*));
                        try o.type_map.put(o.gpa, t.to_intern(), int_ty);
                        return int_ty;
                    }

                    const fqn = try mod.decl_ptr(struct_type.decl.unwrap().?).fully_qualified_name(mod);

                    var llvm_field_types = std.ArrayListUnmanaged(Builder.Type){};
                    defer llvm_field_types.deinit(o.gpa);
                    // Although we can estimate how much capacity to add, these cannot be
                    // relied upon because of the recursive calls to lower_type below.
                    try llvm_field_types.ensure_unused_capacity(o.gpa, struct_type.field_types.len);
                    try o.struct_field_map.ensure_unused_capacity(o.gpa, struct_type.field_types.len);

                    comptime assert(struct_layout_version == 2);
                    var offset: u64 = 0;
                    var big_align: InternPool.Alignment = .@"1";
                    var struct_kind: Builder.Type.Structure.Kind = .normal;
                    // When we encounter a zero-bit field, we place it here so we know to map it to the next non-zero-bit field (if any).
                    var it = struct_type.iterate_runtime_order(ip);
                    while (it.next()) |field_index| {
                        const field_ty = Type.from_interned(struct_type.field_types.get(ip)[field_index]);
                        const field_align = mod.struct_field_alignment(
                            struct_type.field_align(ip, field_index),
                            field_ty,
                            struct_type.layout,
                        );
                        const field_ty_align = field_ty.abi_alignment(mod);
                        if (field_align.compare(.lt, field_ty_align)) struct_kind = .@"packed";
                        big_align = big_align.max(field_align);
                        const prev_offset = offset;
                        offset = field_align.forward(offset);

                        const padding_len = offset - prev_offset;
                        if (padding_len > 0) try llvm_field_types.append(
                            o.gpa,
                            try o.builder.array_type(padding_len, .i8),
                        );

                        if (!field_ty.has_runtime_bits_ignore_comptime(mod)) {
                            // This is a zero-bit field. If there are runtime bits after this field,
                            // map to the next LLVM field (which we know exists): otherwise, don't
                            // map the field, indicating it's at the end of the struct.
                            if (offset != struct_type.size(ip).*) {
                                try o.struct_field_map.put(o.gpa, .{
                                    .struct_ty = t.to_intern(),
                                    .field_index = field_index,
                                }, @int_cast(llvm_field_types.items.len));
                            }
                            continue;
                        }

                        try o.struct_field_map.put(o.gpa, .{
                            .struct_ty = t.to_intern(),
                            .field_index = field_index,
                        }, @int_cast(llvm_field_types.items.len));
                        try llvm_field_types.append(o.gpa, try o.lower_type(field_ty));

                        offset += field_ty.abi_size(mod);
                    }
                    {
                        const prev_offset = offset;
                        offset = big_align.forward(offset);
                        const padding_len = offset - prev_offset;
                        if (padding_len > 0) try llvm_field_types.append(
                            o.gpa,
                            try o.builder.array_type(padding_len, .i8),
                        );
                    }

                    const ty = try o.builder.opaque_type(try o.builder.string(fqn.to_slice(ip)));
                    try o.type_map.put(o.gpa, t.to_intern(), ty);

                    o.builder.named_type_set_body(
                        ty,
                        try o.builder.struct_type(struct_kind, llvm_field_types.items),
                    );
                    return ty;
                },
                .anon_struct_type => |anon_struct_type| {
                    var llvm_field_types: std.ArrayListUnmanaged(Builder.Type) = .{};
                    defer llvm_field_types.deinit(o.gpa);
                    // Although we can estimate how much capacity to add, these cannot be
                    // relied upon because of the recursive calls to lower_type below.
                    try llvm_field_types.ensure_unused_capacity(o.gpa, anon_struct_type.types.len);
                    try o.struct_field_map.ensure_unused_capacity(o.gpa, anon_struct_type.types.len);

                    comptime assert(struct_layout_version == 2);
                    var offset: u64 = 0;
                    var big_align: InternPool.Alignment = .none;

                    const struct_size = t.abi_size(mod);

                    for (
                        anon_struct_type.types.get(ip),
                        anon_struct_type.values.get(ip),
                        0..,
                    ) |field_ty, field_val, field_index| {
                        if (field_val != .none) continue;

                        const field_align = Type.from_interned(field_ty).abi_alignment(mod);
                        big_align = big_align.max(field_align);
                        const prev_offset = offset;
                        offset = field_align.forward(offset);

                        const padding_len = offset - prev_offset;
                        if (padding_len > 0) try llvm_field_types.append(
                            o.gpa,
                            try o.builder.array_type(padding_len, .i8),
                        );
                        if (!Type.from_interned(field_ty).has_runtime_bits_ignore_comptime(mod)) {
                            // This is a zero-bit field. If there are runtime bits after this field,
                            // map to the next LLVM field (which we know exists): otherwise, don't
                            // map the field, indicating it's at the end of the struct.
                            if (offset != struct_size) {
                                try o.struct_field_map.put(o.gpa, .{
                                    .struct_ty = t.to_intern(),
                                    .field_index = @int_cast(field_index),
                                }, @int_cast(llvm_field_types.items.len));
                            }
                            continue;
                        }
                        try o.struct_field_map.put(o.gpa, .{
                            .struct_ty = t.to_intern(),
                            .field_index = @int_cast(field_index),
                        }, @int_cast(llvm_field_types.items.len));
                        try llvm_field_types.append(o.gpa, try o.lower_type(Type.from_interned(field_ty)));

                        offset += Type.from_interned(field_ty).abi_size(mod);
                    }
                    {
                        const prev_offset = offset;
                        offset = big_align.forward(offset);
                        const padding_len = offset - prev_offset;
                        if (padding_len > 0) try llvm_field_types.append(
                            o.gpa,
                            try o.builder.array_type(padding_len, .i8),
                        );
                    }
                    return o.builder.struct_type(.normal, llvm_field_types.items);
                },
                .union_type => {
                    if (o.type_map.get(t.to_intern())) |value| return value;

                    const union_obj = ip.load_union_type(t.to_intern());
                    const layout = mod.get_union_layout(union_obj);

                    if (union_obj.flags_ptr(ip).layout == .@"packed") {
                        const int_ty = try o.builder.int_type(@int_cast(t.bit_size(mod)));
                        try o.type_map.put(o.gpa, t.to_intern(), int_ty);
                        return int_ty;
                    }

                    if (layout.payload_size == 0) {
                        const enum_tag_ty = try o.lower_type(Type.from_interned(union_obj.enum_tag_ty));
                        try o.type_map.put(o.gpa, t.to_intern(), enum_tag_ty);
                        return enum_tag_ty;
                    }

                    const fqn = try mod.decl_ptr(union_obj.decl).fully_qualified_name(mod);

                    const aligned_field_ty = Type.from_interned(union_obj.field_types.get(ip)[layout.most_aligned_field]);
                    const aligned_field_llvm_ty = try o.lower_type(aligned_field_ty);

                    const payload_ty = ty: {
                        if (layout.most_aligned_field_size == layout.payload_size) {
                            break :ty aligned_field_llvm_ty;
                        }
                        const padding_len = if (layout.tag_size == 0)
                            layout.abi_size - layout.most_aligned_field_size
                        else
                            layout.payload_size - layout.most_aligned_field_size;
                        break :ty try o.builder.struct_type(.@"packed", &.{
                            aligned_field_llvm_ty,
                            try o.builder.array_type(padding_len, .i8),
                        });
                    };

                    if (layout.tag_size == 0) {
                        const ty = try o.builder.opaque_type(try o.builder.string(fqn.to_slice(ip)));
                        try o.type_map.put(o.gpa, t.to_intern(), ty);

                        o.builder.named_type_set_body(
                            ty,
                            try o.builder.struct_type(.normal, &.{payload_ty}),
                        );
                        return ty;
                    }
                    const enum_tag_ty = try o.lower_type(Type.from_interned(union_obj.enum_tag_ty));

                    // Put the tag before or after the payload depending on which one's
                    // alignment is greater.
                    var llvm_fields: [3]Builder.Type = undefined;
                    var llvm_fields_len: usize = 2;

                    if (layout.tag_align.compare(.gte, layout.payload_align)) {
                        llvm_fields = .{ enum_tag_ty, payload_ty, .none };
                    } else {
                        llvm_fields = .{ payload_ty, enum_tag_ty, .none };
                    }

                    // Insert padding to make the LLVM struct ABI size match the Zig union ABI size.
                    if (layout.padding != 0) {
                        llvm_fields[llvm_fields_len] = try o.builder.array_type(layout.padding, .i8);
                        llvm_fields_len += 1;
                    }

                    const ty = try o.builder.opaque_type(try o.builder.string(fqn.to_slice(ip)));
                    try o.type_map.put(o.gpa, t.to_intern(), ty);

                    o.builder.named_type_set_body(
                        ty,
                        try o.builder.struct_type(.normal, llvm_fields[0..llvm_fields_len]),
                    );
                    return ty;
                },
                .opaque_type => {
                    const gop = try o.type_map.get_or_put(o.gpa, t.to_intern());
                    if (!gop.found_existing) {
                        const decl = mod.decl_ptr(ip.load_opaque_type(t.to_intern()).decl);
                        const fqn = try decl.fully_qualified_name(mod);
                        gop.value_ptr.* = try o.builder.opaque_type(try o.builder.string(fqn.to_slice(ip)));
                    }
                    return gop.value_ptr.*;
                },
                .enum_type => try o.lower_type(Type.from_interned(ip.load_enum_type(t.to_intern()).tag_ty)),
                .func_type => |func_type| try o.lower_type_fn(func_type),
                .error_set_type, .inferred_error_set_type => try o.error_int_type(),
                // values, not types
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
                // memoization, not types
                .memoized_call,
                => unreachable,
            },
        };
    }

    /// Use this instead of lower_type when you want to handle correctly the case of elem_ty
    /// being a zero bit type, but it should still be lowered as an i8 in such case.
    /// There are other similar cases handled here as well.
    fn lower_ptr_elem_ty(o: *Object, elem_ty: Type) Allocator.Error!Builder.Type {
        const mod = o.module;
        const lower_elem_ty = switch (elem_ty.zig_type_tag(mod)) {
            .Opaque => true,
            .Fn => !mod.type_to_func(elem_ty).?.is_generic,
            .Array => elem_ty.child_type(mod).has_runtime_bits_ignore_comptime(mod),
            else => elem_ty.has_runtime_bits_ignore_comptime(mod),
        };
        return if (lower_elem_ty) try o.lower_type(elem_ty) else .i8;
    }

    fn lower_type_fn(o: *Object, fn_info: InternPool.Key.FuncType) Allocator.Error!Builder.Type {
        const mod = o.module;
        const ip = &mod.intern_pool;
        const target = mod.get_target();
        const ret_ty = try lower_fn_ret_ty(o, fn_info);

        var llvm_params = std.ArrayListUnmanaged(Builder.Type){};
        defer llvm_params.deinit(o.gpa);

        if (first_param_sret(fn_info, mod, target)) {
            try llvm_params.append(o.gpa, .ptr);
        }

        if (Type.from_interned(fn_info.return_type).is_error(mod) and
            mod.comp.config.any_error_tracing)
        {
            const ptr_ty = try mod.single_mut_ptr_type(try o.get_stack_trace_type());
            try llvm_params.append(o.gpa, try o.lower_type(ptr_ty));
        }

        var it = iterate_param_types(o, fn_info);
        while (try it.next()) |lowering| switch (lowering) {
            .no_bits => continue,
            .byval => {
                const param_ty = Type.from_interned(fn_info.param_types.get(ip)[it.zig_index - 1]);
                try llvm_params.append(o.gpa, try o.lower_type(param_ty));
            },
            .byref, .byref_mut => {
                try llvm_params.append(o.gpa, .ptr);
            },
            .abi_sized_int => {
                const param_ty = Type.from_interned(fn_info.param_types.get(ip)[it.zig_index - 1]);
                try llvm_params.append(o.gpa, try o.builder.int_type(
                    @int_cast(param_ty.abi_size(mod) * 8),
                ));
            },
            .slice => {
                const param_ty = Type.from_interned(fn_info.param_types.get(ip)[it.zig_index - 1]);
                try llvm_params.append_slice(o.gpa, &.{
                    try o.builder.ptr_type(to_llvm_address_space(param_ty.ptr_address_space(mod), target)),
                    try o.lower_type(Type.usize),
                });
            },
            .multiple_llvm_types => {
                try llvm_params.append_slice(o.gpa, it.types_buffer[0..it.types_len]);
            },
            .as_u16 => {
                try llvm_params.append(o.gpa, .i16);
            },
            .float_array => |count| {
                const param_ty = Type.from_interned(fn_info.param_types.get(ip)[it.zig_index - 1]);
                const float_ty = try o.lower_type(aarch64_c_abi.get_float_array_type(param_ty, mod).?);
                try llvm_params.append(o.gpa, try o.builder.array_type(count, float_ty));
            },
            .i32_array, .i64_array => |arr_len| {
                try llvm_params.append(o.gpa, try o.builder.array_type(arr_len, switch (lowering) {
                    .i32_array => .i32,
                    .i64_array => .i64,
                    else => unreachable,
                }));
            },
        };

        return o.builder.fn_type(
            ret_ty,
            llvm_params.items,
            if (fn_info.is_var_args) .vararg else .normal,
        );
    }

    fn lower_value_to_int(o: *Object, llvm_int_ty: Builder.Type, arg_val: InternPool.Index) Error!Builder.Constant {
        const mod = o.module;
        const ip = &mod.intern_pool;
        const target = mod.get_target();

        const val = Value.from_interned(arg_val);
        const val_key = ip.index_to_key(val.to_intern());

        if (val.is_undef_deep(mod)) return o.builder.undef_const(llvm_int_ty);

        const ty = Type.from_interned(val_key.type_of());
        switch (val_key) {
            .extern_func => |extern_func| {
                const fn_decl_index = extern_func.decl;
                const function_index = try o.resolve_llvm_function(fn_decl_index);
                const ptr = function_index.ptr_const(&o.builder).global.to_const();
                return o.builder.conv_const(ptr, llvm_int_ty);
            },
            .func => |func| {
                const fn_decl_index = func.owner_decl;
                const function_index = try o.resolve_llvm_function(fn_decl_index);
                const ptr = function_index.ptr_const(&o.builder).global.to_const();
                return o.builder.conv_const(ptr, llvm_int_ty);
            },
            .ptr => return o.builder.conv_const(try o.lower_ptr(arg_val, 0), llvm_int_ty),
            .aggregate => switch (ip.index_to_key(ty.to_intern())) {
                .struct_type => {
                    const struct_type = ip.load_struct_type(ty.to_intern());
                    assert(struct_type.have_layout(ip));
                    assert(struct_type.layout == .@"packed");
                    comptime assert(Type.packed_struct_layout_version == 2);
                    var running_int = try o.builder.int_const(llvm_int_ty, 0);
                    var running_bits: u16 = 0;
                    for (struct_type.field_types.get(ip), 0..) |field_ty, field_index| {
                        if (!Type.from_interned(field_ty).has_runtime_bits_ignore_comptime(mod)) continue;

                        const shift_rhs = try o.builder.int_const(llvm_int_ty, running_bits);
                        const field_val = try o.lower_value_to_int(llvm_int_ty, (try val.field_value(mod, field_index)).to_intern());
                        const shifted = try o.builder.bin_const(.shl, field_val, shift_rhs);

                        running_int = try o.builder.bin_const(.xor, running_int, shifted);

                        const ty_bit_size: u16 = @int_cast(Type.from_interned(field_ty).bit_size(mod));
                        running_bits += ty_bit_size;
                    }
                    return running_int;
                },
                .vector_type => {},
                else => unreachable,
            },
            .un => |un| {
                const layout = ty.union_get_layout(mod);
                if (layout.payload_size == 0) return o.lower_value(un.tag);

                const union_obj = mod.type_to_union(ty).?;
                const container_layout = union_obj.get_layout(ip);

                assert(container_layout == .@"packed");

                var need_unnamed = false;
                if (un.tag == .none) {
                    assert(layout.tag_size == 0);
                    const union_val = try o.lower_value_to_int(llvm_int_ty, un.val);

                    need_unnamed = true;
                    return union_val;
                }
                const field_index = mod.union_tag_field_index(union_obj, Value.from_interned(un.tag)).?;
                const field_ty = Type.from_interned(union_obj.field_types.get(ip)[field_index]);
                if (!field_ty.has_runtime_bits(mod)) return o.builder.int_const(llvm_int_ty, 0);
                return o.lower_value_to_int(llvm_int_ty, un.val);
            },
            .simple_value => |simple_value| switch (simple_value) {
                .false, .true => {},
                else => unreachable,
            },
            .int,
            .float,
            .enum_tag,
            => {},
            .opt => {}, // pointer like optional expected
            else => unreachable,
        }
        const bits = ty.bit_size(mod);
        const bytes: usize = @int_cast(std.mem.align_forward(u64, bits, 8) / 8);

        var stack = std.heap.stack_fallback(32, o.gpa);
        const allocator = stack.get();

        const limbs = try allocator.alloc(
            std.math.big.Limb,
            std.mem.align_forward(usize, bytes, @size_of(std.math.big.Limb)) /
                @size_of(std.math.big.Limb),
        );
        defer allocator.free(limbs);
        @memset(limbs, 0);

        val.write_to_packed_memory(
            ty,
            mod,
            std.mem.slice_as_bytes(limbs)[0..bytes],
            0,
        ) catch unreachable;

        if (builtin.target.cpu.arch.endian() == .little) {
            if (target.cpu.arch.endian() == .big)
                std.mem.reverse(u8, std.mem.slice_as_bytes(limbs)[0..bytes]);
        } else if (target.cpu.arch.endian() == .little) {
            for (limbs) |*limb| {
                limb.* = std.mem.native_to_little(usize, limb.*);
            }
        }

        return o.builder.big_int_const(llvm_int_ty, .{
            .limbs = limbs,
            .positive = true,
        });
    }

    fn lower_value(o: *Object, arg_val: InternPool.Index) Error!Builder.Constant {
        const mod = o.module;
        const ip = &mod.intern_pool;
        const target = mod.get_target();

        const val = Value.from_interned(arg_val);
        const val_key = ip.index_to_key(val.to_intern());

        if (val.is_undef_deep(mod)) {
            return o.builder.undef_const(try o.lower_type(Type.from_interned(val_key.type_of())));
        }

        const ty = Type.from_interned(val_key.type_of());
        return switch (val_key) {
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
                .false => .false,
                .true => .true,
            },
            .variable,
            .enum_literal,
            .empty_enum_value,
            => unreachable, // non-runtime values
            .extern_func => |extern_func| {
                const fn_decl_index = extern_func.decl;
                const function_index = try o.resolve_llvm_function(fn_decl_index);
                return function_index.ptr_const(&o.builder).global.to_const();
            },
            .func => |func| {
                const fn_decl_index = func.owner_decl;
                const function_index = try o.resolve_llvm_function(fn_decl_index);
                return function_index.ptr_const(&o.builder).global.to_const();
            },
            .int => {
                var bigint_space: Value.BigIntSpace = undefined;
                const bigint = val.to_big_int(&bigint_space, mod);
                return lower_big_int(o, ty, bigint);
            },
            .err => |err| {
                const int = try mod.get_error_value(err.name);
                const llvm_int = try o.builder.int_const(try o.error_int_type(), int);
                return llvm_int;
            },
            .error_union => |error_union| {
                const err_val = switch (error_union.val) {
                    .err_name => |err_name| try mod.intern(.{ .err = .{
                        .ty = ty.error_union_set(mod).to_intern(),
                        .name = err_name,
                    } }),
                    .payload => (try mod.int_value(try mod.error_int_type(), 0)).to_intern(),
                };
                const err_int_ty = try mod.error_int_type();
                const payload_type = ty.error_union_payload(mod);
                if (!payload_type.has_runtime_bits_ignore_comptime(mod)) {
                    // We use the error type directly as the type.
                    return o.lower_value(err_val);
                }

                const payload_align = payload_type.abi_alignment(mod);
                const error_align = err_int_ty.abi_alignment(mod);
                const llvm_error_value = try o.lower_value(err_val);
                const llvm_payload_value = try o.lower_value(switch (error_union.val) {
                    .err_name => try mod.intern(.{ .undef = payload_type.to_intern() }),
                    .payload => |payload| payload,
                });

                var fields: [3]Builder.Type = undefined;
                var vals: [3]Builder.Constant = undefined;
                if (error_align.compare(.gt, payload_align)) {
                    vals[0] = llvm_error_value;
                    vals[1] = llvm_payload_value;
                } else {
                    vals[0] = llvm_payload_value;
                    vals[1] = llvm_error_value;
                }
                fields[0] = vals[0].type_of(&o.builder);
                fields[1] = vals[1].type_of(&o.builder);

                const llvm_ty = try o.lower_type(ty);
                const llvm_ty_fields = llvm_ty.struct_fields(&o.builder);
                if (llvm_ty_fields.len > 2) {
                    assert(llvm_ty_fields.len == 3);
                    fields[2] = llvm_ty_fields[2];
                    vals[2] = try o.builder.undef_const(fields[2]);
                }
                return o.builder.struct_const(try o.builder.struct_type(
                    llvm_ty.struct_kind(&o.builder),
                    fields[0..llvm_ty_fields.len],
                ), vals[0..llvm_ty_fields.len]);
            },
            .enum_tag => |enum_tag| o.lower_value(enum_tag.int),
            .float => switch (ty.float_bits(target)) {
                16 => if (backend_supports_f16(target))
                    try o.builder.half_const(val.to_float(f16, mod))
                else
                    try o.builder.int_const(.i16, @as(i16, @bit_cast(val.to_float(f16, mod)))),
                32 => try o.builder.float_const(val.to_float(f32, mod)),
                64 => try o.builder.double_const(val.to_float(f64, mod)),
                80 => if (backend_supports_f80(target))
                    try o.builder.x86_fp80_const(val.to_float(f80, mod))
                else
                    try o.builder.int_const(.i80, @as(i80, @bit_cast(val.to_float(f80, mod)))),
                128 => try o.builder.fp128_const(val.to_float(f128, mod)),
                else => unreachable,
            },
            .ptr => try o.lower_ptr(arg_val, 0),
            .slice => |slice| return o.builder.struct_const(try o.lower_type(ty), &.{
                try o.lower_value(slice.ptr),
                try o.lower_value(slice.len),
            }),
            .opt => |opt| {
                comptime assert(optional_layout_version == 3);
                const payload_ty = ty.optional_child(mod);

                const non_null_bit = try o.builder.int_const(.i8, @int_from_bool(opt.val != .none));
                if (!payload_ty.has_runtime_bits_ignore_comptime(mod)) {
                    return non_null_bit;
                }
                const llvm_ty = try o.lower_type(ty);
                if (ty.optional_repr_is_payload(mod)) return switch (opt.val) {
                    .none => switch (llvm_ty.tag(&o.builder)) {
                        .integer => try o.builder.int_const(llvm_ty, 0),
                        .pointer => try o.builder.null_const(llvm_ty),
                        .structure => try o.builder.zero_init_const(llvm_ty),
                        else => unreachable,
                    },
                    else => |payload| try o.lower_value(payload),
                };
                assert(payload_ty.zig_type_tag(mod) != .Fn);

                var fields: [3]Builder.Type = undefined;
                var vals: [3]Builder.Constant = undefined;
                vals[0] = try o.lower_value(switch (opt.val) {
                    .none => try mod.intern(.{ .undef = payload_ty.to_intern() }),
                    else => |payload| payload,
                });
                vals[1] = non_null_bit;
                fields[0] = vals[0].type_of(&o.builder);
                fields[1] = vals[1].type_of(&o.builder);

                const llvm_ty_fields = llvm_ty.struct_fields(&o.builder);
                if (llvm_ty_fields.len > 2) {
                    assert(llvm_ty_fields.len == 3);
                    fields[2] = llvm_ty_fields[2];
                    vals[2] = try o.builder.undef_const(fields[2]);
                }
                return o.builder.struct_const(try o.builder.struct_type(
                    llvm_ty.struct_kind(&o.builder),
                    fields[0..llvm_ty_fields.len],
                ), vals[0..llvm_ty_fields.len]);
            },
            .aggregate => |aggregate| switch (ip.index_to_key(ty.to_intern())) {
                .array_type => |array_type| switch (aggregate.storage) {
                    .bytes => |bytes| try o.builder.string_const(try o.builder.string(
                        bytes.to_slice(array_type.len_including_sentinel(), ip),
                    )),
                    .elems => |elems| {
                        const array_ty = try o.lower_type(ty);
                        const elem_ty = array_ty.child_type(&o.builder);
                        assert(elems.len == array_ty.aggregate_len(&o.builder));

                        const ExpectedContents = extern struct {
                            vals: [Builder.expected_fields_len]Builder.Constant,
                            fields: [Builder.expected_fields_len]Builder.Type,
                        };
                        var stack align(@max(
                            @alignOf(std.heap.StackFallbackAllocator(0)),
                            @alignOf(ExpectedContents),
                        )) = std.heap.stack_fallback(@size_of(ExpectedContents), o.gpa);
                        const allocator = stack.get();
                        const vals = try allocator.alloc(Builder.Constant, elems.len);
                        defer allocator.free(vals);
                        const fields = try allocator.alloc(Builder.Type, elems.len);
                        defer allocator.free(fields);

                        var need_unnamed = false;
                        for (vals, fields, elems) |*result_val, *result_field, elem| {
                            result_val.* = try o.lower_value(elem);
                            result_field.* = result_val.type_of(&o.builder);
                            if (result_field.* != elem_ty) need_unnamed = true;
                        }
                        return if (need_unnamed) try o.builder.struct_const(
                            try o.builder.struct_type(.normal, fields),
                            vals,
                        ) else try o.builder.array_const(array_ty, vals);
                    },
                    .repeated_elem => |elem| {
                        const len: usize = @int_cast(array_type.len);
                        const len_including_sentinel: usize = @int_cast(array_type.len_including_sentinel());
                        const array_ty = try o.lower_type(ty);
                        const elem_ty = array_ty.child_type(&o.builder);

                        const ExpectedContents = extern struct {
                            vals: [Builder.expected_fields_len]Builder.Constant,
                            fields: [Builder.expected_fields_len]Builder.Type,
                        };
                        var stack align(@max(
                            @alignOf(std.heap.StackFallbackAllocator(0)),
                            @alignOf(ExpectedContents),
                        )) = std.heap.stack_fallback(@size_of(ExpectedContents), o.gpa);
                        const allocator = stack.get();
                        const vals = try allocator.alloc(Builder.Constant, len_including_sentinel);
                        defer allocator.free(vals);
                        const fields = try allocator.alloc(Builder.Type, len_including_sentinel);
                        defer allocator.free(fields);

                        var need_unnamed = false;
                        @memset(vals[0..len], try o.lower_value(elem));
                        @memset(fields[0..len], vals[0].type_of(&o.builder));
                        if (fields[0] != elem_ty) need_unnamed = true;

                        if (array_type.sentinel != .none) {
                            vals[len] = try o.lower_value(array_type.sentinel);
                            fields[len] = vals[len].type_of(&o.builder);
                            if (fields[len] != elem_ty) need_unnamed = true;
                        }

                        return if (need_unnamed) try o.builder.struct_const(
                            try o.builder.struct_type(.@"packed", fields),
                            vals,
                        ) else try o.builder.array_const(array_ty, vals);
                    },
                },
                .vector_type => |vector_type| {
                    const vector_ty = try o.lower_type(ty);
                    switch (aggregate.storage) {
                        .bytes, .elems => {
                            const ExpectedContents = [Builder.expected_fields_len]Builder.Constant;
                            var stack align(@max(
                                @alignOf(std.heap.StackFallbackAllocator(0)),
                                @alignOf(ExpectedContents),
                            )) = std.heap.stack_fallback(@size_of(ExpectedContents), o.gpa);
                            const allocator = stack.get();
                            const vals = try allocator.alloc(Builder.Constant, vector_type.len);
                            defer allocator.free(vals);

                            switch (aggregate.storage) {
                                .bytes => |bytes| for (vals, bytes.to_slice(vector_type.len, ip)) |*result_val, byte| {
                                    result_val.* = try o.builder.int_const(.i8, byte);
                                },
                                .elems => |elems| for (vals, elems) |*result_val, elem| {
                                    result_val.* = try o.lower_value(elem);
                                },
                                .repeated_elem => unreachable,
                            }
                            return o.builder.vector_const(vector_ty, vals);
                        },
                        .repeated_elem => |elem| return o.builder.splat_const(
                            vector_ty,
                            try o.lower_value(elem),
                        ),
                    }
                },
                .anon_struct_type => |tuple| {
                    const struct_ty = try o.lower_type(ty);
                    const llvm_len = struct_ty.aggregate_len(&o.builder);

                    const ExpectedContents = extern struct {
                        vals: [Builder.expected_fields_len]Builder.Constant,
                        fields: [Builder.expected_fields_len]Builder.Type,
                    };
                    var stack align(@max(
                        @alignOf(std.heap.StackFallbackAllocator(0)),
                        @alignOf(ExpectedContents),
                    )) = std.heap.stack_fallback(@size_of(ExpectedContents), o.gpa);
                    const allocator = stack.get();
                    const vals = try allocator.alloc(Builder.Constant, llvm_len);
                    defer allocator.free(vals);
                    const fields = try allocator.alloc(Builder.Type, llvm_len);
                    defer allocator.free(fields);

                    comptime assert(struct_layout_version == 2);
                    var llvm_index: usize = 0;
                    var offset: u64 = 0;
                    var big_align: InternPool.Alignment = .none;
                    var need_unnamed = false;
                    for (
                        tuple.types.get(ip),
                        tuple.values.get(ip),
                        0..,
                    ) |field_ty, field_val, field_index| {
                        if (field_val != .none) continue;
                        if (!Type.from_interned(field_ty).has_runtime_bits_ignore_comptime(mod)) continue;

                        const field_align = Type.from_interned(field_ty).abi_alignment(mod);
                        big_align = big_align.max(field_align);
                        const prev_offset = offset;
                        offset = field_align.forward(offset);

                        const padding_len = offset - prev_offset;
                        if (padding_len > 0) {
                            // TODO make this and all other padding elsewhere in debug
                            // builds be 0xaa not undef.
                            fields[llvm_index] = try o.builder.array_type(padding_len, .i8);
                            vals[llvm_index] = try o.builder.undef_const(fields[llvm_index]);
                            assert(fields[llvm_index] == struct_ty.struct_fields(&o.builder)[llvm_index]);
                            llvm_index += 1;
                        }

                        vals[llvm_index] =
                            try o.lower_value((try val.field_value(mod, field_index)).to_intern());
                        fields[llvm_index] = vals[llvm_index].type_of(&o.builder);
                        if (fields[llvm_index] != struct_ty.struct_fields(&o.builder)[llvm_index])
                            need_unnamed = true;
                        llvm_index += 1;

                        offset += Type.from_interned(field_ty).abi_size(mod);
                    }
                    {
                        const prev_offset = offset;
                        offset = big_align.forward(offset);
                        const padding_len = offset - prev_offset;
                        if (padding_len > 0) {
                            fields[llvm_index] = try o.builder.array_type(padding_len, .i8);
                            vals[llvm_index] = try o.builder.undef_const(fields[llvm_index]);
                            assert(fields[llvm_index] == struct_ty.struct_fields(&o.builder)[llvm_index]);
                            llvm_index += 1;
                        }
                    }
                    assert(llvm_index == llvm_len);

                    return o.builder.struct_const(if (need_unnamed)
                        try o.builder.struct_type(struct_ty.struct_kind(&o.builder), fields)
                    else
                        struct_ty, vals);
                },
                .struct_type => {
                    const struct_type = ip.load_struct_type(ty.to_intern());
                    assert(struct_type.have_layout(ip));
                    const struct_ty = try o.lower_type(ty);
                    if (struct_type.layout == .@"packed") {
                        comptime assert(Type.packed_struct_layout_version == 2);

                        const bits = ty.bit_size(mod);
                        const llvm_int_ty = try o.builder.int_type(@int_cast(bits));

                        return o.lower_value_to_int(llvm_int_ty, arg_val);
                    }
                    const llvm_len = struct_ty.aggregate_len(&o.builder);

                    const ExpectedContents = extern struct {
                        vals: [Builder.expected_fields_len]Builder.Constant,
                        fields: [Builder.expected_fields_len]Builder.Type,
                    };
                    var stack align(@max(
                        @alignOf(std.heap.StackFallbackAllocator(0)),
                        @alignOf(ExpectedContents),
                    )) = std.heap.stack_fallback(@size_of(ExpectedContents), o.gpa);
                    const allocator = stack.get();
                    const vals = try allocator.alloc(Builder.Constant, llvm_len);
                    defer allocator.free(vals);
                    const fields = try allocator.alloc(Builder.Type, llvm_len);
                    defer allocator.free(fields);

                    comptime assert(struct_layout_version == 2);
                    var llvm_index: usize = 0;
                    var offset: u64 = 0;
                    var big_align: InternPool.Alignment = .@"1";
                    var need_unnamed = false;
                    var field_it = struct_type.iterate_runtime_order(ip);
                    while (field_it.next()) |field_index| {
                        const field_ty = Type.from_interned(struct_type.field_types.get(ip)[field_index]);
                        const field_align = mod.struct_field_alignment(
                            struct_type.field_align(ip, field_index),
                            field_ty,
                            struct_type.layout,
                        );
                        big_align = big_align.max(field_align);
                        const prev_offset = offset;
                        offset = field_align.forward(offset);

                        const padding_len = offset - prev_offset;
                        if (padding_len > 0) {
                            // TODO make this and all other padding elsewhere in debug
                            // builds be 0xaa not undef.
                            fields[llvm_index] = try o.builder.array_type(padding_len, .i8);
                            vals[llvm_index] = try o.builder.undef_const(fields[llvm_index]);
                            assert(fields[llvm_index] ==
                                struct_ty.struct_fields(&o.builder)[llvm_index]);
                            llvm_index += 1;
                        }

                        if (!field_ty.has_runtime_bits_ignore_comptime(mod)) {
                            // This is a zero-bit field - we only needed it for the alignment.
                            continue;
                        }

                        vals[llvm_index] = try o.lower_value(
                            (try val.field_value(mod, field_index)).to_intern(),
                        );
                        fields[llvm_index] = vals[llvm_index].type_of(&o.builder);
                        if (fields[llvm_index] != struct_ty.struct_fields(&o.builder)[llvm_index])
                            need_unnamed = true;
                        llvm_index += 1;

                        offset += field_ty.abi_size(mod);
                    }
                    {
                        const prev_offset = offset;
                        offset = big_align.forward(offset);
                        const padding_len = offset - prev_offset;
                        if (padding_len > 0) {
                            fields[llvm_index] = try o.builder.array_type(padding_len, .i8);
                            vals[llvm_index] = try o.builder.undef_const(fields[llvm_index]);
                            assert(fields[llvm_index] == struct_ty.struct_fields(&o.builder)[llvm_index]);
                            llvm_index += 1;
                        }
                    }
                    assert(llvm_index == llvm_len);

                    return o.builder.struct_const(if (need_unnamed)
                        try o.builder.struct_type(struct_ty.struct_kind(&o.builder), fields)
                    else
                        struct_ty, vals);
                },
                else => unreachable,
            },
            .un => |un| {
                const union_ty = try o.lower_type(ty);
                const layout = ty.union_get_layout(mod);
                if (layout.payload_size == 0) return o.lower_value(un.tag);

                const union_obj = mod.type_to_union(ty).?;
                const container_layout = union_obj.get_layout(ip);

                var need_unnamed = false;
                const payload = if (un.tag != .none) p: {
                    const field_index = mod.union_tag_field_index(union_obj, Value.from_interned(un.tag)).?;
                    const field_ty = Type.from_interned(union_obj.field_types.get(ip)[field_index]);
                    if (container_layout == .@"packed") {
                        if (!field_ty.has_runtime_bits(mod)) return o.builder.int_const(union_ty, 0);
                        const bits = ty.bit_size(mod);
                        const llvm_int_ty = try o.builder.int_type(@int_cast(bits));

                        return o.lower_value_to_int(llvm_int_ty, arg_val);
                    }

                    // Sometimes we must make an unnamed struct because LLVM does
                    // not support bitcasting our payload struct to the true union payload type.
                    // Instead we use an unnamed struct and every reference to the global
                    // must pointer cast to the expected type before accessing the union.
                    need_unnamed = layout.most_aligned_field != field_index;

                    if (!field_ty.has_runtime_bits_ignore_comptime(mod)) {
                        const padding_len = layout.payload_size;
                        break :p try o.builder.undef_const(try o.builder.array_type(padding_len, .i8));
                    }
                    const payload = try o.lower_value(un.val);
                    const payload_ty = payload.type_of(&o.builder);
                    if (payload_ty != union_ty.struct_fields(&o.builder)[
                        @int_from_bool(layout.tag_align.compare(.gte, layout.payload_align))
                    ]) need_unnamed = true;
                    const field_size = field_ty.abi_size(mod);
                    if (field_size == layout.payload_size) break :p payload;
                    const padding_len = layout.payload_size - field_size;
                    const padding_ty = try o.builder.array_type(padding_len, .i8);
                    break :p try o.builder.struct_const(
                        try o.builder.struct_type(.@"packed", &.{ payload_ty, padding_ty }),
                        &.{ payload, try o.builder.undef_const(padding_ty) },
                    );
                } else p: {
                    assert(layout.tag_size == 0);
                    if (container_layout == .@"packed") {
                        const bits = ty.bit_size(mod);
                        const llvm_int_ty = try o.builder.int_type(@int_cast(bits));

                        return o.lower_value_to_int(llvm_int_ty, arg_val);
                    }

                    const union_val = try o.lower_value(un.val);
                    need_unnamed = true;
                    break :p union_val;
                };

                const payload_ty = payload.type_of(&o.builder);
                if (layout.tag_size == 0) return o.builder.struct_const(if (need_unnamed)
                    try o.builder.struct_type(union_ty.struct_kind(&o.builder), &.{payload_ty})
                else
                    union_ty, &.{payload});
                const tag = try o.lower_value(un.tag);
                const tag_ty = tag.type_of(&o.builder);
                var fields: [3]Builder.Type = undefined;
                var vals: [3]Builder.Constant = undefined;
                var len: usize = 2;
                if (layout.tag_align.compare(.gte, layout.payload_align)) {
                    fields = .{ tag_ty, payload_ty, undefined };
                    vals = .{ tag, payload, undefined };
                } else {
                    fields = .{ payload_ty, tag_ty, undefined };
                    vals = .{ payload, tag, undefined };
                }
                if (layout.padding != 0) {
                    fields[2] = try o.builder.array_type(layout.padding, .i8);
                    vals[2] = try o.builder.undef_const(fields[2]);
                    len = 3;
                }
                return o.builder.struct_const(if (need_unnamed)
                    try o.builder.struct_type(union_ty.struct_kind(&o.builder), fields[0..len])
                else
                    union_ty, vals[0..len]);
            },
            .memoized_call => unreachable,
        };
    }

    fn lower_big_int(
        o: *Object,
        ty: Type,
        bigint: std.math.big.int.Const,
    ) Allocator.Error!Builder.Constant {
        const mod = o.module;
        return o.builder.big_int_const(try o.builder.int_type(ty.int_info(mod).bits), bigint);
    }

    fn lower_ptr(
        o: *Object,
        ptr_val: InternPool.Index,
        prev_offset: u64,
    ) Error!Builder.Constant {
        const zcu = o.module;
        const ptr = zcu.intern_pool.index_to_key(ptr_val).ptr;
        const offset: u64 = prev_offset + ptr.byte_offset;
        return switch (ptr.base_addr) {
            .decl => |decl| {
                const base_ptr = try o.lower_decl_ref_value(decl);
                return o.builder.gep_const(.inbounds, .i8, base_ptr, null, &.{
                    try o.builder.int_const(.i64, offset),
                });
            },
            .anon_decl => |ad| {
                const base_ptr = try o.lower_anon_decl_ref(ad);
                return o.builder.gep_const(.inbounds, .i8, base_ptr, null, &.{
                    try o.builder.int_const(.i64, offset),
                });
            },
            .int => try o.builder.cast_const(
                .inttoptr,
                try o.builder.int_const(try o.lower_type(Type.usize), offset),
                try o.lower_type(Type.from_interned(ptr.ty)),
            ),
            .eu_payload => |eu_ptr| try o.lower_ptr(
                eu_ptr,
                offset + @import("../codegen.zig").err_union_payload_offset(
                    Value.from_interned(eu_ptr).type_of(zcu).child_type(zcu),
                    zcu,
                ),
            ),
            .opt_payload => |opt_ptr| try o.lower_ptr(opt_ptr, offset),
            .field => |field| {
                const agg_ty = Value.from_interned(field.base).type_of(zcu).child_type(zcu);
                const field_off: u64 = switch (agg_ty.zig_type_tag(zcu)) {
                    .Pointer => off: {
                        assert(agg_ty.is_slice(zcu));
                        break :off switch (field.index) {
                            Value.slice_ptr_index => 0,
                            Value.slice_len_index => @div_exact(zcu.get_target().ptr_bit_width(), 8),
                            else => unreachable,
                        };
                    },
                    .Struct, .Union => switch (agg_ty.container_layout(zcu)) {
                        .auto => agg_ty.struct_field_offset(@int_cast(field.index), zcu),
                        .@"extern", .@"packed" => unreachable,
                    },
                    else => unreachable,
                };
                return o.lower_ptr(field.base, offset + field_off);
            },
            .arr_elem, .comptime_field, .comptime_alloc => unreachable,
        };
    }

    /// This logic is very similar to `lower_decl_ref_value` but for anonymous declarations.
    /// Maybe the logic could be unified.
    fn lower_anon_decl_ref(
        o: *Object,
        anon_decl: InternPool.Key.Ptr.BaseAddr.AnonDecl,
    ) Error!Builder.Constant {
        const mod = o.module;
        const ip = &mod.intern_pool;
        const decl_val = anon_decl.val;
        const decl_ty = Type.from_interned(ip.type_of(decl_val));
        const target = mod.get_target();

        if (Value.from_interned(decl_val).get_function(mod)) |func| {
            _ = func;
            @panic("TODO");
        } else if (Value.from_interned(decl_val).get_extern_func(mod)) |func| {
            _ = func;
            @panic("TODO");
        }

        const ptr_ty = Type.from_interned(anon_decl.orig_ty);

        const is_fn_body = decl_ty.zig_type_tag(mod) == .Fn;
        if ((!is_fn_body and !decl_ty.has_runtime_bits(mod)) or
            (is_fn_body and mod.type_to_func(decl_ty).?.is_generic)) return o.lower_ptr_to_void(ptr_ty);

        if (is_fn_body)
            @panic("TODO");

        const llvm_addr_space = to_llvm_address_space(ptr_ty.ptr_address_space(mod), target);
        const alignment = ptr_ty.ptr_alignment(mod);
        const llvm_global = (try o.resolve_global_anon_decl(decl_val, llvm_addr_space, alignment)).ptr_const(&o.builder).global;

        const llvm_val = try o.builder.conv_const(
            llvm_global.to_const(),
            try o.builder.ptr_type(llvm_addr_space),
        );

        return o.builder.conv_const(llvm_val, try o.lower_type(ptr_ty));
    }

    fn lower_decl_ref_value(o: *Object, decl_index: InternPool.DeclIndex) Allocator.Error!Builder.Constant {
        const mod = o.module;

        // In the case of something like:
        // fn foo() void {}
        // const bar = foo;
        // ... &bar;
        // `bar` is just an alias and we actually want to lower a reference to `foo`.
        const decl = mod.decl_ptr(decl_index);
        if (decl.val.get_function(mod)) |func| {
            if (func.owner_decl != decl_index) {
                return o.lower_decl_ref_value(func.owner_decl);
            }
        } else if (decl.val.get_extern_func(mod)) |func| {
            if (func.decl != decl_index) {
                return o.lower_decl_ref_value(func.decl);
            }
        }

        const decl_ty = decl.type_of(mod);
        const ptr_ty = try decl.decl_ptr_type(mod);

        const is_fn_body = decl_ty.zig_type_tag(mod) == .Fn;
        if ((!is_fn_body and !decl_ty.has_runtime_bits(mod)) or
            (is_fn_body and mod.type_to_func(decl_ty).?.is_generic))
        {
            return o.lower_ptr_to_void(ptr_ty);
        }

        const llvm_global = if (is_fn_body)
            (try o.resolve_llvm_function(decl_index)).ptr_const(&o.builder).global
        else
            (try o.resolve_global_decl(decl_index)).ptr_const(&o.builder).global;

        const llvm_val = try o.builder.conv_const(
            llvm_global.to_const(),
            try o.builder.ptr_type(to_llvm_address_space(decl.@"addrspace", mod.get_target())),
        );

        return o.builder.conv_const(llvm_val, try o.lower_type(ptr_ty));
    }

    fn lower_ptr_to_void(o: *Object, ptr_ty: Type) Allocator.Error!Builder.Constant {
        const mod = o.module;
        // Even though we are pointing at something which has zero bits (e.g. `void`),
        // Pointers are defined to have bits. So we must return something here.
        // The value cannot be undefined, because we use the `nonnull` annotation
        // for non-optional pointers. We also need to respect the alignment, even though
        // the address will never be dereferenced.
        const int: u64 = ptr_ty.ptr_info(mod).flags.alignment.to_byte_units() orelse
            // Note that these 0xaa values are appropriate even in release-optimized builds
            // because we need a well-defined value that is not null, and LLVM does not
            // have an "undef_but_not_null" attribute. As an example, if this `alloc` AIR
            // instruction is followed by a `wrap_optional`, it will return this value
            // verbatim, and the result should test as non-null.
            switch (mod.get_target().ptr_bit_width()) {
            16 => 0xaaaa,
            32 => 0xaaaaaaaa,
            64 => 0xaaaaaaaa_aaaaaaaa,
            else => unreachable,
        };
        const llvm_usize = try o.lower_type(Type.usize);
        const llvm_ptr_ty = try o.lower_type(ptr_ty);
        return o.builder.cast_const(.inttoptr, try o.builder.int_const(llvm_usize, int), llvm_ptr_ty);
    }

    /// If the operand type of an atomic operation is not byte sized we need to
    /// widen it before using it and then truncate the result.
    /// RMW exchange of floating-point values is bitcasted to same-sized integer
    /// types to work around a LLVM deficiency when targeting ARM/AArch64.
    fn get_atomic_abi_type(o: *Object, ty: Type, is_rmw_xchg: bool) Allocator.Error!Builder.Type {
        const mod = o.module;
        const int_ty = switch (ty.zig_type_tag(mod)) {
            .Int => ty,
            .Enum => ty.int_tag_type(mod),
            .Float => {
                if (!is_rmw_xchg) return .none;
                return o.builder.int_type(@int_cast(ty.abi_size(mod) * 8));
            },
            .Bool => return .i8,
            else => return .none,
        };
        const bit_count = int_ty.int_info(mod).bits;
        if (!std.math.is_power_of_two(bit_count) or (bit_count % 8) != 0) {
            return o.builder.int_type(@int_cast(int_ty.abi_size(mod) * 8));
        } else {
            return .none;
        }
    }

    fn add_by_val_param_attrs(
        o: *Object,
        attributes: *Builder.FunctionAttributes.Wip,
        param_ty: Type,
        param_index: u32,
        fn_info: InternPool.Key.FuncType,
        llvm_arg_i: u32,
    ) Allocator.Error!void {
        const mod = o.module;
        if (param_ty.is_ptr_at_runtime(mod)) {
            const ptr_info = param_ty.ptr_info(mod);
            if (math.cast(u5, param_index)) |i| {
                if (@as(u1, @truncate(fn_info.noalias_bits >> i)) != 0) {
                    try attributes.add_param_attr(llvm_arg_i, .@"noalias", &o.builder);
                }
            }
            if (!param_ty.is_ptr_like_optional(mod) and !ptr_info.flags.is_allowzero) {
                try attributes.add_param_attr(llvm_arg_i, .nonnull, &o.builder);
            }
            if (fn_info.cc == .Interrupt) {
                const child_type = try lower_type(o, Type.from_interned(ptr_info.child));
                try attributes.add_param_attr(llvm_arg_i, .{ .byval = child_type }, &o.builder);
            }
            if (ptr_info.flags.is_const) {
                try attributes.add_param_attr(llvm_arg_i, .readonly, &o.builder);
            }
            const elem_align = if (ptr_info.flags.alignment != .none)
                ptr_info.flags.alignment
            else
                Type.from_interned(ptr_info.child).abi_alignment(mod).max(.@"1");
            try attributes.add_param_attr(llvm_arg_i, .{ .@"align" = elem_align.to_llvm() }, &o.builder);
        } else if (cc_abi_promote_int(fn_info.cc, mod, param_ty)) |s| switch (s) {
            .signed => try attributes.add_param_attr(llvm_arg_i, .signext, &o.builder),
            .unsigned => try attributes.add_param_attr(llvm_arg_i, .zeroext, &o.builder),
        };
    }

    fn add_by_ref_param_attrs(
        o: *Object,
        attributes: *Builder.FunctionAttributes.Wip,
        llvm_arg_i: u32,
        alignment: Builder.Alignment,
        byval: bool,
        param_llvm_ty: Builder.Type,
    ) Allocator.Error!void {
        try attributes.add_param_attr(llvm_arg_i, .nonnull, &o.builder);
        try attributes.add_param_attr(llvm_arg_i, .readonly, &o.builder);
        try attributes.add_param_attr(llvm_arg_i, .{ .@"align" = alignment }, &o.builder);
        if (byval) try attributes.add_param_attr(llvm_arg_i, .{ .byval = param_llvm_ty }, &o.builder);
    }

    fn llvm_field_index(o: *Object, struct_ty: Type, field_index: usize) ?c_uint {
        return o.struct_field_map.get(.{
            .struct_ty = struct_ty.to_intern(),
            .field_index = @int_cast(field_index),
        });
    }

    fn get_cmp_lt_errors_len_function(o: *Object) !Builder.Function.Index {
        const name = try o.builder.strtab_string(lt_errors_fn_name);
        if (o.builder.get_global(name)) |llvm_fn| return llvm_fn.ptr_const(&o.builder).kind.function;

        const zcu = o.module;
        const target = zcu.root_mod.resolved_target.result;
        const function_index = try o.builder.add_function(
            try o.builder.fn_type(.i1, &.{try o.error_int_type()}, .normal),
            name,
            to_llvm_address_space(.generic, target),
        );

        var attributes: Builder.FunctionAttributes.Wip = .{};
        defer attributes.deinit(&o.builder);
        try o.add_common_fn_attributes(&attributes, zcu.root_mod);

        function_index.set_linkage(.internal, &o.builder);
        function_index.set_call_conv(.fastcc, &o.builder);
        function_index.set_attributes(try attributes.finish(&o.builder), &o.builder);
        return function_index;
    }

    fn get_enum_tag_name_function(o: *Object, enum_ty: Type) !Builder.Function.Index {
        const zcu = o.module;
        const ip = &zcu.intern_pool;
        const enum_type = ip.load_enum_type(enum_ty.to_intern());

        // TODO: detect when the type changes and re-emit this function.
        const gop = try o.decl_map.get_or_put(o.gpa, enum_type.decl);
        if (gop.found_existing) return gop.value_ptr.ptr_const(&o.builder).kind.function;
        errdefer assert(o.decl_map.remove(enum_type.decl));

        const usize_ty = try o.lower_type(Type.usize);
        const ret_ty = try o.lower_type(Type.slice_const_u8_sentinel_0);
        const fqn = try zcu.decl_ptr(enum_type.decl).fully_qualified_name(zcu);
        const target = zcu.root_mod.resolved_target.result;
        const function_index = try o.builder.add_function(
            try o.builder.fn_type(ret_ty, &.{try o.lower_type(Type.from_interned(enum_type.tag_ty))}, .normal),
            try o.builder.strtab_string_fmt("__zig_tag_name_{}", .{fqn.fmt(ip)}),
            to_llvm_address_space(.generic, target),
        );

        var attributes: Builder.FunctionAttributes.Wip = .{};
        defer attributes.deinit(&o.builder);
        try o.add_common_fn_attributes(&attributes, zcu.root_mod);

        function_index.set_linkage(.internal, &o.builder);
        function_index.set_call_conv(.fastcc, &o.builder);
        function_index.set_attributes(try attributes.finish(&o.builder), &o.builder);
        gop.value_ptr.* = function_index.ptr_const(&o.builder).global;

        var wip = try Builder.WipFunction.init(&o.builder, .{
            .function = function_index,
            .strip = true,
        });
        defer wip.deinit();
        wip.cursor = .{ .block = try wip.block(0, "Entry") };

        const bad_value_block = try wip.block(1, "BadValue");
        const tag_int_value = wip.arg(0);
        var wip_switch =
            try wip.@"switch"(tag_int_value, bad_value_block, @int_cast(enum_type.names.len));
        defer wip_switch.finish(&wip);

        for (0..enum_type.names.len) |field_index| {
            const name = try o.builder.string_null(enum_type.names.get(ip)[field_index].to_slice(ip));
            const name_init = try o.builder.string_const(name);
            const name_variable_index =
                try o.builder.add_variable(.empty, name_init.type_of(&o.builder), .default);
            try name_variable_index.set_initializer(name_init, &o.builder);
            name_variable_index.set_linkage(.private, &o.builder);
            name_variable_index.set_mutability(.constant, &o.builder);
            name_variable_index.set_unnamed_addr(.unnamed_addr, &o.builder);
            name_variable_index.set_alignment(comptime Builder.Alignment.from_byte_units(1), &o.builder);

            const name_val = try o.builder.struct_value(ret_ty, &.{
                name_variable_index.to_const(&o.builder),
                try o.builder.int_const(usize_ty, name.slice(&o.builder).?.len - 1),
            });

            const return_block = try wip.block(1, "Name");
            const this_tag_int_value = try o.lower_value(
                (try zcu.enum_value_field_index(enum_ty, @int_cast(field_index))).to_intern(),
            );
            try wip_switch.add_case(this_tag_int_value, return_block, &wip);

            wip.cursor = .{ .block = return_block };
            _ = try wip.ret(name_val);
        }

        wip.cursor = .{ .block = bad_value_block };
        _ = try wip.@"unreachable"();

        try wip.finish();
        return function_index;
    }
};

pub const DeclGen = struct {
    object: *Object,
    decl: *Module.Decl,
    decl_index: InternPool.DeclIndex,
    err_msg: ?*Module.ErrorMsg,

    fn owner_module(dg: DeclGen) *Package.Module {
        const o = dg.object;
        const zcu = o.module;
        const namespace = zcu.namespace_ptr(dg.decl.src_namespace);
        return namespace.file_scope.mod;
    }

    fn todo(dg: *DeclGen, comptime format: []const u8, args: anytype) Error {
        @setCold(true);
        assert(dg.err_msg == null);
        const o = dg.object;
        const gpa = o.gpa;
        const mod = o.module;
        const src_loc = dg.decl.src_loc(mod);
        dg.err_msg = try Module.ErrorMsg.create(gpa, src_loc, "TODO (LLVM): " ++ format, args);
        return error.CodegenFail;
    }

    fn gen_decl(dg: *DeclGen) !void {
        const o = dg.object;
        const zcu = o.module;
        const ip = &zcu.intern_pool;
        const decl = dg.decl;
        const decl_index = dg.decl_index;
        assert(decl.has_tv);

        if (decl.val.get_extern_func(zcu)) |extern_func| {
            _ = try o.resolve_llvm_function(extern_func.decl);
        } else {
            const variable_index = try o.resolve_global_decl(decl_index);
            variable_index.set_alignment(
                decl.get_alignment(zcu).to_llvm(),
                &o.builder,
            );
            if (decl.@"linksection".to_slice(ip)) |section|
                variable_index.set_section(try o.builder.string(section), &o.builder);
            assert(decl.has_tv);
            const init_val = if (decl.val.get_variable(zcu)) |decl_var| decl_var.init else init_val: {
                variable_index.set_mutability(.constant, &o.builder);
                break :init_val decl.val.to_intern();
            };
            try variable_index.set_initializer(switch (init_val) {
                .none => .no_init,
                else => try o.lower_value(init_val),
            }, &o.builder);

            const line_number = decl.src_line + 1;
            const is_internal_linkage = !o.module.decl_exports.contains(decl_index);

            const namespace = zcu.namespace_ptr(decl.src_namespace);
            const owner_mod = namespace.file_scope.mod;

            if (owner_mod.strip) return;

            const debug_file = try o.get_debug_file(namespace.file_scope);

            const debug_global_var = try o.builder.debug_global_var(
                try o.builder.metadata_string(decl.name.to_slice(ip)), // Name
                try o.builder.metadata_string_from_strtab_string(variable_index.name(&o.builder)), // Linkage name
                debug_file, // File
                debug_file, // Scope
                line_number,
                try o.lower_debug_type(decl.type_of(zcu)),
                variable_index,
                .{ .local = is_internal_linkage },
            );

            const debug_expression = try o.builder.debug_expression(&.{});

            const debug_global_var_expression = try o.builder.debug_global_var_expression(
                debug_global_var,
                debug_expression,
            );

            variable_index.set_global_variable_expression(debug_global_var_expression, &o.builder);
            try o.debug_globals.append(o.gpa, debug_global_var_expression);
        }
    }
};

pub const FuncGen = struct {
    gpa: Allocator,
    dg: *DeclGen,
    air: Air,
    liveness: Liveness,
    wip: Builder.WipFunction,

    file: Builder.Metadata,
    scope: Builder.Metadata,

    inlined: Builder.DebugLocation = .no_location,

    base_line: u32,
    prev_dbg_line: c_uint,
    prev_dbg_column: c_uint,

    /// This stores the LLVM values used in a function, such that they can be referred to
    /// in other instructions. This table is cleared before every function is generated.
    func_inst_table: std.AutoHashMapUnmanaged(Air.Inst.Ref, Builder.Value),

    /// If the return type is sret, this is the result pointer. Otherwise null.
    /// Note that this can disagree with is_by_ref for the return type in the case
    /// of C ABI functions.
    ret_ptr: Builder.Value,
    /// Any function that needs to perform Valgrind client requests needs an array alloca
    /// instruction, however a maximum of one per function is needed.
    valgrind_client_request_array: Builder.Value = .none,
    /// These fields are used to refer to the LLVM value of the function parameters
    /// in an Arg instruction.
    /// This list may be shorter than the list according to the zig type system;
    /// it omits 0-bit types. If the function uses sret as the first parameter,
    /// this slice does not include it.
    args: []const Builder.Value,
    arg_index: usize,

    err_ret_trace: Builder.Value = .none,

    /// This data structure is used to implement breaking to blocks.
    blocks: std.AutoHashMapUnmanaged(Air.Inst.Index, struct {
        parent_bb: Builder.Function.Block.Index,
        breaks: *BreakList,
    }),

    sync_scope: Builder.SyncScope,

    const BreakList = union {
        list: std.MultiArrayList(struct {
            bb: Builder.Function.Block.Index,
            val: Builder.Value,
        }),
        len: usize,
    };

    fn deinit(self: *FuncGen) void {
        self.wip.deinit();
        self.func_inst_table.deinit(self.gpa);
        self.blocks.deinit(self.gpa);
    }

    fn todo(self: *FuncGen, comptime format: []const u8, args: anytype) Error {
        @setCold(true);
        return self.dg.todo(format, args);
    }

    fn resolve_inst(self: *FuncGen, inst: Air.Inst.Ref) !Builder.Value {
        const gpa = self.gpa;
        const gop = try self.func_inst_table.get_or_put(gpa, inst);
        if (gop.found_existing) return gop.value_ptr.*;

        const o = self.dg.object;
        const mod = o.module;
        const llvm_val = try self.resolve_value((try self.air.value(inst, mod)).?);
        gop.value_ptr.* = llvm_val.to_value();
        return llvm_val.to_value();
    }

    fn resolve_value(self: *FuncGen, val: Value) Error!Builder.Constant {
        const o = self.dg.object;
        const mod = o.module;
        const ty = val.type_of(mod);
        const llvm_val = try o.lower_value(val.to_intern());
        if (!is_by_ref(ty, mod)) return llvm_val;

        // We have an LLVM value but we need to create a global constant and
        // set the value as its initializer, and then return a pointer to the global.
        const target = mod.get_target();
        const variable_index = try o.builder.add_variable(
            .empty,
            llvm_val.type_of(&o.builder),
            to_llvm_global_address_space(.generic, target),
        );
        try variable_index.set_initializer(llvm_val, &o.builder);
        variable_index.set_linkage(.private, &o.builder);
        variable_index.set_mutability(.constant, &o.builder);
        variable_index.set_unnamed_addr(.unnamed_addr, &o.builder);
        variable_index.set_alignment(ty.abi_alignment(mod).to_llvm(), &o.builder);
        return o.builder.conv_const(
            variable_index.to_const(&o.builder),
            try o.builder.ptr_type(to_llvm_address_space(.generic, target)),
        );
    }

    fn resolve_null_opt_usize(self: *FuncGen) Error!Builder.Constant {
        const o = self.dg.object;
        const mod = o.module;
        if (o.null_opt_usize == .no_init) {
            o.null_opt_usize = try self.resolve_value(Value.from_interned(try mod.intern(.{ .opt = .{
                .ty = try mod.intern(.{ .opt_type = .usize_type }),
                .val = .none,
            } })));
        }
        return o.null_opt_usize;
    }

    fn gen_body(self: *FuncGen, body: []const Air.Inst.Index) Error!void {
        const o = self.dg.object;
        const mod = o.module;
        const ip = &mod.intern_pool;
        const air_tags = self.air.instructions.items(.tag);
        for (body, 0..) |inst, i| {
            if (self.liveness.is_unused(inst) and !self.air.must_lower(inst, ip)) continue;

            const val: Builder.Value = switch (air_tags[@int_from_enum(inst)]) {
                // zig fmt: off
                .add            => try self.air_add(inst, .normal),
                .add_optimized  => try self.air_add(inst, .fast),
                .add_wrap       => try self.air_add_wrap(inst),
                .add_sat        => try self.air_add_sat(inst),

                .sub            => try self.air_sub(inst, .normal),
                .sub_optimized  => try self.air_sub(inst, .fast),
                .sub_wrap       => try self.air_sub_wrap(inst),
                .sub_sat        => try self.air_sub_sat(inst),

                .mul           => try self.air_mul(inst, .normal),
                .mul_optimized => try self.air_mul(inst, .fast),
                .mul_wrap      => try self.air_mul_wrap(inst),
                .mul_sat       => try self.air_mul_sat(inst),

                .add_safe => try self.air_safe_arithmetic(inst, .@"sadd.with.overflow", .@"uadd.with.overflow"),
                .sub_safe => try self.air_safe_arithmetic(inst, .@"ssub.with.overflow", .@"usub.with.overflow"),
                .mul_safe => try self.air_safe_arithmetic(inst, .@"smul.with.overflow", .@"umul.with.overflow"),

                .div_float => try self.air_div_float(inst, .normal),
                .div_trunc => try self.air_div_trunc(inst, .normal),
                .div_floor => try self.air_div_floor(inst, .normal),
                .div_exact => try self.air_div_exact(inst, .normal),
                .rem       => try self.air_rem(inst, .normal),
                .mod       => try self.air_mod(inst, .normal),
                .abs       => try self.air_abs(inst),
                .ptr_add   => try self.air_ptr_add(inst),
                .ptr_sub   => try self.air_ptr_sub(inst),
                .shl       => try self.air_shl(inst),
                .shl_sat   => try self.air_shl_sat(inst),
                .shl_exact => try self.air_shl_exact(inst),
                .min       => try self.air_min(inst),
                .max       => try self.air_max(inst),
                .slice     => try self.air_slice(inst),
                .mul_add   => try self.air_mul_add(inst),

                .div_float_optimized => try self.air_div_float(inst, .fast),
                .div_trunc_optimized => try self.air_div_trunc(inst, .fast),
                .div_floor_optimized => try self.air_div_floor(inst, .fast),
                .div_exact_optimized => try self.air_div_exact(inst, .fast),
                .rem_optimized       => try self.air_rem(inst, .fast),
                .mod_optimized       => try self.air_mod(inst, .fast),

                .add_with_overflow => try self.air_overflow(inst, .@"sadd.with.overflow", .@"uadd.with.overflow"),
                .sub_with_overflow => try self.air_overflow(inst, .@"ssub.with.overflow", .@"usub.with.overflow"),
                .mul_with_overflow => try self.air_overflow(inst, .@"smul.with.overflow", .@"umul.with.overflow"),
                .shl_with_overflow => try self.air_shl_with_overflow(inst),

                .bit_and, .bool_and => try self.air_and(inst),
                .bit_or, .bool_or   => try self.air_or(inst),
                .xor                => try self.air_xor(inst),
                .shr                => try self.air_shr(inst, false),
                .shr_exact          => try self.air_shr(inst, true),

                .sqrt         => try self.air_unary_op(inst, .sqrt),
                .sin          => try self.air_unary_op(inst, .sin),
                .cos          => try self.air_unary_op(inst, .cos),
                .tan          => try self.air_unary_op(inst, .tan),
                .exp          => try self.air_unary_op(inst, .exp),
                .exp2         => try self.air_unary_op(inst, .exp2),
                .log          => try self.air_unary_op(inst, .log),
                .log2         => try self.air_unary_op(inst, .log2),
                .log10        => try self.air_unary_op(inst, .log10),
                .floor        => try self.air_unary_op(inst, .floor),
                .ceil         => try self.air_unary_op(inst, .ceil),
                .round        => try self.air_unary_op(inst, .round),
                .trunc_float  => try self.air_unary_op(inst, .trunc),

                .neg           => try self.air_neg(inst, .normal),
                .neg_optimized => try self.air_neg(inst, .fast),

                .cmp_eq  => try self.air_cmp(inst, .eq, .normal),
                .cmp_gt  => try self.air_cmp(inst, .gt, .normal),
                .cmp_gte => try self.air_cmp(inst, .gte, .normal),
                .cmp_lt  => try self.air_cmp(inst, .lt, .normal),
                .cmp_lte => try self.air_cmp(inst, .lte, .normal),
                .cmp_neq => try self.air_cmp(inst, .neq, .normal),

                .cmp_eq_optimized  => try self.air_cmp(inst, .eq, .fast),
                .cmp_gt_optimized  => try self.air_cmp(inst, .gt, .fast),
                .cmp_gte_optimized => try self.air_cmp(inst, .gte, .fast),
                .cmp_lt_optimized  => try self.air_cmp(inst, .lt, .fast),
                .cmp_lte_optimized => try self.air_cmp(inst, .lte, .fast),
                .cmp_neq_optimized => try self.air_cmp(inst, .neq, .fast),

                .cmp_vector           => try self.air_cmp_vector(inst, .normal),
                .cmp_vector_optimized => try self.air_cmp_vector(inst, .fast),
                .cmp_lt_errors_len    => try self.air_cmp_lt_errors_len(inst),

                .is_non_null     => try self.air_is_non_null(inst, false, .ne),
                .is_non_null_ptr => try self.air_is_non_null(inst, true , .ne),
                .is_null         => try self.air_is_non_null(inst, false, .eq),
                .is_null_ptr     => try self.air_is_non_null(inst, true , .eq),

                .is_non_err      => try self.air_is_err(inst, .eq, false),
                .is_non_err_ptr  => try self.air_is_err(inst, .eq, true),
                .is_err          => try self.air_is_err(inst, .ne, false),
                .is_err_ptr      => try self.air_is_err(inst, .ne, true),

                .alloc          => try self.air_alloc(inst),
                .ret_ptr        => try self.air_ret_ptr(inst),
                .arg            => try self.air_arg(inst),
                .bitcast        => try self.air_bit_cast(inst),
                .int_from_bool    => try self.air_int_from_bool(inst),
                .block          => try self.air_block(inst),
                .br             => try self.air_br(inst),
                .switch_br      => try self.air_switch_br(inst),
                .trap           => try self.air_trap(inst),
                .breakpoint     => try self.air_breakpoint(inst),
                .ret_addr       => try self.air_ret_addr(inst),
                .frame_addr     => try self.air_frame_address(inst),
                .cond_br        => try self.air_cond_br(inst),
                .@"try"         => try self.air_try(body[i..]),
                .try_ptr        => try self.air_try_ptr(inst),
                .intcast        => try self.air_int_cast(inst),
                .trunc          => try self.air_trunc(inst),
                .fptrunc        => try self.air_fptrunc(inst),
                .fpext          => try self.air_fpext(inst),
                .int_from_ptr       => try self.air_int_from_ptr(inst),
                .load           => try self.air_load(body[i..]),
                .loop           => try self.air_loop(inst),
                .not            => try self.air_not(inst),
                .ret            => try self.air_ret(inst, false),
                .ret_safe       => try self.air_ret(inst, true),
                .ret_load       => try self.air_ret_load(inst),
                .store          => try self.air_store(inst, false),
                .store_safe     => try self.air_store(inst, true),
                .assembly       => try self.air_assembly(inst),
                .slice_ptr      => try self.air_slice_field(inst, 0),
                .slice_len      => try self.air_slice_field(inst, 1),

                .call              => try self.air_call(inst, .auto),
                .call_always_tail  => try self.air_call(inst, .always_tail),
                .call_never_tail   => try self.air_call(inst, .never_tail),
                .call_never_inline => try self.air_call(inst, .never_inline),

                .ptr_slice_ptr_ptr => try self.air_ptr_slice_field_ptr(inst, 0),
                .ptr_slice_len_ptr => try self.air_ptr_slice_field_ptr(inst, 1),

                .int_from_float           => try self.air_int_from_float(inst, .normal),
                .int_from_float_optimized => try self.air_int_from_float(inst, .fast),

                .array_to_slice => try self.air_array_to_slice(inst),
                .float_from_int => try self.air_float_from_int(inst),
                .cmpxchg_weak   => try self.air_cmpxchg(inst, .weak),
                .cmpxchg_strong => try self.air_cmpxchg(inst, .strong),
                .fence          => try self.air_fence(inst),
                .atomic_rmw     => try self.air_atomic_rmw(inst),
                .atomic_load    => try self.air_atomic_load(inst),
                .memset         => try self.air_memset(inst, false),
                .memset_safe    => try self.air_memset(inst, true),
                .memcpy         => try self.air_memcpy(inst),
                .set_union_tag  => try self.air_set_union_tag(inst),
                .get_union_tag  => try self.air_get_union_tag(inst),
                .clz            => try self.air_clz_ctz(inst, .ctlz),
                .ctz            => try self.air_clz_ctz(inst, .cttz),
                .popcount       => try self.air_bit_op(inst, .ctpop),
                .byte_swap      => try self.air_byte_swap(inst),
                .bit_reverse    => try self.air_bit_op(inst, .bitreverse),
                .tag_name       => try self.air_tag_name(inst),
                .error_name     => try self.air_error_name(inst),
                .splat          => try self.air_splat(inst),
                .select         => try self.air_select(inst),
                .shuffle        => try self.air_shuffle(inst),
                .aggregate_init => try self.air_aggregate_init(inst),
                .union_init     => try self.air_union_init(inst),
                .prefetch       => try self.air_prefetch(inst),
                .addrspace_cast => try self.air_addr_space_cast(inst),

                .is_named_enum_value => try self.air_is_named_enum_value(inst),
                .error_set_has_value => try self.air_error_set_has_value(inst),

                .reduce           => try self.air_reduce(inst, .normal),
                .reduce_optimized => try self.air_reduce(inst, .fast),

                .atomic_store_unordered => try self.air_atomic_store(inst, .unordered),
                .atomic_store_monotonic => try self.air_atomic_store(inst, .monotonic),
                .atomic_store_release   => try self.air_atomic_store(inst, .release),
                .atomic_store_seq_cst   => try self.air_atomic_store(inst, .seq_cst),

                .struct_field_ptr => try self.air_struct_field_ptr(inst),
                .struct_field_val => try self.air_struct_field_val(body[i..]),

                .struct_field_ptr_index_0 => try self.air_struct_field_ptr_index(inst, 0),
                .struct_field_ptr_index_1 => try self.air_struct_field_ptr_index(inst, 1),
                .struct_field_ptr_index_2 => try self.air_struct_field_ptr_index(inst, 2),
                .struct_field_ptr_index_3 => try self.air_struct_field_ptr_index(inst, 3),

                .field_parent_ptr => try self.air_field_parent_ptr(inst),

                .array_elem_val     => try self.air_array_elem_val(body[i..]),
                .slice_elem_val     => try self.air_slice_elem_val(body[i..]),
                .slice_elem_ptr     => try self.air_slice_elem_ptr(inst),
                .ptr_elem_val       => try self.air_ptr_elem_val(body[i..]),
                .ptr_elem_ptr       => try self.air_ptr_elem_ptr(inst),

                .optional_payload         => try self.air_optional_payload(body[i..]),
                .optional_payload_ptr     => try self.air_optional_payload_ptr(inst),
                .optional_payload_ptr_set => try self.air_optional_payload_ptr_set(inst),

                .unwrap_errunion_payload     => try self.air_err_union_payload(body[i..], false),
                .unwrap_errunion_payload_ptr => try self.air_err_union_payload(body[i..], true),
                .unwrap_errunion_err         => try self.air_err_union_err(inst, false),
                .unwrap_errunion_err_ptr     => try self.air_err_union_err(inst, true),
                .errunion_payload_ptr_set    => try self.air_err_union_payload_ptr_set(inst),
                .err_return_trace            => try self.air_err_return_trace(inst),
                .set_err_return_trace        => try self.air_set_err_return_trace(inst),
                .save_err_return_trace_index => try self.air_save_err_return_trace_index(inst),

                .wrap_optional         => try self.air_wrap_optional(body[i..]),
                .wrap_errunion_payload => try self.air_wrap_err_union_payload(body[i..]),
                .wrap_errunion_err     => try self.air_wrap_err_union_err(body[i..]),

                .wasm_memory_size => try self.air_wasm_memory_size(inst),
                .wasm_memory_grow => try self.air_wasm_memory_grow(inst),

                .vector_store_elem => try self.air_vector_store_elem(inst),

                .inferred_alloc, .inferred_alloc_comptime => unreachable,

                .unreach  => try self.air_unreach(inst),
                .dbg_stmt => try self.air_dbg_stmt(inst),
                .dbg_inline_block => try self.air_dbg_inline_block(inst),
                .dbg_var_ptr => try self.air_dbg_var_ptr(inst),
                .dbg_var_val => try self.air_dbg_var_val(inst),

                .c_va_arg => try self.air_cva_arg(inst),
                .c_va_copy => try self.air_cva_copy(inst),
                .c_va_end => try self.air_cva_end(inst),
                .c_va_start => try self.air_cva_start(inst),

                .work_item_id => try self.air_work_item_id(inst),
                .work_group_size => try self.air_work_group_size(inst),
                .work_group_id => try self.air_work_group_id(inst),
                // zig fmt: on
            };
            if (val != .none) try self.func_inst_table.put_no_clobber(self.gpa, inst.to_ref(), val);
        }
    }

    fn gen_body_debug_scope(self: *FuncGen, maybe_inline_func: ?InternPool.Index, body: []const Air.Inst.Index) Error!void {
        if (self.wip.strip) return self.gen_body(body);

        const old_file = self.file;
        const old_inlined = self.inlined;
        const old_base_line = self.base_line;
        const old_scope = self.scope;
        defer if (maybe_inline_func) |_| {
            self.wip.debug_location = self.inlined;
            self.file = old_file;
            self.inlined = old_inlined;
            self.base_line = old_base_line;
        };
        defer self.scope = old_scope;

        if (maybe_inline_func) |inline_func| {
            const o = self.dg.object;
            const zcu = o.module;

            const func = zcu.func_info(inline_func);
            const decl_index = func.owner_decl;
            const decl = zcu.decl_ptr(decl_index);
            const namespace = zcu.namespace_ptr(decl.src_namespace);
            const owner_mod = namespace.file_scope.mod;

            self.file = try o.get_debug_file(namespace.file_scope);

            const line_number = decl.src_line + 1;
            self.inlined = self.wip.debug_location;

            const fqn = try decl.fully_qualified_name(zcu);

            const is_internal_linkage = !zcu.decl_exports.contains(decl_index);
            const fn_ty = try zcu.func_type(.{
                .param_types = &.{},
                .return_type = .void_type,
            });

            self.scope = try o.builder.debug_subprogram(
                self.file,
                try o.builder.metadata_string(decl.name.to_slice(&zcu.intern_pool)),
                try o.builder.metadata_string(fqn.to_slice(&zcu.intern_pool)),
                line_number,
                line_number + func.lbrace_line,
                try o.lower_debug_type(fn_ty),
                .{
                    .di_flags = .{ .StaticMember = true },
                    .sp_flags = .{
                        .Optimized = owner_mod.optimize_mode != .Debug,
                        .Definition = true,
                        .LocalToUnit = is_internal_linkage,
                    },
                },
                o.debug_compile_unit,
            );

            self.base_line = decl.src_line;
            const inlined_at_location = try self.wip.debug_location.to_metadata(&o.builder);
            self.wip.debug_location = .{
                .location = .{
                    .line = line_number,
                    .column = 0,
                    .scope = self.scope,
                    .inlined_at = inlined_at_location,
                },
            };
        }

        self.scope = try self.dg.object.builder.debug_lexical_block(
            self.scope,
            self.file,
            self.prev_dbg_line,
            self.prev_dbg_column,
        );

        switch (self.wip.debug_location) {
            .location => |*l| l.scope = self.scope,
            .no_location => {},
        }
        defer switch (self.wip.debug_location) {
            .location => |*l| l.scope = old_scope,
            .no_location => {},
        };

        try self.gen_body(body);
    }

    pub const CallAttr = enum {
        Auto,
        NeverTail,
        NeverInline,
        AlwaysTail,
        AlwaysInline,
    };

    fn air_call(self: *FuncGen, inst: Air.Inst.Index, modifier: std.builtin.CallModifier) !Builder.Value {
        const pl_op = self.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
        const extra = self.air.extra_data(Air.Call, pl_op.payload);
        const args: []const Air.Inst.Ref = @ptr_cast(self.air.extra[extra.end..][0..extra.data.args_len]);
        const o = self.dg.object;
        const mod = o.module;
        const ip = &mod.intern_pool;
        const callee_ty = self.type_of(pl_op.operand);
        const zig_fn_ty = switch (callee_ty.zig_type_tag(mod)) {
            .Fn => callee_ty,
            .Pointer => callee_ty.child_type(mod),
            else => unreachable,
        };
        const fn_info = mod.type_to_func(zig_fn_ty).?;
        const return_type = Type.from_interned(fn_info.return_type);
        const llvm_fn = try self.resolve_inst(pl_op.operand);
        const target = mod.get_target();
        const sret = first_param_sret(fn_info, mod, target);

        var llvm_args = std.ArrayList(Builder.Value).init(self.gpa);
        defer llvm_args.deinit();

        var attributes: Builder.FunctionAttributes.Wip = .{};
        defer attributes.deinit(&o.builder);

        switch (modifier) {
            .auto, .never_tail, .always_tail => {},
            .never_inline => try attributes.add_fn_attr(.@"noinline", &o.builder),
            .async_kw, .no_async, .always_inline, .compile_time => unreachable,
        }

        const ret_ptr = if (!sret) null else blk: {
            const llvm_ret_ty = try o.lower_type(return_type);
            try attributes.add_param_attr(0, .{ .sret = llvm_ret_ty }, &o.builder);

            const alignment = return_type.abi_alignment(mod).to_llvm();
            const ret_ptr = try self.build_alloca_workaround(return_type, alignment);
            try llvm_args.append(ret_ptr);
            break :blk ret_ptr;
        };

        const err_return_tracing = return_type.is_error(mod) and
            o.module.comp.config.any_error_tracing;
        if (err_return_tracing) {
            assert(self.err_ret_trace != .none);
            try llvm_args.append(self.err_ret_trace);
        }

        var it = iterate_param_types(o, fn_info);
        while (try it.next_call(self, args)) |lowering| switch (lowering) {
            .no_bits => continue,
            .byval => {
                const arg = args[it.zig_index - 1];
                const param_ty = self.type_of(arg);
                const llvm_arg = try self.resolve_inst(arg);
                const llvm_param_ty = try o.lower_type(param_ty);
                if (is_by_ref(param_ty, mod)) {
                    const alignment = param_ty.abi_alignment(mod).to_llvm();
                    const loaded = try self.wip.load(.normal, llvm_param_ty, llvm_arg, alignment, "");
                    try llvm_args.append(loaded);
                } else {
                    try llvm_args.append(llvm_arg);
                }
            },
            .byref => {
                const arg = args[it.zig_index - 1];
                const param_ty = self.type_of(arg);
                const llvm_arg = try self.resolve_inst(arg);
                if (is_by_ref(param_ty, mod)) {
                    try llvm_args.append(llvm_arg);
                } else {
                    const alignment = param_ty.abi_alignment(mod).to_llvm();
                    const param_llvm_ty = llvm_arg.type_of_wip(&self.wip);
                    const arg_ptr = try self.build_alloca(param_llvm_ty, alignment);
                    _ = try self.wip.store(.normal, llvm_arg, arg_ptr, alignment);
                    try llvm_args.append(arg_ptr);
                }
            },
            .byref_mut => {
                const arg = args[it.zig_index - 1];
                const param_ty = self.type_of(arg);
                const llvm_arg = try self.resolve_inst(arg);

                const alignment = param_ty.abi_alignment(mod).to_llvm();
                const param_llvm_ty = try o.lower_type(param_ty);
                const arg_ptr = try self.build_alloca_workaround(param_ty, alignment);
                if (is_by_ref(param_ty, mod)) {
                    const loaded = try self.wip.load(.normal, param_llvm_ty, llvm_arg, alignment, "");
                    _ = try self.wip.store(.normal, loaded, arg_ptr, alignment);
                } else {
                    _ = try self.wip.store(.normal, llvm_arg, arg_ptr, alignment);
                }
                try llvm_args.append(arg_ptr);
            },
            .abi_sized_int => {
                const arg = args[it.zig_index - 1];
                const param_ty = self.type_of(arg);
                const llvm_arg = try self.resolve_inst(arg);
                const int_llvm_ty = try o.builder.int_type(@int_cast(param_ty.abi_size(mod) * 8));

                if (is_by_ref(param_ty, mod)) {
                    const alignment = param_ty.abi_alignment(mod).to_llvm();
                    const loaded = try self.wip.load(.normal, int_llvm_ty, llvm_arg, alignment, "");
                    try llvm_args.append(loaded);
                } else {
                    // LLVM does not allow bitcasting structs so we must allocate
                    // a local, store as one type, and then load as another type.
                    const alignment = param_ty.abi_alignment(mod).to_llvm();
                    const int_ptr = try self.build_alloca_workaround(param_ty, alignment);
                    _ = try self.wip.store(.normal, llvm_arg, int_ptr, alignment);
                    const loaded = try self.wip.load(.normal, int_llvm_ty, int_ptr, alignment, "");
                    try llvm_args.append(loaded);
                }
            },
            .slice => {
                const arg = args[it.zig_index - 1];
                const llvm_arg = try self.resolve_inst(arg);
                const ptr = try self.wip.extract_value(llvm_arg, &.{0}, "");
                const len = try self.wip.extract_value(llvm_arg, &.{1}, "");
                try llvm_args.append_slice(&.{ ptr, len });
            },
            .multiple_llvm_types => {
                const arg = args[it.zig_index - 1];
                const param_ty = self.type_of(arg);
                const llvm_types = it.types_buffer[0..it.types_len];
                const llvm_arg = try self.resolve_inst(arg);
                const is_by_ref = is_by_ref(param_ty, mod);
                const arg_ptr = if (is_by_ref) llvm_arg else ptr: {
                    const alignment = param_ty.abi_alignment(mod).to_llvm();
                    const ptr = try self.build_alloca(llvm_arg.type_of_wip(&self.wip), alignment);
                    _ = try self.wip.store(.normal, llvm_arg, ptr, alignment);
                    break :ptr ptr;
                };

                const llvm_ty = try o.builder.struct_type(.normal, llvm_types);
                try llvm_args.ensure_unused_capacity(it.types_len);
                for (llvm_types, 0..) |field_ty, i| {
                    const alignment =
                        Builder.Alignment.from_byte_units(@div_exact(target.ptr_bit_width(), 8));
                    const field_ptr = try self.wip.gep_struct(llvm_ty, arg_ptr, i, "");
                    const loaded = try self.wip.load(.normal, field_ty, field_ptr, alignment, "");
                    llvm_args.append_assume_capacity(loaded);
                }
            },
            .as_u16 => {
                const arg = args[it.zig_index - 1];
                const llvm_arg = try self.resolve_inst(arg);
                const casted = try self.wip.cast(.bitcast, llvm_arg, .i16, "");
                try llvm_args.append(casted);
            },
            .float_array => |count| {
                const arg = args[it.zig_index - 1];
                const arg_ty = self.type_of(arg);
                var llvm_arg = try self.resolve_inst(arg);
                const alignment = arg_ty.abi_alignment(mod).to_llvm();
                if (!is_by_ref(arg_ty, mod)) {
                    const ptr = try self.build_alloca(llvm_arg.type_of_wip(&self.wip), alignment);
                    _ = try self.wip.store(.normal, llvm_arg, ptr, alignment);
                    llvm_arg = ptr;
                }

                const float_ty = try o.lower_type(aarch64_c_abi.get_float_array_type(arg_ty, mod).?);
                const array_ty = try o.builder.array_type(count, float_ty);

                const loaded = try self.wip.load(.normal, array_ty, llvm_arg, alignment, "");
                try llvm_args.append(loaded);
            },
            .i32_array, .i64_array => |arr_len| {
                const elem_size: u8 = if (lowering == .i32_array) 32 else 64;
                const arg = args[it.zig_index - 1];
                const arg_ty = self.type_of(arg);
                var llvm_arg = try self.resolve_inst(arg);
                const alignment = arg_ty.abi_alignment(mod).to_llvm();
                if (!is_by_ref(arg_ty, mod)) {
                    const ptr = try self.build_alloca(llvm_arg.type_of_wip(&self.wip), alignment);
                    _ = try self.wip.store(.normal, llvm_arg, ptr, alignment);
                    llvm_arg = ptr;
                }

                const array_ty =
                    try o.builder.array_type(arr_len, try o.builder.int_type(@int_cast(elem_size)));
                const loaded = try self.wip.load(.normal, array_ty, llvm_arg, alignment, "");
                try llvm_args.append(loaded);
            },
        };

        {
            // Add argument attributes.
            it = iterate_param_types(o, fn_info);
            it.llvm_index += @int_from_bool(sret);
            it.llvm_index += @int_from_bool(err_return_tracing);
            while (try it.next()) |lowering| switch (lowering) {
                .byval => {
                    const param_index = it.zig_index - 1;
                    const param_ty = Type.from_interned(fn_info.param_types.get(ip)[param_index]);
                    if (!is_by_ref(param_ty, mod)) {
                        try o.add_by_val_param_attrs(&attributes, param_ty, param_index, fn_info, it.llvm_index - 1);
                    }
                },
                .byref => {
                    const param_index = it.zig_index - 1;
                    const param_ty = Type.from_interned(fn_info.param_types.get(ip)[param_index]);
                    const param_llvm_ty = try o.lower_type(param_ty);
                    const alignment = param_ty.abi_alignment(mod).to_llvm();
                    try o.add_by_ref_param_attrs(&attributes, it.llvm_index - 1, alignment, it.byval_attr, param_llvm_ty);
                },
                .byref_mut => try attributes.add_param_attr(it.llvm_index - 1, .noundef, &o.builder),
                // No attributes needed for these.
                .no_bits,
                .abi_sized_int,
                .multiple_llvm_types,
                .as_u16,
                .float_array,
                .i32_array,
                .i64_array,
                => continue,

                .slice => {
                    assert(!it.byval_attr);
                    const param_ty = Type.from_interned(fn_info.param_types.get(ip)[it.zig_index - 1]);
                    const ptr_info = param_ty.ptr_info(mod);
                    const llvm_arg_i = it.llvm_index - 2;

                    if (math.cast(u5, it.zig_index - 1)) |i| {
                        if (@as(u1, @truncate(fn_info.noalias_bits >> i)) != 0) {
                            try attributes.add_param_attr(llvm_arg_i, .@"noalias", &o.builder);
                        }
                    }
                    if (param_ty.zig_type_tag(mod) != .Optional) {
                        try attributes.add_param_attr(llvm_arg_i, .nonnull, &o.builder);
                    }
                    if (ptr_info.flags.is_const) {
                        try attributes.add_param_attr(llvm_arg_i, .readonly, &o.builder);
                    }
                    const elem_align = (if (ptr_info.flags.alignment != .none)
                        @as(InternPool.Alignment, ptr_info.flags.alignment)
                    else
                        Type.from_interned(ptr_info.child).abi_alignment(mod).max(.@"1")).to_llvm();
                    try attributes.add_param_attr(llvm_arg_i, .{ .@"align" = elem_align }, &o.builder);
                },
            };
        }

        const call = try self.wip.call(
            switch (modifier) {
                .auto, .never_inline => .normal,
                .never_tail => .notail,
                .always_tail => .musttail,
                .async_kw, .no_async, .always_inline, .compile_time => unreachable,
            },
            to_llvm_call_conv(fn_info.cc, target),
            try attributes.finish(&o.builder),
            try o.lower_type(zig_fn_ty),
            llvm_fn,
            llvm_args.items,
            "",
        );

        if (fn_info.return_type == .noreturn_type and modifier != .always_tail) {
            return .none;
        }

        if (self.liveness.is_unused(inst) or !return_type.has_runtime_bits_ignore_comptime(mod)) {
            return .none;
        }

        const llvm_ret_ty = try o.lower_type(return_type);
        if (ret_ptr) |rp| {
            if (is_by_ref(return_type, mod)) {
                return rp;
            } else {
                // our by-ref status disagrees with sret so we must load.
                const return_alignment = return_type.abi_alignment(mod).to_llvm();
                return self.wip.load(.normal, llvm_ret_ty, rp, return_alignment, "");
            }
        }

        const abi_ret_ty = try lower_fn_ret_ty(o, fn_info);

        if (abi_ret_ty != llvm_ret_ty) {
            // In this case the function return type is honoring the calling convention by having
            // a different LLVM type than the usual one. We solve this here at the callsite
            // by using our canonical type, then loading it if necessary.
            const alignment = return_type.abi_alignment(mod).to_llvm();
            const rp = try self.build_alloca(abi_ret_ty, alignment);
            _ = try self.wip.store(.normal, call, rp, alignment);
            return if (is_by_ref(return_type, mod))
                rp
            else
                try self.wip.load(.normal, llvm_ret_ty, rp, alignment, "");
        }

        if (is_by_ref(return_type, mod)) {
            // our by-ref status disagrees with sret so we must allocate, store,
            // and return the allocation pointer.
            const alignment = return_type.abi_alignment(mod).to_llvm();
            const rp = try self.build_alloca(llvm_ret_ty, alignment);
            _ = try self.wip.store(.normal, call, rp, alignment);
            return rp;
        } else {
            return call;
        }
    }

    fn build_simple_panic(fg: *FuncGen, panic_id: Module.PanicId) !void {
        const o = fg.dg.object;
        const mod = o.module;
        const msg_decl_index = mod.panic_messages[@int_from_enum(panic_id)].unwrap().?;
        const msg_decl = mod.decl_ptr(msg_decl_index);
        const msg_len = msg_decl.type_of(mod).child_type(mod).array_len(mod);
        const msg_ptr = try o.lower_value(msg_decl.val.to_intern());
        const null_opt_addr_global = try fg.resolve_null_opt_usize();
        const target = mod.get_target();
        const llvm_usize = try o.lower_type(Type.usize);
        // example:
        // call fastcc void @test2.panic(
        //   ptr @builtin.panic_messages.integer_overflow__anon_987, ; msg.ptr
        //   i64 16,                                                 ; msg.len
        //   ptr null,                                               ; stack trace
        //   ptr @2,                                                 ; addr (null ?usize)
        // )
        const panic_func = mod.func_info(mod.panic_func_index);
        const panic_decl = mod.decl_ptr(panic_func.owner_decl);
        const fn_info = mod.type_to_func(panic_decl.type_of(mod)).?;
        const panic_global = try o.resolve_llvm_function(panic_func.owner_decl);
        _ = try fg.wip.call(
            .normal,
            to_llvm_call_conv(fn_info.cc, target),
            .none,
            panic_global.type_of(&o.builder),
            panic_global.to_value(&o.builder),
            &.{
                msg_ptr.to_value(),
                try o.builder.int_value(llvm_usize, msg_len),
                try o.builder.null_value(.ptr),
                null_opt_addr_global.to_value(),
            },
            "",
        );
        _ = try fg.wip.@"unreachable"();
    }

    fn air_ret(self: *FuncGen, inst: Air.Inst.Index, safety: bool) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
        const ret_ty = self.type_of(un_op);

        if (self.ret_ptr != .none) {
            const ptr_ty = try mod.single_mut_ptr_type(ret_ty);

            const operand = try self.resolve_inst(un_op);
            const val_is_undef = if (try self.air.value(un_op, mod)) |val| val.is_undef_deep(mod) else false;
            if (val_is_undef and safety) undef: {
                const ptr_info = ptr_ty.ptr_info(mod);
                const needs_bitmask = (ptr_info.packed_offset.host_size != 0);
                if (needs_bitmask) {
                    // TODO: only some bits are to be undef, we cannot write with a simple memset.
                    // meanwhile, ignore the write rather than stomping over valid bits.
                    // https://github.com/ziglang/zig/issues/15337
                    break :undef;
                }
                const len = try o.builder.int_value(try o.lower_type(Type.usize), ret_ty.abi_size(mod));
                _ = try self.wip.call_mem_set(
                    self.ret_ptr,
                    ptr_ty.ptr_alignment(mod).to_llvm(),
                    try o.builder.int_value(.i8, 0xaa),
                    len,
                    if (ptr_ty.is_volatile_ptr(mod)) .@"volatile" else .normal,
                );
                const owner_mod = self.dg.owner_module();
                if (owner_mod.valgrind) {
                    try self.valgrind_mark_undef(self.ret_ptr, len);
                }
                _ = try self.wip.ret_void();
                return .none;
            }

            const unwrapped_operand = operand.unwrap();
            const unwrapped_ret = self.ret_ptr.unwrap();

            // Return value was stored previously
            if (unwrapped_operand == .instruction and unwrapped_ret == .instruction and unwrapped_operand.instruction == unwrapped_ret.instruction) {
                _ = try self.wip.ret_void();
                return .none;
            }

            try self.store(self.ret_ptr, ptr_ty, operand, .none);
            _ = try self.wip.ret_void();
            return .none;
        }
        const fn_info = mod.type_to_func(self.dg.decl.type_of(mod)).?;
        if (!ret_ty.has_runtime_bits_ignore_comptime(mod)) {
            if (Type.from_interned(fn_info.return_type).is_error(mod)) {
                // Functions with an empty error set are emitted with an error code
                // return type and return zero so they can be function pointers coerced
                // to functions that return anyerror.
                _ = try self.wip.ret(try o.builder.int_value(try o.error_int_type(), 0));
            } else {
                _ = try self.wip.ret_void();
            }
            return .none;
        }

        const abi_ret_ty = try lower_fn_ret_ty(o, fn_info);
        const operand = try self.resolve_inst(un_op);
        const val_is_undef = if (try self.air.value(un_op, mod)) |val| val.is_undef_deep(mod) else false;
        const alignment = ret_ty.abi_alignment(mod).to_llvm();

        if (val_is_undef and safety) {
            const llvm_ret_ty = operand.type_of_wip(&self.wip);
            const rp = try self.build_alloca(llvm_ret_ty, alignment);
            const len = try o.builder.int_value(try o.lower_type(Type.usize), ret_ty.abi_size(mod));
            _ = try self.wip.call_mem_set(
                rp,
                alignment,
                try o.builder.int_value(.i8, 0xaa),
                len,
                .normal,
            );
            const owner_mod = self.dg.owner_module();
            if (owner_mod.valgrind) {
                try self.valgrind_mark_undef(rp, len);
            }
            _ = try self.wip.ret(try self.wip.load(.normal, abi_ret_ty, rp, alignment, ""));
            return .none;
        }

        if (is_by_ref(ret_ty, mod)) {
            // operand is a pointer however self.ret_ptr is null so that means
            // we need to return a value.
            _ = try self.wip.ret(try self.wip.load(.normal, abi_ret_ty, operand, alignment, ""));
            return .none;
        }

        const llvm_ret_ty = operand.type_of_wip(&self.wip);
        if (abi_ret_ty == llvm_ret_ty) {
            _ = try self.wip.ret(operand);
            return .none;
        }

        const rp = try self.build_alloca(llvm_ret_ty, alignment);
        _ = try self.wip.store(.normal, operand, rp, alignment);
        _ = try self.wip.ret(try self.wip.load(.normal, abi_ret_ty, rp, alignment, ""));
        return .none;
    }

    fn air_ret_load(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
        const ptr_ty = self.type_of(un_op);
        const ret_ty = ptr_ty.child_type(mod);
        const fn_info = mod.type_to_func(self.dg.decl.type_of(mod)).?;
        if (!ret_ty.has_runtime_bits_ignore_comptime(mod)) {
            if (Type.from_interned(fn_info.return_type).is_error(mod)) {
                // Functions with an empty error set are emitted with an error code
                // return type and return zero so they can be function pointers coerced
                // to functions that return anyerror.
                _ = try self.wip.ret(try o.builder.int_value(try o.error_int_type(), 0));
            } else {
                _ = try self.wip.ret_void();
            }
            return .none;
        }
        if (self.ret_ptr != .none) {
            _ = try self.wip.ret_void();
            return .none;
        }
        const ptr = try self.resolve_inst(un_op);
        const abi_ret_ty = try lower_fn_ret_ty(o, fn_info);
        const alignment = ret_ty.abi_alignment(mod).to_llvm();
        _ = try self.wip.ret(try self.wip.load(.normal, abi_ret_ty, ptr, alignment, ""));
        return .none;
    }

    fn air_cva_arg(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
        const list = try self.resolve_inst(ty_op.operand);
        const arg_ty = ty_op.ty.to_type();
        const llvm_arg_ty = try o.lower_type(arg_ty);

        return self.wip.va_arg(list, llvm_arg_ty, "");
    }

    fn air_cva_copy(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
        const src_list = try self.resolve_inst(ty_op.operand);
        const va_list_ty = ty_op.ty.to_type();
        const llvm_va_list_ty = try o.lower_type(va_list_ty);
        const mod = o.module;

        const result_alignment = va_list_ty.abi_alignment(mod).to_llvm();
        const dest_list = try self.build_alloca_workaround(va_list_ty, result_alignment);

        _ = try self.wip.call_intrinsic(.normal, .none, .va_copy, &.{}, &.{ dest_list, src_list }, "");
        return if (is_by_ref(va_list_ty, mod))
            dest_list
        else
            try self.wip.load(.normal, llvm_va_list_ty, dest_list, result_alignment, "");
    }

    fn air_cva_end(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
        const src_list = try self.resolve_inst(un_op);

        _ = try self.wip.call_intrinsic(.normal, .none, .va_end, &.{}, &.{src_list}, "");
        return .none;
    }

    fn air_cva_start(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const va_list_ty = self.type_of_index(inst);
        const llvm_va_list_ty = try o.lower_type(va_list_ty);

        const result_alignment = va_list_ty.abi_alignment(mod).to_llvm();
        const dest_list = try self.build_alloca_workaround(va_list_ty, result_alignment);

        _ = try self.wip.call_intrinsic(.normal, .none, .va_start, &.{}, &.{dest_list}, "");
        return if (is_by_ref(va_list_ty, mod))
            dest_list
        else
            try self.wip.load(.normal, llvm_va_list_ty, dest_list, result_alignment, "");
    }

    fn air_cmp(
        self: *FuncGen,
        inst: Air.Inst.Index,
        op: math.CompareOperator,
        fast: Builder.FastMathKind,
    ) !Builder.Value {
        const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
        const lhs = try self.resolve_inst(bin_op.lhs);
        const rhs = try self.resolve_inst(bin_op.rhs);
        const operand_ty = self.type_of(bin_op.lhs);

        return self.cmp(fast, op, operand_ty, lhs, rhs);
    }

    fn air_cmp_vector(self: *FuncGen, inst: Air.Inst.Index, fast: Builder.FastMathKind) !Builder.Value {
        const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
        const extra = self.air.extra_data(Air.VectorCmp, ty_pl.payload).data;

        const lhs = try self.resolve_inst(extra.lhs);
        const rhs = try self.resolve_inst(extra.rhs);
        const vec_ty = self.type_of(extra.lhs);
        const cmp_op = extra.compare_operator();

        return self.cmp(fast, cmp_op, vec_ty, lhs, rhs);
    }

    fn air_cmp_lt_errors_len(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
        const operand = try self.resolve_inst(un_op);
        const llvm_fn = try o.get_cmp_lt_errors_len_function();
        return self.wip.call(
            .normal,
            .fastcc,
            .none,
            llvm_fn.type_of(&o.builder),
            llvm_fn.to_value(&o.builder),
            &.{operand},
            "",
        );
    }

    fn cmp(
        self: *FuncGen,
        fast: Builder.FastMathKind,
        op: math.CompareOperator,
        operand_ty: Type,
        lhs: Builder.Value,
        rhs: Builder.Value,
    ) Allocator.Error!Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const scalar_ty = operand_ty.scalar_type(mod);
        const int_ty = switch (scalar_ty.zig_type_tag(mod)) {
            .Enum => scalar_ty.int_tag_type(mod),
            .Int, .Bool, .Pointer, .ErrorSet => scalar_ty,
            .Optional => blk: {
                const payload_ty = operand_ty.optional_child(mod);
                if (!payload_ty.has_runtime_bits_ignore_comptime(mod) or
                    operand_ty.optional_repr_is_payload(mod))
                {
                    break :blk operand_ty;
                }
                // We need to emit instructions to check for equality/inequality
                // of optionals that are not pointers.
                const is_by_ref = is_by_ref(scalar_ty, mod);
                const opt_llvm_ty = try o.lower_type(scalar_ty);
                const lhs_non_null = try self.opt_cmp_null(.ne, opt_llvm_ty, lhs, is_by_ref);
                const rhs_non_null = try self.opt_cmp_null(.ne, opt_llvm_ty, rhs, is_by_ref);
                const llvm_i2 = try o.builder.int_type(2);
                const lhs_non_null_i2 = try self.wip.cast(.zext, lhs_non_null, llvm_i2, "");
                const rhs_non_null_i2 = try self.wip.cast(.zext, rhs_non_null, llvm_i2, "");
                const lhs_shifted = try self.wip.bin(.shl, lhs_non_null_i2, try o.builder.int_value(llvm_i2, 1), "");
                const lhs_rhs_ored = try self.wip.bin(.@"or", lhs_shifted, rhs_non_null_i2, "");
                const both_null_block = try self.wip.block(1, "BothNull");
                const mixed_block = try self.wip.block(1, "Mixed");
                const both_pl_block = try self.wip.block(1, "BothNonNull");
                const end_block = try self.wip.block(3, "End");
                var wip_switch = try self.wip.@"switch"(lhs_rhs_ored, mixed_block, 2);
                defer wip_switch.finish(&self.wip);
                try wip_switch.add_case(
                    try o.builder.int_const(llvm_i2, 0b00),
                    both_null_block,
                    &self.wip,
                );
                try wip_switch.add_case(
                    try o.builder.int_const(llvm_i2, 0b11),
                    both_pl_block,
                    &self.wip,
                );

                self.wip.cursor = .{ .block = both_null_block };
                _ = try self.wip.br(end_block);

                self.wip.cursor = .{ .block = mixed_block };
                _ = try self.wip.br(end_block);

                self.wip.cursor = .{ .block = both_pl_block };
                const lhs_payload = try self.opt_payload_handle(opt_llvm_ty, lhs, scalar_ty, true);
                const rhs_payload = try self.opt_payload_handle(opt_llvm_ty, rhs, scalar_ty, true);
                const payload_cmp = try self.cmp(fast, op, payload_ty, lhs_payload, rhs_payload);
                _ = try self.wip.br(end_block);
                const both_pl_block_end = self.wip.cursor.block;

                self.wip.cursor = .{ .block = end_block };
                const llvm_i1_0 = Builder.Value.false;
                const llvm_i1_1 = Builder.Value.true;
                const incoming_values: [3]Builder.Value = .{
                    switch (op) {
                        .eq => llvm_i1_1,
                        .neq => llvm_i1_0,
                        else => unreachable,
                    },
                    switch (op) {
                        .eq => llvm_i1_0,
                        .neq => llvm_i1_1,
                        else => unreachable,
                    },
                    payload_cmp,
                };

                const phi = try self.wip.phi(.i1, "");
                phi.finish(
                    &incoming_values,
                    &.{ both_null_block, mixed_block, both_pl_block_end },
                    &self.wip,
                );
                return phi.to_value();
            },
            .Float => return self.build_float_cmp(fast, op, operand_ty, .{ lhs, rhs }),
            else => unreachable,
        };
        const is_signed = int_ty.is_signed_int(mod);
        const cond: Builder.IntegerCondition = switch (op) {
            .eq => .eq,
            .neq => .ne,
            .lt => if (is_signed) .slt else .ult,
            .lte => if (is_signed) .sle else .ule,
            .gt => if (is_signed) .sgt else .ugt,
            .gte => if (is_signed) .sge else .uge,
        };
        return self.wip.icmp(cond, lhs, rhs, "");
    }

    fn air_block(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
        const extra = self.air.extra_data(Air.Block, ty_pl.payload);
        return self.lower_block(inst, null, @ptr_cast(self.air.extra[extra.end..][0..extra.data.body_len]));
    }

    fn lower_block(
        self: *FuncGen,
        inst: Air.Inst.Index,
        maybe_inline_func: ?InternPool.Index,
        body: []const Air.Inst.Index,
    ) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const inst_ty = self.type_of_index(inst);

        if (inst_ty.is_no_return(mod)) {
            try self.gen_body_debug_scope(maybe_inline_func, body);
            return .none;
        }

        const have_block_result = inst_ty.is_fn_or_has_runtime_bits_ignore_comptime(mod);

        var breaks: BreakList = if (have_block_result) .{ .list = .{} } else .{ .len = 0 };
        defer if (have_block_result) breaks.list.deinit(self.gpa);

        const parent_bb = try self.wip.block(0, "Block");
        try self.blocks.put_no_clobber(self.gpa, inst, .{
            .parent_bb = parent_bb,
            .breaks = &breaks,
        });
        defer assert(self.blocks.remove(inst));

        try self.gen_body_debug_scope(maybe_inline_func, body);

        self.wip.cursor = .{ .block = parent_bb };

        // Create a phi node only if the block returns a value.
        if (have_block_result) {
            const raw_llvm_ty = try o.lower_type(inst_ty);
            const llvm_ty: Builder.Type = ty: {
                // If the zig tag type is a function, this represents an actual function body; not
                // a pointer to it. LLVM IR allows the call instruction to use function bodies instead
                // of function pointers, however the phi makes it a runtime value and therefore
                // the LLVM type has to be wrapped in a pointer.
                if (inst_ty.zig_type_tag(mod) == .Fn or is_by_ref(inst_ty, mod)) {
                    break :ty .ptr;
                }
                break :ty raw_llvm_ty;
            };

            parent_bb.ptr(&self.wip).incoming = @int_cast(breaks.list.len);
            const phi = try self.wip.phi(llvm_ty, "");
            phi.finish(breaks.list.items(.val), breaks.list.items(.bb), &self.wip);
            return phi.to_value();
        } else {
            parent_bb.ptr(&self.wip).incoming = @int_cast(breaks.len);
            return .none;
        }
    }

    fn air_br(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const branch = self.air.instructions.items(.data)[@int_from_enum(inst)].br;
        const block = self.blocks.get(branch.block_inst).?;

        // Add the values to the lists only if the break provides a value.
        const operand_ty = self.type_of(branch.operand);
        const mod = o.module;
        if (operand_ty.is_fn_or_has_runtime_bits_ignore_comptime(mod)) {
            const val = try self.resolve_inst(branch.operand);

            // For the phi node, we need the basic blocks and the values of the
            // break instructions.
            try block.breaks.list.append(self.gpa, .{ .bb = self.wip.cursor.block, .val = val });
        } else block.breaks.len += 1;
        _ = try self.wip.br(block.parent_bb);
        return .none;
    }

    fn air_cond_br(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const pl_op = self.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
        const cond = try self.resolve_inst(pl_op.operand);
        const extra = self.air.extra_data(Air.CondBr, pl_op.payload);
        const then_body: []const Air.Inst.Index = @ptr_cast(self.air.extra[extra.end..][0..extra.data.then_body_len]);
        const else_body: []const Air.Inst.Index = @ptr_cast(self.air.extra[extra.end + then_body.len ..][0..extra.data.else_body_len]);

        const then_block = try self.wip.block(1, "Then");
        const else_block = try self.wip.block(1, "Else");
        _ = try self.wip.br_cond(cond, then_block, else_block);

        self.wip.cursor = .{ .block = then_block };
        try self.gen_body_debug_scope(null, then_body);

        self.wip.cursor = .{ .block = else_block };
        try self.gen_body_debug_scope(null, else_body);

        // No need to reset the insert cursor since this instruction is noreturn.
        return .none;
    }

    fn air_try(self: *FuncGen, body_tail: []const Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const inst = body_tail[0];
        const pl_op = self.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
        const err_union = try self.resolve_inst(pl_op.operand);
        const extra = self.air.extra_data(Air.Try, pl_op.payload);
        const body: []const Air.Inst.Index = @ptr_cast(self.air.extra[extra.end..][0..extra.data.body_len]);
        const err_union_ty = self.type_of(pl_op.operand);
        const payload_ty = self.type_of_index(inst);
        const can_elide_load = if (is_by_ref(payload_ty, mod)) self.can_elide_load(body_tail) else false;
        const is_unused = self.liveness.is_unused(inst);
        return lower_try(self, err_union, body, err_union_ty, false, can_elide_load, is_unused);
    }

    fn air_try_ptr(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
        const extra = self.air.extra_data(Air.TryPtr, ty_pl.payload);
        const err_union_ptr = try self.resolve_inst(extra.data.ptr);
        const body: []const Air.Inst.Index = @ptr_cast(self.air.extra[extra.end..][0..extra.data.body_len]);
        const err_union_ty = self.type_of(extra.data.ptr).child_type(mod);
        const is_unused = self.liveness.is_unused(inst);
        return lower_try(self, err_union_ptr, body, err_union_ty, true, true, is_unused);
    }

    fn lower_try(
        fg: *FuncGen,
        err_union: Builder.Value,
        body: []const Air.Inst.Index,
        err_union_ty: Type,
        operand_is_ptr: bool,
        can_elide_load: bool,
        is_unused: bool,
    ) !Builder.Value {
        const o = fg.dg.object;
        const mod = o.module;
        const payload_ty = err_union_ty.error_union_payload(mod);
        const payload_has_bits = payload_ty.has_runtime_bits_ignore_comptime(mod);
        const err_union_llvm_ty = try o.lower_type(err_union_ty);
        const error_type = try o.error_int_type();

        if (!err_union_ty.error_union_set(mod).error_set_is_empty(mod)) {
            const loaded = loaded: {
                if (!payload_has_bits) {
                    // TODO add alignment to this load
                    break :loaded if (operand_is_ptr)
                        try fg.wip.load(.normal, error_type, err_union, .default, "")
                    else
                        err_union;
                }
                const err_field_index = try err_union_error_offset(payload_ty, mod);
                if (operand_is_ptr or is_by_ref(err_union_ty, mod)) {
                    const err_field_ptr =
                        try fg.wip.gep_struct(err_union_llvm_ty, err_union, err_field_index, "");
                    // TODO add alignment to this load
                    break :loaded try fg.wip.load(
                        .normal,
                        error_type,
                        err_field_ptr,
                        .default,
                        "",
                    );
                }
                break :loaded try fg.wip.extract_value(err_union, &.{err_field_index}, "");
            };
            const zero = try o.builder.int_value(error_type, 0);
            const is_err = try fg.wip.icmp(.ne, loaded, zero, "");

            const return_block = try fg.wip.block(1, "TryRet");
            const continue_block = try fg.wip.block(1, "TryCont");
            _ = try fg.wip.br_cond(is_err, return_block, continue_block);

            fg.wip.cursor = .{ .block = return_block };
            try fg.gen_body_debug_scope(null, body);

            fg.wip.cursor = .{ .block = continue_block };
        }
        if (is_unused) return .none;
        if (!payload_has_bits) return if (operand_is_ptr) err_union else .none;
        const offset = try err_union_payload_offset(payload_ty, mod);
        if (operand_is_ptr) {
            return fg.wip.gep_struct(err_union_llvm_ty, err_union, offset, "");
        } else if (is_by_ref(err_union_ty, mod)) {
            const payload_ptr = try fg.wip.gep_struct(err_union_llvm_ty, err_union, offset, "");
            const payload_alignment = payload_ty.abi_alignment(mod).to_llvm();
            if (is_by_ref(payload_ty, mod)) {
                if (can_elide_load)
                    return payload_ptr;

                return fg.load_by_ref(payload_ptr, payload_ty, payload_alignment, .normal);
            }
            const load_ty = err_union_llvm_ty.struct_fields(&o.builder)[offset];
            return fg.wip.load(.normal, load_ty, payload_ptr, payload_alignment, "");
        }
        return fg.wip.extract_value(err_union, &.{offset}, "");
    }

    fn air_switch_br(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const pl_op = self.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
        const cond = try self.resolve_inst(pl_op.operand);
        const switch_br = self.air.extra_data(Air.SwitchBr, pl_op.payload);
        const else_block = try self.wip.block(1, "Default");
        const llvm_usize = try o.lower_type(Type.usize);
        const cond_int = if (cond.type_of_wip(&self.wip).is_pointer(&o.builder))
            try self.wip.cast(.ptrtoint, cond, llvm_usize, "")
        else
            cond;

        var extra_index: usize = switch_br.end;
        var case_i: u32 = 0;
        var llvm_cases_len: u32 = 0;
        while (case_i < switch_br.data.cases_len) : (case_i += 1) {
            const case = self.air.extra_data(Air.SwitchBr.Case, extra_index);
            const items: []const Air.Inst.Ref =
                @ptr_cast(self.air.extra[case.end..][0..case.data.items_len]);
            const case_body = self.air.extra[case.end + items.len ..][0..case.data.body_len];
            extra_index = case.end + case.data.items_len + case_body.len;

            llvm_cases_len += @int_cast(items.len);
        }

        var wip_switch = try self.wip.@"switch"(cond_int, else_block, llvm_cases_len);
        defer wip_switch.finish(&self.wip);

        extra_index = switch_br.end;
        case_i = 0;
        while (case_i < switch_br.data.cases_len) : (case_i += 1) {
            const case = self.air.extra_data(Air.SwitchBr.Case, extra_index);
            const items: []const Air.Inst.Ref =
                @ptr_cast(self.air.extra[case.end..][0..case.data.items_len]);
            const case_body: []const Air.Inst.Index = @ptr_cast(self.air.extra[case.end + items.len ..][0..case.data.body_len]);
            extra_index = case.end + case.data.items_len + case_body.len;

            const case_block = try self.wip.block(@int_cast(items.len), "Case");

            for (items) |item| {
                const llvm_item = (try self.resolve_inst(item)).to_const().?;
                const llvm_int_item = if (llvm_item.type_of(&o.builder).is_pointer(&o.builder))
                    try o.builder.cast_const(.ptrtoint, llvm_item, llvm_usize)
                else
                    llvm_item;
                try wip_switch.add_case(llvm_int_item, case_block, &self.wip);
            }

            self.wip.cursor = .{ .block = case_block };
            try self.gen_body_debug_scope(null, case_body);
        }

        self.wip.cursor = .{ .block = else_block };
        const else_body: []const Air.Inst.Index = @ptr_cast(self.air.extra[extra_index..][0..switch_br.data.else_body_len]);
        if (else_body.len != 0) {
            try self.gen_body_debug_scope(null, else_body);
        } else {
            _ = try self.wip.@"unreachable"();
        }

        // No need to reset the insert cursor since this instruction is noreturn.
        return .none;
    }

    fn air_loop(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
        const loop = self.air.extra_data(Air.Block, ty_pl.payload);
        const body: []const Air.Inst.Index = @ptr_cast(self.air.extra[loop.end..][0..loop.data.body_len]);
        const loop_block = try self.wip.block(2, "Loop");
        _ = try self.wip.br(loop_block);

        self.wip.cursor = .{ .block = loop_block };
        try self.gen_body_debug_scope(null, body);

        // TODO instead of this logic, change AIR to have the property that
        // every block is guaranteed to end with a noreturn instruction.
        // Then we can simply rely on the fact that a repeat or break instruction
        // would have been emitted already. Also the main loop in gen_body can
        // be while(true) instead of for(body), which will eliminate 1 branch on
        // a hot path.
        if (body.len == 0 or !self.type_of_index(body[body.len - 1]).is_no_return(mod)) {
            _ = try self.wip.br(loop_block);
        }
        return .none;
    }

    fn air_array_to_slice(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
        const operand_ty = self.type_of(ty_op.operand);
        const array_ty = operand_ty.child_type(mod);
        const llvm_usize = try o.lower_type(Type.usize);
        const len = try o.builder.int_value(llvm_usize, array_ty.array_len(mod));
        const slice_llvm_ty = try o.lower_type(self.type_of_index(inst));
        const operand = try self.resolve_inst(ty_op.operand);
        if (!array_ty.has_runtime_bits_ignore_comptime(mod))
            return self.wip.build_aggregate(slice_llvm_ty, &.{ operand, len }, "");
        const ptr = try self.wip.gep(.inbounds, try o.lower_type(array_ty), operand, &.{
            try o.builder.int_value(llvm_usize, 0), try o.builder.int_value(llvm_usize, 0),
        }, "");
        return self.wip.build_aggregate(slice_llvm_ty, &.{ ptr, len }, "");
    }

    fn air_float_from_int(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

        const workaround_operand = try self.resolve_inst(ty_op.operand);
        const operand_ty = self.type_of(ty_op.operand);
        const operand_scalar_ty = operand_ty.scalar_type(mod);
        const is_signed_int = operand_scalar_ty.is_signed_int(mod);

        const operand = o: {
            // Work around LLVM bug. See https://github.com/ziglang/zig/issues/17381.
            const bit_size = operand_scalar_ty.bit_size(mod);
            for ([_]u8{ 8, 16, 32, 64, 128 }) |b| {
                if (bit_size < b) {
                    break :o try self.wip.cast(
                        if (is_signed_int) .sext else .zext,
                        workaround_operand,
                        try o.builder.int_type(b),
                        "",
                    );
                } else if (bit_size == b) {
                    break :o workaround_operand;
                }
            }
            break :o workaround_operand;
        };

        const dest_ty = self.type_of_index(inst);
        const dest_scalar_ty = dest_ty.scalar_type(mod);
        const dest_llvm_ty = try o.lower_type(dest_ty);
        const target = mod.get_target();

        if (intrinsics_allowed(dest_scalar_ty, target)) return self.wip.conv(
            if (is_signed_int) .signed else .unsigned,
            operand,
            dest_llvm_ty,
            "",
        );

        const rt_int_bits = compiler_rt_int_bits(@int_cast(operand_scalar_ty.bit_size(mod)));
        const rt_int_ty = try o.builder.int_type(rt_int_bits);
        var extended = try self.wip.conv(
            if (is_signed_int) .signed else .unsigned,
            operand,
            rt_int_ty,
            "",
        );
        const dest_bits = dest_scalar_ty.float_bits(target);
        const compiler_rt_operand_abbrev = compiler_rt_int_abbrev(rt_int_bits);
        const compiler_rt_dest_abbrev = compiler_rt_float_abbrev(dest_bits);
        const sign_prefix = if (is_signed_int) "" else "un";
        const fn_name = try o.builder.strtab_string_fmt("__float{s}{s}i{s}f", .{
            sign_prefix,
            compiler_rt_operand_abbrev,
            compiler_rt_dest_abbrev,
        });

        var param_type = rt_int_ty;
        if (rt_int_bits == 128 and (target.os.tag == .windows and target.cpu.arch == .x86_64)) {
            // On Windows x86-64, "ti" functions must use Vector(2, u64) instead of the standard
            // i128 calling convention to adhere to the ABI that LLVM expects compiler-rt to have.
            param_type = try o.builder.vector_type(.normal, 2, .i64);
            extended = try self.wip.cast(.bitcast, extended, param_type, "");
        }

        const libc_fn = try self.get_libc_function(fn_name, &.{param_type}, dest_llvm_ty);
        return self.wip.call(
            .normal,
            .ccc,
            .none,
            libc_fn.type_of(&o.builder),
            libc_fn.to_value(&o.builder),
            &.{extended},
            "",
        );
    }

    fn air_int_from_float(
        self: *FuncGen,
        inst: Air.Inst.Index,
        fast: Builder.FastMathKind,
    ) !Builder.Value {
        _ = fast;

        const o = self.dg.object;
        const mod = o.module;
        const target = mod.get_target();
        const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

        const operand = try self.resolve_inst(ty_op.operand);
        const operand_ty = self.type_of(ty_op.operand);
        const operand_scalar_ty = operand_ty.scalar_type(mod);

        const dest_ty = self.type_of_index(inst);
        const dest_scalar_ty = dest_ty.scalar_type(mod);
        const dest_llvm_ty = try o.lower_type(dest_ty);

        if (intrinsics_allowed(operand_scalar_ty, target)) {
            // TODO set fast math flag
            return self.wip.conv(
                if (dest_scalar_ty.is_signed_int(mod)) .signed else .unsigned,
                operand,
                dest_llvm_ty,
                "",
            );
        }

        const rt_int_bits = compiler_rt_int_bits(@int_cast(dest_scalar_ty.bit_size(mod)));
        const ret_ty = try o.builder.int_type(rt_int_bits);
        const libc_ret_ty = if (rt_int_bits == 128 and (target.os.tag == .windows and target.cpu.arch == .x86_64)) b: {
            // On Windows x86-64, "ti" functions must use Vector(2, u64) instead of the standard
            // i128 calling convention to adhere to the ABI that LLVM expects compiler-rt to have.
            break :b try o.builder.vector_type(.normal, 2, .i64);
        } else ret_ty;

        const operand_bits = operand_scalar_ty.float_bits(target);
        const compiler_rt_operand_abbrev = compiler_rt_float_abbrev(operand_bits);

        const compiler_rt_dest_abbrev = compiler_rt_int_abbrev(rt_int_bits);
        const sign_prefix = if (dest_scalar_ty.is_signed_int(mod)) "" else "uns";

        const fn_name = try o.builder.strtab_string_fmt("__fix{s}{s}f{s}i", .{
            sign_prefix,
            compiler_rt_operand_abbrev,
            compiler_rt_dest_abbrev,
        });

        const operand_llvm_ty = try o.lower_type(operand_ty);
        const libc_fn = try self.get_libc_function(fn_name, &.{operand_llvm_ty}, libc_ret_ty);
        var result = try self.wip.call(
            .normal,
            .ccc,
            .none,
            libc_fn.type_of(&o.builder),
            libc_fn.to_value(&o.builder),
            &.{operand},
            "",
        );

        if (libc_ret_ty != ret_ty) result = try self.wip.cast(.bitcast, result, ret_ty, "");
        if (ret_ty != dest_llvm_ty) result = try self.wip.cast(.trunc, result, dest_llvm_ty, "");
        return result;
    }

    fn slice_or_array_ptr(fg: *FuncGen, ptr: Builder.Value, ty: Type) Allocator.Error!Builder.Value {
        const o = fg.dg.object;
        const mod = o.module;
        return if (ty.is_slice(mod)) fg.wip.extract_value(ptr, &.{0}, "") else ptr;
    }

    fn slice_or_array_len_in_bytes(fg: *FuncGen, ptr: Builder.Value, ty: Type) Allocator.Error!Builder.Value {
        const o = fg.dg.object;
        const mod = o.module;
        const llvm_usize = try o.lower_type(Type.usize);
        switch (ty.ptr_size(mod)) {
            .Slice => {
                const len = try fg.wip.extract_value(ptr, &.{1}, "");
                const elem_ty = ty.child_type(mod);
                const abi_size = elem_ty.abi_size(mod);
                if (abi_size == 1) return len;
                const abi_size_llvm_val = try o.builder.int_value(llvm_usize, abi_size);
                return fg.wip.bin(.@"mul nuw", len, abi_size_llvm_val, "");
            },
            .One => {
                const array_ty = ty.child_type(mod);
                const elem_ty = array_ty.child_type(mod);
                const abi_size = elem_ty.abi_size(mod);
                return o.builder.int_value(llvm_usize, array_ty.array_len(mod) * abi_size);
            },
            .Many, .C => unreachable,
        }
    }

    fn air_slice_field(self: *FuncGen, inst: Air.Inst.Index, index: u32) !Builder.Value {
        const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
        const operand = try self.resolve_inst(ty_op.operand);
        return self.wip.extract_value(operand, &.{index}, "");
    }

    fn air_ptr_slice_field_ptr(self: *FuncGen, inst: Air.Inst.Index, index: c_uint) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
        const slice_ptr = try self.resolve_inst(ty_op.operand);
        const slice_ptr_ty = self.type_of(ty_op.operand);
        const slice_llvm_ty = try o.lower_ptr_elem_ty(slice_ptr_ty.child_type(mod));

        return self.wip.gep_struct(slice_llvm_ty, slice_ptr, index, "");
    }

    fn air_slice_elem_val(self: *FuncGen, body_tail: []const Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const inst = body_tail[0];
        const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
        const slice_ty = self.type_of(bin_op.lhs);
        const slice = try self.resolve_inst(bin_op.lhs);
        const index = try self.resolve_inst(bin_op.rhs);
        const elem_ty = slice_ty.child_type(mod);
        const llvm_elem_ty = try o.lower_ptr_elem_ty(elem_ty);
        const base_ptr = try self.wip.extract_value(slice, &.{0}, "");
        const ptr = try self.wip.gep(.inbounds, llvm_elem_ty, base_ptr, &.{index}, "");
        if (is_by_ref(elem_ty, mod)) {
            if (self.can_elide_load(body_tail))
                return ptr;

            const elem_alignment = elem_ty.abi_alignment(mod).to_llvm();
            return self.load_by_ref(ptr, elem_ty, elem_alignment, .normal);
        }

        return self.load(ptr, slice_ty);
    }

    fn air_slice_elem_ptr(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
        const bin_op = self.air.extra_data(Air.Bin, ty_pl.payload).data;
        const slice_ty = self.type_of(bin_op.lhs);

        const slice = try self.resolve_inst(bin_op.lhs);
        const index = try self.resolve_inst(bin_op.rhs);
        const llvm_elem_ty = try o.lower_ptr_elem_ty(slice_ty.child_type(mod));
        const base_ptr = try self.wip.extract_value(slice, &.{0}, "");
        return self.wip.gep(.inbounds, llvm_elem_ty, base_ptr, &.{index}, "");
    }

    fn air_array_elem_val(self: *FuncGen, body_tail: []const Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const inst = body_tail[0];

        const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
        const array_ty = self.type_of(bin_op.lhs);
        const array_llvm_val = try self.resolve_inst(bin_op.lhs);
        const rhs = try self.resolve_inst(bin_op.rhs);
        const array_llvm_ty = try o.lower_type(array_ty);
        const elem_ty = array_ty.child_type(mod);
        if (is_by_ref(array_ty, mod)) {
            const indices: [2]Builder.Value = .{
                try o.builder.int_value(try o.lower_type(Type.usize), 0), rhs,
            };
            if (is_by_ref(elem_ty, mod)) {
                const elem_ptr =
                    try self.wip.gep(.inbounds, array_llvm_ty, array_llvm_val, &indices, "");
                if (can_elide_load(self, body_tail)) return elem_ptr;
                const elem_alignment = elem_ty.abi_alignment(mod).to_llvm();
                return self.load_by_ref(elem_ptr, elem_ty, elem_alignment, .normal);
            } else {
                const elem_ptr =
                    try self.wip.gep(.inbounds, array_llvm_ty, array_llvm_val, &indices, "");
                return self.load_truncate(.normal, elem_ty, elem_ptr, .default);
            }
        }

        // This branch can be reached for vectors, which are always by-value.
        return self.wip.extract_element(array_llvm_val, rhs, "");
    }

    fn air_ptr_elem_val(self: *FuncGen, body_tail: []const Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const inst = body_tail[0];
        const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
        const ptr_ty = self.type_of(bin_op.lhs);
        const elem_ty = ptr_ty.child_type(mod);
        const llvm_elem_ty = try o.lower_ptr_elem_ty(elem_ty);
        const base_ptr = try self.resolve_inst(bin_op.lhs);
        const rhs = try self.resolve_inst(bin_op.rhs);
        // TODO: when we go fully opaque pointers in LLVM 16 we can remove this branch
        const ptr = try self.wip.gep(.inbounds, llvm_elem_ty, base_ptr, if (ptr_ty.is_single_pointer(mod))
            // If this is a single-item pointer to an array, we need another index in the GEP.
            &.{ try o.builder.int_value(try o.lower_type(Type.usize), 0), rhs }
        else
            &.{rhs}, "");
        if (is_by_ref(elem_ty, mod)) {
            if (self.can_elide_load(body_tail)) return ptr;
            const elem_alignment = elem_ty.abi_alignment(mod).to_llvm();
            return self.load_by_ref(ptr, elem_ty, elem_alignment, .normal);
        }

        return self.load(ptr, ptr_ty);
    }

    fn air_ptr_elem_ptr(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
        const bin_op = self.air.extra_data(Air.Bin, ty_pl.payload).data;
        const ptr_ty = self.type_of(bin_op.lhs);
        const elem_ty = ptr_ty.child_type(mod);
        if (!elem_ty.has_runtime_bits_ignore_comptime(mod)) return self.resolve_inst(bin_op.lhs);

        const base_ptr = try self.resolve_inst(bin_op.lhs);
        const rhs = try self.resolve_inst(bin_op.rhs);

        const elem_ptr = ty_pl.ty.to_type();
        if (elem_ptr.ptr_info(mod).flags.vector_index != .none) return base_ptr;

        const llvm_elem_ty = try o.lower_ptr_elem_ty(elem_ty);
        return self.wip.gep(.inbounds, llvm_elem_ty, base_ptr, if (ptr_ty.is_single_pointer(mod))
            // If this is a single-item pointer to an array, we need another index in the GEP.
            &.{ try o.builder.int_value(try o.lower_type(Type.usize), 0), rhs }
        else
            &.{rhs}, "");
    }

    fn air_struct_field_ptr(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
        const struct_field = self.air.extra_data(Air.StructField, ty_pl.payload).data;
        const struct_ptr = try self.resolve_inst(struct_field.struct_operand);
        const struct_ptr_ty = self.type_of(struct_field.struct_operand);
        return self.field_ptr(inst, struct_ptr, struct_ptr_ty, struct_field.field_index);
    }

    fn air_struct_field_ptr_index(
        self: *FuncGen,
        inst: Air.Inst.Index,
        field_index: u32,
    ) !Builder.Value {
        const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
        const struct_ptr = try self.resolve_inst(ty_op.operand);
        const struct_ptr_ty = self.type_of(ty_op.operand);
        return self.field_ptr(inst, struct_ptr, struct_ptr_ty, field_index);
    }

    fn air_struct_field_val(self: *FuncGen, body_tail: []const Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const inst = body_tail[0];
        const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
        const struct_field = self.air.extra_data(Air.StructField, ty_pl.payload).data;
        const struct_ty = self.type_of(struct_field.struct_operand);
        const struct_llvm_val = try self.resolve_inst(struct_field.struct_operand);
        const field_index = struct_field.field_index;
        const field_ty = struct_ty.struct_field_type(field_index, mod);
        if (!field_ty.has_runtime_bits_ignore_comptime(mod)) return .none;

        if (!is_by_ref(struct_ty, mod)) {
            assert(!is_by_ref(field_ty, mod));
            switch (struct_ty.zig_type_tag(mod)) {
                .Struct => switch (struct_ty.container_layout(mod)) {
                    .@"packed" => {
                        const struct_type = mod.type_to_struct(struct_ty).?;
                        const bit_offset = mod.struct_packed_field_bit_offset(struct_type, field_index);
                        const containing_int = struct_llvm_val;
                        const shift_amt =
                            try o.builder.int_value(containing_int.type_of_wip(&self.wip), bit_offset);
                        const shifted_value = try self.wip.bin(.lshr, containing_int, shift_amt, "");
                        const elem_llvm_ty = try o.lower_type(field_ty);
                        if (field_ty.zig_type_tag(mod) == .Float or field_ty.zig_type_tag(mod) == .Vector) {
                            const same_size_int = try o.builder.int_type(@int_cast(field_ty.bit_size(mod)));
                            const truncated_int =
                                try self.wip.cast(.trunc, shifted_value, same_size_int, "");
                            return self.wip.cast(.bitcast, truncated_int, elem_llvm_ty, "");
                        } else if (field_ty.is_ptr_at_runtime(mod)) {
                            const same_size_int = try o.builder.int_type(@int_cast(field_ty.bit_size(mod)));
                            const truncated_int =
                                try self.wip.cast(.trunc, shifted_value, same_size_int, "");
                            return self.wip.cast(.inttoptr, truncated_int, elem_llvm_ty, "");
                        }
                        return self.wip.cast(.trunc, shifted_value, elem_llvm_ty, "");
                    },
                    else => {
                        const llvm_field_index = o.llvm_field_index(struct_ty, field_index).?;
                        return self.wip.extract_value(struct_llvm_val, &.{llvm_field_index}, "");
                    },
                },
                .Union => {
                    assert(struct_ty.container_layout(mod) == .@"packed");
                    const containing_int = struct_llvm_val;
                    const elem_llvm_ty = try o.lower_type(field_ty);
                    if (field_ty.zig_type_tag(mod) == .Float or field_ty.zig_type_tag(mod) == .Vector) {
                        const same_size_int = try o.builder.int_type(@int_cast(field_ty.bit_size(mod)));
                        const truncated_int =
                            try self.wip.cast(.trunc, containing_int, same_size_int, "");
                        return self.wip.cast(.bitcast, truncated_int, elem_llvm_ty, "");
                    } else if (field_ty.is_ptr_at_runtime(mod)) {
                        const same_size_int = try o.builder.int_type(@int_cast(field_ty.bit_size(mod)));
                        const truncated_int =
                            try self.wip.cast(.trunc, containing_int, same_size_int, "");
                        return self.wip.cast(.inttoptr, truncated_int, elem_llvm_ty, "");
                    }
                    return self.wip.cast(.trunc, containing_int, elem_llvm_ty, "");
                },
                else => unreachable,
            }
        }

        switch (struct_ty.zig_type_tag(mod)) {
            .Struct => {
                const layout = struct_ty.container_layout(mod);
                assert(layout != .@"packed");
                const struct_llvm_ty = try o.lower_type(struct_ty);
                const llvm_field_index = o.llvm_field_index(struct_ty, field_index).?;
                const field_ptr =
                    try self.wip.gep_struct(struct_llvm_ty, struct_llvm_val, llvm_field_index, "");
                const alignment = struct_ty.struct_field_align(field_index, mod);
                const field_ptr_ty = try mod.ptr_type(.{
                    .child = field_ty.to_intern(),
                    .flags = .{ .alignment = alignment },
                });
                if (is_by_ref(field_ty, mod)) {
                    if (can_elide_load(self, body_tail))
                        return field_ptr;

                    assert(alignment != .none);
                    const field_alignment = alignment.to_llvm();
                    return self.load_by_ref(field_ptr, field_ty, field_alignment, .normal);
                } else {
                    return self.load(field_ptr, field_ptr_ty);
                }
            },
            .Union => {
                const union_llvm_ty = try o.lower_type(struct_ty);
                const layout = struct_ty.union_get_layout(mod);
                const payload_index = @int_from_bool(layout.tag_align.compare(.gte, layout.payload_align));
                const field_ptr =
                    try self.wip.gep_struct(union_llvm_ty, struct_llvm_val, payload_index, "");
                const payload_alignment = layout.payload_align.to_llvm();
                if (is_by_ref(field_ty, mod)) {
                    if (can_elide_load(self, body_tail)) return field_ptr;
                    return self.load_by_ref(field_ptr, field_ty, payload_alignment, .normal);
                } else {
                    return self.load_truncate(.normal, field_ty, field_ptr, payload_alignment);
                }
            },
            else => unreachable,
        }
    }

    fn air_field_parent_ptr(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
        const extra = self.air.extra_data(Air.FieldParentPtr, ty_pl.payload).data;

        const field_ptr = try self.resolve_inst(extra.field_ptr);

        const parent_ty = ty_pl.ty.to_type().child_type(mod);
        const field_offset = parent_ty.struct_field_offset(extra.field_index, mod);
        if (field_offset == 0) return field_ptr;

        const res_ty = try o.lower_type(ty_pl.ty.to_type());
        const llvm_usize = try o.lower_type(Type.usize);

        const field_ptr_int = try self.wip.cast(.ptrtoint, field_ptr, llvm_usize, "");
        const base_ptr_int = try self.wip.bin(
            .@"sub nuw",
            field_ptr_int,
            try o.builder.int_value(llvm_usize, field_offset),
            "",
        );
        return self.wip.cast(.inttoptr, base_ptr_int, res_ty, "");
    }

    fn air_not(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
        const operand = try self.resolve_inst(ty_op.operand);

        return self.wip.not(operand, "");
    }

    fn air_unreach(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        _ = inst;
        _ = try self.wip.@"unreachable"();
        return .none;
    }

    fn air_dbg_stmt(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const dbg_stmt = self.air.instructions.items(.data)[@int_from_enum(inst)].dbg_stmt;
        self.prev_dbg_line = @int_cast(self.base_line + dbg_stmt.line + 1);
        self.prev_dbg_column = @int_cast(dbg_stmt.column + 1);

        self.wip.debug_location = .{
            .location = .{
                .line = self.prev_dbg_line,
                .column = self.prev_dbg_column,
                .scope = self.scope,
                .inlined_at = try self.inlined.to_metadata(self.wip.builder),
            },
        };

        return .none;
    }

    fn air_dbg_inline_block(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
        const extra = self.air.extra_data(Air.DbgInlineBlock, ty_pl.payload);
        return self.lower_block(inst, extra.data.func, @ptr_cast(self.air.extra[extra.end..][0..extra.data.body_len]));
    }

    fn air_dbg_var_ptr(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const pl_op = self.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
        const operand = try self.resolve_inst(pl_op.operand);
        const name = self.air.null_terminated_string(pl_op.payload);
        const ptr_ty = self.type_of(pl_op.operand);

        const debug_local_var = try o.builder.debug_local_var(
            try o.builder.metadata_string(name),
            self.file,
            self.scope,
            self.prev_dbg_line,
            try o.lower_debug_type(ptr_ty.child_type(mod)),
        );

        _ = try self.wip.call_intrinsic(
            .normal,
            .none,
            .@"dbg.declare",
            &.{},
            &.{
                (try self.wip.debug_value(operand)).to_value(),
                debug_local_var.to_value(),
                (try o.builder.debug_expression(&.{})).to_value(),
            },
            "",
        );

        return .none;
    }

    fn air_dbg_var_val(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const pl_op = self.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
        const operand = try self.resolve_inst(pl_op.operand);
        const operand_ty = self.type_of(pl_op.operand);
        const name = self.air.null_terminated_string(pl_op.payload);

        if (need_dbg_var_workaround(o)) return .none;

        const debug_local_var = try o.builder.debug_local_var(
            try o.builder.metadata_string(name),
            self.file,
            self.scope,
            self.prev_dbg_line,
            try o.lower_debug_type(operand_ty),
        );

        const zcu = o.module;
        const owner_mod = self.dg.owner_module();
        if (is_by_ref(operand_ty, zcu)) {
            _ = try self.wip.call_intrinsic(
                .normal,
                .none,
                .@"dbg.declare",
                &.{},
                &.{
                    (try self.wip.debug_value(operand)).to_value(),
                    debug_local_var.to_value(),
                    (try o.builder.debug_expression(&.{})).to_value(),
                },
                "",
            );
        } else if (owner_mod.optimize_mode == .Debug) {
            const alignment = operand_ty.abi_alignment(zcu).to_llvm();
            const alloca = try self.build_alloca(operand.type_of_wip(&self.wip), alignment);
            _ = try self.wip.store(.normal, operand, alloca, alignment);
            _ = try self.wip.call_intrinsic(
                .normal,
                .none,
                .@"dbg.declare",
                &.{},
                &.{
                    (try self.wip.debug_value(alloca)).to_value(),
                    debug_local_var.to_value(),
                    (try o.builder.debug_expression(&.{})).to_value(),
                },
                "",
            );
        } else {
            _ = try self.wip.call_intrinsic(
                .normal,
                .none,
                .@"dbg.value",
                &.{},
                &.{
                    (try self.wip.debug_value(operand)).to_value(),
                    debug_local_var.to_value(),
                    (try o.builder.debug_expression(&.{})).to_value(),
                },
                "",
            );
        }
        return .none;
    }

    fn air_assembly(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        // Eventually, the Zig compiler needs to be reworked to have inline
        // assembly go through the same parsing code regardless of backend, and
        // have LLVM-flavored inline assembly be *output* from that assembler.
        // We don't have such an assembler implemented yet though. For now,
        // this implementation feeds the inline assembly code directly to LLVM.

        const o = self.dg.object;
        const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
        const extra = self.air.extra_data(Air.Asm, ty_pl.payload);
        const is_volatile = @as(u1, @truncate(extra.data.flags >> 31)) != 0;
        const clobbers_len: u31 = @truncate(extra.data.flags);
        var extra_i: usize = extra.end;

        const outputs: []const Air.Inst.Ref = @ptr_cast(self.air.extra[extra_i..][0..extra.data.outputs_len]);
        extra_i += outputs.len;
        const inputs: []const Air.Inst.Ref = @ptr_cast(self.air.extra[extra_i..][0..extra.data.inputs_len]);
        extra_i += inputs.len;

        var llvm_constraints: std.ArrayListUnmanaged(u8) = .{};
        defer llvm_constraints.deinit(self.gpa);

        var arena_allocator = std.heap.ArenaAllocator.init(self.gpa);
        defer arena_allocator.deinit();
        const arena = arena_allocator.allocator();

        // The exact number of return / parameter values depends on which output values
        // are passed by reference as indirect outputs (determined below).
        const max_return_count = outputs.len;
        const llvm_ret_types = try arena.alloc(Builder.Type, max_return_count);
        const llvm_ret_indirect = try arena.alloc(bool, max_return_count);
        const llvm_rw_vals = try arena.alloc(Builder.Value, max_return_count);

        const max_param_count = max_return_count + inputs.len + outputs.len;
        const llvm_param_types = try arena.alloc(Builder.Type, max_param_count);
        const llvm_param_values = try arena.alloc(Builder.Value, max_param_count);
        // This stores whether we need to add an elementtype attribute and
        // if so, the element type itself.
        const llvm_param_attrs = try arena.alloc(Builder.Type, max_param_count);
        const mod = o.module;
        const target = mod.get_target();

        var llvm_ret_i: usize = 0;
        var llvm_param_i: usize = 0;
        var total_i: u16 = 0;

        var name_map: std.StringArrayHashMapUnmanaged(u16) = .{};
        try name_map.ensure_unused_capacity(arena, max_param_count);

        var rw_extra_i = extra_i;
        for (outputs, llvm_ret_indirect, llvm_rw_vals) |output, *is_indirect, *llvm_rw_val| {
            const extra_bytes = std.mem.slice_as_bytes(self.air.extra[extra_i..]);
            const constraint = std.mem.slice_to(std.mem.slice_as_bytes(self.air.extra[extra_i..]), 0);
            const name = std.mem.slice_to(extra_bytes[constraint.len + 1 ..], 0);
            // This equation accounts for the fact that even if we have exactly 4 bytes
            // for the string, we still use the next u32 for the null terminator.
            extra_i += (constraint.len + name.len + (2 + 3)) / 4;

            try llvm_constraints.ensure_unused_capacity(self.gpa, constraint.len + 3);
            if (total_i != 0) {
                llvm_constraints.append_assume_capacity(',');
            }
            llvm_constraints.append_assume_capacity('=');

            if (output != .none) {
                const output_inst = try self.resolve_inst(output);
                const output_ty = self.type_of(output);
                assert(output_ty.zig_type_tag(mod) == .Pointer);
                const elem_llvm_ty = try o.lower_ptr_elem_ty(output_ty.child_type(mod));

                switch (constraint[0]) {
                    '=' => {},
                    '+' => llvm_rw_val.* = output_inst,
                    else => return self.todo("unsupported output constraint on output type '{c}'", .{
                        constraint[0],
                    }),
                }

                // Pass any non-return outputs indirectly, if the constraint accepts a memory location
                is_indirect.* = constraint_allows_memory(constraint);
                if (is_indirect.*) {
                    // Pass the result by reference as an indirect output (e.g. "=*m")
                    llvm_constraints.append_assume_capacity('*');

                    llvm_param_values[llvm_param_i] = output_inst;
                    llvm_param_types[llvm_param_i] = output_inst.type_of_wip(&self.wip);
                    llvm_param_attrs[llvm_param_i] = elem_llvm_ty;
                    llvm_param_i += 1;
                } else {
                    // Pass the result directly (e.g. "=r")
                    llvm_ret_types[llvm_ret_i] = elem_llvm_ty;
                    llvm_ret_i += 1;
                }
            } else {
                switch (constraint[0]) {
                    '=' => {},
                    else => return self.todo("unsupported output constraint on result type '{s}'", .{
                        constraint,
                    }),
                }

                is_indirect.* = false;

                const ret_ty = self.type_of_index(inst);
                llvm_ret_types[llvm_ret_i] = try o.lower_type(ret_ty);
                llvm_ret_i += 1;
            }

            // LLVM uses commas internally to separate different constraints,
            // alternative constraints are achieved with pipes.
            // We still allow the user to use commas in a way that is similar
            // to GCC's inline assembly.
            // http://llvm.org/docs/LangRef.html#constraint-codes
            for (constraint[1..]) |byte| {
                switch (byte) {
                    ',' => llvm_constraints.append_assume_capacity('|'),
                    '*' => {}, // Indirect outputs are handled above
                    else => llvm_constraints.append_assume_capacity(byte),
                }
            }

            if (!std.mem.eql(u8, name, "_")) {
                const gop = name_map.get_or_put_assume_capacity(name);
                if (gop.found_existing) return self.todo("duplicate asm output name '{s}'", .{name});
                gop.value_ptr.* = total_i;
            }
            total_i += 1;
        }

        for (inputs) |input| {
            const extra_bytes = std.mem.slice_as_bytes(self.air.extra[extra_i..]);
            const constraint = std.mem.slice_to(extra_bytes, 0);
            const name = std.mem.slice_to(extra_bytes[constraint.len + 1 ..], 0);
            // This equation accounts for the fact that even if we have exactly 4 bytes
            // for the string, we still use the next u32 for the null terminator.
            extra_i += (constraint.len + name.len + (2 + 3)) / 4;

            const arg_llvm_value = try self.resolve_inst(input);
            const arg_ty = self.type_of(input);
            const is_by_ref = is_by_ref(arg_ty, mod);
            if (is_by_ref) {
                if (constraint_allows_memory(constraint)) {
                    llvm_param_values[llvm_param_i] = arg_llvm_value;
                    llvm_param_types[llvm_param_i] = arg_llvm_value.type_of_wip(&self.wip);
                } else {
                    const alignment = arg_ty.abi_alignment(mod).to_llvm();
                    const arg_llvm_ty = try o.lower_type(arg_ty);
                    const load_inst =
                        try self.wip.load(.normal, arg_llvm_ty, arg_llvm_value, alignment, "");
                    llvm_param_values[llvm_param_i] = load_inst;
                    llvm_param_types[llvm_param_i] = arg_llvm_ty;
                }
            } else {
                if (constraint_allows_register(constraint)) {
                    llvm_param_values[llvm_param_i] = arg_llvm_value;
                    llvm_param_types[llvm_param_i] = arg_llvm_value.type_of_wip(&self.wip);
                } else {
                    const alignment = arg_ty.abi_alignment(mod).to_llvm();
                    const arg_ptr = try self.build_alloca(arg_llvm_value.type_of_wip(&self.wip), alignment);
                    _ = try self.wip.store(.normal, arg_llvm_value, arg_ptr, alignment);
                    llvm_param_values[llvm_param_i] = arg_ptr;
                    llvm_param_types[llvm_param_i] = arg_ptr.type_of_wip(&self.wip);
                }
            }

            try llvm_constraints.ensure_unused_capacity(self.gpa, constraint.len + 1);
            if (total_i != 0) {
                llvm_constraints.append_assume_capacity(',');
            }
            for (constraint) |byte| {
                llvm_constraints.append_assume_capacity(switch (byte) {
                    ',' => '|',
                    else => byte,
                });
            }

            if (!std.mem.eql(u8, name, "_")) {
                const gop = name_map.get_or_put_assume_capacity(name);
                if (gop.found_existing) return self.todo("duplicate asm input name '{s}'", .{name});
                gop.value_ptr.* = total_i;
            }

            // In the case of indirect inputs, LLVM requires the callsite to have
            // an elementtype(<ty>) attribute.
            llvm_param_attrs[llvm_param_i] = if (constraint[0] == '*')
                try o.lower_ptr_elem_ty(if (is_by_ref) arg_ty else arg_ty.child_type(mod))
            else
                .none;

            llvm_param_i += 1;
            total_i += 1;
        }

        for (outputs, llvm_ret_indirect, llvm_rw_vals, 0..) |output, is_indirect, llvm_rw_val, output_index| {
            const extra_bytes = std.mem.slice_as_bytes(self.air.extra[rw_extra_i..]);
            const constraint = std.mem.slice_to(std.mem.slice_as_bytes(self.air.extra[rw_extra_i..]), 0);
            const name = std.mem.slice_to(extra_bytes[constraint.len + 1 ..], 0);
            // This equation accounts for the fact that even if we have exactly 4 bytes
            // for the string, we still use the next u32 for the null terminator.
            rw_extra_i += (constraint.len + name.len + (2 + 3)) / 4;

            if (constraint[0] != '+') continue;

            const rw_ty = self.type_of(output);
            const llvm_elem_ty = try o.lower_ptr_elem_ty(rw_ty.child_type(mod));
            if (is_indirect) {
                llvm_param_values[llvm_param_i] = llvm_rw_val;
                llvm_param_types[llvm_param_i] = llvm_rw_val.type_of_wip(&self.wip);
            } else {
                const alignment = rw_ty.abi_alignment(mod).to_llvm();
                const loaded = try self.wip.load(.normal, llvm_elem_ty, llvm_rw_val, alignment, "");
                llvm_param_values[llvm_param_i] = loaded;
                llvm_param_types[llvm_param_i] = llvm_elem_ty;
            }

            try llvm_constraints.writer(self.gpa).print(",{d}", .{output_index});

            // In the case of indirect inputs, LLVM requires the callsite to have
            // an elementtype(<ty>) attribute.
            llvm_param_attrs[llvm_param_i] = if (is_indirect) llvm_elem_ty else .none;

            llvm_param_i += 1;
            total_i += 1;
        }

        {
            var clobber_i: u32 = 0;
            while (clobber_i < clobbers_len) : (clobber_i += 1) {
                const clobber = std.mem.slice_to(std.mem.slice_as_bytes(self.air.extra[extra_i..]), 0);
                // This equation accounts for the fact that even if we have exactly 4 bytes
                // for the string, we still use the next u32 for the null terminator.
                extra_i += clobber.len / 4 + 1;

                try llvm_constraints.ensure_unused_capacity(self.gpa, clobber.len + 4);
                if (total_i != 0) {
                    llvm_constraints.append_assume_capacity(',');
                }
                llvm_constraints.append_slice_assume_capacity("~{");
                llvm_constraints.append_slice_assume_capacity(clobber);
                llvm_constraints.append_slice_assume_capacity("}");

                total_i += 1;
            }
        }

        // We have finished scanning through all inputs/outputs, so the number of
        // parameters and return values is known.
        const param_count = llvm_param_i;
        const return_count = llvm_ret_i;

        // For some targets, Clang unconditionally adds some clobbers to all inline assembly.
        // While this is probably not strictly necessary, if we don't follow Clang's lead
        // here then we may risk tripping LLVM bugs since anything not used by Clang tends
        // to be buggy and regress often.
        switch (target.cpu.arch) {
            .x86_64, .x86 => {
                if (total_i != 0) try llvm_constraints.append(self.gpa, ',');
                try llvm_constraints.append_slice(self.gpa, "~{dirflag},~{fpsr},~{flags}");
                total_i += 3;
            },
            .mips, .mipsel, .mips64, .mips64el => {
                if (total_i != 0) try llvm_constraints.append(self.gpa, ',');
                try llvm_constraints.append_slice(self.gpa, "~{$1}");
                total_i += 1;
            },
            else => {},
        }

        const asm_source = std.mem.slice_as_bytes(self.air.extra[extra_i..])[0..extra.data.source_len];

        // hackety hacks until stage2 has proper inline asm in the frontend.
        var rendered_template = std.ArrayList(u8).init(self.gpa);
        defer rendered_template.deinit();

        const State = enum { start, percent, input, modifier };

        var state: State = .start;

        var name_start: usize = undefined;
        var modifier_start: usize = undefined;
        for (asm_source, 0..) |byte, i| {
            switch (state) {
                .start => switch (byte) {
                    '%' => state = .percent,
                    '$' => try rendered_template.append_slice("$$"),
                    else => try rendered_template.append(byte),
                },
                .percent => switch (byte) {
                    '%' => {
                        try rendered_template.append('%');
                        state = .start;
                    },
                    '[' => {
                        try rendered_template.append('$');
                        try rendered_template.append('{');
                        name_start = i + 1;
                        state = .input;
                    },
                    else => {
                        try rendered_template.append('%');
                        try rendered_template.append(byte);
                        state = .start;
                    },
                },
                .input => switch (byte) {
                    ']', ':' => {
                        const name = asm_source[name_start..i];

                        const index = name_map.get(name) orelse {
                            // we should validate the assembly in Sema; by now it is too late
                            return self.todo("unknown input or output name: '{s}'", .{name});
                        };
                        try rendered_template.writer().print("{d}", .{index});
                        if (byte == ':') {
                            try rendered_template.append(':');
                            modifier_start = i + 1;
                            state = .modifier;
                        } else {
                            try rendered_template.append('}');
                            state = .start;
                        }
                    },
                    else => {},
                },
                .modifier => switch (byte) {
                    ']' => {
                        try rendered_template.append_slice(asm_source[modifier_start..i]);
                        try rendered_template.append('}');
                        state = .start;
                    },
                    else => {},
                },
            }
        }

        var attributes: Builder.FunctionAttributes.Wip = .{};
        defer attributes.deinit(&o.builder);
        for (llvm_param_attrs[0..param_count], 0..) |llvm_elem_ty, i| if (llvm_elem_ty != .none)
            try attributes.add_param_attr(i, .{ .elementtype = llvm_elem_ty }, &o.builder);

        const ret_llvm_ty = switch (return_count) {
            0 => .void,
            1 => llvm_ret_types[0],
            else => try o.builder.struct_type(.normal, llvm_ret_types),
        };
        const llvm_fn_ty = try o.builder.fn_type(ret_llvm_ty, llvm_param_types[0..param_count], .normal);
        const call = try self.wip.call_asm(
            try attributes.finish(&o.builder),
            llvm_fn_ty,
            .{ .sideeffect = is_volatile },
            try o.builder.string(rendered_template.items),
            try o.builder.string(llvm_constraints.items),
            llvm_param_values[0..param_count],
            "",
        );

        var ret_val = call;
        llvm_ret_i = 0;
        for (outputs, 0..) |output, i| {
            if (llvm_ret_indirect[i]) continue;

            const output_value = if (return_count > 1)
                try self.wip.extract_value(call, &[_]u32{@int_cast(llvm_ret_i)}, "")
            else
                call;

            if (output != .none) {
                const output_ptr = try self.resolve_inst(output);
                const output_ptr_ty = self.type_of(output);

                const alignment = output_ptr_ty.ptr_alignment(mod).to_llvm();
                _ = try self.wip.store(.normal, output_value, output_ptr, alignment);
            } else {
                ret_val = output_value;
            }
            llvm_ret_i += 1;
        }

        return ret_val;
    }

    fn air_is_non_null(
        self: *FuncGen,
        inst: Air.Inst.Index,
        operand_is_ptr: bool,
        cond: Builder.IntegerCondition,
    ) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
        const operand = try self.resolve_inst(un_op);
        const operand_ty = self.type_of(un_op);
        const optional_ty = if (operand_is_ptr) operand_ty.child_type(mod) else operand_ty;
        const optional_llvm_ty = try o.lower_type(optional_ty);
        const payload_ty = optional_ty.optional_child(mod);
        if (optional_ty.optional_repr_is_payload(mod)) {
            const loaded = if (operand_is_ptr)
                try self.wip.load(.normal, optional_llvm_ty, operand, .default, "")
            else
                operand;
            if (payload_ty.is_slice(mod)) {
                const slice_ptr = try self.wip.extract_value(loaded, &.{0}, "");
                const ptr_ty = try o.builder.ptr_type(to_llvm_address_space(
                    payload_ty.ptr_address_space(mod),
                    mod.get_target(),
                ));
                return self.wip.icmp(cond, slice_ptr, try o.builder.null_value(ptr_ty), "");
            }
            return self.wip.icmp(cond, loaded, try o.builder.zero_init_value(optional_llvm_ty), "");
        }

        comptime assert(optional_layout_version == 3);

        if (!payload_ty.has_runtime_bits_ignore_comptime(mod)) {
            const loaded = if (operand_is_ptr)
                try self.wip.load(.normal, optional_llvm_ty, operand, .default, "")
            else
                operand;
            return self.wip.icmp(cond, loaded, try o.builder.int_value(.i8, 0), "");
        }

        const is_by_ref = operand_is_ptr or is_by_ref(optional_ty, mod);
        return self.opt_cmp_null(cond, optional_llvm_ty, operand, is_by_ref);
    }

    fn air_is_err(
        self: *FuncGen,
        inst: Air.Inst.Index,
        cond: Builder.IntegerCondition,
        operand_is_ptr: bool,
    ) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
        const operand = try self.resolve_inst(un_op);
        const operand_ty = self.type_of(un_op);
        const err_union_ty = if (operand_is_ptr) operand_ty.child_type(mod) else operand_ty;
        const payload_ty = err_union_ty.error_union_payload(mod);
        const error_type = try o.error_int_type();
        const zero = try o.builder.int_value(error_type, 0);

        if (err_union_ty.error_union_set(mod).error_set_is_empty(mod)) {
            const val: Builder.Constant = switch (cond) {
                .eq => .true, // 0 == 0
                .ne => .false, // 0 != 0
                else => unreachable,
            };
            return val.to_value();
        }

        if (!payload_ty.has_runtime_bits_ignore_comptime(mod)) {
            const loaded = if (operand_is_ptr)
                try self.wip.load(.normal, try o.lower_type(err_union_ty), operand, .default, "")
            else
                operand;
            return self.wip.icmp(cond, loaded, zero, "");
        }

        const err_field_index = try err_union_error_offset(payload_ty, mod);

        const loaded = if (operand_is_ptr or is_by_ref(err_union_ty, mod)) loaded: {
            const err_union_llvm_ty = try o.lower_type(err_union_ty);
            const err_field_ptr =
                try self.wip.gep_struct(err_union_llvm_ty, operand, err_field_index, "");
            break :loaded try self.wip.load(.normal, error_type, err_field_ptr, .default, "");
        } else try self.wip.extract_value(operand, &.{err_field_index}, "");
        return self.wip.icmp(cond, loaded, zero, "");
    }

    fn air_optional_payload_ptr(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
        const operand = try self.resolve_inst(ty_op.operand);
        const optional_ty = self.type_of(ty_op.operand).child_type(mod);
        const payload_ty = optional_ty.optional_child(mod);
        if (!payload_ty.has_runtime_bits_ignore_comptime(mod)) {
            // We have a pointer to a zero-bit value and we need to return
            // a pointer to a zero-bit value.
            return operand;
        }
        if (optional_ty.optional_repr_is_payload(mod)) {
            // The payload and the optional are the same value.
            return operand;
        }
        return self.wip.gep_struct(try o.lower_type(optional_ty), operand, 0, "");
    }

    fn air_optional_payload_ptr_set(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        comptime assert(optional_layout_version == 3);

        const o = self.dg.object;
        const mod = o.module;
        const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
        const operand = try self.resolve_inst(ty_op.operand);
        const optional_ty = self.type_of(ty_op.operand).child_type(mod);
        const payload_ty = optional_ty.optional_child(mod);
        const non_null_bit = try o.builder.int_value(.i8, 1);
        if (!payload_ty.has_runtime_bits_ignore_comptime(mod)) {
            // We have a pointer to a i8. We need to set it to 1 and then return the same pointer.
            _ = try self.wip.store(.normal, non_null_bit, operand, .default);
            return operand;
        }
        if (optional_ty.optional_repr_is_payload(mod)) {
            // The payload and the optional are the same value.
            // Setting to non-null will be done when the payload is set.
            return operand;
        }

        // First set the non-null bit.
        const optional_llvm_ty = try o.lower_type(optional_ty);
        const non_null_ptr = try self.wip.gep_struct(optional_llvm_ty, operand, 1, "");
        // TODO set alignment on this store
        _ = try self.wip.store(.normal, non_null_bit, non_null_ptr, .default);

        // Then return the payload pointer (only if it's used).
        if (self.liveness.is_unused(inst)) return .none;

        return self.wip.gep_struct(optional_llvm_ty, operand, 0, "");
    }

    fn air_optional_payload(self: *FuncGen, body_tail: []const Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const inst = body_tail[0];
        const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
        const operand = try self.resolve_inst(ty_op.operand);
        const optional_ty = self.type_of(ty_op.operand);
        const payload_ty = self.type_of_index(inst);
        if (!payload_ty.has_runtime_bits_ignore_comptime(mod)) return .none;

        if (optional_ty.optional_repr_is_payload(mod)) {
            // Payload value is the same as the optional value.
            return operand;
        }

        const opt_llvm_ty = try o.lower_type(optional_ty);
        const can_elide_load = if (is_by_ref(payload_ty, mod)) self.can_elide_load(body_tail) else false;
        return self.opt_payload_handle(opt_llvm_ty, operand, optional_ty, can_elide_load);
    }

    fn air_err_union_payload(
        self: *FuncGen,
        body_tail: []const Air.Inst.Index,
        operand_is_ptr: bool,
    ) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const inst = body_tail[0];
        const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
        const operand = try self.resolve_inst(ty_op.operand);
        const operand_ty = self.type_of(ty_op.operand);
        const err_union_ty = if (operand_is_ptr) operand_ty.child_type(mod) else operand_ty;
        const result_ty = self.type_of_index(inst);
        const payload_ty = if (operand_is_ptr) result_ty.child_type(mod) else result_ty;

        if (!payload_ty.has_runtime_bits_ignore_comptime(mod)) {
            return if (operand_is_ptr) operand else .none;
        }
        const offset = try err_union_payload_offset(payload_ty, mod);
        const err_union_llvm_ty = try o.lower_type(err_union_ty);
        if (operand_is_ptr) {
            return self.wip.gep_struct(err_union_llvm_ty, operand, offset, "");
        } else if (is_by_ref(err_union_ty, mod)) {
            const payload_alignment = payload_ty.abi_alignment(mod).to_llvm();
            const payload_ptr = try self.wip.gep_struct(err_union_llvm_ty, operand, offset, "");
            if (is_by_ref(payload_ty, mod)) {
                if (self.can_elide_load(body_tail)) return payload_ptr;
                return self.load_by_ref(payload_ptr, payload_ty, payload_alignment, .normal);
            }
            const payload_llvm_ty = err_union_llvm_ty.struct_fields(&o.builder)[offset];
            return self.wip.load(.normal, payload_llvm_ty, payload_ptr, payload_alignment, "");
        }
        return self.wip.extract_value(operand, &.{offset}, "");
    }

    fn air_err_union_err(
        self: *FuncGen,
        inst: Air.Inst.Index,
        operand_is_ptr: bool,
    ) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
        const operand = try self.resolve_inst(ty_op.operand);
        const operand_ty = self.type_of(ty_op.operand);
        const error_type = try o.error_int_type();
        const err_union_ty = if (operand_is_ptr) operand_ty.child_type(mod) else operand_ty;
        if (err_union_ty.error_union_set(mod).error_set_is_empty(mod)) {
            if (operand_is_ptr) {
                return operand;
            } else {
                return o.builder.int_value(error_type, 0);
            }
        }

        const payload_ty = err_union_ty.error_union_payload(mod);
        if (!payload_ty.has_runtime_bits_ignore_comptime(mod)) {
            if (!operand_is_ptr) return operand;
            return self.wip.load(.normal, error_type, operand, .default, "");
        }

        const offset = try err_union_error_offset(payload_ty, mod);

        if (operand_is_ptr or is_by_ref(err_union_ty, mod)) {
            const err_union_llvm_ty = try o.lower_type(err_union_ty);
            const err_field_ptr = try self.wip.gep_struct(err_union_llvm_ty, operand, offset, "");
            return self.wip.load(.normal, error_type, err_field_ptr, .default, "");
        }

        return self.wip.extract_value(operand, &.{offset}, "");
    }

    fn air_err_union_payload_ptr_set(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
        const operand = try self.resolve_inst(ty_op.operand);
        const err_union_ty = self.type_of(ty_op.operand).child_type(mod);

        const payload_ty = err_union_ty.error_union_payload(mod);
        const non_error_val = try o.builder.int_value(try o.error_int_type(), 0);
        if (!payload_ty.has_runtime_bits_ignore_comptime(mod)) {
            _ = try self.wip.store(.normal, non_error_val, operand, .default);
            return operand;
        }
        const err_union_llvm_ty = try o.lower_type(err_union_ty);
        {
            const err_int_ty = try mod.error_int_type();
            const error_alignment = err_int_ty.abi_alignment(mod).to_llvm();
            const error_offset = try err_union_error_offset(payload_ty, mod);
            // First set the non-error value.
            const non_null_ptr = try self.wip.gep_struct(err_union_llvm_ty, operand, error_offset, "");
            _ = try self.wip.store(.normal, non_error_val, non_null_ptr, error_alignment);
        }
        // Then return the payload pointer (only if it is used).
        if (self.liveness.is_unused(inst)) return .none;

        const payload_offset = try err_union_payload_offset(payload_ty, mod);
        return self.wip.gep_struct(err_union_llvm_ty, operand, payload_offset, "");
    }

    fn air_err_return_trace(self: *FuncGen, _: Air.Inst.Index) !Builder.Value {
        assert(self.err_ret_trace != .none);
        return self.err_ret_trace;
    }

    fn air_set_err_return_trace(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
        self.err_ret_trace = try self.resolve_inst(un_op);
        return .none;
    }

    fn air_save_err_return_trace_index(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
        const struct_ty = ty_pl.ty.to_type();
        const field_index = ty_pl.payload;

        const mod = o.module;
        const struct_llvm_ty = try o.lower_type(struct_ty);
        const llvm_field_index = o.llvm_field_index(struct_ty, field_index).?;
        assert(self.err_ret_trace != .none);
        const field_ptr =
            try self.wip.gep_struct(struct_llvm_ty, self.err_ret_trace, llvm_field_index, "");
        const field_alignment = struct_ty.struct_field_align(field_index, mod);
        const field_ty = struct_ty.struct_field_type(field_index, mod);
        const field_ptr_ty = try mod.ptr_type(.{
            .child = field_ty.to_intern(),
            .flags = .{ .alignment = field_alignment },
        });
        return self.load(field_ptr, field_ptr_ty);
    }

    /// As an optimization, we want to avoid unnecessary copies of
    /// error union/optional types when returning from a function.
    /// Here, we scan forward in the current block, looking to see
    /// if the next instruction is a return (ignoring debug instructions).
    ///
    /// The first instruction of `body_tail` is a wrap instruction.
    fn is_next_ret(
        self: *FuncGen,
        body_tail: []const Air.Inst.Index,
    ) bool {
        const air_tags = self.air.instructions.items(.tag);
        for (body_tail[1..]) |body_inst| {
            switch (air_tags[@int_from_enum(body_inst)]) {
                .ret => return true,
                .dbg_stmt => continue,
                else => return false,
            }
        }
        // The only way to get here is to hit the end of a loop instruction
        // (implicit repeat).
        return false;
    }

    fn air_wrap_optional(self: *FuncGen, body_tail: []const Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const inst = body_tail[0];
        const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
        const payload_ty = self.type_of(ty_op.operand);
        const non_null_bit = try o.builder.int_value(.i8, 1);
        comptime assert(optional_layout_version == 3);
        if (!payload_ty.has_runtime_bits_ignore_comptime(mod)) return non_null_bit;
        const operand = try self.resolve_inst(ty_op.operand);
        const optional_ty = self.type_of_index(inst);
        if (optional_ty.optional_repr_is_payload(mod)) return operand;
        const llvm_optional_ty = try o.lower_type(optional_ty);
        if (is_by_ref(optional_ty, mod)) {
            const directReturn = self.is_next_ret(body_tail);
            const optional_ptr = if (directReturn)
                self.ret_ptr
            else brk: {
                const alignment = optional_ty.abi_alignment(mod).to_llvm();
                const optional_ptr = try self.build_alloca_workaround(optional_ty, alignment);
                break :brk optional_ptr;
            };

            const payload_ptr = try self.wip.gep_struct(llvm_optional_ty, optional_ptr, 0, "");
            const payload_ptr_ty = try mod.single_mut_ptr_type(payload_ty);
            try self.store(payload_ptr, payload_ptr_ty, operand, .none);
            const non_null_ptr = try self.wip.gep_struct(llvm_optional_ty, optional_ptr, 1, "");
            _ = try self.wip.store(.normal, non_null_bit, non_null_ptr, .default);
            return optional_ptr;
        }
        return self.wip.build_aggregate(llvm_optional_ty, &.{ operand, non_null_bit }, "");
    }

    fn air_wrap_err_union_payload(self: *FuncGen, body_tail: []const Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const inst = body_tail[0];
        const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
        const err_un_ty = self.type_of_index(inst);
        const operand = try self.resolve_inst(ty_op.operand);
        const payload_ty = self.type_of(ty_op.operand);
        if (!payload_ty.has_runtime_bits_ignore_comptime(mod)) {
            return operand;
        }
        const ok_err_code = try o.builder.int_value(try o.error_int_type(), 0);
        const err_un_llvm_ty = try o.lower_type(err_un_ty);

        const payload_offset = try err_union_payload_offset(payload_ty, mod);
        const error_offset = try err_union_error_offset(payload_ty, mod);
        if (is_by_ref(err_un_ty, mod)) {
            const directReturn = self.is_next_ret(body_tail);
            const result_ptr = if (directReturn)
                self.ret_ptr
            else brk: {
                const alignment = err_un_ty.abi_alignment(mod).to_llvm();
                const result_ptr = try self.build_alloca_workaround(err_un_ty, alignment);
                break :brk result_ptr;
            };

            const err_ptr = try self.wip.gep_struct(err_un_llvm_ty, result_ptr, error_offset, "");
            const err_int_ty = try mod.error_int_type();
            const error_alignment = err_int_ty.abi_alignment(mod).to_llvm();
            _ = try self.wip.store(.normal, ok_err_code, err_ptr, error_alignment);
            const payload_ptr = try self.wip.gep_struct(err_un_llvm_ty, result_ptr, payload_offset, "");
            const payload_ptr_ty = try mod.single_mut_ptr_type(payload_ty);
            try self.store(payload_ptr, payload_ptr_ty, operand, .none);
            return result_ptr;
        }
        var fields: [2]Builder.Value = undefined;
        fields[payload_offset] = operand;
        fields[error_offset] = ok_err_code;
        return self.wip.build_aggregate(err_un_llvm_ty, &fields, "");
    }

    fn air_wrap_err_union_err(self: *FuncGen, body_tail: []const Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const inst = body_tail[0];
        const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
        const err_un_ty = self.type_of_index(inst);
        const payload_ty = err_un_ty.error_union_payload(mod);
        const operand = try self.resolve_inst(ty_op.operand);
        if (!payload_ty.has_runtime_bits_ignore_comptime(mod)) return operand;
        const err_un_llvm_ty = try o.lower_type(err_un_ty);

        const payload_offset = try err_union_payload_offset(payload_ty, mod);
        const error_offset = try err_union_error_offset(payload_ty, mod);
        if (is_by_ref(err_un_ty, mod)) {
            const directReturn = self.is_next_ret(body_tail);
            const result_ptr = if (directReturn)
                self.ret_ptr
            else brk: {
                const alignment = err_un_ty.abi_alignment(mod).to_llvm();
                const result_ptr = try self.build_alloca_workaround(err_un_ty, alignment);
                break :brk result_ptr;
            };

            const err_ptr = try self.wip.gep_struct(err_un_llvm_ty, result_ptr, error_offset, "");
            const err_int_ty = try mod.error_int_type();
            const error_alignment = err_int_ty.abi_alignment(mod).to_llvm();
            _ = try self.wip.store(.normal, operand, err_ptr, error_alignment);
            const payload_ptr = try self.wip.gep_struct(err_un_llvm_ty, result_ptr, payload_offset, "");
            const payload_ptr_ty = try mod.single_mut_ptr_type(payload_ty);
            // TODO store undef to payload_ptr
            _ = payload_ptr;
            _ = payload_ptr_ty;
            return result_ptr;
        }

        // TODO set payload bytes to undef
        const undef = try o.builder.undef_value(err_un_llvm_ty);
        return self.wip.insert_value(undef, operand, &.{error_offset}, "");
    }

    fn air_wasm_memory_size(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const pl_op = self.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
        const index = pl_op.payload;
        const llvm_usize = try o.lower_type(Type.usize);
        return self.wip.call_intrinsic(.normal, .none, .@"wasm.memory.size", &.{llvm_usize}, &.{
            try o.builder.int_value(.i32, index),
        }, "");
    }

    fn air_wasm_memory_grow(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const pl_op = self.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
        const index = pl_op.payload;
        const llvm_isize = try o.lower_type(Type.isize);
        return self.wip.call_intrinsic(.normal, .none, .@"wasm.memory.grow", &.{llvm_isize}, &.{
            try o.builder.int_value(.i32, index), try self.resolve_inst(pl_op.operand),
        }, "");
    }

    fn air_vector_store_elem(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const data = self.air.instructions.items(.data)[@int_from_enum(inst)].vector_store_elem;
        const extra = self.air.extra_data(Air.Bin, data.payload).data;

        const vector_ptr = try self.resolve_inst(data.vector_ptr);
        const vector_ptr_ty = self.type_of(data.vector_ptr);
        const index = try self.resolve_inst(extra.lhs);
        const operand = try self.resolve_inst(extra.rhs);

        const access_kind: Builder.MemoryAccessKind =
            if (vector_ptr_ty.is_volatile_ptr(mod)) .@"volatile" else .normal;
        const elem_llvm_ty = try o.lower_type(vector_ptr_ty.child_type(mod));
        const alignment = vector_ptr_ty.ptr_alignment(mod).to_llvm();
        const loaded = try self.wip.load(access_kind, elem_llvm_ty, vector_ptr, alignment, "");

        const new_vector = try self.wip.insert_element(loaded, operand, index, "");
        _ = try self.store(vector_ptr, vector_ptr_ty, new_vector, .none);
        return .none;
    }

    fn air_min(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
        const lhs = try self.resolve_inst(bin_op.lhs);
        const rhs = try self.resolve_inst(bin_op.rhs);
        const inst_ty = self.type_of_index(inst);
        const scalar_ty = inst_ty.scalar_type(mod);

        if (scalar_ty.is_any_float()) return self.build_float_op(.fmin, .normal, inst_ty, 2, .{ lhs, rhs });
        return self.wip.call_intrinsic(
            .normal,
            .none,
            if (scalar_ty.is_signed_int(mod)) .smin else .umin,
            &.{try o.lower_type(inst_ty)},
            &.{ lhs, rhs },
            "",
        );
    }

    fn air_max(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
        const lhs = try self.resolve_inst(bin_op.lhs);
        const rhs = try self.resolve_inst(bin_op.rhs);
        const inst_ty = self.type_of_index(inst);
        const scalar_ty = inst_ty.scalar_type(mod);

        if (scalar_ty.is_any_float()) return self.build_float_op(.fmax, .normal, inst_ty, 2, .{ lhs, rhs });
        return self.wip.call_intrinsic(
            .normal,
            .none,
            if (scalar_ty.is_signed_int(mod)) .smax else .umax,
            &.{try o.lower_type(inst_ty)},
            &.{ lhs, rhs },
            "",
        );
    }

    fn air_slice(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
        const bin_op = self.air.extra_data(Air.Bin, ty_pl.payload).data;
        const ptr = try self.resolve_inst(bin_op.lhs);
        const len = try self.resolve_inst(bin_op.rhs);
        const inst_ty = self.type_of_index(inst);
        return self.wip.build_aggregate(try o.lower_type(inst_ty), &.{ ptr, len }, "");
    }

    fn air_add(self: *FuncGen, inst: Air.Inst.Index, fast: Builder.FastMathKind) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
        const lhs = try self.resolve_inst(bin_op.lhs);
        const rhs = try self.resolve_inst(bin_op.rhs);
        const inst_ty = self.type_of_index(inst);
        const scalar_ty = inst_ty.scalar_type(mod);

        if (scalar_ty.is_any_float()) return self.build_float_op(.add, fast, inst_ty, 2, .{ lhs, rhs });
        return self.wip.bin(if (scalar_ty.is_signed_int(mod)) .@"add nsw" else .@"add nuw", lhs, rhs, "");
    }

    fn air_safe_arithmetic(
        fg: *FuncGen,
        inst: Air.Inst.Index,
        signed_intrinsic: Builder.Intrinsic,
        unsigned_intrinsic: Builder.Intrinsic,
    ) !Builder.Value {
        const o = fg.dg.object;
        const mod = o.module;

        const bin_op = fg.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
        const lhs = try fg.resolve_inst(bin_op.lhs);
        const rhs = try fg.resolve_inst(bin_op.rhs);
        const inst_ty = fg.type_of_index(inst);
        const scalar_ty = inst_ty.scalar_type(mod);

        const intrinsic = if (scalar_ty.is_signed_int(mod)) signed_intrinsic else unsigned_intrinsic;
        const llvm_inst_ty = try o.lower_type(inst_ty);
        const results =
            try fg.wip.call_intrinsic(.normal, .none, intrinsic, &.{llvm_inst_ty}, &.{ lhs, rhs }, "");

        const overflow_bits = try fg.wip.extract_value(results, &.{1}, "");
        const overflow_bits_ty = overflow_bits.type_of_wip(&fg.wip);
        const overflow_bit = if (overflow_bits_ty.is_vector(&o.builder))
            try fg.wip.call_intrinsic(
                .normal,
                .none,
                .@"vector.reduce.or",
                &.{overflow_bits_ty},
                &.{overflow_bits},
                "",
            )
        else
            overflow_bits;

        const fail_block = try fg.wip.block(1, "OverflowFail");
        const ok_block = try fg.wip.block(1, "OverflowOk");
        _ = try fg.wip.br_cond(overflow_bit, fail_block, ok_block);

        fg.wip.cursor = .{ .block = fail_block };
        try fg.build_simple_panic(.integer_overflow);

        fg.wip.cursor = .{ .block = ok_block };
        return fg.wip.extract_value(results, &.{0}, "");
    }

    fn air_add_wrap(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
        const lhs = try self.resolve_inst(bin_op.lhs);
        const rhs = try self.resolve_inst(bin_op.rhs);

        return self.wip.bin(.add, lhs, rhs, "");
    }

    fn air_add_sat(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
        const lhs = try self.resolve_inst(bin_op.lhs);
        const rhs = try self.resolve_inst(bin_op.rhs);
        const inst_ty = self.type_of_index(inst);
        const scalar_ty = inst_ty.scalar_type(mod);

        if (scalar_ty.is_any_float()) return self.todo("saturating float add", .{});
        return self.wip.call_intrinsic(
            .normal,
            .none,
            if (scalar_ty.is_signed_int(mod)) .@"sadd.sat" else .@"uadd.sat",
            &.{try o.lower_type(inst_ty)},
            &.{ lhs, rhs },
            "",
        );
    }

    fn air_sub(self: *FuncGen, inst: Air.Inst.Index, fast: Builder.FastMathKind) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
        const lhs = try self.resolve_inst(bin_op.lhs);
        const rhs = try self.resolve_inst(bin_op.rhs);
        const inst_ty = self.type_of_index(inst);
        const scalar_ty = inst_ty.scalar_type(mod);

        if (scalar_ty.is_any_float()) return self.build_float_op(.sub, fast, inst_ty, 2, .{ lhs, rhs });
        return self.wip.bin(if (scalar_ty.is_signed_int(mod)) .@"sub nsw" else .@"sub nuw", lhs, rhs, "");
    }

    fn air_sub_wrap(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
        const lhs = try self.resolve_inst(bin_op.lhs);
        const rhs = try self.resolve_inst(bin_op.rhs);

        return self.wip.bin(.sub, lhs, rhs, "");
    }

    fn air_sub_sat(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
        const lhs = try self.resolve_inst(bin_op.lhs);
        const rhs = try self.resolve_inst(bin_op.rhs);
        const inst_ty = self.type_of_index(inst);
        const scalar_ty = inst_ty.scalar_type(mod);

        if (scalar_ty.is_any_float()) return self.todo("saturating float sub", .{});
        return self.wip.call_intrinsic(
            .normal,
            .none,
            if (scalar_ty.is_signed_int(mod)) .@"ssub.sat" else .@"usub.sat",
            &.{try o.lower_type(inst_ty)},
            &.{ lhs, rhs },
            "",
        );
    }

    fn air_mul(self: *FuncGen, inst: Air.Inst.Index, fast: Builder.FastMathKind) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
        const lhs = try self.resolve_inst(bin_op.lhs);
        const rhs = try self.resolve_inst(bin_op.rhs);
        const inst_ty = self.type_of_index(inst);
        const scalar_ty = inst_ty.scalar_type(mod);

        if (scalar_ty.is_any_float()) return self.build_float_op(.mul, fast, inst_ty, 2, .{ lhs, rhs });
        return self.wip.bin(if (scalar_ty.is_signed_int(mod)) .@"mul nsw" else .@"mul nuw", lhs, rhs, "");
    }

    fn air_mul_wrap(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
        const lhs = try self.resolve_inst(bin_op.lhs);
        const rhs = try self.resolve_inst(bin_op.rhs);

        return self.wip.bin(.mul, lhs, rhs, "");
    }

    fn air_mul_sat(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
        const lhs = try self.resolve_inst(bin_op.lhs);
        const rhs = try self.resolve_inst(bin_op.rhs);
        const inst_ty = self.type_of_index(inst);
        const scalar_ty = inst_ty.scalar_type(mod);

        if (scalar_ty.is_any_float()) return self.todo("saturating float mul", .{});
        return self.wip.call_intrinsic(
            .normal,
            .none,
            if (scalar_ty.is_signed_int(mod)) .@"smul.fix.sat" else .@"umul.fix.sat",
            &.{try o.lower_type(inst_ty)},
            &.{ lhs, rhs, .@"0" },
            "",
        );
    }

    fn air_div_float(self: *FuncGen, inst: Air.Inst.Index, fast: Builder.FastMathKind) !Builder.Value {
        const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
        const lhs = try self.resolve_inst(bin_op.lhs);
        const rhs = try self.resolve_inst(bin_op.rhs);
        const inst_ty = self.type_of_index(inst);

        return self.build_float_op(.div, fast, inst_ty, 2, .{ lhs, rhs });
    }

    fn air_div_trunc(self: *FuncGen, inst: Air.Inst.Index, fast: Builder.FastMathKind) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
        const lhs = try self.resolve_inst(bin_op.lhs);
        const rhs = try self.resolve_inst(bin_op.rhs);
        const inst_ty = self.type_of_index(inst);
        const scalar_ty = inst_ty.scalar_type(mod);

        if (scalar_ty.is_runtime_float()) {
            const result = try self.build_float_op(.div, fast, inst_ty, 2, .{ lhs, rhs });
            return self.build_float_op(.trunc, fast, inst_ty, 1, .{result});
        }
        return self.wip.bin(if (scalar_ty.is_signed_int(mod)) .sdiv else .udiv, lhs, rhs, "");
    }

    fn air_div_floor(self: *FuncGen, inst: Air.Inst.Index, fast: Builder.FastMathKind) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
        const lhs = try self.resolve_inst(bin_op.lhs);
        const rhs = try self.resolve_inst(bin_op.rhs);
        const inst_ty = self.type_of_index(inst);
        const scalar_ty = inst_ty.scalar_type(mod);

        if (scalar_ty.is_runtime_float()) {
            const result = try self.build_float_op(.div, fast, inst_ty, 2, .{ lhs, rhs });
            return self.build_float_op(.floor, fast, inst_ty, 1, .{result});
        }
        if (scalar_ty.is_signed_int(mod)) {
            const inst_llvm_ty = try o.lower_type(inst_ty);
            const bit_size_minus_one = try o.builder.splat_value(inst_llvm_ty, try o.builder.int_const(
                inst_llvm_ty.scalar_type(&o.builder),
                inst_llvm_ty.scalar_bits(&o.builder) - 1,
            ));

            const div = try self.wip.bin(.sdiv, lhs, rhs, "");
            const rem = try self.wip.bin(.srem, lhs, rhs, "");
            const div_sign = try self.wip.bin(.xor, lhs, rhs, "");
            const div_sign_mask = try self.wip.bin(.ashr, div_sign, bit_size_minus_one, "");
            const zero = try o.builder.zero_init_value(inst_llvm_ty);
            const rem_nonzero = try self.wip.icmp(.ne, rem, zero, "");
            const correction = try self.wip.select(.normal, rem_nonzero, div_sign_mask, zero, "");
            return self.wip.bin(.@"add nsw", div, correction, "");
        }
        return self.wip.bin(.udiv, lhs, rhs, "");
    }

    fn air_div_exact(self: *FuncGen, inst: Air.Inst.Index, fast: Builder.FastMathKind) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
        const lhs = try self.resolve_inst(bin_op.lhs);
        const rhs = try self.resolve_inst(bin_op.rhs);
        const inst_ty = self.type_of_index(inst);
        const scalar_ty = inst_ty.scalar_type(mod);

        if (scalar_ty.is_runtime_float()) return self.build_float_op(.div, fast, inst_ty, 2, .{ lhs, rhs });
        return self.wip.bin(
            if (scalar_ty.is_signed_int(mod)) .@"sdiv exact" else .@"udiv exact",
            lhs,
            rhs,
            "",
        );
    }

    fn air_rem(self: *FuncGen, inst: Air.Inst.Index, fast: Builder.FastMathKind) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
        const lhs = try self.resolve_inst(bin_op.lhs);
        const rhs = try self.resolve_inst(bin_op.rhs);
        const inst_ty = self.type_of_index(inst);
        const scalar_ty = inst_ty.scalar_type(mod);

        if (scalar_ty.is_runtime_float())
            return self.build_float_op(.fmod, fast, inst_ty, 2, .{ lhs, rhs });
        return self.wip.bin(if (scalar_ty.is_signed_int(mod))
            .srem
        else
            .urem, lhs, rhs, "");
    }

    fn air_mod(self: *FuncGen, inst: Air.Inst.Index, fast: Builder.FastMathKind) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
        const lhs = try self.resolve_inst(bin_op.lhs);
        const rhs = try self.resolve_inst(bin_op.rhs);
        const inst_ty = self.type_of_index(inst);
        const inst_llvm_ty = try o.lower_type(inst_ty);
        const scalar_ty = inst_ty.scalar_type(mod);

        if (scalar_ty.is_runtime_float()) {
            const a = try self.build_float_op(.fmod, fast, inst_ty, 2, .{ lhs, rhs });
            const b = try self.build_float_op(.add, fast, inst_ty, 2, .{ a, rhs });
            const c = try self.build_float_op(.fmod, fast, inst_ty, 2, .{ b, rhs });
            const zero = try o.builder.zero_init_value(inst_llvm_ty);
            const ltz = try self.build_float_cmp(fast, .lt, inst_ty, .{ lhs, zero });
            return self.wip.select(fast, ltz, c, a, "");
        }
        if (scalar_ty.is_signed_int(mod)) {
            const bit_size_minus_one = try o.builder.splat_value(inst_llvm_ty, try o.builder.int_const(
                inst_llvm_ty.scalar_type(&o.builder),
                inst_llvm_ty.scalar_bits(&o.builder) - 1,
            ));

            const rem = try self.wip.bin(.srem, lhs, rhs, "");
            const div_sign = try self.wip.bin(.xor, lhs, rhs, "");
            const div_sign_mask = try self.wip.bin(.ashr, div_sign, bit_size_minus_one, "");
            const rhs_masked = try self.wip.bin(.@"and", rhs, div_sign_mask, "");
            const zero = try o.builder.zero_init_value(inst_llvm_ty);
            const rem_nonzero = try self.wip.icmp(.ne, rem, zero, "");
            const correction = try self.wip.select(.normal, rem_nonzero, rhs_masked, zero, "");
            return self.wip.bin(.@"add nsw", rem, correction, "");
        }
        return self.wip.bin(.urem, lhs, rhs, "");
    }

    fn air_ptr_add(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
        const bin_op = self.air.extra_data(Air.Bin, ty_pl.payload).data;
        const ptr = try self.resolve_inst(bin_op.lhs);
        const offset = try self.resolve_inst(bin_op.rhs);
        const ptr_ty = self.type_of(bin_op.lhs);
        const llvm_elem_ty = try o.lower_ptr_elem_ty(ptr_ty.child_type(mod));
        switch (ptr_ty.ptr_size(mod)) {
            // It's a pointer to an array, so according to LLVM we need an extra GEP index.
            .One => return self.wip.gep(.inbounds, llvm_elem_ty, ptr, &.{
                try o.builder.int_value(try o.lower_type(Type.usize), 0), offset,
            }, ""),
            .C, .Many => return self.wip.gep(.inbounds, llvm_elem_ty, ptr, &.{offset}, ""),
            .Slice => {
                const base = try self.wip.extract_value(ptr, &.{0}, "");
                return self.wip.gep(.inbounds, llvm_elem_ty, base, &.{offset}, "");
            },
        }
    }

    fn air_ptr_sub(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
        const bin_op = self.air.extra_data(Air.Bin, ty_pl.payload).data;
        const ptr = try self.resolve_inst(bin_op.lhs);
        const offset = try self.resolve_inst(bin_op.rhs);
        const negative_offset = try self.wip.neg(offset, "");
        const ptr_ty = self.type_of(bin_op.lhs);
        const llvm_elem_ty = try o.lower_ptr_elem_ty(ptr_ty.child_type(mod));
        switch (ptr_ty.ptr_size(mod)) {
            // It's a pointer to an array, so according to LLVM we need an extra GEP index.
            .One => return self.wip.gep(.inbounds, llvm_elem_ty, ptr, &.{
                try o.builder.int_value(try o.lower_type(Type.usize), 0), negative_offset,
            }, ""),
            .C, .Many => return self.wip.gep(.inbounds, llvm_elem_ty, ptr, &.{negative_offset}, ""),
            .Slice => {
                const base = try self.wip.extract_value(ptr, &.{0}, "");
                return self.wip.gep(.inbounds, llvm_elem_ty, base, &.{negative_offset}, "");
            },
        }
    }

    fn air_overflow(
        self: *FuncGen,
        inst: Air.Inst.Index,
        signed_intrinsic: Builder.Intrinsic,
        unsigned_intrinsic: Builder.Intrinsic,
    ) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
        const extra = self.air.extra_data(Air.Bin, ty_pl.payload).data;

        const lhs = try self.resolve_inst(extra.lhs);
        const rhs = try self.resolve_inst(extra.rhs);

        const lhs_ty = self.type_of(extra.lhs);
        const scalar_ty = lhs_ty.scalar_type(mod);
        const inst_ty = self.type_of_index(inst);

        const intrinsic = if (scalar_ty.is_signed_int(mod)) signed_intrinsic else unsigned_intrinsic;
        const llvm_inst_ty = try o.lower_type(inst_ty);
        const llvm_lhs_ty = try o.lower_type(lhs_ty);
        const results =
            try self.wip.call_intrinsic(.normal, .none, intrinsic, &.{llvm_lhs_ty}, &.{ lhs, rhs }, "");

        const result_val = try self.wip.extract_value(results, &.{0}, "");
        const overflow_bit = try self.wip.extract_value(results, &.{1}, "");

        const result_index = o.llvm_field_index(inst_ty, 0).?;
        const overflow_index = o.llvm_field_index(inst_ty, 1).?;

        if (is_by_ref(inst_ty, mod)) {
            const result_alignment = inst_ty.abi_alignment(mod).to_llvm();
            const alloca_inst = try self.build_alloca_workaround(inst_ty, result_alignment);
            {
                const field_ptr = try self.wip.gep_struct(llvm_inst_ty, alloca_inst, result_index, "");
                _ = try self.wip.store(.normal, result_val, field_ptr, result_alignment);
            }
            {
                const overflow_alignment = comptime Builder.Alignment.from_byte_units(1);
                const field_ptr = try self.wip.gep_struct(llvm_inst_ty, alloca_inst, overflow_index, "");
                _ = try self.wip.store(.normal, overflow_bit, field_ptr, overflow_alignment);
            }

            return alloca_inst;
        }

        var fields: [2]Builder.Value = undefined;
        fields[result_index] = result_val;
        fields[overflow_index] = overflow_bit;
        return self.wip.build_aggregate(llvm_inst_ty, &fields, "");
    }

    fn build_elementwise_call(
        self: *FuncGen,
        llvm_fn: Builder.Function.Index,
        args_vectors: []const Builder.Value,
        result_vector: Builder.Value,
        vector_len: usize,
    ) !Builder.Value {
        const o = self.dg.object;
        assert(args_vectors.len <= 3);

        var i: usize = 0;
        var result = result_vector;
        while (i < vector_len) : (i += 1) {
            const index_i32 = try o.builder.int_value(.i32, i);

            var args: [3]Builder.Value = undefined;
            for (args[0..args_vectors.len], args_vectors) |*arg_elem, arg_vector| {
                arg_elem.* = try self.wip.extract_element(arg_vector, index_i32, "");
            }
            const result_elem = try self.wip.call(
                .normal,
                .ccc,
                .none,
                llvm_fn.type_of(&o.builder),
                llvm_fn.to_value(&o.builder),
                args[0..args_vectors.len],
                "",
            );
            result = try self.wip.insert_element(result, result_elem, index_i32, "");
        }
        return result;
    }

    fn get_libc_function(
        self: *FuncGen,
        fn_name: Builder.StrtabString,
        param_types: []const Builder.Type,
        return_type: Builder.Type,
    ) Allocator.Error!Builder.Function.Index {
        const o = self.dg.object;
        if (o.builder.get_global(fn_name)) |global| return switch (global.ptr_const(&o.builder).kind) {
            .alias => |alias| alias.get_aliasee(&o.builder).ptr_const(&o.builder).kind.function,
            .function => |function| function,
            .variable, .replaced => unreachable,
        };
        return o.builder.add_function(
            try o.builder.fn_type(return_type, param_types, .normal),
            fn_name,
            to_llvm_address_space(.generic, o.module.get_target()),
        );
    }

    /// Creates a floating point comparison by lowering to the appropriate
    /// hardware instruction or softfloat routine for the target
    fn build_float_cmp(
        self: *FuncGen,
        fast: Builder.FastMathKind,
        pred: math.CompareOperator,
        ty: Type,
        params: [2]Builder.Value,
    ) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const target = o.module.get_target();
        const scalar_ty = ty.scalar_type(mod);
        const scalar_llvm_ty = try o.lower_type(scalar_ty);

        if (intrinsics_allowed(scalar_ty, target)) {
            const cond: Builder.FloatCondition = switch (pred) {
                .eq => .oeq,
                .neq => .une,
                .lt => .olt,
                .lte => .ole,
                .gt => .ogt,
                .gte => .oge,
            };
            return self.wip.fcmp(fast, cond, params[0], params[1], "");
        }

        const float_bits = scalar_ty.float_bits(target);
        const compiler_rt_float_abbrev = compiler_rt_float_abbrev(float_bits);
        const fn_base_name = switch (pred) {
            .neq => "ne",
            .eq => "eq",
            .lt => "lt",
            .lte => "le",
            .gt => "gt",
            .gte => "ge",
        };
        const fn_name = try o.builder.strtab_string_fmt("__{s}{s}f2", .{ fn_base_name, compiler_rt_float_abbrev });

        const libc_fn = try self.get_libc_function(fn_name, &.{ scalar_llvm_ty, scalar_llvm_ty }, .i32);

        const int_cond: Builder.IntegerCondition = switch (pred) {
            .eq => .eq,
            .neq => .ne,
            .lt => .slt,
            .lte => .sle,
            .gt => .sgt,
            .gte => .sge,
        };

        if (ty.zig_type_tag(mod) == .Vector) {
            const vec_len = ty.vector_len(mod);
            const vector_result_ty = try o.builder.vector_type(.normal, vec_len, .i32);

            const init = try o.builder.poison_value(vector_result_ty);
            const result = try self.build_elementwise_call(libc_fn, &params, init, vec_len);

            const zero_vector = try o.builder.splat_value(vector_result_ty, .@"0");
            return self.wip.icmp(int_cond, result, zero_vector, "");
        }

        const result = try self.wip.call(
            .normal,
            .ccc,
            .none,
            libc_fn.type_of(&o.builder),
            libc_fn.to_value(&o.builder),
            &params,
            "",
        );
        return self.wip.icmp(int_cond, result, .@"0", "");
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
    };

    const FloatOpStrat = union(enum) {
        intrinsic: []const u8,
        libc: Builder.String,
    };

    /// Creates a floating point operation (add, sub, fma, sqrt, exp, etc.)
    /// by lowering to the appropriate hardware instruction or softfloat
    /// routine for the target
    fn build_float_op(
        self: *FuncGen,
        comptime op: FloatOp,
        fast: Builder.FastMathKind,
        ty: Type,
        comptime params_len: usize,
        params: [params_len]Builder.Value,
    ) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const target = mod.get_target();
        const scalar_ty = ty.scalar_type(mod);
        const llvm_ty = try o.lower_type(ty);

        if (op != .tan and intrinsics_allowed(scalar_ty, target)) switch (op) {
            // Some operations are dedicated LLVM instructions, not available as intrinsics
            .neg => return self.wip.un(.fneg, params[0], ""),
            .add, .sub, .mul, .div, .fmod => return self.wip.bin(switch (fast) {
                .normal => switch (op) {
                    .add => .fadd,
                    .sub => .fsub,
                    .mul => .fmul,
                    .div => .fdiv,
                    .fmod => .frem,
                    else => unreachable,
                },
                .fast => switch (op) {
                    .add => .@"fadd fast",
                    .sub => .@"fsub fast",
                    .mul => .@"fmul fast",
                    .div => .@"fdiv fast",
                    .fmod => .@"frem fast",
                    else => unreachable,
                },
            }, params[0], params[1], ""),
            .fmax,
            .fmin,
            .ceil,
            .cos,
            .exp,
            .exp2,
            .fabs,
            .floor,
            .log,
            .log10,
            .log2,
            .round,
            .sin,
            .sqrt,
            .trunc,
            .fma,
            => return self.wip.call_intrinsic(fast, .none, switch (op) {
                .fmax => .maxnum,
                .fmin => .minnum,
                .ceil => .ceil,
                .cos => .cos,
                .exp => .exp,
                .exp2 => .exp2,
                .fabs => .fabs,
                .floor => .floor,
                .log => .log,
                .log10 => .log10,
                .log2 => .log2,
                .round => .round,
                .sin => .sin,
                .sqrt => .sqrt,
                .trunc => .trunc,
                .fma => .fma,
                else => unreachable,
            }, &.{llvm_ty}, &params, ""),
            .tan => unreachable,
        };

        const float_bits = scalar_ty.float_bits(target);
        const fn_name = switch (op) {
            .neg => {
                // In this case we can generate a softfloat negation by XORing the
                // bits with a constant.
                const int_ty = try o.builder.int_type(@int_cast(float_bits));
                const cast_ty = try llvm_ty.change_scalar(int_ty, &o.builder);
                const sign_mask = try o.builder.splat_value(
                    cast_ty,
                    try o.builder.int_const(int_ty, @as(u128, 1) << @int_cast(float_bits - 1)),
                );
                const bitcasted_operand = try self.wip.cast(.bitcast, params[0], cast_ty, "");
                const result = try self.wip.bin(.xor, bitcasted_operand, sign_mask, "");
                return self.wip.cast(.bitcast, result, llvm_ty, "");
            },
            .add, .sub, .div, .mul => try o.builder.strtab_string_fmt("__{s}{s}f3", .{
                @tag_name(op), compiler_rt_float_abbrev(float_bits),
            }),
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
            => try o.builder.strtab_string_fmt("{s}{s}{s}", .{
                libc_float_prefix(float_bits), @tag_name(op), libc_float_suffix(float_bits),
            }),
        };

        const scalar_llvm_ty = llvm_ty.scalar_type(&o.builder);
        const libc_fn = try self.get_libc_function(
            fn_name,
            ([1]Builder.Type{scalar_llvm_ty} ** 3)[0..params.len],
            scalar_llvm_ty,
        );
        if (ty.zig_type_tag(mod) == .Vector) {
            const result = try o.builder.poison_value(llvm_ty);
            return self.build_elementwise_call(libc_fn, &params, result, ty.vector_len(mod));
        }

        return self.wip.call(
            fast.to_call_kind(),
            .ccc,
            .none,
            libc_fn.type_of(&o.builder),
            libc_fn.to_value(&o.builder),
            &params,
            "",
        );
    }

    fn air_mul_add(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const pl_op = self.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
        const extra = self.air.extra_data(Air.Bin, pl_op.payload).data;

        const mulend1 = try self.resolve_inst(extra.lhs);
        const mulend2 = try self.resolve_inst(extra.rhs);
        const addend = try self.resolve_inst(pl_op.operand);

        const ty = self.type_of_index(inst);
        return self.build_float_op(.fma, .normal, ty, 3, .{ mulend1, mulend2, addend });
    }

    fn air_shl_with_overflow(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
        const extra = self.air.extra_data(Air.Bin, ty_pl.payload).data;

        const lhs = try self.resolve_inst(extra.lhs);
        const rhs = try self.resolve_inst(extra.rhs);

        const lhs_ty = self.type_of(extra.lhs);
        const lhs_scalar_ty = lhs_ty.scalar_type(mod);

        const dest_ty = self.type_of_index(inst);
        const llvm_dest_ty = try o.lower_type(dest_ty);

        const casted_rhs = try self.wip.conv(.unsigned, rhs, try o.lower_type(lhs_ty), "");

        const result = try self.wip.bin(.shl, lhs, casted_rhs, "");
        const reconstructed = try self.wip.bin(if (lhs_scalar_ty.is_signed_int(mod))
            .ashr
        else
            .lshr, result, casted_rhs, "");

        const overflow_bit = try self.wip.icmp(.ne, lhs, reconstructed, "");

        const result_index = o.llvm_field_index(dest_ty, 0).?;
        const overflow_index = o.llvm_field_index(dest_ty, 1).?;

        if (is_by_ref(dest_ty, mod)) {
            const result_alignment = dest_ty.abi_alignment(mod).to_llvm();
            const alloca_inst = try self.build_alloca_workaround(dest_ty, result_alignment);
            {
                const field_ptr = try self.wip.gep_struct(llvm_dest_ty, alloca_inst, result_index, "");
                _ = try self.wip.store(.normal, result, field_ptr, result_alignment);
            }
            {
                const field_alignment = comptime Builder.Alignment.from_byte_units(1);
                const field_ptr = try self.wip.gep_struct(llvm_dest_ty, alloca_inst, overflow_index, "");
                _ = try self.wip.store(.normal, overflow_bit, field_ptr, field_alignment);
            }
            return alloca_inst;
        }

        var fields: [2]Builder.Value = undefined;
        fields[result_index] = result;
        fields[overflow_index] = overflow_bit;
        return self.wip.build_aggregate(llvm_dest_ty, &fields, "");
    }

    fn air_and(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
        const lhs = try self.resolve_inst(bin_op.lhs);
        const rhs = try self.resolve_inst(bin_op.rhs);
        return self.wip.bin(.@"and", lhs, rhs, "");
    }

    fn air_or(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
        const lhs = try self.resolve_inst(bin_op.lhs);
        const rhs = try self.resolve_inst(bin_op.rhs);
        return self.wip.bin(.@"or", lhs, rhs, "");
    }

    fn air_xor(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
        const lhs = try self.resolve_inst(bin_op.lhs);
        const rhs = try self.resolve_inst(bin_op.rhs);
        return self.wip.bin(.xor, lhs, rhs, "");
    }

    fn air_shl_exact(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;

        const lhs = try self.resolve_inst(bin_op.lhs);
        const rhs = try self.resolve_inst(bin_op.rhs);

        const lhs_ty = self.type_of(bin_op.lhs);
        const lhs_scalar_ty = lhs_ty.scalar_type(mod);

        const casted_rhs = try self.wip.conv(.unsigned, rhs, try o.lower_type(lhs_ty), "");
        return self.wip.bin(if (lhs_scalar_ty.is_signed_int(mod))
            .@"shl nsw"
        else
            .@"shl nuw", lhs, casted_rhs, "");
    }

    fn air_shl(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;

        const lhs = try self.resolve_inst(bin_op.lhs);
        const rhs = try self.resolve_inst(bin_op.rhs);

        const lhs_type = self.type_of(bin_op.lhs);

        const casted_rhs = try self.wip.conv(.unsigned, rhs, try o.lower_type(lhs_type), "");
        return self.wip.bin(.shl, lhs, casted_rhs, "");
    }

    fn air_shl_sat(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;

        const lhs = try self.resolve_inst(bin_op.lhs);
        const rhs = try self.resolve_inst(bin_op.rhs);

        const lhs_ty = self.type_of(bin_op.lhs);
        const lhs_scalar_ty = lhs_ty.scalar_type(mod);
        const lhs_bits = lhs_scalar_ty.bit_size(mod);

        const casted_rhs = try self.wip.conv(.unsigned, rhs, try o.lower_type(lhs_ty), "");

        const llvm_lhs_ty = try o.lower_type(lhs_ty);
        const llvm_lhs_scalar_ty = llvm_lhs_ty.scalar_type(&o.builder);
        const result = try self.wip.call_intrinsic(
            .normal,
            .none,
            if (lhs_scalar_ty.is_signed_int(mod)) .@"sshl.sat" else .@"ushl.sat",
            &.{llvm_lhs_ty},
            &.{ lhs, casted_rhs },
            "",
        );

        // LLVM langref says "If b is (statically or dynamically) equal to or
        // larger than the integer bit width of the arguments, the result is a
        // poison value."
        // However Zig semantics says that saturating shift left can never produce
        // undefined; instead it saturates.
        const bits = try o.builder.splat_value(
            llvm_lhs_ty,
            try o.builder.int_const(llvm_lhs_scalar_ty, lhs_bits),
        );
        const lhs_max = try o.builder.splat_value(
            llvm_lhs_ty,
            try o.builder.int_const(llvm_lhs_scalar_ty, -1),
        );
        const in_range = try self.wip.icmp(.ult, casted_rhs, bits, "");
        return self.wip.select(.normal, in_range, result, lhs_max, "");
    }

    fn air_shr(self: *FuncGen, inst: Air.Inst.Index, is_exact: bool) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;

        const lhs = try self.resolve_inst(bin_op.lhs);
        const rhs = try self.resolve_inst(bin_op.rhs);

        const lhs_ty = self.type_of(bin_op.lhs);
        const lhs_scalar_ty = lhs_ty.scalar_type(mod);

        const casted_rhs = try self.wip.conv(.unsigned, rhs, try o.lower_type(lhs_ty), "");
        const is_signed_int = lhs_scalar_ty.is_signed_int(mod);

        return self.wip.bin(if (is_exact)
            if (is_signed_int) .@"ashr exact" else .@"lshr exact"
        else if (is_signed_int) .ashr else .lshr, lhs, casted_rhs, "");
    }

    fn air_abs(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
        const operand = try self.resolve_inst(ty_op.operand);
        const operand_ty = self.type_of(ty_op.operand);
        const scalar_ty = operand_ty.scalar_type(mod);

        switch (scalar_ty.zig_type_tag(mod)) {
            .Int => return self.wip.call_intrinsic(
                .normal,
                .none,
                .abs,
                &.{try o.lower_type(operand_ty)},
                &.{ operand, try o.builder.int_value(.i1, 0) },
                "",
            ),
            .Float => return self.build_float_op(.fabs, .normal, operand_ty, 1, .{operand}),
            else => unreachable,
        }
    }

    fn air_int_cast(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
        const dest_ty = self.type_of_index(inst);
        const dest_llvm_ty = try o.lower_type(dest_ty);
        const operand = try self.resolve_inst(ty_op.operand);
        const operand_ty = self.type_of(ty_op.operand);
        const operand_info = operand_ty.int_info(mod);

        return self.wip.conv(switch (operand_info.signedness) {
            .signed => .signed,
            .unsigned => .unsigned,
        }, operand, dest_llvm_ty, "");
    }

    fn air_trunc(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
        const operand = try self.resolve_inst(ty_op.operand);
        const dest_llvm_ty = try o.lower_type(self.type_of_index(inst));
        return self.wip.cast(.trunc, operand, dest_llvm_ty, "");
    }

    fn air_fptrunc(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
        const operand = try self.resolve_inst(ty_op.operand);
        const operand_ty = self.type_of(ty_op.operand);
        const dest_ty = self.type_of_index(inst);
        const target = mod.get_target();
        const dest_bits = dest_ty.float_bits(target);
        const src_bits = operand_ty.float_bits(target);

        if (intrinsics_allowed(dest_ty, target) and intrinsics_allowed(operand_ty, target)) {
            return self.wip.cast(.fptrunc, operand, try o.lower_type(dest_ty), "");
        } else {
            const operand_llvm_ty = try o.lower_type(operand_ty);
            const dest_llvm_ty = try o.lower_type(dest_ty);

            const fn_name = try o.builder.strtab_string_fmt("__trunc{s}f{s}f2", .{
                compiler_rt_float_abbrev(src_bits), compiler_rt_float_abbrev(dest_bits),
            });

            const libc_fn = try self.get_libc_function(fn_name, &.{operand_llvm_ty}, dest_llvm_ty);
            return self.wip.call(
                .normal,
                .ccc,
                .none,
                libc_fn.type_of(&o.builder),
                libc_fn.to_value(&o.builder),
                &.{operand},
                "",
            );
        }
    }

    fn air_fpext(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
        const operand = try self.resolve_inst(ty_op.operand);
        const operand_ty = self.type_of(ty_op.operand);
        const dest_ty = self.type_of_index(inst);
        const target = mod.get_target();

        if (intrinsics_allowed(dest_ty, target) and intrinsics_allowed(operand_ty, target)) {
            return self.wip.cast(.fpext, operand, try o.lower_type(dest_ty), "");
        } else {
            const operand_llvm_ty = try o.lower_type(operand_ty);
            const dest_llvm_ty = try o.lower_type(dest_ty);

            const dest_bits = dest_ty.scalar_type(mod).float_bits(target);
            const src_bits = operand_ty.scalar_type(mod).float_bits(target);
            const fn_name = try o.builder.strtab_string_fmt("__extend{s}f{s}f2", .{
                compiler_rt_float_abbrev(src_bits), compiler_rt_float_abbrev(dest_bits),
            });

            const libc_fn = try self.get_libc_function(fn_name, &.{operand_llvm_ty}, dest_llvm_ty);
            if (dest_ty.is_vector(mod)) return self.build_elementwise_call(
                libc_fn,
                &.{operand},
                try o.builder.poison_value(dest_llvm_ty),
                dest_ty.vector_len(mod),
            );
            return self.wip.call(
                .normal,
                .ccc,
                .none,
                libc_fn.type_of(&o.builder),
                libc_fn.to_value(&o.builder),
                &.{operand},
                "",
            );
        }
    }

    fn air_int_from_ptr(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
        const operand = try self.resolve_inst(un_op);
        const ptr_ty = self.type_of(un_op);
        const operand_ptr = try self.slice_or_array_ptr(operand, ptr_ty);
        const dest_llvm_ty = try o.lower_type(self.type_of_index(inst));
        return self.wip.cast(.ptrtoint, operand_ptr, dest_llvm_ty, "");
    }

    fn air_bit_cast(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
        const operand_ty = self.type_of(ty_op.operand);
        const inst_ty = self.type_of_index(inst);
        const operand = try self.resolve_inst(ty_op.operand);
        return self.bit_cast(operand, operand_ty, inst_ty);
    }

    fn bit_cast(self: *FuncGen, operand: Builder.Value, operand_ty: Type, inst_ty: Type) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const operand_is_ref = is_by_ref(operand_ty, mod);
        const result_is_ref = is_by_ref(inst_ty, mod);
        const llvm_dest_ty = try o.lower_type(inst_ty);

        if (operand_is_ref and result_is_ref) {
            // They are both pointers, so just return the same opaque pointer :)
            return operand;
        }

        if (llvm_dest_ty.is_integer(&o.builder) and
            operand.type_of_wip(&self.wip).is_integer(&o.builder))
        {
            return self.wip.conv(.unsigned, operand, llvm_dest_ty, "");
        }

        if (operand_ty.zig_type_tag(mod) == .Int and inst_ty.is_ptr_at_runtime(mod)) {
            return self.wip.cast(.inttoptr, operand, llvm_dest_ty, "");
        }

        if (operand_ty.zig_type_tag(mod) == .Vector and inst_ty.zig_type_tag(mod) == .Array) {
            const elem_ty = operand_ty.child_type(mod);
            if (!result_is_ref) {
                return self.dg.todo("implement bitcast vector to non-ref array", .{});
            }
            const alignment = inst_ty.abi_alignment(mod).to_llvm();
            const array_ptr = try self.build_alloca_workaround(inst_ty, alignment);
            const bitcast_ok = elem_ty.bit_size(mod) == elem_ty.abi_size(mod) * 8;
            if (bitcast_ok) {
                _ = try self.wip.store(.normal, operand, array_ptr, alignment);
            } else {
                // If the ABI size of the element type is not evenly divisible by size in bits;
                // a simple bitcast will not work, and we fall back to extractelement.
                const llvm_usize = try o.lower_type(Type.usize);
                const usize_zero = try o.builder.int_value(llvm_usize, 0);
                const vector_len = operand_ty.array_len(mod);
                var i: u64 = 0;
                while (i < vector_len) : (i += 1) {
                    const elem_ptr = try self.wip.gep(.inbounds, llvm_dest_ty, array_ptr, &.{
                        usize_zero, try o.builder.int_value(llvm_usize, i),
                    }, "");
                    const elem =
                        try self.wip.extract_element(operand, try o.builder.int_value(.i32, i), "");
                    _ = try self.wip.store(.normal, elem, elem_ptr, .default);
                }
            }
            return array_ptr;
        } else if (operand_ty.zig_type_tag(mod) == .Array and inst_ty.zig_type_tag(mod) == .Vector) {
            const elem_ty = operand_ty.child_type(mod);
            const llvm_vector_ty = try o.lower_type(inst_ty);
            if (!operand_is_ref) return self.dg.todo("implement bitcast non-ref array to vector", .{});

            const bitcast_ok = elem_ty.bit_size(mod) == elem_ty.abi_size(mod) * 8;
            if (bitcast_ok) {
                // The array is aligned to the element's alignment, while the vector might have a completely
                // different alignment. This means we need to enforce the alignment of this load.
                const alignment = elem_ty.abi_alignment(mod).to_llvm();
                return self.wip.load(.normal, llvm_vector_ty, operand, alignment, "");
            } else {
                // If the ABI size of the element type is not evenly divisible by size in bits;
                // a simple bitcast will not work, and we fall back to extractelement.
                const array_llvm_ty = try o.lower_type(operand_ty);
                const elem_llvm_ty = try o.lower_type(elem_ty);
                const llvm_usize = try o.lower_type(Type.usize);
                const usize_zero = try o.builder.int_value(llvm_usize, 0);
                const vector_len = operand_ty.array_len(mod);
                var vector = try o.builder.poison_value(llvm_vector_ty);
                var i: u64 = 0;
                while (i < vector_len) : (i += 1) {
                    const elem_ptr = try self.wip.gep(.inbounds, array_llvm_ty, operand, &.{
                        usize_zero, try o.builder.int_value(llvm_usize, i),
                    }, "");
                    const elem = try self.wip.load(.normal, elem_llvm_ty, elem_ptr, .default, "");
                    vector =
                        try self.wip.insert_element(vector, elem, try o.builder.int_value(.i32, i), "");
                }
                return vector;
            }
        }

        if (operand_is_ref) {
            const alignment = operand_ty.abi_alignment(mod).to_llvm();
            return self.wip.load(.normal, llvm_dest_ty, operand, alignment, "");
        }

        if (result_is_ref) {
            const alignment = operand_ty.abi_alignment(mod).max(inst_ty.abi_alignment(mod)).to_llvm();
            const result_ptr = try self.build_alloca_workaround(inst_ty, alignment);
            _ = try self.wip.store(.normal, operand, result_ptr, alignment);
            return result_ptr;
        }

        if (llvm_dest_ty.is_struct(&o.builder) or
            ((operand_ty.zig_type_tag(mod) == .Vector or inst_ty.zig_type_tag(mod) == .Vector) and operand_ty.bit_size(mod) != inst_ty.bit_size(mod)))
        {
            // Both our operand and our result are values, not pointers,
            // but LLVM won't let us bitcast struct values or vectors with padding bits.
            // Therefore, we store operand to alloca, then load for result.
            const alignment = operand_ty.abi_alignment(mod).max(inst_ty.abi_alignment(mod)).to_llvm();
            const result_ptr = try self.build_alloca_workaround(inst_ty, alignment);
            _ = try self.wip.store(.normal, operand, result_ptr, alignment);
            return self.wip.load(.normal, llvm_dest_ty, result_ptr, alignment, "");
        }

        return self.wip.cast(.bitcast, operand, llvm_dest_ty, "");
    }

    fn air_int_from_bool(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
        const operand = try self.resolve_inst(un_op);
        return operand;
    }

    fn air_arg(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const arg_val = self.args[self.arg_index];
        self.arg_index += 1;

        if (self.wip.strip) return arg_val;

        const inst_ty = self.type_of_index(inst);
        if (need_dbg_var_workaround(o)) return arg_val;

        const src_index = self.air.instructions.items(.data)[@int_from_enum(inst)].arg.src_index;
        const func_index = self.dg.decl.get_owned_function_index();
        const func = mod.func_info(func_index);
        const lbrace_line = mod.decl_ptr(func.owner_decl).src_line + func.lbrace_line + 1;
        const lbrace_col = func.lbrace_column + 1;

        const debug_parameter = try o.builder.debug_parameter(
            try o.builder.metadata_string(mod.get_param_name(func_index, src_index)),
            self.file,
            self.scope,
            lbrace_line,
            try o.lower_debug_type(inst_ty),
            @int_cast(self.arg_index),
        );

        const old_location = self.wip.debug_location;
        self.wip.debug_location = .{
            .location = .{
                .line = lbrace_line,
                .column = lbrace_col,
                .scope = self.scope,
                .inlined_at = .none,
            },
        };

        const owner_mod = self.dg.owner_module();
        if (is_by_ref(inst_ty, mod)) {
            _ = try self.wip.call_intrinsic(
                .normal,
                .none,
                .@"dbg.declare",
                &.{},
                &.{
                    (try self.wip.debug_value(arg_val)).to_value(),
                    debug_parameter.to_value(),
                    (try o.builder.debug_expression(&.{})).to_value(),
                },
                "",
            );
        } else if (owner_mod.optimize_mode == .Debug) {
            const alignment = inst_ty.abi_alignment(mod).to_llvm();
            const alloca = try self.build_alloca(arg_val.type_of_wip(&self.wip), alignment);
            _ = try self.wip.store(.normal, arg_val, alloca, alignment);
            _ = try self.wip.call_intrinsic(
                .normal,
                .none,
                .@"dbg.declare",
                &.{},
                &.{
                    (try self.wip.debug_value(alloca)).to_value(),
                    debug_parameter.to_value(),
                    (try o.builder.debug_expression(&.{})).to_value(),
                },
                "",
            );
        } else {
            _ = try self.wip.call_intrinsic(
                .normal,
                .none,
                .@"dbg.value",
                &.{},
                &.{
                    (try self.wip.debug_value(arg_val)).to_value(),
                    debug_parameter.to_value(),
                    (try o.builder.debug_expression(&.{})).to_value(),
                },
                "",
            );
        }

        self.wip.debug_location = old_location;
        return arg_val;
    }

    fn air_alloc(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const ptr_ty = self.type_of_index(inst);
        const pointee_type = ptr_ty.child_type(mod);
        if (!pointee_type.is_fn_or_has_runtime_bits_ignore_comptime(mod))
            return (try o.lower_ptr_to_void(ptr_ty)).to_value();

        //const pointee_llvm_ty = try o.lower_type(pointee_type);
        const alignment = ptr_ty.ptr_alignment(mod).to_llvm();
        return self.build_alloca_workaround(pointee_type, alignment);
    }

    fn air_ret_ptr(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const ptr_ty = self.type_of_index(inst);
        const ret_ty = ptr_ty.child_type(mod);
        if (!ret_ty.is_fn_or_has_runtime_bits_ignore_comptime(mod))
            return (try o.lower_ptr_to_void(ptr_ty)).to_value();
        if (self.ret_ptr != .none) return self.ret_ptr;
        //const ret_llvm_ty = try o.lower_type(ret_ty);
        const alignment = ptr_ty.ptr_alignment(mod).to_llvm();
        return self.build_alloca_workaround(ret_ty, alignment);
    }

    /// Use this instead of builder.build_alloca, because this function makes sure to
    /// put the alloca instruction at the top of the function!
    fn build_alloca(
        self: *FuncGen,
        llvm_ty: Builder.Type,
        alignment: Builder.Alignment,
    ) Allocator.Error!Builder.Value {
        const target = self.dg.object.module.get_target();
        return build_alloca_inner(&self.wip, llvm_ty, alignment, target);
    }

    // Workaround for https://github.com/ziglang/zig/issues/16392
    fn build_alloca_workaround(
        self: *FuncGen,
        ty: Type,
        alignment: Builder.Alignment,
    ) Allocator.Error!Builder.Value {
        const o = self.dg.object;
        return self.build_alloca(try o.builder.array_type(ty.abi_size(o.module), .i8), alignment);
    }

    fn air_store(self: *FuncGen, inst: Air.Inst.Index, safety: bool) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
        const dest_ptr = try self.resolve_inst(bin_op.lhs);
        const ptr_ty = self.type_of(bin_op.lhs);
        const operand_ty = ptr_ty.child_type(mod);

        const val_is_undef = if (try self.air.value(bin_op.rhs, mod)) |val| val.is_undef_deep(mod) else false;
        if (val_is_undef) {
            const ptr_info = ptr_ty.ptr_info(mod);
            const needs_bitmask = (ptr_info.packed_offset.host_size != 0);
            if (needs_bitmask) {
                // TODO: only some bits are to be undef, we cannot write with a simple memset.
                // meanwhile, ignore the write rather than stomping over valid bits.
                // https://github.com/ziglang/zig/issues/15337
                return .none;
            }

            // Even if safety is disabled, we still emit a memset to undefined since it conveys
            // extra information to LLVM. However, safety makes the difference between using
            // 0xaa or actual undefined for the fill byte.
            const len = try o.builder.int_value(try o.lower_type(Type.usize), operand_ty.abi_size(mod));
            _ = try self.wip.call_mem_set(
                dest_ptr,
                ptr_ty.ptr_alignment(mod).to_llvm(),
                if (safety) try o.builder.int_value(.i8, 0xaa) else try o.builder.undef_value(.i8),
                len,
                if (ptr_ty.is_volatile_ptr(mod)) .@"volatile" else .normal,
            );
            const owner_mod = self.dg.owner_module();
            if (safety and owner_mod.valgrind) {
                try self.valgrind_mark_undef(dest_ptr, len);
            }
            return .none;
        }

        const src_operand = try self.resolve_inst(bin_op.rhs);
        try self.store(dest_ptr, ptr_ty, src_operand, .none);
        return .none;
    }

    /// As an optimization, we want to avoid unnecessary copies of is_by_ref=true
    /// types. Here, we scan forward in the current block, looking to see if
    /// this load dies before any side effects occur. In such case, we can
    /// safely return the operand without making a copy.
    ///
    /// The first instruction of `body_tail` is the one whose copy we want to elide.
    fn can_elide_load(fg: *FuncGen, body_tail: []const Air.Inst.Index) bool {
        const o = fg.dg.object;
        const mod = o.module;
        const ip = &mod.intern_pool;
        for (body_tail[1..]) |body_inst| {
            switch (fg.liveness.categorize_operand(fg.air, body_inst, body_tail[0], ip)) {
                .none => continue,
                .write, .noret, .complex => return false,
                .tomb => return true,
            }
        }
        // The only way to get here is to hit the end of a loop instruction
        // (implicit repeat).
        return false;
    }

    fn air_load(fg: *FuncGen, body_tail: []const Air.Inst.Index) !Builder.Value {
        const o = fg.dg.object;
        const mod = o.module;
        const inst = body_tail[0];
        const ty_op = fg.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
        const ptr_ty = fg.type_of(ty_op.operand);
        const ptr_info = ptr_ty.ptr_info(mod);
        const ptr = try fg.resolve_inst(ty_op.operand);

        elide: {
            if (!is_by_ref(Type.from_interned(ptr_info.child), mod)) break :elide;
            if (!can_elide_load(fg, body_tail)) break :elide;
            return ptr;
        }
        return fg.load(ptr, ptr_ty);
    }

    fn air_trap(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        _ = inst;
        _ = try self.wip.call_intrinsic(.normal, .none, .trap, &.{}, &.{}, "");
        _ = try self.wip.@"unreachable"();
        return .none;
    }

    fn air_breakpoint(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        _ = inst;
        _ = try self.wip.call_intrinsic(.normal, .none, .debugtrap, &.{}, &.{}, "");
        return .none;
    }

    fn air_ret_addr(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        _ = inst;
        const o = self.dg.object;
        const llvm_usize = try o.lower_type(Type.usize);
        if (!target_util.supports_return_address(o.module.get_target())) {
            // https://github.com/ziglang/zig/issues/11946
            return o.builder.int_value(llvm_usize, 0);
        }
        const result = try self.wip.call_intrinsic(.normal, .none, .returnaddress, &.{}, &.{.@"0"}, "");
        return self.wip.cast(.ptrtoint, result, llvm_usize, "");
    }

    fn air_frame_address(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        _ = inst;
        const o = self.dg.object;
        const result = try self.wip.call_intrinsic(.normal, .none, .frameaddress, &.{.ptr}, &.{.@"0"}, "");
        return self.wip.cast(.ptrtoint, result, try o.lower_type(Type.usize), "");
    }

    fn air_fence(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const atomic_order = self.air.instructions.items(.data)[@int_from_enum(inst)].fence;
        const ordering = to_llvm_atomic_ordering(atomic_order);
        _ = try self.wip.fence(self.sync_scope, ordering);
        return .none;
    }

    fn air_cmpxchg(
        self: *FuncGen,
        inst: Air.Inst.Index,
        kind: Builder.Function.Instruction.CmpXchg.Kind,
    ) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
        const extra = self.air.extra_data(Air.Cmpxchg, ty_pl.payload).data;
        const ptr = try self.resolve_inst(extra.ptr);
        const ptr_ty = self.type_of(extra.ptr);
        var expected_value = try self.resolve_inst(extra.expected_value);
        var new_value = try self.resolve_inst(extra.new_value);
        const operand_ty = ptr_ty.child_type(mod);
        const llvm_operand_ty = try o.lower_type(operand_ty);
        const llvm_abi_ty = try o.get_atomic_abi_type(operand_ty, false);
        if (llvm_abi_ty != .none) {
            // operand needs widening and truncating
            const signedness: Builder.Function.Instruction.Cast.Signedness =
                if (operand_ty.is_signed_int(mod)) .signed else .unsigned;
            expected_value = try self.wip.conv(signedness, expected_value, llvm_abi_ty, "");
            new_value = try self.wip.conv(signedness, new_value, llvm_abi_ty, "");
        }

        const result = try self.wip.cmpxchg(
            kind,
            if (ptr_ty.is_volatile_ptr(mod)) .@"volatile" else .normal,
            ptr,
            expected_value,
            new_value,
            self.sync_scope,
            to_llvm_atomic_ordering(extra.success_order()),
            to_llvm_atomic_ordering(extra.failure_order()),
            ptr_ty.ptr_alignment(mod).to_llvm(),
            "",
        );

        const optional_ty = self.type_of_index(inst);

        var payload = try self.wip.extract_value(result, &.{0}, "");
        if (llvm_abi_ty != .none) payload = try self.wip.cast(.trunc, payload, llvm_operand_ty, "");
        const success_bit = try self.wip.extract_value(result, &.{1}, "");

        if (optional_ty.optional_repr_is_payload(mod)) {
            const zero = try o.builder.zero_init_value(payload.type_of_wip(&self.wip));
            return self.wip.select(.normal, success_bit, zero, payload, "");
        }

        comptime assert(optional_layout_version == 3);

        const non_null_bit = try self.wip.not(success_bit, "");
        return build_optional(self, optional_ty, payload, non_null_bit);
    }

    fn air_atomic_rmw(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const pl_op = self.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
        const extra = self.air.extra_data(Air.AtomicRmw, pl_op.payload).data;
        const ptr = try self.resolve_inst(pl_op.operand);
        const ptr_ty = self.type_of(pl_op.operand);
        const operand_ty = ptr_ty.child_type(mod);
        const operand = try self.resolve_inst(extra.operand);
        const is_signed_int = operand_ty.is_signed_int(mod);
        const is_float = operand_ty.is_runtime_float();
        const op = to_llvm_atomic_rmw_bin_op(extra.op(), is_signed_int, is_float);
        const ordering = to_llvm_atomic_ordering(extra.ordering());
        const llvm_abi_ty = try o.get_atomic_abi_type(operand_ty, op == .xchg);
        const llvm_operand_ty = try o.lower_type(operand_ty);

        const access_kind: Builder.MemoryAccessKind =
            if (ptr_ty.is_volatile_ptr(mod)) .@"volatile" else .normal;
        const ptr_alignment = ptr_ty.ptr_alignment(mod).to_llvm();

        if (llvm_abi_ty != .none) {
            // operand needs widening and truncating or bitcasting.
            return self.wip.cast(if (is_float) .bitcast else .trunc, try self.wip.atomicrmw(
                access_kind,
                op,
                ptr,
                try self.wip.cast(
                    if (is_float) .bitcast else if (is_signed_int) .sext else .zext,
                    operand,
                    llvm_abi_ty,
                    "",
                ),
                self.sync_scope,
                ordering,
                ptr_alignment,
                "",
            ), llvm_operand_ty, "");
        }

        if (!llvm_operand_ty.is_pointer(&o.builder)) return self.wip.atomicrmw(
            access_kind,
            op,
            ptr,
            operand,
            self.sync_scope,
            ordering,
            ptr_alignment,
            "",
        );

        // It's a pointer but we need to treat it as an int.
        return self.wip.cast(.inttoptr, try self.wip.atomicrmw(
            access_kind,
            op,
            ptr,
            try self.wip.cast(.ptrtoint, operand, try o.lower_type(Type.usize), ""),
            self.sync_scope,
            ordering,
            ptr_alignment,
            "",
        ), llvm_operand_ty, "");
    }

    fn air_atomic_load(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const atomic_load = self.air.instructions.items(.data)[@int_from_enum(inst)].atomic_load;
        const ptr = try self.resolve_inst(atomic_load.ptr);
        const ptr_ty = self.type_of(atomic_load.ptr);
        const info = ptr_ty.ptr_info(mod);
        const elem_ty = Type.from_interned(info.child);
        if (!elem_ty.has_runtime_bits_ignore_comptime(mod)) return .none;
        const ordering = to_llvm_atomic_ordering(atomic_load.order);
        const llvm_abi_ty = try o.get_atomic_abi_type(elem_ty, false);
        const ptr_alignment = (if (info.flags.alignment != .none)
            @as(InternPool.Alignment, info.flags.alignment)
        else
            Type.from_interned(info.child).abi_alignment(mod)).to_llvm();
        const access_kind: Builder.MemoryAccessKind =
            if (info.flags.is_volatile) .@"volatile" else .normal;
        const elem_llvm_ty = try o.lower_type(elem_ty);

        if (llvm_abi_ty != .none) {
            // operand needs widening and truncating
            const loaded = try self.wip.load_atomic(
                access_kind,
                llvm_abi_ty,
                ptr,
                self.sync_scope,
                ordering,
                ptr_alignment,
                "",
            );
            return self.wip.cast(.trunc, loaded, elem_llvm_ty, "");
        }
        return self.wip.load_atomic(
            access_kind,
            elem_llvm_ty,
            ptr,
            self.sync_scope,
            ordering,
            ptr_alignment,
            "",
        );
    }

    fn air_atomic_store(
        self: *FuncGen,
        inst: Air.Inst.Index,
        ordering: Builder.AtomicOrdering,
    ) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
        const ptr_ty = self.type_of(bin_op.lhs);
        const operand_ty = ptr_ty.child_type(mod);
        if (!operand_ty.is_fn_or_has_runtime_bits_ignore_comptime(mod)) return .none;
        const ptr = try self.resolve_inst(bin_op.lhs);
        var element = try self.resolve_inst(bin_op.rhs);
        const llvm_abi_ty = try o.get_atomic_abi_type(operand_ty, false);

        if (llvm_abi_ty != .none) {
            // operand needs widening
            element = try self.wip.conv(
                if (operand_ty.is_signed_int(mod)) .signed else .unsigned,
                element,
                llvm_abi_ty,
                "",
            );
        }
        try self.store(ptr, ptr_ty, element, ordering);
        return .none;
    }

    fn air_memset(self: *FuncGen, inst: Air.Inst.Index, safety: bool) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
        const dest_slice = try self.resolve_inst(bin_op.lhs);
        const ptr_ty = self.type_of(bin_op.lhs);
        const elem_ty = self.type_of(bin_op.rhs);
        const dest_ptr_align = ptr_ty.ptr_alignment(mod).to_llvm();
        const dest_ptr = try self.slice_or_array_ptr(dest_slice, ptr_ty);
        const access_kind: Builder.MemoryAccessKind =
            if (ptr_ty.is_volatile_ptr(mod)) .@"volatile" else .normal;

        // Any WebAssembly runtime will trap when the destination pointer is out-of-bounds, regardless
        // of the length. This means we need to emit a check where we skip the memset when the length
        // is 0 as we allow for undefined pointers in 0-sized slices.
        // This logic can be removed once https://github.com/ziglang/zig/issues/16360 is done.
        const intrinsic_len0_traps = o.target.is_wasm() and
            ptr_ty.is_slice(mod) and
            std.Target.wasm.feature_set_has(o.target.cpu.features, .bulk_memory);

        if (try self.air.value(bin_op.rhs, mod)) |elem_val| {
            if (elem_val.is_undef_deep(mod)) {
                // Even if safety is disabled, we still emit a memset to undefined since it conveys
                // extra information to LLVM. However, safety makes the difference between using
                // 0xaa or actual undefined for the fill byte.
                const fill_byte = if (safety)
                    try o.builder.int_value(.i8, 0xaa)
                else
                    try o.builder.undef_value(.i8);
                const len = try self.slice_or_array_len_in_bytes(dest_slice, ptr_ty);
                if (intrinsic_len0_traps) {
                    try self.safe_wasm_memset(dest_ptr, fill_byte, len, dest_ptr_align, access_kind);
                } else {
                    _ = try self.wip.call_mem_set(dest_ptr, dest_ptr_align, fill_byte, len, access_kind);
                }
                const owner_mod = self.dg.owner_module();
                if (safety and owner_mod.valgrind) {
                    try self.valgrind_mark_undef(dest_ptr, len);
                }
                return .none;
            }

            // Test if the element value is compile-time known to be a
            // repeating byte pattern, for example, `@as(u64, 0)` has a
            // repeating byte pattern of 0 bytes. In such case, the memset
            // intrinsic can be used.
            if (try elem_val.has_repeated_byte_repr(elem_ty, mod)) |byte_val| {
                const fill_byte = try o.builder.int_value(.i8, byte_val);
                const len = try self.slice_or_array_len_in_bytes(dest_slice, ptr_ty);
                if (intrinsic_len0_traps) {
                    try self.safe_wasm_memset(dest_ptr, fill_byte, len, dest_ptr_align, access_kind);
                } else {
                    _ = try self.wip.call_mem_set(dest_ptr, dest_ptr_align, fill_byte, len, access_kind);
                }
                return .none;
            }
        }

        const value = try self.resolve_inst(bin_op.rhs);
        const elem_abi_size = elem_ty.abi_size(mod);

        if (elem_abi_size == 1) {
            // In this case we can take advantage of LLVM's intrinsic.
            const fill_byte = try self.bit_cast(value, elem_ty, Type.u8);
            const len = try self.slice_or_array_len_in_bytes(dest_slice, ptr_ty);

            if (intrinsic_len0_traps) {
                try self.safe_wasm_memset(dest_ptr, fill_byte, len, dest_ptr_align, access_kind);
            } else {
                _ = try self.wip.call_mem_set(dest_ptr, dest_ptr_align, fill_byte, len, access_kind);
            }
            return .none;
        }

        // non-byte-sized element. lower with a loop. something like this:

        // entry:
        //   ...
        //   %end_ptr = getelementptr %ptr, %len
        //   br %loop
        // loop:
        //   %it_ptr = phi body %next_ptr, entry %ptr
        //   %end = cmp eq %it_ptr, %end_ptr
        //   br %end, %body, %end
        // body:
        //   store %it_ptr, %value
        //   %next_ptr = getelementptr %it_ptr, 1
        //   br %loop
        // end:
        //   ...
        const entry_block = self.wip.cursor.block;
        const loop_block = try self.wip.block(2, "InlineMemsetLoop");
        const body_block = try self.wip.block(1, "InlineMemsetBody");
        const end_block = try self.wip.block(1, "InlineMemsetEnd");

        const llvm_usize_ty = try o.lower_type(Type.usize);
        const len = switch (ptr_ty.ptr_size(mod)) {
            .Slice => try self.wip.extract_value(dest_slice, &.{1}, ""),
            .One => try o.builder.int_value(llvm_usize_ty, ptr_ty.child_type(mod).array_len(mod)),
            .Many, .C => unreachable,
        };
        const elem_llvm_ty = try o.lower_type(elem_ty);
        const end_ptr = try self.wip.gep(.inbounds, elem_llvm_ty, dest_ptr, &.{len}, "");
        _ = try self.wip.br(loop_block);

        self.wip.cursor = .{ .block = loop_block };
        const it_ptr = try self.wip.phi(.ptr, "");
        const end = try self.wip.icmp(.ne, it_ptr.to_value(), end_ptr, "");
        _ = try self.wip.br_cond(end, body_block, end_block);

        self.wip.cursor = .{ .block = body_block };
        const elem_abi_align = elem_ty.abi_alignment(mod);
        const it_ptr_align = InternPool.Alignment.from_llvm(dest_ptr_align).min(elem_abi_align).to_llvm();
        if (is_by_ref(elem_ty, mod)) {
            _ = try self.wip.call_mem_cpy(
                it_ptr.to_value(),
                it_ptr_align,
                value,
                elem_abi_align.to_llvm(),
                try o.builder.int_value(llvm_usize_ty, elem_abi_size),
                access_kind,
            );
        } else _ = try self.wip.store(access_kind, value, it_ptr.to_value(), it_ptr_align);
        const next_ptr = try self.wip.gep(.inbounds, elem_llvm_ty, it_ptr.to_value(), &.{
            try o.builder.int_value(llvm_usize_ty, 1),
        }, "");
        _ = try self.wip.br(loop_block);

        self.wip.cursor = .{ .block = end_block };
        it_ptr.finish(&.{ next_ptr, dest_ptr }, &.{ body_block, entry_block }, &self.wip);
        return .none;
    }

    fn safe_wasm_memset(
        self: *FuncGen,
        dest_ptr: Builder.Value,
        fill_byte: Builder.Value,
        len: Builder.Value,
        dest_ptr_align: Builder.Alignment,
        access_kind: Builder.MemoryAccessKind,
    ) !void {
        const o = self.dg.object;
        const usize_zero = try o.builder.int_value(try o.lower_type(Type.usize), 0);
        const cond = try self.cmp(.normal, .neq, Type.usize, len, usize_zero);
        const memset_block = try self.wip.block(1, "MemsetTrapSkip");
        const end_block = try self.wip.block(2, "MemsetTrapEnd");
        _ = try self.wip.br_cond(cond, memset_block, end_block);
        self.wip.cursor = .{ .block = memset_block };
        _ = try self.wip.call_mem_set(dest_ptr, dest_ptr_align, fill_byte, len, access_kind);
        _ = try self.wip.br(end_block);
        self.wip.cursor = .{ .block = end_block };
    }

    fn air_memcpy(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
        const dest_slice = try self.resolve_inst(bin_op.lhs);
        const dest_ptr_ty = self.type_of(bin_op.lhs);
        const src_slice = try self.resolve_inst(bin_op.rhs);
        const src_ptr_ty = self.type_of(bin_op.rhs);
        const src_ptr = try self.slice_or_array_ptr(src_slice, src_ptr_ty);
        const len = try self.slice_or_array_len_in_bytes(dest_slice, dest_ptr_ty);
        const dest_ptr = try self.slice_or_array_ptr(dest_slice, dest_ptr_ty);
        const access_kind: Builder.MemoryAccessKind = if (src_ptr_ty.is_volatile_ptr(mod) or
            dest_ptr_ty.is_volatile_ptr(mod)) .@"volatile" else .normal;

        // When bulk-memory is enabled, this will be lowered to WebAssembly's memory.copy instruction.
        // This instruction will trap on an invalid address, regardless of the length.
        // For this reason we must add a check for 0-sized slices as its pointer field can be undefined.
        // We only have to do this for slices as arrays will have a valid pointer.
        // This logic can be removed once https://github.com/ziglang/zig/issues/16360 is done.
        if (o.target.is_wasm() and
            std.Target.wasm.feature_set_has(o.target.cpu.features, .bulk_memory) and
            dest_ptr_ty.is_slice(mod))
        {
            const usize_zero = try o.builder.int_value(try o.lower_type(Type.usize), 0);
            const cond = try self.cmp(.normal, .neq, Type.usize, len, usize_zero);
            const memcpy_block = try self.wip.block(1, "MemcpyTrapSkip");
            const end_block = try self.wip.block(2, "MemcpyTrapEnd");
            _ = try self.wip.br_cond(cond, memcpy_block, end_block);
            self.wip.cursor = .{ .block = memcpy_block };
            _ = try self.wip.call_mem_cpy(
                dest_ptr,
                dest_ptr_ty.ptr_alignment(mod).to_llvm(),
                src_ptr,
                src_ptr_ty.ptr_alignment(mod).to_llvm(),
                len,
                access_kind,
            );
            _ = try self.wip.br(end_block);
            self.wip.cursor = .{ .block = end_block };
            return .none;
        }

        _ = try self.wip.call_mem_cpy(
            dest_ptr,
            dest_ptr_ty.ptr_alignment(mod).to_llvm(),
            src_ptr,
            src_ptr_ty.ptr_alignment(mod).to_llvm(),
            len,
            access_kind,
        );
        return .none;
    }

    fn air_set_union_tag(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
        const un_ty = self.type_of(bin_op.lhs).child_type(mod);
        const layout = un_ty.union_get_layout(mod);
        if (layout.tag_size == 0) return .none;
        const union_ptr = try self.resolve_inst(bin_op.lhs);
        const new_tag = try self.resolve_inst(bin_op.rhs);
        if (layout.payload_size == 0) {
            // TODO alignment on this store
            _ = try self.wip.store(.normal, new_tag, union_ptr, .default);
            return .none;
        }
        const tag_index = @int_from_bool(layout.tag_align.compare(.lt, layout.payload_align));
        const tag_field_ptr = try self.wip.gep_struct(try o.lower_type(un_ty), union_ptr, tag_index, "");
        // TODO alignment on this store
        _ = try self.wip.store(.normal, new_tag, tag_field_ptr, .default);
        return .none;
    }

    fn air_get_union_tag(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
        const un_ty = self.type_of(ty_op.operand);
        const layout = un_ty.union_get_layout(mod);
        if (layout.tag_size == 0) return .none;
        const union_handle = try self.resolve_inst(ty_op.operand);
        if (is_by_ref(un_ty, mod)) {
            const llvm_un_ty = try o.lower_type(un_ty);
            if (layout.payload_size == 0)
                return self.wip.load(.normal, llvm_un_ty, union_handle, .default, "");
            const tag_index = @int_from_bool(layout.tag_align.compare(.lt, layout.payload_align));
            const tag_field_ptr = try self.wip.gep_struct(llvm_un_ty, union_handle, tag_index, "");
            const llvm_tag_ty = llvm_un_ty.struct_fields(&o.builder)[tag_index];
            return self.wip.load(.normal, llvm_tag_ty, tag_field_ptr, .default, "");
        } else {
            if (layout.payload_size == 0) return union_handle;
            const tag_index = @int_from_bool(layout.tag_align.compare(.lt, layout.payload_align));
            return self.wip.extract_value(union_handle, &.{tag_index}, "");
        }
    }

    fn air_unary_op(self: *FuncGen, inst: Air.Inst.Index, comptime op: FloatOp) !Builder.Value {
        const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
        const operand = try self.resolve_inst(un_op);
        const operand_ty = self.type_of(un_op);

        return self.build_float_op(op, .normal, operand_ty, 1, .{operand});
    }

    fn air_neg(self: *FuncGen, inst: Air.Inst.Index, fast: Builder.FastMathKind) !Builder.Value {
        const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
        const operand = try self.resolve_inst(un_op);
        const operand_ty = self.type_of(un_op);

        return self.build_float_op(.neg, fast, operand_ty, 1, .{operand});
    }

    fn air_clz_ctz(self: *FuncGen, inst: Air.Inst.Index, intrinsic: Builder.Intrinsic) !Builder.Value {
        const o = self.dg.object;
        const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
        const inst_ty = self.type_of_index(inst);
        const operand_ty = self.type_of(ty_op.operand);
        const operand = try self.resolve_inst(ty_op.operand);

        const result = try self.wip.call_intrinsic(
            .normal,
            .none,
            intrinsic,
            &.{try o.lower_type(operand_ty)},
            &.{ operand, .false },
            "",
        );
        return self.wip.conv(.unsigned, result, try o.lower_type(inst_ty), "");
    }

    fn air_bit_op(self: *FuncGen, inst: Air.Inst.Index, intrinsic: Builder.Intrinsic) !Builder.Value {
        const o = self.dg.object;
        const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
        const inst_ty = self.type_of_index(inst);
        const operand_ty = self.type_of(ty_op.operand);
        const operand = try self.resolve_inst(ty_op.operand);

        const result = try self.wip.call_intrinsic(
            .normal,
            .none,
            intrinsic,
            &.{try o.lower_type(operand_ty)},
            &.{operand},
            "",
        );
        return self.wip.conv(.unsigned, result, try o.lower_type(inst_ty), "");
    }

    fn air_byte_swap(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
        const operand_ty = self.type_of(ty_op.operand);
        var bits = operand_ty.int_info(mod).bits;
        assert(bits % 8 == 0);

        const inst_ty = self.type_of_index(inst);
        var operand = try self.resolve_inst(ty_op.operand);
        var llvm_operand_ty = try o.lower_type(operand_ty);

        if (bits % 16 == 8) {
            // If not an even byte-multiple, we need zero-extend + shift-left 1 byte
            // The truncated result at the end will be the correct bswap
            const scalar_ty = try o.builder.int_type(@int_cast(bits + 8));
            if (operand_ty.zig_type_tag(mod) == .Vector) {
                const vec_len = operand_ty.vector_len(mod);
                llvm_operand_ty = try o.builder.vector_type(.normal, vec_len, scalar_ty);
            } else llvm_operand_ty = scalar_ty;

            const shift_amt =
                try o.builder.splat_value(llvm_operand_ty, try o.builder.int_const(scalar_ty, 8));
            const extended = try self.wip.cast(.zext, operand, llvm_operand_ty, "");
            operand = try self.wip.bin(.shl, extended, shift_amt, "");

            bits = bits + 8;
        }

        const result =
            try self.wip.call_intrinsic(.normal, .none, .bswap, &.{llvm_operand_ty}, &.{operand}, "");
        return self.wip.conv(.unsigned, result, try o.lower_type(inst_ty), "");
    }

    fn air_error_set_has_value(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const ip = &mod.intern_pool;
        const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
        const operand = try self.resolve_inst(ty_op.operand);
        const error_set_ty = ty_op.ty.to_type();

        const names = error_set_ty.error_set_names(mod);
        const valid_block = try self.wip.block(@int_cast(names.len), "Valid");
        const invalid_block = try self.wip.block(1, "Invalid");
        const end_block = try self.wip.block(2, "End");
        var wip_switch = try self.wip.@"switch"(operand, invalid_block, @int_cast(names.len));
        defer wip_switch.finish(&self.wip);

        for (0..names.len) |name_index| {
            const err_int = mod.global_error_set.get_index(names.get(ip)[name_index]).?;
            const this_tag_int_value = try o.builder.int_const(try o.error_int_type(), err_int);
            try wip_switch.add_case(this_tag_int_value, valid_block, &self.wip);
        }
        self.wip.cursor = .{ .block = valid_block };
        _ = try self.wip.br(end_block);

        self.wip.cursor = .{ .block = invalid_block };
        _ = try self.wip.br(end_block);

        self.wip.cursor = .{ .block = end_block };
        const phi = try self.wip.phi(.i1, "");
        phi.finish(&.{ .true, .false }, &.{ valid_block, invalid_block }, &self.wip);
        return phi.to_value();
    }

    fn air_is_named_enum_value(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
        const operand = try self.resolve_inst(un_op);
        const enum_ty = self.type_of(un_op);

        const llvm_fn = try self.get_is_named_enum_value_function(enum_ty);
        return self.wip.call(
            .normal,
            .fastcc,
            .none,
            llvm_fn.type_of(&o.builder),
            llvm_fn.to_value(&o.builder),
            &.{operand},
            "",
        );
    }

    fn get_is_named_enum_value_function(self: *FuncGen, enum_ty: Type) !Builder.Function.Index {
        const o = self.dg.object;
        const zcu = o.module;
        const enum_type = zcu.intern_pool.load_enum_type(enum_ty.to_intern());

        // TODO: detect when the type changes and re-emit this function.
        const gop = try o.named_enum_map.get_or_put(o.gpa, enum_type.decl);
        if (gop.found_existing) return gop.value_ptr.*;
        errdefer assert(o.named_enum_map.remove(enum_type.decl));

        const fqn = try zcu.decl_ptr(enum_type.decl).fully_qualified_name(zcu);
        const target = zcu.root_mod.resolved_target.result;
        const function_index = try o.builder.add_function(
            try o.builder.fn_type(.i1, &.{try o.lower_type(Type.from_interned(enum_type.tag_ty))}, .normal),
            try o.builder.strtab_string_fmt("__zig_is_named_enum_value_{}", .{fqn.fmt(&zcu.intern_pool)}),
            to_llvm_address_space(.generic, target),
        );

        var attributes: Builder.FunctionAttributes.Wip = .{};
        defer attributes.deinit(&o.builder);
        try o.add_common_fn_attributes(&attributes, zcu.root_mod);

        function_index.set_linkage(.internal, &o.builder);
        function_index.set_call_conv(.fastcc, &o.builder);
        function_index.set_attributes(try attributes.finish(&o.builder), &o.builder);
        gop.value_ptr.* = function_index;

        var wip = try Builder.WipFunction.init(&o.builder, .{
            .function = function_index,
            .strip = true,
        });
        defer wip.deinit();
        wip.cursor = .{ .block = try wip.block(0, "Entry") };

        const named_block = try wip.block(@int_cast(enum_type.names.len), "Named");
        const unnamed_block = try wip.block(1, "Unnamed");
        const tag_int_value = wip.arg(0);
        var wip_switch = try wip.@"switch"(tag_int_value, unnamed_block, @int_cast(enum_type.names.len));
        defer wip_switch.finish(&wip);

        for (0..enum_type.names.len) |field_index| {
            const this_tag_int_value = try o.lower_value(
                (try zcu.enum_value_field_index(enum_ty, @int_cast(field_index))).to_intern(),
            );
            try wip_switch.add_case(this_tag_int_value, named_block, &wip);
        }
        wip.cursor = .{ .block = named_block };
        _ = try wip.ret(.true);

        wip.cursor = .{ .block = unnamed_block };
        _ = try wip.ret(.false);

        try wip.finish();
        return function_index;
    }

    fn air_tag_name(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
        const operand = try self.resolve_inst(un_op);
        const enum_ty = self.type_of(un_op);

        const llvm_fn = try o.get_enum_tag_name_function(enum_ty);
        return self.wip.call(
            .normal,
            .fastcc,
            .none,
            llvm_fn.type_of(&o.builder),
            llvm_fn.to_value(&o.builder),
            &.{operand},
            "",
        );
    }

    fn air_error_name(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
        const operand = try self.resolve_inst(un_op);
        const slice_ty = self.type_of_index(inst);
        const slice_llvm_ty = try o.lower_type(slice_ty);

        const error_name_table_ptr = try self.get_error_name_table();
        const error_name_table =
            try self.wip.load(.normal, .ptr, error_name_table_ptr.to_value(&o.builder), .default, "");
        const error_name_ptr =
            try self.wip.gep(.inbounds, slice_llvm_ty, error_name_table, &.{operand}, "");
        return self.wip.load(.normal, slice_llvm_ty, error_name_ptr, .default, "");
    }

    fn air_splat(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
        const scalar = try self.resolve_inst(ty_op.operand);
        const vector_ty = self.type_of_index(inst);
        return self.wip.splat_vector(try o.lower_type(vector_ty), scalar, "");
    }

    fn air_select(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const pl_op = self.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
        const extra = self.air.extra_data(Air.Bin, pl_op.payload).data;
        const pred = try self.resolve_inst(pl_op.operand);
        const a = try self.resolve_inst(extra.lhs);
        const b = try self.resolve_inst(extra.rhs);

        return self.wip.select(.normal, pred, a, b, "");
    }

    fn air_shuffle(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
        const extra = self.air.extra_data(Air.Shuffle, ty_pl.payload).data;
        const a = try self.resolve_inst(extra.a);
        const b = try self.resolve_inst(extra.b);
        const mask = Value.from_interned(extra.mask);
        const mask_len = extra.mask_len;
        const a_len = self.type_of(extra.a).vector_len(mod);

        // LLVM uses integers larger than the length of the first array to
        // index into the second array. This was deemed unnecessarily fragile
        // when changing code, so Zig uses negative numbers to index the
        // second vector. These start at -1 and go down, and are easiest to use
        // with the ~ operator. Here we convert between the two formats.
        const values = try self.gpa.alloc(Builder.Constant, mask_len);
        defer self.gpa.free(values);

        for (values, 0..) |*val, i| {
            const elem = try mask.elem_value(mod, i);
            if (elem.is_undef(mod)) {
                val.* = try o.builder.undef_const(.i32);
            } else {
                const int = elem.to_signed_int(mod);
                const unsigned: u32 = @int_cast(if (int >= 0) int else ~int + a_len);
                val.* = try o.builder.int_const(.i32, unsigned);
            }
        }

        const llvm_mask_value = try o.builder.vector_value(
            try o.builder.vector_type(.normal, mask_len, .i32),
            values,
        );
        return self.wip.shuffle_vector(a, b, llvm_mask_value, "");
    }

    /// Reduce a vector by repeatedly applying `llvm_fn` to produce an accumulated result.
    ///
    /// Equivalent to:
    ///   reduce: {
    ///     var i: usize = 0;
    ///     var accum: T = init;
    ///     while (i < vec.len) : (i += 1) {
    ///       accum = llvm_fn(accum, vec[i]);
    ///     }
    ///     break :reduce accum;
    ///   }
    ///
    fn build_reduced_call(
        self: *FuncGen,
        llvm_fn: Builder.Function.Index,
        operand_vector: Builder.Value,
        vector_len: usize,
        accum_init: Builder.Value,
    ) !Builder.Value {
        const o = self.dg.object;
        const usize_ty = try o.lower_type(Type.usize);
        const llvm_vector_len = try o.builder.int_value(usize_ty, vector_len);
        const llvm_result_ty = accum_init.type_of_wip(&self.wip);

        // Allocate and initialize our mutable variables
        const i_ptr = try self.build_alloca_workaround(Type.usize, .default);
        _ = try self.wip.store(.normal, try o.builder.int_value(usize_ty, 0), i_ptr, .default);
        const accum_ptr = try self.build_alloca(llvm_result_ty, .default);
        _ = try self.wip.store(.normal, accum_init, accum_ptr, .default);

        // Setup the loop
        const loop = try self.wip.block(2, "ReduceLoop");
        const loop_exit = try self.wip.block(1, "AfterReduce");
        _ = try self.wip.br(loop);
        {
            self.wip.cursor = .{ .block = loop };

            // while (i < vec.len)
            const i = try self.wip.load(.normal, usize_ty, i_ptr, .default, "");
            const cond = try self.wip.icmp(.ult, i, llvm_vector_len, "");
            const loop_then = try self.wip.block(1, "ReduceLoopThen");

            _ = try self.wip.br_cond(cond, loop_then, loop_exit);

            {
                self.wip.cursor = .{ .block = loop_then };

                // accum = f(accum, vec[i]);
                const accum = try self.wip.load(.normal, llvm_result_ty, accum_ptr, .default, "");
                const element = try self.wip.extract_element(operand_vector, i, "");
                const new_accum = try self.wip.call(
                    .normal,
                    .ccc,
                    .none,
                    llvm_fn.type_of(&o.builder),
                    llvm_fn.to_value(&o.builder),
                    &.{ accum, element },
                    "",
                );
                _ = try self.wip.store(.normal, new_accum, accum_ptr, .default);

                // i += 1
                const new_i = try self.wip.bin(.add, i, try o.builder.int_value(usize_ty, 1), "");
                _ = try self.wip.store(.normal, new_i, i_ptr, .default);
                _ = try self.wip.br(loop);
            }
        }

        self.wip.cursor = .{ .block = loop_exit };
        return self.wip.load(.normal, llvm_result_ty, accum_ptr, .default, "");
    }

    fn air_reduce(self: *FuncGen, inst: Air.Inst.Index, fast: Builder.FastMathKind) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const target = mod.get_target();

        const reduce = self.air.instructions.items(.data)[@int_from_enum(inst)].reduce;
        const operand = try self.resolve_inst(reduce.operand);
        const operand_ty = self.type_of(reduce.operand);
        const llvm_operand_ty = try o.lower_type(operand_ty);
        const scalar_ty = self.type_of_index(inst);
        const llvm_scalar_ty = try o.lower_type(scalar_ty);

        switch (reduce.operation) {
            .And, .Or, .Xor => return self.wip.call_intrinsic(.normal, .none, switch (reduce.operation) {
                .And => .@"vector.reduce.and",
                .Or => .@"vector.reduce.or",
                .Xor => .@"vector.reduce.xor",
                else => unreachable,
            }, &.{llvm_operand_ty}, &.{operand}, ""),
            .Min, .Max => switch (scalar_ty.zig_type_tag(mod)) {
                .Int => return self.wip.call_intrinsic(.normal, .none, switch (reduce.operation) {
                    .Min => if (scalar_ty.is_signed_int(mod))
                        .@"vector.reduce.smin"
                    else
                        .@"vector.reduce.umin",
                    .Max => if (scalar_ty.is_signed_int(mod))
                        .@"vector.reduce.smax"
                    else
                        .@"vector.reduce.umax",
                    else => unreachable,
                }, &.{llvm_operand_ty}, &.{operand}, ""),
                .Float => if (intrinsics_allowed(scalar_ty, target))
                    return self.wip.call_intrinsic(fast, .none, switch (reduce.operation) {
                        .Min => .@"vector.reduce.fmin",
                        .Max => .@"vector.reduce.fmax",
                        else => unreachable,
                    }, &.{llvm_operand_ty}, &.{operand}, ""),
                else => unreachable,
            },
            .Add, .Mul => switch (scalar_ty.zig_type_tag(mod)) {
                .Int => return self.wip.call_intrinsic(.normal, .none, switch (reduce.operation) {
                    .Add => .@"vector.reduce.add",
                    .Mul => .@"vector.reduce.mul",
                    else => unreachable,
                }, &.{llvm_operand_ty}, &.{operand}, ""),
                .Float => if (intrinsics_allowed(scalar_ty, target))
                    return self.wip.call_intrinsic(fast, .none, switch (reduce.operation) {
                        .Add => .@"vector.reduce.fadd",
                        .Mul => .@"vector.reduce.fmul",
                        else => unreachable,
                    }, &.{llvm_operand_ty}, &.{ switch (reduce.operation) {
                        .Add => try o.builder.fp_value(llvm_scalar_ty, -0.0),
                        .Mul => try o.builder.fp_value(llvm_scalar_ty, 1.0),
                        else => unreachable,
                    }, operand }, ""),
                else => unreachable,
            },
        }

        // Reduction could not be performed with intrinsics.
        // Use a manual loop over a softfloat call instead.
        const float_bits = scalar_ty.float_bits(target);
        const fn_name = switch (reduce.operation) {
            .Min => try o.builder.strtab_string_fmt("{s}fmin{s}", .{
                libc_float_prefix(float_bits), libc_float_suffix(float_bits),
            }),
            .Max => try o.builder.strtab_string_fmt("{s}fmax{s}", .{
                libc_float_prefix(float_bits), libc_float_suffix(float_bits),
            }),
            .Add => try o.builder.strtab_string_fmt("__add{s}f3", .{
                compiler_rt_float_abbrev(float_bits),
            }),
            .Mul => try o.builder.strtab_string_fmt("__mul{s}f3", .{
                compiler_rt_float_abbrev(float_bits),
            }),
            else => unreachable,
        };

        const libc_fn =
            try self.get_libc_function(fn_name, &.{ llvm_scalar_ty, llvm_scalar_ty }, llvm_scalar_ty);
        const init_val = switch (llvm_scalar_ty) {
            .i16 => try o.builder.int_value(.i16, @as(i16, @bit_cast(
                @as(f16, switch (reduce.operation) {
                    .Min, .Max => std.math.nan(f16),
                    .Add => -0.0,
                    .Mul => 1.0,
                    else => unreachable,
                }),
            ))),
            .i80 => try o.builder.int_value(.i80, @as(i80, @bit_cast(
                @as(f80, switch (reduce.operation) {
                    .Min, .Max => std.math.nan(f80),
                    .Add => -0.0,
                    .Mul => 1.0,
                    else => unreachable,
                }),
            ))),
            .i128 => try o.builder.int_value(.i128, @as(i128, @bit_cast(
                @as(f128, switch (reduce.operation) {
                    .Min, .Max => std.math.nan(f128),
                    .Add => -0.0,
                    .Mul => 1.0,
                    else => unreachable,
                }),
            ))),
            else => unreachable,
        };
        return self.build_reduced_call(libc_fn, operand, operand_ty.vector_len(mod), init_val);
    }

    fn air_aggregate_init(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const ip = &mod.intern_pool;
        const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
        const result_ty = self.type_of_index(inst);
        const len: usize = @int_cast(result_ty.array_len(mod));
        const elements: []const Air.Inst.Ref = @ptr_cast(self.air.extra[ty_pl.payload..][0..len]);
        const llvm_result_ty = try o.lower_type(result_ty);

        switch (result_ty.zig_type_tag(mod)) {
            .Vector => {
                var vector = try o.builder.poison_value(llvm_result_ty);
                for (elements, 0..) |elem, i| {
                    const index_u32 = try o.builder.int_value(.i32, i);
                    const llvm_elem = try self.resolve_inst(elem);
                    vector = try self.wip.insert_element(vector, llvm_elem, index_u32, "");
                }
                return vector;
            },
            .Struct => {
                if (mod.type_to_packed_struct(result_ty)) |struct_type| {
                    const backing_int_ty = struct_type.backing_int_type(ip).*;
                    assert(backing_int_ty != .none);
                    const big_bits = Type.from_interned(backing_int_ty).bit_size(mod);
                    const int_ty = try o.builder.int_type(@int_cast(big_bits));
                    comptime assert(Type.packed_struct_layout_version == 2);
                    var running_int = try o.builder.int_value(int_ty, 0);
                    var running_bits: u16 = 0;
                    for (elements, struct_type.field_types.get(ip)) |elem, field_ty| {
                        if (!Type.from_interned(field_ty).has_runtime_bits_ignore_comptime(mod)) continue;

                        const non_int_val = try self.resolve_inst(elem);
                        const ty_bit_size: u16 = @int_cast(Type.from_interned(field_ty).bit_size(mod));
                        const small_int_ty = try o.builder.int_type(ty_bit_size);
                        const small_int_val = if (Type.from_interned(field_ty).is_ptr_at_runtime(mod))
                            try self.wip.cast(.ptrtoint, non_int_val, small_int_ty, "")
                        else
                            try self.wip.cast(.bitcast, non_int_val, small_int_ty, "");
                        const shift_rhs = try o.builder.int_value(int_ty, running_bits);
                        const extended_int_val =
                            try self.wip.conv(.unsigned, small_int_val, int_ty, "");
                        const shifted = try self.wip.bin(.shl, extended_int_val, shift_rhs, "");
                        running_int = try self.wip.bin(.@"or", running_int, shifted, "");
                        running_bits += ty_bit_size;
                    }
                    return running_int;
                }

                assert(result_ty.container_layout(mod) != .@"packed");

                if (is_by_ref(result_ty, mod)) {
                    // TODO in debug builds init to undef so that the padding will be 0xaa
                    // even if we fully populate the fields.
                    const alignment = result_ty.abi_alignment(mod).to_llvm();
                    const alloca_inst = try self.build_alloca_workaround(result_ty, alignment);

                    for (elements, 0..) |elem, i| {
                        if ((try result_ty.struct_field_value_comptime(mod, i)) != null) continue;

                        const llvm_elem = try self.resolve_inst(elem);
                        const llvm_i = o.llvm_field_index(result_ty, i).?;
                        const field_ptr =
                            try self.wip.gep_struct(llvm_result_ty, alloca_inst, llvm_i, "");
                        const field_ptr_ty = try mod.ptr_type(.{
                            .child = self.type_of(elem).to_intern(),
                            .flags = .{
                                .alignment = result_ty.struct_field_align(i, mod),
                            },
                        });
                        try self.store(field_ptr, field_ptr_ty, llvm_elem, .none);
                    }

                    return alloca_inst;
                } else {
                    var result = try o.builder.poison_value(llvm_result_ty);
                    for (elements, 0..) |elem, i| {
                        if ((try result_ty.struct_field_value_comptime(mod, i)) != null) continue;

                        const llvm_elem = try self.resolve_inst(elem);
                        const llvm_i = o.llvm_field_index(result_ty, i).?;
                        result = try self.wip.insert_value(result, llvm_elem, &.{llvm_i}, "");
                    }
                    return result;
                }
            },
            .Array => {
                assert(is_by_ref(result_ty, mod));

                const llvm_usize = try o.lower_type(Type.usize);
                const usize_zero = try o.builder.int_value(llvm_usize, 0);
                const alignment = result_ty.abi_alignment(mod).to_llvm();
                const alloca_inst = try self.build_alloca_workaround(result_ty, alignment);

                const array_info = result_ty.array_info(mod);
                const elem_ptr_ty = try mod.ptr_type(.{
                    .child = array_info.elem_type.to_intern(),
                });

                for (elements, 0..) |elem, i| {
                    const elem_ptr = try self.wip.gep(.inbounds, llvm_result_ty, alloca_inst, &.{
                        usize_zero, try o.builder.int_value(llvm_usize, i),
                    }, "");
                    const llvm_elem = try self.resolve_inst(elem);
                    try self.store(elem_ptr, elem_ptr_ty, llvm_elem, .none);
                }
                if (array_info.sentinel) |sent_val| {
                    const elem_ptr = try self.wip.gep(.inbounds, llvm_result_ty, alloca_inst, &.{
                        usize_zero, try o.builder.int_value(llvm_usize, array_info.len),
                    }, "");
                    const llvm_elem = try self.resolve_value(sent_val);
                    try self.store(elem_ptr, elem_ptr_ty, llvm_elem.to_value(), .none);
                }

                return alloca_inst;
            },
            else => unreachable,
        }
    }

    fn air_union_init(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const ip = &mod.intern_pool;
        const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
        const extra = self.air.extra_data(Air.UnionInit, ty_pl.payload).data;
        const union_ty = self.type_of_index(inst);
        const union_llvm_ty = try o.lower_type(union_ty);
        const layout = union_ty.union_get_layout(mod);
        const union_obj = mod.type_to_union(union_ty).?;

        if (union_obj.get_layout(ip) == .@"packed") {
            const big_bits = union_ty.bit_size(mod);
            const int_llvm_ty = try o.builder.int_type(@int_cast(big_bits));
            const field_ty = Type.from_interned(union_obj.field_types.get(ip)[extra.field_index]);
            const non_int_val = try self.resolve_inst(extra.init);
            const small_int_ty = try o.builder.int_type(@int_cast(field_ty.bit_size(mod)));
            const small_int_val = if (field_ty.is_ptr_at_runtime(mod))
                try self.wip.cast(.ptrtoint, non_int_val, small_int_ty, "")
            else
                try self.wip.cast(.bitcast, non_int_val, small_int_ty, "");
            return self.wip.conv(.unsigned, small_int_val, int_llvm_ty, "");
        }

        const tag_int_val = blk: {
            const tag_ty = union_ty.union_tag_type_hypothetical(mod);
            const union_field_name = union_obj.load_tag_type(ip).names.get(ip)[extra.field_index];
            const enum_field_index = tag_ty.enum_field_index(union_field_name, mod).?;
            const tag_val = try mod.enum_value_field_index(tag_ty, enum_field_index);
            break :blk try tag_val.int_from_enum(tag_ty, mod);
        };
        if (layout.payload_size == 0) {
            if (layout.tag_size == 0) {
                return .none;
            }
            assert(!is_by_ref(union_ty, mod));
            var big_int_space: Value.BigIntSpace = undefined;
            const tag_big_int = tag_int_val.to_big_int(&big_int_space, mod);
            return try o.builder.big_int_value(union_llvm_ty, tag_big_int);
        }
        assert(is_by_ref(union_ty, mod));
        // The llvm type of the alloca will be the named LLVM union type, and will not
        // necessarily match the format that we need, depending on which tag is active.
        // We must construct the correct unnamed struct type here, in order to then set
        // the fields appropriately.
        const alignment = layout.abi_align.to_llvm();
        const result_ptr = try self.build_alloca_workaround(union_ty, alignment);
        const llvm_payload = try self.resolve_inst(extra.init);
        const field_ty = Type.from_interned(union_obj.field_types.get(ip)[extra.field_index]);
        const field_llvm_ty = try o.lower_type(field_ty);
        const field_size = field_ty.abi_size(mod);
        const field_align = mod.union_field_normal_alignment(union_obj, extra.field_index);
        const llvm_usize = try o.lower_type(Type.usize);
        const usize_zero = try o.builder.int_value(llvm_usize, 0);

        const llvm_union_ty = t: {
            const payload_ty = p: {
                if (!field_ty.has_runtime_bits_ignore_comptime(mod)) {
                    const padding_len = layout.payload_size;
                    break :p try o.builder.array_type(padding_len, .i8);
                }
                if (field_size == layout.payload_size) {
                    break :p field_llvm_ty;
                }
                const padding_len = layout.payload_size - field_size;
                break :p try o.builder.struct_type(.@"packed", &.{
                    field_llvm_ty, try o.builder.array_type(padding_len, .i8),
                });
            };
            if (layout.tag_size == 0) break :t try o.builder.struct_type(.normal, &.{payload_ty});
            const tag_ty = try o.lower_type(Type.from_interned(union_obj.enum_tag_ty));
            var fields: [3]Builder.Type = undefined;
            var fields_len: usize = 2;
            if (layout.tag_align.compare(.gte, layout.payload_align)) {
                fields = .{ tag_ty, payload_ty, undefined };
            } else {
                fields = .{ payload_ty, tag_ty, undefined };
            }
            if (layout.padding != 0) {
                fields[fields_len] = try o.builder.array_type(layout.padding, .i8);
                fields_len += 1;
            }
            break :t try o.builder.struct_type(.normal, fields[0..fields_len]);
        };

        // Now we follow the layout as expressed above with GEP instructions to set the
        // tag and the payload.
        const field_ptr_ty = try mod.ptr_type(.{
            .child = field_ty.to_intern(),
            .flags = .{ .alignment = field_align },
        });
        if (layout.tag_size == 0) {
            const indices = [3]Builder.Value{ usize_zero, .@"0", .@"0" };
            const len: usize = if (field_size == layout.payload_size) 2 else 3;
            const field_ptr =
                try self.wip.gep(.inbounds, llvm_union_ty, result_ptr, indices[0..len], "");
            try self.store(field_ptr, field_ptr_ty, llvm_payload, .none);
            return result_ptr;
        }

        {
            const payload_index = @int_from_bool(layout.tag_align.compare(.gte, layout.payload_align));
            const indices: [3]Builder.Value = .{ usize_zero, try o.builder.int_value(.i32, payload_index), .@"0" };
            const len: usize = if (field_size == layout.payload_size) 2 else 3;
            const field_ptr = try self.wip.gep(.inbounds, llvm_union_ty, result_ptr, indices[0..len], "");
            try self.store(field_ptr, field_ptr_ty, llvm_payload, .none);
        }
        {
            const tag_index = @int_from_bool(layout.tag_align.compare(.lt, layout.payload_align));
            const indices: [2]Builder.Value = .{ usize_zero, try o.builder.int_value(.i32, tag_index) };
            const field_ptr = try self.wip.gep(.inbounds, llvm_union_ty, result_ptr, &indices, "");
            const tag_ty = try o.lower_type(Type.from_interned(union_obj.enum_tag_ty));
            var big_int_space: Value.BigIntSpace = undefined;
            const tag_big_int = tag_int_val.to_big_int(&big_int_space, mod);
            const llvm_tag = try o.builder.big_int_value(tag_ty, tag_big_int);
            const tag_alignment = Type.from_interned(union_obj.enum_tag_ty).abi_alignment(mod).to_llvm();
            _ = try self.wip.store(.normal, llvm_tag, field_ptr, tag_alignment);
        }

        return result_ptr;
    }

    fn air_prefetch(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const prefetch = self.air.instructions.items(.data)[@int_from_enum(inst)].prefetch;

        comptime assert(@int_from_enum(std.builtin.PrefetchOptions.Rw.read) == 0);
        comptime assert(@int_from_enum(std.builtin.PrefetchOptions.Rw.write) == 1);

        // TODO these two asserts should be able to be comptime because the type is a u2
        assert(prefetch.locality >= 0);
        assert(prefetch.locality <= 3);

        comptime assert(@int_from_enum(std.builtin.PrefetchOptions.Cache.instruction) == 0);
        comptime assert(@int_from_enum(std.builtin.PrefetchOptions.Cache.data) == 1);

        // LLVM fails during codegen of instruction cache prefetchs for these architectures.
        // This is an LLVM bug as the prefetch intrinsic should be a noop if not supported
        // by the target.
        // To work around this, don't emit llvm.prefetch in this case.
        // See https://bugs.llvm.org/show_bug.cgi?id=21037
        const mod = o.module;
        const target = mod.get_target();
        switch (prefetch.cache) {
            .instruction => switch (target.cpu.arch) {
                .x86_64,
                .x86,
                .powerpc,
                .powerpcle,
                .powerpc64,
                .powerpc64le,
                => return .none,
                .arm, .armeb, .thumb, .thumbeb => {
                    switch (prefetch.rw) {
                        .write => return .none,
                        else => {},
                    }
                },
                else => {},
            },
            .data => {},
        }

        _ = try self.wip.call_intrinsic(.normal, .none, .prefetch, &.{.ptr}, &.{
            try self.slice_or_array_ptr(try self.resolve_inst(prefetch.ptr), self.type_of(prefetch.ptr)),
            try o.builder.int_value(.i32, prefetch.rw),
            try o.builder.int_value(.i32, prefetch.locality),
            try o.builder.int_value(.i32, prefetch.cache),
        }, "");
        return .none;
    }

    fn air_addr_space_cast(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
        const inst_ty = self.type_of_index(inst);
        const operand = try self.resolve_inst(ty_op.operand);

        return self.wip.cast(.addrspacecast, operand, try o.lower_type(inst_ty), "");
    }

    fn amdgcn_work_intrinsic(
        self: *FuncGen,
        dimension: u32,
        default: u32,
        comptime basename: []const u8,
    ) !Builder.Value {
        return self.wip.call_intrinsic(.normal, .none, switch (dimension) {
            0 => @field(Builder.Intrinsic, basename ++ ".x"),
            1 => @field(Builder.Intrinsic, basename ++ ".y"),
            2 => @field(Builder.Intrinsic, basename ++ ".z"),
            else => return self.dg.object.builder.int_value(.i32, default),
        }, &.{}, &.{}, "");
    }

    fn air_work_item_id(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const target = o.module.get_target();
        assert(target.cpu.arch == .amdgcn); // TODO is to port this function to other GPU architectures

        const pl_op = self.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
        const dimension = pl_op.payload;
        return self.amdgcn_work_intrinsic(dimension, 0, "amdgcn.workitem.id");
    }

    fn air_work_group_size(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const target = o.module.get_target();
        assert(target.cpu.arch == .amdgcn); // TODO is to port this function to other GPU architectures

        const pl_op = self.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
        const dimension = pl_op.payload;
        if (dimension >= 3) return .@"1";

        // Fetch the dispatch pointer, which points to this structure:
        // https://github.com/RadeonOpenCompute/ROCR-Runtime/blob/adae6c61e10d371f7cbc3d0e94ae2c070cab18a4/src/inc/hsa.h#L2913
        const dispatch_ptr =
            try self.wip.call_intrinsic(.normal, .none, .@"amdgcn.dispatch.ptr", &.{}, &.{}, "");

        // Load the work_group_* member from the struct as u16.
        // Just treat the dispatch pointer as an array of u16 to keep things simple.
        const workgroup_size_ptr = try self.wip.gep(.inbounds, .i16, dispatch_ptr, &.{
            try o.builder.int_value(try o.lower_type(Type.usize), 2 + dimension),
        }, "");
        const workgroup_size_alignment = comptime Builder.Alignment.from_byte_units(2);
        return self.wip.load(.normal, .i16, workgroup_size_ptr, workgroup_size_alignment, "");
    }

    fn air_work_group_id(self: *FuncGen, inst: Air.Inst.Index) !Builder.Value {
        const o = self.dg.object;
        const target = o.module.get_target();
        assert(target.cpu.arch == .amdgcn); // TODO is to port this function to other GPU architectures

        const pl_op = self.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
        const dimension = pl_op.payload;
        return self.amdgcn_work_intrinsic(dimension, 0, "amdgcn.workgroup.id");
    }

    fn get_error_name_table(self: *FuncGen) Allocator.Error!Builder.Variable.Index {
        const o = self.dg.object;
        const mod = o.module;

        const table = o.error_name_table;
        if (table != .none) return table;

        // TODO: Address space
        const variable_index =
            try o.builder.add_variable(try o.builder.strtab_string("__zig_err_name_table"), .ptr, .default);
        variable_index.set_linkage(.private, &o.builder);
        variable_index.set_mutability(.constant, &o.builder);
        variable_index.set_unnamed_addr(.unnamed_addr, &o.builder);
        variable_index.set_alignment(
            Type.slice_const_u8_sentinel_0.abi_alignment(mod).to_llvm(),
            &o.builder,
        );

        o.error_name_table = variable_index;
        return variable_index;
    }

    /// Assumes the optional is not pointer-like and payload has bits.
    fn opt_cmp_null(
        self: *FuncGen,
        cond: Builder.IntegerCondition,
        opt_llvm_ty: Builder.Type,
        opt_handle: Builder.Value,
        is_by_ref: bool,
    ) Allocator.Error!Builder.Value {
        const o = self.dg.object;
        const field = b: {
            if (is_by_ref) {
                const field_ptr = try self.wip.gep_struct(opt_llvm_ty, opt_handle, 1, "");
                break :b try self.wip.load(.normal, .i8, field_ptr, .default, "");
            }
            break :b try self.wip.extract_value(opt_handle, &.{1}, "");
        };
        comptime assert(optional_layout_version == 3);

        return self.wip.icmp(cond, field, try o.builder.int_value(.i8, 0), "");
    }

    /// Assumes the optional is not pointer-like and payload has bits.
    fn opt_payload_handle(
        fg: *FuncGen,
        opt_llvm_ty: Builder.Type,
        opt_handle: Builder.Value,
        opt_ty: Type,
        can_elide_load: bool,
    ) !Builder.Value {
        const o = fg.dg.object;
        const mod = o.module;
        const payload_ty = opt_ty.optional_child(mod);

        if (is_by_ref(opt_ty, mod)) {
            // We have a pointer and we need to return a pointer to the first field.
            const payload_ptr = try fg.wip.gep_struct(opt_llvm_ty, opt_handle, 0, "");

            const payload_alignment = payload_ty.abi_alignment(mod).to_llvm();
            if (is_by_ref(payload_ty, mod)) {
                if (can_elide_load)
                    return payload_ptr;

                return fg.load_by_ref(payload_ptr, payload_ty, payload_alignment, .normal);
            }
            return fg.load_truncate(.normal, payload_ty, payload_ptr, payload_alignment);
        }

        assert(!is_by_ref(payload_ty, mod));
        return fg.wip.extract_value(opt_handle, &.{0}, "");
    }

    fn build_optional(
        self: *FuncGen,
        optional_ty: Type,
        payload: Builder.Value,
        non_null_bit: Builder.Value,
    ) !Builder.Value {
        const o = self.dg.object;
        const optional_llvm_ty = try o.lower_type(optional_ty);
        const non_null_field = try self.wip.cast(.zext, non_null_bit, .i8, "");
        const mod = o.module;

        if (is_by_ref(optional_ty, mod)) {
            const payload_alignment = optional_ty.abi_alignment(mod).to_llvm();
            const alloca_inst = try self.build_alloca_workaround(optional_ty, payload_alignment);

            {
                const field_ptr = try self.wip.gep_struct(optional_llvm_ty, alloca_inst, 0, "");
                _ = try self.wip.store(.normal, payload, field_ptr, payload_alignment);
            }
            {
                const non_null_alignment = comptime Builder.Alignment.from_byte_units(1);
                const field_ptr = try self.wip.gep_struct(optional_llvm_ty, alloca_inst, 1, "");
                _ = try self.wip.store(.normal, non_null_field, field_ptr, non_null_alignment);
            }

            return alloca_inst;
        }

        return self.wip.build_aggregate(optional_llvm_ty, &.{ payload, non_null_field }, "");
    }

    fn field_ptr(
        self: *FuncGen,
        inst: Air.Inst.Index,
        struct_ptr: Builder.Value,
        struct_ptr_ty: Type,
        field_index: u32,
    ) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const struct_ty = struct_ptr_ty.child_type(mod);
        switch (struct_ty.zig_type_tag(mod)) {
            .Struct => switch (struct_ty.container_layout(mod)) {
                .@"packed" => {
                    const result_ty = self.type_of_index(inst);
                    const result_ty_info = result_ty.ptr_info(mod);
                    const struct_ptr_ty_info = struct_ptr_ty.ptr_info(mod);
                    const struct_type = mod.type_to_struct(struct_ty).?;

                    if (result_ty_info.packed_offset.host_size != 0) {
                        // From LLVM's perspective, a pointer to a packed struct and a pointer
                        // to a field of a packed struct are the same. The difference is in the
                        // Zig pointer type which provides information for how to mask and shift
                        // out the relevant bits when accessing the pointee.
                        return struct_ptr;
                    }

                    // We have a pointer to a packed struct field that happens to be byte-aligned.
                    // Offset our operand pointer by the correct number of bytes.
                    const byte_offset = @div_exact(mod.struct_packed_field_bit_offset(struct_type, field_index) + struct_ptr_ty_info.packed_offset.bit_offset, 8);
                    if (byte_offset == 0) return struct_ptr;
                    const usize_ty = try o.lower_type(Type.usize);
                    const llvm_index = try o.builder.int_value(usize_ty, byte_offset);
                    return self.wip.gep(.inbounds, .i8, struct_ptr, &.{llvm_index}, "");
                },
                else => {
                    const struct_llvm_ty = try o.lower_ptr_elem_ty(struct_ty);

                    if (o.llvm_field_index(struct_ty, field_index)) |llvm_field_index| {
                        return self.wip.gep_struct(struct_llvm_ty, struct_ptr, llvm_field_index, "");
                    } else {
                        // If we found no index then this means this is a zero sized field at the
                        // end of the struct. Treat our struct pointer as an array of two and get
                        // the index to the element at index `1` to get a pointer to the end of
                        // the struct.
                        const llvm_index = try o.builder.int_value(
                            try o.lower_type(Type.usize),
                            @int_from_bool(struct_ty.has_runtime_bits_ignore_comptime(mod)),
                        );
                        return self.wip.gep(.inbounds, struct_llvm_ty, struct_ptr, &.{llvm_index}, "");
                    }
                },
            },
            .Union => {
                const layout = struct_ty.union_get_layout(mod);
                if (layout.payload_size == 0 or struct_ty.container_layout(mod) == .@"packed") return struct_ptr;
                const payload_index = @int_from_bool(layout.tag_align.compare(.gte, layout.payload_align));
                const union_llvm_ty = try o.lower_type(struct_ty);
                return self.wip.gep_struct(union_llvm_ty, struct_ptr, payload_index, "");
            },
            else => unreachable,
        }
    }

    /// Load a value and, if needed, mask out padding bits for non byte-sized integer values.
    fn load_truncate(
        fg: *FuncGen,
        access_kind: Builder.MemoryAccessKind,
        payload_ty: Type,
        payload_ptr: Builder.Value,
        payload_alignment: Builder.Alignment,
    ) !Builder.Value {
        // from https://llvm.org/docs/LangRef.html#load-instruction :
        // "When loading a value of a type like i20 with a size that is not an integral number of bytes, the result is undefined if the value was not originally written using a store of the same type. "
        // => so load the byte aligned value and trunc the unwanted bits.

        const o = fg.dg.object;
        const mod = o.module;
        const payload_llvm_ty = try o.lower_type(payload_ty);
        const abi_size = payload_ty.abi_size(mod);

        // llvm bug workarounds:
        const workaround_explicit_mask = o.target.cpu.arch == .powerpc and abi_size >= 4;
        const workaround_disable_truncate = o.target.cpu.arch == .wasm32 and abi_size >= 4;

        if (workaround_disable_truncate) {
            // see https://github.com/llvm/llvm-project/issues/64222
            // disable the truncation codepath for larger that 32bits value - with this heuristic, the backend passes the test suite.
            return try fg.wip.load(access_kind, payload_llvm_ty, payload_ptr, payload_alignment, "");
        }

        const load_llvm_ty = if (payload_ty.is_abi_int(mod))
            try o.builder.int_type(@int_cast(abi_size * 8))
        else
            payload_llvm_ty;
        const loaded = try fg.wip.load(access_kind, load_llvm_ty, payload_ptr, payload_alignment, "");
        const shifted = if (payload_llvm_ty != load_llvm_ty and o.target.cpu.arch.endian() == .big)
            try fg.wip.bin(.lshr, loaded, try o.builder.int_value(
                load_llvm_ty,
                (payload_ty.abi_size(mod) - (std.math.div_ceil(u64, payload_ty.bit_size(mod), 8) catch unreachable)) * 8,
            ), "")
        else
            loaded;

        const anded = if (workaround_explicit_mask and payload_llvm_ty != load_llvm_ty) blk: {
            // this is rendundant with llvm.trunc. But without it, llvm17 emits invalid code for powerpc.
            const mask_val = try o.builder.int_value(payload_llvm_ty, -1);
            const zext_mask_val = try fg.wip.cast(.zext, mask_val, load_llvm_ty, "");
            break :blk try fg.wip.bin(.@"and", shifted, zext_mask_val, "");
        } else shifted;

        return fg.wip.conv(.unneeded, anded, payload_llvm_ty, "");
    }

    /// Load a by-ref type by constructing a new alloca and performing a memcpy.
    fn load_by_ref(
        fg: *FuncGen,
        ptr: Builder.Value,
        pointee_type: Type,
        ptr_alignment: Builder.Alignment,
        access_kind: Builder.MemoryAccessKind,
    ) !Builder.Value {
        const o = fg.dg.object;
        const mod = o.module;
        //const pointee_llvm_ty = try o.lower_type(pointee_type);
        const result_align = InternPool.Alignment.from_llvm(ptr_alignment).max(pointee_type.abi_alignment(mod)).to_llvm();
        const result_ptr = try fg.build_alloca_workaround(pointee_type, result_align);
        const size_bytes = pointee_type.abi_size(mod);
        _ = try fg.wip.call_mem_cpy(
            result_ptr,
            result_align,
            ptr,
            ptr_alignment,
            try o.builder.int_value(try o.lower_type(Type.usize), size_bytes),
            access_kind,
        );
        return result_ptr;
    }

    /// This function always performs a copy. For is_by_ref=true types, it creates a new
    /// alloca and copies the value into it, then returns the alloca instruction.
    /// For is_by_ref=false types, it creates a load instruction and returns it.
    fn load(self: *FuncGen, ptr: Builder.Value, ptr_ty: Type) !Builder.Value {
        const o = self.dg.object;
        const mod = o.module;
        const info = ptr_ty.ptr_info(mod);
        const elem_ty = Type.from_interned(info.child);
        if (!elem_ty.has_runtime_bits_ignore_comptime(mod)) return .none;

        const ptr_alignment = (if (info.flags.alignment != .none)
            @as(InternPool.Alignment, info.flags.alignment)
        else
            elem_ty.abi_alignment(mod)).to_llvm();

        const access_kind: Builder.MemoryAccessKind =
            if (info.flags.is_volatile) .@"volatile" else .normal;

        assert(info.flags.vector_index != .runtime);
        if (info.flags.vector_index != .none) {
            const index_u32 = try o.builder.int_value(.i32, info.flags.vector_index);
            const vec_elem_ty = try o.lower_type(elem_ty);
            const vec_ty = try o.builder.vector_type(.normal, info.packed_offset.host_size, vec_elem_ty);

            const loaded_vector = try self.wip.load(access_kind, vec_ty, ptr, ptr_alignment, "");
            return self.wip.extract_element(loaded_vector, index_u32, "");
        }

        if (info.packed_offset.host_size == 0) {
            if (is_by_ref(elem_ty, mod)) {
                return self.load_by_ref(ptr, elem_ty, ptr_alignment, access_kind);
            }
            return self.load_truncate(access_kind, elem_ty, ptr, ptr_alignment);
        }

        const containing_int_ty = try o.builder.int_type(@int_cast(info.packed_offset.host_size * 8));
        const containing_int =
            try self.wip.load(access_kind, containing_int_ty, ptr, ptr_alignment, "");

        const elem_bits = ptr_ty.child_type(mod).bit_size(mod);
        const shift_amt = try o.builder.int_value(containing_int_ty, info.packed_offset.bit_offset);
        const shifted_value = try self.wip.bin(.lshr, containing_int, shift_amt, "");
        const elem_llvm_ty = try o.lower_type(elem_ty);

        if (is_by_ref(elem_ty, mod)) {
            const result_align = elem_ty.abi_alignment(mod).to_llvm();
            const result_ptr = try self.build_alloca_workaround(elem_ty, result_align);

            const same_size_int = try o.builder.int_type(@int_cast(elem_bits));
            const truncated_int = try self.wip.cast(.trunc, shifted_value, same_size_int, "");
            _ = try self.wip.store(.normal, truncated_int, result_ptr, result_align);
            return result_ptr;
        }

        if (elem_ty.zig_type_tag(mod) == .Float or elem_ty.zig_type_tag(mod) == .Vector) {
            const same_size_int = try o.builder.int_type(@int_cast(elem_bits));
            const truncated_int = try self.wip.cast(.trunc, shifted_value, same_size_int, "");
            return self.wip.cast(.bitcast, truncated_int, elem_llvm_ty, "");
        }

        if (elem_ty.is_ptr_at_runtime(mod)) {
            const same_size_int = try o.builder.int_type(@int_cast(elem_bits));
            const truncated_int = try self.wip.cast(.trunc, shifted_value, same_size_int, "");
            return self.wip.cast(.inttoptr, truncated_int, elem_llvm_ty, "");
        }

        return self.wip.cast(.trunc, shifted_value, elem_llvm_ty, "");
    }

    fn store(
        self: *FuncGen,
        ptr: Builder.Value,
        ptr_ty: Type,
        elem: Builder.Value,
        ordering: Builder.AtomicOrdering,
    ) !void {
        const o = self.dg.object;
        const mod = o.module;
        const info = ptr_ty.ptr_info(mod);
        const elem_ty = Type.from_interned(info.child);
        if (!elem_ty.is_fn_or_has_runtime_bits_ignore_comptime(mod)) {
            return;
        }
        const ptr_alignment = ptr_ty.ptr_alignment(mod).to_llvm();
        const access_kind: Builder.MemoryAccessKind =
            if (info.flags.is_volatile) .@"volatile" else .normal;

        assert(info.flags.vector_index != .runtime);
        if (info.flags.vector_index != .none) {
            const index_u32 = try o.builder.int_value(.i32, info.flags.vector_index);
            const vec_elem_ty = try o.lower_type(elem_ty);
            const vec_ty = try o.builder.vector_type(.normal, info.packed_offset.host_size, vec_elem_ty);

            const loaded_vector = try self.wip.load(access_kind, vec_ty, ptr, ptr_alignment, "");

            const modified_vector = try self.wip.insert_element(loaded_vector, elem, index_u32, "");

            assert(ordering == .none);
            _ = try self.wip.store(access_kind, modified_vector, ptr, ptr_alignment);
            return;
        }

        if (info.packed_offset.host_size != 0) {
            const containing_int_ty = try o.builder.int_type(@int_cast(info.packed_offset.host_size * 8));
            assert(ordering == .none);
            const containing_int =
                try self.wip.load(access_kind, containing_int_ty, ptr, ptr_alignment, "");
            const elem_bits = ptr_ty.child_type(mod).bit_size(mod);
            const shift_amt = try o.builder.int_const(containing_int_ty, info.packed_offset.bit_offset);
            // Convert to equally-sized integer type in order to perform the bit
            // operations on the value to store
            const value_bits_type = try o.builder.int_type(@int_cast(elem_bits));
            const value_bits = if (elem_ty.is_ptr_at_runtime(mod))
                try self.wip.cast(.ptrtoint, elem, value_bits_type, "")
            else
                try self.wip.cast(.bitcast, elem, value_bits_type, "");

            const mask_val = blk: {
                const zext = try self.wip.cast(
                    .zext,
                    try o.builder.int_value(value_bits_type, -1),
                    containing_int_ty,
                    "",
                );
                const shl = try self.wip.bin(.shl, zext, shift_amt.to_value(), "");
                break :blk try self.wip.bin(
                    .xor,
                    shl,
                    try o.builder.int_value(containing_int_ty, -1),
                    "",
                );
            };

            const anded_containing_int = try self.wip.bin(.@"and", containing_int, mask_val, "");
            const extended_value = try self.wip.cast(.zext, value_bits, containing_int_ty, "");
            const shifted_value = try self.wip.bin(.shl, extended_value, shift_amt.to_value(), "");
            const ored_value = try self.wip.bin(.@"or", shifted_value, anded_containing_int, "");

            assert(ordering == .none);
            _ = try self.wip.store(access_kind, ored_value, ptr, ptr_alignment);
            return;
        }
        if (!is_by_ref(elem_ty, mod)) {
            _ = try self.wip.store_atomic(
                access_kind,
                elem,
                ptr,
                self.sync_scope,
                ordering,
                ptr_alignment,
            );
            return;
        }
        assert(ordering == .none);
        _ = try self.wip.call_mem_cpy(
            ptr,
            ptr_alignment,
            elem,
            elem_ty.abi_alignment(mod).to_llvm(),
            try o.builder.int_value(try o.lower_type(Type.usize), elem_ty.abi_size(mod)),
            access_kind,
        );
    }

    fn valgrind_mark_undef(fg: *FuncGen, ptr: Builder.Value, len: Builder.Value) Allocator.Error!void {
        const VG_USERREQ__MAKE_MEM_UNDEFINED = 1296236545;
        const o = fg.dg.object;
        const usize_ty = try o.lower_type(Type.usize);
        const zero = try o.builder.int_value(usize_ty, 0);
        const req = try o.builder.int_value(usize_ty, VG_USERREQ__MAKE_MEM_UNDEFINED);
        const ptr_as_usize = try fg.wip.cast(.ptrtoint, ptr, usize_ty, "");
        _ = try valgrind_client_request(fg, zero, req, ptr_as_usize, len, zero, zero, zero);
    }

    fn valgrind_client_request(
        fg: *FuncGen,
        default_value: Builder.Value,
        request: Builder.Value,
        a1: Builder.Value,
        a2: Builder.Value,
        a3: Builder.Value,
        a4: Builder.Value,
        a5: Builder.Value,
    ) Allocator.Error!Builder.Value {
        const o = fg.dg.object;
        const mod = o.module;
        const target = mod.get_target();
        if (!target_util.has_valgrind_support(target)) return default_value;

        const llvm_usize = try o.lower_type(Type.usize);
        const usize_alignment = Type.usize.abi_alignment(mod).to_llvm();

        const array_llvm_ty = try o.builder.array_type(6, llvm_usize);
        const array_ptr = if (fg.valgrind_client_request_array == .none) a: {
            const array_ptr = try fg.build_alloca(array_llvm_ty, usize_alignment);
            fg.valgrind_client_request_array = array_ptr;
            break :a array_ptr;
        } else fg.valgrind_client_request_array;
        const array_elements = [_]Builder.Value{ request, a1, a2, a3, a4, a5 };
        const zero = try o.builder.int_value(llvm_usize, 0);
        for (array_elements, 0..) |elem, i| {
            const elem_ptr = try fg.wip.gep(.inbounds, array_llvm_ty, array_ptr, &.{
                zero, try o.builder.int_value(llvm_usize, i),
            }, "");
            _ = try fg.wip.store(.normal, elem, elem_ptr, usize_alignment);
        }

        const arch_specific: struct {
            template: [:0]const u8,
            constraints: [:0]const u8,
        } = switch (target.cpu.arch) {
            .x86 => .{
                .template =
                \\roll $$3,  %edi ; roll $$13, %edi
                \\roll $$61, %edi ; roll $$51, %edi
                \\xchgl %ebx,%ebx
                ,
                .constraints = "={edx},{eax},0,~{cc},~{memory}",
            },
            .x86_64 => .{
                .template =
                \\rolq $$3,  %rdi ; rolq $$13, %rdi
                \\rolq $$61, %rdi ; rolq $$51, %rdi
                \\xchgq %rbx,%rbx
                ,
                .constraints = "={rdx},{rax},0,~{cc},~{memory}",
            },
            .aarch64, .aarch64_32, .aarch64_be => .{
                .template =
                \\ror x12, x12, #3  ;  ror x12, x12, #13
                \\ror x12, x12, #51 ;  ror x12, x12, #61
                \\orr x10, x10, x10
                ,
                .constraints = "={x3},{x4},0,~{cc},~{memory}",
            },
            else => unreachable,
        };

        return fg.wip.call_asm(
            .none,
            try o.builder.fn_type(llvm_usize, &.{ llvm_usize, llvm_usize }, .normal),
            .{ .sideeffect = true },
            try o.builder.string(arch_specific.template),
            try o.builder.string(arch_specific.constraints),
            &.{ try fg.wip.cast(.ptrtoint, array_ptr, llvm_usize, ""), default_value },
            "",
        );
    }

    fn type_of(fg: *FuncGen, inst: Air.Inst.Ref) Type {
        const o = fg.dg.object;
        const mod = o.module;
        return fg.air.type_of(inst, &mod.intern_pool);
    }

    fn type_of_index(fg: *FuncGen, inst: Air.Inst.Index) Type {
        const o = fg.dg.object;
        const mod = o.module;
        return fg.air.type_of_index(inst, &mod.intern_pool);
    }
};

fn to_llvm_atomic_ordering(atomic_order: std.builtin.AtomicOrder) Builder.AtomicOrdering {
    return switch (atomic_order) {
        .unordered => .unordered,
        .monotonic => .monotonic,
        .acquire => .acquire,
        .release => .release,
        .acq_rel => .acq_rel,
        .seq_cst => .seq_cst,
    };
}

fn to_llvm_atomic_rmw_bin_op(
    op: std.builtin.AtomicRmwOp,
    is_signed: bool,
    is_float: bool,
) Builder.Function.Instruction.AtomicRmw.Operation {
    return switch (op) {
        .Xchg => .xchg,
        .Add => if (is_float) .fadd else return .add,
        .Sub => if (is_float) .fsub else return .sub,
        .And => .@"and",
        .Nand => .nand,
        .Or => .@"or",
        .Xor => .xor,
        .Max => if (is_float) .fmax else if (is_signed) .max else return .umax,
        .Min => if (is_float) .fmin else if (is_signed) .min else return .umin,
    };
}

fn to_llvm_call_conv(cc: std.builtin.CallingConvention, target: std.Target) Builder.CallConv {
    return switch (cc) {
        .Unspecified, .Inline, .Async => .fastcc,
        .C, .Naked => .ccc,
        .Stdcall => .x86_stdcallcc,
        .Fastcall => .x86_fastcallcc,
        .Vectorcall => return switch (target.cpu.arch) {
            .x86, .x86_64 => .x86_vectorcallcc,
            .aarch64, .aarch64_be, .aarch64_32 => .aarch64_vector_pcs,
            else => unreachable,
        },
        .Thiscall => .x86_thiscallcc,
        .APCS => .arm_apcscc,
        .AAPCS => .arm_aapcscc,
        .AAPCSVFP => .arm_aapcs_vfpcc,
        .Interrupt => return switch (target.cpu.arch) {
            .x86, .x86_64 => .x86_intrcc,
            .avr => .avr_intrcc,
            .msp430 => .msp430_intrcc,
            else => unreachable,
        },
        .Signal => .avr_signalcc,
        .SysV => .x86_64_sysvcc,
        .Win64 => .win64cc,
        .Kernel => return switch (target.cpu.arch) {
            .nvptx, .nvptx64 => .ptx_kernel,
            .amdgcn => .amdgpu_kernel,
            else => unreachable,
        },
        .Vertex, .Fragment => unreachable,
    };
}

/// Convert a zig-address space to an llvm address space.
fn to_llvm_address_space(address_space: std.builtin.AddressSpace, target: std.Target) Builder.AddrSpace {
    for (llvm_addr_space_info(target)) |info| if (info.zig == address_space) return info.llvm;
    unreachable;
}

const AddrSpaceInfo = struct {
    zig: ?std.builtin.AddressSpace,
    llvm: Builder.AddrSpace,
    non_integral: bool = false,
    size: ?u16 = null,
    abi: ?u16 = null,
    pref: ?u16 = null,
    idx: ?u16 = null,
    force_in_data_layout: bool = false,
};
fn llvm_addr_space_info(target: std.Target) []const AddrSpaceInfo {
    return switch (target.cpu.arch) {
        .x86, .x86_64 => &.{
            .{ .zig = .generic, .llvm = .default },
            .{ .zig = .gs, .llvm = Builder.AddrSpace.x86.gs },
            .{ .zig = .fs, .llvm = Builder.AddrSpace.x86.fs },
            .{ .zig = .ss, .llvm = Builder.AddrSpace.x86.ss },
            .{ .zig = null, .llvm = Builder.AddrSpace.x86.ptr32_sptr, .size = 32, .abi = 32, .force_in_data_layout = true },
            .{ .zig = null, .llvm = Builder.AddrSpace.x86.ptr32_uptr, .size = 32, .abi = 32, .force_in_data_layout = true },
            .{ .zig = null, .llvm = Builder.AddrSpace.x86.ptr64, .size = 64, .abi = 64, .force_in_data_layout = true },
        },
        .nvptx, .nvptx64 => &.{
            .{ .zig = .generic, .llvm = .default },
            .{ .zig = .global, .llvm = Builder.AddrSpace.nvptx.global },
            .{ .zig = .constant, .llvm = Builder.AddrSpace.nvptx.constant },
            .{ .zig = .param, .llvm = Builder.AddrSpace.nvptx.param },
            .{ .zig = .shared, .llvm = Builder.AddrSpace.nvptx.shared },
            .{ .zig = .local, .llvm = Builder.AddrSpace.nvptx.local },
        },
        .amdgcn => &.{
            .{ .zig = .generic, .llvm = Builder.AddrSpace.amdgpu.flat, .force_in_data_layout = true },
            .{ .zig = .global, .llvm = Builder.AddrSpace.amdgpu.global, .force_in_data_layout = true },
            .{ .zig = null, .llvm = Builder.AddrSpace.amdgpu.region, .size = 32, .abi = 32 },
            .{ .zig = .shared, .llvm = Builder.AddrSpace.amdgpu.local, .size = 32, .abi = 32 },
            .{ .zig = .constant, .llvm = Builder.AddrSpace.amdgpu.constant, .force_in_data_layout = true },
            .{ .zig = .local, .llvm = Builder.AddrSpace.amdgpu.private, .size = 32, .abi = 32 },
            .{ .zig = null, .llvm = Builder.AddrSpace.amdgpu.constant_32bit, .size = 32, .abi = 32 },
            .{ .zig = null, .llvm = Builder.AddrSpace.amdgpu.buffer_fat_pointer, .non_integral = true, .size = 160, .abi = 256, .idx = 32 },
            .{ .zig = null, .llvm = Builder.AddrSpace.amdgpu.buffer_resource, .non_integral = true, .size = 128, .abi = 128 },
        },
        .avr => &.{
            .{ .zig = .generic, .llvm = .default, .abi = 8 },
            .{ .zig = .flash, .llvm = Builder.AddrSpace.avr.program, .abi = 8 },
            .{ .zig = .flash1, .llvm = Builder.AddrSpace.avr.program1, .abi = 8 },
            .{ .zig = .flash2, .llvm = Builder.AddrSpace.avr.program2, .abi = 8 },
            .{ .zig = .flash3, .llvm = Builder.AddrSpace.avr.program3, .abi = 8 },
            .{ .zig = .flash4, .llvm = Builder.AddrSpace.avr.program4, .abi = 8 },
            .{ .zig = .flash5, .llvm = Builder.AddrSpace.avr.program5, .abi = 8 },
        },
        .wasm32, .wasm64 => &.{
            .{ .zig = .generic, .llvm = .default, .force_in_data_layout = true },
            .{ .zig = null, .llvm = Builder.AddrSpace.wasm.variable, .non_integral = true },
            .{ .zig = null, .llvm = Builder.AddrSpace.wasm.externref, .non_integral = true, .size = 8, .abi = 8 },
            .{ .zig = null, .llvm = Builder.AddrSpace.wasm.funcref, .non_integral = true, .size = 8, .abi = 8 },
        },
        .m68k => &.{
            .{ .zig = .generic, .llvm = .default, .abi = 16, .pref = 32 },
        },
        else => &.{
            .{ .zig = .generic, .llvm = .default },
        },
    };
}

/// On some targets, local values that are in the generic address space must be generated into a
/// different address, space and then cast back to the generic address space.
/// For example, on GPUs local variable declarations must be generated into the local address space.
/// This function returns the address space local values should be generated into.
fn llvm_alloca_address_space(target: std.Target) Builder.AddrSpace {
    return switch (target.cpu.arch) {
        // On amdgcn, locals should be generated into the private address space.
        // To make Zig not impossible to use, these are then converted to addresses in the
        // generic address space and treates as regular pointers. This is the way that HIP also does it.
        .amdgcn => Builder.AddrSpace.amdgpu.private,
        else => .default,
    };
}

/// On some targets, global values that are in the generic address space must be generated into a
/// different address space, and then cast back to the generic address space.
fn llvm_default_global_address_space(target: std.Target) Builder.AddrSpace {
    return switch (target.cpu.arch) {
        // On amdgcn, globals must be explicitly allocated and uploaded so that the program can access
        // them.
        .amdgcn => Builder.AddrSpace.amdgpu.global,
        else => .default,
    };
}

/// Return the actual address space that a value should be stored in if its a global address space.
/// When a value is placed in the resulting address space, it needs to be cast back into wanted_address_space.
fn to_llvm_global_address_space(wanted_address_space: std.builtin.AddressSpace, target: std.Target) Builder.AddrSpace {
    return switch (wanted_address_space) {
        .generic => llvm_default_global_address_space(target),
        else => |as| to_llvm_address_space(as, target),
    };
}

fn return_type_by_ref(zcu: *Zcu, target: std.Target, ty: Type) bool {
    if (is_by_ref(ty, zcu)) {
        return true;
    } else if (target.cpu.arch.is_x86() and
        !std.Target.x86.feature_set_has(target.cpu.features, .evex512) and
        ty.total_vector_bits(zcu) >= 512)
    {
        // As of LLVM 18, passing a vector byval with fastcc that is 512 bits or more returns
        // "512-bit vector arguments require 'evex512' for AVX512"
        return true;
    } else {
        return false;
    }
}

fn first_param_sret(fn_info: InternPool.Key.FuncType, zcu: *Zcu, target: std.Target) bool {
    const return_type = Type.from_interned(fn_info.return_type);
    if (!return_type.has_runtime_bits_ignore_comptime(zcu)) return false;

    return switch (fn_info.cc) {
        .Unspecified, .Inline => return_type_by_ref(zcu, target, return_type),
        .C => switch (target.cpu.arch) {
            .mips, .mipsel => false,
            .x86 => is_by_ref(return_type, zcu),
            .x86_64 => switch (target.os.tag) {
                .windows => x86_64_abi.classify_windows(return_type, zcu) == .memory,
                else => first_param_sret_system_v(return_type, zcu, target),
            },
            .wasm32 => wasm_c_abi.classify_type(return_type, zcu)[0] == .indirect,
            .aarch64, .aarch64_be => aarch64_c_abi.classify_type(return_type, zcu) == .memory,
            .arm, .armeb => switch (arm_c_abi.classify_type(return_type, zcu, .ret)) {
                .memory, .i64_array => true,
                .i32_array => |size| size != 1,
                .byval => false,
            },
            .riscv32, .riscv64 => riscv_c_abi.classify_type(return_type, zcu) == .memory,
            else => false, // TODO investigate C ABI for other architectures
        },
        .SysV => first_param_sret_system_v(return_type, zcu, target),
        .Win64 => x86_64_abi.classify_windows(return_type, zcu) == .memory,
        .Stdcall => !is_scalar(zcu, return_type),
        else => false,
    };
}

fn first_param_sret_system_v(ty: Type, zcu: *Zcu, target: std.Target) bool {
    const class = x86_64_abi.classify_system_v(ty, zcu, target, .ret);
    if (class[0] == .memory) return true;
    if (class[0] == .x87 and class[2] != .none) return true;
    return false;
}

/// In order to support the C calling convention, some return types need to be lowered
/// completely differently in the function prototype to honor the C ABI, and then
/// be effectively bitcasted to the actual return type.
fn lower_fn_ret_ty(o: *Object, fn_info: InternPool.Key.FuncType) Allocator.Error!Builder.Type {
    const mod = o.module;
    const return_type = Type.from_interned(fn_info.return_type);
    if (!return_type.has_runtime_bits_ignore_comptime(mod)) {
        // If the return type is an error set or an error union, then we make this
        // anyerror return type instead, so that it can be coerced into a function
        // pointer type which has anyerror as the return type.
        return if (return_type.is_error(mod)) try o.error_int_type() else .void;
    }
    const target = mod.get_target();
    switch (fn_info.cc) {
        .Unspecified,
        .Inline,
        => return if (return_type_by_ref(mod, target, return_type)) .void else o.lower_type(return_type),

        .C => {
            switch (target.cpu.arch) {
                .mips, .mipsel => return o.lower_type(return_type),
                .x86 => return if (is_by_ref(return_type, mod)) .void else o.lower_type(return_type),
                .x86_64 => switch (target.os.tag) {
                    .windows => return lower_win64_fn_ret_ty(o, fn_info),
                    else => return lower_system_vfn_ret_ty(o, fn_info),
                },
                .wasm32 => {
                    if (is_scalar(mod, return_type)) {
                        return o.lower_type(return_type);
                    }
                    const classes = wasm_c_abi.classify_type(return_type, mod);
                    if (classes[0] == .indirect or classes[0] == .none) {
                        return .void;
                    }

                    assert(classes[0] == .direct and classes[1] == .none);
                    const scalar_type = wasm_c_abi.scalar_type(return_type, mod);
                    return o.builder.int_type(@int_cast(scalar_type.abi_size(mod) * 8));
                },
                .aarch64, .aarch64_be => {
                    switch (aarch64_c_abi.classify_type(return_type, mod)) {
                        .memory => return .void,
                        .float_array => return o.lower_type(return_type),
                        .byval => return o.lower_type(return_type),
                        .integer => return o.builder.int_type(@int_cast(return_type.bit_size(mod))),
                        .double_integer => return o.builder.array_type(2, .i64),
                    }
                },
                .arm, .armeb => {
                    switch (arm_c_abi.classify_type(return_type, mod, .ret)) {
                        .memory, .i64_array => return .void,
                        .i32_array => |len| return if (len == 1) .i32 else .void,
                        .byval => return o.lower_type(return_type),
                    }
                },
                .riscv32, .riscv64 => {
                    switch (riscv_c_abi.classify_type(return_type, mod)) {
                        .memory => return .void,
                        .integer => {
                            return o.builder.int_type(@int_cast(return_type.bit_size(mod)));
                        },
                        .double_integer => {
                            return o.builder.struct_type(.normal, &.{ .i64, .i64 });
                        },
                        .byval => return o.lower_type(return_type),
                        .fields => {
                            var types_len: usize = 0;
                            var types: [8]Builder.Type = undefined;
                            for (0..return_type.struct_field_count(mod)) |field_index| {
                                const field_ty = return_type.struct_field_type(field_index, mod);
                                if (!field_ty.has_runtime_bits_ignore_comptime(mod)) continue;
                                types[types_len] = try o.lower_type(field_ty);
                                types_len += 1;
                            }
                            return o.builder.struct_type(.normal, types[0..types_len]);
                        },
                        .none => unreachable,
                    }
                },
                // TODO investigate C ABI for other architectures
                else => return o.lower_type(return_type),
            }
        },
        .Win64 => return lower_win64_fn_ret_ty(o, fn_info),
        .SysV => return lower_system_vfn_ret_ty(o, fn_info),
        .Stdcall => return if (is_scalar(mod, return_type)) o.lower_type(return_type) else .void,
        else => return o.lower_type(return_type),
    }
}

fn lower_win64_fn_ret_ty(o: *Object, fn_info: InternPool.Key.FuncType) Allocator.Error!Builder.Type {
    const mod = o.module;
    const return_type = Type.from_interned(fn_info.return_type);
    switch (x86_64_abi.classify_windows(return_type, mod)) {
        .integer => {
            if (is_scalar(mod, return_type)) {
                return o.lower_type(return_type);
            } else {
                return o.builder.int_type(@int_cast(return_type.abi_size(mod) * 8));
            }
        },
        .win_i128 => return o.builder.vector_type(.normal, 2, .i64),
        .memory => return .void,
        .sse => return o.lower_type(return_type),
        else => unreachable,
    }
}

fn lower_system_vfn_ret_ty(o: *Object, fn_info: InternPool.Key.FuncType) Allocator.Error!Builder.Type {
    const mod = o.module;
    const ip = &mod.intern_pool;
    const return_type = Type.from_interned(fn_info.return_type);
    if (is_scalar(mod, return_type)) {
        return o.lower_type(return_type);
    }
    const target = mod.get_target();
    const classes = x86_64_abi.classify_system_v(return_type, mod, target, .ret);
    if (classes[0] == .memory) return .void;
    var types_index: u32 = 0;
    var types_buffer: [8]Builder.Type = undefined;
    for (classes) |class| {
        switch (class) {
            .integer => {
                types_buffer[types_index] = .i64;
                types_index += 1;
            },
            .sse => {
                types_buffer[types_index] = .double;
                types_index += 1;
            },
            .sseup => {
                if (types_buffer[types_index - 1] == .double) {
                    types_buffer[types_index - 1] = .fp128;
                } else {
                    types_buffer[types_index] = .double;
                    types_index += 1;
                }
            },
            .float => {
                types_buffer[types_index] = .float;
                types_index += 1;
            },
            .float_combine => {
                types_buffer[types_index] = try o.builder.vector_type(.normal, 2, .float);
                types_index += 1;
            },
            .x87 => {
                if (types_index != 0 or classes[2] != .none) return .void;
                types_buffer[types_index] = .x86_fp80;
                types_index += 1;
            },
            .x87up => continue,
            .complex_x87 => {
                @panic("TODO");
            },
            .memory => unreachable, // handled above
            .win_i128 => unreachable, // windows only
            .none => break,
            .integer_per_element => {
                @panic("TODO");
            },
        }
    }
    const first_non_integer = std.mem.index_of_none(x86_64_abi.Class, &classes, &.{.integer});
    if (first_non_integer == null or classes[first_non_integer.?] == .none) {
        assert(first_non_integer orelse classes.len == types_index);
        switch (ip.index_to_key(return_type.to_intern())) {
            .struct_type => {
                const struct_type = ip.load_struct_type(return_type.to_intern());
                assert(struct_type.have_layout(ip));
                const size: u64 = struct_type.size(ip).*;
                assert((std.math.div_ceil(u64, size, 8) catch unreachable) == types_index);
                if (size % 8 > 0) {
                    types_buffer[types_index - 1] = try o.builder.int_type(@int_cast(size % 8 * 8));
                }
            },
            else => {},
        }
        if (types_index == 1) return types_buffer[0];
    }
    return o.builder.struct_type(.normal, types_buffer[0..types_index]);
}

const ParamTypeIterator = struct {
    object: *Object,
    fn_info: InternPool.Key.FuncType,
    zig_index: u32,
    llvm_index: u32,
    types_len: u32,
    types_buffer: [8]Builder.Type,
    byval_attr: bool,

    const Lowering = union(enum) {
        no_bits,
        byval,
        byref,
        byref_mut,
        abi_sized_int,
        multiple_llvm_types,
        slice,
        as_u16,
        float_array: u8,
        i32_array: u8,
        i64_array: u8,
    };

    pub fn next(it: *ParamTypeIterator) Allocator.Error!?Lowering {
        if (it.zig_index >= it.fn_info.param_types.len) return null;
        const zcu = it.object.module;
        const ip = &zcu.intern_pool;
        const ty = it.fn_info.param_types.get(ip)[it.zig_index];
        it.byval_attr = false;
        return next_inner(it, Type.from_interned(ty));
    }

    /// `air_call` uses this instead of `next` so that it can take into account variadic functions.
    pub fn next_call(it: *ParamTypeIterator, fg: *FuncGen, args: []const Air.Inst.Ref) Allocator.Error!?Lowering {
        const zcu = it.object.module;
        const ip = &zcu.intern_pool;
        if (it.zig_index >= it.fn_info.param_types.len) {
            if (it.zig_index >= args.len) {
                return null;
            } else {
                return next_inner(it, fg.type_of(args[it.zig_index]));
            }
        } else {
            return next_inner(it, Type.from_interned(it.fn_info.param_types.get(ip)[it.zig_index]));
        }
    }

    fn next_inner(it: *ParamTypeIterator, ty: Type) Allocator.Error!?Lowering {
        const zcu = it.object.module;
        const target = zcu.get_target();

        if (!ty.has_runtime_bits_ignore_comptime(zcu)) {
            it.zig_index += 1;
            return .no_bits;
        }
        switch (it.fn_info.cc) {
            .Unspecified, .Inline => {
                it.zig_index += 1;
                it.llvm_index += 1;
                if (ty.is_slice(zcu) or
                    (ty.zig_type_tag(zcu) == .Optional and ty.optional_child(zcu).is_slice(zcu) and !ty.ptr_allows_zero(zcu)))
                {
                    it.llvm_index += 1;
                    return .slice;
                } else if (is_by_ref(ty, zcu)) {
                    return .byref;
                } else if (target.cpu.arch.is_x86() and
                    !std.Target.x86.feature_set_has(target.cpu.features, .evex512) and
                    ty.total_vector_bits(zcu) >= 512)
                {
                    // As of LLVM 18, passing a vector byval with fastcc that is 512 bits or more returns
                    // "512-bit vector arguments require 'evex512' for AVX512"
                    return .byref;
                } else {
                    return .byval;
                }
            },
            .Async => {
                @panic("TODO implement async function lowering in the LLVM backend");
            },
            .C => switch (target.cpu.arch) {
                .mips, .mipsel => {
                    it.zig_index += 1;
                    it.llvm_index += 1;
                    return .byval;
                },
                .x86_64 => switch (target.os.tag) {
                    .windows => return it.next_win64(ty),
                    else => return it.next_system_v(ty),
                },
                .wasm32 => {
                    it.zig_index += 1;
                    it.llvm_index += 1;
                    if (is_scalar(zcu, ty)) {
                        return .byval;
                    }
                    const classes = wasm_c_abi.classify_type(ty, zcu);
                    if (classes[0] == .indirect) {
                        return .byref;
                    }
                    return .abi_sized_int;
                },
                .aarch64, .aarch64_be => {
                    it.zig_index += 1;
                    it.llvm_index += 1;
                    switch (aarch64_c_abi.classify_type(ty, zcu)) {
                        .memory => return .byref_mut,
                        .float_array => |len| return Lowering{ .float_array = len },
                        .byval => return .byval,
                        .integer => {
                            it.types_len = 1;
                            it.types_buffer[0] = .i64;
                            return .multiple_llvm_types;
                        },
                        .double_integer => return Lowering{ .i64_array = 2 },
                    }
                },
                .arm, .armeb => {
                    it.zig_index += 1;
                    it.llvm_index += 1;
                    switch (arm_c_abi.classify_type(ty, zcu, .arg)) {
                        .memory => {
                            it.byval_attr = true;
                            return .byref;
                        },
                        .byval => return .byval,
                        .i32_array => |size| return Lowering{ .i32_array = size },
                        .i64_array => |size| return Lowering{ .i64_array = size },
                    }
                },
                .riscv32, .riscv64 => {
                    it.zig_index += 1;
                    it.llvm_index += 1;
                    if (ty.to_intern() == .f16_type and
                        !std.Target.riscv.feature_set_has(target.cpu.features, .d)) return .as_u16;
                    switch (riscv_c_abi.classify_type(ty, zcu)) {
                        .memory => return .byref_mut,
                        .byval => return .byval,
                        .integer => return .abi_sized_int,
                        .double_integer => return Lowering{ .i64_array = 2 },
                        .fields => {
                            it.types_len = 0;
                            for (0..ty.struct_field_count(zcu)) |field_index| {
                                const field_ty = ty.struct_field_type(field_index, zcu);
                                if (!field_ty.has_runtime_bits_ignore_comptime(zcu)) continue;
                                it.types_buffer[it.types_len] = try it.object.lower_type(field_ty);
                                it.types_len += 1;
                            }
                            it.llvm_index += it.types_len - 1;
                            return .multiple_llvm_types;
                        },
                        .none => unreachable,
                    }
                },
                // TODO investigate C ABI for other architectures
                else => {
                    it.zig_index += 1;
                    it.llvm_index += 1;
                    return .byval;
                },
            },
            .Win64 => return it.next_win64(ty),
            .SysV => return it.next_system_v(ty),
            .Stdcall => {
                it.zig_index += 1;
                it.llvm_index += 1;

                if (is_scalar(zcu, ty)) {
                    return .byval;
                } else {
                    it.byval_attr = true;
                    return .byref;
                }
            },
            else => {
                it.zig_index += 1;
                it.llvm_index += 1;
                return .byval;
            },
        }
    }

    fn next_win64(it: *ParamTypeIterator, ty: Type) ?Lowering {
        const zcu = it.object.module;
        switch (x86_64_abi.classify_windows(ty, zcu)) {
            .integer => {
                if (is_scalar(zcu, ty)) {
                    it.zig_index += 1;
                    it.llvm_index += 1;
                    return .byval;
                } else {
                    it.zig_index += 1;
                    it.llvm_index += 1;
                    return .abi_sized_int;
                }
            },
            .win_i128 => {
                it.zig_index += 1;
                it.llvm_index += 1;
                return .byref;
            },
            .memory => {
                it.zig_index += 1;
                it.llvm_index += 1;
                return .byref_mut;
            },
            .sse => {
                it.zig_index += 1;
                it.llvm_index += 1;
                return .byval;
            },
            else => unreachable,
        }
    }

    fn next_system_v(it: *ParamTypeIterator, ty: Type) Allocator.Error!?Lowering {
        const zcu = it.object.module;
        const ip = &zcu.intern_pool;
        const target = zcu.get_target();
        const classes = x86_64_abi.classify_system_v(ty, zcu, target, .arg);
        if (classes[0] == .memory) {
            it.zig_index += 1;
            it.llvm_index += 1;
            it.byval_attr = true;
            return .byref;
        }
        if (is_scalar(zcu, ty)) {
            it.zig_index += 1;
            it.llvm_index += 1;
            return .byval;
        }
        var types_index: u32 = 0;
        var types_buffer: [8]Builder.Type = undefined;
        for (classes) |class| {
            switch (class) {
                .integer => {
                    types_buffer[types_index] = .i64;
                    types_index += 1;
                },
                .sse => {
                    types_buffer[types_index] = .double;
                    types_index += 1;
                },
                .sseup => {
                    if (types_buffer[types_index - 1] == .double) {
                        types_buffer[types_index - 1] = .fp128;
                    } else {
                        types_buffer[types_index] = .double;
                        types_index += 1;
                    }
                },
                .float => {
                    types_buffer[types_index] = .float;
                    types_index += 1;
                },
                .float_combine => {
                    types_buffer[types_index] = try it.object.builder.vector_type(.normal, 2, .float);
                    types_index += 1;
                },
                .x87 => {
                    it.zig_index += 1;
                    it.llvm_index += 1;
                    it.byval_attr = true;
                    return .byref;
                },
                .x87up => unreachable,
                .complex_x87 => {
                    @panic("TODO");
                },
                .memory => unreachable, // handled above
                .win_i128 => unreachable, // windows only
                .none => break,
                .integer_per_element => {
                    @panic("TODO");
                },
            }
        }
        const first_non_integer = std.mem.index_of_none(x86_64_abi.Class, &classes, &.{.integer});
        if (first_non_integer == null or classes[first_non_integer.?] == .none) {
            assert(first_non_integer orelse classes.len == types_index);
            if (types_index == 1) {
                it.zig_index += 1;
                it.llvm_index += 1;
                return .abi_sized_int;
            }
            if (it.llvm_index + types_index > 6) {
                it.zig_index += 1;
                it.llvm_index += 1;
                it.byval_attr = true;
                return .byref;
            }
            switch (ip.index_to_key(ty.to_intern())) {
                .struct_type => {
                    const struct_type = ip.load_struct_type(ty.to_intern());
                    assert(struct_type.have_layout(ip));
                    const size: u64 = struct_type.size(ip).*;
                    assert((std.math.div_ceil(u64, size, 8) catch unreachable) == types_index);
                    if (size % 8 > 0) {
                        types_buffer[types_index - 1] =
                            try it.object.builder.int_type(@int_cast(size % 8 * 8));
                    }
                },
                else => {},
            }
        }
        it.types_len = types_index;
        it.types_buffer = types_buffer;
        it.llvm_index += types_index;
        it.zig_index += 1;
        return .multiple_llvm_types;
    }
};

fn iterate_param_types(object: *Object, fn_info: InternPool.Key.FuncType) ParamTypeIterator {
    return .{
        .object = object,
        .fn_info = fn_info,
        .zig_index = 0,
        .llvm_index = 0,
        .types_len = 0,
        .types_buffer = undefined,
        .byval_attr = false,
    };
}

fn cc_abi_promote_int(
    cc: std.builtin.CallingConvention,
    mod: *Module,
    ty: Type,
) ?std.builtin.Signedness {
    const target = mod.get_target();
    switch (cc) {
        .Unspecified, .Inline, .Async => return null,
        else => {},
    }
    const int_info = switch (ty.zig_type_tag(mod)) {
        .Bool => Type.u1.int_info(mod),
        .Int, .Enum, .ErrorSet => ty.int_info(mod),
        else => return null,
    };
    return switch (target.os.tag) {
        .macos, .ios, .watchos, .tvos, .visionos => switch (int_info.bits) {
            0...16 => int_info.signedness,
            else => null,
        },
        else => switch (target.cpu.arch) {
            .riscv64 => switch (int_info.bits) {
                0...16 => int_info.signedness,
                32 => .signed, // LLVM always signextends 32 bit ints, unsure if bug.
                17...31, 33...63 => int_info.signedness,
                else => null,
            },

            .sparc64,
            .powerpc64,
            .powerpc64le,
            => switch (int_info.bits) {
                0...63 => int_info.signedness,
                else => null,
            },

            .aarch64,
            .aarch64_be,
            => null,

            else => switch (int_info.bits) {
                0...16 => int_info.signedness,
                else => null,
            },
        },
    };
}

/// This is the one source of truth for whether a type is passed around as an LLVM pointer,
/// or as an LLVM value.
fn is_by_ref(ty: Type, mod: *Module) bool {
    // For tuples and structs, if there are more than this many non-void
    // fields, then we make it byref, otherwise byval.
    const max_fields_byval = 0;
    const ip = &mod.intern_pool;

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
        .Int,
        .Float,
        .Pointer,
        .ErrorSet,
        .Fn,
        .Enum,
        .Vector,
        .AnyFrame,
        => return false,

        .Array, .Frame => return ty.has_runtime_bits(mod),
        .Struct => {
            const struct_type = switch (ip.index_to_key(ty.to_intern())) {
                .anon_struct_type => |tuple| {
                    var count: usize = 0;
                    for (tuple.types.get(ip), tuple.values.get(ip)) |field_ty, field_val| {
                        if (field_val != .none or !Type.from_interned(field_ty).has_runtime_bits(mod)) continue;

                        count += 1;
                        if (count > max_fields_byval) return true;
                        if (is_by_ref(Type.from_interned(field_ty), mod)) return true;
                    }
                    return false;
                },
                .struct_type => ip.load_struct_type(ty.to_intern()),
                else => unreachable,
            };

            // Packed structs are represented to LLVM as integers.
            if (struct_type.layout == .@"packed") return false;

            const field_types = struct_type.field_types.get(ip);
            var it = struct_type.iterate_runtime_order(ip);
            var count: usize = 0;
            while (it.next()) |field_index| {
                count += 1;
                if (count > max_fields_byval) return true;
                const field_ty = Type.from_interned(field_types[field_index]);
                if (is_by_ref(field_ty, mod)) return true;
            }
            return false;
        },
        .Union => switch (ty.container_layout(mod)) {
            .@"packed" => return false,
            else => return ty.has_runtime_bits(mod),
        },
        .ErrorUnion => {
            const payload_ty = ty.error_union_payload(mod);
            if (!payload_ty.has_runtime_bits_ignore_comptime(mod)) {
                return false;
            }
            return true;
        },
        .Optional => {
            const payload_ty = ty.optional_child(mod);
            if (!payload_ty.has_runtime_bits_ignore_comptime(mod)) {
                return false;
            }
            if (ty.optional_repr_is_payload(mod)) {
                return false;
            }
            return true;
        },
    }
}

fn is_scalar(mod: *Module, ty: Type) bool {
    return switch (ty.zig_type_tag(mod)) {
        .Void,
        .Bool,
        .NoReturn,
        .Int,
        .Float,
        .Pointer,
        .Optional,
        .ErrorSet,
        .Enum,
        .AnyFrame,
        .Vector,
        => true,

        .Struct => ty.container_layout(mod) == .@"packed",
        .Union => ty.container_layout(mod) == .@"packed",
        else => false,
    };
}

/// This function returns true if we expect LLVM to lower x86_fp80 correctly
/// and false if we expect LLVM to crash if it counters an x86_fp80 type.
fn backend_supports_f80(target: std.Target) bool {
    return switch (target.cpu.arch) {
        .x86_64, .x86 => !std.Target.x86.feature_set_has(target.cpu.features, .soft_float),
        else => false,
    };
}

/// This function returns true if we expect LLVM to lower f16 correctly
/// and false if we expect LLVM to crash if it counters an f16 type or
/// if it produces miscompilations.
fn backend_supports_f16(target: std.Target) bool {
    return switch (target.cpu.arch) {
        .powerpc,
        .powerpcle,
        .powerpc64,
        .powerpc64le,
        .wasm32,
        .wasm64,
        .mips,
        .mipsel,
        .mips64,
        .mips64el,
        => false,
        .aarch64 => std.Target.aarch64.feature_set_has(target.cpu.features, .fp_armv8),
        else => true,
    };
}

/// This function returns true if we expect LLVM to lower f128 correctly,
/// and false if we expect LLVm to crash if it encounters and f128 type
/// or if it produces miscompilations.
fn backend_supports_f128(target: std.Target) bool {
    return switch (target.cpu.arch) {
        .amdgcn => false,
        .aarch64 => std.Target.aarch64.feature_set_has(target.cpu.features, .fp_armv8),
        else => true,
    };
}

/// LLVM does not support all relevant intrinsics for all targets, so we
/// may need to manually generate a libc call
fn intrinsics_allowed(scalar_ty: Type, target: std.Target) bool {
    return switch (scalar_ty.to_intern()) {
        .f16_type => backend_supports_f16(target),
        .f80_type => (target.c_type_bit_size(.longdouble) == 80) and backend_supports_f80(target),
        .f128_type => (target.c_type_bit_size(.longdouble) == 128) and backend_supports_f128(target),
        else => true,
    };
}

/// We need to insert extra padding if LLVM's isn't enough.
/// However we don't want to ever call LLVMABIAlignmentOfType or
/// LLVMABISizeOfType because these functions will trip assertions
/// when using them for self-referential types. So our strategy is
/// to use non-packed llvm structs but to emit all padding explicitly.
/// We can do this because for all types, Zig ABI alignment >= LLVM ABI
/// alignment.
const struct_layout_version = 2;

// TODO: Restore the non_null field to i1 once
//       https://github.com/llvm/llvm-project/issues/56585/ is fixed
const optional_layout_version = 3;

const lt_errors_fn_name = "__zig_lt_errors_len";

/// Without this workaround, LLVM crashes with "unknown codeview register H1"
/// https://github.com/llvm/llvm-project/issues/56484
fn need_dbg_var_workaround(o: *Object) bool {
    const target = o.module.get_target();
    if (target.os.tag == .windows and target.cpu.arch == .aarch64) {
        return true;
    }
    return false;
}

fn compiler_rt_int_bits(bits: u16) u16 {
    inline for (.{ 32, 64, 128 }) |b| {
        if (bits <= b) {
            return b;
        }
    }
    return bits;
}

fn build_alloca_inner(
    wip: *Builder.WipFunction,
    llvm_ty: Builder.Type,
    alignment: Builder.Alignment,
    target: std.Target,
) Allocator.Error!Builder.Value {
    const address_space = llvm_alloca_address_space(target);

    const alloca = blk: {
        const prev_cursor = wip.cursor;
        const prev_debug_location = wip.debug_location;
        defer {
            wip.cursor = prev_cursor;
            if (wip.cursor.block == .entry) wip.cursor.instruction += 1;
            wip.debug_location = prev_debug_location;
        }

        wip.cursor = .{ .block = .entry };
        wip.debug_location = .no_location;
        break :blk try wip.alloca(.normal, llvm_ty, .none, alignment, address_space, "");
    };

    // The pointer returned from this function should have the generic address space,
    // if this isn't the case then cast it to the generic address space.
    return wip.conv(.unneeded, alloca, .ptr, "");
}

fn err_union_payload_offset(payload_ty: Type, mod: *Module) !u1 {
    const err_int_ty = try mod.error_int_type();
    return @int_from_bool(err_int_ty.abi_alignment(mod).compare(.gt, payload_ty.abi_alignment(mod)));
}

fn err_union_error_offset(payload_ty: Type, mod: *Module) !u1 {
    const err_int_ty = try mod.error_int_type();
    return @int_from_bool(err_int_ty.abi_alignment(mod).compare(.lte, payload_ty.abi_alignment(mod)));
}

/// Returns true for asm constraint (e.g. "=*m", "=r") if it accepts a memory location
///
/// See also TargetInfo::validateOutputConstraint, AArch64TargetInfo::validateAsmConstraint, etc. in Clang
fn constraint_allows_memory(constraint: []const u8) bool {
    // TODO: This implementation is woefully incomplete.
    for (constraint) |byte| {
        switch (byte) {
            '=', '*', ',', '&' => {},
            'm', 'o', 'X', 'g' => return true,
            else => {},
        }
    } else return false;
}

/// Returns true for asm constraint (e.g. "=*m", "=r") if it accepts a register
///
/// See also TargetInfo::validateOutputConstraint, AArch64TargetInfo::validateAsmConstraint, etc. in Clang
fn constraint_allows_register(constraint: []const u8) bool {
    // TODO: This implementation is woefully incomplete.
    for (constraint) |byte| {
        switch (byte) {
            '=', '*', ',', '&' => {},
            'm', 'o' => {},
            else => return true,
        }
    } else return false;
}

pub fn initialize_llvmtarget(arch: std.Target.Cpu.Arch) void {
    switch (arch) {
        .aarch64, .aarch64_be, .aarch64_32 => {
            llvm.LLVMInitializeAArch64Target();
            llvm.LLVMInitializeAArch64TargetInfo();
            llvm.LLVMInitializeAArch64TargetMC();
            llvm.LLVMInitializeAArch64AsmPrinter();
            llvm.LLVMInitializeAArch64AsmParser();
        },
        .amdgcn => {
            llvm.LLVMInitializeAMDGPUTarget();
            llvm.LLVMInitializeAMDGPUTargetInfo();
            llvm.LLVMInitializeAMDGPUTargetMC();
            llvm.LLVMInitializeAMDGPUAsmPrinter();
            llvm.LLVMInitializeAMDGPUAsmParser();
        },
        .thumb, .thumbeb, .arm, .armeb => {
            llvm.LLVMInitializeARMTarget();
            llvm.LLVMInitializeARMTargetInfo();
            llvm.LLVMInitializeARMTargetMC();
            llvm.LLVMInitializeARMAsmPrinter();
            llvm.LLVMInitializeARMAsmParser();
        },
        .avr => {
            llvm.LLVMInitializeAVRTarget();
            llvm.LLVMInitializeAVRTargetInfo();
            llvm.LLVMInitializeAVRTargetMC();
            llvm.LLVMInitializeAVRAsmPrinter();
            llvm.LLVMInitializeAVRAsmParser();
        },
        .bpfel, .bpfeb => {
            llvm.LLVMInitializeBPFTarget();
            llvm.LLVMInitializeBPFTargetInfo();
            llvm.LLVMInitializeBPFTargetMC();
            llvm.LLVMInitializeBPFAsmPrinter();
            llvm.LLVMInitializeBPFAsmParser();
        },
        .hexagon => {
            llvm.LLVMInitializeHexagonTarget();
            llvm.LLVMInitializeHexagonTargetInfo();
            llvm.LLVMInitializeHexagonTargetMC();
            llvm.LLVMInitializeHexagonAsmPrinter();
            llvm.LLVMInitializeHexagonAsmParser();
        },
        .lanai => {
            llvm.LLVMInitializeLanaiTarget();
            llvm.LLVMInitializeLanaiTargetInfo();
            llvm.LLVMInitializeLanaiTargetMC();
            llvm.LLVMInitializeLanaiAsmPrinter();
            llvm.LLVMInitializeLanaiAsmParser();
        },
        .mips, .mipsel, .mips64, .mips64el => {
            llvm.LLVMInitializeMipsTarget();
            llvm.LLVMInitializeMipsTargetInfo();
            llvm.LLVMInitializeMipsTargetMC();
            llvm.LLVMInitializeMipsAsmPrinter();
            llvm.LLVMInitializeMipsAsmParser();
        },
        .msp430 => {
            llvm.LLVMInitializeMSP430Target();
            llvm.LLVMInitializeMSP430TargetInfo();
            llvm.LLVMInitializeMSP430TargetMC();
            llvm.LLVMInitializeMSP430AsmPrinter();
            llvm.LLVMInitializeMSP430AsmParser();
        },
        .nvptx, .nvptx64 => {
            llvm.LLVMInitializeNVPTXTarget();
            llvm.LLVMInitializeNVPTXTargetInfo();
            llvm.LLVMInitializeNVPTXTargetMC();
            llvm.LLVMInitializeNVPTXAsmPrinter();
            // There is no LLVMInitializeNVPTXAsmParser function available.
        },
        .powerpc, .powerpcle, .powerpc64, .powerpc64le => {
            llvm.LLVMInitializePowerPCTarget();
            llvm.LLVMInitializePowerPCTargetInfo();
            llvm.LLVMInitializePowerPCTargetMC();
            llvm.LLVMInitializePowerPCAsmPrinter();
            llvm.LLVMInitializePowerPCAsmParser();
        },
        .riscv32, .riscv64 => {
            llvm.LLVMInitializeRISCVTarget();
            llvm.LLVMInitializeRISCVTargetInfo();
            llvm.LLVMInitializeRISCVTargetMC();
            llvm.LLVMInitializeRISCVAsmPrinter();
            llvm.LLVMInitializeRISCVAsmParser();
        },
        .sparc, .sparc64, .sparcel => {
            llvm.LLVMInitializeSparcTarget();
            llvm.LLVMInitializeSparcTargetInfo();
            llvm.LLVMInitializeSparcTargetMC();
            llvm.LLVMInitializeSparcAsmPrinter();
            llvm.LLVMInitializeSparcAsmParser();
        },
        .s390x => {
            llvm.LLVMInitializeSystemZTarget();
            llvm.LLVMInitializeSystemZTargetInfo();
            llvm.LLVMInitializeSystemZTargetMC();
            llvm.LLVMInitializeSystemZAsmPrinter();
            llvm.LLVMInitializeSystemZAsmParser();
        },
        .wasm32, .wasm64 => {
            llvm.LLVMInitializeWebAssemblyTarget();
            llvm.LLVMInitializeWebAssemblyTargetInfo();
            llvm.LLVMInitializeWebAssemblyTargetMC();
            llvm.LLVMInitializeWebAssemblyAsmPrinter();
            llvm.LLVMInitializeWebAssemblyAsmParser();
        },
        .x86, .x86_64 => {
            llvm.LLVMInitializeX86Target();
            llvm.LLVMInitializeX86TargetInfo();
            llvm.LLVMInitializeX86TargetMC();
            llvm.LLVMInitializeX86AsmPrinter();
            llvm.LLVMInitializeX86AsmParser();
        },
        .xtensa => {
            if (build_options.llvm_has_xtensa) {
                llvm.LLVMInitializeXtensaTarget();
                llvm.LLVMInitializeXtensaTargetInfo();
                llvm.LLVMInitializeXtensaTargetMC();
                // There is no LLVMInitializeXtensaAsmPrinter function.
                llvm.LLVMInitializeXtensaAsmParser();
            }
        },
        .xcore => {
            llvm.LLVMInitializeXCoreTarget();
            llvm.LLVMInitializeXCoreTargetInfo();
            llvm.LLVMInitializeXCoreTargetMC();
            llvm.LLVMInitializeXCoreAsmPrinter();
            // There is no LLVMInitializeXCoreAsmParser function.
        },
        .m68k => {
            if (build_options.llvm_has_m68k) {
                llvm.LLVMInitializeM68kTarget();
                llvm.LLVMInitializeM68kTargetInfo();
                llvm.LLVMInitializeM68kTargetMC();
                llvm.LLVMInitializeM68kAsmPrinter();
                llvm.LLVMInitializeM68kAsmParser();
            }
        },
        .csky => {
            if (build_options.llvm_has_csky) {
                llvm.LLVMInitializeCSKYTarget();
                llvm.LLVMInitializeCSKYTargetInfo();
                llvm.LLVMInitializeCSKYTargetMC();
                // There is no LLVMInitializeCSKYAsmPrinter function.
                llvm.LLVMInitializeCSKYAsmParser();
            }
        },
        .ve => {
            llvm.LLVMInitializeVETarget();
            llvm.LLVMInitializeVETargetInfo();
            llvm.LLVMInitializeVETargetMC();
            llvm.LLVMInitializeVEAsmPrinter();
            llvm.LLVMInitializeVEAsmParser();
        },
        .arc => {
            if (build_options.llvm_has_arc) {
                llvm.LLVMInitializeARCTarget();
                llvm.LLVMInitializeARCTargetInfo();
                llvm.LLVMInitializeARCTargetMC();
                llvm.LLVMInitializeARCAsmPrinter();
                // There is no LLVMInitializeARCAsmParser function.
            }
        },
        .loongarch32, .loongarch64 => {
            llvm.LLVMInitializeLoongArchTarget();
            llvm.LLVMInitializeLoongArchTargetInfo();
            llvm.LLVMInitializeLoongArchTargetMC();
            llvm.LLVMInitializeLoongArchAsmPrinter();
            llvm.LLVMInitializeLoongArchAsmParser();
        },

        // LLVM backends that have no initialization functions.
        .tce,
        .tcele,
        .r600,
        .le32,
        .le64,
        .amdil,
        .amdil64,
        .hsail,
        .hsail64,
        .shave,
        .spir,
        .spir64,
        .spirv,
        .spirv32,
        .spirv64,
        .kalimba,
        .renderscript32,
        .renderscript64,
        .dxil,
        => {},

        .spu_2 => unreachable, // LLVM does not support this backend
    }
}
