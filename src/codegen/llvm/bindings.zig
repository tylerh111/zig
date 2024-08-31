//! We do this instead of @cImport because the self-hosted compiler is easier
//! to bootstrap if it does not depend on translate-c.

/// Do not compare directly to .True, use toBool() instead.
pub const Bool = enum(c_int) {
    False,
    True,
    _,

    pub fn from_bool(b: bool) Bool {
        return @as(Bool, @enumFromInt(@intFromBool(b)));
    }

    pub fn to_bool(b: Bool) bool {
        return b != .False;
    }
};

pub const MemoryBuffer = opaque {
    pub const createMemoryBufferWithMemoryRange = LLVMCreateMemoryBufferWithMemoryRange;
    pub const dispose = LLVMDisposeMemoryBuffer;

    extern fn llvmcreate_memory_buffer_with_memory_range(InputData: [*]const u8, InputDataLength: usize, BufferName: ?[*:0]const u8, RequiresNullTerminator: Bool) *MemoryBuffer;
    extern fn llvmdispose_memory_buffer(MemBuf: *MemoryBuffer) void;
};

/// Make sure to use the *InContext functions instead of the global ones.
pub const Context = opaque {
    pub const create = LLVMContextCreate;
    extern fn llvmcontext_create() *Context;

    pub const dispose = LLVMContextDispose;
    extern fn llvmcontext_dispose(C: *Context) void;

    pub const parseBitcodeInContext2 = LLVMParseBitcodeInContext2;
    extern fn llvmparse_bitcode_in_context2(C: *Context, MemBuf: *MemoryBuffer, OutModule: **Module) Bool;

    pub const setOptBisectLimit = ZigLLVMSetOptBisectLimit;
    extern fn zig_llvmset_opt_bisect_limit(C: *Context, limit: c_int) void;

    pub const enableBrokenDebugInfoCheck = ZigLLVMEnableBrokenDebugInfoCheck;
    extern fn zig_llvmenable_broken_debug_info_check(C: *Context) void;

    pub const getBrokenDebugInfo = ZigLLVMGetBrokenDebugInfo;
    extern fn zig_llvmget_broken_debug_info(C: *Context) bool;

    pub const intType = LLVMIntTypeInContext;
    extern fn llvmint_type_in_context(C: *Context, NumBits: c_uint) *Type;
};

pub const Module = opaque {
    pub const dispose = LLVMDisposeModule;
    extern fn llvmdispose_module(*Module) void;

    pub const setModulePICLevel = ZigLLVMSetModulePICLevel;
    extern fn zig_llvmset_module_piclevel(module: *Module) void;

    pub const setModulePIELevel = ZigLLVMSetModulePIELevel;
    extern fn zig_llvmset_module_pielevel(module: *Module) void;

    pub const setModuleCodeModel = ZigLLVMSetModuleCodeModel;
    extern fn zig_llvmset_module_code_model(module: *Module, code_model: CodeModel) void;
};

pub const disposeMessage = LLVMDisposeMessage;
extern fn llvmdispose_message(Message: [*:0]const u8) void;

pub const TargetMachine = opaque {
    pub const create = ZigLLVMCreateTargetMachine;
    extern fn zig_llvmcreate_target_machine(
        T: *Target,
        Triple: [*:0]const u8,
        CPU: ?[*:0]const u8,
        Features: ?[*:0]const u8,
        Level: CodeGenOptLevel,
        Reloc: RelocMode,
        CodeModel: CodeModel,
        function_sections: bool,
        data_sections: bool,
        float_abi: ABIType,
        abi_name: ?[*:0]const u8,
    ) *TargetMachine;

    pub const dispose = LLVMDisposeTargetMachine;
    extern fn llvmdispose_target_machine(T: *TargetMachine) void;

    pub const emitToFile = ZigLLVMTargetMachineEmitToFile;
    extern fn zig_llvmtarget_machine_emit_to_file(
        T: *TargetMachine,
        M: *Module,
        ErrorMessage: *[*:0]const u8,
        is_debug: bool,
        is_small: bool,
        time_report: bool,
        tsan: bool,
        lto: bool,
        asm_filename: ?[*:0]const u8,
        bin_filename: ?[*:0]const u8,
        llvm_ir_filename: ?[*:0]const u8,
        bitcode_filename: ?[*:0]const u8,
    ) bool;

    pub const createTargetDataLayout = LLVMCreateTargetDataLayout;
    extern fn llvmcreate_target_data_layout(*TargetMachine) *TargetData;
};

pub const TargetData = opaque {
    pub const dispose = LLVMDisposeTargetData;
    extern fn llvmdispose_target_data(*TargetData) void;

    pub const abiAlignmentOfType = LLVMABIAlignmentOfType;
    extern fn llvmabialignment_of_type(TD: *TargetData, Ty: *Type) c_uint;
};

pub const Type = opaque {};

pub const CodeModel = enum(c_int) {
    Default,
    JITDefault,
    Tiny,
    Small,
    Kernel,
    Medium,
    Large,
};

pub const CodeGenOptLevel = enum(c_int) {
    None,
    Less,
    Default,
    Aggressive,
};

pub const RelocMode = enum(c_int) {
    Default,
    Static,
    PIC,
    DynamicNoPIC,
    ROPI,
    RWPI,
    ROPI_RWPI,
};

pub const ABIType = enum(c_int) {
    /// Target-specific (either soft or hard depending on triple, etc).
    Default,
    /// Soft float.
    Soft,
    // Hard float.
    Hard,
};

pub const Target = opaque {
    pub const getFromTriple = LLVMGetTargetFromTriple;
    extern fn llvmget_target_from_triple(Triple: [*:0]const u8, T: **Target, ErrorMessage: *[*:0]const u8) Bool;
};

pub extern fn llvminitialize_aarch64_target_info() void;
pub extern fn llvminitialize_amdgputarget_info() void;
pub extern fn llvminitialize_armtarget_info() void;
pub extern fn llvminitialize_avrtarget_info() void;
pub extern fn llvminitialize_bpftarget_info() void;
pub extern fn llvminitialize_hexagon_target_info() void;
pub extern fn llvminitialize_lanai_target_info() void;
pub extern fn llvminitialize_mips_target_info() void;
pub extern fn llvminitialize_msp430_target_info() void;
pub extern fn llvminitialize_nvptxtarget_info() void;
pub extern fn llvminitialize_power_pctarget_info() void;
pub extern fn llvminitialize_riscvtarget_info() void;
pub extern fn llvminitialize_sparc_target_info() void;
pub extern fn llvminitialize_system_ztarget_info() void;
pub extern fn llvminitialize_web_assembly_target_info() void;
pub extern fn llvminitialize_x86_target_info() void;
pub extern fn llvminitialize_xcore_target_info() void;
pub extern fn llvminitialize_xtensa_target_info() void;
pub extern fn llvminitialize_m68k_target_info() void;
pub extern fn llvminitialize_cskytarget_info() void;
pub extern fn llvminitialize_vetarget_info() void;
pub extern fn llvminitialize_arctarget_info() void;
pub extern fn llvminitialize_loong_arch_target_info() void;

pub extern fn llvminitialize_aarch64_target() void;
pub extern fn llvminitialize_amdgputarget() void;
pub extern fn llvminitialize_armtarget() void;
pub extern fn llvminitialize_avrtarget() void;
pub extern fn llvminitialize_bpftarget() void;
pub extern fn llvminitialize_hexagon_target() void;
pub extern fn llvminitialize_lanai_target() void;
pub extern fn llvminitialize_mips_target() void;
pub extern fn llvminitialize_msp430_target() void;
pub extern fn llvminitialize_nvptxtarget() void;
pub extern fn llvminitialize_power_pctarget() void;
pub extern fn llvminitialize_riscvtarget() void;
pub extern fn llvminitialize_sparc_target() void;
pub extern fn llvminitialize_system_ztarget() void;
pub extern fn llvminitialize_web_assembly_target() void;
pub extern fn llvminitialize_x86_target() void;
pub extern fn llvminitialize_xcore_target() void;
pub extern fn llvminitialize_xtensa_target() void;
pub extern fn llvminitialize_m68k_target() void;
pub extern fn llvminitialize_vetarget() void;
pub extern fn llvminitialize_cskytarget() void;
pub extern fn llvminitialize_arctarget() void;
pub extern fn llvminitialize_loong_arch_target() void;

pub extern fn llvminitialize_aarch64_target_mc() void;
pub extern fn llvminitialize_amdgputarget_mc() void;
pub extern fn llvminitialize_armtarget_mc() void;
pub extern fn llvminitialize_avrtarget_mc() void;
pub extern fn llvminitialize_bpftarget_mc() void;
pub extern fn llvminitialize_hexagon_target_mc() void;
pub extern fn llvminitialize_lanai_target_mc() void;
pub extern fn llvminitialize_mips_target_mc() void;
pub extern fn llvminitialize_msp430_target_mc() void;
pub extern fn llvminitialize_nvptxtarget_mc() void;
pub extern fn llvminitialize_power_pctarget_mc() void;
pub extern fn llvminitialize_riscvtarget_mc() void;
pub extern fn llvminitialize_sparc_target_mc() void;
pub extern fn llvminitialize_system_ztarget_mc() void;
pub extern fn llvminitialize_web_assembly_target_mc() void;
pub extern fn llvminitialize_x86_target_mc() void;
pub extern fn llvminitialize_xcore_target_mc() void;
pub extern fn llvminitialize_xtensa_target_mc() void;
pub extern fn llvminitialize_m68k_target_mc() void;
pub extern fn llvminitialize_cskytarget_mc() void;
pub extern fn llvminitialize_vetarget_mc() void;
pub extern fn llvminitialize_arctarget_mc() void;
pub extern fn llvminitialize_loong_arch_target_mc() void;

pub extern fn llvminitialize_aarch64_asm_printer() void;
pub extern fn llvminitialize_amdgpuasm_printer() void;
pub extern fn llvminitialize_armasm_printer() void;
pub extern fn llvminitialize_avrasm_printer() void;
pub extern fn llvminitialize_bpfasm_printer() void;
pub extern fn llvminitialize_hexagon_asm_printer() void;
pub extern fn llvminitialize_lanai_asm_printer() void;
pub extern fn llvminitialize_mips_asm_printer() void;
pub extern fn llvminitialize_msp430_asm_printer() void;
pub extern fn llvminitialize_nvptxasm_printer() void;
pub extern fn llvminitialize_power_pcasm_printer() void;
pub extern fn llvminitialize_riscvasm_printer() void;
pub extern fn llvminitialize_sparc_asm_printer() void;
pub extern fn llvminitialize_system_zasm_printer() void;
pub extern fn llvminitialize_web_assembly_asm_printer() void;
pub extern fn llvminitialize_x86_asm_printer() void;
pub extern fn llvminitialize_xcore_asm_printer() void;
pub extern fn llvminitialize_m68k_asm_printer() void;
pub extern fn llvminitialize_veasm_printer() void;
pub extern fn llvminitialize_arcasm_printer() void;
pub extern fn llvminitialize_loong_arch_asm_printer() void;

pub extern fn llvminitialize_aarch64_asm_parser() void;
pub extern fn llvminitialize_amdgpuasm_parser() void;
pub extern fn llvminitialize_armasm_parser() void;
pub extern fn llvminitialize_avrasm_parser() void;
pub extern fn llvminitialize_bpfasm_parser() void;
pub extern fn llvminitialize_hexagon_asm_parser() void;
pub extern fn llvminitialize_lanai_asm_parser() void;
pub extern fn llvminitialize_mips_asm_parser() void;
pub extern fn llvminitialize_msp430_asm_parser() void;
pub extern fn llvminitialize_power_pcasm_parser() void;
pub extern fn llvminitialize_riscvasm_parser() void;
pub extern fn llvminitialize_sparc_asm_parser() void;
pub extern fn llvminitialize_system_zasm_parser() void;
pub extern fn llvminitialize_web_assembly_asm_parser() void;
pub extern fn llvminitialize_x86_asm_parser() void;
pub extern fn llvminitialize_xtensa_asm_parser() void;
pub extern fn llvminitialize_m68k_asm_parser() void;
pub extern fn llvminitialize_cskyasm_parser() void;
pub extern fn llvminitialize_veasm_parser() void;
pub extern fn llvminitialize_loong_arch_asm_parser() void;

extern fn zig_lldlink_coff(argc: c_int, argv: [*:null]const ?[*:0]const u8, can_exit_early: bool, disable_output: bool) bool;
extern fn zig_lldlink_elf(argc: c_int, argv: [*:null]const ?[*:0]const u8, can_exit_early: bool, disable_output: bool) bool;
extern fn zig_lldlink_wasm(argc: c_int, argv: [*:null]const ?[*:0]const u8, can_exit_early: bool, disable_output: bool) bool;

pub const LinkCOFF = ZigLLDLinkCOFF;
pub const LinkELF = ZigLLDLinkELF;
pub const LinkWasm = ZigLLDLinkWasm;

pub const ObjectFormatType = enum(c_int) {
    Unknown,
    COFF,
    DXContainer,
    ELF,
    GOFF,
    MachO,
    SPIRV,
    Wasm,
    XCOFF,
};

pub const WriteArchive = ZigLLVMWriteArchive;
extern fn zig_llvmwrite_archive(
    archive_name: [*:0]const u8,
    file_names_ptr: [*]const [*:0]const u8,
    file_names_len: usize,
    os_type: OSType,
) bool;

pub const OSType = enum(c_int) {
    UnknownOS,
    Darwin,
    DragonFly,
    FreeBSD,
    Fuchsia,
    IOS,
    KFreeBSD,
    Linux,
    Lv2,
    MacOSX,
    NetBSD,
    OpenBSD,
    Solaris,
    UEFI,
    Win32,
    ZOS,
    Haiku,
    RTEMS,
    NaCl,
    AIX,
    CUDA,
    NVCL,
    AMDHSA,
    PS4,
    PS5,
    ELFIAMCU,
    TvOS,
    WatchOS,
    DriverKit,
    XROS,
    Mesa3D,
    AMDPAL,
    HermitCore,
    Hurd,
    WASI,
    Emscripten,
    ShaderModel,
    LiteOS,
    Serenity,
    Vulkan,
};

pub const ArchType = enum(c_int) {
    UnknownArch,
    arm,
    armeb,
    aarch64,
    aarch64_be,
    aarch64_32,
    arc,
    avr,
    bpfel,
    bpfeb,
    csky,
    dxil,
    hexagon,
    loongarch32,
    loongarch64,
    m68k,
    mips,
    mipsel,
    mips64,
    mips64el,
    msp430,
    ppc,
    ppcle,
    ppc64,
    ppc64le,
    r600,
    amdgcn,
    riscv32,
    riscv64,
    sparc,
    sparcv9,
    sparcel,
    systemz,
    tce,
    tcele,
    thumb,
    thumbeb,
    x86,
    x86_64,
    xcore,
    xtensa,
    nvptx,
    nvptx64,
    le32,
    le64,
    amdil,
    amdil64,
    hsail,
    hsail64,
    spir,
    spir64,
    spirv,
    spirv32,
    spirv64,
    kalimba,
    shave,
    lanai,
    wasm32,
    wasm64,
    renderscript32,
    renderscript64,
    ve,
};

pub const ParseCommandLineOptions = ZigLLVMParseCommandLineOptions;
extern fn zig_llvmparse_command_line_options(argc: usize, argv: [*]const [*:0]const u8) void;

pub const WriteImportLibrary = ZigLLVMWriteImportLibrary;
extern fn zig_llvmwrite_import_library(
    def_path: [*:0]const u8,
    arch: ArchType,
    output_lib_path: [*:0]const u8,
    kill_at: bool,
) bool;

pub const GetHostCPUName = LLVMGetHostCPUName;
extern fn llvmget_host_cpuname() ?[*:0]u8;

pub const GetHostCPUFeatures = LLVMGetHostCPUFeatures;
extern fn llvmget_host_cpufeatures() ?[*:0]u8;
