pub const BuildOptions = struct {
    has_macos_sdk: bool,
    has_ios_sdk: bool,
    has_symlinks: bool,
};

pub const Options = struct {
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode = .Debug,
    use_llvm: bool = true,
    use_lld: bool = false,
    strip: ?bool = null,
};

pub fn add_test_step(b: *Build, prefix: []const u8, opts: Options) *Step {
    const target = opts.target.result.zigTriple(b.allocator) catch @panic("OOM");
    const optimize = @tagName(opts.optimize);
    const use_llvm = if (opts.use_llvm) "llvm" else "no-llvm";
    const use_lld = if (opts.use_lld) "lld" else "no-lld";
    if (opts.strip) |strip| {
        const s = if (strip) "strip" else "no-strip";
        const name = std.fmt.allocPrint(b.allocator, "test-{s}-{s}-{s}-{s}-{s}-{s}", .{
            prefix, target, optimize, use_llvm, use_lld, s,
        }) catch @panic("OOM");
        return b.step(name, "");
    }
    const name = std.fmt.allocPrint(b.allocator, "test-{s}-{s}-{s}-{s}-{s}", .{
        prefix, target, optimize, use_llvm, use_lld,
    }) catch @panic("OOM");
    return b.step(name, "");
}

const OverlayOptions = struct {
    name: []const u8,
    asm_source_bytes: ?[]const u8 = null,
    c_source_bytes: ?[]const u8 = null,
    c_source_flags: []const []const u8 = &.{},
    cpp_source_bytes: ?[]const u8 = null,
    cpp_source_flags: []const []const u8 = &.{},
    objc_source_bytes: ?[]const u8 = null,
    objc_source_flags: []const []const u8 = &.{},
    objcpp_source_bytes: ?[]const u8 = null,
    objcpp_source_flags: []const []const u8 = &.{},
    zig_source_bytes: ?[]const u8 = null,
    pic: ?bool = null,
    strip: ?bool = null,
};

pub fn add_executable(b: *std.Build, base: Options, overlay: OverlayOptions) *Compile {
    return addCompileStep(b, base, overlay, .exe);
}

pub fn add_object(b: *Build, base: Options, overlay: OverlayOptions) *Compile {
    return addCompileStep(b, base, overlay, .obj);
}

pub fn add_static_library(b: *Build, base: Options, overlay: OverlayOptions) *Compile {
    return addCompileStep(b, base, overlay, .static_lib);
}

pub fn add_shared_library(b: *Build, base: Options, overlay: OverlayOptions) *Compile {
    return addCompileStep(b, base, overlay, .shared_lib);
}

fn add_compile_step(
    b: *Build,
    base: Options,
    overlay: OverlayOptions,
    kind: enum { exe, obj, shared_lib, static_lib },
) *Compile {
    const compile_step = Compile.create(b, .{
        .name = overlay.name,
        .root_module = .{
            .target = base.target,
            .optimize = base.optimize,
            .root_source_file = rsf: {
                const bytes = overlay.zig_source_bytes orelse break :rsf null;
                break :rsf b.addWriteFiles().add("a.zig", bytes);
            },
            .pic = overlay.pic,
            .strip = if (base.strip) |s| s else overlay.strip,
        },
        .use_llvm = base.use_llvm,
        .use_lld = base.use_lld,
        .kind = switch (kind) {
            .exe => .exe,
            .obj => .obj,
            .shared_lib, .static_lib => .lib,
        },
        .linkage = switch (kind) {
            .exe, .obj => null,
            .shared_lib => .dynamic,
            .static_lib => .static,
        },
    });
    if (overlay.objcpp_source_bytes) |bytes| {
        compile_step.addCSourceFile(.{
            .file = b.addWriteFiles().add("a.mm", bytes),
            .flags = overlay.objcpp_source_flags,
        });
    }
    if (overlay.objc_source_bytes) |bytes| {
        compile_step.addCSourceFile(.{
            .file = b.addWriteFiles().add("a.m", bytes),
            .flags = overlay.objc_source_flags,
        });
    }
    if (overlay.cpp_source_bytes) |bytes| {
        compile_step.addCSourceFile(.{
            .file = b.addWriteFiles().add("a.cpp", bytes),
            .flags = overlay.cpp_source_flags,
        });
    }
    if (overlay.c_source_bytes) |bytes| {
        compile_step.addCSourceFile(.{
            .file = b.addWriteFiles().add("a.c", bytes),
            .flags = overlay.c_source_flags,
        });
    }
    if (overlay.asm_source_bytes) |bytes| {
        compile_step.addAssemblyFile(b.addWriteFiles().add("a.s", bytes));
    }
    return compile_step;
}

pub fn add_run_artifact(comp: *Compile) *Run {
    const b = comp.step.owner;
    const run = b.addRunArtifact(comp);
    run.skip_foreign_checks = true;
    return run;
}

pub fn add_csource_bytes(comp: *Compile, bytes: []const u8, flags: []const []const u8) void {
    const b = comp.step.owner;
    const file = WriteFile.create(b).add("a.c", bytes);
    comp.addCSourceFile(.{ .file = file, .flags = flags });
}

pub fn add_cpp_source_bytes(comp: *Compile, bytes: []const u8, flags: []const []const u8) void {
    const b = comp.step.owner;
    const file = WriteFile.create(b).add("a.cpp", bytes);
    comp.addCSourceFile(.{ .file = file, .flags = flags });
}

pub fn add_asm_source_bytes(comp: *Compile, bytes: []const u8) void {
    const b = comp.step.owner;
    const actual_bytes = std.fmt.allocPrint(b.allocator, "{s}\n", .{bytes}) catch @panic("OOM");
    const file = WriteFile.create(b).add("a.s", actual_bytes);
    comp.addAssemblyFile(file);
}

pub fn expect_link_errors(comp: *Compile, test_step: *Step, expected_errors: Compile.ExpectedCompileErrors) void {
    comp.expect_errors = expected_errors;
    const bin_file = comp.getEmittedBin();
    bin_file.addStepDependencies(test_step);
}

const std = @import("std");

const Build = std.Build;
const Compile = Step.Compile;
const Run = Step.Run;
const Step = Build.Step;
const WriteFile = Step.WriteFile;
