const std = @import("std");
const mem = std.mem;
const Compilation = @import("../Compilation.zig");
const GCCDetector = @import("../Driver/GCCDetector.zig");
const Toolchain = @import("../Toolchain.zig");
const Driver = @import("../Driver.zig");
const Distro = @import("../Driver/Distro.zig");
const target_util = @import("../target.zig");
const system_defaults = @import("system_defaults");

const Linux = @This();

distro: Distro.Tag = .unknown,
extra_opts: std.ArrayListUnmanaged([]const u8) = .{},
gcc_detector: GCCDetector = .{},

pub fn discover(self: *Linux, tc: *Toolchain) !void {
    self.distro = Distro.detect(tc.get_target(), tc.filesystem);
    try self.gcc_detector.discover(tc);
    tc.selected_multilib = self.gcc_detector.selected;

    try self.gcc_detector.append_tool_path(tc);
    try self.build_extra_opts(tc);
    try self.find_paths(tc);
}

fn build_extra_opts(self: *Linux, tc: *const Toolchain) !void {
    const gpa = tc.driver.comp.gpa;
    const target = tc.get_target();
    const is_android = target.is_android();
    if (self.distro.is_alpine() or is_android) {
        try self.extra_opts.ensure_unused_capacity(gpa, 2);
        self.extra_opts.append_assume_capacity("-z");
        self.extra_opts.append_assume_capacity("now");
    }

    if (self.distro.is_open_suse() or self.distro.is_ubuntu() or self.distro.is_alpine() or is_android) {
        try self.extra_opts.ensure_unused_capacity(gpa, 2);
        self.extra_opts.append_assume_capacity("-z");
        self.extra_opts.append_assume_capacity("relro");
    }

    if (target.cpu.arch.is_arm() or target.cpu.arch.is_aarch64() or is_android) {
        try self.extra_opts.ensure_unused_capacity(gpa, 2);
        self.extra_opts.append_assume_capacity("-z");
        self.extra_opts.append_assume_capacity("max-page-size=4096");
    }

    if (target.cpu.arch == .arm or target.cpu.arch == .thumb) {
        try self.extra_opts.append(gpa, "-X");
    }

    if (!target.cpu.arch.is_mips() and target.cpu.arch != .hexagon) {
        const hash_style = if (is_android) .both else self.distro.get_hash_style();
        try self.extra_opts.append(gpa, switch (hash_style) {
            inline else => |tag| "--hash-style=" ++ @tag_name(tag),
        });
    }

    if (system_defaults.enable_linker_build_id) {
        try self.extra_opts.append(gpa, "--build-id");
    }
}

fn add_multi_lib_paths(self: *Linux, tc: *Toolchain, sysroot: []const u8, os_lib_dir: []const u8) !void {
    if (!self.gcc_detector.is_valid) return;
    const gcc_triple = self.gcc_detector.gcc_triple;
    const lib_path = self.gcc_detector.parent_lib_path;

    // Add lib/gcc/$triple/$version, with an optional /multilib suffix.
    try tc.add_path_if_exists(&.{ self.gcc_detector.install_path, tc.selected_multilib.gcc_suffix }, .file);

    // Add lib/gcc/$triple/$libdir
    // For GCC built with --enable-version-specific-runtime-libs.
    try tc.add_path_if_exists(&.{ self.gcc_detector.install_path, "..", os_lib_dir }, .file);

    try tc.add_path_if_exists(&.{ lib_path, "..", gcc_triple, "lib", "..", os_lib_dir, tc.selected_multilib.os_suffix }, .file);

    // If the GCC installation we found is inside of the sysroot, we want to
    // prefer libraries installed in the parent prefix of the GCC installation.
    // It is important to *not* use these paths when the GCC installation is
    // outside of the system root as that can pick up unintended libraries.
    // This usually happens when there is an external cross compiler on the
    // host system, and a more minimal sysroot available that is the target of
    // the cross. Note that GCC does include some of these directories in some
    // configurations but this seems somewhere between questionable and simply
    // a bug.
    if (mem.starts_with(u8, lib_path, sysroot)) {
        try tc.add_path_if_exists(&.{ lib_path, "..", os_lib_dir }, .file);
    }
}

fn add_multi_arch_paths(self: *Linux, tc: *Toolchain) !void {
    if (!self.gcc_detector.is_valid) return;
    const lib_path = self.gcc_detector.parent_lib_path;
    const gcc_triple = self.gcc_detector.gcc_triple;
    const multilib = self.gcc_detector.selected;
    try tc.add_path_if_exists(&.{ lib_path, "..", gcc_triple, "lib", multilib.os_suffix }, .file);
}

/// TODO: Very incomplete
fn find_paths(self: *Linux, tc: *Toolchain) !void {
    const target = tc.get_target();
    const sysroot = tc.get_sysroot();

    var output: [64]u8 = undefined;

    const os_lib_dir = get_oslib_dir(target);
    const multiarch_triple = get_multiarch_triple(target) orelse target_util.to_llvmtriple(target, &output);

    try self.add_multi_lib_paths(tc, sysroot, os_lib_dir);

    try tc.add_path_if_exists(&.{ sysroot, "/lib", multiarch_triple }, .file);
    try tc.add_path_if_exists(&.{ sysroot, "/lib", "..", os_lib_dir }, .file);

    if (target.is_android()) {
        // TODO
    }
    try tc.add_path_if_exists(&.{ sysroot, "/usr", "lib", multiarch_triple }, .file);
    try tc.add_path_if_exists(&.{ sysroot, "/usr", "lib", "..", os_lib_dir }, .file);

    try self.add_multi_arch_paths(tc);

    try tc.add_path_if_exists(&.{ sysroot, "/lib" }, .file);
    try tc.add_path_if_exists(&.{ sysroot, "/usr", "lib" }, .file);
}

pub fn deinit(self: *Linux, allocator: std.mem.Allocator) void {
    self.extra_opts.deinit(allocator);
}

fn is_piedefault(self: *const Linux) bool {
    _ = self;
    return false;
}

fn get_pie(self: *const Linux, d: *const Driver) bool {
    if (d.shared or d.static or d.relocatable or d.static_pie) {
        return false;
    }
    return d.pie orelse self.is_piedefault();
}

fn get_static_pie(self: *const Linux, d: *Driver) !bool {
    _ = self;
    if (d.static_pie and d.pie != null) {
        try d.err("cannot specify 'nopie' along with 'static-pie'");
    }
    return d.static_pie;
}

fn get_static(self: *const Linux, d: *const Driver) bool {
    _ = self;
    return d.static and !d.static_pie;
}

pub fn get_default_linker(self: *const Linux, target: std.Target) []const u8 {
    _ = self;
    if (target.is_android()) {
        return "ld.lld";
    }
    return "ld";
}

pub fn build_linker_args(self: *const Linux, tc: *const Toolchain, argv: *std.ArrayList([]const u8)) Compilation.Error!void {
    const d = tc.driver;
    const target = tc.get_target();

    const is_pie = self.get_pie(d);
    const is_static_pie = try self.get_static_pie(d);
    const is_static = self.get_static(d);
    const is_android = target.is_android();
    const is_iamcu = target.os.tag == .elfiamcu;
    const is_ve = target.cpu.arch == .ve;
    const has_crt_begin_end_files = target.abi != .none; // TODO: clang checks for MIPS vendor

    if (is_pie) {
        try argv.append("-pie");
    }
    if (is_static_pie) {
        try argv.append_slice(&.{ "-static", "-pie", "--no-dynamic-linker", "-z", "text" });
    }

    if (d.rdynamic) {
        try argv.append("-export-dynamic");
    }

    if (d.strip) {
        try argv.append("-s");
    }

    try argv.append_slice(self.extra_opts.items);
    try argv.append("--eh-frame-hdr");

    // Todo: Driver should parse `-EL`/`-EB` for arm to set endianness for arm targets
    if (target_util.ld_emulation_option(d.comp.target, null)) |emulation| {
        try argv.append_slice(&.{ "-m", emulation });
    } else {
        try d.err("Unknown target triple");
        return;
    }
    if (d.comp.target.cpu.arch.is_riscv()) {
        try argv.append("-X");
    }
    if (d.shared) {
        try argv.append("-shared");
    }
    if (is_static) {
        try argv.append("-static");
    } else {
        if (d.rdynamic) {
            try argv.append("-export-dynamic");
        }
        if (!d.shared and !is_static_pie and !d.relocatable) {
            const dynamic_linker = d.comp.target.standard_dynamic_linker_path();
            // todo: check for --dyld-prefix
            if (dynamic_linker.get()) |path| {
                try argv.append_slice(&.{ "-dynamic-linker", try tc.arena.dupe(u8, path) });
            } else {
                try d.err("Could not find dynamic linker path");
            }
        }
    }

    try argv.append_slice(&.{ "-o", d.output_name orelse "a.out" });

    if (!d.nostdlib and !d.nostartfiles and !d.relocatable) {
        if (!is_android and !is_iamcu) {
            if (!d.shared) {
                const crt1 = if (is_pie)
                    "Scrt1.o"
                else if (is_static_pie)
                    "rcrt1.o"
                else
                    "crt1.o";
                try argv.append(try tc.get_file_path(crt1));
            }
            try argv.append(try tc.get_file_path("crti.o"));
        }
        if (is_ve) {
            try argv.append_slice(&.{ "-z", "max-page-size=0x4000000" });
        }

        if (is_iamcu) {
            try argv.append(try tc.get_file_path("crt0.o"));
        } else if (has_crt_begin_end_files) {
            var path: []const u8 = "";
            if (tc.get_runtime_lib_kind() == .compiler_rt and !is_android) {
                const crt_begin = try tc.get_compiler_rt("crtbegin", .object);
                if (tc.filesystem.exists(crt_begin)) {
                    path = crt_begin;
                }
            }
            if (path.len == 0) {
                const crt_begin = if (tc.driver.shared)
                    if (is_android) "crtbegin_so.o" else "crtbeginS.o"
                else if (is_static)
                    if (is_android) "crtbegin_static.o" else "crtbeginT.o"
                else if (is_pie or is_static_pie)
                    if (is_android) "crtbegin_dynamic.o" else "crtbeginS.o"
                else if (is_android) "crtbegin_dynamic.o" else "crtbegin.o";
                path = try tc.get_file_path(crt_begin);
            }
            try argv.append(path);
        }
    }

    // TODO add -L opts
    // TODO add -u opts

    try tc.add_file_path_lib_args(argv);

    // TODO handle LTO

    try argv.append_slice(d.link_objects.items);

    if (!d.nostdlib and !d.relocatable) {
        if (!d.nodefaultlibs) {
            if (is_static or is_static_pie) {
                try argv.append("--start-group");
            }
            try tc.add_runtime_libs(argv);

            // TODO: add pthread if needed
            if (!d.nolibc) {
                try argv.append("-lc");
            }
            if (is_iamcu) {
                try argv.append("-lgloss");
            }
            if (is_static or is_static_pie) {
                try argv.append("--end-group");
            } else {
                try tc.add_runtime_libs(argv);
            }
            if (is_iamcu) {
                try argv.append_slice(&.{ "--as-needed", "-lsoftfp", "--no-as-needed" });
            }
        }
        if (!d.nostartfiles and !is_iamcu) {
            if (has_crt_begin_end_files) {
                var path: []const u8 = "";
                if (tc.get_runtime_lib_kind() == .compiler_rt and !is_android) {
                    const crt_end = try tc.get_compiler_rt("crtend", .object);
                    if (tc.filesystem.exists(crt_end)) {
                        path = crt_end;
                    }
                }
                if (path.len == 0) {
                    const crt_end = if (d.shared)
                        if (is_android) "crtend_so.o" else "crtendS.o"
                    else if (is_pie or is_static_pie)
                        if (is_android) "crtend_android.o" else "crtendS.o"
                    else if (is_android) "crtend_android.o" else "crtend.o";
                    path = try tc.get_file_path(crt_end);
                }
                try argv.append(path);
            }
            if (!is_android) {
                try argv.append(try tc.get_file_path("crtn.o"));
            }
        }
    }

    // TODO add -T args
}

fn get_multiarch_triple(target: std.Target) ?[]const u8 {
    const is_android = target.is_android();
    const is_mips_r6 = std.Target.mips.feature_set_has(target.cpu.features, .mips32r6);
    return switch (target.cpu.arch) {
        .arm, .thumb => if (is_android) "arm-linux-androideabi" else if (target.abi == .gnueabihf) "arm-linux-gnueabihf" else "arm-linux-gnueabi",
        .armeb, .thumbeb => if (target.abi == .gnueabihf) "armeb-linux-gnueabihf" else "armeb-linux-gnueabi",
        .aarch64 => if (is_android) "aarch64-linux-android" else "aarch64-linux-gnu",
        .aarch64_be => "aarch64_be-linux-gnu",
        .x86 => if (is_android) "i686-linux-android" else "i386-linux-gnu",
        .x86_64 => if (is_android) "x86_64-linux-android" else if (target.abi == .gnux32) "x86_64-linux-gnux32" else "x86_64-linux-gnu",
        .m68k => "m68k-linux-gnu",
        .mips => if (is_mips_r6) "mipsisa32r6-linux-gnu" else "mips-linux-gnu",
        .mipsel => if (is_android) "mipsel-linux-android" else if (is_mips_r6) "mipsisa32r6el-linux-gnu" else "mipsel-linux-gnu",
        .powerpcle => "powerpcle-linux-gnu",
        .powerpc64 => "powerpc64-linux-gnu",
        .powerpc64le => "powerpc64le-linux-gnu",
        .riscv64 => "riscv64-linux-gnu",
        .sparc => "sparc-linux-gnu",
        .sparc64 => "sparc64-linux-gnu",
        .s390x => "s390x-linux-gnu",

        // TODO: expand this
        else => null,
    };
}

fn get_oslib_dir(target: std.Target) []const u8 {
    switch (target.cpu.arch) {
        .x86,
        .powerpc,
        .powerpcle,
        .sparc,
        .sparcel,
        => return "lib32",
        else => {},
    }
    if (target.cpu.arch == .x86_64 and (target.abi == .gnux32 or target.abi == .muslx32)) {
        return "libx32";
    }
    if (target.cpu.arch == .riscv32) {
        return "lib32";
    }
    if (target.ptr_bit_width() == 32) {
        return "lib";
    }
    return "lib64";
}

pub fn define_system_includes(self: *const Linux, tc: *const Toolchain) !void {
    if (tc.driver.nostdinc) return;

    const comp = tc.driver.comp;
    const target = tc.get_target();

    // musl prefers /usr/include before builtin includes, so musl targets will add builtins
    // at the end of this function (unless disabled with nostdlibinc)
    if (!tc.driver.nobuiltininc and (!target.is_musl() or tc.driver.nostdlibinc)) {
        try comp.add_builtin_include_dir(tc.driver.aro_name);
    }

    if (tc.driver.nostdlibinc) return;

    const sysroot = tc.get_sysroot();
    const local_include = try std.fmt.alloc_print(comp.gpa, "{s}{s}", .{ sysroot, "/usr/local/include" });
    defer comp.gpa.free(local_include);
    try comp.add_system_include_dir(local_include);

    if (self.gcc_detector.is_valid) {
        const gcc_include_path = try std.fs.path.join(comp.gpa, &.{ self.gcc_detector.parent_lib_path, "..", self.gcc_detector.gcc_triple, "include" });
        defer comp.gpa.free(gcc_include_path);
        try comp.add_system_include_dir(gcc_include_path);
    }

    if (get_multiarch_triple(target)) |triple| {
        const joined = try std.fs.path.join(comp.gpa, &.{ sysroot, "usr", "include", triple });
        defer comp.gpa.free(joined);
        if (tc.filesystem.exists(joined)) {
            try comp.add_system_include_dir(joined);
        }
    }

    if (target.os.tag == .rtems) return;

    try comp.add_system_include_dir("/include");
    try comp.add_system_include_dir("/usr/include");

    std.debug.assert(!tc.driver.nostdlibinc);
    if (!tc.driver.nobuiltininc and target.is_musl()) {
        try comp.add_builtin_include_dir(tc.driver.aro_name);
    }
}

test Linux {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;

    var arena_instance = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_instance.deinit();
    const arena = arena_instance.allocator();

    var comp = Compilation.init(std.testing.allocator);
    defer comp.deinit();
    comp.environment = .{
        .path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    };
    defer comp.environment = .{};

    const raw_triple = "x86_64-linux-gnu";
    const target_query = try std.Target.Query.parse(.{ .arch_os_abi = raw_triple });
    comp.target = try std.zig.system.resolve_target_query(target_query);
    comp.langopts.set_emulated_compiler(.gcc);

    var driver: Driver = .{ .comp = &comp };
    defer driver.deinit();
    driver.raw_target_triple = raw_triple;

    const link_obj = try driver.comp.gpa.dupe(u8, "/tmp/foo.o");
    try driver.link_objects.append(driver.comp.gpa, link_obj);
    driver.temp_file_count += 1;

    var toolchain: Toolchain = .{ .driver = &driver, .arena = arena, .filesystem = .{ .fake = &.{
        .{ .path = "/tmp" },
        .{ .path = "/usr" },
        .{ .path = "/usr/lib64" },
        .{ .path = "/usr/bin" },
        .{ .path = "/usr/bin/ld", .executable = true },
        .{ .path = "/lib" },
        .{ .path = "/lib/x86_64-linux-gnu" },
        .{ .path = "/lib/x86_64-linux-gnu/crt1.o" },
        .{ .path = "/lib/x86_64-linux-gnu/crti.o" },
        .{ .path = "/lib/x86_64-linux-gnu/crtn.o" },
        .{ .path = "/lib64" },
        .{ .path = "/usr/lib" },
        .{ .path = "/usr/lib/gcc" },
        .{ .path = "/usr/lib/gcc/x86_64-linux-gnu" },
        .{ .path = "/usr/lib/gcc/x86_64-linux-gnu/9" },
        .{ .path = "/usr/lib/gcc/x86_64-linux-gnu/9/crtbegin.o" },
        .{ .path = "/usr/lib/gcc/x86_64-linux-gnu/9/crtend.o" },
        .{ .path = "/usr/lib/x86_64-linux-gnu" },
        .{ .path = "/etc/lsb-release", .contents = 
        \\DISTRIB_ID=Ubuntu
        \\DISTRIB_RELEASE=20.04
        \\DISTRIB_CODENAME=focal
        \\DISTRIB_DESCRIPTION="Ubuntu 20.04.6 LTS"
        \\
        },
    } } };
    defer toolchain.deinit();

    try toolchain.discover();

    var argv = std.ArrayList([]const u8).init(driver.comp.gpa);
    defer argv.deinit();

    var linker_path_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    const linker_path = try toolchain.get_linker_path(&linker_path_buf);
    try argv.append(linker_path);

    try toolchain.build_linker_args(&argv);

    const expected = [_][]const u8{
        "/usr/bin/ld",
        "-z",
        "relro",
        "--hash-style=gnu",
        "--eh-frame-hdr",
        "-m",
        "elf_x86_64",
        "-dynamic-linker",
        "/lib64/ld-linux-x86-64.so.2",
        "-o",
        "a.out",
        "/lib/x86_64-linux-gnu/crt1.o",
        "/lib/x86_64-linux-gnu/crti.o",
        "/usr/lib/gcc/x86_64-linux-gnu/9/crtbegin.o",
        "-L/usr/lib/gcc/x86_64-linux-gnu/9",
        "-L/usr/lib/gcc/x86_64-linux-gnu/9/../../../../lib64",
        "-L/lib/x86_64-linux-gnu",
        "-L/lib/../lib64",
        "-L/usr/lib/x86_64-linux-gnu",
        "-L/usr/lib/../lib64",
        "-L/lib",
        "-L/usr/lib",
        link_obj,
        "-lgcc",
        "--as-needed",
        "-lgcc_s",
        "--no-as-needed",
        "-lc",
        "-lgcc",
        "--as-needed",
        "-lgcc_s",
        "--no-as-needed",
        "/usr/lib/gcc/x86_64-linux-gnu/9/crtend.o",
        "/lib/x86_64-linux-gnu/crtn.o",
    };
    try std.testing.expect_equal(expected.len, argv.items.len);
    for (expected, argv.items) |expected_item, actual_item| {
        try std.testing.expect_equal_strings(expected_item, actual_item);
    }
}
