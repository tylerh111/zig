const std = @import("std");
const Step = std.Build.Step;
const InstallDir = std.Build.InstallDir;
const InstallArtifact = @This();
const fs = std.fs;
const LazyPath = std.Build.LazyPath;

step: Step,

dest_dir: ?InstallDir,
dest_sub_path: []const u8,
emitted_bin: ?LazyPath,

implib_dir: ?InstallDir,
emitted_implib: ?LazyPath,

pdb_dir: ?InstallDir,
emitted_pdb: ?LazyPath,

h_dir: ?InstallDir,
emitted_h: ?LazyPath,

dylib_symlinks: ?DylibSymlinkInfo,

artifact: *Step.Compile,

const DylibSymlinkInfo = struct {
    major_only_filename: []const u8,
    name_only_filename: []const u8,
};

pub const base_id: Step.Id = .install_artifact;

pub const Options = struct {
    /// Which installation directory to put the main output file into.
    dest_dir: Dir = .default,
    pdb_dir: Dir = .default,
    h_dir: Dir = .default,
    implib_dir: Dir = .default,

    /// Whether to install symlinks along with dynamic libraries.
    dylib_symlinks: ?bool = null,
    /// If non-null, adds additional path components relative to bin dir, and
    /// overrides the basename of the Compile step for installation purposes.
    dest_sub_path: ?[]const u8 = null,

    pub const Dir = union(enum) {
        disabled,
        default,
        override: InstallDir,
    };
};

pub fn create(owner: *std.Build, artifact: *Step.Compile, options: Options) *InstallArtifact {
    const install_artifact = owner.allocator.create(InstallArtifact) catch @panic("OOM");
    const dest_dir: ?InstallDir = switch (options.dest_dir) {
        .disabled => null,
        .default => switch (artifact.kind) {
            .obj => @panic("object files have no standard installation procedure"),
            .exe, .@"test" => .bin,
            .lib => if (artifact.is_dll()) .bin else .lib,
        },
        .override => |o| o,
    };
    install_artifact.* = .{
        .step = Step.init(.{
            .id = base_id,
            .name = owner.fmt("install {s}", .{artifact.name}),
            .owner = owner,
            .makeFn = make,
        }),
        .dest_dir = dest_dir,
        .pdb_dir = switch (options.pdb_dir) {
            .disabled => null,
            .default => if (artifact.produces_pdb_file()) dest_dir else null,
            .override => |o| o,
        },
        .h_dir = switch (options.h_dir) {
            .disabled => null,
            .default => if (artifact.kind == .lib) .header else null,
            .override => |o| o,
        },
        .implib_dir = switch (options.implib_dir) {
            .disabled => null,
            .default => if (artifact.produces_implib()) .lib else null,
            .override => |o| o,
        },

        .dylib_symlinks = if (options.dylib_symlinks orelse (dest_dir != null and
            artifact.is_dynamic_library() and
            artifact.version != null and
            std.Build.want_shared_lib_sym_links(artifact.root_module_target()))) .{
            .major_only_filename = artifact.major_only_filename.?,
            .name_only_filename = artifact.name_only_filename.?,
        } else null,

        .dest_sub_path = options.dest_sub_path orelse artifact.out_filename,

        .emitted_bin = null,
        .emitted_pdb = null,
        .emitted_h = null,
        .emitted_implib = null,

        .artifact = artifact,
    };

    install_artifact.step.depend_on(&artifact.step);

    if (install_artifact.dest_dir != null) install_artifact.emitted_bin = artifact.get_emitted_bin();
    if (install_artifact.pdb_dir != null) install_artifact.emitted_pdb = artifact.get_emitted_pdb();
    // https://github.com/ziglang/zig/issues/9698
    //if (install_artifact.h_dir != null) install_artifact.emitted_h = artifact.get_emitted_h();
    if (install_artifact.implib_dir != null) install_artifact.emitted_implib = artifact.get_emitted_implib();

    return install_artifact;
}

fn make(step: *Step, prog_node: std.Progress.Node) !void {
    _ = prog_node;
    const install_artifact: *InstallArtifact = @fieldParentPtr("step", step);
    const b = step.owner;
    const cwd = fs.cwd();

    var all_cached = true;

    if (install_artifact.dest_dir) |dest_dir| {
        const full_dest_path = b.get_install_path(dest_dir, install_artifact.dest_sub_path);
        const full_src_path = install_artifact.emitted_bin.?.get_path2(b, step);
        const p = fs.Dir.update_file(cwd, full_src_path, cwd, full_dest_path, .{}) catch |err| {
            return step.fail("unable to update file from '{s}' to '{s}': {s}", .{
                full_src_path, full_dest_path, @errorName(err),
            });
        };
        all_cached = all_cached and p == .fresh;

        if (install_artifact.dylib_symlinks) |dls| {
            try Step.Compile.do_atomic_sym_links(step, full_dest_path, dls.major_only_filename, dls.name_only_filename);
        }

        install_artifact.artifact.installed_path = full_dest_path;
    }

    if (install_artifact.implib_dir) |implib_dir| {
        const full_src_path = install_artifact.emitted_implib.?.get_path2(b, step);
        const full_implib_path = b.get_install_path(implib_dir, fs.path.basename(full_src_path));
        const p = fs.Dir.update_file(cwd, full_src_path, cwd, full_implib_path, .{}) catch |err| {
            return step.fail("unable to update file from '{s}' to '{s}': {s}", .{
                full_src_path, full_implib_path, @errorName(err),
            });
        };
        all_cached = all_cached and p == .fresh;
    }

    if (install_artifact.pdb_dir) |pdb_dir| {
        const full_src_path = install_artifact.emitted_pdb.?.get_path2(b, step);
        const full_pdb_path = b.get_install_path(pdb_dir, fs.path.basename(full_src_path));
        const p = fs.Dir.update_file(cwd, full_src_path, cwd, full_pdb_path, .{}) catch |err| {
            return step.fail("unable to update file from '{s}' to '{s}': {s}", .{
                full_src_path, full_pdb_path, @errorName(err),
            });
        };
        all_cached = all_cached and p == .fresh;
    }

    if (install_artifact.h_dir) |h_dir| {
        if (install_artifact.emitted_h) |emitted_h| {
            const full_src_path = emitted_h.get_path2(b, step);
            const full_h_path = b.get_install_path(h_dir, fs.path.basename(full_src_path));
            const p = fs.Dir.update_file(cwd, full_src_path, cwd, full_h_path, .{}) catch |err| {
                return step.fail("unable to update file from '{s}' to '{s}': {s}", .{
                    full_src_path, full_h_path, @errorName(err),
                });
            };
            all_cached = all_cached and p == .fresh;
        }

        for (install_artifact.artifact.installed_headers.items) |installation| switch (installation) {
            .file => |file| {
                const full_src_path = file.source.get_path2(b, step);
                const full_h_path = b.get_install_path(h_dir, file.dest_rel_path);
                const p = fs.Dir.update_file(cwd, full_src_path, cwd, full_h_path, .{}) catch |err| {
                    return step.fail("unable to update file from '{s}' to '{s}': {s}", .{
                        full_src_path, full_h_path, @errorName(err),
                    });
                };
                all_cached = all_cached and p == .fresh;
            },
            .directory => |dir| {
                const full_src_dir_path = dir.source.get_path2(b, step);
                const full_h_prefix = b.get_install_path(h_dir, dir.dest_rel_path);

                var src_dir = b.build_root.handle.open_dir(full_src_dir_path, .{ .iterate = true }) catch |err| {
                    return step.fail("unable to open source directory '{s}': {s}", .{
                        full_src_dir_path, @errorName(err),
                    });
                };
                defer src_dir.close();

                var it = try src_dir.walk(b.allocator);
                next_entry: while (try it.next()) |entry| {
                    for (dir.options.exclude_extensions) |ext| {
                        if (std.mem.ends_with(u8, entry.path, ext)) continue :next_entry;
                    }
                    if (dir.options.include_extensions) |incs| {
                        for (incs) |inc| {
                            if (std.mem.ends_with(u8, entry.path, inc)) break;
                        } else {
                            continue :next_entry;
                        }
                    }
                    const full_src_entry_path = b.path_join(&.{ full_src_dir_path, entry.path });
                    const full_dest_path = b.path_join(&.{ full_h_prefix, entry.path });
                    switch (entry.kind) {
                        .directory => try cwd.make_path(full_dest_path),
                        .file => {
                            const p = fs.Dir.update_file(cwd, full_src_entry_path, cwd, full_dest_path, .{}) catch |err| {
                                return step.fail("unable to update file from '{s}' to '{s}': {s}", .{
                                    full_src_entry_path, full_dest_path, @errorName(err),
                                });
                            };
                            all_cached = all_cached and p == .fresh;
                        },
                        else => continue,
                    }
                }
            },
        };
    }

    step.result_cached = all_cached;
}
