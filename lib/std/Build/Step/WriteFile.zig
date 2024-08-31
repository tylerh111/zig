//! WriteFile is primarily used to create a directory in an appropriate
//! location inside the local cache which has a set of files that have either
//! been generated during the build, or are copied from the source package.
//!
//! However, this step has an additional capability of writing data to paths
//! relative to the package root, effectively mutating the package's source
//! files. Be careful with the latter functionality; it should not be used
//! during the normal build process, but as a utility run by a developer with
//! intention to update source files, which will then be committed to version
//! control.
const std = @import("std");
const Step = std.Build.Step;
const fs = std.fs;
const ArrayList = std.ArrayList;
const WriteFile = @This();

step: Step,

// The elements here are pointers because we need stable pointers for the GeneratedFile field.
files: std.ArrayListUnmanaged(*File),
directories: std.ArrayListUnmanaged(*Directory),

output_source_files: std.ArrayListUnmanaged(OutputSourceFile),
generated_directory: std.Build.GeneratedFile,

pub const base_id: Step.Id = .write_file;

pub const File = struct {
    generated_file: std.Build.GeneratedFile,
    sub_path: []const u8,
    contents: Contents,

    pub fn get_path(file: *File) std.Build.LazyPath {
        return .{ .generated = .{ .file = &file.generated_file } };
    }
};

pub const Directory = struct {
    source: std.Build.LazyPath,
    sub_path: []const u8,
    options: Options,
    generated_dir: std.Build.GeneratedFile,

    pub const Options = struct {
        /// File paths that end in any of these suffixes will be excluded from copying.
        exclude_extensions: []const []const u8 = &.{},
        /// Only file paths that end in any of these suffixes will be included in copying.
        /// `null` means that all suffixes will be included.
        /// `exclude_extensions` takes precedence over `include_extensions`.
        include_extensions: ?[]const []const u8 = null,

        pub fn dupe(opts: Options, b: *std.Build) Options {
            return .{
                .exclude_extensions = b.dupe_strings(opts.exclude_extensions),
                .include_extensions = if (opts.include_extensions) |incs| b.dupe_strings(incs) else null,
            };
        }
    };

    pub fn get_path(dir: *Directory) std.Build.LazyPath {
        return .{ .generated = .{ .file = &dir.generated_dir } };
    }
};

pub const OutputSourceFile = struct {
    contents: Contents,
    sub_path: []const u8,
};

pub const Contents = union(enum) {
    bytes: []const u8,
    copy: std.Build.LazyPath,
};

pub fn create(owner: *std.Build) *WriteFile {
    const write_file = owner.allocator.create(WriteFile) catch @panic("OOM");
    write_file.* = .{
        .step = Step.init(.{
            .id = base_id,
            .name = "WriteFile",
            .owner = owner,
            .makeFn = make,
        }),
        .files = .{},
        .directories = .{},
        .output_source_files = .{},
        .generated_directory = .{ .step = &write_file.step },
    };
    return write_file;
}

pub fn add(write_file: *WriteFile, sub_path: []const u8, bytes: []const u8) std.Build.LazyPath {
    const b = write_file.step.owner;
    const gpa = b.allocator;
    const file = gpa.create(File) catch @panic("OOM");
    file.* = .{
        .generated_file = .{ .step = &write_file.step },
        .sub_path = b.dupe_path(sub_path),
        .contents = .{ .bytes = b.dupe(bytes) },
    };
    write_file.files.append(gpa, file) catch @panic("OOM");
    write_file.maybe_update_name();
    return file.get_path();
}

/// Place the file into the generated directory within the local cache,
/// along with all the rest of the files added to this step. The parameter
/// here is the destination path relative to the local cache directory
/// associated with this WriteFile. It may be a basename, or it may
/// include sub-directories, in which case this step will ensure the
/// required sub-path exists.
/// This is the option expected to be used most commonly with `add_copy_file`.
pub fn add_copy_file(write_file: *WriteFile, source: std.Build.LazyPath, sub_path: []const u8) std.Build.LazyPath {
    const b = write_file.step.owner;
    const gpa = b.allocator;
    const file = gpa.create(File) catch @panic("OOM");
    file.* = .{
        .generated_file = .{ .step = &write_file.step },
        .sub_path = b.dupe_path(sub_path),
        .contents = .{ .copy = source },
    };
    write_file.files.append(gpa, file) catch @panic("OOM");

    write_file.maybe_update_name();
    source.add_step_dependencies(&write_file.step);
    return file.get_path();
}

/// Copy files matching the specified exclude/include patterns to the specified subdirectory
/// relative to this step's generated directory.
/// The returned value is a lazy path to the generated subdirectory.
pub fn add_copy_directory(
    write_file: *WriteFile,
    source: std.Build.LazyPath,
    sub_path: []const u8,
    options: Directory.Options,
) std.Build.LazyPath {
    const b = write_file.step.owner;
    const gpa = b.allocator;
    const dir = gpa.create(Directory) catch @panic("OOM");
    dir.* = .{
        .source = source.dupe(b),
        .sub_path = b.dupe_path(sub_path),
        .options = options.dupe(b),
        .generated_dir = .{ .step = &write_file.step },
    };
    write_file.directories.append(gpa, dir) catch @panic("OOM");

    write_file.maybe_update_name();
    source.add_step_dependencies(&write_file.step);
    return dir.get_path();
}

/// A path relative to the package root.
/// Be careful with this because it updates source files. This should not be
/// used as part of the normal build process, but as a utility occasionally
/// run by a developer with intent to modify source files and then commit
/// those changes to version control.
pub fn add_copy_file_to_source(write_file: *WriteFile, source: std.Build.LazyPath, sub_path: []const u8) void {
    const b = write_file.step.owner;
    write_file.output_source_files.append(b.allocator, .{
        .contents = .{ .copy = source },
        .sub_path = sub_path,
    }) catch @panic("OOM");
    source.add_step_dependencies(&write_file.step);
}

/// A path relative to the package root.
/// Be careful with this because it updates source files. This should not be
/// used as part of the normal build process, but as a utility occasionally
/// run by a developer with intent to modify source files and then commit
/// those changes to version control.
pub fn add_bytes_to_source(write_file: *WriteFile, bytes: []const u8, sub_path: []const u8) void {
    const b = write_file.step.owner;
    write_file.output_source_files.append(b.allocator, .{
        .contents = .{ .bytes = bytes },
        .sub_path = sub_path,
    }) catch @panic("OOM");
}

/// Returns a `LazyPath` representing the base directory that contains all the
/// files from this `WriteFile`.
pub fn get_directory(write_file: *WriteFile) std.Build.LazyPath {
    return .{ .generated = .{ .file = &write_file.generated_directory } };
}

fn maybe_update_name(write_file: *WriteFile) void {
    if (write_file.files.items.len == 1 and write_file.directories.items.len == 0) {
        // First time adding a file; update name.
        if (std.mem.eql(u8, write_file.step.name, "WriteFile")) {
            write_file.step.name = write_file.step.owner.fmt("WriteFile {s}", .{write_file.files.items[0].sub_path});
        }
    } else if (write_file.directories.items.len == 1 and write_file.files.items.len == 0) {
        // First time adding a directory; update name.
        if (std.mem.eql(u8, write_file.step.name, "WriteFile")) {
            write_file.step.name = write_file.step.owner.fmt("WriteFile {s}", .{write_file.directories.items[0].sub_path});
        }
    }
}

fn make(step: *Step, prog_node: std.Progress.Node) !void {
    _ = prog_node;
    const b = step.owner;
    const write_file: *WriteFile = @fieldParentPtr("step", step);

    // Writing to source files is kind of an extra capability of this
    // WriteFile - arguably it should be a different step. But anyway here
    // it is, it happens unconditionally and does not interact with the other
    // files here.
    var any_miss = false;
    for (write_file.output_source_files.items) |output_source_file| {
        if (fs.path.dirname(output_source_file.sub_path)) |dirname| {
            b.build_root.handle.make_path(dirname) catch |err| {
                return step.fail("unable to make path '{}{s}': {s}", .{
                    b.build_root, dirname, @errorName(err),
                });
            };
        }
        switch (output_source_file.contents) {
            .bytes => |bytes| {
                b.build_root.handle.write_file(.{ .sub_path = output_source_file.sub_path, .data = bytes }) catch |err| {
                    return step.fail("unable to write file '{}{s}': {s}", .{
                        b.build_root, output_source_file.sub_path, @errorName(err),
                    });
                };
                any_miss = true;
            },
            .copy => |file_source| {
                const source_path = file_source.get_path2(b, step);
                const prev_status = fs.Dir.update_file(
                    fs.cwd(),
                    source_path,
                    b.build_root.handle,
                    output_source_file.sub_path,
                    .{},
                ) catch |err| {
                    return step.fail("unable to update file from '{s}' to '{}{s}': {s}", .{
                        source_path, b.build_root, output_source_file.sub_path, @errorName(err),
                    });
                };
                any_miss = any_miss or prev_status == .stale;
            },
        }
    }

    // The cache is used here not really as a way to speed things up - because writing
    // the data to a file would probably be very fast - but as a way to find a canonical
    // location to put build artifacts.

    // If, for example, a hard-coded path was used as the location to put WriteFile
    // files, then two WriteFiles executing in parallel might clobber each other.

    var man = b.graph.cache.obtain();
    defer man.deinit();

    // Random bytes to make WriteFile unique. Refresh this with
    // new random bytes when WriteFile implementation is modified
    // in a non-backwards-compatible way.
    man.hash.add(@as(u32, 0xd767ee59));

    for (write_file.files.items) |file| {
        man.hash.add_bytes(file.sub_path);
        switch (file.contents) {
            .bytes => |bytes| {
                man.hash.add_bytes(bytes);
            },
            .copy => |file_source| {
                _ = try man.add_file(file_source.get_path2(b, step), null);
            },
        }
    }
    for (write_file.directories.items) |dir| {
        man.hash.add_bytes(dir.source.get_path2(b, step));
        man.hash.add_bytes(dir.sub_path);
        for (dir.options.exclude_extensions) |ext| man.hash.add_bytes(ext);
        if (dir.options.include_extensions) |incs| for (incs) |inc| man.hash.add_bytes(inc);
    }

    if (try step.cache_hit(&man)) {
        const digest = man.final();
        for (write_file.files.items) |file| {
            file.generated_file.path = try b.cache_root.join(b.allocator, &.{
                "o", &digest, file.sub_path,
            });
        }
        write_file.generated_directory.path = try b.cache_root.join(b.allocator, &.{ "o", &digest });
        return;
    }

    const digest = man.final();
    const cache_path = "o" ++ fs.path.sep_str ++ digest;

    write_file.generated_directory.path = try b.cache_root.join(b.allocator, &.{ "o", &digest });

    var cache_dir = b.cache_root.handle.make_open_path(cache_path, .{}) catch |err| {
        return step.fail("unable to make path '{}{s}': {s}", .{
            b.cache_root, cache_path, @errorName(err),
        });
    };
    defer cache_dir.close();

    const cwd = fs.cwd();

    for (write_file.files.items) |file| {
        if (fs.path.dirname(file.sub_path)) |dirname| {
            cache_dir.make_path(dirname) catch |err| {
                return step.fail("unable to make path '{}{s}{c}{s}': {s}", .{
                    b.cache_root, cache_path, fs.path.sep, dirname, @errorName(err),
                });
            };
        }
        switch (file.contents) {
            .bytes => |bytes| {
                cache_dir.write_file(.{ .sub_path = file.sub_path, .data = bytes }) catch |err| {
                    return step.fail("unable to write file '{}{s}{c}{s}': {s}", .{
                        b.cache_root, cache_path, fs.path.sep, file.sub_path, @errorName(err),
                    });
                };
            },
            .copy => |file_source| {
                const source_path = file_source.get_path2(b, step);
                const prev_status = fs.Dir.update_file(
                    cwd,
                    source_path,
                    cache_dir,
                    file.sub_path,
                    .{},
                ) catch |err| {
                    return step.fail("unable to update file from '{s}' to '{}{s}{c}{s}': {s}", .{
                        source_path,
                        b.cache_root,
                        cache_path,
                        fs.path.sep,
                        file.sub_path,
                        @errorName(err),
                    });
                };
                // At this point we already will mark the step as a cache miss.
                // But this is kind of a partial cache hit since individual
                // file copies may be avoided. Oh well, this information is
                // discarded.
                _ = prev_status;
            },
        }

        file.generated_file.path = try b.cache_root.join(b.allocator, &.{
            cache_path, file.sub_path,
        });
    }
    for (write_file.directories.items) |dir| {
        const full_src_dir_path = dir.source.get_path2(b, step);
        const dest_dirname = dir.sub_path;

        if (dest_dirname.len != 0) {
            cache_dir.make_path(dest_dirname) catch |err| {
                return step.fail("unable to make path '{}{s}{c}{s}': {s}", .{
                    b.cache_root, cache_path, fs.path.sep, dest_dirname, @errorName(err),
                });
            };
        }

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
            const dest_path = b.path_join(&.{ dest_dirname, entry.path });
            switch (entry.kind) {
                .directory => try cache_dir.make_path(dest_path),
                .file => {
                    const prev_status = fs.Dir.update_file(
                        cwd,
                        full_src_entry_path,
                        cache_dir,
                        dest_path,
                        .{},
                    ) catch |err| {
                        return step.fail("unable to update file from '{s}' to '{}{s}{c}{s}': {s}", .{
                            full_src_entry_path,
                            b.cache_root,
                            cache_path,
                            fs.path.sep,
                            dest_path,
                            @errorName(err),
                        });
                    };
                    _ = prev_status;
                },
                else => continue,
            }
        }
    }

    try step.write_manifest(&man);
}
