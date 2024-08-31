//! This step has two modes:
//! * Modify mode: directly modify source files, formatting them in place.
//! * Check mode: fail the step if a non-conforming file is found.
const std = @import("std");
const Step = std.Build.Step;
const Fmt = @This();

step: Step,
paths: []const []const u8,
exclude_paths: []const []const u8,
check: bool,

pub const base_id: Step.Id = .fmt;

pub const Options = struct {
    paths: []const []const u8 = &.{},
    exclude_paths: []const []const u8 = &.{},
    /// If true, fails the build step when any non-conforming files are encountered.
    check: bool = false,
};

pub fn create(owner: *std.Build, options: Options) *Fmt {
    const fmt = owner.allocator.create(Fmt) catch @panic("OOM");
    const name = if (options.check) "zig fmt --check" else "zig fmt";
    fmt.* = .{
        .step = Step.init(.{
            .id = base_id,
            .name = name,
            .owner = owner,
            .makeFn = make,
        }),
        .paths = owner.dupe_strings(options.paths),
        .exclude_paths = owner.dupe_strings(options.exclude_paths),
        .check = options.check,
    };
    return fmt;
}

fn make(step: *Step, prog_node: std.Progress.Node) !void {
    // zig fmt is fast enough that no progress is needed.
    _ = prog_node;

    // TODO: if check=false, this means we are modifying source files in place, which
    // is an operation that could race against other operations also modifying source files
    // in place. In this case, this step should obtain a write lock while making those
    // modifications.

    const b = step.owner;
    const arena = b.allocator;
    const fmt: *Fmt = @fieldParentPtr("step", step);

    var argv: std.ArrayListUnmanaged([]const u8) = .{};
    try argv.ensure_unused_capacity(arena, 2 + 1 + fmt.paths.len + 2 * fmt.exclude_paths.len);

    argv.append_assume_capacity(b.graph.zig_exe);
    argv.append_assume_capacity("fmt");

    if (fmt.check) {
        argv.append_assume_capacity("--check");
    }

    for (fmt.paths) |p| {
        argv.append_assume_capacity(b.path_from_root(p));
    }

    for (fmt.exclude_paths) |p| {
        argv.append_assume_capacity("--exclude");
        argv.append_assume_capacity(b.path_from_root(p));
    }

    return step.eval_child_process(argv.items);
}
