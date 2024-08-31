b: *std.Build,
step: *Step,
test_index: usize,
test_filters: []const []const u8,
optimize_modes: []const OptimizeMode,
check_exe: *std.Build.Step.Compile,

const Config = struct {
    name: []const u8,
    source: []const u8,
    Debug: ?PerMode = null,
    ReleaseSmall: ?PerMode = null,
    ReleaseSafe: ?PerMode = null,
    ReleaseFast: ?PerMode = null,

    const PerMode = struct {
        expect: []const u8,
        exclude_os: []const std.Target.Os.Tag = &.{},
        error_tracing: ?bool = null,
    };
};

pub fn add_case(self: *StackTrace, config: Config) void {
    if (config.Debug) |per_mode|
        self.add_expect(config.name, config.source, .Debug, per_mode);

    if (config.ReleaseSmall) |per_mode|
        self.add_expect(config.name, config.source, .ReleaseSmall, per_mode);

    if (config.ReleaseFast) |per_mode|
        self.add_expect(config.name, config.source, .ReleaseFast, per_mode);

    if (config.ReleaseSafe) |per_mode|
        self.add_expect(config.name, config.source, .ReleaseSafe, per_mode);
}

fn add_expect(
    self: *StackTrace,
    name: []const u8,
    source: []const u8,
    optimize_mode: OptimizeMode,
    mode_config: Config.PerMode,
) void {
    for (mode_config.exclude_os) |tag| if (tag == builtin.os.tag) return;

    const b = self.b;
    const annotated_case_name = fmt.alloc_print(b.allocator, "check {s} ({s})", .{
        name, @tag_name(optimize_mode),
    }) catch @panic("OOM");
    for (self.test_filters) |test_filter| {
        if (mem.index_of(u8, annotated_case_name, test_filter)) |_| break;
    } else if (self.test_filters.len > 0) return;

    const write_src = b.add_write_file("source.zig", source);
    const exe = b.add_executable(.{
        .name = "test",
        .root_source_file = write_src.files.items[0].get_path(),
        .optimize = optimize_mode,
        .target = b.host,
        .error_tracing = mode_config.error_tracing,
    });

    const run = b.add_run_artifact(exe);
    run.remove_environment_variable("CLICOLOR_FORCE");
    run.set_environment_variable("NO_COLOR", "1");
    run.expect_exit_code(1);
    run.expect_std_out_equal("");

    const check_run = b.add_run_artifact(self.check_exe);
    check_run.set_name(annotated_case_name);
    check_run.add_file_arg(run.capture_std_err());
    check_run.add_args(&.{
        @tag_name(optimize_mode),
    });
    check_run.expect_std_out_equal(mode_config.expect);

    self.step.depend_on(&check_run.step);
}

const StackTrace = @This();
const std = @import("std");
const builtin = @import("builtin");
const Step = std.Build.Step;
const OptimizeMode = std.builtin.OptimizeMode;
const fmt = std.fmt;
const mem = std.mem;
