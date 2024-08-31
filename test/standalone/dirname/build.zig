const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standard_target_options(.{});

    const test_step = b.step("test", "Test it");
    b.default_step = test_step;

    const touch_src = b.path("touch.zig");

    const touch = b.add_executable(.{
        .name = "touch",
        .root_source_file = touch_src,
        .optimize = .Debug,
        .target = target,
    });
    const generated = b.add_run_artifact(touch).add_output_file_arg("subdir" ++ std.fs.path.sep_str ++ "generated.txt");

    const exists_in = b.add_executable(.{
        .name = "exists_in",
        .root_source_file = b.path("exists_in.zig"),
        .optimize = .Debug,
        .target = target,
    });

    const has_basename = b.add_executable(.{
        .name = "has_basename",
        .root_source_file = b.path("has_basename.zig"),
        .optimize = .Debug,
        .target = target,
    });

    // Known path:
    add_test_run(test_step, exists_in, touch_src.dirname(), &.{"touch.zig"});

    // Generated file:
    add_test_run(test_step, exists_in, generated.dirname(), &.{"generated.txt"});

    // Generated file multiple levels:
    add_test_run(test_step, exists_in, generated.dirname().dirname(), &.{
        "subdir" ++ std.fs.path.sep_str ++ "generated.txt",
    });

    // Cache root:
    const cache_dir = b.cache_root.path orelse
        (b.cache_root.join(b.allocator, &.{"."}) catch @panic("OOM"));
    add_test_run(
        test_step,
        has_basename,
        generated.dirname().dirname().dirname().dirname(),
        &.{std.fs.path.basename(cache_dir)},
    );

    // Absolute path:
    const abs_path = setup_abspath: {
        const temp_dir = b.make_temp_path();

        var dir = std.fs.cwd().open_dir(temp_dir, .{}) catch @panic("failed to open temp dir");
        defer dir.close();

        var file = dir.create_file("foo.txt", .{}) catch @panic("failed to create file");
        file.close();

        break :setup_abspath std.Build.LazyPath{ .cwd_relative = temp_dir };
    };
    add_test_run(test_step, exists_in, abs_path, &.{"foo.txt"});
}

// Runs exe with the parameters [dirname, args...].
// Expects the exit code to be 0.
fn add_test_run(
    test_step: *std.Build.Step,
    exe: *std.Build.Step.Compile,
    dirname: std.Build.LazyPath,
    args: []const []const u8,
) void {
    const run = test_step.owner.add_run_artifact(exe);
    run.add_directory_arg(dirname);
    run.add_args(args);
    run.expect_exit_code(0);
    test_step.depend_on(&run.step);
}
