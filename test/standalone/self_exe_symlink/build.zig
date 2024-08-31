const std = @import("std");

pub const requires_symlinks = true;

pub fn build(b: *std.Build) void {
    const test_step = b.step("test", "Test it");
    b.default_step = test_step;

    const optimize: std.builtin.OptimizeMode = .Debug;
    const target = b.host;

    // The test requires get_fd_path in order to to get the path of the
    // File returned by open_self_exe
    if (!std.os.is_get_fd_path_supported_on_target(target.result.os)) return;

    const main = b.add_executable(.{
        .name = "main",
        .root_source_file = b.path("main.zig"),
        .optimize = optimize,
        .target = target,
    });

    const create_symlink_exe = b.add_executable(.{
        .name = "create-symlink",
        .root_source_file = b.path("create-symlink.zig"),
        .optimize = optimize,
        .target = target,
    });

    var run_create_symlink = b.add_run_artifact(create_symlink_exe);
    run_create_symlink.add_artifact_arg(main);
    const symlink_path = run_create_symlink.add_output_file_arg("main-symlink");
    run_create_symlink.expect_exit_code(0);
    run_create_symlink.skip_foreign_checks = true;

    var run_from_symlink = std.Build.Step.Run.create(b, "run symlink");
    run_from_symlink.add_file_arg(symlink_path);
    run_from_symlink.expect_exit_code(0);
    run_from_symlink.skip_foreign_checks = true;
    run_from_symlink.step.depend_on(&run_create_symlink.step);

    test_step.depend_on(&run_from_symlink.step);
}
