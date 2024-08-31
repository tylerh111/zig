const std = @import("std");

pub fn build(b: *std.Build) void {
    const test_step = b.step("test", "Test it");
    b.default_step = test_step;

    const target = b.standard_target_options(.{});
    const optimize = b.standard_optimize_option(.{});

    const create_file_exe = b.add_executable(.{
        .name = "create_file",
        .root_source_file = b.path("create_file.zig"),
        .target = target,
        .optimize = optimize,
    });

    const create_first = b.add_run_artifact(create_file_exe);
    const first_dir = create_first.add_output_directory_arg("first");
    create_first.add_arg("hello1.txt");
    test_step.depend_on(&b.add_check_file(first_dir.path(b, "hello1.txt"), .{ .expected_matches = &.{
        std.fs.path.sep_str ++
            \\first
            \\hello1.txt
            \\Hello, world!
            \\
        ,
    } }).step);

    const create_second = b.add_run_artifact(create_file_exe);
    const second_dir = create_second.add_prefixed_output_directory_arg("--dir=", "second");
    create_second.add_arg("hello2.txt");
    test_step.depend_on(&b.add_check_file(second_dir.path(b, "hello2.txt"), .{ .expected_matches = &.{
        std.fs.path.sep_str ++
            \\second
            \\hello2.txt
            \\Hello, world!
            \\
        ,
    } }).step);
}
