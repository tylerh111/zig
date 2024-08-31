const std = @import("std");

pub fn build(b: *std.Build) void {
    const main = b.add_test(.{
        .root_source_file = b.path("src/main.zig"),
        .target = b.host,
        .optimize = .Debug,
    });

    const options = b.add_options();
    main.add_options("build_options", options);
    options.add_option(bool, "bool_true", b.option(bool, "bool_true", "t").?);
    options.add_option(bool, "bool_false", b.option(bool, "bool_false", "f").?);
    options.add_option(u32, "int", b.option(u32, "int", "i").?);
    const E = enum { one, two, three };
    options.add_option(E, "e", b.option(E, "e", "e").?);
    options.add_option([]const u8, "string", b.option([]const u8, "string", "s").?);

    const test_step = b.step("test", "Run unit tests");
    test_step.depend_on(&b.add_run_artifact(main).step);
}
