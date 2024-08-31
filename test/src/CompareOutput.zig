//! This is the implementation of the test harness.
//! For the actual test cases, see test/compare_output.zig.

b: *std.Build,
step: *std.Build.Step,
test_index: usize,
test_filters: []const []const u8,
optimize_modes: []const OptimizeMode,

const Special = enum {
    None,
    Asm,
    RuntimeSafety,
};

const TestCase = struct {
    name: []const u8,
    sources: ArrayList(SourceFile),
    expected_output: []const u8,
    link_libc: bool,
    special: Special,
    cli_args: []const []const u8,

    const SourceFile = struct {
        filename: []const u8,
        source: []const u8,
    };

    pub fn add_source_file(self: *TestCase, filename: []const u8, source: []const u8) void {
        self.sources.append(SourceFile{
            .filename = filename,
            .source = source,
        }) catch @panic("OOM");
    }

    pub fn set_command_line_args(self: *TestCase, args: []const []const u8) void {
        self.cli_args = args;
    }
};

pub fn create_extra(self: *CompareOutput, name: []const u8, source: []const u8, expected_output: []const u8, special: Special) TestCase {
    var tc = TestCase{
        .name = name,
        .sources = ArrayList(TestCase.SourceFile).init(self.b.allocator),
        .expected_output = expected_output,
        .link_libc = false,
        .special = special,
        .cli_args = &[_][]const u8{},
    };
    const root_src_name = if (special == Special.Asm) "source.s" else "source.zig";
    tc.add_source_file(root_src_name, source);
    return tc;
}

pub fn create(self: *CompareOutput, name: []const u8, source: []const u8, expected_output: []const u8) TestCase {
    return create_extra(self, name, source, expected_output, Special.None);
}

pub fn add_c(self: *CompareOutput, name: []const u8, source: []const u8, expected_output: []const u8) void {
    var tc = self.create(name, source, expected_output);
    tc.link_libc = true;
    self.add_case(tc);
}

pub fn add(self: *CompareOutput, name: []const u8, source: []const u8, expected_output: []const u8) void {
    const tc = self.create(name, source, expected_output);
    self.add_case(tc);
}

pub fn add_asm(self: *CompareOutput, name: []const u8, source: []const u8, expected_output: []const u8) void {
    const tc = self.create_extra(name, source, expected_output, Special.Asm);
    self.add_case(tc);
}

pub fn add_runtime_safety(self: *CompareOutput, name: []const u8, source: []const u8) void {
    const tc = self.create_extra(name, source, undefined, Special.RuntimeSafety);
    self.add_case(tc);
}

pub fn add_case(self: *CompareOutput, case: TestCase) void {
    const b = self.b;

    const write_src = b.add_write_files();
    for (case.sources.items) |src_file| {
        _ = write_src.add(src_file.filename, src_file.source);
    }

    switch (case.special) {
        Special.Asm => {
            const annotated_case_name = fmt.alloc_print(self.b.allocator, "run assemble-and-link {s}", .{
                case.name,
            }) catch @panic("OOM");
            for (self.test_filters) |test_filter| {
                if (mem.index_of(u8, annotated_case_name, test_filter)) |_| break;
            } else if (self.test_filters.len > 0) return;

            const exe = b.add_executable(.{
                .name = "test",
                .target = b.host,
                .optimize = .Debug,
            });
            exe.add_assembly_file(write_src.files.items[0].get_path());

            const run = b.add_run_artifact(exe);
            run.set_name(annotated_case_name);
            run.add_args(case.cli_args);
            run.expect_std_out_equal(case.expected_output);

            self.step.depend_on(&run.step);
        },
        Special.None => {
            for (self.optimize_modes) |optimize| {
                const annotated_case_name = fmt.alloc_print(self.b.allocator, "run compare-output {s} ({s})", .{
                    case.name, @tag_name(optimize),
                }) catch @panic("OOM");
                for (self.test_filters) |test_filter| {
                    if (mem.index_of(u8, annotated_case_name, test_filter)) |_| break;
                } else if (self.test_filters.len > 0) return;

                const exe = b.add_executable(.{
                    .name = "test",
                    .root_source_file = write_src.files.items[0].get_path(),
                    .optimize = optimize,
                    .target = b.host,
                });
                if (case.link_libc) {
                    exe.link_system_library("c");
                }

                const run = b.add_run_artifact(exe);
                run.set_name(annotated_case_name);
                run.add_args(case.cli_args);
                run.expect_std_out_equal(case.expected_output);

                self.step.depend_on(&run.step);
            }
        },
        Special.RuntimeSafety => {
            // TODO iterate over self.optimize_modes and test this in both
            // debug and release safe mode
            const annotated_case_name = fmt.alloc_print(self.b.allocator, "run safety {s}", .{case.name}) catch @panic("OOM");
            for (self.test_filters) |test_filter| {
                if (mem.index_of(u8, annotated_case_name, test_filter)) |_| break;
            } else if (self.test_filters.len > 0) return;

            const exe = b.add_executable(.{
                .name = "test",
                .root_source_file = write_src.files.items[0].get_path(),
                .target = b.host,
                .optimize = .Debug,
            });
            if (case.link_libc) {
                exe.link_system_library("c");
            }

            const run = b.add_run_artifact(exe);
            run.set_name(annotated_case_name);
            run.add_args(case.cli_args);
            run.expect_exit_code(126);

            self.step.depend_on(&run.step);
        },
    }
}

const CompareOutput = @This();
const std = @import("std");
const ArrayList = std.ArrayList;
const fmt = std.fmt;
const mem = std.mem;
const fs = std.fs;
const OptimizeMode = std.builtin.OptimizeMode;
