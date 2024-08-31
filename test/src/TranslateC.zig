b: *std.Build,
step: *std.Build.Step,
test_index: usize,
test_filters: []const []const u8,

const TestCase = struct {
    name: []const u8,
    sources: ArrayList(SourceFile),
    expected_lines: ArrayList([]const u8),
    allow_warnings: bool,
    target: std.Target.Query = .{},

    const SourceFile = struct {
        filename: []const u8,
        source: []const u8,
    };

    pub fn add_source_file(self: *TestCase, filename: []const u8, source: []const u8) void {
        self.sources.append(SourceFile{
            .filename = filename,
            .source = source,
        }) catch unreachable;
    }

    pub fn add_expected_line(self: *TestCase, text: []const u8) void {
        self.expected_lines.append(text) catch unreachable;
    }
};

pub fn create(
    self: *TranslateCContext,
    allow_warnings: bool,
    filename: []const u8,
    name: []const u8,
    source: []const u8,
    expected_lines: []const []const u8,
) *TestCase {
    const tc = self.b.allocator.create(TestCase) catch unreachable;
    tc.* = TestCase{
        .name = name,
        .sources = ArrayList(TestCase.SourceFile).init(self.b.allocator),
        .expected_lines = ArrayList([]const u8).init(self.b.allocator),
        .allow_warnings = allow_warnings,
    };

    tc.add_source_file(filename, source);
    var arg_i: usize = 0;
    while (arg_i < expected_lines.len) : (arg_i += 1) {
        tc.add_expected_line(expected_lines[arg_i]);
    }
    return tc;
}

pub fn add(
    self: *TranslateCContext,
    name: []const u8,
    source: []const u8,
    expected_lines: []const []const u8,
) void {
    const tc = self.create(false, "source.h", name, source, expected_lines);
    self.add_case(tc);
}

pub fn add_with_target(
    self: *TranslateCContext,
    name: []const u8,
    target: std.Target.Query,
    source: []const u8,
    expected_lines: []const []const u8,
) void {
    const tc = self.create(false, "source.h", name, source, expected_lines);
    tc.target = target;
    self.add_case(tc);
}

pub fn add_allow_warnings(
    self: *TranslateCContext,
    name: []const u8,
    source: []const u8,
    expected_lines: []const []const u8,
) void {
    const tc = self.create(true, "source.h", name, source, expected_lines);
    self.add_case(tc);
}

pub fn add_case(self: *TranslateCContext, case: *const TestCase) void {
    const b = self.b;

    const translate_c_cmd = "translate-c";
    const annotated_case_name = fmt.alloc_print(self.b.allocator, "{s} {s}", .{ translate_c_cmd, case.name }) catch unreachable;
    for (self.test_filters) |test_filter| {
        if (mem.index_of(u8, annotated_case_name, test_filter)) |_| break;
    } else if (self.test_filters.len > 0) return;

    const write_src = b.add_write_files();
    for (case.sources.items) |src_file| {
        _ = write_src.add(src_file.filename, src_file.source);
    }

    const translate_c = b.add_translate_c(.{
        .root_source_file = write_src.files.items[0].get_path(),
        .target = b.resolve_target_query(case.target),
        .optimize = .Debug,
    });

    translate_c.step.name = annotated_case_name;

    const check_file = translate_c.add_check_file(case.expected_lines.items);

    self.step.depend_on(&check_file.step);
}

const TranslateCContext = @This();
const std = @import("std");
const ArrayList = std.ArrayList;
const fmt = std.fmt;
const mem = std.mem;
const fs = std.fs;
