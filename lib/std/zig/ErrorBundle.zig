//! To support incremental compilation, errors are stored in various places
//! so that they can be created and destroyed appropriately. This structure
//! is used to collect all the errors from the various places into one
//! convenient place for API users to consume.
//!
//! There is one special encoding for this data structure. If both arrays are
//! empty, it means there are no errors. This special encoding exists so that
//! heap allocation is not needed in the common case of no errors.

string_bytes: []const u8,
/// The first thing in this array is an `ErrorMessageList`.
extra: []const u32,

/// Special encoding when there are no errors.
pub const empty: ErrorBundle = .{
    .string_bytes = &.{},
    .extra = &.{},
};

// An index into `extra` pointing at an `ErrorMessage`.
pub const MessageIndex = enum(u32) {
    _,
};

// An index into `extra` pointing at an `SourceLocation`.
pub const SourceLocationIndex = enum(u32) {
    none = 0,
    _,
};

/// There will be a MessageIndex for each len at start.
pub const ErrorMessageList = struct {
    len: u32,
    start: u32,
    /// null-terminated string index. 0 means no compile log text.
    compile_log_text: u32,
};

/// Trailing:
/// * ReferenceTrace for each reference_trace_len
pub const SourceLocation = struct {
    /// null terminated string index
    src_path: u32,
    line: u32,
    column: u32,
    /// byte offset of starting token
    span_start: u32,
    /// byte offset of main error location
    span_main: u32,
    /// byte offset of end of last token
    span_end: u32,
    /// null terminated string index, possibly null.
    /// Does not include the trailing newline.
    source_line: u32 = 0,
    reference_trace_len: u32 = 0,
};

/// Trailing:
/// * MessageIndex for each notes_len.
pub const ErrorMessage = struct {
    /// null terminated string index
    msg: u32,
    /// Usually one, but incremented for redundant messages.
    count: u32 = 1,
    src_loc: SourceLocationIndex = .none,
    notes_len: u32 = 0,
};

pub const ReferenceTrace = struct {
    /// null terminated string index
    /// Except for the sentinel ReferenceTrace element, in which case:
    /// * 0 means remaining references hidden
    /// * >0 means N references hidden
    decl_name: u32,
    /// Index into extra of a SourceLocation
    /// If this is 0, this is the sentinel ReferenceTrace element.
    src_loc: SourceLocationIndex,
};

pub fn deinit(eb: *ErrorBundle, gpa: Allocator) void {
    gpa.free(eb.string_bytes);
    gpa.free(eb.extra);
    eb.* = undefined;
}

pub fn error_message_count(eb: ErrorBundle) u32 {
    if (eb.extra.len == 0) return 0;
    return eb.get_error_message_list().len;
}

pub fn get_error_message_list(eb: ErrorBundle) ErrorMessageList {
    return eb.extra_data(ErrorMessageList, 0).data;
}

pub fn get_messages(eb: ErrorBundle) []const MessageIndex {
    const list = eb.get_error_message_list();
    return @as([]const MessageIndex, @ptr_cast(eb.extra[list.start..][0..list.len]));
}

pub fn get_error_message(eb: ErrorBundle, index: MessageIndex) ErrorMessage {
    return eb.extra_data(ErrorMessage, @int_from_enum(index)).data;
}

pub fn get_source_location(eb: ErrorBundle, index: SourceLocationIndex) SourceLocation {
    assert(index != .none);
    return eb.extra_data(SourceLocation, @int_from_enum(index)).data;
}

pub fn get_notes(eb: ErrorBundle, index: MessageIndex) []const MessageIndex {
    const notes_len = eb.get_error_message(index).notes_len;
    const start = @int_from_enum(index) + @typeInfo(ErrorMessage).Struct.fields.len;
    return @as([]const MessageIndex, @ptr_cast(eb.extra[start..][0..notes_len]));
}

pub fn get_compile_log_output(eb: ErrorBundle) [:0]const u8 {
    return null_terminated_string(eb, get_error_message_list(eb).compile_log_text);
}

/// Returns the requested data, as well as the new index which is at the start of the
/// trailers for the object.
fn extra_data(eb: ErrorBundle, comptime T: type, index: usize) struct { data: T, end: usize } {
    const fields = @typeInfo(T).Struct.fields;
    var i: usize = index;
    var result: T = undefined;
    inline for (fields) |field| {
        @field(result, field.name) = switch (field.type) {
            u32 => eb.extra[i],
            MessageIndex => @as(MessageIndex, @enumFromInt(eb.extra[i])),
            SourceLocationIndex => @as(SourceLocationIndex, @enumFromInt(eb.extra[i])),
            else => @compile_error("bad field type"),
        };
        i += 1;
    }
    return .{
        .data = result,
        .end = i,
    };
}

/// Given an index into `string_bytes` returns the null-terminated string found there.
pub fn null_terminated_string(eb: ErrorBundle, index: usize) [:0]const u8 {
    const string_bytes = eb.string_bytes;
    var end: usize = index;
    while (string_bytes[end] != 0) {
        end += 1;
    }
    return string_bytes[index..end :0];
}

pub const RenderOptions = struct {
    ttyconf: std.io.tty.Config,
    include_reference_trace: bool = true,
    include_source_line: bool = true,
    include_log_text: bool = true,
};

pub fn render_to_std_err(eb: ErrorBundle, options: RenderOptions) void {
    std.debug.lock_std_err();
    defer std.debug.unlock_std_err();
    const stderr = std.io.get_std_err();
    return render_to_writer(eb, options, stderr.writer()) catch return;
}

pub fn render_to_writer(eb: ErrorBundle, options: RenderOptions, writer: anytype) anyerror!void {
    if (eb.extra.len == 0) return;
    for (eb.get_messages()) |err_msg| {
        try render_error_message_to_writer(eb, options, err_msg, writer, "error", .red, 0);
    }

    if (options.include_log_text) {
        const log_text = eb.get_compile_log_output();
        if (log_text.len != 0) {
            try writer.write_all("\nCompile Log Output:\n");
            try writer.write_all(log_text);
        }
    }
}

fn render_error_message_to_writer(
    eb: ErrorBundle,
    options: RenderOptions,
    err_msg_index: MessageIndex,
    stderr: anytype,
    kind: []const u8,
    color: std.io.tty.Color,
    indent: usize,
) anyerror!void {
    const ttyconf = options.ttyconf;
    var counting_writer = std.io.counting_writer(stderr);
    const counting_stderr = counting_writer.writer();
    const err_msg = eb.get_error_message(err_msg_index);
    if (err_msg.src_loc != .none) {
        const src = eb.extra_data(SourceLocation, @int_from_enum(err_msg.src_loc));
        try counting_stderr.write_byte_ntimes(' ', indent);
        try ttyconf.set_color(stderr, .bold);
        try counting_stderr.print("{s}:{d}:{d}: ", .{
            eb.null_terminated_string(src.data.src_path),
            src.data.line + 1,
            src.data.column + 1,
        });
        try ttyconf.set_color(stderr, color);
        try counting_stderr.write_all(kind);
        try counting_stderr.write_all(": ");
        // This is the length of the part before the error message:
        // e.g. "file.zig:4:5: error: "
        const prefix_len: usize = @int_cast(counting_stderr.context.bytes_written);
        try ttyconf.set_color(stderr, .reset);
        try ttyconf.set_color(stderr, .bold);
        if (err_msg.count == 1) {
            try write_msg(eb, err_msg, stderr, prefix_len);
            try stderr.write_byte('\n');
        } else {
            try write_msg(eb, err_msg, stderr, prefix_len);
            try ttyconf.set_color(stderr, .dim);
            try stderr.print(" ({d} times)\n", .{err_msg.count});
        }
        try ttyconf.set_color(stderr, .reset);
        if (src.data.source_line != 0 and options.include_source_line) {
            const line = eb.null_terminated_string(src.data.source_line);
            for (line) |b| switch (b) {
                '\t' => try stderr.write_byte(' '),
                else => try stderr.write_byte(b),
            };
            try stderr.write_byte('\n');
            // TODO basic unicode code point monospace width
            const before_caret = src.data.span_main - src.data.span_start;
            // -1 since span.main includes the caret
            const after_caret = src.data.span_end -| src.data.span_main -| 1;
            try stderr.write_byte_ntimes(' ', src.data.column - before_caret);
            try ttyconf.set_color(stderr, .green);
            try stderr.write_byte_ntimes('~', before_caret);
            try stderr.write_byte('^');
            try stderr.write_byte_ntimes('~', after_caret);
            try stderr.write_byte('\n');
            try ttyconf.set_color(stderr, .reset);
        }
        for (eb.get_notes(err_msg_index)) |note| {
            try render_error_message_to_writer(eb, options, note, stderr, "note", .cyan, indent);
        }
        if (src.data.reference_trace_len > 0 and options.include_reference_trace) {
            try ttyconf.set_color(stderr, .reset);
            try ttyconf.set_color(stderr, .dim);
            try stderr.print("referenced by:\n", .{});
            var ref_index = src.end;
            for (0..src.data.reference_trace_len) |_| {
                const ref_trace = eb.extra_data(ReferenceTrace, ref_index);
                ref_index = ref_trace.end;
                if (ref_trace.data.src_loc != .none) {
                    const ref_src = eb.get_source_location(ref_trace.data.src_loc);
                    try stderr.print("    {s}: {s}:{d}:{d}\n", .{
                        eb.null_terminated_string(ref_trace.data.decl_name),
                        eb.null_terminated_string(ref_src.src_path),
                        ref_src.line + 1,
                        ref_src.column + 1,
                    });
                } else if (ref_trace.data.decl_name != 0) {
                    const count = ref_trace.data.decl_name;
                    try stderr.print(
                        "    {d} reference(s) hidden; use '-freference-trace={d}' to see all references\n",
                        .{ count, count + src.data.reference_trace_len - 1 },
                    );
                } else {
                    try stderr.print(
                        "    remaining reference traces hidden; use '-freference-trace' to see all reference traces\n",
                        .{},
                    );
                }
            }
            try ttyconf.set_color(stderr, .reset);
        }
    } else {
        try ttyconf.set_color(stderr, color);
        try stderr.write_byte_ntimes(' ', indent);
        try stderr.write_all(kind);
        try stderr.write_all(": ");
        try ttyconf.set_color(stderr, .reset);
        const msg = eb.null_terminated_string(err_msg.msg);
        if (err_msg.count == 1) {
            try stderr.print("{s}\n", .{msg});
        } else {
            try stderr.print("{s}", .{msg});
            try ttyconf.set_color(stderr, .dim);
            try stderr.print(" ({d} times)\n", .{err_msg.count});
        }
        try ttyconf.set_color(stderr, .reset);
        for (eb.get_notes(err_msg_index)) |note| {
            try render_error_message_to_writer(eb, options, note, stderr, "note", .cyan, indent + 4);
        }
    }
}

/// Splits the error message up into lines to properly indent them
/// to allow for long, good-looking error messages.
///
/// This is used to split the message in `@compile_error("hello\nworld")` for example.
fn write_msg(eb: ErrorBundle, err_msg: ErrorMessage, stderr: anytype, indent: usize) !void {
    var lines = std.mem.split_scalar(u8, eb.null_terminated_string(err_msg.msg), '\n');
    while (lines.next()) |line| {
        try stderr.write_all(line);
        if (lines.index == null) break;
        try stderr.write_byte('\n');
        try stderr.write_byte_ntimes(' ', indent);
    }
}

const std = @import("std");
const ErrorBundle = @This();
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

pub const Wip = struct {
    gpa: Allocator,
    string_bytes: std.ArrayListUnmanaged(u8),
    /// The first thing in this array is a ErrorMessageList.
    extra: std.ArrayListUnmanaged(u32),
    root_list: std.ArrayListUnmanaged(MessageIndex),

    pub fn init(wip: *Wip, gpa: Allocator) !void {
        wip.* = .{
            .gpa = gpa,
            .string_bytes = .{},
            .extra = .{},
            .root_list = .{},
        };

        // So that 0 can be used to indicate a null string.
        try wip.string_bytes.append(gpa, 0);

        assert(0 == try add_extra(wip, ErrorMessageList{
            .len = 0,
            .start = 0,
            .compile_log_text = 0,
        }));
    }

    pub fn deinit(wip: *Wip) void {
        const gpa = wip.gpa;
        wip.root_list.deinit(gpa);
        wip.string_bytes.deinit(gpa);
        wip.extra.deinit(gpa);
        wip.* = undefined;
    }

    pub fn to_owned_bundle(wip: *Wip, compile_log_text: []const u8) !ErrorBundle {
        const gpa = wip.gpa;
        if (wip.root_list.items.len == 0) {
            assert(compile_log_text.len == 0);
            // Special encoding when there are no errors.
            wip.deinit();
            wip.* = .{
                .gpa = gpa,
                .string_bytes = .{},
                .extra = .{},
                .root_list = .{},
            };
            return empty;
        }

        const compile_log_str_index = if (compile_log_text.len == 0) 0 else str: {
            const str: u32 = @int_cast(wip.string_bytes.items.len);
            try wip.string_bytes.ensure_unused_capacity(gpa, compile_log_text.len + 1);
            wip.string_bytes.append_slice_assume_capacity(compile_log_text);
            wip.string_bytes.append_assume_capacity(0);
            break :str str;
        };

        wip.set_extra(0, ErrorMessageList{
            .len = @int_cast(wip.root_list.items.len),
            .start = @int_cast(wip.extra.items.len),
            .compile_log_text = compile_log_str_index,
        });
        try wip.extra.append_slice(gpa, @as([]const u32, @ptr_cast(wip.root_list.items)));
        wip.root_list.clear_and_free(gpa);
        return .{
            .string_bytes = try wip.string_bytes.to_owned_slice(gpa),
            .extra = try wip.extra.to_owned_slice(gpa),
        };
    }

    pub fn tmp_bundle(wip: Wip) ErrorBundle {
        return .{
            .string_bytes = wip.string_bytes.items,
            .extra = wip.extra.items,
        };
    }

    pub fn add_string(wip: *Wip, s: []const u8) Allocator.Error!u32 {
        const gpa = wip.gpa;
        const index: u32 = @int_cast(wip.string_bytes.items.len);
        try wip.string_bytes.ensure_unused_capacity(gpa, s.len + 1);
        wip.string_bytes.append_slice_assume_capacity(s);
        wip.string_bytes.append_assume_capacity(0);
        return index;
    }

    pub fn print_string(wip: *Wip, comptime fmt: []const u8, args: anytype) Allocator.Error!u32 {
        const gpa = wip.gpa;
        const index: u32 = @int_cast(wip.string_bytes.items.len);
        try wip.string_bytes.writer(gpa).print(fmt, args);
        try wip.string_bytes.append(gpa, 0);
        return index;
    }

    pub fn add_root_error_message(wip: *Wip, em: ErrorMessage) Allocator.Error!void {
        try wip.root_list.ensure_unused_capacity(wip.gpa, 1);
        wip.root_list.append_assume_capacity(try add_error_message(wip, em));
    }

    pub fn add_error_message(wip: *Wip, em: ErrorMessage) Allocator.Error!MessageIndex {
        return @enumFromInt(try add_extra(wip, em));
    }

    pub fn add_error_message_assume_capacity(wip: *Wip, em: ErrorMessage) MessageIndex {
        return @enumFromInt(add_extra_assume_capacity(wip, em));
    }

    pub fn add_source_location(wip: *Wip, sl: SourceLocation) Allocator.Error!SourceLocationIndex {
        return @enumFromInt(try add_extra(wip, sl));
    }

    pub fn add_reference_trace(wip: *Wip, rt: ReferenceTrace) Allocator.Error!void {
        _ = try add_extra(wip, rt);
    }

    pub fn add_bundle_as_notes(wip: *Wip, other: ErrorBundle) Allocator.Error!void {
        const gpa = wip.gpa;

        try wip.string_bytes.ensure_unused_capacity(gpa, other.string_bytes.len);
        try wip.extra.ensure_unused_capacity(gpa, other.extra.len);

        const other_list = other.get_messages();

        // The ensure_unused_capacity call above guarantees this.
        const notes_start = wip.reserve_notes(@int_cast(other_list.len)) catch unreachable;
        for (notes_start.., other_list) |note, message| {
            // This line can cause `wip.extra.items` to be resized.
            const note_index = @int_from_enum(wip.add_other_message(other, message) catch unreachable);
            wip.extra.items[note] = note_index;
        }
    }

    pub fn add_bundle_as_roots(wip: *Wip, other: ErrorBundle) !void {
        const gpa = wip.gpa;

        try wip.string_bytes.ensure_unused_capacity(gpa, other.string_bytes.len);
        try wip.extra.ensure_unused_capacity(gpa, other.extra.len);

        const other_list = other.get_messages();

        try wip.root_list.ensure_unused_capacity(gpa, other_list.len);
        for (other_list) |other_msg| {
            // The ensure_unused_capacity calls above guarantees this.
            wip.root_list.append_assume_capacity(wip.add_other_message(other, other_msg) catch unreachable);
        }
    }

    pub fn reserve_notes(wip: *Wip, notes_len: u32) !u32 {
        try wip.extra.ensure_unused_capacity(wip.gpa, notes_len +
            notes_len * @typeInfo(ErrorBundle.ErrorMessage).Struct.fields.len);
        wip.extra.items.len += notes_len;
        return @int_cast(wip.extra.items.len - notes_len);
    }

    pub fn add_zir_error_messages(
        eb: *ErrorBundle.Wip,
        zir: std.zig.Zir,
        tree: std.zig.Ast,
        source: [:0]const u8,
        src_path: []const u8,
    ) !void {
        const Zir = std.zig.Zir;
        const payload_index = zir.extra[@int_from_enum(Zir.ExtraIndex.compile_errors)];
        assert(payload_index != 0);

        const header = zir.extra_data(Zir.Inst.CompileErrors, payload_index);
        const items_len = header.data.items_len;
        var extra_index = header.end;
        for (0..items_len) |_| {
            const item = zir.extra_data(Zir.Inst.CompileErrors.Item, extra_index);
            extra_index = item.end;
            const err_span = blk: {
                if (item.data.node != 0) {
                    break :blk tree.node_to_span(item.data.node);
                }
                const token_starts = tree.tokens.items(.start);
                const start = token_starts[item.data.token] + item.data.byte_offset;
                const end = start + @as(u32, @int_cast(tree.token_slice(item.data.token).len)) - item.data.byte_offset;
                break :blk std.zig.Ast.Span{ .start = start, .end = end, .main = start };
            };
            const err_loc = std.zig.find_line_column(source, err_span.main);

            {
                const msg = zir.null_terminated_string(item.data.msg);
                try eb.add_root_error_message(.{
                    .msg = try eb.add_string(msg),
                    .src_loc = try eb.add_source_location(.{
                        .src_path = try eb.add_string(src_path),
                        .span_start = err_span.start,
                        .span_main = err_span.main,
                        .span_end = err_span.end,
                        .line = @int_cast(err_loc.line),
                        .column = @int_cast(err_loc.column),
                        .source_line = try eb.add_string(err_loc.source_line),
                    }),
                    .notes_len = item.data.notes_len(zir),
                });
            }

            if (item.data.notes != 0) {
                const notes_start = try eb.reserve_notes(item.data.notes);
                const block = zir.extra_data(Zir.Inst.Block, item.data.notes);
                const body = zir.extra[block.end..][0..block.data.body_len];
                for (notes_start.., body) |note_i, body_elem| {
                    const note_item = zir.extra_data(Zir.Inst.CompileErrors.Item, body_elem);
                    const msg = zir.null_terminated_string(note_item.data.msg);
                    const span = blk: {
                        if (note_item.data.node != 0) {
                            break :blk tree.node_to_span(note_item.data.node);
                        }
                        const token_starts = tree.tokens.items(.start);
                        const start = token_starts[note_item.data.token] + note_item.data.byte_offset;
                        const end = start + @as(u32, @int_cast(tree.token_slice(note_item.data.token).len)) - item.data.byte_offset;
                        break :blk std.zig.Ast.Span{ .start = start, .end = end, .main = start };
                    };
                    const loc = std.zig.find_line_column(source, span.main);

                    // This line can cause `wip.extra.items` to be resized.
                    const note_index = @int_from_enum(try eb.add_error_message(.{
                        .msg = try eb.add_string(msg),
                        .src_loc = try eb.add_source_location(.{
                            .src_path = try eb.add_string(src_path),
                            .span_start = span.start,
                            .span_main = span.main,
                            .span_end = span.end,
                            .line = @int_cast(loc.line),
                            .column = @int_cast(loc.column),
                            .source_line = if (loc.eql(err_loc))
                                0
                            else
                                try eb.add_string(loc.source_line),
                        }),
                        .notes_len = 0, // TODO rework this function to be recursive
                    }));
                    eb.extra.items[note_i] = note_index;
                }
            }
        }
    }

    fn add_other_message(wip: *Wip, other: ErrorBundle, msg_index: MessageIndex) !MessageIndex {
        const other_msg = other.get_error_message(msg_index);
        const src_loc = try wip.add_other_source_location(other, other_msg.src_loc);
        const msg = try wip.add_error_message(.{
            .msg = try wip.add_string(other.null_terminated_string(other_msg.msg)),
            .count = other_msg.count,
            .src_loc = src_loc,
            .notes_len = other_msg.notes_len,
        });
        const notes_start = try wip.reserve_notes(other_msg.notes_len);
        for (notes_start.., other.get_notes(msg_index)) |note, other_note| {
            wip.extra.items[note] = @int_from_enum(try wip.add_other_message(other, other_note));
        }
        return msg;
    }

    fn add_other_source_location(
        wip: *Wip,
        other: ErrorBundle,
        index: SourceLocationIndex,
    ) !SourceLocationIndex {
        if (index == .none) return .none;
        const other_sl = other.get_source_location(index);

        var ref_traces: std.ArrayListUnmanaged(ReferenceTrace) = .{};
        defer ref_traces.deinit(wip.gpa);

        if (other_sl.reference_trace_len > 0) {
            var ref_index = other.extra_data(SourceLocation, @int_from_enum(index)).end;
            for (0..other_sl.reference_trace_len) |_| {
                const other_ref_trace_ed = other.extra_data(ReferenceTrace, ref_index);
                const other_ref_trace = other_ref_trace_ed.data;
                ref_index = other_ref_trace_ed.end;

                const ref_trace: ReferenceTrace = if (other_ref_trace.src_loc == .none) .{
                    // sentinel ReferenceTrace does not store a string index in decl_name
                    .decl_name = other_ref_trace.decl_name,
                    .src_loc = .none,
                } else .{
                    .decl_name = try wip.add_string(other.null_terminated_string(other_ref_trace.decl_name)),
                    .src_loc = try wip.add_other_source_location(other, other_ref_trace.src_loc),
                };
                try ref_traces.append(wip.gpa, ref_trace);
            }
        }

        const src_loc = try wip.add_source_location(.{
            .src_path = try wip.add_string(other.null_terminated_string(other_sl.src_path)),
            .line = other_sl.line,
            .column = other_sl.column,
            .span_start = other_sl.span_start,
            .span_main = other_sl.span_main,
            .span_end = other_sl.span_end,
            .source_line = if (other_sl.source_line != 0)
                try wip.add_string(other.null_terminated_string(other_sl.source_line))
            else
                0,
            .reference_trace_len = other_sl.reference_trace_len,
        });

        for (ref_traces.items) |ref_trace| {
            try wip.add_reference_trace(ref_trace);
        }

        return src_loc;
    }

    fn add_extra(wip: *Wip, extra: anytype) Allocator.Error!u32 {
        const gpa = wip.gpa;
        const fields = @typeInfo(@TypeOf(extra)).Struct.fields;
        try wip.extra.ensure_unused_capacity(gpa, fields.len);
        return add_extra_assume_capacity(wip, extra);
    }

    fn add_extra_assume_capacity(wip: *Wip, extra: anytype) u32 {
        const fields = @typeInfo(@TypeOf(extra)).Struct.fields;
        const result: u32 = @int_cast(wip.extra.items.len);
        wip.extra.items.len += fields.len;
        set_extra(wip, result, extra);
        return result;
    }

    fn set_extra(wip: *Wip, index: usize, extra: anytype) void {
        const fields = @typeInfo(@TypeOf(extra)).Struct.fields;
        var i = index;
        inline for (fields) |field| {
            wip.extra.items[i] = switch (field.type) {
                u32 => @field(extra, field.name),
                MessageIndex => @int_from_enum(@field(extra, field.name)),
                SourceLocationIndex => @int_from_enum(@field(extra, field.name)),
                else => @compile_error("bad field type"),
            };
            i += 1;
        }
    }

    test add_bundle_as_roots {
        var bundle = bundle: {
            var wip: ErrorBundle.Wip = undefined;
            try wip.init(std.testing.allocator);
            errdefer wip.deinit();

            var ref_traces: [3]ReferenceTrace = undefined;
            for (&ref_traces, 0..) |*ref_trace, i| {
                if (i == ref_traces.len - 1) {
                    // sentinel reference trace
                    ref_trace.* = .{
                        .decl_name = 3, // signifies 3 hidden references
                        .src_loc = .none,
                    };
                } else {
                    ref_trace.* = .{
                        .decl_name = try wip.add_string("foo"),
                        .src_loc = try wip.add_source_location(.{
                            .src_path = try wip.add_string("foo"),
                            .line = 1,
                            .column = 2,
                            .span_start = 3,
                            .span_main = 4,
                            .span_end = 5,
                            .source_line = 0,
                        }),
                    };
                }
            }

            const src_loc = try wip.add_source_location(.{
                .src_path = try wip.add_string("foo"),
                .line = 1,
                .column = 2,
                .span_start = 3,
                .span_main = 4,
                .span_end = 5,
                .source_line = try wip.add_string("some source code"),
                .reference_trace_len = ref_traces.len,
            });
            for (&ref_traces) |ref_trace| {
                try wip.add_reference_trace(ref_trace);
            }

            try wip.add_root_error_message(ErrorMessage{
                .msg = try wip.add_string("hello world"),
                .src_loc = src_loc,
                .notes_len = 1,
            });
            const i = try wip.reserve_notes(1);
            const note_index = @int_from_enum(wip.add_error_message_assume_capacity(.{
                .msg = try wip.add_string("this is a note"),
                .src_loc = try wip.add_source_location(.{
                    .src_path = try wip.add_string("bar"),
                    .line = 1,
                    .column = 2,
                    .span_start = 3,
                    .span_main = 4,
                    .span_end = 5,
                    .source_line = try wip.add_string("another line of source"),
                }),
            }));
            wip.extra.items[i] = note_index;

            break :bundle try wip.to_owned_bundle("");
        };
        defer bundle.deinit(std.testing.allocator);

        const ttyconf: std.io.tty.Config = .no_color;

        var bundle_buf = std.ArrayList(u8).init(std.testing.allocator);
        defer bundle_buf.deinit();
        try bundle.render_to_writer(.{ .ttyconf = ttyconf }, bundle_buf.writer());

        var copy = copy: {
            var wip: ErrorBundle.Wip = undefined;
            try wip.init(std.testing.allocator);
            errdefer wip.deinit();

            try wip.add_bundle_as_roots(bundle);

            break :copy try wip.to_owned_bundle("");
        };
        defer copy.deinit(std.testing.allocator);

        var copy_buf = std.ArrayList(u8).init(std.testing.allocator);
        defer copy_buf.deinit();
        try copy.render_to_writer(.{ .ttyconf = ttyconf }, copy_buf.writer());

        try std.testing.expect_equal_strings(bundle_buf.items, copy_buf.items);
    }
};
