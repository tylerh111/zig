//! A Markdown parser producing `Document`s.
//!
//! The parser operates at two levels: at the outer level, the parser accepts
//! the content of an input document line by line and begins building the _block
//! structure_ of the document. This creates a stack of currently open blocks.
//!
//! When the parser detects the end of a block, it closes the block, popping it
//! from the open block stack and completing any additional parsing of the
//! block's content. For blocks which contain parseable inline content, this
//! invokes the inner level of the parser, handling the _inline structure_ of
//! the block.
//!
//! Inline parsing scans through the collected inline content of a block. When
//! it encounters a character that could indicate the beginning of an inline, it
//! either handles the inline right away (if possible) or adds it to a pending
//! inlines stack. When an inline is completed, it is added to a list of
//! completed inlines, which (along with any surrounding text nodes) will become
//! the children of the parent inline or the block whose inline content is being
//! parsed.

const std = @import("std");
const mem = std.mem;
const assert = std.debug.assert;
const is_whitespace = std.ascii.is_whitespace;
const Allocator = mem.Allocator;
const expect_equal = std.testing.expect_equal;
const Document = @import("Document.zig");
const Node = Document.Node;
const ExtraIndex = Document.ExtraIndex;
const ExtraData = Document.ExtraData;
const StringIndex = Document.StringIndex;

nodes: Node.List = .{},
extra: std.ArrayListUnmanaged(u32) = .{},
scratch_extra: std.ArrayListUnmanaged(u32) = .{},
string_bytes: std.ArrayListUnmanaged(u8) = .{},
scratch_string: std.ArrayListUnmanaged(u8) = .{},
pending_blocks: std.ArrayListUnmanaged(Block) = .{},
allocator: Allocator,

const Parser = @This();

/// An arbitrary limit on the maximum number of columns in a table so that
/// table-related metadata maintained by the parser does not require dynamic
/// memory allocation.
const max_table_columns = 128;

/// A block element which is still receiving children.
const Block = struct {
    tag: Tag,
    data: Data,
    extra_start: usize,
    string_start: usize,

    const Tag = enum {
        /// Data is `list`.
        list,
        /// Data is `list_item`.
        list_item,
        /// Data is `table`.
        table,
        /// Data is `none`.
        table_row,
        /// Data is `heading`.
        heading,
        /// Data is `code_block`.
        code_block,
        /// Data is `none`.
        blockquote,
        /// Data is `none`.
        paragraph,
        /// Data is `none`.
        thematic_break,
    };

    const Data = union {
        none: void,
        list: struct {
            marker: ListMarker,
            /// Between 0 and 999,999,999, inclusive.
            start: u30,
            tight: bool,
            last_line_blank: bool = false,
        },
        list_item: struct {
            continuation_indent: usize,
        },
        table: struct {
            column_alignments: std.BoundedArray(Node.TableCellAlignment, max_table_columns) = .{},
        },
        heading: struct {
            /// Between 1 and 6, inclusive.
            level: u3,
        },
        code_block: struct {
            tag: StringIndex,
            fence_len: usize,
            indent: usize,
        },

        const ListMarker = enum {
            @"-",
            @"*",
            @"+",
            number_dot,
            number_paren,
        };
    };

    const ContentType = enum {
        blocks,
        inlines,
        raw_inlines,
        nothing,
    };

    fn can_accept(b: Block) ContentType {
        return switch (b.tag) {
            .list,
            .list_item,
            .table,
            .blockquote,
            => .blocks,

            .heading,
            .paragraph,
            => .inlines,

            .code_block,
            => .raw_inlines,

            .table_row,
            .thematic_break,
            => .nothing,
        };
    }

    /// Attempts to continue `b` using the contents of `line`. If successful,
    /// returns the remaining portion of `line` to be considered part of `b`
    /// (e.g. for a blockquote, this would be everything except the leading
    /// `>`). If unsuccessful, returns null.
    fn match(b: Block, line: []const u8) ?[]const u8 {
        const unindented = mem.trim_left(u8, line, " \t");
        const indent = line.len - unindented.len;
        return switch (b.tag) {
            .list => line,
            .list_item => if (indent >= b.data.list_item.continuation_indent)
                line[b.data.list_item.continuation_indent..]
            else if (unindented.len == 0)
                // Blank lines should not close list items, since there may be
                // more indented contents to follow after the blank line.
                ""
            else
                null,
            .table => if (unindented.len > 0) line else null,
            .table_row => null,
            .heading => null,
            .code_block => code_block: {
                const trimmed = mem.trim_right(u8, unindented, " \t");
                if (mem.index_of_none(u8, trimmed, "`") != null or trimmed.len != b.data.code_block.fence_len) {
                    const effective_indent = @min(indent, b.data.code_block.indent);
                    break :code_block line[effective_indent..];
                } else {
                    break :code_block null;
                }
            },
            .blockquote => if (mem.starts_with(u8, unindented, ">"))
                unindented[1..]
            else
                null,
            .paragraph => if (unindented.len > 0) line else null,
            .thematic_break => null,
        };
    }
};

pub fn init(allocator: Allocator) Allocator.Error!Parser {
    var p: Parser = .{ .allocator = allocator };
    try p.nodes.append(allocator, .{
        .tag = .root,
        .data = undefined,
    });
    try p.string_bytes.append(allocator, 0);
    return p;
}

pub fn deinit(p: *Parser) void {
    p.nodes.deinit(p.allocator);
    p.extra.deinit(p.allocator);
    p.scratch_extra.deinit(p.allocator);
    p.string_bytes.deinit(p.allocator);
    p.scratch_string.deinit(p.allocator);
    p.pending_blocks.deinit(p.allocator);
    p.* = undefined;
}

/// Accepts a single line of content. `line` should not have a trailing line
/// ending character.
pub fn feed_line(p: *Parser, line: []const u8) Allocator.Error!void {
    var rest_line = line;
    const first_unmatched = for (p.pending_blocks.items, 0..) |b, i| {
        if (b.match(rest_line)) |rest| {
            rest_line = rest;
        } else {
            break i;
        }
    } else p.pending_blocks.items.len;

    const in_code_block = p.pending_blocks.items.len > 0 and
        p.pending_blocks.get_last().tag == .code_block;
    const code_block_end = in_code_block and
        first_unmatched + 1 == p.pending_blocks.items.len;
    // New blocks cannot be started if we are actively inside a code block or
    // are just closing one (to avoid interpreting the closing ``` as a new code
    // block start).
    var maybe_block_start = if (!in_code_block or first_unmatched + 2 <= p.pending_blocks.items.len)
        try p.start_block(rest_line)
    else
        null;

    // This is a lazy continuation line if there are no new blocks to open and
    // the last open block is a paragraph.
    if (maybe_block_start == null and
        !is_blank(rest_line) and
        p.pending_blocks.items.len > 0 and
        p.pending_blocks.get_last().tag == .paragraph)
    {
        try p.add_scratch_string_line(mem.trim_left(u8, rest_line, " \t"));
        return;
    }

    // If a new block needs to be started, any paragraph needs to be closed,
    // even though this isn't detected as part of the closing condition for
    // paragraphs.
    if (maybe_block_start != null and
        p.pending_blocks.items.len > 0 and
        p.pending_blocks.get_last().tag == .paragraph)
    {
        try p.close_last_block();
    }

    while (p.pending_blocks.items.len > first_unmatched) {
        try p.close_last_block();
    }

    while (maybe_block_start) |block_start| : (maybe_block_start = try p.start_block(rest_line)) {
        try p.append_block_start(block_start);
        // There may be more blocks to start within the same line.
        rest_line = block_start.rest;
        // Headings may only contain inline content.
        if (block_start.tag == .heading) break;
        // An opening code fence does not contain any additional block or inline
        // content to process.
        if (block_start.tag == .code_block) return;
    }

    // Do not append the end of a code block (```) as textual content.
    if (code_block_end) return;

    const can_accept = if (p.pending_blocks.get_last_or_null()) |last_pending_block|
        last_pending_block.can_accept()
    else
        .blocks;
    const rest_line_trimmed = mem.trim_left(u8, rest_line, " \t");
    switch (can_accept) {
        .blocks => {
            // If we're inside a list item and the rest of the line is blank, it
            // means that any subsequent child of the list item (or subsequent
            // item in the list) will cause the containing list to be considered
            // loose. However, we can't immediately declare that the list is
            // loose, since we might just be looking at a blank line after the
            // end of the last item in the list. The final determination will be
            // made when appending the next child of the list or list item.
            const maybe_containing_list_index = if (p.pending_blocks.items.len > 0 and p.pending_blocks.get_last().tag == .list_item)
                p.pending_blocks.items.len - 2
            else
                null;

            if (rest_line_trimmed.len > 0) {
                try p.append_block_start(.{
                    .tag = .paragraph,
                    .data = .{ .none = {} },
                    .rest = undefined,
                });
                try p.add_scratch_string_line(rest_line_trimmed);
            }

            if (maybe_containing_list_index) |containing_list_index| {
                p.pending_blocks.items[containing_list_index].data.list.last_line_blank = rest_line_trimmed.len == 0;
            }
        },
        .inlines => try p.add_scratch_string_line(rest_line_trimmed),
        .raw_inlines => try p.add_scratch_string_line(rest_line),
        .nothing => {},
    }
}

/// Completes processing of the input and returns the parsed document.
pub fn end_input(p: *Parser) Allocator.Error!Document {
    while (p.pending_blocks.items.len > 0) {
        try p.close_last_block();
    }
    // There should be no inline content pending after closing the last open
    // block.
    assert(p.scratch_string.items.len == 0);

    const children = try p.add_extra_children(@ptr_cast(p.scratch_extra.items));
    p.nodes.items(.data)[0] = .{ .container = .{ .children = children } };
    p.scratch_string.items.len = 0;
    p.scratch_extra.items.len = 0;

    var nodes = p.nodes.to_owned_slice();
    errdefer nodes.deinit(p.allocator);
    const extra = try p.extra.to_owned_slice(p.allocator);
    errdefer p.allocator.free(extra);
    const string_bytes = try p.string_bytes.to_owned_slice(p.allocator);
    errdefer p.allocator.free(string_bytes);

    return .{
        .nodes = nodes,
        .extra = extra,
        .string_bytes = string_bytes,
    };
}

/// Data describing the start of a new block element.
const BlockStart = struct {
    tag: Tag,
    data: Data,
    rest: []const u8,

    const Tag = enum {
        /// Data is `list_item`.
        list_item,
        /// Data is `table_row`.
        table_row,
        /// Data is `heading`.
        heading,
        /// Data is `code_block`.
        code_block,
        /// Data is `none`.
        blockquote,
        /// Data is `none`.
        paragraph,
        /// Data is `none`.
        thematic_break,
    };

    const Data = union {
        none: void,
        list_item: struct {
            marker: Block.Data.ListMarker,
            number: u30,
            continuation_indent: usize,
        },
        table_row: struct {
            cells: std.BoundedArray([]const u8, max_table_columns),
        },
        heading: struct {
            /// Between 1 and 6, inclusive.
            level: u3,
        },
        code_block: struct {
            tag: StringIndex,
            fence_len: usize,
            indent: usize,
        },
    };
};

fn append_block_start(p: *Parser, block_start: BlockStart) !void {
    if (p.pending_blocks.get_last_or_null()) |last_pending_block| {
        // Close the last block if it is a list and the new block is not a list item
        // or not of the same marker type.
        const should_close_list = last_pending_block.tag == .list and
            (block_start.tag != .list_item or
            block_start.data.list_item.marker != last_pending_block.data.list.marker);
        // The last block should also be closed if the new block is not a table
        // row, which is the only allowed child of a table.
        const should_close_table = last_pending_block.tag == .table and
            block_start.tag != .table_row;
        if (should_close_list or should_close_table) {
            try p.close_last_block();
        }
    }

    if (p.pending_blocks.get_last_or_null()) |last_pending_block| {
        // If the last block is a list or list item, check for tightness based
        // on the last line.
        const maybe_containing_list = switch (last_pending_block.tag) {
            .list => &p.pending_blocks.items[p.pending_blocks.items.len - 1],
            .list_item => &p.pending_blocks.items[p.pending_blocks.items.len - 2],
            else => null,
        };
        if (maybe_containing_list) |containing_list| {
            if (containing_list.data.list.last_line_blank) {
                containing_list.data.list.tight = false;
            }
        }
    }

    // Start a new list if the new block is a list item and there is no
    // containing list yet.
    if (block_start.tag == .list_item and
        (p.pending_blocks.items.len == 0 or p.pending_blocks.get_last().tag != .list))
    {
        try p.pending_blocks.append(p.allocator, .{
            .tag = .list,
            .data = .{ .list = .{
                .marker = block_start.data.list_item.marker,
                .start = block_start.data.list_item.number,
                .tight = true,
            } },
            .string_start = p.scratch_string.items.len,
            .extra_start = p.scratch_extra.items.len,
        });
    }

    if (block_start.tag == .table_row) {
        // Likewise, table rows start a table implicitly.
        if (p.pending_blocks.items.len == 0 or p.pending_blocks.get_last().tag != .table) {
            try p.pending_blocks.append(p.allocator, .{
                .tag = .table,
                .data = .{ .table = .{
                    .column_alignments = .{},
                } },
                .string_start = p.scratch_string.items.len,
                .extra_start = p.scratch_extra.items.len,
            });
        }

        const current_row = p.scratch_extra.items.len - p.pending_blocks.get_last().extra_start;
        if (current_row <= 1) {
            if (parse_table_header_delimiter(block_start.data.table_row.cells)) |alignments| {
                p.pending_blocks.items[p.pending_blocks.items.len - 1].data.table.column_alignments = alignments;
                if (current_row == 1) {
                    // We need to go back and mark the header row and its column
                    // alignments.
                    const datas = p.nodes.items(.data);
                    const header_data = datas[p.scratch_extra.get_last()];
                    for (p.extra_children(header_data.container.children), 0..) |header_cell, i| {
                        const alignment = if (i < alignments.len) alignments.buffer[i] else .unset;
                        const cell_data = &datas[@int_from_enum(header_cell)].table_cell;
                        cell_data.info.alignment = alignment;
                        cell_data.info.header = true;
                    }
                }
                return;
            }
        }
    }

    const tag: Block.Tag, const data: Block.Data = switch (block_start.tag) {
        .list_item => .{ .list_item, .{ .list_item = .{
            .continuation_indent = block_start.data.list_item.continuation_indent,
        } } },
        .table_row => .{ .table_row, .{ .none = {} } },
        .heading => .{ .heading, .{ .heading = .{
            .level = block_start.data.heading.level,
        } } },
        .code_block => .{ .code_block, .{ .code_block = .{
            .tag = block_start.data.code_block.tag,
            .fence_len = block_start.data.code_block.fence_len,
            .indent = block_start.data.code_block.indent,
        } } },
        .blockquote => .{ .blockquote, .{ .none = {} } },
        .paragraph => .{ .paragraph, .{ .none = {} } },
        .thematic_break => .{ .thematic_break, .{ .none = {} } },
    };

    try p.pending_blocks.append(p.allocator, .{
        .tag = tag,
        .data = data,
        .string_start = p.scratch_string.items.len,
        .extra_start = p.scratch_extra.items.len,
    });

    if (tag == .table_row) {
        // Table rows are unique, since we already have all the children
        // available in the BlockStart. We can immediately parse and append
        // these children now.
        const containing_table = p.pending_blocks.items[p.pending_blocks.items.len - 2];
        const column_alignments = containing_table.data.table.column_alignments.slice();
        for (block_start.data.table_row.cells.slice(), 0..) |cell_content, i| {
            const cell_children = try p.parse_inlines(cell_content);
            const alignment = if (i < column_alignments.len) column_alignments[i] else .unset;
            const cell = try p.add_node(.{
                .tag = .table_cell,
                .data = .{ .table_cell = .{
                    .info = .{
                        .alignment = alignment,
                        .header = false,
                    },
                    .children = cell_children,
                } },
            });
            try p.add_scratch_extra_node(cell);
        }
    }
}

fn start_block(p: *Parser, line: []const u8) !?BlockStart {
    const unindented = mem.trim_left(u8, line, " \t");
    const indent = line.len - unindented.len;
    if (is_thematic_break(line)) {
        // Thematic breaks take precedence over list items.
        return .{
            .tag = .thematic_break,
            .data = .{ .none = {} },
            .rest = "",
        };
    } else if (start_list_item(unindented)) |list_item| {
        return .{
            .tag = .list_item,
            .data = .{ .list_item = .{
                .marker = list_item.marker,
                .number = list_item.number,
                .continuation_indent = indent + list_item.marker_len,
            } },
            .rest = list_item.rest,
        };
    } else if (start_table_row(unindented)) |table_row| {
        return .{
            .tag = .table_row,
            .data = .{ .table_row = .{
                .cells = table_row.cells,
            } },
            .rest = "",
        };
    } else if (start_heading(unindented)) |heading| {
        return .{
            .tag = .heading,
            .data = .{ .heading = .{
                .level = heading.level,
            } },
            .rest = heading.rest,
        };
    } else if (try p.start_code_block(unindented)) |code_block| {
        return .{
            .tag = .code_block,
            .data = .{ .code_block = .{
                .tag = code_block.tag,
                .fence_len = code_block.fence_len,
                .indent = indent,
            } },
            .rest = "",
        };
    } else if (start_blockquote(unindented)) |rest| {
        return .{
            .tag = .blockquote,
            .data = .{ .none = {} },
            .rest = rest,
        };
    } else {
        return null;
    }
}

const ListItemStart = struct {
    marker: Block.Data.ListMarker,
    number: u30,
    marker_len: usize,
    rest: []const u8,
};

fn start_list_item(unindented_line: []const u8) ?ListItemStart {
    if (mem.starts_with(u8, unindented_line, "- ")) {
        return .{
            .marker = .@"-",
            .number = undefined,
            .marker_len = 2,
            .rest = unindented_line[2..],
        };
    } else if (mem.starts_with(u8, unindented_line, "* ")) {
        return .{
            .marker = .@"*",
            .number = undefined,
            .marker_len = 2,
            .rest = unindented_line[2..],
        };
    } else if (mem.starts_with(u8, unindented_line, "+ ")) {
        return .{
            .marker = .@"+",
            .number = undefined,
            .marker_len = 2,
            .rest = unindented_line[2..],
        };
    }

    const number_end = mem.index_of_none(u8, unindented_line, "0123456789") orelse return null;
    const after_number = unindented_line[number_end..];
    const marker: Block.Data.ListMarker = if (mem.starts_with(u8, after_number, ". "))
        .number_dot
    else if (mem.starts_with(u8, after_number, ") "))
        .number_paren
    else
        return null;
    const number = std.fmt.parse_int(u30, unindented_line[0..number_end], 10) catch return null;
    if (number > 999_999_999) return null;
    return .{
        .marker = marker,
        .number = number,
        .marker_len = number_end + 2,
        .rest = after_number[2..],
    };
}

const TableRowStart = struct {
    cells: std.BoundedArray([]const u8, max_table_columns),
};

fn start_table_row(unindented_line: []const u8) ?TableRowStart {
    if (unindented_line.len < 2 or
        !mem.starts_with(u8, unindented_line, "|") or
        mem.ends_with(u8, unindented_line, "\\|") or
        !mem.ends_with(u8, unindented_line, "|")) return null;

    var cells: std.BoundedArray([]const u8, max_table_columns) = .{};
    const table_row_content = unindented_line[1 .. unindented_line.len - 1];
    var cell_start: usize = 0;
    var i: usize = 0;
    while (i < table_row_content.len) : (i += 1) {
        switch (table_row_content[i]) {
            '\\' => i += 1,
            '|' => {
                cells.append(table_row_content[cell_start..i]) catch return null;
                cell_start = i + 1;
            },
            '`' => {
                // Ignoring pipes in code spans allows table cells to contain
                // code using ||, for example.
                const open_start = i;
                i = mem.index_of_none_pos(u8, table_row_content, i, "`") orelse return null;
                const open_len = i - open_start;
                while (mem.index_of_scalar_pos(u8, table_row_content, i, '`')) |close_start| {
                    i = mem.index_of_none_pos(u8, table_row_content, close_start, "`") orelse return null;
                    const close_len = i - close_start;
                    if (close_len == open_len) break;
                } else return null;
            },
            else => {},
        }
    }
    cells.append(table_row_content[cell_start..]) catch return null;

    return .{ .cells = cells };
}

fn parse_table_header_delimiter(
    row_cells: std.BoundedArray([]const u8, max_table_columns),
) ?std.BoundedArray(Node.TableCellAlignment, max_table_columns) {
    var alignments: std.BoundedArray(Node.TableCellAlignment, max_table_columns) = .{};
    for (row_cells.slice()) |content| {
        const alignment = parse_table_header_delimiter_cell(content) orelse return null;
        alignments.append_assume_capacity(alignment);
    }
    return alignments;
}

fn parse_table_header_delimiter_cell(content: []const u8) ?Node.TableCellAlignment {
    var state: enum {
        before_rule,
        after_left_anchor,
        in_rule,
        after_right_anchor,
        after_rule,
    } = .before_rule;
    var left_anchor = false;
    var right_anchor = false;
    for (content) |c| {
        switch (state) {
            .before_rule => switch (c) {
                ' ' => {},
                ':' => {
                    left_anchor = true;
                    state = .after_left_anchor;
                },
                '-' => state = .in_rule,
                else => return null,
            },
            .after_left_anchor => switch (c) {
                '-' => state = .in_rule,
                else => return null,
            },
            .in_rule => switch (c) {
                '-' => {},
                ':' => {
                    right_anchor = true;
                    state = .after_right_anchor;
                },
                ' ' => state = .after_rule,
                else => return null,
            },
            .after_right_anchor => switch (c) {
                ' ' => state = .after_rule,
                else => return null,
            },
            .after_rule => switch (c) {
                ' ' => {},
                else => return null,
            },
        }
    }

    switch (state) {
        .before_rule,
        .after_left_anchor,
        => return null,

        .in_rule,
        .after_right_anchor,
        .after_rule,
        => {},
    }

    return if (left_anchor and right_anchor)
        .center
    else if (left_anchor)
        .left
    else if (right_anchor)
        .right
    else
        .unset;
}

test parse_table_header_delimiter_cell {
    try expect_equal(null, parse_table_header_delimiter_cell(""));
    try expect_equal(null, parse_table_header_delimiter_cell("   "));
    try expect_equal(.unset, parse_table_header_delimiter_cell("-"));
    try expect_equal(.unset, parse_table_header_delimiter_cell(" - "));
    try expect_equal(.unset, parse_table_header_delimiter_cell("----"));
    try expect_equal(.unset, parse_table_header_delimiter_cell(" ---- "));
    try expect_equal(null, parse_table_header_delimiter_cell(":"));
    try expect_equal(null, parse_table_header_delimiter_cell("::"));
    try expect_equal(.left, parse_table_header_delimiter_cell(":-"));
    try expect_equal(.left, parse_table_header_delimiter_cell(" :----"));
    try expect_equal(.center, parse_table_header_delimiter_cell(":-:"));
    try expect_equal(.center, parse_table_header_delimiter_cell(":----:"));
    try expect_equal(.center, parse_table_header_delimiter_cell("   :----:   "));
    try expect_equal(.right, parse_table_header_delimiter_cell("-:"));
    try expect_equal(.right, parse_table_header_delimiter_cell("----:"));
    try expect_equal(.right, parse_table_header_delimiter_cell("  ----:  "));
}

const HeadingStart = struct {
    level: u3,
    rest: []const u8,
};

fn start_heading(unindented_line: []const u8) ?HeadingStart {
    var level: u3 = 0;
    return for (unindented_line, 0..) |c, i| {
        switch (c) {
            '#' => {
                if (level == 6) break null;
                level += 1;
            },
            ' ' => {
                // We must have seen at least one # by this point, since
                // unindented_line has no leading spaces.
                assert(level > 0);
                break .{
                    .level = level,
                    .rest = unindented_line[i + 1 ..],
                };
            },
            else => break null,
        }
    } else null;
}

const CodeBlockStart = struct {
    tag: StringIndex,
    fence_len: usize,
};

fn start_code_block(p: *Parser, unindented_line: []const u8) !?CodeBlockStart {
    var fence_len: usize = 0;
    const tag_bytes = for (unindented_line, 0..) |c, i| {
        switch (c) {
            '`' => fence_len += 1,
            else => break unindented_line[i..],
        }
    } else "";
    // Code block tags may not contain backticks, since that would create
    // potential confusion with inline code spans.
    if (fence_len < 3 or mem.index_of_scalar(u8, tag_bytes, '`') != null) return null;
    return .{
        .tag = try p.add_string(mem.trim(u8, tag_bytes, " ")),
        .fence_len = fence_len,
    };
}

fn start_blockquote(unindented_line: []const u8) ?[]const u8 {
    return if (mem.starts_with(u8, unindented_line, ">"))
        unindented_line[1..]
    else
        null;
}

fn is_thematic_break(line: []const u8) bool {
    var char: ?u8 = null;
    var count: usize = 0;
    for (line) |c| {
        switch (c) {
            ' ' => {},
            '-', '_', '*' => {
                if (char != null and c != char.?) return false;
                char = c;
                count += 1;
            },
            else => return false,
        }
    }
    return count >= 3;
}

fn close_last_block(p: *Parser) !void {
    const b = p.pending_blocks.pop();
    const node = switch (b.tag) {
        .list => list: {
            assert(b.string_start == p.scratch_string.items.len);

            // Although tightness is parsed as a property of the list, it is
            // stored at the list item level to make it possible to render each
            // node without any context from its parents.
            const list_items = p.scratch_extra.items[b.extra_start..];
            const node_datas = p.nodes.items(.data);
            if (!b.data.list.tight) {
                for (list_items) |list_item| {
                    node_datas[list_item].list_item.tight = false;
                }
            }

            const children = try p.add_extra_children(@ptr_cast(list_items));
            break :list try p.add_node(.{
                .tag = .list,
                .data = .{ .list = .{
                    .start = switch (b.data.list.marker) {
                        .number_dot, .number_paren => @enumFromInt(b.data.list.start),
                        .@"-", .@"*", .@"+" => .unordered,
                    },
                    .children = children,
                } },
            });
        },
        .list_item => list_item: {
            assert(b.string_start == p.scratch_string.items.len);
            const children = try p.add_extra_children(@ptr_cast(p.scratch_extra.items[b.extra_start..]));
            break :list_item try p.add_node(.{
                .tag = .list_item,
                .data = .{ .list_item = .{
                    .tight = true,
                    .children = children,
                } },
            });
        },
        .table => table: {
            assert(b.string_start == p.scratch_string.items.len);
            const children = try p.add_extra_children(@ptr_cast(p.scratch_extra.items[b.extra_start..]));
            break :table try p.add_node(.{
                .tag = .table,
                .data = .{ .container = .{
                    .children = children,
                } },
            });
        },
        .table_row => table_row: {
            assert(b.string_start == p.scratch_string.items.len);
            const children = try p.add_extra_children(@ptr_cast(p.scratch_extra.items[b.extra_start..]));
            break :table_row try p.add_node(.{
                .tag = .table_row,
                .data = .{ .container = .{
                    .children = children,
                } },
            });
        },
        .heading => heading: {
            const children = try p.parse_inlines(p.scratch_string.items[b.string_start..]);
            break :heading try p.add_node(.{
                .tag = .heading,
                .data = .{ .heading = .{
                    .level = b.data.heading.level,
                    .children = children,
                } },
            });
        },
        .code_block => code_block: {
            const content = try p.add_string(p.scratch_string.items[b.string_start..]);
            break :code_block try p.add_node(.{
                .tag = .code_block,
                .data = .{ .code_block = .{
                    .tag = b.data.code_block.tag,
                    .content = content,
                } },
            });
        },
        .blockquote => blockquote: {
            assert(b.string_start == p.scratch_string.items.len);
            const children = try p.add_extra_children(@ptr_cast(p.scratch_extra.items[b.extra_start..]));
            break :blockquote try p.add_node(.{
                .tag = .blockquote,
                .data = .{ .container = .{
                    .children = children,
                } },
            });
        },
        .paragraph => paragraph: {
            const children = try p.parse_inlines(p.scratch_string.items[b.string_start..]);
            break :paragraph try p.add_node(.{
                .tag = .paragraph,
                .data = .{ .container = .{
                    .children = children,
                } },
            });
        },
        .thematic_break => try p.add_node(.{
            .tag = .thematic_break,
            .data = .{ .none = {} },
        }),
    };
    p.scratch_string.items.len = b.string_start;
    p.scratch_extra.items.len = b.extra_start;
    try p.add_scratch_extra_node(node);
}

const InlineParser = struct {
    parent: *Parser,
    content: []const u8,
    pos: usize = 0,
    pending_inlines: std.ArrayListUnmanaged(PendingInline) = .{},
    completed_inlines: std.ArrayListUnmanaged(CompletedInline) = .{},

    const PendingInline = struct {
        tag: Tag,
        data: Data,
        start: usize,

        const Tag = enum {
            /// Data is `emphasis`.
            emphasis,
            /// Data is `none`.
            link,
            /// Data is `none`.
            image,
        };

        const Data = union {
            none: void,
            emphasis: struct {
                underscore: bool,
                run_len: usize,
            },
        };
    };

    const CompletedInline = struct {
        node: Node.Index,
        start: usize,
        len: usize,
    };

    fn deinit(ip: *InlineParser) void {
        ip.pending_inlines.deinit(ip.parent.allocator);
        ip.completed_inlines.deinit(ip.parent.allocator);
    }

    /// Parses all of `ip.content`, returning the children of the node
    /// containing the inline content.
    fn parse(ip: *InlineParser) Allocator.Error!ExtraIndex {
        while (ip.pos < ip.content.len) : (ip.pos += 1) {
            switch (ip.content[ip.pos]) {
                '\\' => ip.pos += 1,
                '[' => try ip.pending_inlines.append(ip.parent.allocator, .{
                    .tag = .link,
                    .data = .{ .none = {} },
                    .start = ip.pos,
                }),
                '!' => if (ip.pos + 1 < ip.content.len and ip.content[ip.pos + 1] == '[') {
                    try ip.pending_inlines.append(ip.parent.allocator, .{
                        .tag = .image,
                        .data = .{ .none = {} },
                        .start = ip.pos,
                    });
                    ip.pos += 1;
                },
                ']' => try ip.parse_link(),
                '<' => try ip.parse_autolink(),
                '*', '_' => try ip.parse_emphasis(),
                '`' => try ip.parse_code_span(),
                'h' => if (ip.pos == 0 or is_pre_text_autolink(ip.content[ip.pos - 1])) {
                    try ip.parse_text_autolink();
                },
                else => {},
            }
        }

        const children = try ip.encode_children(0, ip.content.len);
        // There may be pending inlines after parsing (e.g. unclosed emphasis
        // runs), but there must not be any completed inlines, since those
        // should all be part of `children`.
        assert(ip.completed_inlines.items.len == 0);
        return children;
    }

    /// Parses a link, starting at the `]` at the end of the link text. `ip.pos`
    /// is left at the closing `)` of the link target or at the closing `]` if
    /// there is none.
    fn parse_link(ip: *InlineParser) !void {
        var i = ip.pending_inlines.items.len;
        while (i > 0) {
            i -= 1;
            if (ip.pending_inlines.items[i].tag == .link or
                ip.pending_inlines.items[i].tag == .image) break;
        } else return;
        const opener = ip.pending_inlines.items[i];
        ip.pending_inlines.shrink_retaining_capacity(i);
        const text_start = switch (opener.tag) {
            .link => opener.start + 1,
            .image => opener.start + 2,
            else => unreachable,
        };

        if (ip.pos + 1 >= ip.content.len or ip.content[ip.pos + 1] != '(') return;
        const text_end = ip.pos;

        const target_start = text_end + 2;
        var target_end = target_start;
        var nesting_level: usize = 1;
        while (target_end < ip.content.len) : (target_end += 1) {
            switch (ip.content[target_end]) {
                '\\' => target_end += 1,
                '(' => nesting_level += 1,
                ')' => {
                    if (nesting_level == 1) break;
                    nesting_level -= 1;
                },
                else => {},
            }
        } else return;
        ip.pos = target_end;

        const children = try ip.encode_children(text_start, text_end);
        const target = try ip.encode_link_target(target_start, target_end);

        const link = try ip.parent.add_node(.{
            .tag = switch (opener.tag) {
                .link => .link,
                .image => .image,
                else => unreachable,
            },
            .data = .{ .link = .{
                .target = target,
                .children = children,
            } },
        });
        try ip.completed_inlines.append(ip.parent.allocator, .{
            .node = link,
            .start = opener.start,
            .len = ip.pos - opener.start + 1,
        });
    }

    fn encode_link_target(ip: *InlineParser, start: usize, end: usize) !StringIndex {
        // For efficiency, we can encode directly into string_bytes rather than
        // creating a temporary string and then encoding it, since this process
        // is entirely linear.
        const string_top = ip.parent.string_bytes.items.len;
        errdefer ip.parent.string_bytes.shrink_retaining_capacity(string_top);

        var text_iter: TextIterator = .{ .content = ip.content[start..end] };
        while (text_iter.next()) |content| {
            switch (content) {
                .char => |c| try ip.parent.string_bytes.append(ip.parent.allocator, c),
                .text => |s| try ip.parent.string_bytes.append_slice(ip.parent.allocator, s),
                .line_break => try ip.parent.string_bytes.append_slice(ip.parent.allocator, "\\\n"),
            }
        }
        try ip.parent.string_bytes.append(ip.parent.allocator, 0);
        return @enumFromInt(string_top);
    }

    /// Parses an autolink, starting at the opening `<`. `ip.pos` is left at the
    /// closing `>`, or remains unchanged at the opening `<` if there is none.
    fn parse_autolink(ip: *InlineParser) !void {
        const start = ip.pos;
        ip.pos += 1;
        var state: enum {
            start,
            scheme,
            target,
        } = .start;
        while (ip.pos < ip.content.len) : (ip.pos += 1) {
            switch (state) {
                .start => switch (ip.content[ip.pos]) {
                    'A'...'Z', 'a'...'z' => state = .scheme,
                    else => break,
                },
                .scheme => switch (ip.content[ip.pos]) {
                    'A'...'Z', 'a'...'z', '0'...'9', '+', '.', '-' => {},
                    ':' => state = .target,
                    else => break,
                },
                .target => switch (ip.content[ip.pos]) {
                    '<', ' ', '\t', '\n' => break, // Not allowed in autolinks
                    '>' => {
                        // Backslash escapes are not recognized in autolink targets.
                        const target = try ip.parent.add_string(ip.content[start + 1 .. ip.pos]);
                        const node = try ip.parent.add_node(.{
                            .tag = .autolink,
                            .data = .{ .text = .{
                                .content = target,
                            } },
                        });
                        try ip.completed_inlines.append(ip.parent.allocator, .{
                            .node = node,
                            .start = start,
                            .len = ip.pos - start + 1,
                        });
                        return;
                    },
                    else => {},
                },
            }
        }
        ip.pos = start;
    }

    /// Parses a plain text autolink (not delimited by `<>`), starting at the
    /// first character in the link (an `h`). `ip.pos` is left at the last
    /// character of the link, or remains unchanged if there is no valid link.
    fn parse_text_autolink(ip: *InlineParser) !void {
        const start = ip.pos;
        var state: union(enum) {
            /// Inside `http`. Contains the rest of the text to be matched.
            http: []const u8,
            after_http,
            after_https,
            /// Inside `://`. Contains the rest of the text to be matched.
            authority: []const u8,
            /// Inside link content.
            content: struct {
                start: usize,
                paren_nesting: usize,
            },
        } = .{ .http = "http" };

        while (ip.pos < ip.content.len) : (ip.pos += 1) {
            switch (state) {
                .http => |rest| {
                    if (ip.content[ip.pos] != rest[0]) break;
                    if (rest.len > 1) {
                        state = .{ .http = rest[1..] };
                    } else {
                        state = .after_http;
                    }
                },
                .after_http => switch (ip.content[ip.pos]) {
                    's' => state = .after_https,
                    ':' => state = .{ .authority = "//" },
                    else => break,
                },
                .after_https => switch (ip.content[ip.pos]) {
                    ':' => state = .{ .authority = "//" },
                    else => break,
                },
                .authority => |rest| {
                    if (ip.content[ip.pos] != rest[0]) break;
                    if (rest.len > 1) {
                        state = .{ .authority = rest[1..] };
                    } else {
                        state = .{ .content = .{
                            .start = ip.pos + 1,
                            .paren_nesting = 0,
                        } };
                    }
                },
                .content => |*content| switch (ip.content[ip.pos]) {
                    ' ', '\t', '\n' => break,
                    '(' => content.paren_nesting += 1,
                    ')' => if (content.paren_nesting == 0) {
                        break;
                    } else {
                        content.paren_nesting -= 1;
                    },
                    else => {},
                },
            }
        }

        switch (state) {
            .http, .after_http, .after_https, .authority => {
                ip.pos = start;
            },
            .content => |content| {
                while (ip.pos > content.start and is_post_text_autolink(ip.content[ip.pos - 1])) {
                    ip.pos -= 1;
                }
                if (ip.pos == content.start) {
                    ip.pos = start;
                    return;
                }

                const target = try ip.parent.add_string(ip.content[start..ip.pos]);
                const node = try ip.parent.add_node(.{
                    .tag = .autolink,
                    .data = .{ .text = .{
                        .content = target,
                    } },
                });
                try ip.completed_inlines.append(ip.parent.allocator, .{
                    .node = node,
                    .start = start,
                    .len = ip.pos - start,
                });
                ip.pos -= 1;
            },
        }
    }

    /// Returns whether `c` may appear before a text autolink is recognized.
    fn is_pre_text_autolink(c: u8) bool {
        return switch (c) {
            ' ', '\t', '\n', '*', '_', '(' => true,
            else => false,
        };
    }

    /// Returns whether `c` is punctuation that may appear after a text autolink
    /// and not be considered part of it.
    fn is_post_text_autolink(c: u8) bool {
        return switch (c) {
            '?', '!', '.', ',', ':', '*', '_' => true,
            else => false,
        };
    }

    /// Parses emphasis, starting at the beginning of a run of `*` or `_`
    /// characters. `ip.pos` is left at the last character in the run after
    /// parsing.
    fn parse_emphasis(ip: *InlineParser) !void {
        const char = ip.content[ip.pos];
        var start = ip.pos;
        while (ip.pos + 1 < ip.content.len and ip.content[ip.pos + 1] == char) {
            ip.pos += 1;
        }
        var len = ip.pos - start + 1;
        const underscore = char == '_';
        const space_before = start == 0 or is_whitespace(ip.content[start - 1]);
        const space_after = start + len == ip.content.len or is_whitespace(ip.content[start + len]);
        const punct_before = start == 0 or is_punctuation(ip.content[start - 1]);
        const punct_after = start + len == ip.content.len or is_punctuation(ip.content[start + len]);
        // The rules for when emphasis may be closed or opened are stricter for
        // underscores to avoid inappropriately interpreting snake_case words as
        // containing emphasis markers.
        const can_open = if (underscore)
            !space_after and (space_before or punct_before)
        else
            !space_after;
        const can_close = if (underscore)
            !space_before and (space_after or punct_after)
        else
            !space_before;

        if (can_close and ip.pending_inlines.items.len > 0) {
            var i = ip.pending_inlines.items.len;
            while (i > 0 and len > 0) {
                i -= 1;
                const opener = &ip.pending_inlines.items[i];
                if (opener.tag != .emphasis or
                    opener.data.emphasis.underscore != underscore) continue;

                const close_len = @min(opener.data.emphasis.run_len, len);
                const opener_end = opener.start + opener.data.emphasis.run_len;

                const emphasis = try ip.encode_emphasis(opener_end, start, close_len);
                const emphasis_start = opener_end - close_len;
                const emphasis_len = start - emphasis_start + close_len;
                try ip.completed_inlines.append(ip.parent.allocator, .{
                    .node = emphasis,
                    .start = emphasis_start,
                    .len = emphasis_len,
                });

                // There may still be other openers further down in the
                // stack to close, or part of this run might serve as an
                // opener itself.
                start += close_len;
                len -= close_len;

                // Remove any pending inlines above this on the stack, since
                // closing this emphasis will prevent them from being closed.
                // Additionally, if this opener is completely consumed by
                // being closed, it can be removed.
                opener.data.emphasis.run_len -= close_len;
                if (opener.data.emphasis.run_len == 0) {
                    ip.pending_inlines.shrink_retaining_capacity(i);
                } else {
                    ip.pending_inlines.shrink_retaining_capacity(i + 1);
                }
            }
        }

        if (can_open and len > 0) {
            try ip.pending_inlines.append(ip.parent.allocator, .{
                .tag = .emphasis,
                .data = .{ .emphasis = .{
                    .underscore = underscore,
                    .run_len = len,
                } },
                .start = start,
            });
        }
    }

    /// Encodes emphasis specified by a run of `run_len` emphasis characters,
    /// with `start..end` being the range of content contained within the
    /// emphasis.
    fn encode_emphasis(ip: *InlineParser, start: usize, end: usize, run_len: usize) !Node.Index {
        const children = try ip.encode_children(start, end);
        var inner = switch (run_len % 3) {
            1 => try ip.parent.add_node(.{
                .tag = .emphasis,
                .data = .{ .container = .{
                    .children = children,
                } },
            }),
            2 => try ip.parent.add_node(.{
                .tag = .strong,
                .data = .{ .container = .{
                    .children = children,
                } },
            }),
            0 => strong_emphasis: {
                const strong = try ip.parent.add_node(.{
                    .tag = .strong,
                    .data = .{ .container = .{
                        .children = children,
                    } },
                });
                break :strong_emphasis try ip.parent.add_node(.{
                    .tag = .emphasis,
                    .data = .{ .container = .{
                        .children = try ip.parent.add_extra_children(&.{strong}),
                    } },
                });
            },
            else => unreachable,
        };

        var run_left = run_len;
        while (run_left > 3) : (run_left -= 3) {
            const strong = try ip.parent.add_node(.{
                .tag = .strong,
                .data = .{ .container = .{
                    .children = try ip.parent.add_extra_children(&.{inner}),
                } },
            });
            inner = try ip.parent.add_node(.{
                .tag = .emphasis,
                .data = .{ .container = .{
                    .children = try ip.parent.add_extra_children(&.{strong}),
                } },
            });
        }

        return inner;
    }

    /// Parses a code span, starting at the beginning of the opening backtick
    /// run. `ip.pos` is left at the last character in the closing run after
    /// parsing.
    fn parse_code_span(ip: *InlineParser) !void {
        const opener_start = ip.pos;
        ip.pos = mem.index_of_none_pos(u8, ip.content, ip.pos, "`") orelse ip.content.len;
        const opener_len = ip.pos - opener_start;

        const start = ip.pos;
        const end = while (mem.index_of_scalar_pos(u8, ip.content, ip.pos, '`')) |closer_start| {
            ip.pos = mem.index_of_none_pos(u8, ip.content, closer_start, "`") orelse ip.content.len;
            const closer_len = ip.pos - closer_start;

            if (closer_len == opener_len) break closer_start;
        } else unterminated: {
            ip.pos = ip.content.len;
            break :unterminated ip.content.len;
        };

        var content = if (start < ip.content.len)
            ip.content[start..end]
        else
            "";
        // This single space removal rule allows code spans to be written which
        // start or end with backticks.
        if (mem.starts_with(u8, content, " `")) content = content[1..];
        if (mem.ends_with(u8, content, "` ")) content = content[0 .. content.len - 1];

        const text = try ip.parent.add_node(.{
            .tag = .code_span,
            .data = .{ .text = .{
                .content = try ip.parent.add_string(content),
            } },
        });
        try ip.completed_inlines.append(ip.parent.allocator, .{
            .node = text,
            .start = opener_start,
            .len = ip.pos - opener_start,
        });
        // Ensure ip.pos is pointing at the last character of the
        // closer, not after it.
        ip.pos -= 1;
    }

    /// Encodes children parsed in the content range `start..end`. The children
    /// will be text nodes and any completed inlines within the range.
    fn encode_children(ip: *InlineParser, start: usize, end: usize) !ExtraIndex {
        const scratch_extra_top = ip.parent.scratch_extra.items.len;
        defer ip.parent.scratch_extra.shrink_retaining_capacity(scratch_extra_top);

        var child_index = ip.completed_inlines.items.len;
        while (child_index > 0 and ip.completed_inlines.items[child_index - 1].start >= start) {
            child_index -= 1;
        }
        const start_child_index = child_index;

        var pos = start;
        while (child_index < ip.completed_inlines.items.len) : (child_index += 1) {
            const child_inline = ip.completed_inlines.items[child_index];
            // Completed inlines must be strictly nested within the encodable
            // content.
            assert(child_inline.start >= pos and child_inline.start + child_inline.len <= end);

            if (child_inline.start > pos) {
                try ip.encode_text_node(pos, child_inline.start);
            }
            try ip.parent.add_scratch_extra_node(child_inline.node);

            pos = child_inline.start + child_inline.len;
        }
        ip.completed_inlines.shrink_retaining_capacity(start_child_index);

        if (pos < end) {
            try ip.encode_text_node(pos, end);
        }

        const children = ip.parent.scratch_extra.items[scratch_extra_top..];
        return try ip.parent.add_extra_children(@ptr_cast(children));
    }

    /// Encodes textual content `ip.content[start..end]` to `scratch_extra`. The
    /// encoded content may include both `text` and `line_break` nodes.
    fn encode_text_node(ip: *InlineParser, start: usize, end: usize) !void {
        // For efficiency, we can encode directly into string_bytes rather than
        // creating a temporary string and then encoding it, since this process
        // is entirely linear.
        const string_top = ip.parent.string_bytes.items.len;
        errdefer ip.parent.string_bytes.shrink_retaining_capacity(string_top);

        var string_start = string_top;
        var text_iter: TextIterator = .{ .content = ip.content[start..end] };
        while (text_iter.next()) |content| {
            switch (content) {
                .char => |c| try ip.parent.string_bytes.append(ip.parent.allocator, c),
                .text => |s| try ip.parent.string_bytes.append_slice(ip.parent.allocator, s),
                .line_break => {
                    if (ip.parent.string_bytes.items.len > string_start) {
                        try ip.parent.string_bytes.append(ip.parent.allocator, 0);
                        try ip.parent.add_scratch_extra_node(try ip.parent.add_node(.{
                            .tag = .text,
                            .data = .{ .text = .{
                                .content = @enumFromInt(string_start),
                            } },
                        }));
                        string_start = ip.parent.string_bytes.items.len;
                    }
                    try ip.parent.add_scratch_extra_node(try ip.parent.add_node(.{
                        .tag = .line_break,
                        .data = .{ .none = {} },
                    }));
                },
            }
        }
        if (ip.parent.string_bytes.items.len > string_start) {
            try ip.parent.string_bytes.append(ip.parent.allocator, 0);
            try ip.parent.add_scratch_extra_node(try ip.parent.add_node(.{
                .tag = .text,
                .data = .{ .text = .{
                    .content = @enumFromInt(string_start),
                } },
            }));
        }
    }

    /// An iterator over parts of textual content, handling unescaping of
    /// escaped characters and line breaks.
    const TextIterator = struct {
        content: []const u8,
        pos: usize = 0,

        const Content = union(enum) {
            char: u8,
            text: []const u8,
            line_break,
        };

        const replacement = "\u{FFFD}";

        fn next(iter: *TextIterator) ?Content {
            if (iter.pos >= iter.content.len) return null;
            if (iter.content[iter.pos] == '\\') {
                iter.pos += 1;
                if (iter.pos == iter.content.len) {
                    return .{ .char = '\\' };
                } else if (iter.content[iter.pos] == '\n') {
                    iter.pos += 1;
                    return .line_break;
                } else if (is_punctuation(iter.content[iter.pos])) {
                    const c = iter.content[iter.pos];
                    iter.pos += 1;
                    return .{ .char = c };
                } else {
                    return .{ .char = '\\' };
                }
            }
            return iter.next_codepoint();
        }

        fn next_codepoint(iter: *TextIterator) ?Content {
            switch (iter.content[iter.pos]) {
                0 => {
                    iter.pos += 1;
                    return .{ .text = replacement };
                },
                1...127 => |c| {
                    iter.pos += 1;
                    return .{ .char = c };
                },
                else => |b| {
                    const cp_len = std.unicode.utf8_byte_sequence_length(b) catch {
                        iter.pos += 1;
                        return .{ .text = replacement };
                    };
                    const is_valid = iter.pos + cp_len <= iter.content.len and
                        std.unicode.utf8_validate_slice(iter.content[iter.pos..][0..cp_len]);
                    const cp_encoded = if (is_valid)
                        iter.content[iter.pos..][0..cp_len]
                    else
                        replacement;
                    iter.pos += cp_len;
                    return .{ .text = cp_encoded };
                },
            }
        }
    };
};

fn parse_inlines(p: *Parser, content: []const u8) !ExtraIndex {
    var ip: InlineParser = .{
        .parent = p,
        .content = mem.trim(u8, content, " \t\n"),
    };
    defer ip.deinit();
    return try ip.parse();
}

pub fn extra_data(p: Parser, comptime T: type, index: ExtraIndex) ExtraData(T) {
    const fields = @typeInfo(T).Struct.fields;
    var i: usize = @int_from_enum(index);
    var result: T = undefined;
    inline for (fields) |field| {
        @field(result, field.name) = switch (field.type) {
            u32 => p.extra.items[i],
            else => @compile_error("bad field type"),
        };
        i += 1;
    }
    return .{ .data = result, .end = i };
}

pub fn extra_children(p: Parser, index: ExtraIndex) []const Node.Index {
    const children = p.extra_data(Node.Children, index);
    return @ptr_cast(p.extra.items[children.end..][0..children.data.len]);
}

fn add_node(p: *Parser, node: Node) !Node.Index {
    const index: Node.Index = @enumFromInt(@as(u32, @int_cast(p.nodes.len)));
    try p.nodes.append(p.allocator, node);
    return index;
}

fn add_string(p: *Parser, s: []const u8) !StringIndex {
    if (s.len == 0) return .empty;

    const index: StringIndex = @enumFromInt(@as(u32, @int_cast(p.string_bytes.items.len)));
    try p.string_bytes.ensure_unused_capacity(p.allocator, s.len + 1);
    p.string_bytes.append_slice_assume_capacity(s);
    p.string_bytes.append_assume_capacity(0);
    return index;
}

fn add_extra_children(p: *Parser, nodes: []const Node.Index) !ExtraIndex {
    const index: ExtraIndex = @enumFromInt(@as(u32, @int_cast(p.extra.items.len)));
    try p.extra.ensure_unused_capacity(p.allocator, nodes.len + 1);
    p.extra.append_assume_capacity(@int_cast(nodes.len));
    p.extra.append_slice_assume_capacity(@ptr_cast(nodes));
    return index;
}

fn add_scratch_extra_node(p: *Parser, node: Node.Index) !void {
    try p.scratch_extra.append(p.allocator, @int_from_enum(node));
}

fn add_scratch_string_line(p: *Parser, line: []const u8) !void {
    try p.scratch_string.ensure_unused_capacity(p.allocator, line.len + 1);
    p.scratch_string.append_slice_assume_capacity(line);
    p.scratch_string.append_assume_capacity('\n');
}

fn is_blank(line: []const u8) bool {
    return mem.index_of_none(u8, line, " \t") == null;
}

fn is_punctuation(c: u8) bool {
    return switch (c) {
        '!',
        '"',
        '#',
        '$',
        '%',
        '&',
        '\'',
        '(',
        ')',
        '*',
        '+',
        ',',
        '-',
        '.',
        '/',
        ':',
        ';',
        '<',
        '=',
        '>',
        '?',
        '@',
        '[',
        '\\',
        ']',
        '^',
        '_',
        '`',
        '{',
        '|',
        '}',
        '~',
        => true,
        else => false,
    };
}
