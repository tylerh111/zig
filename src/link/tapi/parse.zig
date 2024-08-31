const std = @import("std");
const assert = std.debug.assert;
const log = std.log.scoped(.yaml);
const mem = std.mem;

const Allocator = mem.Allocator;
const Tokenizer = @import("Tokenizer.zig");
const Token = Tokenizer.Token;
const TokenIndex = Tokenizer.TokenIndex;
const TokenIterator = Tokenizer.TokenIterator;

pub const ParseError = error{
    InvalidEscapeSequence,
    MalformedYaml,
    NestedDocuments,
    UnexpectedEof,
    UnexpectedToken,
    Unhandled,
} || Allocator.Error;

pub const Node = struct {
    tag: Tag,
    tree: *const Tree,
    start: TokenIndex,
    end: TokenIndex,

    pub const Tag = enum {
        doc,
        map,
        list,
        value,

        pub fn Type(comptime tag: Tag) type {
            return switch (tag) {
                .doc => Doc,
                .map => Map,
                .list => List,
                .value => Value,
            };
        }
    };

    pub fn cast(self: *const Node, comptime T: type) ?*const T {
        if (self.tag != T.base_tag) {
            return null;
        }
        return @fieldParentPtr("base", self);
    }

    pub fn deinit(self: *Node, allocator: Allocator) void {
        switch (self.tag) {
            inline else => |tag| {
                const parent: *tag.Type() = @fieldParentPtr("base", self);
                parent.deinit(allocator);
                allocator.destroy(parent);
            },
        }
    }

    pub fn format(
        self: *const Node,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        switch (self.tag) {
            inline else => |tag| return @as(*tag.Type(), @fieldParentPtr("base", self)).format(fmt, options, writer),
        }
    }

    pub const Doc = struct {
        base: Node = Node{
            .tag = Tag.doc,
            .tree = undefined,
            .start = undefined,
            .end = undefined,
        },
        directive: ?TokenIndex = null,
        value: ?*Node = null,

        pub const base_tag: Node.Tag = .doc;

        pub fn deinit(self: *Doc, allocator: Allocator) void {
            if (self.value) |node| {
                node.deinit(allocator);
            }
        }

        pub fn format(
            self: *const Doc,
            comptime fmt: []const u8,
            options: std.fmt.FormatOptions,
            writer: anytype,
        ) !void {
            _ = options;
            _ = fmt;
            if (self.directive) |id| {
                try std.fmt.format(writer, "{{ ", .{});
                const directive = self.base.tree.get_raw(id, id);
                try std.fmt.format(writer, ".directive = {s}, ", .{directive});
            }
            if (self.value) |node| {
                try std.fmt.format(writer, "{}", .{node});
            }
            if (self.directive != null) {
                try std.fmt.format(writer, " }}", .{});
            }
        }
    };

    pub const Map = struct {
        base: Node = Node{
            .tag = Tag.map,
            .tree = undefined,
            .start = undefined,
            .end = undefined,
        },
        values: std.ArrayListUnmanaged(Entry) = .{},

        pub const base_tag: Node.Tag = .map;

        pub const Entry = struct {
            key: TokenIndex,
            value: ?*Node,
        };

        pub fn deinit(self: *Map, allocator: Allocator) void {
            for (self.values.items) |entry| {
                if (entry.value) |value| {
                    value.deinit(allocator);
                }
            }
            self.values.deinit(allocator);
        }

        pub fn format(
            self: *const Map,
            comptime fmt: []const u8,
            options: std.fmt.FormatOptions,
            writer: anytype,
        ) !void {
            _ = options;
            _ = fmt;
            try std.fmt.format(writer, "{{ ", .{});
            for (self.values.items) |entry| {
                const key = self.base.tree.get_raw(entry.key, entry.key);
                if (entry.value) |value| {
                    try std.fmt.format(writer, "{s} => {}, ", .{ key, value });
                } else {
                    try std.fmt.format(writer, "{s} => null, ", .{key});
                }
            }
            return std.fmt.format(writer, " }}", .{});
        }
    };

    pub const List = struct {
        base: Node = Node{
            .tag = Tag.list,
            .tree = undefined,
            .start = undefined,
            .end = undefined,
        },
        values: std.ArrayListUnmanaged(*Node) = .{},

        pub const base_tag: Node.Tag = .list;

        pub fn deinit(self: *List, allocator: Allocator) void {
            for (self.values.items) |node| {
                node.deinit(allocator);
            }
            self.values.deinit(allocator);
        }

        pub fn format(
            self: *const List,
            comptime fmt: []const u8,
            options: std.fmt.FormatOptions,
            writer: anytype,
        ) !void {
            _ = options;
            _ = fmt;
            try std.fmt.format(writer, "[ ", .{});
            for (self.values.items) |node| {
                try std.fmt.format(writer, "{}, ", .{node});
            }
            return std.fmt.format(writer, " ]", .{});
        }
    };

    pub const Value = struct {
        base: Node = Node{
            .tag = Tag.value,
            .tree = undefined,
            .start = undefined,
            .end = undefined,
        },
        string_value: std.ArrayListUnmanaged(u8) = .{},

        pub const base_tag: Node.Tag = .value;

        pub fn deinit(self: *Value, allocator: Allocator) void {
            self.string_value.deinit(allocator);
        }

        pub fn format(
            self: *const Value,
            comptime fmt: []const u8,
            options: std.fmt.FormatOptions,
            writer: anytype,
        ) !void {
            _ = options;
            _ = fmt;
            const raw = self.base.tree.get_raw(self.base.start, self.base.end);
            return std.fmt.format(writer, "{s}", .{raw});
        }
    };
};

pub const LineCol = struct {
    line: usize,
    col: usize,
};

pub const Tree = struct {
    allocator: Allocator,
    source: []const u8,
    tokens: []Token,
    line_cols: std.AutoHashMap(TokenIndex, LineCol),
    docs: std.ArrayListUnmanaged(*Node) = .{},

    pub fn init(allocator: Allocator) Tree {
        return .{
            .allocator = allocator,
            .source = undefined,
            .tokens = undefined,
            .line_cols = std.AutoHashMap(TokenIndex, LineCol).init(allocator),
        };
    }

    pub fn deinit(self: *Tree) void {
        self.allocator.free(self.tokens);
        self.line_cols.deinit();
        for (self.docs.items) |doc| {
            doc.deinit(self.allocator);
        }
        self.docs.deinit(self.allocator);
    }

    pub fn get_directive(self: Tree, doc_index: usize) ?[]const u8 {
        assert(doc_index < self.docs.items.len);
        const doc = self.docs.items[doc_index].cast(Node.Doc) orelse return null;
        const id = doc.directive orelse return null;
        return self.get_raw(id, id);
    }

    pub fn get_raw(self: Tree, start: TokenIndex, end: TokenIndex) []const u8 {
        assert(start <= end);
        assert(start < self.tokens.len and end < self.tokens.len);
        const start_token = self.tokens[start];
        const end_token = self.tokens[end];
        return self.source[start_token.start..end_token.end];
    }

    pub fn parse(self: *Tree, source: []const u8) !void {
        var tokenizer = Tokenizer{ .buffer = source };
        var tokens = std.ArrayList(Token).init(self.allocator);
        defer tokens.deinit();

        var line: usize = 0;
        var prev_line_last_col: usize = 0;

        while (true) {
            const token = tokenizer.next();
            const tok_id = tokens.items.len;
            try tokens.append(token);

            try self.line_cols.put_no_clobber(tok_id, .{
                .line = line,
                .col = token.start - prev_line_last_col,
            });

            switch (token.id) {
                .eof => break,
                .new_line => {
                    line += 1;
                    prev_line_last_col = token.end;
                },
                else => {},
            }
        }

        self.source = source;
        self.tokens = try tokens.to_owned_slice();

        var it = TokenIterator{ .buffer = self.tokens };
        var parser = Parser{
            .allocator = self.allocator,
            .tree = self,
            .token_it = &it,
            .line_cols = &self.line_cols,
        };

        parser.eat_comments_and_space(&.{});

        while (true) {
            parser.eat_comments_and_space(&.{});
            const token = parser.token_it.next() orelse break;

            log.debug("(main) next {s}@{d}", .{ @tag_name(token.id), parser.token_it.pos - 1 });

            switch (token.id) {
                .eof => break,
                else => {
                    parser.token_it.seek_by(-1);
                    const doc = try parser.doc();
                    try self.docs.append(self.allocator, doc);
                },
            }
        }
    }
};

const Parser = struct {
    allocator: Allocator,
    tree: *Tree,
    token_it: *TokenIterator,
    line_cols: *const std.AutoHashMap(TokenIndex, LineCol),

    fn value(self: *Parser) ParseError!?*Node {
        self.eat_comments_and_space(&.{});

        const pos = self.token_it.pos;
        const token = self.token_it.next() orelse return error.UnexpectedEof;

        log.debug("  next {s}@{d}", .{ @tag_name(token.id), pos });

        switch (token.id) {
            .literal => if (self.eat_token(.map_value_ind, &.{ .new_line, .comment })) |_| {
                // map
                self.token_it.seek_to(pos);
                return self.map();
            } else {
                // leaf value
                self.token_it.seek_to(pos);
                return self.leaf_value();
            },
            .single_quoted, .double_quoted => {
                // leaf value
                self.token_it.seek_by(-1);
                return self.leaf_value();
            },
            .seq_item_ind => {
                // list
                self.token_it.seek_by(-1);
                return self.list();
            },
            .flow_seq_start => {
                // list
                self.token_it.seek_by(-1);
                return self.list_bracketed();
            },
            else => return null,
        }
    }

    fn doc(self: *Parser) ParseError!*Node {
        const node = try self.allocator.create(Node.Doc);
        errdefer self.allocator.destroy(node);
        node.* = .{};
        node.base.tree = self.tree;
        node.base.start = self.token_it.pos;

        log.debug("(doc) begin {s}@{d}", .{ @tag_name(self.tree.tokens[node.base.start].id), node.base.start });

        // Parse header
        const explicit_doc: bool = if (self.eat_token(.doc_start, &.{})) |doc_pos| explicit_doc: {
            if (self.get_col(doc_pos) > 0) return error.MalformedYaml;
            if (self.eat_token(.tag, &.{ .new_line, .comment })) |_| {
                node.directive = try self.expect_token(.literal, &.{ .new_line, .comment });
            }
            break :explicit_doc true;
        } else false;

        // Parse value
        node.value = try self.value();
        if (node.value == null) {
            self.token_it.seek_by(-1);
        }
        errdefer if (node.value) |val| {
            val.deinit(self.allocator);
        };

        // Parse footer
        footer: {
            if (self.eat_token(.doc_end, &.{})) |pos| {
                if (!explicit_doc) return error.UnexpectedToken;
                if (self.get_col(pos) > 0) return error.MalformedYaml;
                node.base.end = pos;
                break :footer;
            }
            if (self.eat_token(.doc_start, &.{})) |pos| {
                if (!explicit_doc) return error.UnexpectedToken;
                if (self.get_col(pos) > 0) return error.MalformedYaml;
                self.token_it.seek_by(-1);
                node.base.end = pos - 1;
                break :footer;
            }
            if (self.eat_token(.eof, &.{})) |pos| {
                node.base.end = pos - 1;
                break :footer;
            }
            return error.UnexpectedToken;
        }

        log.debug("(doc) end {s}@{d}", .{ @tag_name(self.tree.tokens[node.base.end].id), node.base.end });

        return &node.base;
    }

    fn map(self: *Parser) ParseError!*Node {
        const node = try self.allocator.create(Node.Map);
        errdefer self.allocator.destroy(node);
        node.* = .{};
        node.base.tree = self.tree;
        node.base.start = self.token_it.pos;
        errdefer {
            for (node.values.items) |entry| {
                if (entry.value) |val| {
                    val.deinit(self.allocator);
                }
            }
            node.values.deinit(self.allocator);
        }

        log.debug("(map) begin {s}@{d}", .{ @tag_name(self.tree.tokens[node.base.start].id), node.base.start });

        const col = self.get_col(node.base.start);

        while (true) {
            self.eat_comments_and_space(&.{});

            // Parse key
            const key_pos = self.token_it.pos;
            if (self.get_col(key_pos) < col) {
                break;
            }

            const key = self.token_it.next() orelse return error.UnexpectedEof;
            switch (key.id) {
                .literal => {},
                .doc_start, .doc_end, .eof => {
                    self.token_it.seek_by(-1);
                    break;
                },
                else => {
                    // TODO key not being a literal
                    return error.Unhandled;
                },
            }

            log.debug("(map) key {s}@{d}", .{ self.tree.get_raw(key_pos, key_pos), key_pos });

            // Separator
            _ = try self.expect_token(.map_value_ind, &.{ .new_line, .comment });

            // Parse value
            const val = try self.value();
            errdefer if (val) |v| {
                v.deinit(self.allocator);
            };

            if (val) |v| {
                if (self.get_col(v.start) < self.get_col(key_pos)) {
                    return error.MalformedYaml;
                }
                if (v.cast(Node.Value)) |_| {
                    if (self.get_col(v.start) == self.get_col(key_pos)) {
                        return error.MalformedYaml;
                    }
                }
            }

            try node.values.append(self.allocator, .{
                .key = key_pos,
                .value = val,
            });
        }

        node.base.end = self.token_it.pos - 1;

        log.debug("(map) end {s}@{d}", .{ @tag_name(self.tree.tokens[node.base.end].id), node.base.end });

        return &node.base;
    }

    fn list(self: *Parser) ParseError!*Node {
        const node = try self.allocator.create(Node.List);
        errdefer self.allocator.destroy(node);
        node.* = .{};
        node.base.tree = self.tree;
        node.base.start = self.token_it.pos;
        errdefer {
            for (node.values.items) |val| {
                val.deinit(self.allocator);
            }
            node.values.deinit(self.allocator);
        }

        log.debug("(list) begin {s}@{d}", .{ @tag_name(self.tree.tokens[node.base.start].id), node.base.start });

        while (true) {
            self.eat_comments_and_space(&.{});

            _ = self.eat_token(.seq_item_ind, &.{}) orelse break;

            const val = (try self.value()) orelse return error.MalformedYaml;
            try node.values.append(self.allocator, val);
        }

        node.base.end = self.token_it.pos - 1;

        log.debug("(list) end {s}@{d}", .{ @tag_name(self.tree.tokens[node.base.end].id), node.base.end });

        return &node.base;
    }

    fn list_bracketed(self: *Parser) ParseError!*Node {
        const node = try self.allocator.create(Node.List);
        errdefer self.allocator.destroy(node);
        node.* = .{};
        node.base.tree = self.tree;
        node.base.start = self.token_it.pos;
        errdefer {
            for (node.values.items) |val| {
                val.deinit(self.allocator);
            }
            node.values.deinit(self.allocator);
        }

        log.debug("(list) begin {s}@{d}", .{ @tag_name(self.tree.tokens[node.base.start].id), node.base.start });

        _ = try self.expect_token(.flow_seq_start, &.{});

        while (true) {
            self.eat_comments_and_space(&.{.comment});

            if (self.eat_token(.flow_seq_end, &.{.comment})) |pos| {
                node.base.end = pos;
                break;
            }
            _ = self.eat_token(.comma, &.{.comment});

            const val = (try self.value()) orelse return error.MalformedYaml;
            try node.values.append(self.allocator, val);
        }

        log.debug("(list) end {s}@{d}", .{ @tag_name(self.tree.tokens[node.base.end].id), node.base.end });

        return &node.base;
    }

    fn leaf_value(self: *Parser) ParseError!*Node {
        const node = try self.allocator.create(Node.Value);
        errdefer self.allocator.destroy(node);
        node.* = .{ .string_value = .{} };
        node.base.tree = self.tree;
        node.base.start = self.token_it.pos;
        errdefer node.string_value.deinit(self.allocator);

        // TODO handle multiline strings in new block scope
        while (self.token_it.next()) |tok| {
            switch (tok.id) {
                .single_quoted => {
                    node.base.end = self.token_it.pos - 1;
                    const raw = self.tree.get_raw(node.base.start, node.base.end);
                    try self.parse_single_quoted(node, raw);
                    break;
                },
                .double_quoted => {
                    node.base.end = self.token_it.pos - 1;
                    const raw = self.tree.get_raw(node.base.start, node.base.end);
                    try self.parse_double_quoted(node, raw);
                    break;
                },
                .literal => {},
                .space => {
                    const trailing = self.token_it.pos - 2;
                    self.eat_comments_and_space(&.{});
                    if (self.token_it.peek()) |peek| {
                        if (peek.id != .literal) {
                            node.base.end = trailing;
                            const raw = self.tree.get_raw(node.base.start, node.base.end);
                            try node.string_value.append_slice(self.allocator, raw);
                            break;
                        }
                    }
                },
                else => {
                    self.token_it.seek_by(-1);
                    node.base.end = self.token_it.pos - 1;
                    const raw = self.tree.get_raw(node.base.start, node.base.end);
                    try node.string_value.append_slice(self.allocator, raw);
                    break;
                },
            }
        }

        log.debug("(leaf) {s}", .{self.tree.get_raw(node.base.start, node.base.end)});

        return &node.base;
    }

    fn eat_comments_and_space(self: *Parser, comptime exclusions: []const Token.Id) void {
        log.debug("eat_comments_and_space", .{});
        outer: while (self.token_it.next()) |token| {
            log.debug("  (token '{s}')", .{@tag_name(token.id)});
            switch (token.id) {
                .comment, .space, .new_line => |space| {
                    inline for (exclusions) |excl| {
                        if (excl == space) {
                            self.token_it.seek_by(-1);
                            break :outer;
                        }
                    } else continue;
                },
                else => {
                    self.token_it.seek_by(-1);
                    break;
                },
            }
        }
    }

    fn eat_token(self: *Parser, id: Token.Id, comptime exclusions: []const Token.Id) ?TokenIndex {
        log.debug("eat_token('{s}')", .{@tag_name(id)});
        self.eat_comments_and_space(exclusions);
        const pos = self.token_it.pos;
        const token = self.token_it.next() orelse return null;
        if (token.id == id) {
            log.debug("  (found at {d})", .{pos});
            return pos;
        } else {
            log.debug("  (not found)", .{});
            self.token_it.seek_by(-1);
            return null;
        }
    }

    fn expect_token(self: *Parser, id: Token.Id, comptime exclusions: []const Token.Id) ParseError!TokenIndex {
        log.debug("expect_token('{s}')", .{@tag_name(id)});
        return self.eat_token(id, exclusions) orelse error.UnexpectedToken;
    }

    fn get_line(self: *Parser, index: TokenIndex) usize {
        return self.line_cols.get(index).?.line;
    }

    fn get_col(self: *Parser, index: TokenIndex) usize {
        return self.line_cols.get(index).?.col;
    }

    fn parse_single_quoted(self: *Parser, node: *Node.Value, raw: []const u8) ParseError!void {
        assert(raw[0] == '\'' and raw[raw.len - 1] == '\'');

        const raw_no_quotes = raw[1 .. raw.len - 1];
        try node.string_value.ensure_total_capacity(self.allocator, raw_no_quotes.len);

        var state: enum {
            start,
            escape,
        } = .start;
        var index: usize = 0;

        while (index < raw_no_quotes.len) : (index += 1) {
            const c = raw_no_quotes[index];
            switch (state) {
                .start => switch (c) {
                    '\'' => {
                        state = .escape;
                    },
                    else => {
                        node.string_value.append_assume_capacity(c);
                    },
                },
                .escape => switch (c) {
                    '\'' => {
                        state = .start;
                        node.string_value.append_assume_capacity(c);
                    },
                    else => return error.InvalidEscapeSequence,
                },
            }
        }
    }

    fn parse_double_quoted(self: *Parser, node: *Node.Value, raw: []const u8) ParseError!void {
        assert(raw[0] == '"' and raw[raw.len - 1] == '"');

        const raw_no_quotes = raw[1 .. raw.len - 1];
        try node.string_value.ensure_total_capacity(self.allocator, raw_no_quotes.len);

        var state: enum {
            start,
            escape,
        } = .start;

        var index: usize = 0;
        while (index < raw_no_quotes.len) : (index += 1) {
            const c = raw_no_quotes[index];
            switch (state) {
                .start => switch (c) {
                    '\\' => {
                        state = .escape;
                    },
                    else => {
                        node.string_value.append_assume_capacity(c);
                    },
                },
                .escape => switch (c) {
                    'n' => {
                        state = .start;
                        node.string_value.append_assume_capacity('\n');
                    },
                    't' => {
                        state = .start;
                        node.string_value.append_assume_capacity('\t');
                    },
                    '"' => {
                        state = .start;
                        node.string_value.append_assume_capacity('"');
                    },
                    else => return error.InvalidEscapeSequence,
                },
            }
        }
    }
};

test {
    std.testing.ref_all_decls(@This());
    _ = @import("parse/test.zig");
}
