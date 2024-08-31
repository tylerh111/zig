const std = @import("std");
const builtin = @import("builtin");
const io = std.io;
const fs = std.fs;
const process = std.process;
const ChildProcess = std.process.Child;
const Progress = std.Progress;
const print = std.debug.print;
const mem = std.mem;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const get_external_executor = std.zig.system.get_external_executor;
const fatal = std.zig.fatal;

const max_doc_file_size = 10 * 1024 * 1024;

const obj_ext = builtin.object_format.file_ext(builtin.cpu.arch);

const usage =
    \\Usage: docgen [options] input output
    \\
    \\   Generates an HTML document from a docgen template.
    \\
    \\Options:
    \\   --code-dir dir         Path to directory containing code example outputs
    \\   -h, --help             Print this help and exit
    \\
;

pub fn main() !void {
    var arena_instance = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_instance.deinit();

    const arena = arena_instance.allocator();

    var args_it = try process.args_with_allocator(arena);
    if (!args_it.skip()) @panic("expected self arg");

    var opt_code_dir: ?[]const u8 = null;
    var opt_input: ?[]const u8 = null;
    var opt_output: ?[]const u8 = null;

    while (args_it.next()) |arg| {
        if (mem.starts_with(u8, arg, "-")) {
            if (mem.eql(u8, arg, "-h") or mem.eql(u8, arg, "--help")) {
                const stdout = io.get_std_out().writer();
                try stdout.write_all(usage);
                process.exit(0);
            } else if (mem.eql(u8, arg, "--code-dir")) {
                if (args_it.next()) |param| {
                    opt_code_dir = param;
                } else {
                    fatal("expected parameter after --code-dir", .{});
                }
            } else {
                fatal("unrecognized option: '{s}'", .{arg});
            }
        } else if (opt_input == null) {
            opt_input = arg;
        } else if (opt_output == null) {
            opt_output = arg;
        } else {
            fatal("unexpected positional argument: '{s}'", .{arg});
        }
    }
    const input_path = opt_input orelse fatal("missing input file", .{});
    const output_path = opt_output orelse fatal("missing output file", .{});
    const code_dir_path = opt_code_dir orelse fatal("missing --code-dir argument", .{});

    var in_file = try fs.cwd().open_file(input_path, .{});
    defer in_file.close();

    var out_file = try fs.cwd().create_file(output_path, .{});
    defer out_file.close();

    var code_dir = try fs.cwd().open_dir(code_dir_path, .{});
    defer code_dir.close();

    const input_file_bytes = try in_file.reader().read_all_alloc(arena, max_doc_file_size);

    var buffered_writer = io.buffered_writer(out_file.writer());

    var tokenizer = Tokenizer.init(input_path, input_file_bytes);
    var toc = try gen_toc(arena, &tokenizer);

    try gen_html(arena, &tokenizer, &toc, code_dir, buffered_writer.writer());
    try buffered_writer.flush();
}

const Token = struct {
    id: Id,
    start: usize,
    end: usize,

    const Id = enum {
        invalid,
        content,
        bracket_open,
        tag_content,
        separator,
        bracket_close,
        eof,
    };
};

const Tokenizer = struct {
    buffer: []const u8,
    index: usize,
    state: State,
    source_file_name: []const u8,

    const State = enum {
        start,
        l_bracket,
        hash,
        tag_name,
        eof,
    };

    fn init(source_file_name: []const u8, buffer: []const u8) Tokenizer {
        return Tokenizer{
            .buffer = buffer,
            .index = 0,
            .state = .start,
            .source_file_name = source_file_name,
        };
    }

    fn next(self: *Tokenizer) Token {
        var result = Token{
            .id = .eof,
            .start = self.index,
            .end = undefined,
        };
        while (self.index < self.buffer.len) : (self.index += 1) {
            const c = self.buffer[self.index];
            switch (self.state) {
                .start => switch (c) {
                    '{' => {
                        self.state = .l_bracket;
                    },
                    else => {
                        result.id = .content;
                    },
                },
                .l_bracket => switch (c) {
                    '#' => {
                        if (result.id != .eof) {
                            self.index -= 1;
                            self.state = .start;
                            break;
                        } else {
                            result.id = .bracket_open;
                            self.index += 1;
                            self.state = .tag_name;
                            break;
                        }
                    },
                    else => {
                        result.id = .content;
                        self.state = .start;
                    },
                },
                .tag_name => switch (c) {
                    '|' => {
                        if (result.id != .eof) {
                            break;
                        } else {
                            result.id = .separator;
                            self.index += 1;
                            break;
                        }
                    },
                    '#' => {
                        self.state = .hash;
                    },
                    else => {
                        result.id = .tag_content;
                    },
                },
                .hash => switch (c) {
                    '}' => {
                        if (result.id != .eof) {
                            self.index -= 1;
                            self.state = .tag_name;
                            break;
                        } else {
                            result.id = .bracket_close;
                            self.index += 1;
                            self.state = .start;
                            break;
                        }
                    },
                    else => {
                        result.id = .tag_content;
                        self.state = .tag_name;
                    },
                },
                .eof => unreachable,
            }
        } else {
            switch (self.state) {
                .start, .l_bracket, .eof => {},
                else => {
                    result.id = .invalid;
                },
            }
            self.state = .eof;
        }
        result.end = self.index;
        return result;
    }

    const Location = struct {
        line: usize,
        column: usize,
        line_start: usize,
        line_end: usize,
    };

    fn get_token_location(self: *Tokenizer, token: Token) Location {
        var loc = Location{
            .line = 0,
            .column = 0,
            .line_start = 0,
            .line_end = 0,
        };
        for (self.buffer, 0..) |c, i| {
            if (i == token.start) {
                loc.line_end = i;
                while (loc.line_end < self.buffer.len and self.buffer[loc.line_end] != '\n') : (loc.line_end += 1) {}
                return loc;
            }
            if (c == '\n') {
                loc.line += 1;
                loc.column = 0;
                loc.line_start = i + 1;
            } else {
                loc.column += 1;
            }
        }
        return loc;
    }
};

fn parse_error(tokenizer: *Tokenizer, token: Token, comptime fmt: []const u8, args: anytype) anyerror {
    const loc = tokenizer.get_token_location(token);
    const args_prefix = .{ tokenizer.source_file_name, loc.line + 1, loc.column + 1 };
    print("{s}:{d}:{d}: error: " ++ fmt ++ "\n", args_prefix ++ args);
    if (loc.line_start <= loc.line_end) {
        print("{s}\n", .{tokenizer.buffer[loc.line_start..loc.line_end]});
        {
            var i: usize = 0;
            while (i < loc.column) : (i += 1) {
                print(" ", .{});
            }
        }
        {
            const caret_count = @min(token.end, loc.line_end) - token.start;
            var i: usize = 0;
            while (i < caret_count) : (i += 1) {
                print("~", .{});
            }
        }
        print("\n", .{});
    }
    return error.ParseError;
}

fn assert_token(tokenizer: *Tokenizer, token: Token, id: Token.Id) !void {
    if (token.id != id) {
        return parse_error(tokenizer, token, "expected {s}, found {s}", .{ @tag_name(id), @tag_name(token.id) });
    }
}

fn eat_token(tokenizer: *Tokenizer, id: Token.Id) !Token {
    const token = tokenizer.next();
    try assert_token(tokenizer, token, id);
    return token;
}

const HeaderOpen = struct {
    name: []const u8,
    url: []const u8,
    n: usize,
};

const SeeAlsoItem = struct {
    name: []const u8,
    token: Token,
};

const Code = struct {
    name: []const u8,
    token: Token,
};

const Link = struct {
    url: []const u8,
    name: []const u8,
    token: Token,
};

const SyntaxBlock = struct {
    source_type: SourceType,
    name: []const u8,
    source_token: Token,

    const SourceType = enum {
        zig,
        c,
        peg,
        javascript,
    };
};

const Node = union(enum) {
    Content: []const u8,
    Nav,
    Builtin: Token,
    HeaderOpen: HeaderOpen,
    SeeAlso: []const SeeAlsoItem,
    Code: Code,
    Link: Link,
    InlineSyntax: Token,
    Shell: Token,
    SyntaxBlock: SyntaxBlock,
};

const Toc = struct {
    nodes: []Node,
    toc: []u8,
    urls: std.StringHashMap(Token),
};

const Action = enum {
    open,
    close,
};

fn gen_toc(allocator: Allocator, tokenizer: *Tokenizer) !Toc {
    var urls = std.StringHashMap(Token).init(allocator);
    errdefer urls.deinit();

    var header_stack_size: usize = 0;
    var last_action: Action = .open;
    var last_columns: ?u8 = null;

    var toc_buf = std.ArrayList(u8).init(allocator);
    defer toc_buf.deinit();

    var toc = toc_buf.writer();

    var nodes = std.ArrayList(Node).init(allocator);
    defer nodes.deinit();

    try toc.write_byte('\n');

    while (true) {
        const token = tokenizer.next();
        switch (token.id) {
            .eof => {
                if (header_stack_size != 0) {
                    return parse_error(tokenizer, token, "unbalanced headers", .{});
                }
                try toc.write_all("    </ul>\n");
                break;
            },
            .content => {
                try nodes.append(Node{ .Content = tokenizer.buffer[token.start..token.end] });
            },
            .bracket_open => {
                const tag_token = try eat_token(tokenizer, .tag_content);
                const tag_name = tokenizer.buffer[tag_token.start..tag_token.end];

                if (mem.eql(u8, tag_name, "nav")) {
                    _ = try eat_token(tokenizer, .bracket_close);

                    try nodes.append(Node.Nav);
                } else if (mem.eql(u8, tag_name, "builtin")) {
                    _ = try eat_token(tokenizer, .bracket_close);
                    try nodes.append(Node{ .Builtin = tag_token });
                } else if (mem.eql(u8, tag_name, "header_open")) {
                    _ = try eat_token(tokenizer, .separator);
                    const content_token = try eat_token(tokenizer, .tag_content);
                    const content = tokenizer.buffer[content_token.start..content_token.end];
                    var columns: ?u8 = null;
                    while (true) {
                        const bracket_tok = tokenizer.next();
                        switch (bracket_tok.id) {
                            .bracket_close => break,
                            .separator => continue,
                            .tag_content => {
                                const param = tokenizer.buffer[bracket_tok.start..bracket_tok.end];
                                if (mem.eql(u8, param, "2col")) {
                                    columns = 2;
                                } else {
                                    return parse_error(
                                        tokenizer,
                                        bracket_tok,
                                        "unrecognized header_open param: {s}",
                                        .{param},
                                    );
                                }
                            },
                            else => return parse_error(tokenizer, bracket_tok, "invalid header_open token", .{}),
                        }
                    }

                    header_stack_size += 1;

                    const urlized = try urlize(allocator, content);
                    try nodes.append(Node{
                        .HeaderOpen = HeaderOpen{
                            .name = content,
                            .url = urlized,
                            .n = header_stack_size + 1, // highest-level section headers start at h2
                        },
                    });
                    if (try urls.fetch_put(urlized, tag_token)) |kv| {
                        parse_error(tokenizer, tag_token, "duplicate header url: #{s}", .{urlized}) catch {};
                        parse_error(tokenizer, kv.value, "other tag here", .{}) catch {};
                        return error.ParseError;
                    }
                    if (last_action == .open) {
                        try toc.write_byte('\n');
                        try toc.write_byte_ntimes(' ', header_stack_size * 4);
                        if (last_columns) |n| {
                            try toc.print("<ul style=\"columns: {}\">\n", .{n});
                        } else {
                            try toc.write_all("<ul>\n");
                        }
                    } else {
                        last_action = .open;
                    }
                    last_columns = columns;
                    try toc.write_byte_ntimes(' ', 4 + header_stack_size * 4);
                    try toc.print("<li><a id=\"toc-{s}\" href=\"#{s}\">{s}</a>", .{ urlized, urlized, content });
                } else if (mem.eql(u8, tag_name, "header_close")) {
                    if (header_stack_size == 0) {
                        return parse_error(tokenizer, tag_token, "unbalanced close header", .{});
                    }
                    header_stack_size -= 1;
                    _ = try eat_token(tokenizer, .bracket_close);

                    if (last_action == .close) {
                        try toc.write_byte_ntimes(' ', 8 + header_stack_size * 4);
                        try toc.write_all("</ul></li>\n");
                    } else {
                        try toc.write_all("</li>\n");
                        last_action = .close;
                    }
                } else if (mem.eql(u8, tag_name, "see_also")) {
                    var list = std.ArrayList(SeeAlsoItem).init(allocator);
                    errdefer list.deinit();

                    while (true) {
                        const see_also_tok = tokenizer.next();
                        switch (see_also_tok.id) {
                            .tag_content => {
                                const content = tokenizer.buffer[see_also_tok.start..see_also_tok.end];
                                try list.append(SeeAlsoItem{
                                    .name = content,
                                    .token = see_also_tok,
                                });
                            },
                            .separator => {},
                            .bracket_close => {
                                try nodes.append(Node{ .SeeAlso = try list.to_owned_slice() });
                                break;
                            },
                            else => return parse_error(tokenizer, see_also_tok, "invalid see_also token", .{}),
                        }
                    }
                } else if (mem.eql(u8, tag_name, "link")) {
                    _ = try eat_token(tokenizer, .separator);
                    const name_tok = try eat_token(tokenizer, .tag_content);
                    const name = tokenizer.buffer[name_tok.start..name_tok.end];

                    const url_name = blk: {
                        const tok = tokenizer.next();
                        switch (tok.id) {
                            .bracket_close => break :blk name,
                            .separator => {
                                const explicit_text = try eat_token(tokenizer, .tag_content);
                                _ = try eat_token(tokenizer, .bracket_close);
                                break :blk tokenizer.buffer[explicit_text.start..explicit_text.end];
                            },
                            else => return parse_error(tokenizer, tok, "invalid link token", .{}),
                        }
                    };

                    try nodes.append(Node{
                        .Link = Link{
                            .url = try urlize(allocator, url_name),
                            .name = name,
                            .token = name_tok,
                        },
                    });
                } else if (mem.eql(u8, tag_name, "code")) {
                    _ = try eat_token(tokenizer, .separator);
                    const name_tok = try eat_token(tokenizer, .tag_content);
                    _ = try eat_token(tokenizer, .bracket_close);
                    try nodes.append(.{
                        .Code = .{
                            .name = tokenizer.buffer[name_tok.start..name_tok.end],
                            .token = name_tok,
                        },
                    });
                } else if (mem.eql(u8, tag_name, "syntax")) {
                    _ = try eat_token(tokenizer, .bracket_close);
                    const content_tok = try eat_token(tokenizer, .content);
                    _ = try eat_token(tokenizer, .bracket_open);
                    const end_syntax_tag = try eat_token(tokenizer, .tag_content);
                    const end_tag_name = tokenizer.buffer[end_syntax_tag.start..end_syntax_tag.end];
                    if (!mem.eql(u8, end_tag_name, "endsyntax")) {
                        return parse_error(
                            tokenizer,
                            end_syntax_tag,
                            "invalid token inside syntax: {s}",
                            .{end_tag_name},
                        );
                    }
                    _ = try eat_token(tokenizer, .bracket_close);
                    try nodes.append(Node{ .InlineSyntax = content_tok });
                } else if (mem.eql(u8, tag_name, "shell_samp")) {
                    _ = try eat_token(tokenizer, .bracket_close);
                    const content_tok = try eat_token(tokenizer, .content);
                    _ = try eat_token(tokenizer, .bracket_open);
                    const end_syntax_tag = try eat_token(tokenizer, .tag_content);
                    const end_tag_name = tokenizer.buffer[end_syntax_tag.start..end_syntax_tag.end];
                    if (!mem.eql(u8, end_tag_name, "end_shell_samp")) {
                        return parse_error(
                            tokenizer,
                            end_syntax_tag,
                            "invalid token inside syntax: {s}",
                            .{end_tag_name},
                        );
                    }
                    _ = try eat_token(tokenizer, .bracket_close);
                    try nodes.append(Node{ .Shell = content_tok });
                } else if (mem.eql(u8, tag_name, "syntax_block")) {
                    _ = try eat_token(tokenizer, .separator);
                    const source_type_tok = try eat_token(tokenizer, .tag_content);
                    var name: []const u8 = "sample_code";
                    const maybe_sep = tokenizer.next();
                    switch (maybe_sep.id) {
                        .separator => {
                            const name_tok = try eat_token(tokenizer, .tag_content);
                            name = tokenizer.buffer[name_tok.start..name_tok.end];
                            _ = try eat_token(tokenizer, .bracket_close);
                        },
                        .bracket_close => {},
                        else => return parse_error(tokenizer, token, "invalid token", .{}),
                    }
                    const source_type_str = tokenizer.buffer[source_type_tok.start..source_type_tok.end];
                    var source_type: SyntaxBlock.SourceType = undefined;
                    if (mem.eql(u8, source_type_str, "zig")) {
                        source_type = SyntaxBlock.SourceType.zig;
                    } else if (mem.eql(u8, source_type_str, "c")) {
                        source_type = SyntaxBlock.SourceType.c;
                    } else if (mem.eql(u8, source_type_str, "peg")) {
                        source_type = SyntaxBlock.SourceType.peg;
                    } else if (mem.eql(u8, source_type_str, "javascript")) {
                        source_type = SyntaxBlock.SourceType.javascript;
                    } else {
                        return parse_error(tokenizer, source_type_tok, "unrecognized code kind: {s}", .{source_type_str});
                    }
                    const source_token = while (true) {
                        const content_tok = try eat_token(tokenizer, .content);
                        _ = try eat_token(tokenizer, .bracket_open);
                        const end_code_tag = try eat_token(tokenizer, .tag_content);
                        const end_tag_name = tokenizer.buffer[end_code_tag.start..end_code_tag.end];
                        if (mem.eql(u8, end_tag_name, "end_syntax_block")) {
                            _ = try eat_token(tokenizer, .bracket_close);
                            break content_tok;
                        } else {
                            return parse_error(
                                tokenizer,
                                end_code_tag,
                                "invalid token inside code_begin: {s}",
                                .{end_tag_name},
                            );
                        }
                        _ = try eat_token(tokenizer, .bracket_close);
                    };
                    try nodes.append(Node{ .SyntaxBlock = SyntaxBlock{ .source_type = source_type, .name = name, .source_token = source_token } });
                } else {
                    return parse_error(tokenizer, tag_token, "unrecognized tag name: {s}", .{tag_name});
                }
            },
            else => return parse_error(tokenizer, token, "invalid token", .{}),
        }
    }

    return Toc{
        .nodes = try nodes.to_owned_slice(),
        .toc = try toc_buf.to_owned_slice(),
        .urls = urls,
    };
}

fn urlize(allocator: Allocator, input: []const u8) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();

    const out = buf.writer();
    for (input) |c| {
        switch (c) {
            'a'...'z', 'A'...'Z', '_', '-', '0'...'9' => {
                try out.write_byte(c);
            },
            ' ' => {
                try out.write_byte('-');
            },
            else => {},
        }
    }
    return try buf.to_owned_slice();
}

fn escape_html(allocator: Allocator, input: []const u8) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();

    const out = buf.writer();
    try write_escaped(out, input);
    return try buf.to_owned_slice();
}

fn write_escaped(out: anytype, input: []const u8) !void {
    for (input) |c| {
        try switch (c) {
            '&' => out.write_all("&amp;"),
            '<' => out.write_all("&lt;"),
            '>' => out.write_all("&gt;"),
            '"' => out.write_all("&quot;"),
            else => out.write_byte(c),
        };
    }
}

// Returns true if number is in slice.
fn in(slice: []const u8, number: u8) bool {
    for (slice) |n| {
        if (number == n) return true;
    }
    return false;
}

const builtin_types = [_][]const u8{
    "f16",          "f32",     "f64",        "f80",          "f128",
    "c_longdouble", "c_short", "c_ushort",   "c_int",        "c_uint",
    "c_long",       "c_ulong", "c_longlong", "c_ulonglong",  "c_char",
    "anyopaque",    "void",    "bool",       "isize",        "usize",
    "noreturn",     "type",    "anyerror",   "comptime_int", "comptime_float",
};

fn is_type(name: []const u8) bool {
    for (builtin_types) |t| {
        if (mem.eql(u8, t, name))
            return true;
    }
    return false;
}

fn write_escaped_lines(out: anytype, text: []const u8) !void {
    return write_escaped(out, text);
}

fn tokenize_and_print_raw(
    allocator: Allocator,
    docgen_tokenizer: *Tokenizer,
    out: anytype,
    source_token: Token,
    raw_src: []const u8,
) !void {
    const src_non_terminated = mem.trim(u8, raw_src, " \r\n");
    const src = try allocator.dupe_z(u8, src_non_terminated);

    try out.write_all("<code>");
    var tokenizer = std.zig.Tokenizer.init(src);
    var index: usize = 0;
    var next_tok_is_fn = false;
    while (true) {
        const prev_tok_was_fn = next_tok_is_fn;
        next_tok_is_fn = false;

        const token = tokenizer.next();
        if (mem.index_of(u8, src[index..token.loc.start], "//")) |comment_start_off| {
            // render one comment
            const comment_start = index + comment_start_off;
            const comment_end_off = mem.index_of(u8, src[comment_start..token.loc.start], "\n");
            const comment_end = if (comment_end_off) |o| comment_start + o else token.loc.start;

            try write_escaped_lines(out, src[index..comment_start]);
            try out.write_all("<span class=\"tok-comment\">");
            try write_escaped(out, src[comment_start..comment_end]);
            try out.write_all("</span>");
            index = comment_end;
            tokenizer.index = index;
            continue;
        }

        try write_escaped_lines(out, src[index..token.loc.start]);
        switch (token.tag) {
            .eof => break,

            .keyword_addrspace,
            .keyword_align,
            .keyword_and,
            .keyword_asm,
            .keyword_async,
            .keyword_await,
            .keyword_break,
            .keyword_catch,
            .keyword_comptime,
            .keyword_const,
            .keyword_continue,
            .keyword_defer,
            .keyword_else,
            .keyword_enum,
            .keyword_errdefer,
            .keyword_error,
            .keyword_export,
            .keyword_extern,
            .keyword_for,
            .keyword_if,
            .keyword_inline,
            .keyword_noalias,
            .keyword_noinline,
            .keyword_nosuspend,
            .keyword_opaque,
            .keyword_or,
            .keyword_orelse,
            .keyword_packed,
            .keyword_anyframe,
            .keyword_pub,
            .keyword_resume,
            .keyword_return,
            .keyword_linksection,
            .keyword_callconv,
            .keyword_struct,
            .keyword_suspend,
            .keyword_switch,
            .keyword_test,
            .keyword_threadlocal,
            .keyword_try,
            .keyword_union,
            .keyword_unreachable,
            .keyword_usingnamespace,
            .keyword_var,
            .keyword_volatile,
            .keyword_allowzero,
            .keyword_while,
            .keyword_anytype,
            => {
                try out.write_all("<span class=\"tok-kw\">");
                try write_escaped(out, src[token.loc.start..token.loc.end]);
                try out.write_all("</span>");
            },

            .keyword_fn => {
                try out.write_all("<span class=\"tok-kw\">");
                try write_escaped(out, src[token.loc.start..token.loc.end]);
                try out.write_all("</span>");
                next_tok_is_fn = true;
            },

            .string_literal,
            .multiline_string_literal_line,
            .char_literal,
            => {
                try out.write_all("<span class=\"tok-str\">");
                try write_escaped(out, src[token.loc.start..token.loc.end]);
                try out.write_all("</span>");
            },

            .builtin => {
                try out.write_all("<span class=\"tok-builtin\">");
                try write_escaped(out, src[token.loc.start..token.loc.end]);
                try out.write_all("</span>");
            },

            .doc_comment,
            .container_doc_comment,
            => {
                try out.write_all("<span class=\"tok-comment\">");
                try write_escaped(out, src[token.loc.start..token.loc.end]);
                try out.write_all("</span>");
            },

            .identifier => {
                const tok_bytes = src[token.loc.start..token.loc.end];
                if (mem.eql(u8, tok_bytes, "undefined") or
                    mem.eql(u8, tok_bytes, "null") or
                    mem.eql(u8, tok_bytes, "true") or
                    mem.eql(u8, tok_bytes, "false"))
                {
                    try out.write_all("<span class=\"tok-null\">");
                    try write_escaped(out, tok_bytes);
                    try out.write_all("</span>");
                } else if (prev_tok_was_fn) {
                    try out.write_all("<span class=\"tok-fn\">");
                    try write_escaped(out, tok_bytes);
                    try out.write_all("</span>");
                } else {
                    const is_int = blk: {
                        if (src[token.loc.start] != 'i' and src[token.loc.start] != 'u')
                            break :blk false;
                        var i = token.loc.start + 1;
                        if (i == token.loc.end)
                            break :blk false;
                        while (i != token.loc.end) : (i += 1) {
                            if (src[i] < '0' or src[i] > '9')
                                break :blk false;
                        }
                        break :blk true;
                    };
                    if (is_int or is_type(tok_bytes)) {
                        try out.write_all("<span class=\"tok-type\">");
                        try write_escaped(out, tok_bytes);
                        try out.write_all("</span>");
                    } else {
                        try write_escaped(out, tok_bytes);
                    }
                }
            },

            .number_literal => {
                try out.write_all("<span class=\"tok-number\">");
                try write_escaped(out, src[token.loc.start..token.loc.end]);
                try out.write_all("</span>");
            },

            .bang,
            .pipe,
            .pipe_pipe,
            .pipe_equal,
            .equal,
            .equal_equal,
            .equal_angle_bracket_right,
            .bang_equal,
            .l_paren,
            .r_paren,
            .semicolon,
            .percent,
            .percent_equal,
            .l_brace,
            .r_brace,
            .l_bracket,
            .r_bracket,
            .period,
            .period_asterisk,
            .ellipsis2,
            .ellipsis3,
            .caret,
            .caret_equal,
            .plus,
            .plus_plus,
            .plus_equal,
            .plus_percent,
            .plus_percent_equal,
            .plus_pipe,
            .plus_pipe_equal,
            .minus,
            .minus_equal,
            .minus_percent,
            .minus_percent_equal,
            .minus_pipe,
            .minus_pipe_equal,
            .asterisk,
            .asterisk_equal,
            .asterisk_asterisk,
            .asterisk_percent,
            .asterisk_percent_equal,
            .asterisk_pipe,
            .asterisk_pipe_equal,
            .arrow,
            .colon,
            .slash,
            .slash_equal,
            .comma,
            .ampersand,
            .ampersand_equal,
            .question_mark,
            .angle_bracket_left,
            .angle_bracket_left_equal,
            .angle_bracket_angle_bracket_left,
            .angle_bracket_angle_bracket_left_equal,
            .angle_bracket_angle_bracket_left_pipe,
            .angle_bracket_angle_bracket_left_pipe_equal,
            .angle_bracket_right,
            .angle_bracket_right_equal,
            .angle_bracket_angle_bracket_right,
            .angle_bracket_angle_bracket_right_equal,
            .tilde,
            => try write_escaped(out, src[token.loc.start..token.loc.end]),

            .invalid, .invalid_periodasterisks => return parse_error(
                docgen_tokenizer,
                source_token,
                "syntax error",
                .{},
            ),
        }
        index = token.loc.end;
    }
    try out.write_all("</code>");
}

fn tokenize_and_print(
    allocator: Allocator,
    docgen_tokenizer: *Tokenizer,
    out: anytype,
    source_token: Token,
) !void {
    const raw_src = docgen_tokenizer.buffer[source_token.start..source_token.end];
    return tokenize_and_print_raw(allocator, docgen_tokenizer, out, source_token, raw_src);
}

fn print_source_block(allocator: Allocator, docgen_tokenizer: *Tokenizer, out: anytype, syntax_block: SyntaxBlock) !void {
    const source_type = @tag_name(syntax_block.source_type);

    try out.print("<figure><figcaption class=\"{s}-cap\"><cite class=\"file\">{s}</cite></figcaption><pre>", .{ source_type, syntax_block.name });
    switch (syntax_block.source_type) {
        .zig => try tokenize_and_print(allocator, docgen_tokenizer, out, syntax_block.source_token),
        else => {
            const raw_source = docgen_tokenizer.buffer[syntax_block.source_token.start..syntax_block.source_token.end];
            const trimmed_raw_source = mem.trim(u8, raw_source, " \r\n");

            try out.write_all("<code>");
            try write_escaped_lines(out, trimmed_raw_source);
            try out.write_all("</code>");
        },
    }
    try out.write_all("</pre></figure>");
}

fn print_shell(out: anytype, shell_content: []const u8, escape: bool) !void {
    const trimmed_shell_content = mem.trim(u8, shell_content, " \r\n");
    try out.write_all("<figure><figcaption class=\"shell-cap\">Shell</figcaption><pre><samp>");
    var cmd_cont: bool = false;
    var iter = std.mem.split_scalar(u8, trimmed_shell_content, '\n');
    while (iter.next()) |orig_line| {
        const line = mem.trim_right(u8, orig_line, " \r");
        if (!cmd_cont and line.len > 1 and mem.eql(u8, line[0..2], "$ ") and line[line.len - 1] != '\\') {
            try out.write_all("$ <kbd>");
            const s = std.mem.trim_left(u8, line[1..], " ");
            if (escape) {
                try write_escaped(out, s);
            } else {
                try out.write_all(s);
            }
            try out.write_all("</kbd>" ++ "\n");
        } else if (!cmd_cont and line.len > 1 and mem.eql(u8, line[0..2], "$ ") and line[line.len - 1] == '\\') {
            try out.write_all("$ <kbd>");
            const s = std.mem.trim_left(u8, line[1..], " ");
            if (escape) {
                try write_escaped(out, s);
            } else {
                try out.write_all(s);
            }
            try out.write_all("\n");
            cmd_cont = true;
        } else if (line.len > 0 and line[line.len - 1] != '\\' and cmd_cont) {
            if (escape) {
                try write_escaped(out, line);
            } else {
                try out.write_all(line);
            }
            try out.write_all("</kbd>" ++ "\n");
            cmd_cont = false;
        } else {
            if (escape) {
                try write_escaped(out, line);
            } else {
                try out.write_all(line);
            }
            try out.write_all("\n");
        }
    }

    try out.write_all("</samp></pre></figure>");
}

fn gen_html(
    allocator: Allocator,
    tokenizer: *Tokenizer,
    toc: *Toc,
    code_dir: std.fs.Dir,
    out: anytype,
) !void {
    for (toc.nodes) |node| {
        switch (node) {
            .Content => |data| {
                try out.write_all(data);
            },
            .Link => |info| {
                if (!toc.urls.contains(info.url)) {
                    return parse_error(tokenizer, info.token, "url not found: {s}", .{info.url});
                }
                try out.print("<a href=\"#{s}\">{s}</a>", .{ info.url, info.name });
            },
            .Nav => {
                try out.write_all(toc.toc);
            },
            .Builtin => |tok| {
                try out.write_all("<figure><figcaption class=\"zig-cap\"><cite>@import(\"builtin\")</cite></figcaption><pre>");
                const builtin_code = @embed_file("builtin"); // 😎
                try tokenize_and_print_raw(allocator, tokenizer, out, tok, builtin_code);
                try out.write_all("</pre></figure>");
            },
            .HeaderOpen => |info| {
                try out.print(
                    "<h{d} id=\"{s}\"><a href=\"#toc-{s}\">{s}</a> <a class=\"hdr\" href=\"#{s}\">§</a></h{d}>\n",
                    .{ info.n, info.url, info.url, info.name, info.url, info.n },
                );
            },
            .SeeAlso => |items| {
                try out.write_all("<p>See also:</p><ul>\n");
                for (items) |item| {
                    const url = try urlize(allocator, item.name);
                    if (!toc.urls.contains(url)) {
                        return parse_error(tokenizer, item.token, "url not found: {s}", .{url});
                    }
                    try out.print("<li><a href=\"#{s}\">{s}</a></li>\n", .{ url, item.name });
                }
                try out.write_all("</ul>\n");
            },
            .InlineSyntax => |content_tok| {
                try tokenize_and_print(allocator, tokenizer, out, content_tok);
            },
            .Shell => |content_tok| {
                const raw_shell_content = tokenizer.buffer[content_tok.start..content_tok.end];
                try print_shell(out, raw_shell_content, true);
            },
            .SyntaxBlock => |syntax_block| {
                try print_source_block(allocator, tokenizer, out, syntax_block);
            },
            .Code => |code| {
                const out_basename = try std.fmt.alloc_print(allocator, "{s}.out", .{
                    fs.path.stem(code.name),
                });
                defer allocator.free(out_basename);

                const contents = code_dir.read_file_alloc(allocator, out_basename, std.math.max_int(u32)) catch |err| {
                    return parse_error(tokenizer, code.token, "unable to open '{s}': {s}", .{
                        out_basename, @errorName(err),
                    });
                };
                defer allocator.free(contents);

                try out.write_all(contents);
            },
        }
    }
}
