const std = @import("std");
const Document = @import("Document.zig");
const Node = Document.Node;

/// A Markdown document renderer.
///
/// Each concrete `Renderer` type has a `render_default` function, with the
/// intention that custom `render_fn` implementations can call `render_default`
/// for node types for which they require no special rendering.
pub fn Renderer(comptime Writer: type, comptime Context: type) type {
    return struct {
        render_fn: *const fn (
            r: Self,
            doc: Document,
            node: Node.Index,
            writer: Writer,
        ) Writer.Error!void = render_default,
        context: Context,

        const Self = @This();

        pub fn render(r: Self, doc: Document, writer: Writer) Writer.Error!void {
            try r.render_fn(r, doc, .root, writer);
        }

        pub fn render_default(
            r: Self,
            doc: Document,
            node: Node.Index,
            writer: Writer,
        ) Writer.Error!void {
            const data = doc.nodes.items(.data)[@int_from_enum(node)];
            switch (doc.nodes.items(.tag)[@int_from_enum(node)]) {
                .root => {
                    for (doc.extra_children(data.container.children)) |child| {
                        try r.render_fn(r, doc, child, writer);
                    }
                },
                .list => {
                    if (data.list.start.as_number()) |start| {
                        if (start == 1) {
                            try writer.write_all("<ol>\n");
                        } else {
                            try writer.print("<ol start=\"{}\">\n", .{start});
                        }
                    } else {
                        try writer.write_all("<ul>\n");
                    }
                    for (doc.extra_children(data.list.children)) |child| {
                        try r.render_fn(r, doc, child, writer);
                    }
                    if (data.list.start.as_number() != null) {
                        try writer.write_all("</ol>\n");
                    } else {
                        try writer.write_all("</ul>\n");
                    }
                },
                .list_item => {
                    try writer.write_all("<li>");
                    for (doc.extra_children(data.list_item.children)) |child| {
                        if (data.list_item.tight and doc.nodes.items(.tag)[@int_from_enum(child)] == .paragraph) {
                            const para_data = doc.nodes.items(.data)[@int_from_enum(child)];
                            for (doc.extra_children(para_data.container.children)) |para_child| {
                                try r.render_fn(r, doc, para_child, writer);
                            }
                        } else {
                            try r.render_fn(r, doc, child, writer);
                        }
                    }
                    try writer.write_all("</li>\n");
                },
                .table => {
                    try writer.write_all("<table>\n");
                    for (doc.extra_children(data.container.children)) |child| {
                        try r.render_fn(r, doc, child, writer);
                    }
                    try writer.write_all("</table>\n");
                },
                .table_row => {
                    try writer.write_all("<tr>\n");
                    for (doc.extra_children(data.container.children)) |child| {
                        try r.render_fn(r, doc, child, writer);
                    }
                    try writer.write_all("</tr>\n");
                },
                .table_cell => {
                    if (data.table_cell.info.header) {
                        try writer.write_all("<th");
                    } else {
                        try writer.write_all("<td");
                    }
                    switch (data.table_cell.info.alignment) {
                        .unset => try writer.write_all(">"),
                        else => |a| try writer.print(" style=\"text-align: {s}\">", .{@tag_name(a)}),
                    }

                    for (doc.extra_children(data.table_cell.children)) |child| {
                        try r.render_fn(r, doc, child, writer);
                    }

                    if (data.table_cell.info.header) {
                        try writer.write_all("</th>\n");
                    } else {
                        try writer.write_all("</td>\n");
                    }
                },
                .heading => {
                    try writer.print("<h{}>", .{data.heading.level});
                    for (doc.extra_children(data.heading.children)) |child| {
                        try r.render_fn(r, doc, child, writer);
                    }
                    try writer.print("</h{}>\n", .{data.heading.level});
                },
                .code_block => {
                    const content = doc.string(data.code_block.content);
                    try writer.print("<pre><code>{}</code></pre>\n", .{fmt_html(content)});
                },
                .blockquote => {
                    try writer.write_all("<blockquote>\n");
                    for (doc.extra_children(data.container.children)) |child| {
                        try r.render_fn(r, doc, child, writer);
                    }
                    try writer.write_all("</blockquote>\n");
                },
                .paragraph => {
                    try writer.write_all("<p>");
                    for (doc.extra_children(data.container.children)) |child| {
                        try r.render_fn(r, doc, child, writer);
                    }
                    try writer.write_all("</p>\n");
                },
                .thematic_break => {
                    try writer.write_all("<hr />\n");
                },
                .link => {
                    const target = doc.string(data.link.target);
                    try writer.print("<a href=\"{}\">", .{fmt_html(target)});
                    for (doc.extra_children(data.link.children)) |child| {
                        try r.render_fn(r, doc, child, writer);
                    }
                    try writer.write_all("</a>");
                },
                .autolink => {
                    const target = doc.string(data.text.content);
                    try writer.print("<a href=\"{0}\">{0}</a>", .{fmt_html(target)});
                },
                .image => {
                    const target = doc.string(data.link.target);
                    try writer.print("<img src=\"{}\" alt=\"", .{fmt_html(target)});
                    for (doc.extra_children(data.link.children)) |child| {
                        try render_inline_node_text(doc, child, writer);
                    }
                    try writer.write_all("\" />");
                },
                .strong => {
                    try writer.write_all("<strong>");
                    for (doc.extra_children(data.container.children)) |child| {
                        try r.render_fn(r, doc, child, writer);
                    }
                    try writer.write_all("</strong>");
                },
                .emphasis => {
                    try writer.write_all("<em>");
                    for (doc.extra_children(data.container.children)) |child| {
                        try r.render_fn(r, doc, child, writer);
                    }
                    try writer.write_all("</em>");
                },
                .code_span => {
                    const content = doc.string(data.text.content);
                    try writer.print("<code>{}</code>", .{fmt_html(content)});
                },
                .text => {
                    const content = doc.string(data.text.content);
                    try writer.print("{}", .{fmt_html(content)});
                },
                .line_break => {
                    try writer.write_all("<br />\n");
                },
            }
        }
    };
}

/// Renders an inline node as plain text. Asserts that the node is an inline and
/// has no non-inline children.
pub fn render_inline_node_text(
    doc: Document,
    node: Node.Index,
    writer: anytype,
) @TypeOf(writer).Error!void {
    const data = doc.nodes.items(.data)[@int_from_enum(node)];
    switch (doc.nodes.items(.tag)[@int_from_enum(node)]) {
        .root,
        .list,
        .list_item,
        .table,
        .table_row,
        .table_cell,
        .heading,
        .code_block,
        .blockquote,
        .paragraph,
        .thematic_break,
        => unreachable, // Blocks

        .link, .image => {
            for (doc.extra_children(data.link.children)) |child| {
                try render_inline_node_text(doc, child, writer);
            }
        },
        .strong => {
            for (doc.extra_children(data.container.children)) |child| {
                try render_inline_node_text(doc, child, writer);
            }
        },
        .emphasis => {
            for (doc.extra_children(data.container.children)) |child| {
                try render_inline_node_text(doc, child, writer);
            }
        },
        .autolink, .code_span, .text => {
            const content = doc.string(data.text.content);
            try writer.print("{}", .{fmt_html(content)});
        },
        .line_break => {
            try writer.write_all("\n");
        },
    }
}

pub fn fmt_html(bytes: []const u8) std.fmt.Formatter(format_html) {
    return .{ .data = bytes };
}

fn format_html(
    bytes: []const u8,
    comptime fmt: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = fmt;
    _ = options;
    for (bytes) |b| {
        switch (b) {
            '<' => try writer.write_all("&lt;"),
            '>' => try writer.write_all("&gt;"),
            '&' => try writer.write_all("&amp;"),
            '"' => try writer.write_all("&quot;"),
            else => try writer.write_byte(b),
        }
    }
}
