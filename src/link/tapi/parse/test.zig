const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const parse = @import("../parse.zig");

const Node = parse.Node;
const Tree = parse.Tree;

test "explicit doc" {
    const source =
        \\--- !tapi-tbd
        \\tbd-version: 4
        \\abc-version: 5
        \\...
    ;

    var tree = Tree.init(testing.allocator);
    defer tree.deinit();
    try tree.parse(source);

    try testing.expect_equal(tree.docs.items.len, 1);

    const doc = tree.docs.items[0].cast(Node.Doc).?;
    try testing.expect_equal(doc.base.start, 0);
    try testing.expect_equal(doc.base.end, tree.tokens.len - 2);

    const directive = tree.tokens[doc.directive.?];
    try testing.expect_equal(directive.id, .literal);
    try testing.expect_equal_strings("tapi-tbd", tree.source[directive.start..directive.end]);

    try testing.expect(doc.value != null);
    try testing.expect_equal(doc.value.?.tag, .map);

    const map = doc.value.?.cast(Node.Map).?;
    try testing.expect_equal(map.base.start, 5);
    try testing.expect_equal(map.base.end, 14);
    try testing.expect_equal(map.values.items.len, 2);

    {
        const entry = map.values.items[0];

        const key = tree.tokens[entry.key];
        try testing.expect_equal(key.id, .literal);
        try testing.expect_equal_strings("tbd-version", tree.source[key.start..key.end]);

        const value = entry.value.?.cast(Node.Value).?;
        const value_tok = tree.tokens[value.base.start];
        try testing.expect_equal(value_tok.id, .literal);
        try testing.expect_equal_strings("4", tree.source[value_tok.start..value_tok.end]);
    }

    {
        const entry = map.values.items[1];

        const key = tree.tokens[entry.key];
        try testing.expect_equal(key.id, .literal);
        try testing.expect_equal_strings("abc-version", tree.source[key.start..key.end]);

        const value = entry.value.?.cast(Node.Value).?;
        const value_tok = tree.tokens[value.base.start];
        try testing.expect_equal(value_tok.id, .literal);
        try testing.expect_equal_strings("5", tree.source[value_tok.start..value_tok.end]);
    }
}

test "leaf in quotes" {
    const source =
        \\key1: no quotes
        \\key2: 'single quoted'
        \\key3: "double quoted"
    ;

    var tree = Tree.init(testing.allocator);
    defer tree.deinit();
    try tree.parse(source);

    try testing.expect_equal(tree.docs.items.len, 1);

    const doc = tree.docs.items[0].cast(Node.Doc).?;
    try testing.expect_equal(doc.base.start, 0);
    try testing.expect_equal(doc.base.end, tree.tokens.len - 2);
    try testing.expect(doc.directive == null);

    try testing.expect(doc.value != null);
    try testing.expect_equal(doc.value.?.tag, .map);

    const map = doc.value.?.cast(Node.Map).?;
    try testing.expect_equal(map.base.start, 0);
    try testing.expect_equal(map.base.end, tree.tokens.len - 2);
    try testing.expect_equal(map.values.items.len, 3);

    {
        const entry = map.values.items[0];

        const key = tree.tokens[entry.key];
        try testing.expect_equal(key.id, .literal);
        try testing.expect_equal_strings("key1", tree.source[key.start..key.end]);

        const value = entry.value.?.cast(Node.Value).?;
        const start = tree.tokens[value.base.start];
        const end = tree.tokens[value.base.end];
        try testing.expect_equal(start.id, .literal);
        try testing.expect_equal(end.id, .literal);
        try testing.expect_equal_strings("no quotes", tree.source[start.start..end.end]);
    }
}

test "nested maps" {
    const source =
        \\key1:
        \\  key1_1 : value1_1
        \\  key1_2 : value1_2
        \\key2   : value2
    ;

    var tree = Tree.init(testing.allocator);
    defer tree.deinit();
    try tree.parse(source);

    try testing.expect_equal(tree.docs.items.len, 1);

    const doc = tree.docs.items[0].cast(Node.Doc).?;
    try testing.expect_equal(doc.base.start, 0);
    try testing.expect_equal(doc.base.end, tree.tokens.len - 2);
    try testing.expect(doc.directive == null);

    try testing.expect(doc.value != null);
    try testing.expect_equal(doc.value.?.tag, .map);

    const map = doc.value.?.cast(Node.Map).?;
    try testing.expect_equal(map.base.start, 0);
    try testing.expect_equal(map.base.end, tree.tokens.len - 2);
    try testing.expect_equal(map.values.items.len, 2);

    {
        const entry = map.values.items[0];

        const key = tree.tokens[entry.key];
        try testing.expect_equal(key.id, .literal);
        try testing.expect_equal_strings("key1", tree.source[key.start..key.end]);

        const nested_map = entry.value.?.cast(Node.Map).?;
        try testing.expect_equal(nested_map.base.start, 4);
        try testing.expect_equal(nested_map.base.end, 16);
        try testing.expect_equal(nested_map.values.items.len, 2);

        {
            const nested_entry = nested_map.values.items[0];

            const nested_key = tree.tokens[nested_entry.key];
            try testing.expect_equal(nested_key.id, .literal);
            try testing.expect_equal_strings("key1_1", tree.source[nested_key.start..nested_key.end]);

            const nested_value = nested_entry.value.?.cast(Node.Value).?;
            const nested_value_tok = tree.tokens[nested_value.base.start];
            try testing.expect_equal(nested_value_tok.id, .literal);
            try testing.expect_equal_strings(
                "value1_1",
                tree.source[nested_value_tok.start..nested_value_tok.end],
            );
        }

        {
            const nested_entry = nested_map.values.items[1];

            const nested_key = tree.tokens[nested_entry.key];
            try testing.expect_equal(nested_key.id, .literal);
            try testing.expect_equal_strings("key1_2", tree.source[nested_key.start..nested_key.end]);

            const nested_value = nested_entry.value.?.cast(Node.Value).?;
            const nested_value_tok = tree.tokens[nested_value.base.start];
            try testing.expect_equal(nested_value_tok.id, .literal);
            try testing.expect_equal_strings(
                "value1_2",
                tree.source[nested_value_tok.start..nested_value_tok.end],
            );
        }
    }

    {
        const entry = map.values.items[1];

        const key = tree.tokens[entry.key];
        try testing.expect_equal(key.id, .literal);
        try testing.expect_equal_strings("key2", tree.source[key.start..key.end]);

        const value = entry.value.?.cast(Node.Value).?;
        const value_tok = tree.tokens[value.base.start];
        try testing.expect_equal(value_tok.id, .literal);
        try testing.expect_equal_strings("value2", tree.source[value_tok.start..value_tok.end]);
    }
}

test "map of list of values" {
    const source =
        \\ints:
        \\  - 0
        \\  - 1
        \\  - 2
    ;
    var tree = Tree.init(testing.allocator);
    defer tree.deinit();
    try tree.parse(source);

    try testing.expect_equal(tree.docs.items.len, 1);

    const doc = tree.docs.items[0].cast(Node.Doc).?;
    try testing.expect_equal(doc.base.start, 0);
    try testing.expect_equal(doc.base.end, tree.tokens.len - 2);

    try testing.expect(doc.value != null);
    try testing.expect_equal(doc.value.?.tag, .map);

    const map = doc.value.?.cast(Node.Map).?;
    try testing.expect_equal(map.base.start, 0);
    try testing.expect_equal(map.base.end, tree.tokens.len - 2);
    try testing.expect_equal(map.values.items.len, 1);

    const entry = map.values.items[0];
    const key = tree.tokens[entry.key];
    try testing.expect_equal(key.id, .literal);
    try testing.expect_equal_strings("ints", tree.source[key.start..key.end]);

    const value = entry.value.?.cast(Node.List).?;
    try testing.expect_equal(value.base.start, 4);
    try testing.expect_equal(value.base.end, tree.tokens.len - 2);
    try testing.expect_equal(value.values.items.len, 3);

    {
        const elem = value.values.items[0].cast(Node.Value).?;
        const leaf = tree.tokens[elem.base.start];
        try testing.expect_equal(leaf.id, .literal);
        try testing.expect_equal_strings("0", tree.source[leaf.start..leaf.end]);
    }

    {
        const elem = value.values.items[1].cast(Node.Value).?;
        const leaf = tree.tokens[elem.base.start];
        try testing.expect_equal(leaf.id, .literal);
        try testing.expect_equal_strings("1", tree.source[leaf.start..leaf.end]);
    }

    {
        const elem = value.values.items[2].cast(Node.Value).?;
        const leaf = tree.tokens[elem.base.start];
        try testing.expect_equal(leaf.id, .literal);
        try testing.expect_equal_strings("2", tree.source[leaf.start..leaf.end]);
    }
}

test "map of list of maps" {
    const source =
        \\key1:
        \\- key2 : value2
        \\- key3 : value3
        \\- key4 : value4
    ;

    var tree = Tree.init(testing.allocator);
    defer tree.deinit();
    try tree.parse(source);

    try testing.expect_equal(tree.docs.items.len, 1);

    const doc = tree.docs.items[0].cast(Node.Doc).?;
    try testing.expect_equal(doc.base.start, 0);
    try testing.expect_equal(doc.base.end, tree.tokens.len - 2);

    try testing.expect(doc.value != null);
    try testing.expect_equal(doc.value.?.tag, .map);

    const map = doc.value.?.cast(Node.Map).?;
    try testing.expect_equal(map.base.start, 0);
    try testing.expect_equal(map.base.end, tree.tokens.len - 2);
    try testing.expect_equal(map.values.items.len, 1);

    const entry = map.values.items[0];
    const key = tree.tokens[entry.key];
    try testing.expect_equal(key.id, .literal);
    try testing.expect_equal_strings("key1", tree.source[key.start..key.end]);

    const value = entry.value.?.cast(Node.List).?;
    try testing.expect_equal(value.base.start, 3);
    try testing.expect_equal(value.base.end, tree.tokens.len - 2);
    try testing.expect_equal(value.values.items.len, 3);

    {
        const elem = value.values.items[0].cast(Node.Map).?;
        const nested = elem.values.items[0];
        const nested_key = tree.tokens[nested.key];
        try testing.expect_equal(nested_key.id, .literal);
        try testing.expect_equal_strings("key2", tree.source[nested_key.start..nested_key.end]);

        const nested_v = nested.value.?.cast(Node.Value).?;
        const leaf = tree.tokens[nested_v.base.start];
        try testing.expect_equal(leaf.id, .literal);
        try testing.expect_equal_strings("value2", tree.source[leaf.start..leaf.end]);
    }

    {
        const elem = value.values.items[1].cast(Node.Map).?;
        const nested = elem.values.items[0];
        const nested_key = tree.tokens[nested.key];
        try testing.expect_equal(nested_key.id, .literal);
        try testing.expect_equal_strings("key3", tree.source[nested_key.start..nested_key.end]);

        const nested_v = nested.value.?.cast(Node.Value).?;
        const leaf = tree.tokens[nested_v.base.start];
        try testing.expect_equal(leaf.id, .literal);
        try testing.expect_equal_strings("value3", tree.source[leaf.start..leaf.end]);
    }

    {
        const elem = value.values.items[2].cast(Node.Map).?;
        const nested = elem.values.items[0];
        const nested_key = tree.tokens[nested.key];
        try testing.expect_equal(nested_key.id, .literal);
        try testing.expect_equal_strings("key4", tree.source[nested_key.start..nested_key.end]);

        const nested_v = nested.value.?.cast(Node.Value).?;
        const leaf = tree.tokens[nested_v.base.start];
        try testing.expect_equal(leaf.id, .literal);
        try testing.expect_equal_strings("value4", tree.source[leaf.start..leaf.end]);
    }
}

test "list of lists" {
    const source =
        \\- [name        , hr, avg  ]
        \\- [Mark McGwire , 65, 0.278]
        \\- [Sammy Sosa   , 63, 0.288]
    ;

    var tree = Tree.init(testing.allocator);
    defer tree.deinit();
    try tree.parse(source);

    try testing.expect_equal(tree.docs.items.len, 1);

    const doc = tree.docs.items[0].cast(Node.Doc).?;
    try testing.expect_equal(doc.base.start, 0);
    try testing.expect_equal(doc.base.end, tree.tokens.len - 2);

    try testing.expect(doc.value != null);
    try testing.expect_equal(doc.value.?.tag, .list);

    const list = doc.value.?.cast(Node.List).?;
    try testing.expect_equal(list.base.start, 0);
    try testing.expect_equal(list.base.end, tree.tokens.len - 2);
    try testing.expect_equal(list.values.items.len, 3);

    {
        try testing.expect_equal(list.values.items[0].tag, .list);
        const nested = list.values.items[0].cast(Node.List).?;
        try testing.expect_equal(nested.values.items.len, 3);

        {
            try testing.expect_equal(nested.values.items[0].tag, .value);
            const value = nested.values.items[0].cast(Node.Value).?;
            const leaf = tree.tokens[value.base.start];
            try testing.expect_equal_strings("name", tree.source[leaf.start..leaf.end]);
        }

        {
            try testing.expect_equal(nested.values.items[1].tag, .value);
            const value = nested.values.items[1].cast(Node.Value).?;
            const leaf = tree.tokens[value.base.start];
            try testing.expect_equal_strings("hr", tree.source[leaf.start..leaf.end]);
        }

        {
            try testing.expect_equal(nested.values.items[2].tag, .value);
            const value = nested.values.items[2].cast(Node.Value).?;
            const leaf = tree.tokens[value.base.start];
            try testing.expect_equal_strings("avg", tree.source[leaf.start..leaf.end]);
        }
    }

    {
        try testing.expect_equal(list.values.items[1].tag, .list);
        const nested = list.values.items[1].cast(Node.List).?;
        try testing.expect_equal(nested.values.items.len, 3);

        {
            try testing.expect_equal(nested.values.items[0].tag, .value);
            const value = nested.values.items[0].cast(Node.Value).?;
            const start = tree.tokens[value.base.start];
            const end = tree.tokens[value.base.end];
            try testing.expect_equal_strings("Mark McGwire", tree.source[start.start..end.end]);
        }

        {
            try testing.expect_equal(nested.values.items[1].tag, .value);
            const value = nested.values.items[1].cast(Node.Value).?;
            const leaf = tree.tokens[value.base.start];
            try testing.expect_equal_strings("65", tree.source[leaf.start..leaf.end]);
        }

        {
            try testing.expect_equal(nested.values.items[2].tag, .value);
            const value = nested.values.items[2].cast(Node.Value).?;
            const leaf = tree.tokens[value.base.start];
            try testing.expect_equal_strings("0.278", tree.source[leaf.start..leaf.end]);
        }
    }

    {
        try testing.expect_equal(list.values.items[2].tag, .list);
        const nested = list.values.items[2].cast(Node.List).?;
        try testing.expect_equal(nested.values.items.len, 3);

        {
            try testing.expect_equal(nested.values.items[0].tag, .value);
            const value = nested.values.items[0].cast(Node.Value).?;
            const start = tree.tokens[value.base.start];
            const end = tree.tokens[value.base.end];
            try testing.expect_equal_strings("Sammy Sosa", tree.source[start.start..end.end]);
        }

        {
            try testing.expect_equal(nested.values.items[1].tag, .value);
            const value = nested.values.items[1].cast(Node.Value).?;
            const leaf = tree.tokens[value.base.start];
            try testing.expect_equal_strings("63", tree.source[leaf.start..leaf.end]);
        }

        {
            try testing.expect_equal(nested.values.items[2].tag, .value);
            const value = nested.values.items[2].cast(Node.Value).?;
            const leaf = tree.tokens[value.base.start];
            try testing.expect_equal_strings("0.288", tree.source[leaf.start..leaf.end]);
        }
    }
}

test "inline list" {
    const source =
        \\[name        , hr, avg  ]
    ;

    var tree = Tree.init(testing.allocator);
    defer tree.deinit();
    try tree.parse(source);

    try testing.expect_equal(tree.docs.items.len, 1);

    const doc = tree.docs.items[0].cast(Node.Doc).?;
    try testing.expect_equal(doc.base.start, 0);
    try testing.expect_equal(doc.base.end, tree.tokens.len - 2);

    try testing.expect(doc.value != null);
    try testing.expect_equal(doc.value.?.tag, .list);

    const list = doc.value.?.cast(Node.List).?;
    try testing.expect_equal(list.base.start, 0);
    try testing.expect_equal(list.base.end, tree.tokens.len - 2);
    try testing.expect_equal(list.values.items.len, 3);

    {
        try testing.expect_equal(list.values.items[0].tag, .value);
        const value = list.values.items[0].cast(Node.Value).?;
        const leaf = tree.tokens[value.base.start];
        try testing.expect_equal_strings("name", tree.source[leaf.start..leaf.end]);
    }

    {
        try testing.expect_equal(list.values.items[1].tag, .value);
        const value = list.values.items[1].cast(Node.Value).?;
        const leaf = tree.tokens[value.base.start];
        try testing.expect_equal_strings("hr", tree.source[leaf.start..leaf.end]);
    }

    {
        try testing.expect_equal(list.values.items[2].tag, .value);
        const value = list.values.items[2].cast(Node.Value).?;
        const leaf = tree.tokens[value.base.start];
        try testing.expect_equal_strings("avg", tree.source[leaf.start..leaf.end]);
    }
}

test "inline list as mapping value" {
    const source =
        \\key : [
        \\        name        ,
        \\        hr, avg  ]
    ;

    var tree = Tree.init(testing.allocator);
    defer tree.deinit();
    try tree.parse(source);

    try testing.expect_equal(tree.docs.items.len, 1);

    const doc = tree.docs.items[0].cast(Node.Doc).?;
    try testing.expect_equal(doc.base.start, 0);
    try testing.expect_equal(doc.base.end, tree.tokens.len - 2);

    try testing.expect(doc.value != null);
    try testing.expect_equal(doc.value.?.tag, .map);

    const map = doc.value.?.cast(Node.Map).?;
    try testing.expect_equal(map.base.start, 0);
    try testing.expect_equal(map.base.end, tree.tokens.len - 2);
    try testing.expect_equal(map.values.items.len, 1);

    const entry = map.values.items[0];
    const key = tree.tokens[entry.key];
    try testing.expect_equal(key.id, .literal);
    try testing.expect_equal_strings("key", tree.source[key.start..key.end]);

    const list = entry.value.?.cast(Node.List).?;
    try testing.expect_equal(list.base.start, 4);
    try testing.expect_equal(list.base.end, tree.tokens.len - 2);
    try testing.expect_equal(list.values.items.len, 3);

    {
        try testing.expect_equal(list.values.items[0].tag, .value);
        const value = list.values.items[0].cast(Node.Value).?;
        const leaf = tree.tokens[value.base.start];
        try testing.expect_equal_strings("name", tree.source[leaf.start..leaf.end]);
    }

    {
        try testing.expect_equal(list.values.items[1].tag, .value);
        const value = list.values.items[1].cast(Node.Value).?;
        const leaf = tree.tokens[value.base.start];
        try testing.expect_equal_strings("hr", tree.source[leaf.start..leaf.end]);
    }

    {
        try testing.expect_equal(list.values.items[2].tag, .value);
        const value = list.values.items[2].cast(Node.Value).?;
        const leaf = tree.tokens[value.base.start];
        try testing.expect_equal_strings("avg", tree.source[leaf.start..leaf.end]);
    }
}

fn parse_success(comptime source: []const u8) !void {
    var tree = Tree.init(testing.allocator);
    defer tree.deinit();
    try tree.parse(source);
}

fn parse_error(comptime source: []const u8, err: parse.ParseError) !void {
    var tree = Tree.init(testing.allocator);
    defer tree.deinit();
    try testing.expect_error(err, tree.parse(source));
}

test "empty doc with spaces and comments" {
    try parse_success(
        \\
        \\
        \\   # this is a comment in a weird place
        \\# and this one is too
    );
}

test "comment between --- and ! in document start" {
    try parse_error(
        \\--- # what is it?
        \\!
    , error.UnexpectedToken);
}

test "correct doc start with tag" {
    try parse_success(
        \\--- !some-tag
        \\
    );
}

test "doc close without explicit doc open" {
    try parse_error(
        \\
        \\
        \\# something cool
        \\...
    , error.UnexpectedToken);
}

test "doc open and close are ok" {
    try parse_success(
        \\---
        \\# first doc
        \\
        \\
        \\---
        \\# second doc
        \\
        \\
        \\...
    );
}

test "doc with a single string is ok" {
    try parse_success(
        \\a string of some sort
        \\
    );
}

test "explicit doc with a single string is ok" {
    try parse_success(
        \\--- !anchor
        \\# nothing to see here except one string
        \\  # not a lot to go on with
        \\a single string
        \\...
    );
}

test "doc with two string is bad" {
    try parse_error(
        \\first
        \\second
        \\# this should fail already
    , error.UnexpectedToken);
}

test "single quote string can have new lines" {
    try parse_success(
        \\'what is this
        \\ thing?'
    );
}

test "single quote string on one line is fine" {
    try parse_success(
        \\'here''s an apostrophe'
    );
}

test "double quote string can have new lines" {
    try parse_success(
        \\"what is this
        \\ thing?"
    );
}

test "double quote string on one line is fine" {
    try parse_success(
        \\"a newline\nand a\ttab"
    );
}

test "map with key and value literals" {
    try parse_success(
        \\key1: val1
        \\key2 : val2
    );
}

test "map of maps" {
    try parse_success(
        \\
        \\# the first key
        \\key1:
        \\  # the first subkey
        \\  key1_1: 0
        \\  key1_2: 1
        \\# the second key
        \\key2:
        \\  key2_1: -1
        \\  key2_2: -2
        \\# the end of map
    );
}

test "map value indicator needs to be on the same line" {
    try parse_error(
        \\a
        \\  : b
    , error.UnexpectedToken);
}

test "value needs to be indented" {
    try parse_error(
        \\a:
        \\b
    , error.MalformedYaml);
}

test "comment between a key and a value is fine" {
    try parse_success(
        \\a:
        \\  # this is a value
        \\  b
    );
}

test "simple list" {
    try parse_success(
        \\# first el
        \\- a
        \\# second el
        \\-  b
        \\# third el
        \\-   c
    );
}

test "list indentation matters" {
    try parse_success(
        \\  - a
        \\- b
    );

    try parse_success(
        \\- a
        \\  - b
    );
}

test "unindented list is fine too" {
    try parse_success(
        \\a:
        \\- 0
        \\- 1
    );
}

test "empty values in a map" {
    try parse_success(
        \\a:
        \\b:
        \\- 0
    );
}

test "weirdly nested map of maps of lists" {
    try parse_success(
        \\a:
        \\ b:
        \\  - 0
        \\  - 1
    );
}

test "square brackets denote a list" {
    try parse_success(
        \\[ a,
        \\  b, c ]
    );
}

test "empty list" {
    try parse_success(
        \\[ ]
    );
}

test "comment within a bracketed list is an error" {
    try parse_error(
        \\[ # something
        \\]
    , error.MalformedYaml);
}

test "mixed ints with floats in a list" {
    try parse_success(
        \\[0, 1.0]
    );
}
