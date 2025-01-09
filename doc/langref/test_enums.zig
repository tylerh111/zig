const expect = @import("std").testing.expect;
const mem = @import("std").mem;

// Declare an enum.
const Type = enum {
    ok,
    not_ok,
};

// Declare a specific enum field.
const c = Type.ok;

// If you want access to the ordinal value of an enum, you
// can specify the tag type.
const Value = enum(u2) {
    zero,
    one,
    two,
};
// Now you can cast between u2 and Value.
// The ordinal value starts from 0, counting up by 1 from the previous member.
test "enum ordinal value" {
    try expect(@intfromenum(Value.zero) == 0);
    try expect(@intfromenum(Value.one) == 1);
    try expect(@intfromenum(Value.two) == 2);
}

// You can override the ordinal value for an enum.
const Value2 = enum(u32) {
    hundred = 100,
    thousand = 1000,
    million = 1000000,
};
test "set enum ordinal value" {
    try expect(@intfromenum(Value2.hundred) == 100);
    try expect(@intfromenum(Value2.thousand) == 1000);
    try expect(@intfromenum(Value2.million) == 1000000);
}

// You can also override only some values.
const Value3 = enum(u4) {
    a,
    b = 8,
    c,
    d = 4,
    e,
};
test "enum implicit ordinal values and overridden values" {
    try expect(@intfromenum(Value3.a) == 0);
    try expect(@intfromenum(Value3.b) == 8);
    try expect(@intfromenum(Value3.c) == 9);
    try expect(@intfromenum(Value3.d) == 4);
    try expect(@intfromenum(Value3.e) == 5);
}

// Enums can have methods, the same as structs and unions.
// Enum methods are not special, they are only namespaced
// functions that you can call with dot syntax.
const Suit = enum {
    clubs,
    spades,
    diamonds,
    hearts,

    pub fn isClubs(self: Suit) bool {
        return self == Suit.clubs;
    }
};
test "enum method" {
    const p = Suit.spades;
    try expect(!p.isClubs());
}

// An enum can be switched upon.
const Foo = enum {
    string,
    number,
    none,
};
test "enum switch" {
    const p = Foo.number;
    const what_is_it = switch (p) {
        Foo.string => "this is a string",
        Foo.number => "this is a number",
        Foo.none => "this is a none",
    };
    try expect(mem.eql(u8, what_is_it, "this is a number"));
}

// @typeinfo can be used to access the integer tag type of an enum.
const Small = enum {
    one,
    two,
    three,
    four,
};
test "std.meta.Tag" {
    try expect(@typeinfo(Small).Enum.tag_type == u2);
}

// @typeinfo tells us the field count and the fields names:
test "@typeinfo" {
    try expect(@typeinfo(Small).Enum.fields.len == 4);
    try expect(mem.eql(u8, @typeinfo(Small).Enum.fields[1].name, "two"));
}

// @tagname gives a [:0]const u8 representation of an enum value:
test "@tagname" {
    try expect(mem.eql(u8, @tagname(Small.three), "three"));
}

// test
