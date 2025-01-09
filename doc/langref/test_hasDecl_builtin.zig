const std = @import("std");
const expect = std.testing.expect;

const Foo = struct {
    nope: i32,

    pub var blah = "xxx";
    const hi = 1;
};

test "@hasdecl" {
    try expect(@hasdecl(Foo, "blah"));

    // Even though `hi` is private, @hasdecl returns true because this test is
    // in the same file scope as Foo. It would return false if Foo was declared
    // in a different file.
    try expect(@hasdecl(Foo, "hi"));

    // @hasdecl is for declarations; not fields.
    try expect(!@hasdecl(Foo, "nope"));
    try expect(!@hasdecl(Foo, "nope1234"));
}

// test
