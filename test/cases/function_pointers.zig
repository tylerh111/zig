const std = @import("std");

const PrintFn = *const fn () void;

pub fn main() void {
    var printFn: PrintFn = stop_saying_that;
    var i: u32 = 0;
    while (i < 4) : (i += 1) printFn();

    printFn = move_every_zig;
    printFn();
}

fn stop_saying_that() void {
    _ = std.posix.write(1, "Hello, my name is Inigo Montoya; you killed my father, prepare to die.\n") catch {};
}

fn move_every_zig() void {
    _ = std.posix.write(1, "All your codebase are belong to us\n") catch {};
}

// run
// target=x86_64-macos
//
// Hello, my name is Inigo Montoya; you killed my father, prepare to die.
// Hello, my name is Inigo Montoya; you killed my father, prepare to die.
// Hello, my name is Inigo Montoya; you killed my father, prepare to die.
// Hello, my name is Inigo Montoya; you killed my father, prepare to die.
// All your codebase are belong to us
//
