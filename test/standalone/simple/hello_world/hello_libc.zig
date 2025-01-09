const c = @cimport({
    // See https://github.com/ziglang/zig/issues/515
    @cdefine("_NO_CRT_STDIO_INLINE", "1");
    @cinclude("stdio.h");
    @cinclude("string.h");
});

const msg = "Hello, world!\n";

pub export fn main(argc: c_int, argv: **u8) c_int {
    _ = argv;
    _ = argc;
    if (c.printf(msg) != @as(c_int, @intcast(c.strlen(msg)))) return -1;
    return 0;
}
