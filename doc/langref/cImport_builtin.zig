const c = @cimport({
    // See https://github.com/ziglang/zig/issues/515
    @cdefine("_NO_CRT_STDIO_INLINE", "1");
    @cinclude("stdio.h");
});
pub fn main() void {
    _ = c.printf("hello\n");
}

// exe=succeed
// link_libc
