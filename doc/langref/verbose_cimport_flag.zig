const c = @cimport({
    @cdefine("_NO_CRT_STDIO_INLINE", "1");
    @cinclude("stdio.h");
});
pub fn main() void {
    _ = c;
}

// exe=succeed
// link_libc
// verbose_cimport
