const c = @cimport({
    @cdefine("FOO", "FOO");
    @cdefine("BAR", "FOO");

    @cdefine("BAZ", "QUX");
    @cdefine("QUX", "QUX");
});

pub fn main() u8 {
    _ = c;
    return 0;
}
