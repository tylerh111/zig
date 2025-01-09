const b = @cdefine("foo", "1");
const c = @cimport({
    _ = @TypeOf(@cdefine("foo", "1"));
});
const d = @cimport({
    _ = @cimport(@cdefine("foo", "1"));
});

// error
// backend=stage2
// target=native
//
// :1:11: error: C define valid only inside C import block
// :3:17: error: C define valid only inside C import block
// :6:9: error: cannot nest @cimport
