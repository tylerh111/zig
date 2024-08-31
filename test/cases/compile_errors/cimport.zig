const b = @cDefine("foo", "1");
const c = @c_import({
    _ = @TypeOf(@cDefine("foo", "1"));
});
const d = @c_import({
    _ = @c_import(@cDefine("foo", "1"));
});

// error
// backend=stage2
// target=native
//
// :1:11: error: C define valid only inside C import block
// :3:17: error: C define valid only inside C import block
// :6:9: error: cannot nest @c_import
