test "enum" {
    const E = enum(u8) { A, B, _ };
    _ = @tagname(@as(E, @enumfromint(5)));
}

// error
// backend=stage2
// target=native
// is_test=true
//
// :3:9: error: no field with value '@enumfromint(5)' in enum 'test.enum.E'
// :2:15: note: declared here
