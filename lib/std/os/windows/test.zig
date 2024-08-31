const std = @import("../../std.zig");
const builtin = @import("builtin");
const windows = std.os.windows;
const mem = std.mem;
const testing = std.testing;

/// Wrapper around RtlDosPathNameToNtPathName_U for use in comparing
/// the behavior of RtlDosPathNameToNtPathName_U with w_to_prefixed_file_w
/// Note: RtlDosPathNameToNtPathName_U is not used in the Zig implementation
//        because it allocates.
fn RtlDosPathNameToNtPathName_U(path: [:0]const u16) !windows.PathSpace {
    var out: windows.UNICODE_STRING = undefined;
    const rc = windows.ntdll.RtlDosPathNameToNtPathName_U(path, &out, null, null);
    if (rc != windows.TRUE) return error.BadPathName;
    defer windows.ntdll.RtlFreeUnicodeString(&out);

    var path_space: windows.PathSpace = undefined;
    const out_path = out.Buffer.?[0 .. out.Length / 2];
    @memcpy(path_space.data[0..out_path.len], out_path);
    path_space.len = out.Length / 2;
    path_space.data[path_space.len] = 0;

    return path_space;
}

/// Test that the Zig conversion matches the expected_path (for instances where
/// the Zig implementation intentionally diverges from what RtlDosPathNameToNtPathName_U does).
fn test_to_prefixed_file_no_oracle(comptime path: []const u8, comptime expected_path: []const u8) !void {
    const path_utf16 = std.unicode.utf8_to_utf16_le_string_literal(path);
    const expected_path_utf16 = std.unicode.utf8_to_utf16_le_string_literal(expected_path);
    const actual_path = try windows.w_to_prefixed_file_w(null, path_utf16);
    std.testing.expect_equal_slices(u16, expected_path_utf16, actual_path.span()) catch |e| {
        std.debug.print("got '{s}', expected '{s}'\n", .{ std.unicode.fmt_utf16_le(actual_path.span()), std.unicode.fmtUtf16le(expected_path_utf16) });
        return e;
    };
}

/// Test that the Zig conversion matches the expected_path and that the
/// expected_path matches the conversion that RtlDosPathNameToNtPathName_U does.
fn test_to_prefixed_file_with_oracle(comptime path: []const u8, comptime expected_path: []const u8) !void {
    try test_to_prefixed_file_no_oracle(path, expected_path);
    try test_to_prefixed_file_only_oracle(path);
}

/// Test that the Zig conversion matches the conversion that RtlDosPathNameToNtPathName_U does.
fn test_to_prefixed_file_only_oracle(comptime path: []const u8) !void {
    const path_utf16 = std.unicode.utf8_to_utf16_le_string_literal(path);
    const zig_result = try windows.w_to_prefixed_file_w(null, path_utf16);
    const win32_api_result = try RtlDosPathNameToNtPathName_U(path_utf16);
    std.testing.expect_equal_slices(u16, win32_api_result.span(), zig_result.span()) catch |e| {
        std.debug.print("got '{s}', expected '{s}'\n", .{ std.unicode.fmt_utf16_le(zig_result.span()), std.unicode.fmtUtf16le(win32_api_result.span()) });
        return e;
    };
}

test "toPrefixedFileW" {
    if (builtin.os.tag != .windows)
        return;

    // Most test cases come from https://googleprojectzero.blogspot.com/2016/02/the-definitive-guide-on-win32-to-nt.html
    // Note that these tests do not actually touch the filesystem or care about whether or not
    // any of the paths actually exist or are otherwise valid.

    // Drive Absolute
    try test_to_prefixed_file_with_oracle("X:\\ABC\\DEF", "\\??\\X:\\ABC\\DEF");
    try test_to_prefixed_file_with_oracle("X:\\", "\\??\\X:\\");
    try test_to_prefixed_file_with_oracle("X:\\ABC\\", "\\??\\X:\\ABC\\");
    // Trailing . and space characters are stripped
    try test_to_prefixed_file_with_oracle("X:\\ABC\\DEF. .", "\\??\\X:\\ABC\\DEF");
    try test_to_prefixed_file_with_oracle("X:/ABC/DEF", "\\??\\X:\\ABC\\DEF");
    try test_to_prefixed_file_with_oracle("X:\\ABC\\..\\XYZ", "\\??\\X:\\XYZ");
    try test_to_prefixed_file_with_oracle("X:\\ABC\\..\\..\\..", "\\??\\X:\\");
    // Drive letter casing is unchanged
    try test_to_prefixed_file_with_oracle("x:\\", "\\??\\x:\\");

    // Drive Relative
    // These tests depend on the CWD of the specified drive letter which can vary,
    // so instead we just test that the Zig implementation matches the result of
    // RtlDosPathNameToNtPathName_U.
    // TODO: Setting the =X: environment variable didn't seem to affect
    //       RtlDosPathNameToNtPathName_U, not sure why that is but getting that
    //       to work could be an avenue to making these cases environment-independent.
    // All -> are examples of the result if the X drive's cwd was X:\ABC
    try test_to_prefixed_file_only_oracle("X:DEF\\GHI"); // -> \??\X:\ABC\DEF\GHI
    try test_to_prefixed_file_only_oracle("X:"); // -> \??\X:\ABC
    try test_to_prefixed_file_only_oracle("X:DEF. ."); // -> \??\X:\ABC\DEF
    try test_to_prefixed_file_only_oracle("X:ABC\\..\\XYZ"); // -> \??\X:\ABC\XYZ
    try test_to_prefixed_file_only_oracle("X:ABC\\..\\..\\.."); // -> \??\X:\
    try test_to_prefixed_file_only_oracle("x:"); // -> \??\X:\ABC

    // Rooted
    // These tests depend on the drive letter of the CWD which can vary, so
    // instead we just test that the Zig implementation matches the result of
    // RtlDosPathNameToNtPathName_U.
    // TODO: Getting the CWD path, getting the drive letter from it, and using it to
    //       construct the expected NT paths could be an avenue to making these cases
    //       environment-independent and therefore able to use test_to_prefixed_file_with_oracle.
    // All -> are examples of the result if the CWD's drive letter was X
    try test_to_prefixed_file_only_oracle("\\ABC\\DEF"); // -> \??\X:\ABC\DEF
    try test_to_prefixed_file_only_oracle("\\"); // -> \??\X:\
    try test_to_prefixed_file_only_oracle("\\ABC\\DEF. ."); // -> \??\X:\ABC\DEF
    try test_to_prefixed_file_only_oracle("/ABC/DEF"); // -> \??\X:\ABC\DEF
    try test_to_prefixed_file_only_oracle("\\ABC\\..\\XYZ"); // -> \??\X:\XYZ
    try test_to_prefixed_file_only_oracle("\\ABC\\..\\..\\.."); // -> \??\X:\

    // Relative
    // These cases differ in functionality to RtlDosPathNameToNtPathName_U.
    // Relative paths remain relative if they don't have enough .. components
    // to error with TooManyParentDirs
    try test_to_prefixed_file_no_oracle("ABC\\DEF", "ABC\\DEF");
    // TODO: enable this if trailing . and spaces are stripped from relative paths
    //try test_to_prefixed_file_no_oracle("ABC\\DEF. .", "ABC\\DEF");
    try test_to_prefixed_file_no_oracle("ABC/DEF", "ABC\\DEF");
    try test_to_prefixed_file_no_oracle("./ABC/.././DEF", "DEF");
    // TooManyParentDirs, so resolved relative to the CWD
    // All -> are examples of the result if the CWD was X:\ABC\DEF
    try test_to_prefixed_file_only_oracle("..\\GHI"); // -> \??\X:\ABC\GHI
    try test_to_prefixed_file_only_oracle("GHI\\..\\..\\.."); // -> \??\X:\

    // UNC Absolute
    try test_to_prefixed_file_with_oracle("\\\\server\\share\\ABC\\DEF", "\\??\\UNC\\server\\share\\ABC\\DEF");
    try test_to_prefixed_file_with_oracle("\\\\server", "\\??\\UNC\\server");
    try test_to_prefixed_file_with_oracle("\\\\server\\share", "\\??\\UNC\\server\\share");
    try test_to_prefixed_file_with_oracle("\\\\server\\share\\ABC. .", "\\??\\UNC\\server\\share\\ABC");
    try test_to_prefixed_file_with_oracle("//server/share/ABC/DEF", "\\??\\UNC\\server\\share\\ABC\\DEF");
    try test_to_prefixed_file_with_oracle("\\\\server\\share\\ABC\\..\\XYZ", "\\??\\UNC\\server\\share\\XYZ");
    try test_to_prefixed_file_with_oracle("\\\\server\\share\\ABC\\..\\..\\..", "\\??\\UNC\\server\\share");

    // Local Device
    try test_to_prefixed_file_with_oracle("\\\\.\\COM20", "\\??\\COM20");
    try test_to_prefixed_file_with_oracle("\\\\.\\pipe\\mypipe", "\\??\\pipe\\mypipe");
    try test_to_prefixed_file_with_oracle("\\\\.\\X:\\ABC\\DEF. .", "\\??\\X:\\ABC\\DEF");
    try test_to_prefixed_file_with_oracle("\\\\.\\X:/ABC/DEF", "\\??\\X:\\ABC\\DEF");
    try test_to_prefixed_file_with_oracle("\\\\.\\X:\\ABC\\..\\XYZ", "\\??\\X:\\XYZ");
    // Can replace the first component of the path (contrary to drive absolute and UNC absolute paths)
    try test_to_prefixed_file_with_oracle("\\\\.\\X:\\ABC\\..\\..\\C:\\", "\\??\\C:\\");
    try test_to_prefixed_file_with_oracle("\\\\.\\pipe\\mypipe\\..\\notmine", "\\??\\pipe\\notmine");

    // Special-case device names
    // TODO: Enable once these are supported
    //       more cases to test here: https://googleprojectzero.blogspot.com/2016/02/the-definitive-guide-on-win32-to-nt.html
    //try test_to_prefixed_file_with_oracle("COM1", "\\??\\COM1");
    // Sometimes the special-cased device names are not respected
    try test_to_prefixed_file_with_oracle("\\\\.\\X:\\COM1", "\\??\\X:\\COM1");
    try test_to_prefixed_file_with_oracle("\\\\abc\\xyz\\COM1", "\\??\\UNC\\abc\\xyz\\COM1");

    // Verbatim
    // Left untouched except \\?\ is replaced by \??\
    try test_to_prefixed_file_with_oracle("\\\\?\\X:", "\\??\\X:");
    try test_to_prefixed_file_with_oracle("\\\\?\\X:\\COM1", "\\??\\X:\\COM1");
    try test_to_prefixed_file_with_oracle("\\\\?\\X:/ABC/DEF. .", "\\??\\X:/ABC/DEF. .");
    try test_to_prefixed_file_with_oracle("\\\\?\\X:\\ABC\\..\\..\\..", "\\??\\X:\\ABC\\..\\..\\..");
    // NT Namespace
    // Fully unmodified
    try test_to_prefixed_file_with_oracle("\\??\\X:", "\\??\\X:");
    try test_to_prefixed_file_with_oracle("\\??\\X:\\COM1", "\\??\\X:\\COM1");
    try test_to_prefixed_file_with_oracle("\\??\\X:/ABC/DEF. .", "\\??\\X:/ABC/DEF. .");
    try test_to_prefixed_file_with_oracle("\\??\\X:\\ABC\\..\\..\\..", "\\??\\X:\\ABC\\..\\..\\..");

    // 'Fake' Verbatim
    // If the prefix looks like the verbatim prefix but not all path separators in the
    // prefix are backslashes, then it gets canonicalized and the prefix is dropped in favor
    // of the NT prefix.
    try test_to_prefixed_file_with_oracle("//?/C:/ABC", "\\??\\C:\\ABC");
    // 'Fake' NT
    // If the prefix looks like the NT prefix but not all path separators in the prefix
    // are backslashes, then it gets canonicalized and the /??/ is not dropped but
    // rather treated as part of the path. In other words, the path is treated
    // as a rooted path, so the final path is resolved relative to the CWD's
    // drive letter.
    // The -> shows an example of the result if the CWD's drive letter was X
    try test_to_prefixed_file_only_oracle("/??/C:/ABC"); // -> \??\X:\??\C:\ABC

    // Root Local Device
    // \\. and \\? always get converted to \??\
    try test_to_prefixed_file_with_oracle("\\\\.", "\\??\\");
    try test_to_prefixed_file_with_oracle("\\\\?", "\\??\\");
    try test_to_prefixed_file_with_oracle("//?", "\\??\\");
    try test_to_prefixed_file_with_oracle("//.", "\\??\\");
}

fn test_remove_dot_dirs(str: []const u8, expected: []const u8) !void {
    const mutable = try testing.allocator.dupe(u8, str);
    defer testing.allocator.free(mutable);
    const actual = mutable[0..try windows.remove_dot_dirs_sanitized(u8, mutable)];
    try testing.expect(mem.eql(u8, actual, expected));
}
fn test_remove_dot_dirs_error(err: anyerror, str: []const u8) !void {
    const mutable = try testing.allocator.dupe(u8, str);
    defer testing.allocator.free(mutable);
    try testing.expect_error(err, windows.remove_dot_dirs_sanitized(u8, mutable));
}
test "removeDotDirs" {
    try test_remove_dot_dirs("", "");
    try test_remove_dot_dirs(".", "");
    try test_remove_dot_dirs(".\\", "");
    try test_remove_dot_dirs(".\\.", "");
    try test_remove_dot_dirs(".\\.\\", "");
    try test_remove_dot_dirs(".\\.\\.", "");

    try test_remove_dot_dirs("a", "a");
    try test_remove_dot_dirs("a\\", "a\\");
    try test_remove_dot_dirs("a\\b", "a\\b");
    try test_remove_dot_dirs("a\\.", "a\\");
    try test_remove_dot_dirs("a\\b\\.", "a\\b\\");
    try test_remove_dot_dirs("a\\.\\b", "a\\b");

    try test_remove_dot_dirs(".a", ".a");
    try test_remove_dot_dirs(".a\\", ".a\\");
    try test_remove_dot_dirs(".a\\.b", ".a\\.b");
    try test_remove_dot_dirs(".a\\.", ".a\\");
    try test_remove_dot_dirs(".a\\.\\.", ".a\\");
    try test_remove_dot_dirs(".a\\.\\.\\.b", ".a\\.b");
    try test_remove_dot_dirs(".a\\.\\.\\.b\\", ".a\\.b\\");

    try test_remove_dot_dirs_error(error.TooManyParentDirs, "..");
    try test_remove_dot_dirs_error(error.TooManyParentDirs, "..\\");
    try test_remove_dot_dirs_error(error.TooManyParentDirs, ".\\..\\");
    try test_remove_dot_dirs_error(error.TooManyParentDirs, ".\\.\\..\\");

    try test_remove_dot_dirs("a\\..", "");
    try test_remove_dot_dirs("a\\..\\", "");
    try test_remove_dot_dirs("a\\..\\.", "");
    try test_remove_dot_dirs("a\\..\\.\\", "");
    try test_remove_dot_dirs("a\\..\\.\\.", "");
    try test_remove_dot_dirs_error(error.TooManyParentDirs, "a\\..\\.\\.\\..");

    try test_remove_dot_dirs("a\\..\\.\\.\\b", "b");
    try test_remove_dot_dirs("a\\..\\.\\.\\b\\", "b\\");
    try test_remove_dot_dirs("a\\..\\.\\.\\b\\.", "b\\");
    try test_remove_dot_dirs("a\\..\\.\\.\\b\\.\\", "b\\");
    try test_remove_dot_dirs("a\\..\\.\\.\\b\\.\\..", "");
    try test_remove_dot_dirs("a\\..\\.\\.\\b\\.\\..\\", "");
    try test_remove_dot_dirs("a\\..\\.\\.\\b\\.\\..\\.", "");
    try test_remove_dot_dirs_error(error.TooManyParentDirs, "a\\..\\.\\.\\b\\.\\..\\.\\..");

    try test_remove_dot_dirs("a\\b\\..\\", "a\\");
    try test_remove_dot_dirs("a\\b\\..\\c", "a\\c");
}

test "load_winsock_extension_function" {
    _ = try windows.WSAStartup(2, 2);
    defer windows.WSACleanup() catch unreachable;

    const LPFN_CONNECTEX = *const fn (
        Socket: windows.ws2_32.SOCKET,
        SockAddr: *const windows.ws2_32.sockaddr,
        SockLen: std.posix.socklen_t,
        SendBuf: ?*const anyopaque,
        SendBufLen: windows.DWORD,
        BytesSent: *windows.DWORD,
        Overlapped: *windows.OVERLAPPED,
    ) callconv(windows.WINAPI) windows.BOOL;

    _ = windows.load_winsock_extension_function(
        LPFN_CONNECTEX,
        try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0),
        windows.ws2_32.WSAID_CONNECTEX,
    ) catch |err| switch (err) {
        error.OperationNotSupported => unreachable,
        error.ShortRead => unreachable,
        else => |e| return e,
    };
}
