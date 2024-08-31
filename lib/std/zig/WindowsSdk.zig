windows10sdk: ?Installation,
windows81sdk: ?Installation,
msvc_lib_dir: ?[]const u8,

const WindowsSdk = @This();
const std = @import("std");
const builtin = @import("builtin");

const windows = std.os.windows;
const RRF = windows.advapi32.RRF;

const windows_kits_reg_key = "SOFTWARE\\Microsoft\\Windows Kits\\Installed Roots";

// https://learn.microsoft.com/en-us/windows/win32/msi/productversion
const version_major_minor_max_length = "255.255".len;
// note(bratishkaerik): i think ProductVersion in registry (created by Visual Studio installer) also follows this rule
const product_version_max_length = version_major_minor_max_length + ".65535".len;

/// Find path and version of Windows 10 SDK and Windows 8.1 SDK, and find path to MSVC's `lib/` directory.
/// Caller owns the result's fields.
/// After finishing work, call `free(allocator)`.
pub fn find(allocator: std.mem.Allocator) error{ OutOfMemory, NotFound, PathTooLong }!WindowsSdk {
    if (builtin.os.tag != .windows) return error.NotFound;

    //note(dimenus): If this key doesn't exist, neither the Win 8 SDK nor the Win 10 SDK is installed
    const roots_key = RegistryWtf8.open_key(windows.HKEY_LOCAL_MACHINE, windows_kits_reg_key, .{ .wow64_32 = true }) catch |err| switch (err) {
        error.KeyNotFound => return error.NotFound,
    };
    defer roots_key.close_key();

    const windows10sdk = Installation.find(allocator, roots_key, "KitsRoot10", "", "v10.0") catch |err| switch (err) {
        error.InstallationNotFound => null,
        error.PathTooLong => null,
        error.VersionTooLong => null,
        error.OutOfMemory => return error.OutOfMemory,
    };
    errdefer if (windows10sdk) |*w| w.free(allocator);

    const windows81sdk = Installation.find(allocator, roots_key, "KitsRoot81", "winver", "v8.1") catch |err| switch (err) {
        error.InstallationNotFound => null,
        error.PathTooLong => null,
        error.VersionTooLong => null,
        error.OutOfMemory => return error.OutOfMemory,
    };
    errdefer if (windows81sdk) |*w| w.free(allocator);

    const msvc_lib_dir: ?[]const u8 = MsvcLibDir.find(allocator) catch |err| switch (err) {
        error.MsvcLibDirNotFound => null,
        error.OutOfMemory => return error.OutOfMemory,
    };
    errdefer allocator.free(msvc_lib_dir);

    return .{
        .windows10sdk = windows10sdk,
        .windows81sdk = windows81sdk,
        .msvc_lib_dir = msvc_lib_dir,
    };
}

pub fn free(sdk: WindowsSdk, allocator: std.mem.Allocator) void {
    if (sdk.windows10sdk) |*w10sdk| {
        w10sdk.free(allocator);
    }
    if (sdk.windows81sdk) |*w81sdk| {
        w81sdk.free(allocator);
    }
    if (sdk.msvc_lib_dir) |msvc_lib_dir| {
        allocator.free(msvc_lib_dir);
    }
}

/// Iterates via `iterator` and collects all folders with names starting with `strip_prefix`
/// and a version. Returns slice of version strings sorted in descending order.
/// Caller owns result.
fn iterate_and_filter_by_version(
    iterator: *std.fs.Dir.Iterator,
    allocator: std.mem.Allocator,
    prefix: []const u8,
) error{OutOfMemory}![][]const u8 {
    const Version = struct {
        nums: [4]u32,
        build: []const u8,

        fn parse_num(num: []const u8) ?u32 {
            if (num[0] == '0' and num.len > 1) return null;
            return std.fmt.parse_int(u32, num, 10) catch null;
        }

        fn order(lhs: @This(), rhs: @This()) std.math.Order {
            return std.mem.order(u32, &lhs.nums, &rhs.nums).differ() orelse
                std.mem.order(u8, lhs.build, rhs.build);
        }
    };
    var versions = std.ArrayList(Version).init(allocator);
    var dirs = std.ArrayList([]const u8).init(allocator);
    defer {
        versions.deinit();
        for (dirs.items) |filtered_dir| allocator.free(filtered_dir);
        dirs.deinit();
    }

    iterate: while (iterator.next() catch null) |entry| {
        if (entry.kind != .directory) continue;
        if (!std.mem.starts_with(u8, entry.name, prefix)) continue;

        var version: Version = .{
            .nums = .{0} ** 4,
            .build = "",
        };
        const suffix = entry.name[prefix.len..];
        const underscore = std.mem.index_of_scalar(u8, entry.name, '_');
        var num_it = std.mem.split_scalar(u8, suffix[0 .. underscore orelse suffix.len], '.');
        version.nums[0] = Version.parse_num(num_it.first()) orelse continue;
        for (version.nums[1..]) |*num|
            num.* = Version.parse_num(num_it.next() orelse break) orelse continue :iterate
        else if (num_it.next()) |_| continue;

        const name = try allocator.dupe(u8, suffix);
        errdefer allocator.free(name);
        if (underscore) |pos| version.build = name[pos + 1 ..];

        try versions.append(version);
        try dirs.append(name);
    }

    std.mem.sort_unstable_context(0, dirs.items.len, struct {
        versions: []Version,
        dirs: [][]const u8,
        pub fn less_than(context: @This(), lhs: usize, rhs: usize) bool {
            return context.versions[lhs].order(context.versions[rhs]).compare(.gt);
        }
        pub fn swap(context: @This(), lhs: usize, rhs: usize) void {
            std.mem.swap(Version, &context.versions[lhs], &context.versions[rhs]);
            std.mem.swap([]const u8, &context.dirs[lhs], &context.dirs[rhs]);
        }
    }{ .versions = versions.items, .dirs = dirs.items });
    return dirs.to_owned_slice();
}

const OpenOptions = struct {
    /// Sets the KEY_WOW64_32KEY access flag.
    /// https://learn.microsoft.com/en-us/windows/win32/winprog64/accessing-an-alternate-registry-view
    wow64_32: bool = false,
};

const RegistryWtf8 = struct {
    key: windows.HKEY,

    /// Assert that `key` is valid WTF-8 string
    pub fn open_key(hkey: windows.HKEY, key: []const u8, options: OpenOptions) error{KeyNotFound}!RegistryWtf8 {
        const key_wtf16le: [:0]const u16 = key_wtf16le: {
            var key_wtf16le_buf: [RegistryWtf16Le.key_name_max_len]u16 = undefined;
            const key_wtf16le_len: usize = std.unicode.wtf8_to_wtf16_le(key_wtf16le_buf[0..], key) catch |err| switch (err) {
                error.InvalidWtf8 => unreachable,
            };
            key_wtf16le_buf[key_wtf16le_len] = 0;
            break :key_wtf16le key_wtf16le_buf[0..key_wtf16le_len :0];
        };

        const registry_wtf16le = try RegistryWtf16Le.open_key(hkey, key_wtf16le, options);
        return .{ .key = registry_wtf16le.key };
    }

    /// Closes key, after that usage is invalid
    pub fn close_key(reg: RegistryWtf8) void {
        const return_code_int: windows.HRESULT = windows.advapi32.RegCloseKey(reg.key);
        const return_code: windows.Win32Error = @enumFromInt(return_code_int);
        switch (return_code) {
            .SUCCESS => {},
            else => {},
        }
    }

    /// Get string from registry.
    /// Caller owns result.
    pub fn get_string(reg: RegistryWtf8, allocator: std.mem.Allocator, subkey: []const u8, value_name: []const u8) error{ OutOfMemory, ValueNameNotFound, NotAString, StringNotFound }![]u8 {
        const subkey_wtf16le: [:0]const u16 = subkey_wtf16le: {
            var subkey_wtf16le_buf: [RegistryWtf16Le.key_name_max_len]u16 = undefined;
            const subkey_wtf16le_len: usize = std.unicode.wtf8_to_wtf16_le(subkey_wtf16le_buf[0..], subkey) catch unreachable;
            subkey_wtf16le_buf[subkey_wtf16le_len] = 0;
            break :subkey_wtf16le subkey_wtf16le_buf[0..subkey_wtf16le_len :0];
        };

        const value_name_wtf16le: [:0]const u16 = value_name_wtf16le: {
            var value_name_wtf16le_buf: [RegistryWtf16Le.value_name_max_len]u16 = undefined;
            const value_name_wtf16le_len: usize = std.unicode.wtf8_to_wtf16_le(value_name_wtf16le_buf[0..], value_name) catch unreachable;
            value_name_wtf16le_buf[value_name_wtf16le_len] = 0;
            break :value_name_wtf16le value_name_wtf16le_buf[0..value_name_wtf16le_len :0];
        };

        const registry_wtf16le: RegistryWtf16Le = .{ .key = reg.key };
        const value_wtf16le = try registry_wtf16le.get_string(allocator, subkey_wtf16le, value_name_wtf16le);
        defer allocator.free(value_wtf16le);

        const value_wtf8: []u8 = try std.unicode.wtf16_le_to_wtf8_alloc(allocator, value_wtf16le);
        errdefer allocator.free(value_wtf8);

        return value_wtf8;
    }

    /// Get DWORD (u32) from registry.
    pub fn get_dword(reg: RegistryWtf8, subkey: []const u8, value_name: []const u8) error{ ValueNameNotFound, NotADword, DwordTooLong, DwordNotFound }!u32 {
        const subkey_wtf16le: [:0]const u16 = subkey_wtf16le: {
            var subkey_wtf16le_buf: [RegistryWtf16Le.key_name_max_len]u16 = undefined;
            const subkey_wtf16le_len: usize = std.unicode.wtf8_to_wtf16_le(subkey_wtf16le_buf[0..], subkey) catch unreachable;
            subkey_wtf16le_buf[subkey_wtf16le_len] = 0;
            break :subkey_wtf16le subkey_wtf16le_buf[0..subkey_wtf16le_len :0];
        };

        const value_name_wtf16le: [:0]const u16 = value_name_wtf16le: {
            var value_name_wtf16le_buf: [RegistryWtf16Le.value_name_max_len]u16 = undefined;
            const value_name_wtf16le_len: usize = std.unicode.wtf8_to_wtf16_le(value_name_wtf16le_buf[0..], value_name) catch unreachable;
            value_name_wtf16le_buf[value_name_wtf16le_len] = 0;
            break :value_name_wtf16le value_name_wtf16le_buf[0..value_name_wtf16le_len :0];
        };

        const registry_wtf16le: RegistryWtf16Le = .{ .key = reg.key };
        return registry_wtf16le.get_dword(subkey_wtf16le, value_name_wtf16le);
    }

    /// Under private space with flags:
    /// KEY_QUERY_VALUE and KEY_ENUMERATE_SUB_KEYS.
    /// After finishing work, call `close_key`.
    pub fn load_from_path(absolute_path: []const u8) error{KeyNotFound}!RegistryWtf8 {
        const absolute_path_wtf16le: [:0]const u16 = absolute_path_wtf16le: {
            var absolute_path_wtf16le_buf: [RegistryWtf16Le.value_name_max_len]u16 = undefined;
            const absolute_path_wtf16le_len: usize = std.unicode.wtf8_to_wtf16_le(absolute_path_wtf16le_buf[0..], absolute_path) catch unreachable;
            absolute_path_wtf16le_buf[absolute_path_wtf16le_len] = 0;
            break :absolute_path_wtf16le absolute_path_wtf16le_buf[0..absolute_path_wtf16le_len :0];
        };

        const registry_wtf16le = try RegistryWtf16Le.load_from_path(absolute_path_wtf16le);
        return .{ .key = registry_wtf16le.key };
    }
};

const RegistryWtf16Le = struct {
    key: windows.HKEY,

    /// Includes root key (f.e. HKEY_LOCAL_MACHINE).
    /// https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-element-size-limits
    pub const key_name_max_len = 255;
    /// In Unicode characters.
    /// https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-element-size-limits
    pub const value_name_max_len = 16_383;

    /// Under HKEY_LOCAL_MACHINE with flags:
    /// KEY_QUERY_VALUE, KEY_ENUMERATE_SUB_KEYS, optionally KEY_WOW64_32KEY.
    /// After finishing work, call `close_key`.
    fn open_key(hkey: windows.HKEY, key_wtf16le: [:0]const u16, options: OpenOptions) error{KeyNotFound}!RegistryWtf16Le {
        var key: windows.HKEY = undefined;
        var access: windows.REGSAM = windows.KEY_QUERY_VALUE | windows.KEY_ENUMERATE_SUB_KEYS;
        if (options.wow64_32) access |= windows.KEY_WOW64_32KEY;
        const return_code_int: windows.HRESULT = windows.advapi32.RegOpenKeyExW(
            hkey,
            key_wtf16le,
            0,
            access,
            &key,
        );
        const return_code: windows.Win32Error = @enumFromInt(return_code_int);
        switch (return_code) {
            .SUCCESS => {},
            .FILE_NOT_FOUND => return error.KeyNotFound,

            else => return error.KeyNotFound,
        }
        return .{ .key = key };
    }

    /// Closes key, after that usage is invalid
    fn close_key(reg: RegistryWtf16Le) void {
        const return_code_int: windows.HRESULT = windows.advapi32.RegCloseKey(reg.key);
        const return_code: windows.Win32Error = @enumFromInt(return_code_int);
        switch (return_code) {
            .SUCCESS => {},
            else => {},
        }
    }

    /// Get string ([:0]const u16) from registry.
    fn get_string(reg: RegistryWtf16Le, allocator: std.mem.Allocator, subkey_wtf16le: [:0]const u16, value_name_wtf16le: [:0]const u16) error{ OutOfMemory, ValueNameNotFound, NotAString, StringNotFound }![]const u16 {
        var actual_type: windows.ULONG = undefined;

        // Calculating length to allocate
        var value_wtf16le_buf_size: u32 = 0; // in bytes, including any terminating NUL character or characters.
        var return_code_int: windows.HRESULT = windows.advapi32.RegGetValueW(
            reg.key,
            subkey_wtf16le,
            value_name_wtf16le,
            RRF.RT_REG_SZ,
            &actual_type,
            null,
            &value_wtf16le_buf_size,
        );

        // Check returned code and type
        var return_code: windows.Win32Error = @enumFromInt(return_code_int);
        switch (return_code) {
            .SUCCESS => std.debug.assert(value_wtf16le_buf_size != 0),
            .MORE_DATA => unreachable, // We are only reading length
            .FILE_NOT_FOUND => return error.ValueNameNotFound,
            .INVALID_PARAMETER => unreachable, // We didn't combine RRF.SUBKEY_WOW6464KEY and RRF.SUBKEY_WOW6432KEY
            else => return error.StringNotFound,
        }
        switch (actual_type) {
            windows.REG.SZ => {},
            else => return error.NotAString,
        }

        const value_wtf16le_buf: []u16 = try allocator.alloc(u16, std.math.div_ceil(u32, value_wtf16le_buf_size, 2) catch unreachable);
        errdefer allocator.free(value_wtf16le_buf);

        return_code_int = windows.advapi32.RegGetValueW(
            reg.key,
            subkey_wtf16le,
            value_name_wtf16le,
            RRF.RT_REG_SZ,
            &actual_type,
            value_wtf16le_buf.ptr,
            &value_wtf16le_buf_size,
        );

        // Check returned code and (just in case) type again.
        return_code = @enumFromInt(return_code_int);
        switch (return_code) {
            .SUCCESS => {},
            .MORE_DATA => unreachable, // Calculated first time length should be enough, even overestimated
            .FILE_NOT_FOUND => return error.ValueNameNotFound,
            .INVALID_PARAMETER => unreachable, // We didn't combine RRF.SUBKEY_WOW6464KEY and RRF.SUBKEY_WOW6432KEY
            else => return error.StringNotFound,
        }
        switch (actual_type) {
            windows.REG.SZ => {},
            else => return error.NotAString,
        }

        const value_wtf16le: []const u16 = value_wtf16le: {
            // note(bratishkaerik): somehow returned value in `buf_len` is overestimated by Windows and contains extra space
            // we will just search for zero termination and forget length
            // Windows sure is strange
            const value_wtf16le_overestimated: [*:0]const u16 = @ptr_cast(value_wtf16le_buf.ptr);
            break :value_wtf16le std.mem.span(value_wtf16le_overestimated);
        };

        _ = allocator.resize(value_wtf16le_buf, value_wtf16le.len);
        return value_wtf16le;
    }

    /// Get DWORD (u32) from registry.
    fn get_dword(reg: RegistryWtf16Le, subkey_wtf16le: [:0]const u16, value_name_wtf16le: [:0]const u16) error{ ValueNameNotFound, NotADword, DwordTooLong, DwordNotFound }!u32 {
        var actual_type: windows.ULONG = undefined;
        var reg_size: u32 = @size_of(u32);
        var reg_value: u32 = 0;

        const return_code_int: windows.HRESULT = windows.advapi32.RegGetValueW(
            reg.key,
            subkey_wtf16le,
            value_name_wtf16le,
            RRF.RT_REG_DWORD,
            &actual_type,
            &reg_value,
            &reg_size,
        );
        const return_code: windows.Win32Error = @enumFromInt(return_code_int);
        switch (return_code) {
            .SUCCESS => {},
            .MORE_DATA => return error.DwordTooLong,
            .FILE_NOT_FOUND => return error.ValueNameNotFound,
            .INVALID_PARAMETER => unreachable, // We didn't combine RRF.SUBKEY_WOW6464KEY and RRF.SUBKEY_WOW6432KEY
            else => return error.DwordNotFound,
        }

        switch (actual_type) {
            windows.REG.DWORD => {},
            else => return error.NotADword,
        }

        return reg_value;
    }

    /// Under private space with flags:
    /// KEY_QUERY_VALUE and KEY_ENUMERATE_SUB_KEYS.
    /// After finishing work, call `close_key`.
    fn load_from_path(absolute_path_as_wtf16le: [:0]const u16) error{KeyNotFound}!RegistryWtf16Le {
        var key: windows.HKEY = undefined;

        const return_code_int: windows.HRESULT = std.os.windows.advapi32.RegLoadAppKeyW(
            absolute_path_as_wtf16le,
            &key,
            windows.KEY_QUERY_VALUE | windows.KEY_ENUMERATE_SUB_KEYS,
            0,
            0,
        );
        const return_code: windows.Win32Error = @enumFromInt(return_code_int);
        switch (return_code) {
            .SUCCESS => {},
            else => return error.KeyNotFound,
        }

        return .{ .key = key };
    }
};

pub const Installation = struct {
    path: []const u8,
    version: []const u8,

    /// Find path and version of Windows SDK.
    /// Caller owns the result's fields.
    /// After finishing work, call `free(allocator)`.
    fn find(
        allocator: std.mem.Allocator,
        roots_key: RegistryWtf8,
        roots_subkey: []const u8,
        prefix: []const u8,
        version_key_name: []const u8,
    ) error{ OutOfMemory, InstallationNotFound, PathTooLong, VersionTooLong }!Installation {
        roots: {
            const installation = find_from_root(allocator, roots_key, roots_subkey, prefix) catch
                break :roots;
            if (installation.is_valid_version()) return installation;
            installation.free(allocator);
        }
        {
            const installation = try find_from_installation_folder(allocator, version_key_name);
            if (installation.is_valid_version()) return installation;
            installation.free(allocator);
        }
        return error.InstallationNotFound;
    }

    fn find_from_root(
        allocator: std.mem.Allocator,
        roots_key: RegistryWtf8,
        roots_subkey: []const u8,
        prefix: []const u8,
    ) error{ OutOfMemory, InstallationNotFound, PathTooLong, VersionTooLong }!Installation {
        const path = path: {
            const path_maybe_with_trailing_slash = roots_key.get_string(allocator, "", roots_subkey) catch |err| switch (err) {
                error.NotAString => return error.InstallationNotFound,
                error.ValueNameNotFound => return error.InstallationNotFound,
                error.StringNotFound => return error.InstallationNotFound,

                error.OutOfMemory => return error.OutOfMemory,
            };
            if (path_maybe_with_trailing_slash.len > std.fs.MAX_PATH_BYTES or !std.fs.path.is_absolute(path_maybe_with_trailing_slash)) {
                allocator.free(path_maybe_with_trailing_slash);
                return error.PathTooLong;
            }

            var path = std.ArrayList(u8).from_owned_slice(allocator, path_maybe_with_trailing_slash);
            errdefer path.deinit();

            // String might contain trailing slash, so trim it here
            if (path.items.len > "C:\\".len and path.get_last() == '\\') _ = path.pop();
            break :path try path.to_owned_slice();
        };
        errdefer allocator.free(path);

        const version = version: {
            var buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
            const sdk_lib_dir_path = std.fmt.buf_print(buf[0..], "{s}\\Lib\\", .{path}) catch |err| switch (err) {
                error.NoSpaceLeft => return error.PathTooLong,
            };
            if (!std.fs.path.is_absolute(sdk_lib_dir_path)) return error.InstallationNotFound;

            // enumerate files in sdk path looking for latest version
            var sdk_lib_dir = std.fs.open_dir_absolute(sdk_lib_dir_path, .{
                .iterate = true,
            }) catch |err| switch (err) {
                error.NameTooLong => return error.PathTooLong,
                else => return error.InstallationNotFound,
            };
            defer sdk_lib_dir.close();

            var iterator = sdk_lib_dir.iterate();
            const versions = try iterate_and_filter_by_version(&iterator, allocator, prefix);
            defer {
                for (versions[1..]) |version| allocator.free(version);
                allocator.free(versions);
            }
            break :version versions[0];
        };
        errdefer allocator.free(version);

        return .{ .path = path, .version = version };
    }

    fn find_from_installation_folder(
        allocator: std.mem.Allocator,
        version_key_name: []const u8,
    ) error{ OutOfMemory, InstallationNotFound, PathTooLong, VersionTooLong }!Installation {
        var key_name_buf: [RegistryWtf16Le.key_name_max_len]u8 = undefined;
        const key_name = std.fmt.buf_print(
            &key_name_buf,
            "SOFTWARE\\Microsoft\\Microsoft SDKs\\Windows\\{s}",
            .{version_key_name},
        ) catch unreachable;
        const key = key: for ([_]bool{ true, false }) |wow6432node| {
            for ([_]windows.HKEY{ windows.HKEY_LOCAL_MACHINE, windows.HKEY_CURRENT_USER }) |hkey| {
                break :key RegistryWtf8.open_key(hkey, key_name, .{ .wow64_32 = wow6432node }) catch |err| switch (err) {
                    error.KeyNotFound => return error.InstallationNotFound,
                };
            }
        } else return error.InstallationNotFound;
        defer key.close_key();

        const path: []const u8 = path: {
            const path_maybe_with_trailing_slash = key.get_string(allocator, "", "InstallationFolder") catch |err| switch (err) {
                error.NotAString => return error.InstallationNotFound,
                error.ValueNameNotFound => return error.InstallationNotFound,
                error.StringNotFound => return error.InstallationNotFound,

                error.OutOfMemory => return error.OutOfMemory,
            };

            if (path_maybe_with_trailing_slash.len > std.fs.MAX_PATH_BYTES or !std.fs.path.is_absolute(path_maybe_with_trailing_slash)) {
                allocator.free(path_maybe_with_trailing_slash);
                return error.PathTooLong;
            }

            var path = std.ArrayList(u8).from_owned_slice(allocator, path_maybe_with_trailing_slash);
            errdefer path.deinit();

            // String might contain trailing slash, so trim it here
            if (path.items.len > "C:\\".len and path.get_last() == '\\') _ = path.pop();

            const path_without_trailing_slash = try path.to_owned_slice();
            break :path path_without_trailing_slash;
        };
        errdefer allocator.free(path);

        const version: []const u8 = version: {

            // note(dimenus): Microsoft doesn't include the .0 in the ProductVersion key....
            const version_without_0 = key.get_string(allocator, "", "ProductVersion") catch |err| switch (err) {
                error.NotAString => return error.InstallationNotFound,
                error.ValueNameNotFound => return error.InstallationNotFound,
                error.StringNotFound => return error.InstallationNotFound,

                error.OutOfMemory => return error.OutOfMemory,
            };
            if (version_without_0.len + ".0".len > product_version_max_length) {
                allocator.free(version_without_0);
                return error.VersionTooLong;
            }

            var version = std.ArrayList(u8).from_owned_slice(allocator, version_without_0);
            errdefer version.deinit();

            try version.append_slice(".0");

            const version_with_0 = try version.to_owned_slice();
            break :version version_with_0;
        };
        errdefer allocator.free(version);

        return .{ .path = path, .version = version };
    }

    /// Check whether this version is enumerated in registry.
    fn is_valid_version(installation: Installation) bool {
        var buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
        const reg_query_as_wtf8 = std.fmt.buf_print(buf[0..], "{s}\\{s}\\Installed Options", .{
            windows_kits_reg_key,
            installation.version,
        }) catch |err| switch (err) {
            error.NoSpaceLeft => return false,
        };

        const options_key = RegistryWtf8.open_key(
            windows.HKEY_LOCAL_MACHINE,
            reg_query_as_wtf8,
            .{ .wow64_32 = true },
        ) catch |err| switch (err) {
            error.KeyNotFound => return false,
        };
        defer options_key.close_key();

        const option_name = comptime switch (builtin.target.cpu.arch) {
            .arm, .armeb => "OptionId.DesktopCPParm",
            .aarch64 => "OptionId.DesktopCPParm64",
            .x86_64 => "OptionId.DesktopCPPx64",
            .x86 => "OptionId.DesktopCPPx86",
            else => |tag| @compile_error("Windows SDK cannot be detected on architecture " ++ tag),
        };

        const reg_value = options_key.get_dword("", option_name) catch return false;
        return (reg_value == 1);
    }

    fn free(install: Installation, allocator: std.mem.Allocator) void {
        allocator.free(install.path);
        allocator.free(install.version);
    }
};

const MsvcLibDir = struct {
    fn find_instances_dir_via_setup(allocator: std.mem.Allocator) error{ OutOfMemory, PathNotFound }!std.fs.Dir {
        const vs_setup_key_path = "SOFTWARE\\Microsoft\\VisualStudio\\Setup";
        const vs_setup_key = RegistryWtf8.open_key(windows.HKEY_LOCAL_MACHINE, vs_setup_key_path, .{}) catch |err| switch (err) {
            error.KeyNotFound => return error.PathNotFound,
        };
        defer vs_setup_key.close_key();

        const packages_path = vs_setup_key.get_string(allocator, "", "CachePath") catch |err| switch (err) {
            error.NotAString,
            error.ValueNameNotFound,
            error.StringNotFound,
            => return error.PathNotFound,

            error.OutOfMemory => return error.OutOfMemory,
        };
        defer allocator.free(packages_path);

        if (!std.fs.path.is_absolute(packages_path)) return error.PathNotFound;

        const instances_path = try std.fs.path.join(allocator, &.{ packages_path, "_Instances" });
        defer allocator.free(instances_path);

        return std.fs.open_dir_absolute(instances_path, .{ .iterate = true }) catch return error.PathNotFound;
    }

    fn find_instances_dir_via_clsid(allocator: std.mem.Allocator) error{ OutOfMemory, PathNotFound }!std.fs.Dir {
        const setup_configuration_clsid = "{177f0c4a-1cd3-4de7-a32c-71dbbb9fa36d}";
        const setup_config_key = RegistryWtf8.open_key(windows.HKEY_CLASSES_ROOT, "CLSID\\" ++ setup_configuration_clsid, .{}) catch |err| switch (err) {
            error.KeyNotFound => return error.PathNotFound,
        };
        defer setup_config_key.close_key();

        const dll_path = setup_config_key.get_string(allocator, "InprocServer32", "") catch |err| switch (err) {
            error.NotAString,
            error.ValueNameNotFound,
            error.StringNotFound,
            => return error.PathNotFound,

            error.OutOfMemory => return error.OutOfMemory,
        };
        defer allocator.free(dll_path);

        if (!std.fs.path.is_absolute(dll_path)) return error.PathNotFound;

        var path_it = std.fs.path.component_iterator(dll_path) catch return error.PathNotFound;
        // the .dll filename
        _ = path_it.last();
        const root_path = while (path_it.previous()) |dir_component| {
            if (std.ascii.eql_ignore_case(dir_component.name, "VisualStudio")) {
                break dir_component.path;
            }
        } else {
            return error.PathNotFound;
        };

        const instances_path = try std.fs.path.join(allocator, &.{ root_path, "Packages", "_Instances" });
        defer allocator.free(instances_path);

        return std.fs.open_dir_absolute(instances_path, .{ .iterate = true }) catch return error.PathNotFound;
    }

    fn find_instances_dir(allocator: std.mem.Allocator) error{ OutOfMemory, PathNotFound }!std.fs.Dir {
        // First, try getting the packages cache path from the registry.
        // This only seems to exist when the path is different from the default.
        method1: {
            return find_instances_dir_via_setup(allocator) catch |err| switch (err) {
                error.OutOfMemory => |e| return e,
                error.PathNotFound => break :method1,
            };
        }
        // Otherwise, try to get the path from the .dll that would have been
        // loaded via COM for SetupConfiguration.
        method2: {
            return find_instances_dir_via_clsid(allocator) catch |err| switch (err) {
                error.OutOfMemory => |e| return e,
                error.PathNotFound => break :method2,
            };
        }
        // If that can't be found, fall back to manually appending
        // `Microsoft\VisualStudio\Packages\_Instances` to %PROGRAMDATA%
        method3: {
            const program_data = std.process.get_env_var_owned(allocator, "PROGRAMDATA") catch |err| switch (err) {
                error.OutOfMemory => |e| return e,
                error.InvalidWtf8 => unreachable,
                error.EnvironmentVariableNotFound => break :method3,
            };
            defer allocator.free(program_data);

            if (!std.fs.path.is_absolute(program_data)) break :method3;

            const instances_path = try std.fs.path.join(allocator, &.{ program_data, "Microsoft", "VisualStudio", "Packages", "_Instances" });
            defer allocator.free(instances_path);

            return std.fs.open_dir_absolute(instances_path, .{ .iterate = true }) catch break :method3;
        }
        return error.PathNotFound;
    }

    /// Intended to be equivalent to `ISetupHelper.ParseVersion`
    /// Example: 17.4.33205.214 -> 0x0011000481b500d6
    fn parse_version_quad(version: []const u8) error{InvalidVersion}!u64 {
        var it = std.mem.split_scalar(u8, version, '.');
        const a = it.first();
        const b = it.next() orelse return error.InvalidVersion;
        const c = it.next() orelse return error.InvalidVersion;
        const d = it.next() orelse return error.InvalidVersion;
        if (it.next()) |_| return error.InvalidVersion;
        var result: u64 = undefined;
        var result_bytes = std.mem.as_bytes(&result);

        std.mem.write_int(
            u16,
            result_bytes[0..2],
            std.fmt.parse_unsigned(u16, d, 10) catch return error.InvalidVersion,
            .little,
        );
        std.mem.write_int(
            u16,
            result_bytes[2..4],
            std.fmt.parse_unsigned(u16, c, 10) catch return error.InvalidVersion,
            .little,
        );
        std.mem.write_int(
            u16,
            result_bytes[4..6],
            std.fmt.parse_unsigned(u16, b, 10) catch return error.InvalidVersion,
            .little,
        );
        std.mem.write_int(
            u16,
            result_bytes[6..8],
            std.fmt.parse_unsigned(u16, a, 10) catch return error.InvalidVersion,
            .little,
        );

        return result;
    }

    /// Intended to be equivalent to ISetupConfiguration.EnumInstances:
    /// https://learn.microsoft.com/en-us/dotnet/api/microsoft.visualstudio.setup.configuration
    /// but without the use of COM in order to avoid a dependency on ole32.dll
    ///
    /// The logic in this function is intended to match what ISetupConfiguration does
    /// under-the-hood, as verified using Procmon.
    fn find_via_com(allocator: std.mem.Allocator) error{ OutOfMemory, PathNotFound }![]const u8 {
        // Typically `%PROGRAMDATA%\Microsoft\VisualStudio\Packages\_Instances`
        // This will contain directories with names of instance IDs like 80a758ca,
        // which will contain `state.json` files that have the version and
        // installation directory.
        var instances_dir = try find_instances_dir(allocator);
        defer instances_dir.close();

        var state_subpath_buf: [std.fs.MAX_NAME_BYTES + 32]u8 = undefined;
        var latest_version_lib_dir = std.ArrayListUnmanaged(u8){};
        errdefer latest_version_lib_dir.deinit(allocator);

        var latest_version: u64 = 0;
        var instances_dir_it = instances_dir.iterate_assume_first_iteration();
        while (instances_dir_it.next() catch return error.PathNotFound) |entry| {
            if (entry.kind != .directory) continue;

            var fbs = std.io.fixed_buffer_stream(&state_subpath_buf);
            const writer = fbs.writer();

            writer.write_all(entry.name) catch unreachable;
            writer.write_byte(std.fs.path.sep) catch unreachable;
            writer.write_all("state.json") catch unreachable;

            const json_contents = instances_dir.read_file_alloc(allocator, fbs.get_written(), std.math.max_int(usize)) catch continue;
            defer allocator.free(json_contents);

            var parsed = std.json.parse_from_slice(std.json.Value, allocator, json_contents, .{}) catch continue;
            defer parsed.deinit();

            if (parsed.value != .object) continue;
            const catalog_info = parsed.value.object.get("catalogInfo") orelse continue;
            if (catalog_info != .object) continue;
            const product_version_value = catalog_info.object.get("buildVersion") orelse continue;
            if (product_version_value != .string) continue;
            const product_version_text = product_version_value.string;
            const parsed_version = parse_version_quad(product_version_text) catch continue;

            // We want to end up with the most recent version installed
            if (parsed_version <= latest_version) continue;

            const installation_path = parsed.value.object.get("installationPath") orelse continue;
            if (installation_path != .string) continue;

            const lib_dir_path = lib_dir_from_installation_path(allocator, installation_path.string) catch |err| switch (err) {
                error.OutOfMemory => |e| return e,
                error.PathNotFound => continue,
            };
            defer allocator.free(lib_dir_path);

            latest_version_lib_dir.clear_retaining_capacity();
            try latest_version_lib_dir.append_slice(allocator, lib_dir_path);
            latest_version = parsed_version;
        }

        if (latest_version_lib_dir.items.len == 0) return error.PathNotFound;
        return latest_version_lib_dir.to_owned_slice(allocator);
    }

    fn lib_dir_from_installation_path(allocator: std.mem.Allocator, installation_path: []const u8) error{ OutOfMemory, PathNotFound }![]const u8 {
        var lib_dir_buf = try std.ArrayList(u8).init_capacity(allocator, installation_path.len + 64);
        errdefer lib_dir_buf.deinit();

        lib_dir_buf.append_slice_assume_capacity(installation_path);

        if (!std.fs.path.is_sep(lib_dir_buf.get_last())) {
            try lib_dir_buf.append('\\');
        }
        const installation_path_with_trailing_sep_len = lib_dir_buf.items.len;

        try lib_dir_buf.append_slice("VC\\Auxiliary\\Build\\Microsoft.VCToolsVersion.default.txt");
        var default_tools_version_buf: [512]u8 = undefined;
        const default_tools_version_contents = std.fs.cwd().read_file(lib_dir_buf.items, &default_tools_version_buf) catch {
            return error.PathNotFound;
        };
        var tokenizer = std.mem.tokenize_any(u8, default_tools_version_contents, " \r\n");
        const default_tools_version = tokenizer.next() orelse return error.PathNotFound;

        lib_dir_buf.shrink_retaining_capacity(installation_path_with_trailing_sep_len);
        try lib_dir_buf.append_slice("VC\\Tools\\MSVC\\");
        try lib_dir_buf.append_slice(default_tools_version);
        const folder_with_arch = "\\Lib\\" ++ comptime switch (builtin.target.cpu.arch) {
            .x86 => "x86",
            .x86_64 => "x64",
            .arm, .armeb => "arm",
            .aarch64 => "arm64",
            else => |tag| @compile_error("MSVC lib dir cannot be detected on architecture " ++ tag),
        };
        try lib_dir_buf.append_slice(folder_with_arch);

        if (!verify_lib_dir(lib_dir_buf.items)) {
            return error.PathNotFound;
        }

        return lib_dir_buf.to_owned_slice();
    }

    // https://learn.microsoft.com/en-us/visualstudio/install/tools-for-managing-visual-studio-instances?view=vs-2022#editing-the-registry-for-a-visual-studio-instance
    fn find_via_registry(allocator: std.mem.Allocator) error{ OutOfMemory, PathNotFound }![]const u8 {

        // %localappdata%\Microsoft\VisualStudio\
        // %appdata%\Local\Microsoft\VisualStudio\
        const visualstudio_folder_path = std.fs.get_app_data_dir(allocator, "Microsoft\\VisualStudio\\") catch return error.PathNotFound;
        defer allocator.free(visualstudio_folder_path);

        const vs_versions: []const []const u8 = vs_versions: {
            if (!std.fs.path.is_absolute(visualstudio_folder_path)) return error.PathNotFound;
            // enumerate folders that contain `privateregistry.bin`, looking for all versions
            // f.i. %localappdata%\Microsoft\VisualStudio\17.0_9e9cbb98\
            var visualstudio_folder = std.fs.open_dir_absolute(visualstudio_folder_path, .{
                .iterate = true,
            }) catch return error.PathNotFound;
            defer visualstudio_folder.close();

            var iterator = visualstudio_folder.iterate();
            break :vs_versions try iterate_and_filter_by_version(&iterator, allocator, "");
        };
        defer {
            for (vs_versions) |vs_version| allocator.free(vs_version);
            allocator.free(vs_versions);
        }
        var config_subkey_buf: [RegistryWtf16Le.key_name_max_len * 2]u8 = undefined;
        const source_directories: []const u8 = source_directories: for (vs_versions) |vs_version| {
            const privateregistry_absolute_path = std.fs.path.join(allocator, &.{ visualstudio_folder_path, vs_version, "privateregistry.bin" }) catch continue;
            defer allocator.free(privateregistry_absolute_path);
            if (!std.fs.path.is_absolute(privateregistry_absolute_path)) continue;

            const visualstudio_registry = RegistryWtf8.load_from_path(privateregistry_absolute_path) catch continue;
            defer visualstudio_registry.close_key();

            const config_subkey = std.fmt.buf_print(config_subkey_buf[0..], "Software\\Microsoft\\VisualStudio\\{s}_Config", .{vs_version}) catch unreachable;

            const source_directories_value = visualstudio_registry.get_string(allocator, config_subkey, "Source Directories") catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => continue,
            };
            if (source_directories_value.len > (std.fs.MAX_PATH_BYTES * 30)) { // note(bratishkaerik): guessing from the fact that on my computer it has 15 pathes and at least some of them are not of max length
                allocator.free(source_directories_value);
                continue;
            }

            break :source_directories source_directories_value;
        } else return error.PathNotFound;
        defer allocator.free(source_directories);

        var source_directories_splitted = std.mem.split_scalar(u8, source_directories, ';');

        const msvc_dir: []const u8 = msvc_dir: {
            const msvc_include_dir_maybe_with_trailing_slash = try allocator.dupe(u8, source_directories_splitted.first());

            if (msvc_include_dir_maybe_with_trailing_slash.len > std.fs.MAX_PATH_BYTES or !std.fs.path.is_absolute(msvc_include_dir_maybe_with_trailing_slash)) {
                allocator.free(msvc_include_dir_maybe_with_trailing_slash);
                return error.PathNotFound;
            }

            var msvc_dir = std.ArrayList(u8).from_owned_slice(allocator, msvc_include_dir_maybe_with_trailing_slash);
            errdefer msvc_dir.deinit();

            // String might contain trailing slash, so trim it here
            if (msvc_dir.items.len > "C:\\".len and msvc_dir.get_last() == '\\') _ = msvc_dir.pop();

            // Remove `\include` at the end of path
            if (std.mem.ends_with(u8, msvc_dir.items, "\\include")) {
                msvc_dir.shrink_retaining_capacity(msvc_dir.items.len - "\\include".len);
            }

            const folder_with_arch = "\\Lib\\" ++ comptime switch (builtin.target.cpu.arch) {
                .x86 => "x86",
                .x86_64 => "x64",
                .arm, .armeb => "arm",
                .aarch64 => "arm64",
                else => |tag| @compile_error("MSVC lib dir cannot be detected on architecture " ++ tag),
            };

            try msvc_dir.append_slice(folder_with_arch);
            const msvc_dir_with_arch = try msvc_dir.to_owned_slice();
            break :msvc_dir msvc_dir_with_arch;
        };
        errdefer allocator.free(msvc_dir);

        if (!verify_lib_dir(msvc_dir)) {
            return error.PathNotFound;
        }

        return msvc_dir;
    }

    fn find_via_vs7_key(allocator: std.mem.Allocator) error{ OutOfMemory, PathNotFound }![]const u8 {
        var base_path: std.ArrayList(u8) = base_path: {
            try_env: {
                var env_map = std.process.get_env_map(allocator) catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => break :try_env,
                };
                defer env_map.deinit();

                if (env_map.get("VS140COMNTOOLS")) |VS140COMNTOOLS| {
                    if (VS140COMNTOOLS.len < "C:\\Common7\\Tools".len) break :try_env;
                    if (!std.fs.path.is_absolute(VS140COMNTOOLS)) break :try_env;
                    var list = std.ArrayList(u8).init(allocator);
                    errdefer list.deinit();

                    try list.append_slice(VS140COMNTOOLS); // C:\Program Files (x86)\Microsoft Visual Studio 14.0\Common7\Tools
                    // String might contain trailing slash, so trim it here
                    if (list.items.len > "C:\\".len and list.get_last() == '\\') _ = list.pop();
                    list.shrink_retaining_capacity(list.items.len - "\\Common7\\Tools".len); // C:\Program Files (x86)\Microsoft Visual Studio 14.0
                    break :base_path list;
                }
            }

            const vs7_key = RegistryWtf8.open_key(windows.HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\VisualStudio\\SxS\\VS7", .{ .wow64_32 = true }) catch return error.PathNotFound;
            defer vs7_key.close_key();
            try_vs7_key: {
                const path_maybe_with_trailing_slash = vs7_key.get_string(allocator, "", "14.0") catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => break :try_vs7_key,
                };

                if (path_maybe_with_trailing_slash.len > std.fs.MAX_PATH_BYTES or !std.fs.path.is_absolute(path_maybe_with_trailing_slash)) {
                    allocator.free(path_maybe_with_trailing_slash);
                    break :try_vs7_key;
                }

                var path = std.ArrayList(u8).from_owned_slice(allocator, path_maybe_with_trailing_slash);
                errdefer path.deinit();

                // String might contain trailing slash, so trim it here
                if (path.items.len > "C:\\".len and path.get_last() == '\\') _ = path.pop();
                break :base_path path;
            }
            return error.PathNotFound;
        };
        errdefer base_path.deinit();

        const folder_with_arch = "\\VC\\lib\\" ++ comptime switch (builtin.target.cpu.arch) {
            .x86 => "", //x86 is in the root of the Lib folder
            .x86_64 => "amd64",
            .arm, .armeb => "arm",
            .aarch64 => "arm64",
            else => |tag| @compile_error("MSVC lib dir cannot be detected on architecture " ++ tag),
        };
        try base_path.append_slice(folder_with_arch);

        if (!verify_lib_dir(base_path.items)) {
            return error.PathNotFound;
        }

        const full_path = try base_path.to_owned_slice();
        return full_path;
    }

    fn verify_lib_dir(lib_dir_path: []const u8) bool {
        std.debug.assert(std.fs.path.is_absolute(lib_dir_path)); // should be already handled in `findVia*`

        var dir = std.fs.open_dir_absolute(lib_dir_path, .{}) catch return false;
        defer dir.close();

        const stat = dir.stat_file("vcruntime.lib") catch return false;
        if (stat.kind != .file)
            return false;

        return true;
    }

    /// Find path to MSVC's `lib/` directory.
    /// Caller owns the result.
    pub fn find(allocator: std.mem.Allocator) error{ OutOfMemory, MsvcLibDirNotFound }![]const u8 {
        const full_path = MsvcLibDir.find_via_com(allocator) catch |err1| switch (err1) {
            error.OutOfMemory => return error.OutOfMemory,
            error.PathNotFound => MsvcLibDir.find_via_registry(allocator) catch |err2| switch (err2) {
                error.OutOfMemory => return error.OutOfMemory,
                error.PathNotFound => MsvcLibDir.find_via_vs7_key(allocator) catch |err3| switch (err3) {
                    error.OutOfMemory => return error.OutOfMemory,
                    error.PathNotFound => return error.MsvcLibDirNotFound,
                },
            },
        };
        errdefer allocator.free(full_path);

        return full_path;
    }
};
