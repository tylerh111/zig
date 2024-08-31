//! A set of certificates. Typically pre-installed on every operating system,
//! these are "Certificate Authorities" used to validate SSL certificates.
//! This data structure stores certificates in DER-encoded form, all of them
//! concatenated together in the `bytes` array. The `map` field contains an
//! index from the DER-encoded subject name to the index of the containing
//! certificate within `bytes`.

/// The key is the contents slice of the subject.
map: std.HashMapUnmanaged(der.Element.Slice, u32, MapContext, std.hash_map.default_max_load_percentage) = .{},
bytes: std.ArrayListUnmanaged(u8) = .{},

pub const VerifyError = Certificate.Parsed.VerifyError || error{
    CertificateIssuerNotFound,
};

pub fn verify(cb: Bundle, subject: Certificate.Parsed, now_sec: i64) VerifyError!void {
    const bytes_index = cb.find(subject.issuer()) orelse return error.CertificateIssuerNotFound;
    const issuer_cert: Certificate = .{
        .buffer = cb.bytes.items,
        .index = bytes_index,
    };
    // Every certificate in the bundle is pre-parsed before adding it, ensuring
    // that parsing will succeed here.
    const issuer = issuer_cert.parse() catch unreachable;
    try subject.verify(issuer, now_sec);
}

/// The returned bytes become invalid after calling any of the rescan functions
/// or add functions.
pub fn find(cb: Bundle, subject_name: []const u8) ?u32 {
    const Adapter = struct {
        cb: Bundle,

        pub fn hash(ctx: @This(), k: []const u8) u64 {
            _ = ctx;
            return std.hash_map.hash_string(k);
        }

        pub fn eql(ctx: @This(), a: []const u8, b_key: der.Element.Slice) bool {
            const b = ctx.cb.bytes.items[b_key.start..b_key.end];
            return mem.eql(u8, a, b);
        }
    };
    return cb.map.get_adapted(subject_name, Adapter{ .cb = cb });
}

pub fn deinit(cb: *Bundle, gpa: Allocator) void {
    cb.map.deinit(gpa);
    cb.bytes.deinit(gpa);
    cb.* = undefined;
}

pub const RescanError = RescanLinuxError || RescanMacError || RescanBSDError || RescanWindowsError;

/// Clears the set of certificates and then scans the host operating system
/// file system standard locations for certificates.
/// For operating systems that do not have standard CA installations to be
/// found, this function clears the set of certificates.
pub fn rescan(cb: *Bundle, gpa: Allocator) RescanError!void {
    switch (builtin.os.tag) {
        .linux => return rescan_linux(cb, gpa),
        .macos => return rescan_mac(cb, gpa),
        .freebsd, .openbsd => return rescan_bsd(cb, gpa, "/etc/ssl/cert.pem"),
        .netbsd => return rescan_bsd(cb, gpa, "/etc/openssl/certs/ca-certificates.crt"),
        .dragonfly => return rescan_bsd(cb, gpa, "/usr/local/etc/ssl/cert.pem"),
        .solaris, .illumos => return rescan_bsd(cb, gpa, "/etc/ssl/cacert.pem"),
        .windows => return rescan_windows(cb, gpa),
        else => {},
    }
}

const rescan_mac = @import("Bundle/macos.zig").rescan_mac;
const RescanMacError = @import("Bundle/macos.zig").RescanMacError;

const RescanLinuxError = AddCertsFromFilePathError || AddCertsFromDirPathError;

fn rescan_linux(cb: *Bundle, gpa: Allocator) RescanLinuxError!void {
    // Possible certificate files; stop after finding one.
    const cert_file_paths = [_][]const u8{
        "/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu/Gentoo etc.
        "/etc/pki/tls/certs/ca-bundle.crt", // Fedora/RHEL 6
        "/etc/ssl/ca-bundle.pem", // OpenSUSE
        "/etc/pki/tls/cacert.pem", // OpenELEC
        "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // CentOS/RHEL 7
        "/etc/ssl/cert.pem", // Alpine Linux
    };

    // Possible directories with certificate files; all will be read.
    const cert_dir_paths = [_][]const u8{
        "/etc/ssl/certs", // SLES10/SLES11
        "/etc/pki/tls/certs", // Fedora/RHEL
        "/system/etc/security/cacerts", // Android
    };

    cb.bytes.clear_retaining_capacity();
    cb.map.clear_retaining_capacity();

    scan: {
        for (cert_file_paths) |cert_file_path| {
            if (add_certs_from_file_path_absolute(cb, gpa, cert_file_path)) |_| {
                break :scan;
            } else |err| switch (err) {
                error.FileNotFound => continue,
                else => |e| return e,
            }
        }

        for (cert_dir_paths) |cert_dir_path| {
            add_certs_from_dir_path_absolute(cb, gpa, cert_dir_path) catch |err| switch (err) {
                error.FileNotFound => continue,
                else => |e| return e,
            };
        }
    }

    cb.bytes.shrink_and_free(gpa, cb.bytes.items.len);
}

const RescanBSDError = AddCertsFromFilePathError;

fn rescan_bsd(cb: *Bundle, gpa: Allocator, cert_file_path: []const u8) RescanBSDError!void {
    cb.bytes.clear_retaining_capacity();
    cb.map.clear_retaining_capacity();
    try add_certs_from_file_path_absolute(cb, gpa, cert_file_path);
    cb.bytes.shrink_and_free(gpa, cb.bytes.items.len);
}

const RescanWindowsError = Allocator.Error || ParseCertError || std.posix.UnexpectedError || error{FileNotFound};

fn rescan_windows(cb: *Bundle, gpa: Allocator) RescanWindowsError!void {
    cb.bytes.clear_retaining_capacity();
    cb.map.clear_retaining_capacity();

    const w = std.os.windows;
    const GetLastError = w.kernel32.GetLastError;
    const root = [4:0]u16{ 'R', 'O', 'O', 'T' };
    const store = w.crypt32.CertOpenSystemStoreW(null, &root) orelse switch (GetLastError()) {
        .FILE_NOT_FOUND => return error.FileNotFound,
        else => |err| return w.unexpected_error(err),
    };
    defer _ = w.crypt32.CertCloseStore(store, 0);

    const now_sec = std.time.timestamp();

    var ctx = w.crypt32.CertEnumCertificatesInStore(store, null);
    while (ctx) |context| : (ctx = w.crypt32.CertEnumCertificatesInStore(store, ctx)) {
        const decoded_start = @as(u32, @int_cast(cb.bytes.items.len));
        const encoded_cert = context.pbCertEncoded[0..context.cbCertEncoded];
        try cb.bytes.append_slice(gpa, encoded_cert);
        try cb.parse_cert(gpa, decoded_start, now_sec);
    }
    cb.bytes.shrink_and_free(gpa, cb.bytes.items.len);
}

pub const AddCertsFromDirPathError = fs.File.OpenError || AddCertsFromDirError;

pub fn add_certs_from_dir_path(
    cb: *Bundle,
    gpa: Allocator,
    dir: fs.Dir,
    sub_dir_path: []const u8,
) AddCertsFromDirPathError!void {
    var iterable_dir = try dir.open_dir(sub_dir_path, .{ .iterate = true });
    defer iterable_dir.close();
    return add_certs_from_dir(cb, gpa, iterable_dir);
}

pub fn add_certs_from_dir_path_absolute(
    cb: *Bundle,
    gpa: Allocator,
    abs_dir_path: []const u8,
) AddCertsFromDirPathError!void {
    assert(fs.path.is_absolute(abs_dir_path));
    var iterable_dir = try fs.open_dir_absolute(abs_dir_path, .{ .iterate = true });
    defer iterable_dir.close();
    return add_certs_from_dir(cb, gpa, iterable_dir);
}

pub const AddCertsFromDirError = AddCertsFromFilePathError;

pub fn add_certs_from_dir(cb: *Bundle, gpa: Allocator, iterable_dir: fs.Dir) AddCertsFromDirError!void {
    var it = iterable_dir.iterate();
    while (try it.next()) |entry| {
        switch (entry.kind) {
            .file, .sym_link => {},
            else => continue,
        }

        try add_certs_from_file_path(cb, gpa, iterable_dir, entry.name);
    }
}

pub const AddCertsFromFilePathError = fs.File.OpenError || AddCertsFromFileError;

pub fn add_certs_from_file_path_absolute(
    cb: *Bundle,
    gpa: Allocator,
    abs_file_path: []const u8,
) AddCertsFromFilePathError!void {
    assert(fs.path.is_absolute(abs_file_path));
    var file = try fs.open_file_absolute(abs_file_path, .{});
    defer file.close();
    return add_certs_from_file(cb, gpa, file);
}

pub fn add_certs_from_file_path(
    cb: *Bundle,
    gpa: Allocator,
    dir: fs.Dir,
    sub_file_path: []const u8,
) AddCertsFromFilePathError!void {
    var file = try dir.open_file(sub_file_path, .{});
    defer file.close();
    return add_certs_from_file(cb, gpa, file);
}

pub const AddCertsFromFileError = Allocator.Error ||
    fs.File.GetSeekPosError ||
    fs.File.ReadError ||
    ParseCertError ||
    std.base64.Error ||
    error{ CertificateAuthorityBundleTooBig, MissingEndCertificateMarker };

pub fn add_certs_from_file(cb: *Bundle, gpa: Allocator, file: fs.File) AddCertsFromFileError!void {
    const size = try file.get_end_pos();

    // We borrow `bytes` as a temporary buffer for the base64-encoded data.
    // This is possible by computing the decoded length and reserving the space
    // for the decoded bytes first.
    const decoded_size_upper_bound = size / 4 * 3;
    const needed_capacity = std.math.cast(u32, decoded_size_upper_bound + size) orelse
        return error.CertificateAuthorityBundleTooBig;
    try cb.bytes.ensure_unused_capacity(gpa, needed_capacity);
    const end_reserved: u32 = @int_cast(cb.bytes.items.len + decoded_size_upper_bound);
    const buffer = cb.bytes.allocated_slice()[end_reserved..];
    const end_index = try file.read_all(buffer);
    const encoded_bytes = buffer[0..end_index];

    const begin_marker = "-----BEGIN CERTIFICATE-----";
    const end_marker = "-----END CERTIFICATE-----";

    const now_sec = std.time.timestamp();

    var start_index: usize = 0;
    while (mem.index_of_pos(u8, encoded_bytes, start_index, begin_marker)) |begin_marker_start| {
        const cert_start = begin_marker_start + begin_marker.len;
        const cert_end = mem.index_of_pos(u8, encoded_bytes, cert_start, end_marker) orelse
            return error.MissingEndCertificateMarker;
        start_index = cert_end + end_marker.len;
        const encoded_cert = mem.trim(u8, encoded_bytes[cert_start..cert_end], " \t\r\n");
        const decoded_start: u32 = @int_cast(cb.bytes.items.len);
        const dest_buf = cb.bytes.allocated_slice()[decoded_start..];
        cb.bytes.items.len += try base64.decode(dest_buf, encoded_cert);
        try cb.parse_cert(gpa, decoded_start, now_sec);
    }
}

pub const ParseCertError = Allocator.Error || Certificate.ParseError;

pub fn parse_cert(cb: *Bundle, gpa: Allocator, decoded_start: u32, now_sec: i64) ParseCertError!void {
    // Even though we could only partially parse the certificate to find
    // the subject name, we pre-parse all of them to make sure and only
    // include in the bundle ones that we know will parse. This way we can
    // use `catch unreachable` later.
    const parsed_cert = Certificate.parse(.{
        .buffer = cb.bytes.items,
        .index = decoded_start,
    }) catch |err| switch (err) {
        error.CertificateHasUnrecognizedObjectId => {
            cb.bytes.items.len = decoded_start;
            return;
        },
        else => |e| return e,
    };
    if (now_sec > parsed_cert.validity.not_after) {
        // Ignore expired cert.
        cb.bytes.items.len = decoded_start;
        return;
    }
    const gop = try cb.map.get_or_put_context(gpa, parsed_cert.subject_slice, .{ .cb = cb });
    if (gop.found_existing) {
        cb.bytes.items.len = decoded_start;
    } else {
        gop.value_ptr.* = decoded_start;
    }
}

const builtin = @import("builtin");
const std = @import("../../std.zig");
const assert = std.debug.assert;
const fs = std.fs;
const mem = std.mem;
const crypto = std.crypto;
const Allocator = std.mem.Allocator;
const Certificate = std.crypto.Certificate;
const der = Certificate.der;
const Bundle = @This();

const base64 = std.base64.standard.decoderWithIgnore(" \t\r\n");

const MapContext = struct {
    cb: *const Bundle,

    pub fn hash(ctx: MapContext, k: der.Element.Slice) u64 {
        return std.hash_map.hash_string(ctx.cb.bytes.items[k.start..k.end]);
    }

    pub fn eql(ctx: MapContext, a: der.Element.Slice, b: der.Element.Slice) bool {
        const bytes = ctx.cb.bytes.items;
        return mem.eql(
            u8,
            bytes[a.start..a.end],
            bytes[b.start..b.end],
        );
    }
};

test "scan for OS-provided certificates" {
    if (builtin.os.tag == .wasi) return error.SkipZigTest;

    var bundle: Bundle = .{};
    defer bundle.deinit(std.testing.allocator);

    try bundle.rescan(std.testing.allocator);
}
