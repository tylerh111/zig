const std = @import("std");
const assert = std.debug.assert;
const fs = std.fs;
const mem = std.mem;
const Allocator = std.mem.Allocator;
const Bundle = @import("../Bundle.zig");

pub const RescanMacError = Allocator.Error || fs.File.OpenError || fs.File.ReadError || fs.File.SeekError || Bundle.ParseCertError || error{EndOfStream};

pub fn rescan_mac(cb: *Bundle, gpa: Allocator) RescanMacError!void {
    cb.bytes.clear_retaining_capacity();
    cb.map.clear_retaining_capacity();

    const file = try fs.open_file_absolute("/System/Library/Keychains/SystemRootCertificates.keychain", .{});
    defer file.close();

    const bytes = try file.read_to_end_alloc(gpa, std.math.max_int(u32));
    defer gpa.free(bytes);

    var stream = std.io.fixed_buffer_stream(bytes);
    const reader = stream.reader();

    const db_header = try reader.read_struct_endian(ApplDbHeader, .big);
    assert(mem.eql(u8, &db_header.signature, "kych"));

    try stream.seek_to(db_header.schema_offset);

    const db_schema = try reader.read_struct_endian(ApplDbSchema, .big);

    var table_list = try gpa.alloc(u32, db_schema.table_count);
    defer gpa.free(table_list);

    var table_idx: u32 = 0;
    while (table_idx < table_list.len) : (table_idx += 1) {
        table_list[table_idx] = try reader.read_int(u32, .big);
    }

    const now_sec = std.time.timestamp();

    for (table_list) |table_offset| {
        try stream.seek_to(db_header.schema_offset + table_offset);

        const table_header = try reader.read_struct_endian(TableHeader, .big);

        if (@as(std.c.cssm.DB_RECORDTYPE, @enumFromInt(table_header.table_id)) != .X509_CERTIFICATE) {
            continue;
        }

        var record_list = try gpa.alloc(u32, table_header.record_count);
        defer gpa.free(record_list);

        var record_idx: u32 = 0;
        while (record_idx < record_list.len) : (record_idx += 1) {
            record_list[record_idx] = try reader.read_int(u32, .big);
        }

        for (record_list) |record_offset| {
            try stream.seek_to(db_header.schema_offset + table_offset + record_offset);

            const cert_header = try reader.read_struct_endian(X509CertHeader, .big);

            try cb.bytes.ensure_unused_capacity(gpa, cert_header.cert_size);

            const cert_start = @as(u32, @int_cast(cb.bytes.items.len));
            const dest_buf = cb.bytes.allocated_slice()[cert_start..];
            cb.bytes.items.len += try reader.read_at_least(dest_buf, cert_header.cert_size);

            try cb.parse_cert(gpa, cert_start, now_sec);
        }
    }

    cb.bytes.shrink_and_free(gpa, cb.bytes.items.len);
}

const ApplDbHeader = extern struct {
    signature: [4]u8,
    version: u32,
    header_size: u32,
    schema_offset: u32,
    auth_offset: u32,
};

const ApplDbSchema = extern struct {
    schema_size: u32,
    table_count: u32,
};

const TableHeader = extern struct {
    table_size: u32,
    table_id: u32,
    record_count: u32,
    records: u32,
    indexes_offset: u32,
    free_list_head: u32,
    record_numbers_count: u32,
};

const X509CertHeader = extern struct {
    record_size: u32,
    record_number: u32,
    unknown1: u32,
    unknown2: u32,
    cert_size: u32,
    unknown3: u32,
    cert_type: u32,
    cert_encoding: u32,
    print_name: u32,
    alias: u32,
    subject: u32,
    issuer: u32,
    serial_number: u32,
    subject_key_identifier: u32,
    public_key_hash: u32,
};
