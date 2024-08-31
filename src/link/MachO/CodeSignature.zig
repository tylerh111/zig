const CodeSignature = @This();

const std = @import("std");
const assert = std.debug.assert;
const fs = std.fs;
const log = std.log.scoped(.link);
const macho = std.macho;
const mem = std.mem;
const testing = std.testing;
const Allocator = mem.Allocator;
const Hasher = @import("hasher.zig").ParallelHasher;
const MachO = @import("../MachO.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;

const hash_size = Sha256.digest_length;

const Blob = union(enum) {
    code_directory: *CodeDirectory,
    requirements: *Requirements,
    entitlements: *Entitlements,
    signature: *Signature,

    fn slot_type(self: Blob) u32 {
        return switch (self) {
            .code_directory => |x| x.slot_type(),
            .requirements => |x| x.slot_type(),
            .entitlements => |x| x.slot_type(),
            .signature => |x| x.slot_type(),
        };
    }

    fn size(self: Blob) u32 {
        return switch (self) {
            .code_directory => |x| x.size(),
            .requirements => |x| x.size(),
            .entitlements => |x| x.size(),
            .signature => |x| x.size(),
        };
    }

    fn write(self: Blob, writer: anytype) !void {
        return switch (self) {
            .code_directory => |x| x.write(writer),
            .requirements => |x| x.write(writer),
            .entitlements => |x| x.write(writer),
            .signature => |x| x.write(writer),
        };
    }
};

const CodeDirectory = struct {
    inner: macho.CodeDirectory,
    ident: []const u8,
    special_slots: [n_special_slots][hash_size]u8,
    code_slots: std.ArrayListUnmanaged([hash_size]u8) = .{},

    const n_special_slots: usize = 7;

    fn init(page_size: u16) CodeDirectory {
        var cdir: CodeDirectory = .{
            .inner = .{
                .magic = macho.CSMAGIC_CODEDIRECTORY,
                .length = @size_of(macho.CodeDirectory),
                .version = macho.CS_SUPPORTSEXECSEG,
                .flags = macho.CS_ADHOC | macho.CS_LINKER_SIGNED,
                .hashOffset = 0,
                .identOffset = @size_of(macho.CodeDirectory),
                .nSpecialSlots = 0,
                .nCodeSlots = 0,
                .codeLimit = 0,
                .hashSize = hash_size,
                .hashType = macho.CS_HASHTYPE_SHA256,
                .platform = 0,
                .pageSize = @as(u8, @truncate(std.math.log2(page_size))),
                .spare2 = 0,
                .scatterOffset = 0,
                .teamOffset = 0,
                .spare3 = 0,
                .codeLimit64 = 0,
                .execSegBase = 0,
                .execSegLimit = 0,
                .execSegFlags = 0,
            },
            .ident = undefined,
            .special_slots = undefined,
        };
        comptime var i = 0;
        inline while (i < n_special_slots) : (i += 1) {
            cdir.special_slots[i] = [_]u8{0} ** hash_size;
        }
        return cdir;
    }

    fn deinit(self: *CodeDirectory, allocator: Allocator) void {
        self.code_slots.deinit(allocator);
    }

    fn add_special_hash(self: *CodeDirectory, index: u32, hash: [hash_size]u8) void {
        assert(index > 0);
        self.inner.nSpecialSlots = @max(self.inner.nSpecialSlots, index);
        @memcpy(&self.special_slots[index - 1], &hash);
    }

    fn slot_type(self: CodeDirectory) u32 {
        _ = self;
        return macho.CSSLOT_CODEDIRECTORY;
    }

    fn size(self: CodeDirectory) u32 {
        const code_slots = self.inner.nCodeSlots * hash_size;
        const special_slots = self.inner.nSpecialSlots * hash_size;
        return @size_of(macho.CodeDirectory) + @as(u32, @int_cast(self.ident.len + 1 + special_slots + code_slots));
    }

    fn write(self: CodeDirectory, writer: anytype) !void {
        try writer.write_int(u32, self.inner.magic, .big);
        try writer.write_int(u32, self.inner.length, .big);
        try writer.write_int(u32, self.inner.version, .big);
        try writer.write_int(u32, self.inner.flags, .big);
        try writer.write_int(u32, self.inner.hashOffset, .big);
        try writer.write_int(u32, self.inner.identOffset, .big);
        try writer.write_int(u32, self.inner.nSpecialSlots, .big);
        try writer.write_int(u32, self.inner.nCodeSlots, .big);
        try writer.write_int(u32, self.inner.codeLimit, .big);
        try writer.write_byte(self.inner.hashSize);
        try writer.write_byte(self.inner.hashType);
        try writer.write_byte(self.inner.platform);
        try writer.write_byte(self.inner.pageSize);
        try writer.write_int(u32, self.inner.spare2, .big);
        try writer.write_int(u32, self.inner.scatterOffset, .big);
        try writer.write_int(u32, self.inner.teamOffset, .big);
        try writer.write_int(u32, self.inner.spare3, .big);
        try writer.write_int(u64, self.inner.codeLimit64, .big);
        try writer.write_int(u64, self.inner.execSegBase, .big);
        try writer.write_int(u64, self.inner.execSegLimit, .big);
        try writer.write_int(u64, self.inner.execSegFlags, .big);

        try writer.write_all(self.ident);
        try writer.write_byte(0);

        var i: isize = @as(isize, @int_cast(self.inner.nSpecialSlots));
        while (i > 0) : (i -= 1) {
            try writer.write_all(&self.special_slots[@as(usize, @int_cast(i - 1))]);
        }

        for (self.code_slots.items) |slot| {
            try writer.write_all(&slot);
        }
    }
};

const Requirements = struct {
    fn deinit(self: *Requirements, allocator: Allocator) void {
        _ = self;
        _ = allocator;
    }

    fn slot_type(self: Requirements) u32 {
        _ = self;
        return macho.CSSLOT_REQUIREMENTS;
    }

    fn size(self: Requirements) u32 {
        _ = self;
        return 3 * @size_of(u32);
    }

    fn write(self: Requirements, writer: anytype) !void {
        try writer.write_int(u32, macho.CSMAGIC_REQUIREMENTS, .big);
        try writer.write_int(u32, self.size(), .big);
        try writer.write_int(u32, 0, .big);
    }
};

const Entitlements = struct {
    inner: []const u8,

    fn deinit(self: *Entitlements, allocator: Allocator) void {
        allocator.free(self.inner);
    }

    fn slot_type(self: Entitlements) u32 {
        _ = self;
        return macho.CSSLOT_ENTITLEMENTS;
    }

    fn size(self: Entitlements) u32 {
        return @as(u32, @int_cast(self.inner.len)) + 2 * @size_of(u32);
    }

    fn write(self: Entitlements, writer: anytype) !void {
        try writer.write_int(u32, macho.CSMAGIC_EMBEDDED_ENTITLEMENTS, .big);
        try writer.write_int(u32, self.size(), .big);
        try writer.write_all(self.inner);
    }
};

const Signature = struct {
    fn deinit(self: *Signature, allocator: Allocator) void {
        _ = self;
        _ = allocator;
    }

    fn slot_type(self: Signature) u32 {
        _ = self;
        return macho.CSSLOT_SIGNATURESLOT;
    }

    fn size(self: Signature) u32 {
        _ = self;
        return 2 * @size_of(u32);
    }

    fn write(self: Signature, writer: anytype) !void {
        try writer.write_int(u32, macho.CSMAGIC_BLOBWRAPPER, .big);
        try writer.write_int(u32, self.size(), .big);
    }
};

page_size: u16,
code_directory: CodeDirectory,
requirements: ?Requirements = null,
entitlements: ?Entitlements = null,
signature: ?Signature = null,

pub fn init(page_size: u16) CodeSignature {
    return .{
        .page_size = page_size,
        .code_directory = CodeDirectory.init(page_size),
    };
}

pub fn deinit(self: *CodeSignature, allocator: Allocator) void {
    self.code_directory.deinit(allocator);
    if (self.requirements) |*req| {
        req.deinit(allocator);
    }
    if (self.entitlements) |*ents| {
        ents.deinit(allocator);
    }
    if (self.signature) |*sig| {
        sig.deinit(allocator);
    }
}

pub fn add_entitlements(self: *CodeSignature, allocator: Allocator, path: []const u8) !void {
    const file = try fs.cwd().open_file(path, .{});
    defer file.close();
    const inner = try file.read_to_end_alloc(allocator, std.math.max_int(u32));
    self.entitlements = .{ .inner = inner };
}

pub const WriteOpts = struct {
    file: fs.File,
    exec_seg_base: u64,
    exec_seg_limit: u64,
    file_size: u32,
    dylib: bool,
};

pub fn write_adhoc_signature(
    self: *CodeSignature,
    macho_file: *MachO,
    opts: WriteOpts,
    writer: anytype,
) !void {
    const allocator = macho_file.base.comp.gpa;

    var header: macho.SuperBlob = .{
        .magic = macho.CSMAGIC_EMBEDDED_SIGNATURE,
        .length = @size_of(macho.SuperBlob),
        .count = 0,
    };

    var blobs = std.ArrayList(Blob).init(allocator);
    defer blobs.deinit();

    self.code_directory.inner.execSegBase = opts.exec_seg_base;
    self.code_directory.inner.execSegLimit = opts.exec_seg_limit;
    self.code_directory.inner.execSegFlags = if (!opts.dylib) macho.CS_EXECSEG_MAIN_BINARY else 0;
    self.code_directory.inner.codeLimit = opts.file_size;

    const total_pages = @as(u32, @int_cast(mem.align_forward(usize, opts.file_size, self.page_size) / self.page_size));

    try self.code_directory.code_slots.ensure_total_capacity_precise(allocator, total_pages);
    self.code_directory.code_slots.items.len = total_pages;
    self.code_directory.inner.nCodeSlots = total_pages;

    // Calculate hash for each page (in file) and write it to the buffer
    var hasher = Hasher(Sha256){ .allocator = allocator, .thread_pool = macho_file.base.comp.thread_pool };
    try hasher.hash(opts.file, self.code_directory.code_slots.items, .{
        .chunk_size = self.page_size,
        .max_file_size = opts.file_size,
    });

    try blobs.append(.{ .code_directory = &self.code_directory });
    header.length += @size_of(macho.BlobIndex);
    header.count += 1;

    var hash: [hash_size]u8 = undefined;

    if (self.requirements) |*req| {
        var buf = std.ArrayList(u8).init(allocator);
        defer buf.deinit();
        try req.write(buf.writer());
        Sha256.hash(buf.items, &hash, .{});
        self.code_directory.add_special_hash(req.slot_type(), hash);

        try blobs.append(.{ .requirements = req });
        header.count += 1;
        header.length += @size_of(macho.BlobIndex) + req.size();
    }

    if (self.entitlements) |*ents| {
        var buf = std.ArrayList(u8).init(allocator);
        defer buf.deinit();
        try ents.write(buf.writer());
        Sha256.hash(buf.items, &hash, .{});
        self.code_directory.add_special_hash(ents.slot_type(), hash);

        try blobs.append(.{ .entitlements = ents });
        header.count += 1;
        header.length += @size_of(macho.BlobIndex) + ents.size();
    }

    if (self.signature) |*sig| {
        try blobs.append(.{ .signature = sig });
        header.count += 1;
        header.length += @size_of(macho.BlobIndex) + sig.size();
    }

    self.code_directory.inner.hashOffset =
        @size_of(macho.CodeDirectory) + @as(u32, @int_cast(self.code_directory.ident.len + 1 + self.code_directory.inner.nSpecialSlots * hash_size));
    self.code_directory.inner.length = self.code_directory.size();
    header.length += self.code_directory.size();

    try writer.write_int(u32, header.magic, .big);
    try writer.write_int(u32, header.length, .big);
    try writer.write_int(u32, header.count, .big);

    var offset: u32 = @size_of(macho.SuperBlob) + @size_of(macho.BlobIndex) * @as(u32, @int_cast(blobs.items.len));
    for (blobs.items) |blob| {
        try writer.write_int(u32, blob.slot_type(), .big);
        try writer.write_int(u32, offset, .big);
        offset += blob.size();
    }

    for (blobs.items) |blob| {
        try blob.write(writer);
    }
}

pub fn size(self: CodeSignature) u32 {
    var ssize: u32 = @size_of(macho.SuperBlob) + @size_of(macho.BlobIndex) + self.code_directory.size();
    if (self.requirements) |req| {
        ssize += @size_of(macho.BlobIndex) + req.size();
    }
    if (self.entitlements) |ent| {
        ssize += @size_of(macho.BlobIndex) + ent.size();
    }
    if (self.signature) |sig| {
        ssize += @size_of(macho.BlobIndex) + sig.size();
    }
    return ssize;
}

pub fn estimate_size(self: CodeSignature, file_size: u64) u32 {
    var ssize: u64 = @size_of(macho.SuperBlob) + @size_of(macho.BlobIndex) + self.code_directory.size();
    // Approx code slots
    const total_pages = mem.align_forward(u64, file_size, self.page_size) / self.page_size;
    ssize += total_pages * hash_size;
    var n_special_slots: u32 = 0;
    if (self.requirements) |req| {
        ssize += @size_of(macho.BlobIndex) + req.size();
        n_special_slots = @max(n_special_slots, req.slot_type());
    }
    if (self.entitlements) |ent| {
        ssize += @size_of(macho.BlobIndex) + ent.size() + hash_size;
        n_special_slots = @max(n_special_slots, ent.slot_type());
    }
    if (self.signature) |sig| {
        ssize += @size_of(macho.BlobIndex) + sig.size();
    }
    ssize += n_special_slots * hash_size;
    return @as(u32, @int_cast(mem.align_forward(u64, ssize, @size_of(u64))));
}

pub fn clear(self: *CodeSignature, allocator: Allocator) void {
    self.code_directory.deinit(allocator);
    self.code_directory = CodeDirectory.init(self.page_size);
}
