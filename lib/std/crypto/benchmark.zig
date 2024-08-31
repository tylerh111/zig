// zig run -O ReleaseFast --zig-lib-dir ../.. benchmark.zig

const std = @import("std");
const builtin = @import("builtin");
const mem = std.mem;
const time = std.time;
const Timer = time.Timer;
const crypto = std.crypto;

const KiB = 1024;
const MiB = 1024 * KiB;

var prng = std.Random.DefaultPrng.init(0);
const random = prng.random();

const Crypto = struct {
    ty: type,
    name: []const u8,
};

const hashes = [_]Crypto{
    Crypto{ .ty = crypto.hash.Md5, .name = "md5" },
    Crypto{ .ty = crypto.hash.Sha1, .name = "sha1" },
    Crypto{ .ty = crypto.hash.sha2.Sha256, .name = "sha256" },
    Crypto{ .ty = crypto.hash.sha2.Sha512, .name = "sha512" },
    Crypto{ .ty = crypto.hash.sha3.Sha3_256, .name = "sha3-256" },
    Crypto{ .ty = crypto.hash.sha3.Sha3_512, .name = "sha3-512" },
    Crypto{ .ty = crypto.hash.sha3.Shake128, .name = "shake-128" },
    Crypto{ .ty = crypto.hash.sha3.Shake256, .name = "shake-256" },
    Crypto{ .ty = crypto.hash.sha3.TurboShake128(null), .name = "turboshake-128" },
    Crypto{ .ty = crypto.hash.sha3.TurboShake256(null), .name = "turboshake-256" },
    Crypto{ .ty = crypto.hash.blake2.Blake2s256, .name = "blake2s" },
    Crypto{ .ty = crypto.hash.blake2.Blake2b512, .name = "blake2b" },
    Crypto{ .ty = crypto.hash.Blake3, .name = "blake3" },
};

const block_size: usize = 8 * 8192;

pub fn benchmark_hash(comptime Hash: anytype, comptime bytes: comptime_int) !u64 {
    const blocks_count = bytes / block_size;
    var block: [block_size]u8 = undefined;
    random.bytes(&block);

    var h = Hash.init(.{});

    var timer = try Timer.start();
    const start = timer.lap();
    for (0..blocks_count) |_| {
        h.update(&block);
    }
    var final: [Hash.digest_length]u8 = undefined;
    h.final(&final);
    std.mem.do_not_optimize_away(final);

    const end = timer.read();

    const elapsed_s = @as(f64, @float_from_int(end - start)) / time.ns_per_s;
    const throughput = @as(u64, @int_from_float(bytes / elapsed_s));

    return throughput;
}

const macs = [_]Crypto{
    Crypto{ .ty = crypto.onetimeauth.Ghash, .name = "ghash" },
    Crypto{ .ty = crypto.onetimeauth.Polyval, .name = "polyval" },
    Crypto{ .ty = crypto.onetimeauth.Poly1305, .name = "poly1305" },
    Crypto{ .ty = crypto.auth.hmac.HmacMd5, .name = "hmac-md5" },
    Crypto{ .ty = crypto.auth.hmac.HmacSha1, .name = "hmac-sha1" },
    Crypto{ .ty = crypto.auth.hmac.sha2.HmacSha256, .name = "hmac-sha256" },
    Crypto{ .ty = crypto.auth.hmac.sha2.HmacSha512, .name = "hmac-sha512" },
    Crypto{ .ty = crypto.auth.siphash.SipHash64(2, 4), .name = "siphash-2-4" },
    Crypto{ .ty = crypto.auth.siphash.SipHash64(1, 3), .name = "siphash-1-3" },
    Crypto{ .ty = crypto.auth.siphash.SipHash128(2, 4), .name = "siphash128-2-4" },
    Crypto{ .ty = crypto.auth.siphash.SipHash128(1, 3), .name = "siphash128-1-3" },
    Crypto{ .ty = crypto.auth.aegis.Aegis128LMac, .name = "aegis-128l mac" },
    Crypto{ .ty = crypto.auth.aegis.Aegis256Mac, .name = "aegis-256 mac" },
    Crypto{ .ty = crypto.auth.cmac.CmacAes128, .name = "aes-cmac" },
};

pub fn benchmark_mac(comptime Mac: anytype, comptime bytes: comptime_int) !u64 {
    var in: [512 * KiB]u8 = undefined;
    random.bytes(in[0..]);

    const key_length = if (Mac.key_length == 0) 32 else Mac.key_length;
    var key: [key_length]u8 = undefined;
    random.bytes(key[0..]);

    var mac: [Mac.mac_length]u8 = undefined;
    var offset: usize = 0;
    var timer = try Timer.start();
    const start = timer.lap();
    while (offset < bytes) : (offset += in.len) {
        Mac.create(mac[0..], in[0..], key[0..]);
        mem.do_not_optimize_away(&mac);
    }
    const end = timer.read();

    const elapsed_s = @as(f64, @float_from_int(end - start)) / time.ns_per_s;
    const throughput = @as(u64, @int_from_float(bytes / elapsed_s));

    return throughput;
}

const exchanges = [_]Crypto{Crypto{ .ty = crypto.dh.X25519, .name = "x25519" }};

pub fn benchmark_key_exchange(comptime DhKeyExchange: anytype, comptime exchange_count: comptime_int) !u64 {
    std.debug.assert(DhKeyExchange.shared_length >= DhKeyExchange.secret_length);

    var secret: [DhKeyExchange.shared_length]u8 = undefined;
    random.bytes(secret[0..]);

    var public: [DhKeyExchange.shared_length]u8 = undefined;
    random.bytes(public[0..]);

    var timer = try Timer.start();
    const start = timer.lap();
    {
        var i: usize = 0;
        while (i < exchange_count) : (i += 1) {
            const out = try DhKeyExchange.scalarmult(secret, public);
            secret[0..16].* = out[0..16].*;
            public[0..16].* = out[16..32].*;
            mem.do_not_optimize_away(&out);
        }
    }
    const end = timer.read();

    const elapsed_s = @as(f64, @float_from_int(end - start)) / time.ns_per_s;
    const throughput = @as(u64, @int_from_float(exchange_count / elapsed_s));

    return throughput;
}

const signatures = [_]Crypto{
    Crypto{ .ty = crypto.sign.Ed25519, .name = "ed25519" },
    Crypto{ .ty = crypto.sign.ecdsa.EcdsaP256Sha256, .name = "ecdsa-p256" },
    Crypto{ .ty = crypto.sign.ecdsa.EcdsaP384Sha384, .name = "ecdsa-p384" },
    Crypto{ .ty = crypto.sign.ecdsa.EcdsaSecp256k1Sha256, .name = "ecdsa-secp256k1" },
};

pub fn benchmark_signature(comptime Signature: anytype, comptime signatures_count: comptime_int) !u64 {
    const msg = [_]u8{0} ** 64;
    const key_pair = try Signature.KeyPair.create(null);

    var timer = try Timer.start();
    const start = timer.lap();
    {
        var i: usize = 0;
        while (i < signatures_count) : (i += 1) {
            const sig = try key_pair.sign(&msg, null);
            mem.do_not_optimize_away(&sig);
        }
    }
    const end = timer.read();

    const elapsed_s = @as(f64, @float_from_int(end - start)) / time.ns_per_s;
    const throughput = @as(u64, @int_from_float(signatures_count / elapsed_s));

    return throughput;
}

const signature_verifications = [_]Crypto{Crypto{ .ty = crypto.sign.Ed25519, .name = "ed25519" }};

pub fn benchmark_signature_verification(comptime Signature: anytype, comptime signatures_count: comptime_int) !u64 {
    const msg = [_]u8{0} ** 64;
    const key_pair = try Signature.KeyPair.create(null);
    const sig = try key_pair.sign(&msg, null);

    var timer = try Timer.start();
    const start = timer.lap();
    {
        var i: usize = 0;
        while (i < signatures_count) : (i += 1) {
            try sig.verify(&msg, key_pair.public_key);
            mem.do_not_optimize_away(&sig);
        }
    }
    const end = timer.read();

    const elapsed_s = @as(f64, @float_from_int(end - start)) / time.ns_per_s;
    const throughput = @as(u64, @int_from_float(signatures_count / elapsed_s));

    return throughput;
}

const batch_signature_verifications = [_]Crypto{Crypto{ .ty = crypto.sign.Ed25519, .name = "ed25519" }};

pub fn benchmark_batch_signature_verification(comptime Signature: anytype, comptime signatures_count: comptime_int) !u64 {
    const msg = [_]u8{0} ** 64;
    const key_pair = try Signature.KeyPair.create(null);
    const sig = try key_pair.sign(&msg, null);

    var batch: [64]Signature.BatchElement = undefined;
    for (&batch) |*element| {
        element.* = Signature.BatchElement{ .sig = sig, .msg = &msg, .public_key = key_pair.public_key };
    }

    var timer = try Timer.start();
    const start = timer.lap();
    {
        var i: usize = 0;
        while (i < signatures_count) : (i += 1) {
            try Signature.verify_batch(batch.len, batch);
            mem.do_not_optimize_away(&sig);
        }
    }
    const end = timer.read();

    const elapsed_s = @as(f64, @float_from_int(end - start)) / time.ns_per_s;
    const throughput = batch.len * @as(u64, @int_from_float(signatures_count / elapsed_s));

    return throughput;
}

const kems = [_]Crypto{
    Crypto{ .ty = crypto.kem.kyber_d00.Kyber512, .name = "kyber512d00" },
    Crypto{ .ty = crypto.kem.kyber_d00.Kyber768, .name = "kyber768d00" },
    Crypto{ .ty = crypto.kem.kyber_d00.Kyber1024, .name = "kyber1024d00" },
};

pub fn benchmark_kem(comptime Kem: anytype, comptime kems_count: comptime_int) !u64 {
    const key_pair = try Kem.KeyPair.create(null);

    var timer = try Timer.start();
    const start = timer.lap();
    {
        var i: usize = 0;
        while (i < kems_count) : (i += 1) {
            const e = key_pair.public_key.encaps(null);
            mem.do_not_optimize_away(&e);
        }
    }
    const end = timer.read();

    const elapsed_s = @as(f64, @float_from_int(end - start)) / time.ns_per_s;
    const throughput = @as(u64, @int_from_float(kems_count / elapsed_s));

    return throughput;
}

pub fn benchmark_kem_decaps(comptime Kem: anytype, comptime kems_count: comptime_int) !u64 {
    const key_pair = try Kem.KeyPair.create(null);

    const e = key_pair.public_key.encaps(null);

    var timer = try Timer.start();
    const start = timer.lap();
    {
        var i: usize = 0;
        while (i < kems_count) : (i += 1) {
            const ss2 = try key_pair.secret_key.decaps(&e.ciphertext);
            mem.do_not_optimize_away(&ss2);
        }
    }
    const end = timer.read();

    const elapsed_s = @as(f64, @float_from_int(end - start)) / time.ns_per_s;
    const throughput = @as(u64, @int_from_float(kems_count / elapsed_s));

    return throughput;
}

pub fn benchmark_kem_key_gen(comptime Kem: anytype, comptime kems_count: comptime_int) !u64 {
    var timer = try Timer.start();
    const start = timer.lap();
    {
        var i: usize = 0;
        while (i < kems_count) : (i += 1) {
            const key_pair = try Kem.KeyPair.create(null);
            mem.do_not_optimize_away(&key_pair);
        }
    }
    const end = timer.read();

    const elapsed_s = @as(f64, @float_from_int(end - start)) / time.ns_per_s;
    const throughput = @as(u64, @int_from_float(kems_count / elapsed_s));

    return throughput;
}

const aeads = [_]Crypto{
    Crypto{ .ty = crypto.aead.chacha_poly.ChaCha20Poly1305, .name = "chacha20Poly1305" },
    Crypto{ .ty = crypto.aead.chacha_poly.XChaCha20Poly1305, .name = "xchacha20Poly1305" },
    Crypto{ .ty = crypto.aead.chacha_poly.XChaCha8Poly1305, .name = "xchacha8Poly1305" },
    Crypto{ .ty = crypto.aead.salsa_poly.XSalsa20Poly1305, .name = "xsalsa20Poly1305" },
    Crypto{ .ty = crypto.aead.aegis.Aegis128L, .name = "aegis-128l" },
    Crypto{ .ty = crypto.aead.aegis.Aegis256, .name = "aegis-256" },
    Crypto{ .ty = crypto.aead.aes_gcm.Aes128Gcm, .name = "aes128-gcm" },
    Crypto{ .ty = crypto.aead.aes_gcm.Aes256Gcm, .name = "aes256-gcm" },
    Crypto{ .ty = crypto.aead.aes_ocb.Aes128Ocb, .name = "aes128-ocb" },
    Crypto{ .ty = crypto.aead.aes_ocb.Aes256Ocb, .name = "aes256-ocb" },
    Crypto{ .ty = crypto.aead.isap.IsapA128A, .name = "isapa128a" },
};

pub fn benchmark_aead(comptime Aead: anytype, comptime bytes: comptime_int) !u64 {
    var in: [512 * KiB]u8 = undefined;
    random.bytes(in[0..]);

    var tag: [Aead.tag_length]u8 = undefined;

    var key: [Aead.key_length]u8 = undefined;
    random.bytes(key[0..]);

    var nonce: [Aead.nonce_length]u8 = undefined;
    random.bytes(nonce[0..]);

    var offset: usize = 0;
    var timer = try Timer.start();
    const start = timer.lap();
    while (offset < bytes) : (offset += in.len) {
        Aead.encrypt(in[0..], tag[0..], in[0..], &[_]u8{}, nonce, key);
        try Aead.decrypt(in[0..], in[0..], tag, &[_]u8{}, nonce, key);
    }
    mem.do_not_optimize_away(&in);
    const end = timer.read();

    const elapsed_s = @as(f64, @float_from_int(end - start)) / time.ns_per_s;
    const throughput = @as(u64, @int_from_float(2 * bytes / elapsed_s));

    return throughput;
}

const aes = [_]Crypto{
    Crypto{ .ty = crypto.core.aes.Aes128, .name = "aes128-single" },
    Crypto{ .ty = crypto.core.aes.Aes256, .name = "aes256-single" },
};

pub fn benchmark_aes(comptime Aes: anytype, comptime count: comptime_int) !u64 {
    var key: [Aes.key_bits / 8]u8 = undefined;
    random.bytes(key[0..]);
    const ctx = Aes.init_enc(key);

    var in = [_]u8{0} ** 16;

    var timer = try Timer.start();
    const start = timer.lap();
    {
        var i: usize = 0;
        while (i < count) : (i += 1) {
            ctx.encrypt(&in, &in);
        }
    }
    mem.do_not_optimize_away(&in);
    const end = timer.read();

    const elapsed_s = @as(f64, @float_from_int(end - start)) / time.ns_per_s;
    const throughput = @as(u64, @int_from_float(count / elapsed_s));

    return throughput;
}

const aes8 = [_]Crypto{
    Crypto{ .ty = crypto.core.aes.Aes128, .name = "aes128-8" },
    Crypto{ .ty = crypto.core.aes.Aes256, .name = "aes256-8" },
};

pub fn benchmark_aes8(comptime Aes: anytype, comptime count: comptime_int) !u64 {
    var key: [Aes.key_bits / 8]u8 = undefined;
    random.bytes(key[0..]);
    const ctx = Aes.init_enc(key);

    var in = [_]u8{0} ** (8 * 16);

    var timer = try Timer.start();
    const start = timer.lap();
    {
        var i: usize = 0;
        while (i < count) : (i += 1) {
            ctx.encrypt_wide(8, &in, &in);
        }
    }
    mem.do_not_optimize_away(&in);
    const end = timer.read();

    const elapsed_s = @as(f64, @float_from_int(end - start)) / time.ns_per_s;
    const throughput = @as(u64, @int_from_float(8 * count / elapsed_s));

    return throughput;
}

const CryptoPwhash = struct {
    ty: type,
    params: *const anyopaque,
    name: []const u8,
};
const bcrypt_params = crypto.pwhash.bcrypt.Params{ .rounds_log = 8 };
const pwhashes = [_]CryptoPwhash{
    .{
        .ty = crypto.pwhash.bcrypt,
        .params = &bcrypt_params,
        .name = "bcrypt",
    },
    .{
        .ty = crypto.pwhash.scrypt,
        .params = &crypto.pwhash.scrypt.Params.interactive,
        .name = "scrypt",
    },
    .{
        .ty = crypto.pwhash.argon2,
        .params = &crypto.pwhash.argon2.Params.interactive_2id,
        .name = "argon2",
    },
};

fn benchmark_pwhash(
    allocator: mem.Allocator,
    comptime ty: anytype,
    comptime params: *const anyopaque,
    comptime count: comptime_int,
) !f64 {
    const password = "testpass" ** 2;
    const opts = .{
        .allocator = allocator,
        .params = @as(*const ty.Params, @ptr_cast(@align_cast(params))).*,
        .encoding = .phc,
    };
    var buf: [256]u8 = undefined;

    var timer = try Timer.start();
    const start = timer.lap();
    {
        var i: usize = 0;
        while (i < count) : (i += 1) {
            _ = try ty.str_hash(password, opts, &buf);
            mem.do_not_optimize_away(&buf);
        }
    }
    const end = timer.read();

    const elapsed_s = @as(f64, @float_from_int(end - start)) / time.ns_per_s;
    const throughput = elapsed_s / count;

    return throughput;
}

fn usage() void {
    std.debug.print(
        \\throughput_test [options]
        \\
        \\Options:
        \\  --filter [test-name]
        \\  --seed   [int]
        \\  --help
        \\
    , .{});
}

fn mode(comptime x: comptime_int) comptime_int {
    return if (builtin.mode == .Debug) x / 64 else x;
}

pub fn main() !void {
    const stdout = std.io.get_std_out().writer();

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const arena_allocator = arena.allocator();
    const args = try std.process.args_alloc(arena_allocator);

    var filter: ?[]u8 = "";

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--mode")) {
            try stdout.print("{}\n", .{builtin.mode});
            return;
        } else if (std.mem.eql(u8, args[i], "--seed")) {
            i += 1;
            if (i == args.len) {
                usage();
                std.process.exit(1);
            }

            const seed = try std.fmt.parse_unsigned(u32, args[i], 10);
            prng.seed(seed);
        } else if (std.mem.eql(u8, args[i], "--filter")) {
            i += 1;
            if (i == args.len) {
                usage();
                std.process.exit(1);
            }

            filter = args[i];
        } else if (std.mem.eql(u8, args[i], "--help")) {
            usage();
            return;
        } else {
            usage();
            std.process.exit(1);
        }
    }

    inline for (hashes) |H| {
        if (filter == null or std.mem.index_of(u8, H.name, filter.?) != null) {
            const throughput = try benchmark_hash(H.ty, mode(128 * MiB));
            try stdout.print("{s:>17}: {:10} MiB/s\n", .{ H.name, throughput / (1 * MiB) });
        }
    }

    inline for (macs) |M| {
        if (filter == null or std.mem.index_of(u8, M.name, filter.?) != null) {
            const throughput = try benchmark_mac(M.ty, mode(128 * MiB));
            try stdout.print("{s:>17}: {:10} MiB/s\n", .{ M.name, throughput / (1 * MiB) });
        }
    }

    inline for (exchanges) |E| {
        if (filter == null or std.mem.index_of(u8, E.name, filter.?) != null) {
            const throughput = try benchmark_key_exchange(E.ty, mode(1000));
            try stdout.print("{s:>17}: {:10} exchanges/s\n", .{ E.name, throughput });
        }
    }

    inline for (signatures) |E| {
        if (filter == null or std.mem.index_of(u8, E.name, filter.?) != null) {
            const throughput = try benchmark_signature(E.ty, mode(1000));
            try stdout.print("{s:>17}: {:10} signatures/s\n", .{ E.name, throughput });
        }
    }

    inline for (signature_verifications) |E| {
        if (filter == null or std.mem.index_of(u8, E.name, filter.?) != null) {
            const throughput = try benchmark_signature_verification(E.ty, mode(1000));
            try stdout.print("{s:>17}: {:10} verifications/s\n", .{ E.name, throughput });
        }
    }

    inline for (batch_signature_verifications) |E| {
        if (filter == null or std.mem.index_of(u8, E.name, filter.?) != null) {
            const throughput = try benchmark_batch_signature_verification(E.ty, mode(1000));
            try stdout.print("{s:>17}: {:10} verifications/s (batch)\n", .{ E.name, throughput });
        }
    }

    inline for (aeads) |E| {
        if (filter == null or std.mem.index_of(u8, E.name, filter.?) != null) {
            const throughput = try benchmark_aead(E.ty, mode(128 * MiB));
            try stdout.print("{s:>17}: {:10} MiB/s\n", .{ E.name, throughput / (1 * MiB) });
        }
    }

    inline for (aes) |E| {
        if (filter == null or std.mem.index_of(u8, E.name, filter.?) != null) {
            const throughput = try benchmark_aes(E.ty, mode(100000000));
            try stdout.print("{s:>17}: {:10} ops/s\n", .{ E.name, throughput });
        }
    }

    inline for (aes8) |E| {
        if (filter == null or std.mem.index_of(u8, E.name, filter.?) != null) {
            const throughput = try benchmark_aes8(E.ty, mode(10000000));
            try stdout.print("{s:>17}: {:10} ops/s\n", .{ E.name, throughput });
        }
    }

    inline for (pwhashes) |H| {
        if (filter == null or std.mem.index_of(u8, H.name, filter.?) != null) {
            const throughput = try benchmark_pwhash(arena_allocator, H.ty, H.params, mode(64));
            try stdout.print("{s:>17}: {d:10.3} s/ops\n", .{ H.name, throughput });
        }
    }

    inline for (kems) |E| {
        if (filter == null or std.mem.index_of(u8, E.name, filter.?) != null) {
            const throughput = try benchmark_kem(E.ty, mode(1000));
            try stdout.print("{s:>17}: {:10} encaps/s\n", .{ E.name, throughput });
        }
    }

    inline for (kems) |E| {
        if (filter == null or std.mem.index_of(u8, E.name, filter.?) != null) {
            const throughput = try benchmark_kem_decaps(E.ty, mode(25000));
            try stdout.print("{s:>17}: {:10} decaps/s\n", .{ E.name, throughput });
        }
    }

    inline for (kems) |E| {
        if (filter == null or std.mem.index_of(u8, E.name, filter.?) != null) {
            const throughput = try benchmark_kem_key_gen(E.ty, mode(25000));
            try stdout.print("{s:>17}: {:10} keygen/s\n", .{ E.name, throughput });
        }
    }
}
