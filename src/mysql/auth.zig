// MySQL authentication methods.
// Originally from myzql library (MIT License, Copyright (c) 2023 Zack).
const std = @import("std");
const builtin = @import("builtin");
const PublicKey = std.crypto.Certificate.rsa.PublicKey;
const Sha1 = std.crypto.hash.Sha1;
const Sha256 = std.crypto.hash.sha2.Sha256;

const base64 = std.base64.standard.decoderWithIgnore(" \t\r\n");

pub const AuthPlugin = enum {
    unspecified,
    mysql_native_password,
    sha256_password,
    caching_sha2_password,
    mysql_clear_password,
    unknown,

    pub fn fromName(name: []const u8) AuthPlugin {
        return std.meta.stringToEnum(AuthPlugin, name) orelse .unknown;
    }

    pub fn toName(auth_plugin: AuthPlugin) [:0]const u8 {
        return @tagName(auth_plugin);
    }
};

// https://mariadb.com/kb/en/sha256_password-plugin/
pub const sha256_password_public_key_request = 0x01;

// https://dev.mysql.com/doc/dev/mysql-server/latest/page_caching_sha2_authentication_exchanges.html
// https://mariadb.com/kb/en/caching_sha2_password-authentication-plugin/
pub const caching_sha2_password_public_key_response = 0x01;
pub const caching_sha2_password_public_key_request = 0x02;
pub const caching_sha2_password_fast_auth_success = 0x03;
pub const caching_sha2_password_full_authentication_start = 0x04;

pub const DecodedPublicKey = struct {
    allocated: []const u8,
    value: std.crypto.Certificate.rsa.PublicKey,

    pub fn deinit(d: *const DecodedPublicKey, allocator: std.mem.Allocator) void {
        allocator.free(d.allocated);
    }
};

pub fn decodePublicKey(encoded_bytes: []const u8, allocator: std.mem.Allocator) !DecodedPublicKey {
    var decoded_pk: DecodedPublicKey = undefined;

    const start_marker = "-----BEGIN PUBLIC KEY-----";
    const end_marker = "-----END PUBLIC KEY-----";

    const base64_encoded = blk: {
        const start_marker_pos = std.mem.indexOfPos(u8, encoded_bytes, 0, start_marker).?;
        const base64_start = start_marker_pos + start_marker.len;
        const base64_end = std.mem.indexOfPos(u8, encoded_bytes, base64_start, end_marker).?;
        break :blk std.mem.trim(u8, encoded_bytes[base64_start..base64_end], " \t\r\n");
    };

    const dest = try allocator.alloc(u8, base64.calcSizeUpperBound(base64_encoded.len));
    decoded_pk.allocated = dest;
    errdefer allocator.free(decoded_pk.allocated);

    const base64_decoded = blk: {
        const n = try base64.decode(dest, base64_encoded);
        break :blk decoded_pk.allocated[0..n];
    };

    const bitstring = blk: {
        const Element = std.crypto.Certificate.der.Element;
        const top_level = try Element.parse(base64_decoded, 0);
        const seq_1 = try Element.parse(base64_decoded, top_level.slice.start);
        const bitstring_elem = try Element.parse(base64_decoded, seq_1.slice.end);
        break :blk std.mem.trim(u8, base64_decoded[bitstring_elem.slice.start..bitstring_elem.slice.end], &.{0});
    };

    const pk_decoded = try std.crypto.Certificate.rsa.PublicKey.parseDer(bitstring);
    decoded_pk.value = try std.crypto.Certificate.rsa.PublicKey.fromBytes(pk_decoded.exponent, pk_decoded.modulus);
    return decoded_pk;
}

// https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_authentication_methods_native_password_authentication.html
// SHA1(password) XOR SHA1(scramble ++ SHA1(SHA1(password)))
pub fn scramblePassword(scramble: []const u8, password: []const u8) [20]u8 {
    var message1 = blk: { // SHA1(password)
        var sha1 = Sha1.init(.{});
        sha1.update(password);
        break :blk sha1.finalResult();
    };
    const message2 = blk: { // SHA1(SHA1(password))
        var sha1 = Sha1.init(.{});
        sha1.update(&message1);
        var hash = sha1.finalResult();

        sha1 = Sha1.init(.{});
        sha1.update(scramble);
        sha1.update(&hash);
        sha1.final(&hash);
        break :blk hash;
    };
    for (&message1, message2) |*m1, m2| {
        m1.* ^= m2;
    }
    return message1;
}

// https://dev.mysql.com/doc/dev/mysql-server/latest/page_caching_sha2_authentication_exchanges.html
// XOR(SHA256(password), SHA256(SHA256(SHA256(password)), scramble))
pub fn scrambleSHA256Password(scramble: []const u8, password: []const u8) [32]u8 {
    std.debug.assert(password.len > 0);

    var message1 = blk: { // SHA256(password)
        var hasher = Sha256.init(.{});
        hasher.update(password);
        break :blk hasher.finalResult();
    };
    const message2 = blk: { // SHA256(SHA256(SHA256(password)), scramble)
        var sha256 = Sha256.init(.{});
        sha256.update(&message1);
        var hash = sha256.finalResult();

        sha256 = Sha256.init(.{});
        sha256.update(&hash);
        sha256.update(scramble);
        sha256.final(&hash);
        break :blk hash;
    };
    for (&message1, message2) |*m1, m2| {
        m1.* ^= m2;
    }
    return message1;
}

// https://mariadb.com/kb/en/sha256_password-plugin/#rsa-encrypted-password
// RSA encrypted value of XOR(password, seed) using server public key (RSA_PKCS1_OAEP_PADDING).
pub fn encryptPassword(allocator: std.mem.Allocator, password: []const u8, seed: *const [20]u8, pk: *const PublicKey) ![]const u8 {
    const plain = blk: {
        var plain = try allocator.alloc(u8, password.len + 1);
        @memcpy(plain.ptr, password);
        plain[plain.len - 1] = 0;
        break :blk plain;
    };
    defer allocator.free(plain);

    for (plain, 0..) |*c, i| {
        c.* ^= seed[i % 20];
    }

    return rsaEncryptOAEP(allocator, plain, pk);
}

/// Fill buffer with cryptographically secure random bytes.
/// Uses arc4random_buf on BSD/macOS, getrandom syscall on Linux.
fn fillRandomBytes(buf: []u8) void {
    if (comptime builtin.os.tag == .linux) {
        // Linux: use getrandom syscall directly (available since kernel 3.17)
        var filled: usize = 0;
        while (filled < buf.len) {
            const rc = std.os.linux.getrandom(buf[filled..].ptr, buf.len - filled, 0);
            const errno = std.posix.errno(rc);
            if (errno == .SUCCESS) {
                filled += rc;
            } else if (errno == .INTR) {
                continue;
            } else {
                // Should not happen with flags=0, but fall through
                @panic("getrandom failed");
            }
        }
    } else {
        // macOS, FreeBSD, etc: arc4random_buf is always available
        std.c.arc4random_buf(buf.ptr, buf.len);
    }
}

fn rsaEncryptOAEP(allocator: std.mem.Allocator, msg: []const u8, pk: *const PublicKey) ![]const u8 {
    const init_hash = Sha1.init(.{});

    const lHash = blk: {
        var hash = init_hash;
        hash.update(&.{});
        break :blk hash.finalResult();
    };
    const digest_len = lHash.len;

    const k = (pk.n.bits() + 7) / 8; //  modulus size in bytes

    var em = try allocator.alloc(u8, k);
    defer allocator.free(em);
    @memset(em, 0);
    const seed = em[1 .. 1 + digest_len];
    const db = em[1 + digest_len ..];

    @memcpy(db[0..lHash.len], &lHash);
    db[db.len - msg.len - 1] = 1;
    @memcpy(db[db.len - msg.len ..], msg);
    fillRandomBytes(seed);

    mgf1XOR(db, &init_hash, seed);
    mgf1XOR(seed, &init_hash, db);

    return encryptMsg(allocator, em, pk);
}

fn encryptMsg(allocator: std.mem.Allocator, msg: []const u8, pk: *const PublicKey) ![]const u8 {
    const max_modulus_bits = 4096;
    const Modulus = std.crypto.ff.Modulus(max_modulus_bits);
    const Fe = Modulus.Fe;

    const m = try Fe.fromBytes(pk.*.n, msg, .big);
    const e = try pk.n.powPublic(m, pk.e);

    const res = try allocator.alloc(u8, msg.len);
    try e.toBytes(res, .big);
    return res;
}

// mgf1XOR XORs the bytes in out with a mask generated using the MGF1 function
// specified in PKCS #1 v2.1.
fn mgf1XOR(dest: []u8, init_hash: *const Sha1, seed: []const u8) void {
    var counter: [4]u8 = .{ 0, 0, 0, 0 };
    var digest: [Sha1.digest_length]u8 = undefined;

    var done: usize = 0;
    while (done < dest.len) : (incCounter(&counter)) {
        var hash = init_hash.*;
        hash.update(seed);
        hash.update(counter[0..4]);
        digest = hash.finalResult();

        for (&digest) |*d| {
            if (done >= dest.len) break;
            dest[done] ^= d.*;
            done += 1;
        }
    }
}

// incCounter increments a four byte, big-endian counter.
fn incCounter(c: *[4]u8) void {
    inline for (&.{ 3, 2, 1, 0 }) |i| {
        c[i], const overflow_bit = @addWithOverflow(c[i], 1);
        if (overflow_bit == 0) return; // no overflow, so we're done
    }
}
