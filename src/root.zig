const std = @import("std");
const crypto = std.crypto;
const aes = crypto.core.aes;
const assert = std.debug.assert;
const mem = std.mem;
const AuthenticationError = crypto.errors.AuthenticationError;

pub const Aes128Gem = AesGem(aes.Aes128);
pub const Aes256Gem = AesGem(aes.Aes256);

fn AesGem(comptime Aes: type) type {
    return struct {
        pub const key_length = Aes.key_bits / 8;
        pub const nonce_length = if (Aes == aes.Aes128) 24 else 32;
        pub const tag_length = 16;
        pub const commitment_length = 32;

        pub fn encrypt(ciphertext: []u8, tag: *[tag_length]u8, plaintext: []const u8, ad: []const u8, nonce: [nonce_length]u8, key: [key_length]u8) void {
            assert(plaintext.len == ciphertext.len);

            const key_schedule = Aes.initEnc(key);
            const subkey = deriveSubKey(key_schedule, key, nonce);
            const subkey_schedule = Aes.initEnc(subkey);

            var h = [_]u8{0xff} ** 16;
            subkey_schedule.encrypt(&h, &h);

            var gh = crypto.onetimeauth.Ghash.init(&h);
            gh.update(ad);
            gh.pad();

            const nonce_leftover = nonce[nonce.len - 8 ..].*;
            const j0 = nonce_leftover ++ [_]u8{0xff} ** 7 ++ [_]u8{0xfe};
            const iv = nonce_leftover ++ [_]u8{0x00} ** 8;
            crypto.core.modes.ctr(aes.AesEncryptCtx(Aes), subkey_schedule, ciphertext, plaintext, iv, .big);

            gh.update(ciphertext);
            gh.pad();

            var lengths: [16]u8 = undefined;
            mem.writeInt(u64, lengths[0..8], ad.len * 8, .big);
            mem.writeInt(u64, lengths[8..16], ciphertext.len * 8, .big);
            gh.update(&lengths);

            var s: [crypto.onetimeauth.Ghash.mac_length]u8 = undefined;
            gh.final(&s);
            key_schedule.encrypt(&s, &s);
            crypto.core.modes.ctr(aes.AesEncryptCtx(Aes), subkey_schedule, tag, &j0, iv, .big);
            xor(tag, &s);
        }

        pub fn decrypt(plaintext: []u8, ciphertext: []const u8, expected_tag: [tag_length]u8, ad: []const u8, nonce: [nonce_length]u8, key: [key_length]u8) AuthenticationError!void {
            assert(plaintext.len == ciphertext.len);

            const key_schedule = Aes.initEnc(key);
            const subkey = deriveSubKey(key_schedule, key, nonce);
            const subkey_schedule = Aes.initEnc(subkey);

            var h = [_]u8{0xff} ** 16;
            subkey_schedule.encrypt(&h, &h);

            var gh = crypto.onetimeauth.Ghash.init(&h);
            gh.update(ad);
            gh.pad();
            gh.update(ciphertext);
            gh.pad();

            var lengths: [16]u8 = undefined;
            mem.writeInt(u64, lengths[0..8], ad.len * 8, .big);
            mem.writeInt(u64, lengths[8..16], ciphertext.len * 8, .big);
            gh.update(&lengths);

            const nonce_leftover = nonce[nonce.len - 8 ..].*;
            const j0 = nonce_leftover ++ [_]u8{0xff} ** 7 ++ [_]u8{0xfe};
            const iv = nonce_leftover ++ [_]u8{0x00} ** 8;

            var s: [crypto.onetimeauth.Ghash.mac_length]u8 = undefined;
            gh.final(&s);
            key_schedule.encrypt(&s, &s);

            var computed_tag: [tag_length]u8 = undefined;
            crypto.core.modes.ctr(aes.AesEncryptCtx(Aes), subkey_schedule, &computed_tag, &j0, iv, .big);
            xor(&computed_tag, &s);

            if (!crypto.utils.timingSafeEql([tag_length]u8, computed_tag, expected_tag)) {
                return error.AuthenticationFailed;
            }
            crypto.core.modes.ctr(aes.AesEncryptCtx(Aes), subkey_schedule, plaintext, ciphertext, iv, .big);
        }

        // Key commitment

        pub fn commitment(key: [key_length]u8, nonce: [nonce_length]u8) [commitment_length]u8 {
            const key_schedule = Aes.initEnc(key);
            const subkey = deriveSubKey(key_schedule, key, nonce);
            const subkey_schedule = Aes.initEnc(subkey);
            var out: [commitment_length]u8 = undefined;
            const nonce_leftover = nonce[nonce.len - 8 ..].*;
            const iv = nonce_leftover ++ [_]u8{0xff} ** 7 ++ [_]u8{0xfc};
            crypto.core.modes.ctr(aes.AesEncryptCtx(Aes), subkey_schedule, &out, &out, iv, .big);
            return out;
        }

        // Helpers

        fn xor(a: []u8, b: []const u8) void {
            for (a, b) |*x, y| x.* ^= y;
        }

        fn deriveSubKey(key_schedule: aes.AesEncryptCtx(Aes), key: [key_length]u8, nonce: [nonce_length]u8) [key_length]u8 {
            var subkey = switch (Aes) {
                aes.Aes128 => nonce[0..16].*,
                aes.Aes256 => nonce[0..12].* ++ [4]u8{ 0x41, 0x45, 0x53, 0x80 } ++ nonce[12..24].* ++ [4]u8{ 0x47, 0x45, 0x4d, 0x80 },
                else => unreachable,
            };
            key_schedule.encryptWide(subkey.len / 16, &subkey, &subkey);
            xor(&subkey, &key);
            return subkey;
        }
    };
}

// Tests

test {
    const Aeads = [_]type{ Aes128Gem, Aes256Gem };
    inline for (Aeads) |Aead| {
        var key: [Aead.key_length]u8 = undefined;
        var nonce: [Aead.nonce_length]u8 = undefined;
        crypto.random.bytes(&nonce);
        crypto.random.bytes(&key);
        const ad = "Associated data";
        const plaintext = "Plaintext";
        var ciphertext: [plaintext.len]u8 = undefined;
        var plaintext2: [plaintext.len]u8 = undefined;
        var tag: [Aead.tag_length]u8 = undefined;

        Aead.encrypt(&ciphertext, &tag, plaintext, ad, nonce, key);
        try Aead.decrypt(&plaintext2, &ciphertext, tag, ad, nonce, key);
        try std.testing.expectEqualSlices(u8, plaintext, &plaintext2);

        _ = Aead.commitment(key, nonce);
    }
}
