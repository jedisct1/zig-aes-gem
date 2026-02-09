const std = @import("std");
const crypto = std.crypto;
const aes = crypto.core.aes;
const assert = std.debug.assert;
const mem = std.mem;
const AuthenticationError = crypto.errors.AuthenticationError;

pub const Aes128Gem = AesGem(aes.Aes128, 16);
pub const Aes256Gem = AesGem(aes.Aes256, 16);

fn AesGem(comptime Aes: type, comptime tag_len: comptime_int) type {
    const EncCtx = aes.AesEncryptCtx(Aes);

    return struct {
        pub const key_length = Aes.key_bits / 8;
        pub const nonce_length = if (Aes == aes.Aes128) 24 else 32;
        pub const tag_length = tag_len;
        pub const commitment_length = 32;

        const head_size = nonce_length - 8;
        const bytes_per_segment: u64 = 1 << 36;
        const seg_key_base: u64 = 0xFD00000000000000;

        pub fn encrypt(ciphertext: []u8, tag: *[tag_length]u8, plaintext: []const u8, ad: []const u8, nonce: [nonce_length]u8, key: [key_length]u8) void {
            assert(plaintext.len == ciphertext.len);

            const key_schedule = Aes.initEnc(key);
            const subkey = deriveSubKey(key_schedule, key, nonce);
            const subkey_schedule = Aes.initEnc(subkey);
            const nonce_tail = nonce[head_size..].*;

            @memcpy(ciphertext, plaintext);
            applySegmentedCtr(subkey_schedule, nonce_tail, ciphertext);

            tag.* = computeTag(key_schedule, subkey_schedule, nonce_tail, ad, ciphertext);
        }

        pub fn decrypt(plaintext: []u8, ciphertext: []const u8, expected_tag: [tag_length]u8, ad: []const u8, nonce: [nonce_length]u8, key: [key_length]u8) AuthenticationError!void {
            assert(plaintext.len == ciphertext.len);

            const key_schedule = Aes.initEnc(key);
            const subkey = deriveSubKey(key_schedule, key, nonce);
            const subkey_schedule = Aes.initEnc(subkey);
            const nonce_tail = nonce[head_size..].*;

            const computed_tag = computeTag(key_schedule, subkey_schedule, nonce_tail, ad, ciphertext);
            if (!crypto.timing_safe.eql([tag_length]u8, computed_tag, expected_tag)) {
                return error.AuthenticationFailed;
            }

            @memcpy(plaintext, ciphertext);
            applySegmentedCtr(subkey_schedule, nonce_tail, plaintext);
        }

        pub fn commitment(key: [key_length]u8, nonce: [nonce_length]u8) [commitment_length]u8 {
            const key_schedule = Aes.initEnc(key);
            const subkey = deriveSubKey(key_schedule, key, nonce);
            const subkey_schedule = Aes.initEnc(subkey);
            const nonce_tail = nonce[head_size..].*;

            // IV: nonce_tail || 0xFFFFFFFF_FFFFFFFC
            var iv: [16]u8 = undefined;
            @memcpy(iv[0..8], &nonce_tail);
            mem.writeInt(u64, iv[8..16], 0xFFFFFFFF_FFFFFFFC, .big);

            var out = [_]u8{0} ** commitment_length;
            crypto.core.modes.ctrSlice(EncCtx, subkey_schedule, &out, &out, iv, .big, 12, 4);
            return out;
        }

        // --- Key derivation ---

        fn deriveSubKey(key_schedule: EncCtx, key: [key_length]u8, nonce: [nonce_length]u8) [key_length]u8 {
            if (key_length == 32) {
                return deriveSubKey256(key_schedule, key, nonce);
            } else {
                return deriveSubKey128(key_schedule, key, nonce);
            }
        }

        /// DeriveSubKey for AES-256-GEM (CBC-MAC based):
        ///   state = AES-ECB(K, N[0:16])
        ///   b0 = AES-ECB(K, state XOR (N[16:24] || "AES-256" || 0x80))
        ///   b1 = AES-ECB(K, state XOR (N[16:24] || "AES-GEM" || 0x80))
        ///   subkey = (b0 || b1) XOR K
        fn deriveSubKey256(key_schedule: EncCtx, key: [32]u8, nonce: [32]u8) [32]u8 {
            var state: [16]u8 = nonce[0..16].*;
            key_schedule.encrypt(&state, &state);

            var b0: [16]u8 = undefined;
            @memcpy(b0[0..8], nonce[16..24]);
            @memcpy(b0[8..15], "AES-256");
            b0[15] = 0x80;
            xor(&b0, &state);
            key_schedule.encrypt(&b0, &b0);

            var b1: [16]u8 = undefined;
            @memcpy(b1[0..8], nonce[16..24]);
            @memcpy(b1[8..15], "AES-GEM");
            b1[15] = 0x80;
            xor(&b1, &state);
            key_schedule.encrypt(&b1, &b1);

            var sk: [32]u8 = b0 ++ b1;
            xor(&sk, &key);
            return sk;
        }

        /// DeriveSubKey for AES-128-GEM (CBC-MAC based):
        ///   state = AES-ECB(K, N[0:16])
        ///   b = AES-ECB(K, state XOR ("GEM-128" || 0x80 || zeros))
        ///   subkey = b XOR K
        fn deriveSubKey128(key_schedule: EncCtx, key: [16]u8, nonce: [24]u8) [16]u8 {
            var state: [16]u8 = nonce[0..16].*;
            key_schedule.encrypt(&state, &state);

            var block: [16]u8 = [_]u8{0} ** 16;
            @memcpy(block[0..7], "GEM-128");
            block[7] = 0x80;
            xor(&block, &state);
            key_schedule.encrypt(&block, &block);

            xor(&block, &key);
            return block;
        }

        // --- Segment key derivation ---

        fn deriveSegmentKey(subkey_schedule: EncCtx, nonce_tail: [8]u8, seg_idx: u32) EncCtx {
            if (key_length == 32) {
                return deriveSegmentKey256(subkey_schedule, nonce_tail, seg_idx);
            } else {
                return deriveSegmentKey128(subkey_schedule, nonce_tail, seg_idx);
            }
        }

        /// DeriveSegmentKey for AES-256:
        ///   b0 = AES-ECB(subkey, N_tail || (segKeyBase + 2*i))
        ///   b1 = AES-ECB(subkey, N_tail || (segKeyBase + 2*i + 1))
        ///   return AES(b0 || b1)
        fn deriveSegmentKey256(subkey_schedule: EncCtx, nonce_tail: [8]u8, seg_idx: u32) EncCtx {
            const i: u64 = seg_idx;

            var b0: [16]u8 = undefined;
            @memcpy(b0[0..8], &nonce_tail);
            mem.writeInt(u64, b0[8..16], seg_key_base + 2 * i, .big);
            subkey_schedule.encrypt(&b0, &b0);

            var b1: [16]u8 = undefined;
            @memcpy(b1[0..8], &nonce_tail);
            mem.writeInt(u64, b1[8..16], seg_key_base + 2 * i + 1, .big);
            subkey_schedule.encrypt(&b1, &b1);

            return Aes.initEnc(b0 ++ b1);
        }

        /// DeriveSegmentKey for AES-128:
        ///   b = AES-ECB(subkey, N_tail || (segKeyBase + i))
        ///   return AES(b)
        fn deriveSegmentKey128(subkey_schedule: EncCtx, nonce_tail: [8]u8, seg_idx: u32) EncCtx {
            var b: [16]u8 = undefined;
            @memcpy(b[0..8], &nonce_tail);
            mem.writeInt(u64, b[8..16], seg_key_base + @as(u64, seg_idx), .big);
            subkey_schedule.encrypt(&b, &b);
            return Aes.initEnc(b);
        }

        // --- Segmented CTR mode ---

        /// Encrypt/decrypt using segmented AES-CTR32-BE.
        /// Each segment derives a fresh key for at most 2^36 bytes.
        fn applySegmentedCtr(subkey_schedule: EncCtx, nonce_tail: [8]u8, buf: []u8) void {
            var offset: usize = 0;
            var seg_idx: u32 = 0;

            while (offset < buf.len) {
                const seg_key = deriveSegmentKey(subkey_schedule, nonce_tail, seg_idx);

                // IV: nonce_tail(8) || seg_idx(4) || 0x00000000(4)
                var iv: [16]u8 = undefined;
                @memcpy(iv[0..8], &nonce_tail);
                mem.writeInt(u32, iv[8..12], seg_idx, .big);
                mem.writeInt(u32, iv[12..16], 0, .big);

                const remaining = buf.len - offset;
                const max_seg: usize = if (remaining > bytes_per_segment) @intCast(bytes_per_segment) else remaining;

                const seg = buf[offset..][0..max_seg];
                // CTR32-BE: counter is last 4 bytes of IV block
                crypto.core.modes.ctrSlice(EncCtx, seg_key, seg, seg, iv, .big, 12, 4);

                offset += max_seg;
                seg_idx += 1;
            }
        }

        // --- Authentication tag ---

        /// Compute authentication tag:
        ///   H = AES-ECB(subkey, 0xFF*8 || 0xFE || 0xFF*6 || tag_bits)
        ///   S = GHASH(H, pad(AAD) || pad(CT) || len(AAD) || len(CT))
        ///   S2 = AES-ECB(K, S)  (original key, not subkey)
        ///   j0_mask = AES-ECB(subkey, nonce_tail || 0xFF*7 || 0xFE)
        ///   T = (j0_mask XOR S2)[0..tag_length]
        fn computeTag(key_schedule: EncCtx, subkey_schedule: EncCtx, nonce_tail: [8]u8, ad: []const u8, ct: []const u8) [tag_length]u8 {
            // Derive GHASH key with tag-length domain separation
            var h: [16]u8 = [_]u8{0xFF} ** 16;
            h[8] = 0xFE;
            h[15] = tag_len * 8;
            subkey_schedule.encrypt(&h, &h);

            var gh = crypto.onetimeauth.Ghash.init(&h);
            gh.update(ad);
            gh.pad();
            gh.update(ct);
            gh.pad();

            var lengths: [16]u8 = undefined;
            mem.writeInt(u64, lengths[0..8], @as(u64, @intCast(ad.len)) * 8, .big);
            mem.writeInt(u64, lengths[8..16], @as(u64, @intCast(ct.len)) * 8, .big);
            gh.update(&lengths);

            var s: [16]u8 = undefined;
            gh.final(&s);

            // S2 = AES-ECB(K, S) -- uses original key
            key_schedule.encrypt(&s, &s);

            // j0_mask = AES-ECB(subkey, j0)
            var j0: [16]u8 = nonce_tail ++ [_]u8{0xFF} ** 7 ++ [_]u8{0xFE};
            subkey_schedule.encrypt(&j0, &j0);

            // T = j0_mask XOR S2
            xor(&s, &j0);
            return s[0..tag_length].*;
        }

        // --- Helpers ---

        fn xor(a: []u8, b: []const u8) void {
            for (a, b) |*x, y| x.* ^= y;
        }
    };
}

// --- Tests ---

fn hexToBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var result: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, hex) catch unreachable;
    return result;
}

test "roundtrip" {
    const ad = "Associated data";
    const plaintext = "Plaintext";
    var ciphertext: [plaintext.len]u8 = undefined;
    var decrypted: [plaintext.len]u8 = undefined;

    inline for ([_]type{ Aes128Gem, Aes256Gem }) |Aead| {
        var key: [Aead.key_length]u8 = undefined;
        var nonce: [Aead.nonce_length]u8 = undefined;
        std.testing.io.random(&nonce);
        std.testing.io.random(&key);
        var tag: [Aead.tag_length]u8 = undefined;
        Aead.encrypt(&ciphertext, &tag, plaintext, ad, nonce, key);
        try Aead.decrypt(&decrypted, &ciphertext, tag, ad, nonce, key);
        try std.testing.expectEqualSlices(u8, plaintext, &decrypted);
        _ = Aead.commitment(key, nonce);
    }
}

test "KAT group 1: AES-256-GEM, 128-bit tag" {
    const Gem = Aes256Gem;
    const T = struct { key: [32]u8, nonce: [32]u8, plaintext: []const u8, aad: []const u8, ciphertext: []const u8, tag: [16]u8 };

    const vectors = [_]T{
        // Test 1: Empty plaintext and AAD, all-zero key/nonce
        .{ .key = [_]u8{0} ** 32, .nonce = [_]u8{0} ** 32, .plaintext = "", .aad = "", .ciphertext = "", .tag = hexToBytes("51710d926727d97eafdef7a1e8e84481") },
        // Test 2: Empty plaintext, with AAD
        .{ .key = [_]u8{0} ** 32, .nonce = [_]u8{0} ** 32, .plaintext = "", .aad = &hexToBytes("6164646974696f6e616c2064617461"), .ciphertext = "", .tag = hexToBytes("7b8a46e020f4da8e000d650a1a22d02e") },
        // Test 3: With plaintext, empty AAD
        .{ .key = [_]u8{0} ** 32, .nonce = [_]u8{0} ** 32, .plaintext = &hexToBytes("68656c6c6f2c204145532d3235362d47454d21"), .aad = "", .ciphertext = &hexToBytes("f5b7a03c51ba202ab9c8dc0296dd697b025dfc"), .tag = hexToBytes("3502a8d2342651fa1a810d9e053fede6") },
        // Test 4: With plaintext and AAD
        .{ .key = [_]u8{0} ** 32, .nonce = [_]u8{0} ** 32, .plaintext = &hexToBytes("68656c6c6f2c204145532d3235362d47454d21"), .aad = &hexToBytes("6164646974696f6e616c2064617461"), .ciphertext = &hexToBytes("f5b7a03c51ba202ab9c8dc0296dd697b025dfc"), .tag = hexToBytes("6362a11eff57a8b54fa62581c23e2074") },
        // Test 5: Single byte plaintext
        .{ .key = [_]u8{0} ** 32, .nonce = [_]u8{0} ** 32, .plaintext = &hexToBytes("42"), .aad = "", .ciphertext = &hexToBytes("df"), .tag = hexToBytes("bcf4408eadc5b027a05edf0b919fc6c1") },
        // Test 6: One block (16 bytes) plaintext
        .{ .key = [_]u8{0} ** 32, .nonce = [_]u8{0} ** 32, .plaintext = &hexToBytes("000102030405060708090a0b0c0d0e0f"), .aad = "", .ciphertext = &hexToBytes("9dd3ce533a93066cf492fb3bafe64a33"), .tag = hexToBytes("8b7daf7d2f8f0e697f3c93baeb2007d9") },
        // Test 7: One block + 1 byte (17 bytes) plaintext
        .{ .key = [_]u8{0} ** 32, .nonce = [_]u8{0} ** 32, .plaintext = &hexToBytes("000102030405060708090a0b0c0d0e0f10"), .aad = "", .ciphertext = &hexToBytes("9dd3ce533a93066cf492fb3bafe64a3357"), .tag = hexToBytes("e3850993f3b03edad7641660173640aa") },
        // Test 8: Three blocks (48 bytes) plaintext
        .{ .key = [_]u8{0} ** 32, .nonce = [_]u8{0} ** 32, .plaintext = &hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"), .aad = "", .ciphertext = &hexToBytes("9dd3ce533a93066cf492fb3bafe64a335701cf3060364949799511730bf3721d774a5414662b80d9ae55554bfb4c7d61"), .tag = hexToBytes("e99106ddf89df9bd1af7939ec927b7dc") },
        // Test 9: Incrementing key and nonce
        .{ .key = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"), .nonce = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"), .plaintext = &hexToBytes("54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67"), .aad = &hexToBytes("41454144206173736f6369617465642064617461"), .ciphertext = &hexToBytes("737cf44ad0b728e88e4b9d81bd476d2d6496a87e9661bd0c5576a91bd0dc4d9a46f6a421942c9a4b421a53"), .tag = hexToBytes("681b0552d339fd459bd94a3dc4284b79") },
        // Test 10: All-ones key and nonce
        .{ .key = [_]u8{0xFF} ** 32, .nonce = [_]u8{0xFF} ** 32, .plaintext = &hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"), .aad = &hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"), .ciphertext = &hexToBytes("81be5260fad0773fc6ec46e9cfe67152cb9df6df3c5da4c6f7890d57afece318890ae3de5a0316d4dd7cf1f6fc1bcf666fede6ab044e97a561d1768875da2041"), .tag = hexToBytes("569673d0f112c0b955699646da0261f1") },
        // Test 11: 256-byte plaintext, 64-byte AAD
        .{ .key = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"), .nonce = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"), .plaintext = &hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"), .aad = &hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"), .ciphertext = &hexToBytes("27159369a5c7478ced62f5f8de3d0d0212e8c24de801c66b3e4fdc76a9b373f10eb2a66ed173c54c0e5c1e5fa314a7b49533b8b18aaeb04344099094ce5b4c24db3871999b7a53fab7842062531ef632b2bf1b9cbd59c3c520f5a35f81ea3d257d26081f40328b8b25c06eeaf3a9aab7e7a3d528d93eb6df66f2f88313e38a5bf315259f2f760efb89d6e6f28f09eb44866aab2ed44c71720c9b4f39d4e4667d209e0b981fd76cb3e132b69b50a42a87b5eaff200b61e0b7e34f5a71ff24a66818f4d58cbe76ad18950c357ef30b5223004a4062b53037cc51d1b7a9dc026bafd7441b82b24e94b3d8eaf32da55081bada2e99645841a8febf658b512cb25318"), .tag = hexToBytes("d6d6870574474450567a0181b945c74d") },
        // Test 12: Short plaintext, 256-byte AAD
        .{ .key = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"), .nonce = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"), .plaintext = &hexToBytes("dead"), .aad = &hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"), .ciphertext = &hexToBytes("f9b9"), .tag = hexToBytes("a7ffff2f3b0c76b96d59a61b8ef9d623") },
        // Test 13: 1024-byte plaintext
        .{ .key = hexToBytes("deadbeefdeadbeefdeadbeefdeadbeefcafebabecafebabecafebabecafebabe"), .nonce = hexToBytes("0123456789abcdef0123456789abcdeffedcba9876543210fedcba9876543210"), .plaintext = &hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"), .aad = &hexToBytes("61757468656e7469636174656420627574206e6f7420656e63727970746564"), .ciphertext = &hexToBytes("3a8de7e53e181a4b92d76a3d0673889ab4d3952d6b4cc1b8b20120450c4c83c59a01e175fab1516d59c05cb4f754a0a15e40d77c003ffb14b595267e6575feffcdee883647790a2abcac53b036e318b58ef47b3079585f670c1396ee9ce76f25f0228dc03034bc65289d3c815ce0cea6d066ab8f6b16d4df4a995d6b3e1617591e4e207c265e4f8d1be25a2c0c91eae59abb7ac16336f847fbcb73bb805c13f07262c6d6473a4cb4c269635129de8c0bbd5f46f7e22912c1a4f84ee5eab2fe41854630ccbd908df35865cdc654c2153f9a6a4cfe98c4a5d419abfd2bc687c055b9b27ebb4cf4e594ef6be8e258df1808d93adbd1f09480e7110053dd3f2d9e1bb8a588c362dd9a42655704774eb3aa486fb1feb103a3b123a7a147365183336582d96ef101f265c746fddbd5d30ebe99c81f68ad48de78239dbb44923ed367fae9ef88b3b34b0cd64ccf34c624af95c8b168d1228e1144a067ae2fc5bde238e782d39bb42517664654be099ac5e3f7ebafd7e285f6647b98df7185bf443d2222c37b6a8c5964a37772d36648806217728cdd9f03b7c2f198e60ba59fcb7584944f2a38fcf9acb8a172f5dabe95d664b9cb3be2b8b5751f9e1188d22c564728e3b8cbd14321604df9ca5659016a569f3eae0ed955646c8ab8cd3a4588fd6fedcaac3704d0e64a9df97824539ee647f069fb46631c18e3b1bde57ee74f76cd27b8956906b634e5847bfb8ed4d93ccf204424840cadbf172e8db035e43a3937dfc032c16e2d35b7b6db97d8e31842d403a457836f3719dc5cfa5ba31bfbd0b6558aae0ce8c00b6c5eef95b7d86ddaf78e2041277a57d5014d61b6ed1e021c2afef54f88108182424a1ea5835d74a0f373b4643d716169e6d67e5109e4861f2a6e1d6248177fcf0142251b30d37f5426f7b0281154e816d19dc6f23b0331da551af2efa2c35576e33110ce879eb1e8395829526476624b17c4a1c61f4832d5fde3d587860a0998698c855fa720f731cec5e846b71e61084bc85e31a27ce5af8dca40413dbbb9ce3324243db6d0e0926e77ca654b10c7cca654a640579767db5b188bb00aa102998cf85d01186cfd87bb6eb5a39f69828e7d9a0df1653b9ce832000fe2918b6a7361ad6f6b34df119f1068c21723928e47b871af64e05415e8b768d5fe0facc4e8ca9356dc069b6ba79bea654640dc7b43ea6c982b2594bcd8445181825b0927be9727679056989c26546c31d2ac35ae54bf01ad20f66d975fea6b87c4228a7e9af5548e60760d2231aa2f3b2925db2621c5b4391bbb89d71bbad26de59876b56bc49e65955223555254c2b4d13744522b65372bdcd5175ef031f219675d9c451822f8af508567091a3175651441b77a20cb5a3e626432e99c35b24dc23ce2c538cf92f5b29f5592980f4f733ff1be35e872a4c643c0c45193eee543"), .tag = hexToBytes("8bccdf808d9a99d7adf6e8011a36a1dc") },
        // Test 14: Empty plaintext, 1-byte AAD
        .{ .key = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"), .nonce = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"), .plaintext = "", .aad = &hexToBytes("00"), .ciphertext = "", .tag = hexToBytes("873855442d8e2d0c194727f0febc36e3") },
        // Test 15: 1-byte plaintext, 1-byte AAD
        .{ .key = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"), .nonce = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"), .plaintext = &hexToBytes("ff"), .aad = &hexToBytes("00"), .ciphertext = &hexToBytes("d8"), .tag = hexToBytes("92f3f13f5576942b7da7237497bb4b89") },
    };

    for (vectors) |v| {
        // Test encryption
        var ct_buf: [1024]u8 = undefined;
        const ct = ct_buf[0..v.plaintext.len];
        var tag: [16]u8 = undefined;
        Gem.encrypt(ct, &tag, v.plaintext, v.aad, v.nonce, v.key);
        try std.testing.expectEqualSlices(u8, v.ciphertext, ct);
        try std.testing.expectEqualSlices(u8, &v.tag, &tag);

        // Test decryption
        var pt_buf: [1024]u8 = undefined;
        const pt = pt_buf[0..v.ciphertext.len];
        try Gem.decrypt(pt, v.ciphertext, v.tag, v.aad, v.nonce, v.key);
        try std.testing.expectEqualSlices(u8, v.plaintext, pt);
    }
}

test "KAT group 2: AES-256-GEM, 96-bit tag" {
    const Gem = AesGem(aes.Aes256, 12);
    const T = struct { key: [32]u8, nonce: [32]u8, plaintext: []const u8, aad: []const u8, ciphertext: []const u8, tag: [12]u8 };

    const vectors = [_]T{
        .{ .key = [_]u8{0} ** 32, .nonce = [_]u8{0} ** 32, .plaintext = "", .aad = "", .ciphertext = "", .tag = hexToBytes("51710d926727d97eafdef7a1") },
        .{ .key = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"), .nonce = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"), .plaintext = &hexToBytes("68656c6c6f2c204145532d3235362d47454d21"), .aad = &hexToBytes("6164646974696f6e616c2064617461"), .ciphertext = &hexToBytes("4f71fd06ceee61caa038d2c1e7062e4a47b4f1"), .tag = hexToBytes("b176ea201cf7147f551532a4") },
    };

    for (vectors) |v| {
        var ct_buf: [1024]u8 = undefined;
        const ct = ct_buf[0..v.plaintext.len];
        var tag: [12]u8 = undefined;
        Gem.encrypt(ct, &tag, v.plaintext, v.aad, v.nonce, v.key);
        try std.testing.expectEqualSlices(u8, v.ciphertext, ct);
        try std.testing.expectEqualSlices(u8, &v.tag, &tag);

        var pt_buf: [1024]u8 = undefined;
        const pt = pt_buf[0..v.ciphertext.len];
        try Gem.decrypt(pt, v.ciphertext, v.tag, v.aad, v.nonce, v.key);
        try std.testing.expectEqualSlices(u8, v.plaintext, pt);
    }
}

test "KAT group 6: key commitment" {
    const Gem = Aes256Gem;

    const vectors = [_]struct { key: [32]u8, nonce: [32]u8, commitment: [32]u8 }{
        .{ .key = [_]u8{0} ** 32, .nonce = [_]u8{0} ** 32, .commitment = hexToBytes("6e605e81e59ffebe4e0fb6f49826dd769a29452b64be504635d700e0cb4787b1") },
        .{ .key = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"), .nonce = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"), .commitment = hexToBytes("14f805292761a15ec59045c1ac818f8cc30ef16975895782260b0fe0b96304fb") },
        .{ .key = [_]u8{0xFF} ** 32, .nonce = [_]u8{0xFF} ** 32, .commitment = hexToBytes("6cbbc2c59e777e8d275fc1410eed921abe726320a93c9bd9eac9fa34e0760a3a") },
    };

    for (vectors) |v| {
        const result = Gem.commitment(v.key, v.nonce);
        try std.testing.expectEqualSlices(u8, &v.commitment, &result);
    }
}
