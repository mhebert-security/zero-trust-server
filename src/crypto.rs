//! From-scratch SHA-256 and HMAC-SHA256 on std only.
//!
//! `pow.rs` and `session.rs` used to each carry a private copy of these
//! primitives, so the two could drift apart. They now live in this one module
//! (GitHub issue #12). The implementations are pure Rust with no external
//! crate, and the tests below pin them to the FIPS 180-4 and RFC 4231
//! known-answer vectors.

/// SHA-256 digest of `message`, per FIPS 180-4.
/// Pure Rust, no external crate. Building block for `hmac_sha256`; call sites
/// that need message authentication should use `hmac_sha256` instead.
///
/// The working registers `a`..`h`, the message schedule `W`, and the round
/// constants `K` keep FIPS 180-4's own notation, so the spec and the FIPS
/// test vector stay directly comparable. Single-letter names are deliberate.
#[allow(clippy::many_single_char_names)]
pub fn sha256(message: &[u8]) -> [u8; 32] {
    // Initial hash values — first 32 bits of fractional parts
    // of square roots of first 8 primes.
    let mut h: [u32; 8] = [
        0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a,
        0x510e_527f, 0x9b05_688c, 0x1f83_d9ab, 0x5be0_cd19,
    ];

    // Round constants — first 32 bits of fractional parts
    // of cube roots of first 64 primes.
    let k: [u32; 64] = [
        0x428a_2f98, 0x7137_4491, 0xb5c0_fbcf, 0xe9b5_dba5,
        0x3956_c25b, 0x59f1_11f1, 0x923f_82a4, 0xab1c_5ed5,
        0xd807_aa98, 0x1283_5b01, 0x2431_85be, 0x550c_7dc3,
        0x72be_5d74, 0x80de_b1fe, 0x9bdc_06a7, 0xc19b_f174,
        0xe49b_69c1, 0xefbe_4786, 0x0fc1_9dc6, 0x240c_a1cc,
        0x2de9_2c6f, 0x4a74_84aa, 0x5cb0_a9dc, 0x76f9_88da,
        0x983e_5152, 0xa831_c66d, 0xb003_27c8, 0xbf59_7fc7,
        0xc6e0_0bf3, 0xd5a7_9147, 0x06ca_6351, 0x1429_2967,
        0x27b7_0a85, 0x2e1b_2138, 0x4d2c_6dfc, 0x5338_0d13,
        0x650a_7354, 0x766a_0abb, 0x81c2_c92e, 0x9272_2c85,
        0xa2bf_e8a1, 0xa81a_664b, 0xc24b_8b70, 0xc76c_51a3,
        0xd192_e819, 0xd699_0624, 0xf40e_3585, 0x106a_a070,
        0x19a4_c116, 0x1e37_6c08, 0x2748_774c, 0x34b0_bcb5,
        0x391c_0cb3, 0x4ed8_aa4a, 0x5b9c_ca4f, 0x682e_6ff3,
        0x748f_82ee, 0x78a5_636f, 0x84c8_7814, 0x8cc7_0208,
        0x90be_fffa, 0xa450_6ceb, 0xbef9_a3f7, 0xc671_78f2,
    ];

    // Pre-processing: padding the message.
    let bit_len = (message.len() as u64).wrapping_mul(8);
    let mut padded = message.to_vec();
    padded.push(0x80); // Append bit '1' as byte 0x80
    while padded.len() % 64 != 56 {
        padded.push(0x00);
    }
    // Append original length as 64-bit big-endian
    padded.extend_from_slice(&bit_len.to_be_bytes());

    // Process each 512-bit (64-byte) chunk.
    for chunk in padded.chunks(64) {
        // Prepare message schedule.
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7)
                ^ w[i - 15].rotate_right(18)
                ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17)
                ^ w[i - 2].rotate_right(19)
                ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        // Compression function.
        let [mut a, mut b, mut c, mut d,
             mut e, mut f, mut g, mut hh] = h;

        for i in 0..64 {
            let s1 = e.rotate_right(6)
                ^ e.rotate_right(11)
                ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(k[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2)
                ^ a.rotate_right(13)
                ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        // Add compressed chunk to current hash value.
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    // Produce final hash — concatenate h0..h7 as big-endian bytes.
    let mut digest = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        digest[i * 4..(i + 1) * 4]
            .copy_from_slice(&word.to_be_bytes());
    }
    digest
}

/// HMAC-SHA256 of `message` under `key`, per FIPS 198-1.
/// Pure Rust, no external crate.
///
/// HMAC(K, m) = H((K' XOR opad) || H((K' XOR ipad) || m)),
/// where K' is the key padded to the 64-byte block size,
/// opad = 0x5c repeated, and ipad = 0x36 repeated.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64;
    const OPAD: u8 = 0x5c;
    const IPAD: u8 = 0x36;

    // If key is longer than block size, hash it first (RFC 2104 §2).
    let mut k_prime = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let hashed = sha256(key);
        k_prime[..32].copy_from_slice(&hashed);
    } else {
        k_prime[..key.len()].copy_from_slice(key);
    }

    // Inner hash: H((K' XOR ipad) || message)
    let mut inner_input = Vec::with_capacity(BLOCK_SIZE + message.len());
    for b in &k_prime {
        inner_input.push(b ^ IPAD);
    }
    inner_input.extend_from_slice(message);
    let inner_hash = sha256(&inner_input);

    // Outer hash: H((K' XOR opad) || inner_hash)
    let mut outer_input = Vec::with_capacity(BLOCK_SIZE + 32);
    for b in &k_prime {
        outer_input.push(b ^ OPAD);
    }
    outer_input.extend_from_slice(&inner_hash);

    sha256(&outer_input)
}

/// HMAC-SHA256 of `message` under `key`, hex encoded.
/// Convenience form of `hmac_sha256` for call sites that compare or transmit
/// the digest as a string.
pub fn hmac_hex(key: &[u8], message: &[u8]) -> String {
    let digest = hmac_sha256(key, message);
    to_hex(&digest)
}

/// Lowercase hex encoding of `bytes`.
pub fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Constant-time byte slice comparison.
/// Returns true if both slices are equal.
/// Every byte pair is evaluated regardless of where the first difference
/// appears, so elapsed time does not leak the match position.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    // XOR each byte pair — 0 if equal, non-zero if different.
    // OR all results — 0 if all pairs were equal.
    // This forces the CPU to evaluate every byte pair
    // regardless of early differences.
    let result: u8 = a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y));
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use sha2::{Digest, Sha256};

    /// FIPS 180-4 §B.1: `SHA-256("abc")` = `ba7816bf…f20015ad`.
    #[test]
    fn sha256_matches_fips_abc_vector() {
        assert_eq!(
            to_hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    /// RFC 4231 test case 1: key of twenty 0x0b bytes, message "Hi There".
    #[test]
    fn hmac_sha256_matches_rfc4231_case_1() {
        let key = [0x0b; 20];
        assert_eq!(
            to_hex(&hmac_sha256(&key, b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    /// RFC 4231 test case 6: a key longer than the 64-byte block forces the
    /// hash-first branch (RFC 2104 §2). Catches a regression where that path
    /// stops matching the spec.
    #[test]
    fn hmac_sha256_hashes_overlong_key_per_rfc4231_case_6() {
        let key = [0xaa; 131];
        assert_eq!(
            to_hex(&hmac_sha256(
                &key,
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    /// Equal slices compare equal; a mismatch anywhere, including the very
    /// first byte, compares unequal. Different lengths never match.
    #[test]
    fn constant_time_eq_accepts_only_identical_slices() {
        assert!(constant_time_eq(b"same-length!", b"same-length!"));
        assert!(!constant_time_eq(b"same-length!", b"zame-length!"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }

    /// Hex encoding is lowercase and zero pads every byte.
    #[test]
    fn to_hex_lowercases_and_zero_pads() {
        assert_eq!(to_hex(&[0x00, 0x0f, 0xff]), "000fff");
        assert_eq!(to_hex(b""), "");
    }

    /// Independent SHA-256 via the `RustCrypto` `sha2` crate. It shares no
    /// code with `sha256`, so any divergence between the two on an input
    /// means the hand-rolled primitive left the FIPS 180-4 spec somewhere
    /// the known-answer vectors do not exercise.
    fn oracle_sha256(message: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(message);
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }

    /// Independent HMAC-SHA256 per FIPS 198-1, built from `oracle_sha256`.
    /// The structure follows the same published algorithm as `hmac_sha256`,
    /// but every hash primitive inside is `RustCrypto`, so the two share no
    /// code path and cannot mask each other's bugs.
    fn oracle_hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
        const BLOCK: usize = 64;
        let mut k = [0u8; BLOCK];
        if key.len() > BLOCK {
            let hashed = oracle_sha256(key);
            k[..32].copy_from_slice(&hashed);
        } else {
            k[..key.len()].copy_from_slice(key);
        }
        let mut inner = Vec::with_capacity(BLOCK + message.len());
        for &b in &k {
            inner.push(b ^ 0x36);
        }
        inner.extend_from_slice(message);
        let mut outer = Vec::with_capacity(BLOCK + 32);
        for &b in &k {
            outer.push(b ^ 0x5c);
        }
        outer.extend_from_slice(&oracle_sha256(&inner));
        oracle_sha256(&outer)
    }

    /// FIPS padding appends 0x80, zeroes to byte 56 of a block, then an
    /// 8-byte big-endian bit length. A bug in that arithmetic hides at one
    /// length and works at another, so this walks every length that lands on
    /// the edges: 55/56/57 straddle the length field, 63/64/65 the first
    /// block boundary, and each later stride re-tests a multi-block message.
    #[test]
    fn sha256_matches_oracle_at_padding_boundaries() {
        let lengths = [
            0usize, 1, 2, 54, 55, 56, 57, 58, 63, 64, 65, 119, 120, 121,
            127, 128, 129, 511, 512, 513, 1023, 1024, 2047, 2048,
        ];
        for len in lengths {
            let mut x: u8 = 7;
            let message: Vec<u8> = (0..len)
                .map(|_| {
                    x = x.wrapping_mul(131).wrapping_add(7);
                    x
                })
                .collect();
            assert_eq!(
                sha256(&message),
                oracle_sha256(&message),
                "mismatch at message length {len}"
            );
        }
    }

    // Property: sha256 agrees with the RustCrypto oracle on arbitrary
    // messages up to 2048 bytes. Random lengths reach padding and block
    // boundaries the fixed list above cannot cover exhaustively.
    proptest! {
        #[test]
        fn sha256_matches_rustcrypto_for_arbitrary_inputs(
            message in proptest::collection::vec(any::<u8>(), 0..2048),
        ) {
            prop_assert_eq!(sha256(&message), oracle_sha256(&message));
        }
    }

    // Property: hmac_sha256 agrees with the independent FIPS 198-1 oracle.
    // Key lengths up to 256 force the RFC 2104 hash-first branch (keys over
    // 64 bytes) and the pad-direct branch (keys under it) across messages
    // of arbitrary length.
    proptest! {
        #[test]
        fn hmac_sha256_matches_rustcrypto_for_arbitrary_inputs(
            key in proptest::collection::vec(any::<u8>(), 0..256),
            message in proptest::collection::vec(any::<u8>(), 0..2048),
        ) {
            prop_assert_eq!(
                hmac_sha256(&key, &message),
                oracle_hmac_sha256(&key, &message)
            );
        }
    }

    /// The deterministic complement to the property test above: key and
    /// message lengths pinned to the exact branch boundaries, not sampled.
    #[test]
    fn hmac_sha256_matches_oracle_at_branch_boundaries() {
        let key_lengths = [0usize, 1, 63, 64, 65, 131, 255, 256];
        let message_lengths = [0usize, 55, 56, 64, 65, 1023];
        for klen in key_lengths {
            for mlen in message_lengths {
                let mut x: u8 = 11;
                let key: Vec<u8> = (0..klen)
                    .map(|_| {
                        x = x.wrapping_mul(163).wrapping_add(3);
                        x
                    })
                    .collect();
                let mut y: u8 = 23;
                let message: Vec<u8> = (0..mlen)
                    .map(|_| {
                        y = y.wrapping_mul(197).wrapping_add(5);
                        y
                    })
                    .collect();
                assert_eq!(
                    hmac_sha256(&key, &message),
                    oracle_hmac_sha256(&key, &message),
                    "mismatch at key length {klen}, message length {mlen}"
                );
            }
        }
    }

    // Property: constant_time_eq must be functionally identical to plain
    // slice equality. Constant time is a performance property the test
    // cannot observe, but any input on which the two disagree is a bug in
    // the length guard or the fold, and that is exactly observable.
    proptest! {
        #[test]
        fn constant_time_eq_agrees_with_plain_equality(
            a in proptest::collection::vec(any::<u8>(), 0..128),
            b in proptest::collection::vec(any::<u8>(), 0..128),
        ) {
            prop_assert_eq!(constant_time_eq(&a, &b), a == b);
        }
    }

    /// One lower-case hex digit from an ASCII byte, or None if the byte is
    /// not in `0-9a-f`. Pairs with `to_hex`, whose output is the only thing
    /// this decoder accepts.
    fn nibble(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        }
    }

    /// The inverse of `to_hex`, defined only over the lower-case range that
    /// `to_hex` emits. Test-only, so the round-trip property has a decoder
    /// that does not reuse `to_hex`'s own lookup table.
    fn decode_hex(hex: &str) -> Option<Vec<u8>> {
        let bytes = hex.as_bytes();
        if !bytes.len().is_multiple_of(2) {
            return None;
        }
        bytes
            .chunks_exact(2)
            .map(|pair| {
                let hi = nibble(pair[0])?;
                let lo = nibble(pair[1])?;
                Some(hi << 4 | lo)
            })
            .collect()
    }

    // Property: to_hex is a bijection onto its own range. Two hex digits per
    // byte, all lower-case, and decoding recovers the original bytes. Any
    // collision or omission in the table breaks one of the three.
    proptest! {
        #[test]
        fn to_hex_round_trips_through_decode(
            bytes in proptest::collection::vec(any::<u8>(), 0..1024),
        ) {
            let hex = to_hex(&bytes);
            prop_assert_eq!(hex.len(), bytes.len() * 2);
            prop_assert!(hex.bytes().all(|b| nibble(b).is_some()));
            prop_assert_eq!(decode_hex(&hex), Some(bytes));
        }
    }
}
