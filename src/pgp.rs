//! `OpenPGP` public key disclosure for the site mailbox.
//!
//! The server publishes one `OpenPGP` public key, bound to the contact mailbox
//! admin@mhebert.dev. This module owns that disclosure: the key itself, the
//! Web Key Directory (WKD) address a client resolves to find it, and the
//! fingerprint the contact page prints. Everything derives from a single
//! committed artifact, the ASCII-armored key at
//! `static/openpgp/admin.pub.asc`, so the three views cannot drift apart:
//! the armored copy served at `/.well-known/pgp`, the binary form the WKD
//! spec requires under `/.well-known/openpgpkey/hu/`, and the fingerprint
//! shown on the contact page all come from that one file.
//!
//! The URL layout follows the direct method of the governing `GnuPG` draft,
//! `draft-koch-openpgp-webkey-service`, which is what mail clients and
//! `gpg --locate-keys` implement in practice. The label "RFC 9636" that
//! sometimes appears beside the URL is wrong: RFC 9636 specifies the `TZif`
//! timezone format, and the Web Key Directory has never been an RFC. Under
//! the direct method a client asks for
//! `https://mhebert.dev/.well-known/openpgpkey/hu/<leaf>`, where `<leaf>` is
//! a Z-Base-32 encoding of the SHA-1 of the lowercased mailbox local part,
//! and the server answers with the binary `OpenPGP` key. A companion policy
//! file lives at `/.well-known/openpgpkey/policy`, which the spec requires
//! (an empty body is legal).
//!
//! SHA-1 appears here in exactly the two places the `OpenPGP` and WKD specs
//! mandate it: addressing a WKD directory entry and deriving a version 4
//! fingerprint. Neither is a security boundary. No signature and no
//! integrity check in this codebase uses SHA-1; the primitive for those jobs
//! stays SHA-256 in crypto.rs. Both uses are kept inside this module so the
//! boundary is explicit.

use std::sync::OnceLock;

use crate::crypto::to_hex;

/// The local part of the contact mailbox. The WKD leaf is derived from it.
pub const LOCAL_PART: &str = "admin";

/// The path prefix of a direct-method WKD lookup.
pub const WKD_PREFIX: &str = "/.well-known/openpgpkey/hu/";

/// The ASCII-armored public key, the single committed disclosure artifact.
/// The secret half lives only in the operator's gpg keyring on the host
/// where the key was generated; this file and the repo carry the public half
/// alone, which is meant to be public.
const ARMORED: &str = include_str!("../static/openpgp/admin.pub.asc");

/// Z-Base-32 alphabet (RFC 6189, section 5.1.6). Not the RFC 4648 base32
/// alphabet: WKD leaves use Z-Base-32, which drops the digit and letter
/// pairs that read alike when a hash is typed by hand.
const ZBASE32: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";

/// The ASCII-armored public key, served verbatim at `/.well-known/pgp`.
/// Serving the same text that sits in the repo keeps the wire artifact
/// reviewable: an operator diffing the served body against the committed
/// file sees the real key.
pub const fn armored() -> &'static str {
    ARMORED
}

/// The binary `OpenPGP` transferable public key the WKD URL serves, derived
/// once from the committed armor by stripping it. The WKD spec wants binary
/// on the wire, and the repo keeps only the readable armored artifact, so
/// the two forms never need to be committed side by side.
static BINARY: OnceLock<Vec<u8>> = OnceLock::new();

/// The de-armored key. A corrupted committed key fails here rather than
/// serving bytes the operator never reviewed; the test suite de-armors the
/// same file and would catch that corruption at `cargo test` time.
pub fn binary() -> &'static [u8] {
    BINARY.get_or_init(|| dearmor(ARMORED).expect("embedded PGP key must de-armor cleanly"))
}

/// The version 4 fingerprint of the primary public key, lowercase hex.
/// Derived from the key itself, so the value inserted into the contact page
/// at serve time (content.rs) cannot drift from the key that is served.
pub fn fingerprint() -> String {
    let bytes = binary();
    let (tag, body_len, body) = open_packet(bytes).expect("key export opens with a packet");
    let input = fingerprint_input(tag, body_len, body)
        .expect("embedded key must be a version 4 primary key");
    to_hex(&sha1(&input))
}

/// The fingerprint grouped in fours and uppercased, the form `gpg
/// --fingerprint` prints and the contact page shows.
pub fn fingerprint_display() -> String {
    let hex = fingerprint().to_uppercase();
    let mut out = String::with_capacity(49);
    for (i, c) in hex.chars().enumerate() {
        if i != 0 && i % 4 == 0 {
            out.push(' ');
        }
        out.push(c);
    }
    out
}

/// The Z-Base-32 leaf a WKD client computes for a mailbox local part:
/// SHA-1 over the local part with ASCII uppercasing removed, encoded.
/// Lowercasing ASCII is the only normalization the WKD spec applies.
fn wkd_leaf_for(local: &str) -> String {
    let lower = local.to_ascii_lowercase();
    zbase32(&sha1(lower.as_bytes()))
}

/// The WKD leaf for the site mailbox, the `<hash>` segment of
/// `/.well-known/openpgpkey/hu/<hash>`.
pub fn wkd_leaf() -> String {
    wkd_leaf_for(LOCAL_PART)
}

/// SHA-1 (FIPS 180-4). The `OpenPGP` and WKD specifications demand SHA-1 in
/// exactly two places, both handled here: the WKD leaf and the version 4
/// fingerprint. Neither is a security boundary (see the module docs), so
/// this implementation is kept small rather than hardened against side
/// channels. Not the hashing primitive for anything that needs integrity.
#[allow(clippy::many_single_char_names)]
fn sha1(data: &[u8]) -> [u8; 20] {
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut padded = Vec::with_capacity(data.len() + 72);
    padded.extend_from_slice(data);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    let mut h = [
        0x6745_2301u32,
        0xefcd_ab89,
        0x98ba_dcfe,
        0x1032_5476,
        0xc3d2_e1f0,
    ];
    let mut w = [0u32; 80];
    for block in padded.chunks_exact(64) {
        for (i, word) in w.iter_mut().take(16).enumerate() {
            let start = i * 4;
            *word = u32::from_be_bytes([
                block[start],
                block[start + 1],
                block[start + 2],
                block[start + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5a82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
                _ => (b ^ c ^ d, 0xca62_c1d6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut digest = [0u8; 20];
    for (i, word) in h.iter().enumerate() {
        digest[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

/// Encode bytes as Z-Base-32, most significant bits first.
fn zbase32(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() * 8).div_ceil(5));
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in data {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ZBASE32[((buffer >> bits) & 0x1f) as usize] as char);
        }
        // Drop the bits already emitted so the buffer cannot overflow. The
        // un-emitted tail (0-4 bits) sits in the low end, where the next
        // byte joins it.
        buffer &= (1u32 << bits) - 1;
    }
    if bits > 0 {
        out.push(ZBASE32[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

/// Strip PGP ASCII armor and decode the enclosed `OpenPGP` packet stream,
/// verifying the CRC-24 checksum line the armor carries. Returns None on any
/// framing error, so a corrupted committed key fails closed.
fn dearmor(armored: &str) -> Option<Vec<u8>> {
    let mut base64 = String::new();
    let mut checksum = None;
    for raw in armored.lines() {
        let line = raw.trim_end_matches('\r');
        if line.is_empty() || line.starts_with("-----") {
            continue;
        }
        // Armor header fields ("Version: ...") appear as "Name: value" and
        // are not part of the encoded body. The base64 alphabet has no
        // colon, so a header line is safe to skip by shape.
        if line.contains(':') {
            continue;
        }
        if let Some(crc) = line.strip_prefix('=') {
            checksum = Some(crc);
            continue;
        }
        base64.push_str(line);
    }
    let bytes = base64_decode(&base64)?;
    if let Some(expected) = checksum
        && crc24(&bytes) != decode_armor_crc(expected)?
    {
        return None;
    }
    Some(bytes)
}

/// Decode standard base64 (RFC 4648), the alphabet `OpenPGP` armor uses.
/// Rejects any character outside the alphabet and any final quantum with
/// fewer than two data characters. Padding may be present, absent, or
/// partial, which real armor lines mix freely.
fn base64_decode(encoded: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(encoded.len() / 4 * 3 + 3);
    let mut quad = [0u8; 4];
    let mut in_quad = 0usize;
    for &c in encoded.as_bytes() {
        if c == b'=' {
            continue;
        }
        quad[in_quad] = b64_value(c)?;
        in_quad += 1;
        if in_quad == 4 {
            push_quad(quad, &mut out);
            in_quad = 0;
        }
    }
    match in_quad {
        0 => {}
        2 => out.push((quad[0] << 2) | (quad[1] >> 4)),
        3 => {
            out.push((quad[0] << 2) | (quad[1] >> 4));
            out.push((quad[1] << 4) | (quad[2] >> 2));
        }
        _ => return None,
    }
    Some(out)
}

/// The 6-bit value of one base64 character, or None when not in the alphabet.
const fn b64_value(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Append the three bytes of one full 4-character base64 quantum.
fn push_quad(quad: [u8; 4], out: &mut Vec<u8>) {
    out.push((quad[0] << 2) | (quad[1] >> 4));
    out.push((quad[1] << 4) | (quad[2] >> 2));
    out.push((quad[2] << 6) | quad[3]);
}

/// CRC-24 (RFC 4880, section 6.1), the checksum `OpenPGP` armor appends to
/// catch corruption in transit or at rest.
fn crc24(data: &[u8]) -> u32 {
    const POLY: u32 = 0x0186_4cfb;
    let mut crc = 0x00b7_04ce;
    for &b in data {
        crc ^= u32::from(b) << 16;
        for _ in 0..8 {
            crc <<= 1;
            if crc & 0x0100_0000 != 0 {
                crc ^= POLY;
            }
        }
    }
    crc & 0x00ff_ffff
}

/// Decode the four-character checksum line of an armor body into the
/// 24-bit value it names.
fn decode_armor_crc(line: &str) -> Option<u32> {
    let bytes = base64_decode(line)?;
    let bytes: [u8; 3] = bytes.try_into().ok()?;
    Some(u32::from(bytes[0]) << 16 | u32::from(bytes[1]) << 8 | u32::from(bytes[2]))
}

/// Read the framing of the first `OpenPGP` packet: its tag, body length, and
/// body. Handles both header formats (RFC 4880, sections 4.2.1 and 4.2.2):
/// old format has bit 6 clear and carries its tag and a 1-, 2-, or 4-octet
/// length in the header octet itself; new format has bit 6 set, tag in the
/// low 6 bits, and a body-length encoding in the octets that follow. Real
/// exports mix the two, because modern gpg writes long new-format headers
/// for large packets and compact old-format headers for short ones, which
/// is exactly what the committed key does. Returns None on any framing
/// error.
fn open_packet(data: &[u8]) -> Option<(u8, usize, &[u8])> {
    let first = *data.first()?;
    if first & 0x80 == 0 {
        return None;
    }
    // Cursor names the first length octet; each branch advances it past the
    // octets it consumed so the body slice below starts at the right offset.
    let mut cursor = 1usize;
    let (tag, body_len) = if first & 0x40 == 0 {
        // Old format: tag in bits 5-2, length type in bits 1-0. The length
        // octets that follow are big endian, one, two, or four wide.
        let tag = (first >> 2) & 0x0f;
        match first & 0x03 {
            0 => {
                let len = usize::from(*data.get(cursor)?);
                cursor += 1;
                (tag, len)
            }
            1 => {
                let wide = data.get(cursor..cursor + 2)?;
                cursor += 2;
                let len = usize::from(u16::from_be_bytes(wide.try_into().ok()?));
                (tag, len)
            }
            2 => {
                let wide = data.get(cursor..cursor + 4)?;
                cursor += 4;
                let len = usize::try_from(u32::from_be_bytes(wide.try_into().ok()?)).ok()?;
                (tag, len)
            }
            _ => return None,
        }
    } else {
        // New format: tag in the low 6 bits. The next octet is either the
        // body length itself, a marker for a two-octet value covering
        // 192-8383, or a marker for a four-octet value beyond that.
        let tag = first & 0x3f;
        let l0 = usize::from(*data.get(cursor)?);
        cursor += 1;
        let body_len = match l0 {
            0..=191 => l0,
            192..=223 => {
                let l1 = usize::from(*data.get(cursor)?);
                cursor += 1;
                (l0 - 192) * 256 + l1 + 192
            }
            255 => {
                let wide = data.get(cursor..cursor + 4)?;
                cursor += 4;
                usize::try_from(u32::from_be_bytes(wide.try_into().ok()?)).ok()?
            }
            _ => return None,
        };
        (tag, body_len)
    };
    let body = data.get(cursor..cursor + body_len)?;
    Some((tag, body_len, body))
}

/// Build the byte string a version 4 fingerprint hashes: the octet 0x99,
/// the two-octet body length, then the body (RFC 4880, section 12.2).
/// Returns None when the packet is not a version 4 public key packet or its
/// body cannot fit the two-octet length field.
fn fingerprint_input(tag: u8, body_len: usize, body: &[u8]) -> Option<Vec<u8>> {
    if tag != 6 || body.first() != Some(&4) {
        return None;
    }
    // A version 4 fingerprint's length field is two octets wide, so a body
    // that cannot fit is not a key this function can fingerprint.
    let len16 = u16::try_from(body_len).ok()?;
    let mut input = Vec::with_capacity(body_len + 3);
    input.push(0x99);
    input.extend_from_slice(&len16.to_be_bytes());
    input.extend_from_slice(body);
    Some(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha1_matches_the_fips_vectors() {
        assert_eq!(
            to_hex(&sha1(b"")),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
        assert_eq!(
            to_hex(&sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            to_hex(&sha1(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
    }

    #[test]
    fn zbase32_matches_the_wkd_worked_example() {
        // draft-koch-openpgp-webkey-service uses Joe.Doe as its worked
        // example: the leaf for that local part is iy9q119eutrkn8s1mk4r39qejnbu3n5q.
        let digest = sha1(b"joe.doe");
        assert_eq!(zbase32(&digest), "iy9q119eutrkn8s1mk4r39qejnbu3n5q");
        // A SHA-1 digest is 160 bits, exactly 32 Z-Base-32 characters.
        assert_eq!(zbase32(&digest).len(), 32);
    }

    #[test]
    fn wkd_leaf_for_the_mailbox_is_pinned_and_case_insensitive() {
        // Computed independently (a Python oracle, cross-checked against the
        // draft example above) and pinned here so a regression in SHA-1 or
        // Z-Base-32 changes the leaf and fails the test.
        let leaf = wkd_leaf_for(LOCAL_PART);
        assert_eq!(leaf, "4y36rkzdjnzmk3oxaekyi5biowgr5kcz");
        assert_eq!(leaf.len(), 32);
        assert_eq!(wkd_leaf(), leaf);
        // The spec lowercases ASCII before hashing.
        assert_eq!(wkd_leaf_for("Admin"), wkd_leaf_for("admin"));
    }

    #[test]
    fn embedded_key_dearmors_to_a_version_4_primary_key() {
        let bytes = binary();
        assert!(!bytes.is_empty());
        // Modern gpg frames a short packet like this key with the compact
        // old-format header (0x98), so the parser must read both formats.
        let (tag, _body_len, body) = open_packet(bytes).expect("framing parses");
        assert_eq!(tag, 6, "the first packet is the primary public key");
        assert_eq!(body[0], 4, "the primary key is version 4");
        // The committed artifact is one complete armored key, and the armor
        // carries a checksum line this module verifies.
        assert!(ARMORED.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
        assert!(
            ARMORED
                .trim_end()
                .ends_with("-----END PGP PUBLIC KEY BLOCK-----")
        );
        assert!(ARMORED.lines().any(|l| l.trim_end().starts_with('=')));
    }

    #[test]
    fn fingerprint_matches_the_key_gpg_reports() {
        // `gpg --fingerprint admin@mhebert.dev` reports 0287 6933 E9FA 299C
        // 21DB A8A2 A6CC EAD3 2D59 8F7E. The page must print the fingerprint
        // of the key actually served, or a visitor who verifies the printed
        // value against a key fetched from WKD would see them disagree.
        assert_eq!(fingerprint(), "02876933e9fa299c21dba8a2a6ccead32d598f7e");
        assert_eq!(
            fingerprint_display(),
            "0287 6933 E9FA 299C 21DB A8A2 A6CC EAD3 2D59 8F7E"
        );
    }

    #[test]
    fn armor_checksum_verifies_and_corruption_is_rejected() {
        let crc_line = ARMORED
            .lines()
            .find_map(|l| l.trim_end().strip_prefix('='))
            .expect("armor carries a checksum line");
        assert_eq!(decode_armor_crc(crc_line), Some(crc24(binary())));
        // A single flipped base64 character in the encoded body must fail the
        // checksum rather than serve silently altered bytes. The flip cannot
        // land in a marker line: every letter of "-----BEGIN ... -----" is
        // itself a base64 alphabet character, so the first such letter in the
        // file names a header, and corrupting it only changes a line the
        // dearmorer discards. The body line is found by its shape instead.
        let mut lines: Vec<String> = ARMORED.lines().map(str::to_owned).collect();
        let body_at = lines
            .iter()
            .position(|l| {
                let t = l.trim_end();
                !t.is_empty() && !t.starts_with("-----") && !t.contains(':') && !t.starts_with('=')
            })
            .expect("armor has a body line");
        let head = &mut lines[body_at];
        let replacement = if head.starts_with('A') { "B" } else { "A" };
        head.replace_range(0..1, replacement);
        let corrupted = lines.join("\n");
        assert!(
            dearmor(&corrupted).is_none(),
            "corrupted armor must not de-armor"
        );
    }

    #[test]
    fn base64_decode_rejects_garbage_and_bad_tails() {
        assert!(base64_decode("not base64!!!").is_none());
        assert!(base64_decode("YQ==").is_some(), "one byte, padded");
        assert!(base64_decode("YWE=").is_some(), "two bytes, padded");
        assert!(base64_decode("YWFh").is_some(), "three bytes, unpadded");
        assert!(
            base64_decode("Y").is_none(),
            "a single leftover char is malformed"
        );
        // Two leftover chars are a legal one-byte tail: "YQ" decodes to "a".
        assert_eq!(base64_decode("YQ").as_deref(), Some(&b"a"[..]));
        // Standard vector: "Ma" base64 is TWE=.
        assert_eq!(base64_decode("TWE=").as_deref(), Some(&b"Ma"[..]));
    }
}
