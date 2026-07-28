//! Element / address / time formatting helpers.
//!
//! The display logic mirrors nftables' segtree.c::interval_to_prefix /
//! netlink.c::range_expr_is_prefix for the CIDR recovery (and the simpler
//! integer-bit math path of netlink.c::range_mask_len) and
//! src/datatype.c::time_print for the duration strings (1d2h30m / 1h30m /
//! 45s / 250ms / 0s).

use crate::nl::Elem;

/// Format one reduced element (result of `nl::reduce_intervals`) for display.
///
/// After `nl::reduce_intervals`:
///   * A **single** address has `key_end` empty, `is_end=false`.
///   * A **paired** interval has `key_end` populated (the closing address),
///     `is_end=false`.
///   * An **orphan** end marker (rare; produced by stray boundary elements
///     with no opener) has `is_end=true` and `key_end` empty.
pub fn format_element(e: &Elem) -> String {
    let key_str = format_key(&e.key);
    let body = if !e.key_end.is_empty() {
        // Paired interval (start, end). Try CIDR collapse (like nftables'
        // interval_to_prefix / range_expr_to_prefix); fall back to
        // start-end (nftables' interval_to_range).
        match interval_to_cidr(&e.key, &e.key_end) {
            Some((addr, plen, bits)) => {
                let a = format_addr(&addr, bits);
                format!("{a}/{plen}")
            }
            None => {
                let end_str = format_key(&e.key_end);
                format!("{key_str}-{end_str}")
            }
        }
    } else if e.is_end {
        format!("{key_str} (interval-end)")
    } else {
        key_str
    };
    format!("{body}{}", suffice(e))
}

fn suffice(e: &Elem) -> String {
    let mut s = String::new();
    if let Some(t) = e.timeout_ms {
        s.push_str(" timeout ");
        s.push_str(&format_duration(t));
    }
    if let Some(x) = e.expiration_ms {
        s.push_str(" expires ");
        s.push_str(&format_duration(x));
    }
    s
}

/// Render raw key bytes as an IP address (IPv4 or IPv6 by length) or a prefixed
/// form. Used for non-interval standalone keys.
fn format_key(key: &[u8]) -> String {
    match key.len() {
        4  => format_addr(key, 32),
        16 => format_addr(key, 128),
        _  => hex(key),
    }
}

/// Format an address of `bits` width (32 for IPv4, 128 for IPv6).
fn format_addr(addr_data: &[u8], bits: u32) -> String {
    match (addr_data.len(), bits) {
        (4, 32)  => format!("{}.{}.{}.{}", addr_data[0], addr_data[1], addr_data[2], addr_data[3]),
        (16, 128) => format_ipv6(addr_data),
        _         => hex(addr_data),
    }
}

/// IPv6 address printing, no RFC 5952 zero-group compression (fine for
/// short prefixes; if you really want RFC 5952 it's a 20-line change here).
fn format_ipv6(a: &[u8]) -> String {
    assert_eq!(a.len(), 16);
    let mut s = String::new();
    for i in 0..8 {
        if i > 0 { s.push(':'); }
        s.push_str(&format!("{:x}", u16::from_be_bytes([a[i*2], a[i*2+1]])));
    }
    s
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push_str(&format!("{:02x}", byte));
    }
    s
}

/// Try to collapse the half-open interval [low, high] into a `CIDR /plen`.
///
/// Algorithm (verbatim from nftables/src/segtree.c's `range_expr_is_prefix`
/// and the `range_mask_len` companion, plus its alignment check):
///
///   1. Compute `diff = high − low` (= host-part width uncompressed).
///   2. Move `low` toward `high` while the lowest bit of `low` and the
///      lowest bit of `high` could both shift up without crossing: this
///      reconstructs `range_mask_len` and produces the candidate prefix
///      length `bits − shifts`.
///   3. Check that `low` is aligned to its mask (low & host_mask == 0).
///   4. Check that the differing bits form a single contiguous host block.
///   5. Plen = bits − host_bits.
///
/// Returns `Some((network_bytes, prefix_len, bits))` when a clean CIDR block
/// is recovered; `None` otherwise (caller falls back to start-end):
/// matches nftables' `interval_to_prefix` vs `interval_to_range` switch.
pub fn interval_to_cidr(low: &[u8], high: &[u8]) -> Option<(Vec<u8>, u32, u32)> {
    if low.is_empty() || low.len() != high.len() { return None; }
    let bytes = low.len();
    let bits  = (bytes as u32) * 8;

    // Big-endian raw bytes ⇒ interpret as a `bits`-bit big-endian number
    // (exactly how nftables deals with the data reg for IPADDR/IP6ADDR).
    let l = be_int(low);
    let h = be_int(high);
    if h < l { return None; }

    // `diff = h − l` — describes the host-part extent when interpreted as a
    // contiguous mask. The check below mirrors range_mask_len.
    let diff = h.wrapping_sub(l);

    // The differing host bits must form a single contiguous block of low-set
    // bits — equivalently, `diff = 2^n − 1` for some n (nftables calls this
    // `range_is_prefix(diff)` checking `(diff & (diff+1)) == 0`).
    if !range_is_prefix(diff) { return None; }

    // `host_zone_bits = n` = number of low host bits, computed as ctz(diff+1)
    // because np(diff+1) = 0b...1<<n → trailing_zeros == n  (the bit at n is
    // the first bit outside the host zone, which the scan0 of diff returns).
    let host_zone_bits = diff.wrapping_add(1).trailing_zeros();
    let plen = bits.saturating_sub(host_zone_bits);

    // Alignment: the network address must have all host bits zero
    // (nftables: `mpz_and(p, key->value, range); !mpz_cmp_ui(p, 0)`).
    let host_mask: u128 = if host_zone_bits >= 128 {
        u128::MAX
    } else {
        (1u128 << host_zone_bits).wrapping_sub(1)
    };
    if l & host_mask != 0 { return None; }

    // Sanity: plen within [0, bits]; otherwise not representable as CIDR.
    if plen > bits { return None; }

    Some((low.to_vec(), plen, bits))
}

/// `range + 1` then `(range & (range+1)) == 0` ⇒ the differing host bits
/// form a single contiguous block of low-set bits (i.e. a CIDR-style host
/// mask). Mirrors nftables/src/segtree.c::range_is_prefix.
fn range_is_prefix(diff: u128) -> bool {
    let plus1 = diff.wrapping_add(1);
    (diff & plus1) == 0
}

/// Decode a big-endian unsigned integer from up to 16 bytes.
/// (IPv4=32 bits, IPv6=128 bits — both fit in u128.)
fn be_int(bytes: &[u8]) -> u128 {
    let mut v: u128 = 0;
    for &b in bytes {
        v = (v << 8) | b as u128;
    }
    v
}

/// Format a millisecond duration like nftables' `time_print` in
/// src/datatype.c (1d2h30m / 1h30m / 45s / 250ms / 0s). Only the non-zero
/// largest-first units are emitted, with at least "0s" for zero.
pub fn format_duration(ms: u64) -> String {
    let mut ms = ms;
    let days    = ms / 86_400_000; ms %= 86_400_000;
    let hours   = ms / 3_600_000;  ms %= 3_600_000;
    let minutes = ms / 60_000;     ms %= 60_000;
    let seconds = ms / 1_000;     ms %= 1_000;
    let mut out = String::new();
    let mut printed = false;
    if days > 0     { out.push_str(&format!("{}d", days));     printed = true; }
    if hours > 0    { out.push_str(&format!("{}h", hours));   printed = true; }
    if minutes > 0  { out.push_str(&format!("{}m", minutes)); printed = true; }
    if seconds > 0  { out.push_str(&format!("{}s", seconds)); printed = true; }
    if ms > 0       { out.push_str(&format!("{}ms", ms));     printed = true; }
    if !printed { out.push_str("0s"); }
    out
}

/// Parse a duration string (matching the output of `format_duration`) into
/// milliseconds.  Units: `d` (days), `h` (hours), `m` (minutes), `s` (seconds),
/// `ms` (milliseconds).  Components may appear in any order; unrecognised
/// suffixes or empty input return `None`.
///
/// ```
/// use nft_set_elem::fmt::parse_duration;
/// assert_eq!(parse_duration("1h30m"), Some(5_400_000));
/// assert_eq!(parse_duration("30s"),   Some(30_000));
/// assert_eq!(parse_duration("250ms"), Some(250));
/// assert_eq!(parse_duration("0s"),    Some(0));
/// assert_eq!(parse_duration(""),      None);
/// ```
pub fn parse_duration(s: &str) -> Option<u64> {
    if s.is_empty() { return None; }
    let mut total = 0u64;
    let mut acc = 0u64;
    let mut has_digit = false;
    let chars = s.as_bytes();
    let mut i = 0;
    while i < chars.len() {
        if chars[i].is_ascii_digit() {
            acc = acc * 10 + (chars[i] - b'0') as u64;
            has_digit = true;
            i += 1;
            continue;
        }
        if !has_digit { return None; }
        // Multi-character unit check: "ms" vs "m" vs "d" / "h" / "s"
        if i + 1 < chars.len() && &chars[i..i + 2] == b"ms" {
            total += acc;   // already ms
            i += 2;
        } else {
            match chars[i] {
                b'd' => total += acc * 86_400_000,
                b'h' => total += acc * 3_600_000,
                b'm' => total += acc * 60_000,
                b's' => total += acc * 1_000,
                _    => return None,
            }
            i += 1;
        }
        acc = 0;
        has_digit = false;
    }
    if has_digit { return None; } // trailing number without unit
    Some(total)
}

/// Parse an IP address (v4 or v6) into raw network-order bytes.
/// Returns the byte vector, or `None` on parse failure.
///
/// ```
/// use nft_set_elem::fmt::parse_addr;
/// assert_eq!(parse_addr("192.168.0.1"), Some(vec![192, 168, 0, 1]));
/// assert_eq!(parse_addr("::1"),         Some(vec![0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]));
/// assert_eq!(parse_addr("bad"),         None);
/// ```
pub fn parse_addr(s: &str) -> Option<Vec<u8>> {
    if let Ok(v4) = s.parse::<std::net::Ipv4Addr>() {
        return Some(v4.octets().to_vec());
    }
    if let Ok(v6) = s.parse::<std::net::Ipv6Addr>() {
        return Some(v6.octets().to_vec());
    }
    None
}

/// Parse an element spec that may be a bare IP or a CIDR prefix.
/// Returns `(key, key_end)` where `key_end` is `None` for a plain address
/// and `Some(broadcast_bytes)` for a CIDR range.
///
/// ```
/// use nft_set_elem::fmt::parse_element;
/// let (k, ke) = parse_element("192.168.1.1").unwrap();
/// assert_eq!(k, vec![192, 168, 1, 1]);
/// assert!(ke.is_none());
///
/// let (k, ke) = parse_element("192.168.0.0/24").unwrap();
/// assert_eq!(k,  vec![192, 168, 0, 0]);
/// assert_eq!(ke, Some(vec![192, 168, 0, 255]));
/// ```
pub fn parse_element(s: &str) -> Option<(Vec<u8>, Option<Vec<u8>>)> {
    if let Some((addr_s, plen_s)) = s.split_once('/') {
        let plen: u32 = plen_s.parse().ok()?;
        let bytes = parse_addr(addr_s)?;
        let bits = (bytes.len() * 8) as u32;
        if plen > bits { return None; }
        let _host_bits = bits - plen;
        let mut net = bytes.clone();
        let mut bc = bytes;
        for n in plen..bits {
            let bi = (n / 8) as usize;
            let bit = 7 - (n % 8);
            net[bi] &= !(1 << bit);
            bc[bi]  |= 1 << bit;
        }
        Some((net, Some(bc)))
    } else {
        parse_addr(s).map(|b| (b, None))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        be_int, format_addr, format_duration, interval_to_cidr, parse_addr,
        parse_duration, parse_element, range_is_prefix,
    };
    use crate::nl::Elem;

    #[test]
    fn range_is_prefix_matches_iff_host_mask_is_contiguous_low_bits() {
        assert!(range_is_prefix(0));
        assert!(range_is_prefix(1));
        assert!(range_is_prefix(3));
        assert!(range_is_prefix(0xFF));
        assert!(range_is_prefix(0x03FF)); // 2^10 - 1
        assert!(range_is_prefix(0xFFFF_FFFF));
        assert!(!range_is_prefix(2));     // 0b10 — not the (2^k-1) form
        assert!(!range_is_prefix(5));     // 0b101 — not the (2^k-1) form
    }

    #[test]
    fn ipv4_full_range_is_32_prefixlen_for_full_range() {
        let (addr, plen, bits) = interval_to_cidr(&[0, 0, 0, 0], &[255, 255, 255, 255]).unwrap();
        assert_eq!(bits, 32);
        assert_eq!(plen, 0);
        assert_eq!(format_addr(&addr, bits), "0.0.0.0");
    }

    #[test]
    fn ipv4_192_168_0_0_255_collapses_to_24() {
        let (addr, plen, bits) =
            interval_to_cidr(&[192, 168, 0, 0], &[192, 168, 0, 255]).unwrap();
        assert_eq!(bits, 32);
        assert_eq!(plen, 24);
        assert_eq!(format_addr(&addr, bits), "192.168.0.0");
    }

    #[test]
    fn ipv4_10_0_0_0_to_10_255_255_255_is_8() {
        let (addr, plen, bits) =
            interval_to_cidr(&[10, 0, 0, 0], &[10, 255, 255, 255]).unwrap();
        assert_eq!(bits, 32);
        assert_eq!(plen, 8);
        assert_eq!(format_addr(&addr, bits), "10.0.0.0");
    }

    #[test]
    fn ipv4_single_host_is_32() {
        let (addr, plen, bits) = interval_to_cidr(&[1, 2, 3, 4], &[1, 2, 3, 4]).unwrap();
        assert_eq!(bits, 32);
        assert_eq!(plen, 32);
        assert_eq!(format_addr(&addr, bits), "1.2.3.4");
    }

    #[test]
    fn ipv4_misaligned_low_returns_none() {
        assert!(interval_to_cidr(&[10, 0, 0, 5], &[10, 0, 0, 10]).is_none());
    }

    #[test]
    fn ipv4_range_with_host_gap_returns_none() {
        assert!(interval_to_cidr(&[192, 168, 0, 0], &[192, 168, 1, 1]).is_none());
    }

    #[test]
    fn ipv4_30_pair_collapses() {
        let (addr, plen, _) = interval_to_cidr(&[0, 0, 0, 0], &[0, 0, 0, 3]).unwrap();
        assert_eq!(plen, 30);
        assert_eq!(format_addr(&addr, 32), "0.0.0.0");
    }

    #[test]
    fn ipv6_2001_db8_64_collapses() {
        let low =
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let high =
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let (addr, plen, bits) = interval_to_cidr(&low, &high).unwrap();
        assert_eq!(bits, 128);
        assert_eq!(plen, 64);
        assert_eq!(format_addr(&addr, bits), "2001:db8:0:0:0:0:0:0");
    }

    #[test]
    fn be_int_decodes_natural_order_ipv4() {
        assert_eq!(be_int(&[192, 168, 0, 1]), 0xC0A8_0001);
        assert_eq!(be_int(&[1, 2, 3, 4]), 0x0102_0304);
    }

    #[test]
    fn duration_matches_nftables_print() {
        assert_eq!(format_duration(0), "0s");
        assert_eq!(format_duration(250), "250ms");
        assert_eq!(format_duration(1_000), "1s");
        assert_eq!(format_duration(60_000), "1m");
        assert_eq!(format_duration(3_600_000), "1h");
        assert_eq!(format_duration(86_400_000), "1d");
        assert_eq!(format_duration(5_430_000), "1h30m30s");
        assert_eq!(format_duration(95_040_000), "1d2h24m");
    }

    #[test]
    fn parse_duration_roundtrips() {
        assert_eq!(parse_duration("0s"),    Some(0));
        assert_eq!(parse_duration("250ms"), Some(250));
        assert_eq!(parse_duration("1s"),    Some(1_000));
        assert_eq!(parse_duration("30s"),   Some(30_000));
        assert_eq!(parse_duration("1m"),    Some(60_000));
        assert_eq!(parse_duration("5m"),    Some(300_000));
        assert_eq!(parse_duration("1h"),    Some(3_600_000));
        assert_eq!(parse_duration("1d"),    Some(86_400_000));
        assert_eq!(parse_duration("1h30m30s"), Some(5_430_000));
        assert_eq!(parse_duration("1d2h24m"),  Some(95_040_000));
        assert_eq!(parse_duration(""),       None);
        assert_eq!(parse_duration("xyz"),    None);
        assert_eq!(parse_duration("5x"),     None);
    }

    #[test]
    fn parse_addr_works_for_v4_and_v6() {
        assert_eq!(parse_addr("192.168.0.1"), Some(vec![192, 168, 0, 1]));
        assert_eq!(parse_addr("10.0.0.0"),    Some(vec![10, 0, 0, 0]));
        assert_eq!(parse_addr("::1"),         Some(vec![0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]));
        assert_eq!(parse_addr("2001:db8::1"), Some(vec![0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1]));
        assert_eq!(parse_addr("bad"), None);
    }

    #[test]
    fn parse_element_cidr_and_single() {
        let (k, ke) = parse_element("192.168.0.0/24").unwrap();
        assert_eq!(k,  vec![192, 168, 0, 0]);
        assert_eq!(ke, Some(vec![192, 168, 0, 255]));

        let (k, ke) = parse_element("192.168.1.1").unwrap();
        assert_eq!(k, vec![192, 168, 1, 1]);
        assert!(ke.is_none());

        assert!(parse_element("bogus/24").is_none());
        assert!(parse_element("1.2.3.4/33").is_none());
    }

    #[test]
    fn format_element_3_5_64_0_18_shows_mask() {
        // After reduce_intervals, an element for 3.5.64.0/18 should have
        // key = 3.5.64.0 and key_end = 3.5.127.255 (inclusive).
        let e = Elem {
            key: vec![3, 5, 64, 0],
            is_end: false,
            key_end: vec![3, 5, 127, 255],
            timeout_ms: None,
            expiration_ms: None,
        };
        assert_eq!(super::format_element(&e), "3.5.64.0/18");
    }

    #[test]
    fn format_element_single_ip_no_mask() {
        let e = Elem {
            key: vec![10, 0, 0, 1],
            is_end: false,
            key_end: vec![],
            timeout_ms: None,
            expiration_ms: None,
        };
        assert_eq!(super::format_element(&e), "10.0.0.1");
    }

    #[test]
    fn format_element_with_timeout() {
        let e = Elem {
            key: vec![192, 168, 1, 1],
            is_end: false,
            key_end: vec![],
            timeout_ms: Some(3_600_000),
            expiration_ms: None,
        };
        assert_eq!(super::format_element(&e), "192.168.1.1 timeout 1h");
    }

    #[test]
    fn format_element_range_fallback() {
        // A range that can't collapse to CIDR (misaligned) shows start-end.
        let e = Elem {
            key: vec![10, 0, 0, 5],
            is_end: false,
            key_end: vec![10, 0, 0, 10],
            timeout_ms: None,
            expiration_ms: None,
        };
        assert_eq!(super::format_element(&e), "10.0.0.5-10.0.0.10");
    }
}
