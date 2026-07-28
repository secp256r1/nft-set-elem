//! Raw netlink (nfnetlink) plumbing for dumping nftables set elements.
//!
//! Uses `netlink-sys` (tokio backend) for async socket I/O on Linux.
//! The low-level message building and parsing (TLV attributes, nftables
//! constants) is kept crate-local because no `netlink-packet-nftables`
//! crate exists yet — the `netlink-packet-netfilter` crate only knows
//! about `ULog` and `Conntrack`, not the full nftables TLV schema.
//!
//! On non-Linux hosts only the pure-logic helpers (reduce_intervals, etc.)
//! are compiled; the async netlink entry points return Unsupported.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::io;

#[cfg(target_os = "linux")]
use std::time::Duration;

#[cfg(target_os = "linux")]
use bytes::BytesMut;
#[cfg(target_os = "linux")]
use netlink_sys::{protocols::NETLINK_NETFILTER, AsyncSocket, AsyncSocketExt, SocketAddr, TokioSocket};

// ---------------------------------------------------------------------------
// constants
// ---------------------------------------------------------------------------

/// Netlink TLV alignment (matches NLMSG_ALIGNTO / NLA_ALIGNTO).
const ALIGN: usize = 4;

// nlmsg_flags
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_DUMP:    u16 = 0x300; // ROOT | MATCH
const NLM_F_ACK:     u16 = 0x04;

// nlmsg_type control messages (masked off before dispatch)
const NLMSG_NOOP:  u16 = 0x1;
const NLMSG_ERROR: u16 = 0x2;
const NLMSG_DONE:  u16 = 0x3;

// nla_type flags
const NLA_F_NESTED:       u16 = 1 << 15;
const NLA_F_NET_BYTEORDER: u16 = 1 << 14;
const NLA_TYPE_MASK:      u16 = !(NLA_F_NESTED | NLA_F_NET_BYTEORDER);

// nfnetlink subsystem / message-type encoding
const NFNL_SUBSYS_NFTABLES: u16 = 10;
const NFNETLINK_V0: u8 = 0;

// nftables message sub-types (low byte of nlmsg_type)
const NFT_MSG_GETSET:    u16 = 10;
const NFT_MSG_GETSETELEM: u16 = 13;

// Add-element / delete-element message types (used within a batch).
const NFT_MSG_NEWSETELEM: u16 = 12;
const NFT_MSG_DELSETELEM: u16 = 14;

// nlmsg flags for atomic create.
const NLM_F_CREATE: u16 = 0x400;
const NLM_F_EXCL:  u16 = 0x200;

// nfnetlink batch markers (nlmsg_type without subsys shift; subsys goes in res_id).
const NFNL_MSG_BATCH_BEGIN: u16 = 0x10;
const NFNL_MSG_BATCH_END:   u16 = 0x11;

// AF_UNSPEC (for batch messages).
const AF_UNSPEC: u8 = 0;

// NFTA_SET_* attributes (used by NFT_MSG_GETSET to query set flags).
const NFTA_SET_TABLE: u16 = 1;
const NFTA_SET_NAME:  u16 = 2;
const NFTA_SET_FLAGS: u16 = 3;

// `enum nft_set_flags` bit values (from nf_tables.h) — NFT_SET_INTERVAL is
// used by main.rs to decide whether `reduce_intervals` runs the (start,end)
// pairing path or treats every element as a standalone single address.
pub const NFT_SET_INTERVAL: u32 = 0x4;

// NFTA_SET_ELEM_LIST_* attributes
const NFTA_SET_ELEM_LIST_TABLE:     u16 = 1;
const NFTA_SET_ELEM_LIST_SET:      u16 = 2;
const NFTA_SET_ELEM_LIST_ELEMENTS: u16 = 3;

// NFTA_LIST_ELEM (1) wraps each element inside NFTA_SET_ELEM_LIST_ELEMENTS.
const NFTA_LIST_ELEM: u16 = 1;

// NFTA_SET_ELEM_* attributes  (values from the kernel's nft_set_elem_attr enum)
const NFTA_SET_ELEM_KEY:         u16 = 1;
const NFTA_SET_ELEM_FLAGS:       u16 = 3;
const NFTA_SET_ELEM_TIMEOUT:     u16 = 4;
const NFTA_SET_ELEM_EXPIRATION:  u16 = 5;
const NFTA_SET_ELEM_KEY_END:     u16 = 10;

// NFTA_DATA_* (the inner type of KEY / KEY_END nested attrs)
const NFTA_DATA_VALUE:   u16 = 1;

// nft_set_elem_flags
const NFT_SET_ELEM_INTERVAL_END: u32 = 0x1;

// ---------------------------------------------------------------------------
// errno helper
// ---------------------------------------------------------------------------

/// Linux raw errno communicated through NLMSG_ERROR replies: `nfg_err.error`
/// (= 0 for ACK, = -Eerrno for failure).
fn errno_to_msg(errno: i32) -> String {
    // Map the few errno values that nfnetlink is realistically going to
    // report. Anything unknown is shown numerically so a maintainer can
    // grep /usr/include/asm-generic/errno*.h without us trying to be a
    // libc table.
    match -errno {
        1   => "EPERM: operation not permitted".to_string(),
        2   => "ENOENT: no such set".to_string(),
        13  => "EACCES: permission denied (need root/CAP_NET_ADMIN?)".to_string(),
        22  => "EINVAL: invalid argument".to_string(),
        19  => "ENODEV: no such set".to_string(),
        38  => "ENOSYS: not implemented".to_string(),
        95  => "EOPNOTSUPP: kernel reply: operation not supported".to_string(),
        105 => "ENOBUFS: kernel out of buffers".to_string(),
        n   => format!("errno {n}"),
    }
}

// ---------------------------------------------------------------------------
// wire-format types  (kept for documentation; the parser accesses them
// purely by byte offsets — see the parse loop below)
// ---------------------------------------------------------------------------

#[allow(dead_code)]
#[repr(C)]
#[derive(Clone, Copy)]
struct nlmsghdr {
    nlmsg_len:   u32,
    nlmsg_type:  u16,
    nlmsg_flags: u16,
    nlmsg_seq:   u32,
    nlmsg_pid:   u32,
}
const NLMSG_HDRLEN: usize = 16;

#[allow(dead_code)]
#[repr(C)]
#[derive(Clone, Copy)]
struct nfgenmsg {
    nfgen_family: u8,
    version:      u8,
    res_id:       [u8; 2], // network byte order
}
const NFG_HDRLEN: usize = 4;

// ---------------------------------------------------------------------------
// builder
// ---------------------------------------------------------------------------

/// Byte buffer that grows a netlink message: nlmsghdr + nfgenmsg + TLVs.
struct MsgBuf { buf: Vec<u8> }

impl MsgBuf {
    fn new() -> Self { MsgBuf { buf: Vec::with_capacity(256) } }

    fn as_bytes(&self) -> &[u8] { &self.buf }

    /// Lay down a fresh message header (filled in at finalize()).
    fn put_header(&mut self) -> usize {
        let off = self.buf.len();
        self.buf.resize(off + NLMSG_HDRLEN + NFG_HDRLEN, 0);
        // placeholder nfgenmsg; we fix its family below.
        off
    }

    /// Lay down nlmsghdr + nfgenmsg. `flags` selects between dump-style
    /// (`NLM_F_REQUEST | NLM_F_DUMP | NLM_F_ACK`) and single-message
    /// (`NLM_F_REQUEST | NLM_F_ACK`) requests. `res_id` is written in
    /// network byte order (zero for normal nftables messages, equals
    /// `NFNL_SUBSYS_NFTABLES` for batch BEGIN/END markers).
    fn set_header(&mut self, off: usize, nlmsg_type: u16, family: u8, seq: u32, flags: u16, res_id: u16) {
        let total = (self.buf.len() - off) as u32;
        // nlmsghdr fields (host order on the wire).
        self.buf[off..off + 4].copy_from_slice(&total.to_ne_bytes());
        self.buf[off + 4..off + 6].copy_from_slice(&nlmsg_type.to_ne_bytes());
        self.buf[off + 6..off + 8].copy_from_slice(&flags.to_ne_bytes());
        self.buf[off + 8..off + 12].copy_from_slice(&seq.to_ne_bytes());
        // pid = 0 (kernel assigns / echoes).
        self.buf[off + 12..off + 16].copy_from_slice(&0u32.to_ne_bytes());
        // nfgenmsg (after nlmsghdr).
        self.buf[off + NLMSG_HDRLEN] = family;
        self.buf[off + NLMSG_HDRLEN + 1] = NFNETLINK_V0;
        // res_id in network byte order.
        self.buf[off + NLMSG_HDRLEN + 2..off + NLMSG_HDRLEN + 4].copy_from_slice(&res_id.to_be_bytes());
    }

    /// Overwrite the `nlmsg_seq` of the message that begins at `off` (the
    /// only field we can't know up-front in `set_header` because the caller
    /// wants NlSession's seq obtained after a successful bind).
    fn fix_seq_at(&mut self, off: usize, seq: u32) {
        self.buf[off + 8..off + 12].copy_from_slice(&seq.to_ne_bytes());
    }

    /// Append a TLV attribute with the given type (no NLA_F_* bits) and
    /// raw payload (a stringz for NLA_STRING usage afterwards).
    fn put_attr_stringz(&mut self, t: u16, s: &str) {
        let len = s.len() + 1; // +NUL
        self.put_attr(t, 0, len, |b| {
            b[..s.len()].copy_from_slice(s.as_bytes());
            b[s.len()] = 0;
        });
    }

    /// Generic TLV put; payload laid out via `fill`.
    fn put_attr(&mut self, t: u16, flags: u16, payload_len: usize, fill: impl FnOnce(&mut [u8])) {
        let hdr_off = self.buf.len();
        let nla_len = (4 + payload_len) as u16;
        let nla_type = t | flags;
        self.buf.resize(hdr_off + 4 + payload_len, 0);
        self.buf[hdr_off..hdr_off + 2].copy_from_slice(&nla_len.to_ne_bytes());
        self.buf[hdr_off + 2..hdr_off + 4].copy_from_slice(&nla_type.to_ne_bytes());
        fill(&mut self.buf[hdr_off + 4..hdr_off + 4 + payload_len]);
        // pad to ALIGN
        let unpadded = hdr_off + 4 + payload_len;
        let padded = align_up(unpadded, ALIGN);
        self.buf.resize(padded, 0);
    }

    /// Open a nested attribute (returns an anchor used by close_nest()).
    fn open_nest(&mut self, t: u16) -> usize {
        let hdr_off = self.buf.len();
        let nla_type = t | NLA_F_NESTED;
        self.buf.resize(hdr_off + 4, 0);
        self.buf[hdr_off..hdr_off + 2].copy_from_slice(&(4u16).to_ne_bytes()); // updated in close
        self.buf[hdr_off + 2..hdr_off + 4].copy_from_slice(&nla_type.to_ne_bytes());
        hdr_off
    }

    /// Close a nested attribute, back-patching its length.
    fn close_nest(&mut self, anchor: usize) {
        let total = (self.buf.len() - anchor) as u16;
        self.buf[anchor..anchor + 2].copy_from_slice(&total.to_ne_bytes());
    }
}

fn align_up(n: usize, a: usize) -> usize { (n + a - 1) & !(a - 1) }

// ---------------------------------------------------------------------------
// parser
// ---------------------------------------------------------------------------

/// A borrow-y view of one `nlattr` + payload inside a buffer.
struct NlAttr<'a> { raw_type: u16, payload: &'a [u8] }

impl<'a> NlAttr<'a> {
    fn attr_type(&self) -> u16 { self.raw_type & NLA_TYPE_MASK }
    /// Network-byte-order u32 (libnftnl stores scalars with htonl on the wire).
    fn as_u32_be(&self) -> u32 {
        let mut b = [0u8; 4];
        b.copy_from_slice(&self.payload[..4.min(self.payload.len())]);
        u32::from_be_bytes(b)
    }
    /// Network-byte-order u64.
    fn as_u64_be(&self) -> u64 {
        let mut b = [0u8; 8];
        b.copy_from_slice(&self.payload[..8.min(self.payload.len())]);
        u64::from_be_bytes(b)
    }
}

/// Iterate TLV attributes over `buf`, starting at the byte offset given.
/// `buf` MUST be aligned at the start of the first attribute.
fn iter_attrs(buf: &[u8]) -> impl Iterator<Item = NlAttr<'_>> {
    let mut pos = 0usize;
    std::iter::from_fn(move || {
        if pos + 4 > buf.len() { return None; }
        let nla_len = u16::from_ne_bytes([buf[pos], buf[pos + 1]]) as usize;
        let nla_type = u16::from_ne_bytes([buf[pos + 2], buf[pos + 3]]);
        if nla_len < 4 || pos + nla_len > buf.len() { return None; }
        let payload = &buf[pos + 4..pos + nla_len];
        let next = align_up(pos + nla_len, ALIGN);
        let rtype = nla_type;
        pos = next;
        Some(NlAttr { raw_type: rtype, payload })
    })
}

// ---------------------------------------------------------------------------
// parsed element model
// ---------------------------------------------------------------------------

/// One set element. Key bytes are stored as **network-order** raw bytes
/// (matching how libnftnl lays NFTA_DATA_VALUE on the wire — no swap), so
/// an IPv4 address `192.168.0.0` is exactly `[192,168,0,0]`. The kernel
/// also reports `is_interval_end` (NFT_SET_ELEM_INTERVAL_END) for boundary
/// elements of interval sets and may attach a `key_end` (the exclusive
/// upper bound). `timeout_ms` and `expiration_ms` are u64 milliseconds,
/// present only when the kernel attached those attributes.
#[derive(Clone, Debug)]
pub struct Elem {
    /// Raw key bytes (NFTA_SET_ELEM_KEY → NFTA_DATA_VALUE).
    pub key: Vec<u8>,
    /// True if NFT_SET_ELEM_INTERVAL_END is set (this element closes a
    /// half-open interval pair).
    pub is_end: bool,
    /// Raw upper-bound bytes (NFTA_SET_ELEM_KEY_END if the kernel used the
    /// single-element form), present only for intervals on modern kernels.
    pub key_end: Vec<u8>,
    /// Element-wide timeout configuration (u64 ms), None if not present.
    pub timeout_ms: Option<u64>,
    /// Remaining lifetime (u64 ms), None if the set has no timeout policy.
    pub expiration_ms: Option<u64>,
}

impl Elem {
    fn from_attrs(t: &Table<'_>) -> Option<Elem> {
        let key_attr = t.get(NFTA_SET_ELEM_KEY)?;
        let key = unwrap_data_value(key_attr)?;

        let mut flags = 0u32;
        if let Some(f) = t.get(NFTA_SET_ELEM_FLAGS) {
            flags = f.as_u32_be();
        }
        let is_end = (flags & NFT_SET_ELEM_INTERVAL_END) != 0;

        let key_end = t
            .get(NFTA_SET_ELEM_KEY_END)
            .and_then(unwrap_data_value)
            .unwrap_or_default();

        let timeout_ms = t.get(NFTA_SET_ELEM_TIMEOUT).map(|a| a.as_u64_be());
        let expiration_ms = t.get(NFTA_SET_ELEM_EXPIRATION).map(|a| a.as_u64_be());

        Some(Elem {
            key,
            is_end,
            key_end,
            timeout_ms,
            expiration_ms,
        })
    }
}

/// Unwrap a `NFTA_SET_ELEM_KEY` / `_DATA`-style nested attribute into the
/// raw bytes inside its single `NFTA_DATA_VALUE` child. Returns None if the
/// nesting is malformed (verdict-type data inside a key is unexpected).
fn unwrap_data_value(outer: &NlAttr<'_>) -> Option<Vec<u8>> {
    for inner in iter_attrs(outer.payload) {
        if inner.attr_type() == NFTA_DATA_VALUE {
            return Some(inner.payload.to_vec());
        }
    }
    None
}

/// Tiny attribute-table helper: build a sparse lookup over an attr iterator.
struct Table<'a> { items: Vec<(u16, NlAttr<'a>)> }
impl<'a> Table<'a> {
    fn new<I: IntoIterator<Item = NlAttr<'a>>>(attrs: I) -> Self {
        Table { items: attrs.into_iter().map(|a| (a.attr_type(), a)).collect() }
    }
    /// Look up by attribute type.  Uses `rev().find()` so that if the
    /// kernel (erroneously) duplicates an attribute, the **last** one
    /// wins — consistent with last-value-wins semantics elsewhere.
    fn get(&self, t: u16) -> Option<&NlAttr<'a>> {
        self.items.iter().rev().find(|(k, _)| *k == t).map(|(_, v)| v)
    }
}

// ---------------------------------------------------------------------------
// interval reduction  ⇒  CIDR representation
// ---------------------------------------------------------------------------

/// Reduce a raw stream of start/end elements (as the kernel emits them) into
/// one display element per interval, exactly like
/// nftables/src/netlink.c::netlink_delinearize_setelem +
/// segtree.c::interval_map_decompose + segtree.c::interval_to_prefix.
///
/// `is_interval` mirrors `NFT_SET_INTERVAL` from the set's `NFTA_SET_FLAGS`
/// (obtained via a separate `NFT_MSG_GETSET` — see `dump_set_flags`). When
/// the set is **not** an interval set, every element is a standalone single
/// address and we must NOT pair up consecutive elements (which is what
/// caused bogus `start-end` output before).
///
/// For interval sets, two on-wire forms are normalised here:
///   (a) Two boundary elements sharing a key range — the first without
///       INTERVAL_END, the second with INTERVAL_END set.
///   (b) One element with both KEY and KEY_END present. The KEY_END stands
///       in for the closing boundary element.
///
/// For each (start, end) pair we try the CIDR recovery algorithm (identical
/// to nftables' segtree.c::range_expr_is_prefix / interval_to_prefix): if
/// the (start, end] pair forms a clean power-of-2 host part AND `start` is
/// aligned to that netmask, we emit `start/prefixlen`. Otherwise we emit
/// `start-end` (nftables' interval_to_range fallback). Non-interval elements
/// (no companion end) are emitted verbatim as a single address.
pub fn reduce_intervals(elems: Vec<Elem>, is_interval: bool) -> Vec<Elem> {
    if !is_interval {
        // Plain set: every element is its own standalone single address; do
        // not pair.
        return elems;
    }
    // Step 1: split any element carrying KEY_END into (start, fake_end).
    let mut stream: Vec<Elem> = Vec::with_capacity(elems.len() * 2);
    for mut e in elems {
        if e.is_end {
            stream.push(e);
            continue;
        }
        if e.key_end.is_empty() {
            stream.push(e);
            continue;
        }
        let end_bytes = std::mem::take(&mut e.key_end);
        stream.push(e.clone());
        stream.push(Elem {
            key: end_bytes,
            is_end: true,
            key_end: Vec::new(),
            timeout_ms: e.timeout_ms,
            expiration_ms: e.expiration_ms,
        });
    }

    // Step 2: SORT all elements by key bytes (big-endian network order).
    // This mirrors nftables/src/segtree.c::interval_map_decompose which
    // qsort()s by expr_value_cmp before walking the list.  The kernel dump
    // is NOT in key order — it interleaves start/end markers per logical
    // element, so without sorting an end marker of one element can be
    // wrongly paired with the start of an unrelated neighbour.
    stream.sort_by(|a, b| a.key.cmp(&b.key));

    // Step 3: walk the sorted stream; pair each non-end element with the
    // next end-bearing element.  The kernel's `NFT_SET_ELEM_INTERVAL_END`
    // element carries an **exclusive** upper bound (half-open interval
    // [low, end)), matching `add_interval(set, low, i, true /* closed */)` in
    // segtree.c, which subtracts 1 (`mpz_sub_ui(range, range, 1)`) to compute
    // the inclusive host-part extent.  We translate to inclusive form here
    // by decrementing the end marker's key — so the downstream
    // `interval_to_cidr` works on [start, inclusive_end].
    let mut out: Vec<Elem> = Vec::new();
    let mut pending: Option<Elem> = None;
    for e in stream {
        if e.is_end {
            if let Some(start) = pending.take() {
                let mut merged = start.clone();
                // Carry the closing element's expiration/timeout if the
                // starter lacked them (mirrors nftables attaching timeout to
                // the START of an interval; whichever side has it wins).
                if let Some(x) = e.expiration_ms { merged.expiration_ms.get_or_insert(x); }
                if let Some(x) = e.timeout_ms    { merged.timeout_ms.get_or_insert(x); }
                // Decrement the exclusive end by 1 to get the inclusive
                // upper bound.  If this underflows (end == 0, shouldn't
                // happen in a valid interval set) skip the orphan pair.
                let mut end_incl = e.key.clone();
                if decrement_be(&mut end_incl).is_some() {
                    merged.key_end = end_incl;
                    out.push(merged);
                }
                // else: underflow — drop the orphan pair.
            } else {
                // Orphan end marker (no preceding start) — silently drop
                // it, matching nftables segtree.c lines 649-654 where
                // `if (i->key->flags & EXPR_F_INTERVAL_END) { expr_free(i);
                // continue; }`.  The sorted view makes these letters-but-no-
                // companion easily identifiable at the very front of the
                // stream (the kernel's tidy-up marker for the global prefix).
            }
        } else {
            if let Some(prev) = pending.take() {
                // Consecutive starts without an intermediate end.
                // Check if they form a valid interval pair (prev=start, e=exclusive end).
                // This handles kernels that omit the INTERVAL_END flag on the end boundary.
                // The kernel sends EXCLUSIVE end, so we must decrement to get inclusive end
                // before checking if they form a valid CIDR.
                let mut end_incl = e.key.clone();
                if decrement_be(&mut end_incl).is_some()
                    && crate::fmt::interval_to_cidr(&prev.key, &end_incl).is_some()
                {
                    // They form a valid CIDR range: prev is start, e is exclusive end.
                    let mut merged = prev.clone();
                    // Carry timeout/expiration from either side.
                    if let Some(x) = e.expiration_ms { merged.expiration_ms.get_or_insert(x); }
                    if let Some(x) = e.timeout_ms    { merged.timeout_ms.get_or_insert(x); }
                    merged.key_end = end_incl;
                    out.push(merged);
                    // Clear pending since we consumed both elements.
                    pending = None;
                } else {
                    // Not a valid interval pair: emit prev as single, keep e as pending.
                    out.push(prev);
                    pending = Some(e);
                }
            } else {
                pending = Some(e);
            }
        }
    }
    if let Some(last) = pending {
        // Trailing start with no end: emit it as-is. For a half-open
        // interval-set never emits such an element pair, but a plain set
        // bypasses this whole function and interval sets almost always
        // pair up cleanly post-sort. If it happens, leave the single
        // address visible.
        out.push(last);
    }
    out
}

// ---------------------------------------------------------------------------
// set membership check  (pure logic, available on all platforms)
// ---------------------------------------------------------------------------

/// Check whether `ip_bytes` appears as an element (or inside a range, for
/// interval sets) in a set described by already-fetched elements.
///
/// This is a pure-logic function (no netlink I/O).  The caller must obtain
/// elements via `dump_set_elements` (async) before calling this.
///
/// For interval sets the pairing logic mirrors `reduce_intervals`: elements
/// are sorted by key, start/end pairs are formed, and membership is checked
/// against the half-open interval `[start, end_exclusive)`.  Non-interval
/// sets use exact `key` matching.
pub fn set_contains_ip(elems: &[Elem], is_interval: bool, ip_bytes: &[u8]) -> bool {
    if !is_interval {
        return elems.iter().any(|e| !e.is_end && ip_bytes == e.key.as_slice());
    }

    // ── Step 1: normalise elements carrying KEY_END ──
    let mut stream: Vec<Elem> = Vec::with_capacity(elems.len() * 2);
    for e in elems {
        if e.is_end || e.key_end.is_empty() {
            stream.push(e.clone());
        } else {
            // Split (key + key_end) into a normal start and an end-marker.
            let end_key = e.key_end.clone();
            stream.push(e.clone());
            stream.push(Elem {
                key: end_key,
                is_end: true,
                key_end: Vec::new(),
                timeout_ms: e.timeout_ms,
                expiration_ms: e.expiration_ms,
            });
        }
    }

    // ── Step 2: sort by key bytes ──
    stream.sort_by(|a, b| a.key.cmp(&b.key));

    // ── Step 3: walk the stream, check each pair for containment ──
    // Collect standalone singles (consecutive starts without an intervening
    // end) and check them in a final pass — this ensures we don't drop a
    // start when the next element is also a start rather than an end.
    // Also detect valid interval pairs where the kernel omits INTERVAL_END
    // on the end boundary.
    let mut pending_start: Option<Vec<u8>> = None;
    let mut singles: Vec<Vec<u8>> = Vec::new();
    for e in &stream {
        if e.is_end {
            if let Some(start) = pending_start.take()
                && ip_bytes >= start.as_slice() && ip_bytes < e.key.as_slice() {
                return true;
            }
        } else if let Some(start) = &pending_start {
            // Consecutive starts without an intervening end.
            // Check if they form a valid interval pair (start, exclusive end).
            // The kernel sends EXCLUSIVE end, so we must decrement to get
            // the inclusive upper bound before checking CIDR validity.
            let mut end_incl = e.key.clone();
            if decrement_be(&mut end_incl).is_some()
                && crate::fmt::interval_to_cidr(start, &end_incl).is_some()
            {
                // They form a valid CIDR range: start is inclusive start, e.key is exclusive end.
                if ip_bytes >= start.as_slice() && ip_bytes < e.key.as_slice() {
                    return true;
                }
                // Not in this range, clear pending and continue.
                pending_start = None;
            } else {
                // Not a valid interval pair: the previous start is a standalone single.
                singles.push(start.clone());
                pending_start = Some(e.key.clone());
            }
        } else {
            pending_start = Some(e.key.clone());
        }
    }
    // Check the last pending start (if any) as a standalone.
    if let Some(start) = &pending_start && ip_bytes == start.as_slice() {
        return true;
    }
    // Final pass: check all accumulated standalone singles.
    for s in &singles {
        if ip_bytes == s.as_slice() {
            return true;
        }
    }
    false
}

/// Increment a big-endian (network-order) byte string by 1 in place,
/// propagating carries from the least-significant byte (the last one) up.
/// Returns `None` on overflow (all-0xFF bytes).  On overflow the buffer
/// is left **unchanged**.
fn increment_be(b: &mut [u8]) -> Option<()> {
    // Fast path: if every byte is already 0xff, overflow immediately.
    if b.iter().all(|&x| x == 0xff) {
        return None;
    }
    for i in (0..b.len()).rev() {
        if b[i] != 0xff {
            b[i] += 1;
            return Some(());
        }
        b[i] = 0x00;  // carry to the next more-significant byte
    }
    None
}

/// Decrement a big-endian (network-order) byte string by 1 in place, doing
/// a borrow chain from the least-significant byte (the last one) up.
/// Returns `None` on underflow (all-0x00 bytes — should not happen in a
/// valid interval set, but handled defensively).  On underflow the buffer
/// is left **unchanged**.
fn decrement_be(b: &mut [u8]) -> Option<()> {
    if b.is_empty() { return None; }
    // Fast path: if every byte is already zero, underflow immediately
    // without modifying the buffer.
    if b.iter().all(|&x| x == 0) {
        return None;
    }
    for i in (0..b.len()).rev() {
        if b[i] != 0 {
            b[i] -= 1;
            return Some(());
        }
        b[i] = 0xff;  // borrow from the next more-significant byte
    }
    // We checked all-zero above, so this is unreachable.
    None
}

// ---------------------------------------------------------------------------
// async netlink session  (Linux only — uses netlink-sys TokioSocket)
// ---------------------------------------------------------------------------

/// Async netlink session: open a `NETLINK_NETFILTER` socket, bind, send one
/// request, and drive a multipart recv loop. Mirrors the canonical
/// libmnl/libnftnl dump idiom, but using `netlink-sys` + tokio for async I/O.
#[cfg(target_os = "linux")]
struct NlSession {
    socket: TokioSocket,
    portid: u32,
    seq: u32,
}

#[cfg(target_os = "linux")]
impl NlSession {
    /// Open a `NETLINK_NETFILTER` socket and bind with kernel-assigned portid.
    async fn open() -> io::Result<Self> {
        let mut socket = TokioSocket::new(NETLINK_NETFILTER)?;
        // bind_auto is synchronous (no network I/O — just libc::bind +
        // getsockname), safe to call on a non-blocking socket.
        let addr = socket.socket_mut().bind_auto()?;
        Ok(NlSession {
            socket,
            portid: addr.port_number(),
            seq: std::process::id(),
        })
    }

    /// Send a raw message buffer to the kernel (pid=0, groups=0).
    async fn send(&self, buf: &MsgBuf) -> io::Result<()> {
        let dest = SocketAddr::new(0, 0);
        let n = self.socket.send_to(buf.as_bytes(), &dest).await?;
        if n != buf.as_bytes().len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short write on netlink socket",
            ));
        }
        Ok(())
    }

    /// Drive the multipart reply to completion.
    ///
    /// `multipart=true` (the `NLM_F_DUMP` case) waits for `NLMSG_DONE`;
    /// `multipart=false` (a single-message GET) returns after the first
    /// data message. `on_msg(nlmsg_type, body)` is invoked once per *data*
    /// message in the stream (`NLMSG_DONE` / `NLMSG_ERROR` / `NLMSG_NOOP` are
    /// handled here). Each `recv_from` carries a 3-second timeout (replaces
    /// the former `SO_RCVTIMEO` setsockopt).
    async fn recv_each(
        &self,
        multipart: bool,
        mut on_msg: impl FnMut(u16, &[u8]) -> io::Result<()>,
    ) -> io::Result<()> {
        let mut recv = BytesMut::with_capacity(64 * 1024);
        let mut consumed_done = false;
        let mut got_one_data = false;
        loop {
            recv.clear();
            // 3-second idle timeout per recv (same semantic as SO_RCVTIMEO).
            let _addr = tokio::time::timeout(
                Duration::from_secs(3),
                self.socket.recv_from(&mut recv),
            )
            .await
            .map_err(|_| {
                if !multipart || consumed_done {
                    io::Error::new(io::ErrorKind::TimedOut, "recv timed out")
                } else {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "kernel reply timed out waiting for NLMSG_DONE",
                    )
                }
            })??;

            // If recv_from truncated the message (msg_len == recv.capacity()
            // and the kernel indicates more data was available), grow and
            // retry once.  Note: `n == recv.capacity()` is a heuristic — it
            // may also occur when the message exactly fills the buffer, but
            // retrying once with a larger buffer is harmless.
            let n = recv.len();
            if n == recv.capacity() && n < 256 * 1024 && n > 0 {
                let cap = (recv.capacity() * 2).min(256 * 1024);
                recv = BytesMut::with_capacity(cap);
                continue;
            }
            if n == 0 {
                break;
            }

            let slice = &recv[..n];
            let mut pos = 0usize;
            while pos + NLMSG_HDRLEN <= slice.len() {
                let len = u32::from_ne_bytes([
                    slice[pos], slice[pos+1], slice[pos+2], slice[pos+3],
                ]) as usize;
                if len < NLMSG_HDRLEN || pos + len > slice.len() { break; }
                let nlmsg_type = u16::from_ne_bytes([slice[pos+4], slice[pos+5]]);
                let nlmsg_seq  = u32::from_ne_bytes([slice[pos+8], slice[pos+9], slice[pos+10], slice[pos+11]]);
                let nlmsg_pid  = u32::from_ne_bytes([slice[pos+12], slice[pos+13], slice[pos+14], slice[pos+15]]);

                // Sanity (mirrors mnl_socket_get_portid / mnl_nlmsg_seq_ok).
                if nlmsg_pid != self.portid || nlmsg_seq != self.seq {
                    pos = align_up(pos + len, ALIGN);
                    continue;
                }

                if nlmsg_type == NLMSG_DONE {
                    consumed_done = true;
                    break;
                }
                if nlmsg_type == NLMSG_NOOP {
                    pos = align_up(pos + len, ALIGN);
                    continue;
                }
                if nlmsg_type == NLMSG_ERROR {
                    // struct nlmsgerr { i32 error; nlmsghdr msg; }
                    if pos + NLMSG_HDRLEN + 4 > slice.len() { break; }
                    let err = i32::from_ne_bytes([
                        slice[pos+NLMSG_HDRLEN], slice[pos+NLMSG_HDRLEN+1],
                        slice[pos+NLMSG_HDRLEN+2], slice[pos+NLMSG_HDRLEN+3],
                    ]);
                    if err != 0 {
                        return Err(io::Error::other(
                            format!("kernel refused: {}", errno_to_msg(err)),
                        ));
                    }
                    // err == 0 is an ACK (we requested NLM_F_ACK). For a
                    // multipart dump the kernel follows ACK with NLMSG_DONE;
                    // for a non-multipart single GET the ACK alone is the
                    // end of the reply.
                    if !multipart { return Ok(()); }
                    pos = align_up(pos + len, ALIGN);
                    continue;
                }

                let body = &slice[pos + NLMSG_HDRLEN .. pos + len];
                if body.len() >= NFG_HDRLEN {
                    on_msg(nlmsg_type, body)?;
                    got_one_data = true;
                }
                pos = align_up(pos + len, ALIGN);
            }
            if consumed_done { break; }
            if !multipart && got_one_data { return Ok(()); }
        }
        Ok(())
    }

    /// Like [`recv_each`] but accepts any of the given sequence numbers.
    /// Used for batch operations where multiple messages (each with
    /// a different seq) share one socket and we must verify all of them.
    async fn recv_for_seqs(
        &self,
        valid_seqs: &[u32],
        mut on_msg: impl FnMut(u16, &[u8]) -> io::Result<()>,
    ) -> io::Result<()> {
        let mut recv = BytesMut::with_capacity(64 * 1024);
        loop {
            recv.clear();
            let _addr = tokio::time::timeout(
                Duration::from_secs(3),
                self.socket.recv_from(&mut recv),
            )
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "kernel reply timed out on batch recv")
            })??;

            let n = recv.len();
            if n == recv.capacity() && n < 256 * 1024 && n > 0 {
                let cap = (recv.capacity() * 2).min(256 * 1024);
                recv = BytesMut::with_capacity(cap);
                continue;
            }
            if n == 0 {
                break;
            }

            let slice = &recv[..n];
            let mut pos = 0usize;
            while pos + NLMSG_HDRLEN <= slice.len() {
                let len = u32::from_ne_bytes([
                    slice[pos], slice[pos+1], slice[pos+2], slice[pos+3],
                ]) as usize;
                if len < NLMSG_HDRLEN || pos + len > slice.len() { break; }
                let nlmsg_type = u16::from_ne_bytes([slice[pos+4], slice[pos+5]]);
                let nlmsg_seq  = u32::from_ne_bytes([slice[pos+8], slice[pos+9], slice[pos+10], slice[pos+11]]);
                let nlmsg_pid  = u32::from_ne_bytes([slice[pos+12], slice[pos+13], slice[pos+14], slice[pos+15]]);

                if nlmsg_pid != self.portid || !valid_seqs.contains(&nlmsg_seq) {
                    pos = align_up(pos + len, ALIGN);
                    continue;
                }

                if nlmsg_type == NLMSG_DONE {
                    break;
                }
                if nlmsg_type == NLMSG_NOOP {
                    pos = align_up(pos + len, ALIGN);
                    continue;
                }
                if nlmsg_type == NLMSG_ERROR {
                    if pos + NLMSG_HDRLEN + 4 > slice.len() { break; }
                    let err = i32::from_ne_bytes([
                        slice[pos+NLMSG_HDRLEN], slice[pos+NLMSG_HDRLEN+1],
                        slice[pos+NLMSG_HDRLEN+2], slice[pos+NLMSG_HDRLEN+3],
                    ]);
                    if err != 0 {
                        return Err(io::Error::other(
                            format!("kernel refused: {}", errno_to_msg(err)),
                        ));
                    }
                    // ACK (err=0): continue processing remaining messages
                    // in this datagram.  Batch semantics guarantee that if
                    // one operation committed, the whole batch committed.
                    pos = align_up(pos + len, ALIGN);
                    continue;
                }

                let body = &slice[pos + NLMSG_HDRLEN .. pos + len];
                if body.len() >= NFG_HDRLEN {
                    on_msg(nlmsg_type, body)?;
                }
                pos = align_up(pos + len, ALIGN);
            }
            // Batch responses fit in one datagram — we're done after
            // processing everything the kernel sent in this round.
            break;
        }
        Ok(())
    }

    /// Query set flags for `(family, table, set)` using this session
    /// (avoids opening a separate socket for the flags query).
    /// Returns `NFTA_SET_FLAGS` as a `u32` (host order), `0` if absent.
    async fn query_flags(&self, family: u8, table: &str, set: &str) -> io::Result<u32> {
        const FLAGS: u16 = NLM_F_REQUEST | NLM_F_ACK;
        let nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_GETSET;

        let mut buf = MsgBuf::new();
        let head = buf.put_header();
        buf.put_attr_stringz(NFTA_SET_TABLE, table);
        buf.put_attr_stringz(NFTA_SET_NAME, set);
        buf.set_header(head, nlmsg_type, family, 0, FLAGS, 0);

        buf.fix_seq_at(0, self.seq);
        self.send(&buf).await?;

        let mut flags: u32 = 0;
        self.recv_each(false, |_resp_type, body| {
            for a in iter_attrs(&body[NFG_HDRLEN..]) {
                if a.attr_type() == NFTA_SET_FLAGS {
                    flags = a.as_u32_be();
                }
            }
            Ok(())
        }).await?;
        Ok(flags)
    }
}

// ---------------------------------------------------------------------------
// public async API
// ---------------------------------------------------------------------------

/// Query the set flags for `(family, table, set)` via `NFT_MSG_GETSET`.
/// Returns the `NFTA_SET_FLAGS` bitmask as a `u32` (host order, i.e. raw
/// `ntohl(value)`), `0` if the set carries no flags.  Errors only if the
/// netlink request itself fails or the kernel rejects it (e.g. ENOENT).
#[cfg(target_os = "linux")]
pub async fn dump_set_flags(family: u8, table: &str, set: &str) -> io::Result<u32> {
    let sess = NlSession::open().await?;
    sess.query_flags(family, table, set).await
}

#[cfg(target_os = "linux")]
pub async fn dump_set_elements(family: u8, table: &str, set: &str) -> io::Result<Vec<Elem>> {
    const FLAGS: u16 = NLM_F_REQUEST | NLM_F_DUMP | NLM_F_ACK;
    let nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_GETSETELEM;

    let mut buf = MsgBuf::new();
    let head = buf.put_header();
    // Body for NFT_MSG_GETSETELEM dump: NFTA_SET_ELEM_LIST_TABLE + _SET only.
    buf.put_attr_stringz(NFTA_SET_ELEM_LIST_TABLE, table);
    buf.put_attr_stringz(NFTA_SET_ELEM_LIST_SET, set);
    buf.set_header(head, nlmsg_type, family, 0, FLAGS, 0);

    let sess = NlSession::open().await?;
    buf.fix_seq_at(0, sess.seq);
    sess.send(&buf).await?;

    let mut out: Vec<Elem> = Vec::new();
    sess.recv_each(true, |_nlmsg_type, body| {
        // body = nfgenmsg + NFTA_SET_ELEM_LIST_* TLVs.  Walk ELEMENTS;
        // each entry is a NFTA_LIST_ELEM-wrapped set of NFTA_SET_ELEM_*
        // attributes that we reduce into one `Elem`.
        let outer_attrs = &body[NFG_HDRLEN..];
        for a in iter_attrs(outer_attrs) {
            if a.attr_type() != NFTA_SET_ELEM_LIST_ELEMENTS { continue; }
            for sub in iter_attrs(a.payload) {
                if sub.attr_type() != NFTA_LIST_ELEM { continue; }
                let tbl = Table::new(iter_attrs(sub.payload));
                if let Some(e) = Elem::from_attrs(&tbl) {
                    out.push(e);
                }
            }
        }
        Ok(())
    }).await?;
    Ok(out)
}

/// Add a single element to an nftables set via netlink batch.
///
/// Wraps `NFT_MSG_NEWSETELEM` inside a `NFNL_MSG_BATCH_BEGIN` … `BATCH_END`
/// transaction (the kernel requires nfnetlink batch semantics for write
/// operations). When `timeout_ms` is `Some`, `NFTA_SET_ELEM_TIMEOUT` (u64 BE
/// milliseconds) is attached.
///
/// For **interval sets** (auto-detected via an internal `NFT_MSG_GETSET`
/// query), a bare address is expanded into (start, end-marker) pairs matching
/// what `nft add element` does – otherwise the kernel would leave the start
/// element orphaned and pair it with an unrelated existing end marker.
///
/// `key_end` is the **inclusive** upper bound (e.g. the broadcast for a CIDR
/// block like `10.0.0.0/24` → `10.0.0.255`).  For interval sets it is
/// automatically incremented to form the exclusive end-marker key.  For
/// non-interval sets `key_end` is silently ignored (only bare keys are sent).
///
/// The `NLM_F_CREATE` flag is always set (create-or-replace semantics,
/// equivalent to `nft add element`). If you need exclusive-create semantics
/// (failure on duplicate, like `nft create element`), pass `excl = true`.
#[cfg(target_os = "linux")]
pub async fn add_set_element(
    family: u8,
    table: &str,
    set: &str,
    key: &[u8],
    key_end: Option<&[u8]>,   // inclusive upper bound (e.g. broadcast)
    timeout_ms: Option<u64>,
    excl: bool,
) -> io::Result<()> {
    // Open one session and reuse it for both the flags query and the batch write.
    let mut sess = NlSession::open().await?;

    // Detect whether the target set is an interval set.
    let is_interval = (sess.query_flags(family, table, set).await? & NFT_SET_INTERVAL) != 0;

    let nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWSETELEM;
    let mut extra = NLM_F_CREATE;
    if excl { extra |= NLM_F_EXCL; }
    let flags = NLM_F_REQUEST | extra | NLM_F_ACK;

    let mut buf = MsgBuf::new();
    let base_seq = sess.seq;
    let elem_seq = base_seq.wrapping_add(1);

    // ── BATCH_BEGIN ──
    let begin_off = buf.put_header();
    buf.set_header(
        begin_off, NFNL_MSG_BATCH_BEGIN, AF_UNSPEC,
        base_seq, NLM_F_REQUEST, NFNL_SUBSYS_NFTABLES,
    );

    // ── NEWSETELEM ──
    let elem_off = buf.put_header();
    buf.put_attr_stringz(NFTA_SET_ELEM_LIST_TABLE, table);
    buf.put_attr_stringz(NFTA_SET_ELEM_LIST_SET, set);

    let nest_list = buf.open_nest(NFTA_SET_ELEM_LIST_ELEMENTS);

    // Helper to build one element inside the list (KEY + optional FLAGS + optional TIMEOUT).
    let mut put_one = |k: &[u8], iend: bool, tmo: Option<u64>| {
        let ne = buf.open_nest(NFTA_LIST_ELEM);
        let nk = buf.open_nest(NFTA_SET_ELEM_KEY);
        buf.put_attr(NFTA_DATA_VALUE, 0, k.len(), |b| b.copy_from_slice(k));
        buf.close_nest(nk);
        if iend {
            buf.put_attr(NFTA_SET_ELEM_FLAGS, 0, 4, |b| {
                b.copy_from_slice(&NFT_SET_ELEM_INTERVAL_END.to_be_bytes());
            });
        }
        if let Some(t) = tmo {
            buf.put_attr(NFTA_SET_ELEM_TIMEOUT, 0, 8, |b| {
                b.copy_from_slice(&t.to_be_bytes());
            });
        }
        buf.close_nest(ne);
    };

    if is_interval {
        // Interval set: send TWO elements — start + exclusive-end marker.
        put_one(key, false, timeout_ms);

        // Compute exclusive upper bound.
        let mut end_key = match key_end {
            Some(ke) => ke.to_vec(),
            None => key.to_vec(),
        };
        if increment_be(&mut end_key).is_none() {
            return Err(io::Error::other("element interval overflows (all-0xFF)"));
        }
        put_one(&end_key, true, None);
    } else {
        // Non-interval set: send one bare KEY (no KEY_END, no FLAGS).
        put_one(key, false, timeout_ms);
    }

    buf.close_nest(nest_list);

    buf.set_header(elem_off, nlmsg_type, family, elem_seq, flags, 0);

    // ── BATCH_END ──
    let end_off = buf.put_header();
    buf.set_header(
        end_off, NFNL_MSG_BATCH_END, AF_UNSPEC,
        base_seq + 2, NLM_F_REQUEST, NFNL_SUBSYS_NFTABLES,
    );

    // ── Transport ──
    sess.seq = elem_seq;
    buf.fix_seq_at(elem_off, elem_seq);
    sess.send(&buf).await?;

    sess.recv_each(false, |_nlmsg_type, _body| Ok(())).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// batch-delete helper (Linux only)
// ---------------------------------------------------------------------------

/// Delete a single element from an nftables set via netlink batch.
///
/// Wraps `NFT_MSG_DELSETELEM` inside a `NFNL_MSG_BATCH_BEGIN` … `BATCH_END`
/// transaction (the kernel requires nfnetlink batch semantics for write
/// operations).
///
/// For **interval sets** (auto-detected via an internal `NFT_MSG_GETSET`
/// query), the element is expanded into (start, end-marker) pairs matching
/// what `nft delete element` expects — otherwise the kernel would not
/// find the interval record to remove.
///
/// `key_end` is the **inclusive** upper bound (e.g. the broadcast for a CIDR
/// block like `10.0.0.0/24` → `10.0.0.255`).  For interval sets it is
/// automatically incremented to form the exclusive end-marker key.  For
/// non-interval sets `key_end` is silently ignored (only bare keys are sent).
#[cfg(target_os = "linux")]
pub async fn delete_set_element(
    family: u8,
    table: &str,
    set: &str,
    key: &[u8],
    key_end: Option<&[u8]>,   // inclusive upper bound (e.g. broadcast)
) -> io::Result<()> {
    // Open one session and reuse it for both the flags query and the batch write.
    let mut sess = NlSession::open().await?;

    // Detect whether the target set is an interval set.
    let is_interval = (sess.query_flags(family, table, set).await? & NFT_SET_INTERVAL) != 0;

    let nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_DELSETELEM;
    let flags = NLM_F_REQUEST | NLM_F_ACK;

    let mut buf = MsgBuf::new();
    let base_seq = sess.seq;
    let elem_seq = base_seq.wrapping_add(1);

    // ── BATCH_BEGIN ──
    let begin_off = buf.put_header();
    buf.set_header(
        begin_off, NFNL_MSG_BATCH_BEGIN, AF_UNSPEC,
        base_seq, NLM_F_REQUEST, NFNL_SUBSYS_NFTABLES,
    );

    // ── DELSETELEM ──
    let elem_off = buf.put_header();
    buf.put_attr_stringz(NFTA_SET_ELEM_LIST_TABLE, table);
    buf.put_attr_stringz(NFTA_SET_ELEM_LIST_SET, set);

    let nest_list = buf.open_nest(NFTA_SET_ELEM_LIST_ELEMENTS);

    // Helper to build one element inside the list (KEY + optional FLAGS).
    let mut put_one = |k: &[u8], iend: bool| {
        let ne = buf.open_nest(NFTA_LIST_ELEM);
        let nk = buf.open_nest(NFTA_SET_ELEM_KEY);
        buf.put_attr(NFTA_DATA_VALUE, 0, k.len(), |b| b.copy_from_slice(k));
        buf.close_nest(nk);
        if iend {
            buf.put_attr(NFTA_SET_ELEM_FLAGS, 0, 4, |b| {
                b.copy_from_slice(&NFT_SET_ELEM_INTERVAL_END.to_be_bytes());
            });
        }
        buf.close_nest(ne);
    };

    if is_interval {
        // Interval set: send TWO elements — start + exclusive-end marker.
        put_one(key, false);

        // Compute exclusive upper bound.
        let mut end_key = match key_end {
            Some(ke) => ke.to_vec(),
            None => key.to_vec(),
        };
        if increment_be(&mut end_key).is_none() {
            return Err(io::Error::other("element interval overflows (all-0xFF)"));
        }
        put_one(&end_key, true);
    } else {
        // Non-interval set: send one bare KEY (no KEY_END, no FLAGS).
        put_one(key, false);
    }

    buf.close_nest(nest_list);

    buf.set_header(elem_off, nlmsg_type, family, elem_seq, flags, 0);

    // ── BATCH_END ──
    let end_off = buf.put_header();
    buf.set_header(
        end_off, NFNL_MSG_BATCH_END, AF_UNSPEC,
        base_seq + 2, NLM_F_REQUEST, NFNL_SUBSYS_NFTABLES,
    );

    // ── Transport ──
    sess.seq = elem_seq;
    buf.fix_seq_at(elem_off, elem_seq);
    sess.send(&buf).await?;

    sess.recv_each(false, |_nlmsg_type, _body| Ok(())).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// set membership check  (async convenience — Linux only)
// ---------------------------------------------------------------------------

/// Check whether an IP address (raw bytes, network order) is present in an
/// nftables set.  Internally fetches set flags + elements and delegates to
/// the pure-logic [`set_contains_ip`] for the actual containment test.
///
/// This is the one-call convenience; if you already hold the element vec
/// (e.g. from a prior `dump_set_elements`), call [`set_contains_ip`] directly
/// to avoid the extra `NFT_MSG_GETSET` round trip.
#[cfg(target_os = "linux")]
pub async fn set_contains_ip_async(
    family: u8,
    table: &str,
    set: &str,
    ip_bytes: &[u8],
) -> io::Result<bool> {
    let flags = dump_set_flags(family, table, set).await?;
    let is_interval = (flags & NFT_SET_INTERVAL) != 0;
    let elems = dump_set_elements(family, table, set).await?;
    Ok(set_contains_ip(&elems, is_interval, ip_bytes))
}

// ---------------------------------------------------------------------------
// combined batch: atomically delete + add in one transaction
// ---------------------------------------------------------------------------

/// Atomically delete and then add an element in a single nfnetlink batch.
///
/// The entire batch is committed or rolled back as one unit — there is
/// no window where neither element exists.
///
/// Internally opens one `NlSession`, builds a single batch containing
/// both `NFT_MSG_DELSETELEM` and `NFT_MSG_NEWSETELEM`, sends it once,
/// and validates ACKs for both operations.
///
/// For **interval sets** each operation (delete + add) independently
/// expands into (start, end-marker) pairs via `increment_be`, mirroring
/// what `nft` would send for a standalone add / delete.
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
pub async fn batch_add_and_delete_set_element(
    family: u8,
    table: &str,
    set: &str,
    // delete params
    del_key: &[u8],
    del_key_end: Option<&[u8]>,
    // add params
    add_key: &[u8],
    add_key_end: Option<&[u8]>,
    add_timeout_ms: Option<u64>,
    add_excl: bool,
) -> io::Result<()> {
    // Open one session and reuse it for both the flags query and the batch write.
    let mut sess = NlSession::open().await?;

    // One flags query for both operations.
    let is_interval = (sess.query_flags(family, table, set).await? & NFT_SET_INTERVAL) != 0;

    let del_nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_DELSETELEM;
    let add_nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWSETELEM;
    let mut add_extra = NLM_F_CREATE;
    if add_excl { add_extra |= NLM_F_EXCL; }

    let mut buf = MsgBuf::new();
    let base_seq = sess.seq;
    let del_seq = base_seq.wrapping_add(1);
    let add_seq = base_seq.wrapping_add(2);

    // ── BATCH_BEGIN ──
    {
        let off = buf.put_header();
        buf.set_header(
            off, NFNL_MSG_BATCH_BEGIN, AF_UNSPEC,
            base_seq, NLM_F_REQUEST, NFNL_SUBSYS_NFTABLES,
        );
    }

    // ── DELSETELEM (with ACK) ──
    let del_off = buf.put_header();
    buf.put_attr_stringz(NFTA_SET_ELEM_LIST_TABLE, table);
    buf.put_attr_stringz(NFTA_SET_ELEM_LIST_SET, set);
    {
        let nest_list = buf.open_nest(NFTA_SET_ELEM_LIST_ELEMENTS);
        put_elem_into_list(&mut buf, is_interval, del_key, del_key_end, None)?;
        buf.close_nest(nest_list);
    }
    buf.set_header(del_off, del_nlmsg_type, family, del_seq, NLM_F_REQUEST | NLM_F_ACK, 0);

    // ── NEWSETELEM (with ACK) ──
    let add_off = buf.put_header();
    buf.put_attr_stringz(NFTA_SET_ELEM_LIST_TABLE, table);
    buf.put_attr_stringz(NFTA_SET_ELEM_LIST_SET, set);
    {
        let nest_list = buf.open_nest(NFTA_SET_ELEM_LIST_ELEMENTS);
        put_elem_into_list(&mut buf, is_interval, add_key, add_key_end, add_timeout_ms)?;
        buf.close_nest(nest_list);
    }
    buf.set_header(add_off, add_nlmsg_type, family, add_seq, NLM_F_REQUEST | add_extra | NLM_F_ACK, 0);

    // ── BATCH_END ──
    {
        let off = buf.put_header();
        buf.set_header(
            off, NFNL_MSG_BATCH_END, AF_UNSPEC,
            base_seq + 3, NLM_F_REQUEST, NFNL_SUBSYS_NFTABLES,
        );
    }

    // ── Transport ──
    sess.seq = del_seq;  // accepted alongside add_seq by recv_for_seqs
    buf.fix_seq_at(del_off, del_seq);
    buf.fix_seq_at(add_off, add_seq);
    sess.send(&buf).await?;

    sess.recv_for_seqs(&[del_seq, add_seq], |_nlmsg_type, _body| Ok(())).await?;
    Ok(())
}

/// Helper to serialise one element (or start+end pair for interval sets)
/// into the currently-open `NFTA_SET_ELEM_LIST_ELEMENTS` nest.
/// Returns an error if the element interval overflows (all-0xFF bytes).
#[cfg(target_os = "linux")]
fn put_elem_into_list(
    buf: &mut MsgBuf,
    is_interval: bool,
    key: &[u8],
    key_end: Option<&[u8]>,
    timeout_ms: Option<u64>,
) -> io::Result<()> {
    let mut put_one = |k: &[u8], iend: bool, tmo: Option<u64>| {
        let ne = buf.open_nest(NFTA_LIST_ELEM);
        let nk = buf.open_nest(NFTA_SET_ELEM_KEY);
        buf.put_attr(NFTA_DATA_VALUE, 0, k.len(), |b| b.copy_from_slice(k));
        buf.close_nest(nk);
        if iend {
            buf.put_attr(NFTA_SET_ELEM_FLAGS, 0, 4, |b| {
                b.copy_from_slice(&NFT_SET_ELEM_INTERVAL_END.to_be_bytes());
            });
        }
        if let Some(t) = tmo {
            buf.put_attr(NFTA_SET_ELEM_TIMEOUT, 0, 8, |b| {
                b.copy_from_slice(&t.to_be_bytes());
            });
        }
        buf.close_nest(ne);
    };

    if is_interval {
        put_one(key, false, timeout_ms);
        let mut end_key = match key_end {
            Some(ke) => ke.to_vec(),
            None => key.to_vec(),
        };
        if increment_be(&mut end_key).is_none() {
            return Err(io::Error::other(
                "element interval overflows (all-0xFF bytes)",
            ));
        }
        put_one(&end_key, true, None);
    } else {
        put_one(key, false, timeout_ms);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// batch-add-multiple elements  (Linux only)
// ---------------------------------------------------------------------------

/// Descriptor for one element to be added in a batch.
pub struct AddElem<'a> {
    /// Raw key bytes (network order).
    pub key: &'a [u8],
    /// Inclusive upper bound (e.g. broadcast). For interval sets the
    /// exclusive-end marker is auto-computed by incrementing this value.
    /// Non-interval sets ignore this field.
    pub key_end: Option<&'a [u8]>,
    /// Element-wide timeout (u64 ms). `None` = no timeout.
    pub timeout_ms: Option<u64>,
}

/// Batch-add multiple elements to an nftables set in a single atomic
/// nfnetlink batch transaction.
///
/// All elements are added inside one `NFNL_MSG_BATCH_BEGIN` … `BATCH_END`
/// boundary, so either every element is committed or none are.
///
/// `dump_set_flags` is called once to detect interval semantics and
/// the result applies to every element in the batch.  Each element
/// independently goes through the same expansion as [`add_set_element`]:
/// interval-set elements are sent as (start, end-marker) pairs.
///
/// `excl` controls whether `NLM_F_EXCL` is set (fail on duplicate).
/// When `excl` is `true`, *any* duplicate element causes the entire
/// batch to fail.
#[cfg(target_os = "linux")]
pub async fn batch_add_set_elements(
    family: u8,
    table: &str,
    set: &str,
    elements: &[AddElem<'_>],
    excl: bool,
) -> io::Result<()> {
    // Open one session and reuse it for both the flags query and the batch write.
    let sess = NlSession::open().await?;

    // One flags query for the whole batch.
    let is_interval = (sess.query_flags(family, table, set).await? & NFT_SET_INTERVAL) != 0;

    let nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWSETELEM;
    let mut extra = NLM_F_CREATE;
    if excl { extra |= NLM_F_EXCL; }
    let flags = NLM_F_REQUEST | extra | NLM_F_ACK;

    let mut buf = MsgBuf::new();
    let base_seq = sess.seq;

    // ── BATCH_BEGIN ──
    {
        let off = buf.put_header();
        buf.set_header(
            off, NFNL_MSG_BATCH_BEGIN, AF_UNSPEC,
            base_seq, NLM_F_REQUEST, NFNL_SUBSYS_NFTABLES,
        );
    }

    // ── one NEWSETELEM per element ──
    let elem_seqs: Vec<u32> = (0..elements.len() as u32)
        .map(|i| base_seq.wrapping_add(1 + i))
        .collect();
    let mut elem_offs: Vec<usize> = Vec::with_capacity(elements.len());

    for (i, elem) in elements.iter().enumerate() {
        let elem_off = buf.put_header();
        buf.put_attr_stringz(NFTA_SET_ELEM_LIST_TABLE, table);
        buf.put_attr_stringz(NFTA_SET_ELEM_LIST_SET, set);

        {
            let nest_list = buf.open_nest(NFTA_SET_ELEM_LIST_ELEMENTS);
            put_elem_into_list(&mut buf, is_interval, elem.key, elem.key_end, elem.timeout_ms)?;
            buf.close_nest(nest_list);
        }

        buf.set_header(elem_off, nlmsg_type, family, elem_seqs[i], flags, 0);
        elem_offs.push(elem_off);
    }

    // ── BATCH_END ──
    {
        let off = buf.put_header();
        buf.set_header(
            off, NFNL_MSG_BATCH_END, AF_UNSPEC,
            base_seq.wrapping_add(elements.len() as u32 + 1), NLM_F_REQUEST, NFNL_SUBSYS_NFTABLES,
        );
    }

    // ── Transport ──
    for (&off, &seq) in elem_offs.iter().zip(elem_seqs.iter()) {
        buf.fix_seq_at(off, seq);
    }
    sess.send(&buf).await?;

    sess.recv_for_seqs(&elem_seqs, |_nlmsg_type, _body| Ok(())).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// non-Linux stubs  (the netlink plumbing is Linux-only; on other hosts we
// only keep the pure-logic helpers like `reduce_intervals` available so
// `cargo build` / `cargo test` succeed during development)
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "linux"))]
pub async fn dump_set_flags(_family: u8, _table: &str, _set: &str) -> io::Result<u32> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "nfnetlink operations require Linux; this binary was compiled on a non-Linux target",
    ))
}

#[cfg(not(target_os = "linux"))]
pub async fn dump_set_elements(_family: u8, _table: &str, _set: &str) -> io::Result<Vec<Elem>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "nfnetlink operations require Linux; this binary was compiled on a non-Linux target",
    ))
}

#[cfg(not(target_os = "linux"))]
pub async fn add_set_element(
    _family: u8,
    _table: &str,
    _set: &str,
    _key: &[u8],
    _key_end: Option<&[u8]>,
    _timeout_ms: Option<u64>,
    _excl: bool,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "nfnetlink operations require Linux; this binary was compiled on a non-Linux target",
    ))
}

#[cfg(not(target_os = "linux"))]
pub async fn delete_set_element(
    _family: u8,
    _table: &str,
    _set: &str,
    _key: &[u8],
    _key_end: Option<&[u8]>,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "nfnetlink operations require Linux; this binary was compiled on a non-Linux target",
    ))
}

#[cfg(not(target_os = "linux"))]
#[allow(clippy::too_many_arguments)]
pub async fn batch_add_and_delete_set_element(
    _family: u8,
    _table: &str,
    _set: &str,
    _del_key: &[u8],
    _del_key_end: Option<&[u8]>,
    _add_key: &[u8],
    _add_key_end: Option<&[u8]>,
    _add_timeout_ms: Option<u64>,
    _add_excl: bool,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "nfnetlink operations require Linux; this binary was compiled on a non-Linux target",
    ))
}

#[cfg(not(target_os = "linux"))]
pub async fn batch_add_set_elements(
    _family: u8,
    _table: &str,
    _set: &str,
    _elements: &[AddElem<'_>],
    _excl: bool,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "nfnetlink operations require Linux; this binary was compiled on a non-Linux target",
    ))
}

#[cfg(not(target_os = "linux"))]
pub async fn set_contains_ip_async(
    _family: u8,
    _table: &str,
    _set: &str,
    _ip_bytes: &[u8],
) -> io::Result<bool> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "nfnetlink set membership check is only supported on Linux",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(b: &[u8]) -> Vec<u8> { b.to_vec() }
    fn single(bytes: &[u8], timeout: Option<u64>, exp: Option<u64>) -> Elem {
        Elem {
            key: bytes.to_vec(),
            is_end: false,
            key_end: Vec::new(),
            timeout_ms: timeout,
            expiration_ms: exp,
        }
    }
    fn end(bytes: &[u8]) -> Elem {
        Elem {
            key: bytes.to_vec(),
            is_end: true,
            key_end: Vec::new(),
            timeout_ms: None,
            expiration_ms: None,
        }
    }

    /// Port of the bug report: an interval set containing a single IP that
    /// was dumped back out by the kernel as a start/end pair with an extra
    /// "tidy end marker" interleaved at the boundary. Without sorting AND
    /// without decrementing the exclusive end, reduce_intervals used to
    /// pair the wrong elements and emit `1.2.3.4-1.1.1.2`.
    #[test]
    fn interval_set_with_single_ips_yields_single_addresses() {
        // Simulating the kernel-ordered dump:
        //   [194] 1.2.3.5 end / [195] 1.2.3.4 start(1h timeout) /
        //   [196] 1.1.1.2 end / [197] 1.1.1.1 start /
        //   [198] 0.0.0.0 end (the leading "0/0" tidy marker)
        let raw = vec![
            end(&[1, 2, 3, 5]),
            single(&[1, 2, 3, 4], Some(3_600_000), Some(3_546_490)),
            end(&[1, 1, 1, 2]),
            single(&[1, 1, 1, 1], None, None),
            end(&[0, 0, 0, 0]),
        ];
        let out = reduce_intervals(raw, true);
        assert_eq!(out.len(), 2);
        // 1.1.1.1: low==high so key_end == low (after decrement of 1.1.1.2)
        assert_eq!(&out[0].key, &k(&[1, 1, 1, 1]));
        assert_eq!(&out[0].key_end, &k(&[1, 1, 1, 1]));
        assert_eq!(out[0].timeout_ms, None);
        assert_eq!(out[0].expiration_ms, None);
        // 1.2.3.4: similar, with the timeout carried from start.
        assert_eq!(&out[1].key, &k(&[1, 2, 3, 4]));
        assert_eq!(&out[1].key_end, &k(&[1, 2, 3, 4]));
        assert_eq!(out[1].timeout_ms, Some(3_600_000));
        assert_eq!(out[1].expiration_ms, Some(3_546_490));
    }

    /// A real CIDRlike interval set (`192.168.0.0/24`) reduces to a single
    /// start/end pair with the (exclusive) end at `192.168.1.0`.
    #[test]
    fn interval_set_cidr_24_pairs_to_single_element() {
        let raw = vec![
            single(&[192, 168, 0, 0], None, Some(5_000_000)),
            end(&[192, 168, 1, 0]),    // kernel half-open end: 192.168.1.0
        ];
        let out = reduce_intervals(raw, true);
        assert_eq!(out.len(), 1);
        assert_eq!(&out[0].key, &k(&[192, 168, 0, 0]));
        assert_eq!(&out[0].key_end, &k(&[192, 168, 0, 255])); // end-1
    }

    /// A plain non-interval set must NOT pair anything.
    #[test]
    fn plain_set_short_circuits_pairing() {
        let raw = vec![
            single(&[1, 2, 3, 4], Some(3_600_000), Some(3_000_000)),
            single(&[5, 6, 7, 8], None, None),
        ];
        let out = reduce_intervals(raw, false);
        assert_eq!(out.len(), 2);
        assert!(out[0].key_end.is_empty());
        assert!(out[1].key_end.is_empty());
    }

    #[test]
    fn decrement_be_handles_borrow() {
        let mut b = vec![0u8, 0, 5];
        assert!(decrement_be(&mut b).is_some());
        assert_eq!(b, vec![0u8, 0, 4]);
        let mut c = vec![1u8, 0, 0];
        assert!(decrement_be(&mut c).is_some());
        assert_eq!(c, vec![0u8, 0xff, 0xff]);
    }

    #[test]
    fn decrement_be_underflow_returns_none() {
        let mut d = vec![0u8; 4];
        assert!(decrement_be(&mut d).is_none());
        // On underflow the buffer is unchanged (all zeros).
        assert_eq!(d, vec![0u8, 0, 0, 0]);
        // Single zero byte also underflows.
        let mut e = vec![0u8];
        assert!(decrement_be(&mut e).is_none());
    }

    #[test]
    fn decrement_be_empty_returns_none() {
        let mut empty: Vec<u8> = vec![];
        assert!(decrement_be(&mut empty).is_none());
    }

    #[test]
    fn set_contains_ip_non_interval_exact_match() {
        let elems = vec![
            single(&[192, 168, 1, 1], None, None),
            single(&[10, 0, 0, 1], None, None),
        ];
        assert!(set_contains_ip(&elems, false, &[192, 168, 1, 1]));
        assert!(set_contains_ip(&elems, false, &[10, 0, 0, 1]));
        assert!(!set_contains_ip(&elems, false, &[192, 168, 1, 2]));
        assert!(!set_contains_ip(&elems, false, &[10, 0, 0, 0]));
    }

    #[test]
    fn set_contains_ip_interval_range() {
        // Interval set: 10.0.0.0/24 as a raw start/end pair.
        let raw = vec![
            single(&[10, 0, 0, 0], None, None),
            end(&[10, 0, 1, 0]),    // exclusive end = 10.0.1.0
        ];
        assert!(set_contains_ip(&raw, true, &[10, 0, 0, 0]));   // network
        assert!(set_contains_ip(&raw, true, &[10, 0, 0, 1]));   // inside
        assert!(set_contains_ip(&raw, true, &[10, 0, 0, 255])); // broadcast
        assert!(!set_contains_ip(&raw, true, &[10, 0, 1, 0]));  // exclusive end
        assert!(!set_contains_ip(&raw, true, &[10, 0, 1, 1]));  // outside
        assert!(!set_contains_ip(&raw, true, &[9, 255, 255, 255])); // below
    }

    #[test]
    fn set_contains_ip_interval_single_address() {
        // Single address in an interval set: start == end.
        let raw = vec![
            single(&[1, 2, 3, 4], None, None),
            end(&[1, 2, 3, 5]),     // exclusive end = 1.2.3.5
        ];
        assert!(set_contains_ip(&raw, true, &[1, 2, 3, 4]));
        assert!(!set_contains_ip(&raw, true, &[1, 2, 3, 5]));
        assert!(!set_contains_ip(&raw, true, &[1, 2, 3, 3]));
    }

    #[test]
    fn set_contains_ip_interval_with_orphan_end() {
        // Orphan end marker at the front (e.g. the 0.0.0.0 tidy marker)
        // must be ignored; the only real element is 10.0.0.0/24.
        let raw = vec![
            end(&[0, 0, 0, 0]),
            single(&[10, 0, 0, 0], None, None),
            end(&[10, 0, 1, 0]),
        ];
        assert!(set_contains_ip(&raw, true, &[10, 0, 0, 1]));
        assert!(set_contains_ip(&raw, true, &[10, 0, 0, 255]));
        assert!(!set_contains_ip(&raw, true, &[0, 0, 0, 0]));
        assert!(!set_contains_ip(&raw, true, &[10, 0, 1, 0]));
    }

    #[test]
    fn set_contains_ip_interval_key_end_form() {
        // Element with KEY + KEY_END (single-element form).
        // The kernel stores `key_end` as the **exclusive** upper bound,
        // so for a 192.168.0.0/24 range the exclusive end is 192.168.1.0.
        let raw = vec![
            Elem {
                key: vec![192, 168, 0, 0],
                is_end: false,
                key_end: vec![192, 168, 1, 0],  // exclusive upper bound
                timeout_ms: None,
                expiration_ms: None,
            },
        ];
        assert!(set_contains_ip(&raw, true, &[192, 168, 0, 0]));
        assert!(set_contains_ip(&raw, true, &[192, 168, 0, 100]));
        assert!(set_contains_ip(&raw, true, &[192, 168, 0, 255]));
        assert!(!set_contains_ip(&raw, true, &[192, 168, 1, 0]));
        assert!(!set_contains_ip(&raw, true, &[192, 168, 1, 1]));
    }

    /// Reproduce the reported bug: 3.5.64.0/18 showing as bare "3.5.64.0"
    /// because NFTA_SET_ELEM_KEY_END constant was wrong (10 instead of 9).
    /// Both the start/end-marker pair form and the single-element KEY_END
    /// form must produce a paired Elem with key_end = 3.5.127.255.
    #[test]
    fn interval_set_3_5_64_0_18_properly_paired() {
        // ── Boundary-pair form ──
        let raw = vec![
            single(&[3, 5, 64, 0], None, None),
            end(&[3, 5, 128, 0]),   // exclusive end
        ];
        let out = reduce_intervals(raw, true);
        assert_eq!(out.len(), 1, "expected 1 paired element");
        assert_eq!(&out[0].key, &k(&[3, 5, 64, 0]));
        assert_eq!(&out[0].key_end, &k(&[3, 5, 127, 255]));

        // ── Single-element KEY_END form ──
        let raw = vec![
            Elem {
                key: vec![3, 5, 64, 0],
                is_end: false,
                key_end: vec![3, 5, 128, 0],
                timeout_ms: None,
                expiration_ms: None,
            },
        ];
        let out = reduce_intervals(raw, true);
        assert_eq!(out.len(), 1, "expected 1 paired element from KEY_END form");
        assert_eq!(&out[0].key, &k(&[3, 5, 64, 0]));
        assert_eq!(&out[0].key_end, &k(&[3, 5, 127, 255]));
    }

    #[test]
    fn increment_be_works_correctly() {
        let mut b = vec![0u8; 4];
        assert!(increment_be(&mut b).is_some());
        assert_eq!(b, vec![0, 0, 0, 1]);

        let mut all_ff = vec![0xffu8; 4];
        assert!(increment_be(&mut all_ff).is_none());
        // On overflow the buffer is unchanged.
        assert_eq!(all_ff, vec![0xff, 0xff, 0xff, 0xff]);

        let mut carry = vec![0u8, 0, 0xff];
        assert!(increment_be(&mut carry).is_some());
        assert_eq!(carry, vec![0, 1, 0]);
    }
}