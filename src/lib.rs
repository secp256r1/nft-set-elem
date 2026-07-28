//! Low-level Rust library for managing nftables set elements over nfnetlink,
//! without libnftnl or libmnl.
//!
//! # Overview
//!
//! `nft-set-elem` speaks the nfnetlink / nftables wire protocol directly.
//! There is no `netlink-packet-nftables` crate in the ecosystem, so all TLV
//! attribute building and parsing (`NFTA_*` constants, nested NLA_F_NESTED
//! attributes) is done manually in [`nl`].
//!
//! The crate is used inside nftables itself when looking at
//! `libnftnl/src/set_elem.c`, `nftables/src/segtree.c` and
//! `nftables/src/netlink.c`.
//!
//! # Architecture
//!
//! Two modules:
//!
//! | Module | Contents | Platform |
//! |---|---|---|
//! | [`nl`] | nfnetlink socket I/O, message building/parsing, set‑element CRUD | Linux-only async |
//! | [`fmt`] | Element formatting, CIDR recovery, duration parsing, IP address parsing | All platforms |
//!
//! Most users will call the async functions in [`nl`]:
//!
//! - [`nl::dump_set_elements`] — fetch all elements of an nftables set
//! - [`nl::dump_set_flags`] — fetch `NFTA_SET_FLAGS` (to detect interval sets)
//! - [`nl::add_set_element`] — add a single element
//! - [`nl::delete_set_element`] — delete a single element
//! - [`nl::batch_add_and_delete_set_element`] — atomically replace one element
//!   with another in a single nfnetlink batch transaction
//!
//! Two pure-logic helpers (no I/O, available everywhere):
//!
//! - [`nl::reduce_intervals`] — pair raw start/end elements into human‑friendly
//!   CIDR or range representations (same algorithm as nftables' `seg_tree.c`)
//! - [`nl::set_contains_ip`] — check whether an IP falls within a set's elements
//!   (interval‑aware)
//!
//! For formatting and auxiliary parsing:
//!
//! - [`fmt::format_element`] — render an [`Elem`](nl::Elem) as a string
//! - [`fmt::parse_element`] — parse `"192.168.1.1"` or `"10.0.0.0/24"` into
//!   raw key bytes
//! - [`fmt::parse_duration`] / [`fmt::format_duration`] — convert between
//!   human‑readable durations (`"30s"`, `"1h30m"`) and milliseconds
//!
//! # Platform support
//!
//! The nfnetlink socket I/O is **Linux-only** behind `#[cfg(target_os = "linux")]`.
//! Non-Linux stubs return [`io::ErrorKind::Unsupported`] for every async function
//! so the crate builds and tests on macOS / Windows during development.
//!
//! Pure-logic helpers ([`nl::reduce_intervals`], [`nl::set_contains_ip`],
//! and everything in [`fmt`]) are available on **all platforms**.
//!
//! # Dependencies
//!
//! | Crate | Required by | Notes |
//! |---|---|---|
//! | `tokio` | [`nl`] async functions | `features = ["rt", "time", "macros"]` sufficient |
//! | `netlink-sys` | [`nl`] socket I/O | Only on Linux; `features = ["tokio_socket"]` |
//! | `bytes` | [`nl`] socket receive buffer | Only on Linux; re-exported as [`nl::BytesMut`] if needed |
//!
//! # Quick start
//!
//! ```toml
//! [dependencies]
//! nft-set-elem = "0.1"
//! tokio = { version = "1", features = ["rt", "macros"] }
//! ```
//!
//! ```rust,no_run
//! use nft_set_elem::{fmt, nl};
//!
//! #[tokio::main(flavor = "current_thread")]
//! async fn main() -> std::io::Result<()> {
//!     // 1. Detect whether the set is an interval set.
//!     let flags = nl::dump_set_flags(2, "filter", "my_set").await?;
//!     let is_interval = (flags & nl::NFT_SET_INTERVAL) != 0;
//!
//!     // 2. Fetch all elements.
//!     let elems = nl::dump_set_elements(2, "filter", "my_set").await?;
//!
//!     // 3. Reduce to human-friendly ranges.
//!     let reduced = nl::reduce_intervals(elems, is_interval);
//!     for e in &reduced {
//!         println!("{}", fmt::format_element(e));
//!     }
//!
//!     // 4. Check membership.
//!     let ip = [10, 0, 0, 1];
//!     if nl::set_contains_ip(&reduced, false, &ip) {
//!         println!("10.0.0.1 is in the set");
//!     }
//!
//!     // 5. Add an element.
//!     nl::add_set_element(2, "filter", "my_set", &ip, None, None, false).await?;
//!
//!     // 6. Delete an element.
//!     nl::delete_set_element(2, "filter", "my_set", &ip, None).await?;
//!
//!     // 7. Atomically replace one element with another.
//!     nl::batch_add_and_delete_set_element(
//!         2, "filter", "my_set",
//!         &[10, 0, 0, 1], None,   // delete
//!         &[10, 0, 0, 2], None,   // add
//!         None, false,
//!     )
//!     .await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! # Safety
//!
//! This crate uses **no `unsafe`** — neither in the manual TLV serializer
//! nor in the netlink socket code (the underlying `netlink-sys` / tokio stack
//! is safe Rust on the caller's side).
//!
//! # Comparison with other approaches
//!
//! | Approach | Dependency weight | Control | Notes |
//! |---|---|---|---|
//! | **This crate** (`nft-set-elem`) | `netlink-sys` + `bytes` + `tokio` | Full | Manual TLV building; no libmnl/libnftnl |
//! | `nftables` CLI via `std::process::Command` | None | None (string‑based) | Slow fork‑per‑operation |
//! | Python `pyroute2` / `nftables` lib | Python runtime | Medium | Not usable from Rust |
//! | Raw `libc` netlink FFI | `libc` only | Full | Unsafe, no async, macOS stubs must be written by hand |

pub mod fmt;
pub mod nl;