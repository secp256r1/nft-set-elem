# nft-set-elem

Manage nftables set elements over nfnetlink — **no libmnl / libnftnl binding**,
no shell-out to `nft`.

This crate talks the nfnetlink/nftables wire protocol directly. It rebuils just
enough of `libnftnl/src/set_elem.c` and `nftables/src/segtree.c` to list,
add, delete, and atomically replace set elements without any C dependency.

## Library

Add to your `Cargo.toml`:

```toml
[dependencies]
nft-set-elem = "0.1"
tokio = { version = "1", features = ["rt", "macros"] }
```

```rust
use nft_set_elem::{fmt, nl};

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::io::Result<()> {
    let elems = nl::dump_set_elements(2, "filter", "my_set").await?;
    for e in nl::reduce_intervals(elems, false) {
        println!("{}", fmt::format_element(&e));
    }
    Ok(())
}
```

### Public API

| Function | Description |
|---|---|
| `nl::dump_set_elements` | Fetch all elements of an nftables set |
| `nl::dump_set_flags` | Fetch `NFTA_SET_FLAGS` (to detect interval sets) |
| `nl::add_set_element` | Add a single element (IP or CIDR) |
| `nl::delete_set_element` | Delete a single element |
| `nl::batch_add_and_delete_set_element` | Atomically replace one element with another |
| `nl::reduce_intervals` | Pair raw start/end elements → CIDR or range output |
| `nl::set_contains_ip` | Check whether an IP falls within a set's elements |
| `fmt::format_element` | Render an element as a string |
| `fmt::parse_element` | Parse `"192.168.1.1"` or `"10.0.0.0/24"` into raw key bytes |
| `fmt::parse_duration` / `fmt::format_duration` | Convert between human-readable durations and ms |

Full docs: `cargo doc --open --no-deps`

## CLI — `nftse`

```text
Usage: nftse <COMMAND>

Commands:
  list     List elements of an nftables set
  add      Add an element (IP or CIDR) to an nftables set
  delete   Delete an element from an nftables set
  replace  Atomically delete one element and add another in a single batch
  help     Print this message or the help of the given subcommand(s)
```

Also accepts the shorthand `nftse <family> <table> <set>` (no subcommand) as
equivalent to `nftse list <family> <table> <set>`.

### Examples

```sh
# List elements
sudo nftse list ip filter my_set

# Shorthand (backward compat)
sudo nftse ip filter my_set

# Add a single address
sudo nftse add ip filter my_set 192.168.1.1

# Add a CIDR range with timeout
sudo nftse add ip filter my_set 10.0.0.0/24 --timeout 1h

# Delete
sudo nftse delete ip filter my_set 192.168.1.1

# Atomically replace (single batch transaction)
sudo nftse replace ip filter my_set 192.168.1.1 10.0.0.1 --timeout 30m
```

Element dump and mutations require **root** or `CAP_NET_ADMIN`.

## Build

```sh
# Native Linux
cargo build --release
./target/release/nftse --help

# Cross-compile for aarch64 Linux musl (needs Docker + cross)
cross build --release --target aarch64-unknown-linux-musl

# macOS / development — library builds fine, async stubs return Err(Unsupported)
cargo test
```

## Platform support

The nfnetlink socket I/O is **Linux-only**. On other platforms all async
functions return `Err(io::ErrorKind::Unsupported)`, so the crate compiles
and tests on macOS / Windows during development. Pure-logic helpers
(`reduce_intervals`, `set_contains_ip`, `fmt::*`) are available everywhere.

## How it works

| Step | Source analogue |
|------|-----------------|
| Open socket | `libmnl/src/socket.c::mnl_socket_open` — we use `netlink-sys::TokioSocket` (async, tokio backend) |
| Build request | `libnftnl/src/set_elem.c::nftnl_set_elems_nlmsg_build_payload` — manual `NFTA_*` TLV serialization with nested `NLA_F_NESTED` attributes |
| Recv loop | `libnftnl/examples/nft-set-elem-get.c` — multipart `NLMSG_DONE` with ACK/error handling, driven by `tokio::time::timeout` |
| Parse element | `libnftnl/src/set_elem.c::nftnl_set_elems_parse2` — unwrap `NFTA_SET_ELEM_LIST_ELEMENTS → NFTA_LIST_ELEM → {KEY, KEY_END, FLAGS, TIMEOUT, EXPIRATION}` |
| Interval reduce | `nftables/src/netlink.c::netlink_delinearize_setelem` (split KEY+KEY_END) + `segtree.c::interval_map_decompose` (pair start/end) + `interval_to_prefix` (try CIDR) |
| CIDR check | `nftables/src/segtree.c::range_is_prefix` — `(diff & (diff+1)) == 0` and alignment `low & host_mask == 0` |
| Duration format | `nftables/src/datatype.c::time_print` — `d/h/m/s/ms` highest-unit-first, `0s` for zero |

## Layout

```
src/
├── lib.rs               # Crate root — re-exports the public API for library consumers
├── nl.rs                # Netlink wire types, message builder, recv loop, element CRUD, interval reduction
├── fmt.rs               # Element formatting, CIDR recovery, duration & address parsing
└── bin/
    └── nft-set-elem.rs  # CLI entry point (uses clap for argument parsing)
```

## Dependencies

| Crate | Scope | Notes |
|---|---|---|
| `tokio` | All platforms | Async runtime (current_thread), `timeout` for recv |
| `clap` | Binary only | Argument parsing (derive) |
| `netlink-sys` | Linux only | `TokioSocket` with `tokio_socket` feature |
| `bytes` | Linux only | `BytesMut` for socket receive buffer |

## License

MIT.