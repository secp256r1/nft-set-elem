//! nftse — CLI for nftables set element operations over nfnetlink.
//!
//! The underlying nfnetlink logic lives in the `nft_set_elem` library crate.
//!
//! Usage:
//!     nftse list <family> <table> <set>
//!     nftse add <family> <table> <set> <element> [--timeout <dur>]
//!     nftse delete <family> <table> <set> <element>
//!     nftse replace <family> <table> <set> <del_elem> <add_elem> [--timeout <dur>]
//!
//! Shorthand (backward compat):
//!     nftse <family> <table> <set>    ≡  nftse list <family> <table> <set>

use clap::{Parser, Subcommand};
use nft_set_elem::{fmt, nl};
use std::process::ExitCode;

// ---------------------------------------------------------------------------
// clap — argument parsing
// ---------------------------------------------------------------------------

/// Manage nftables set elements over nfnetlink
#[derive(Parser)]
#[command(name = "nftse", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List elements of an nftables set
    #[command(alias = "ls")]
    List {
        /// Address family (ip, ip6, inet, bridge, arp, netdev)
        #[arg(value_parser = parse_family)]
        family: u8,
        /// Table name
        table: String,
        /// Set name
        set: String,
    },
    /// Add an element (IP or CIDR) to an nftables set
    Add {
        #[arg(value_parser = parse_family)]
        family: u8,
        table: String,
        set: String,
        element: String,
        /// Element timeout (e.g. 30s, 5m, 1h30m, 250ms)
        #[arg(short = 't', long, value_parser = parse_duration)]
        timeout: Option<u64>,
    },
    /// Delete an element from an nftables set
    #[command(alias = "del")]
    Delete {
        #[arg(value_parser = parse_family)]
        family: u8,
        table: String,
        set: String,
        element: String,
    },
    /// Atomically delete one element and add another in a single batch
    #[command(alias = "repl")]
    Replace {
        #[arg(value_parser = parse_family)]
        family: u8,
        table: String,
        set: String,
        /// Element to delete
        del_elem: String,
        /// Element to add
        add_elem: String,
        /// Element timeout for the new element (e.g. 30s, 5m, 1h30m)
        #[arg(short = 't', long, value_parser = parse_duration)]
        timeout: Option<u64>,
    },
}

fn parse_family(s: &str) -> Result<u8, String> {
    match s {
        "ip"     => Ok(2),   // NFPROTO_IPV4
        "ip6"    => Ok(10),  // NFPROTO_IPV6
        "inet"   => Ok(1),   // NFPROTO_INET
        "bridge" => Ok(7),   // NFPROTO_BRIDGE
        "arp"    => Ok(3),   // NFPROTO_ARP
        "netdev" => Ok(5),   // NFPROTO_NETDEV
        _ => Err(format!(
            "unknown family '{s}' (try: ip, ip6, inet, bridge, arp, netdev)"
        )),
    }
}

fn is_family(s: &str) -> bool {
    matches!(s, "ip" | "ip6" | "inet" | "bridge" | "arp" | "netdev")
}

fn parse_duration(s: &str) -> Result<u64, String> {
    fmt::parse_duration(s).ok_or_else(|| {
        format!("cannot parse duration '{s}' (expected format like 30s, 5m, 1h30m, 250ms)")
    })
}

fn parse_element(s: &str) -> Result<(Vec<u8>, Option<Vec<u8>>), String> {
    fmt::parse_element(s).ok_or_else(|| format!("cannot parse element '{s}'"))
}

// ---------------------------------------------------------------------------
// command implementations
// ---------------------------------------------------------------------------

async fn cmd_list(family: u8, table: &str, set: &str) -> ExitCode {
    let is_interval = match nl::dump_set_flags(family, table, set).await {
        Ok(f) => (f & nl::NFT_SET_INTERVAL) != 0,
        Err(e) => {
            eprintln!("warning: NFT_MSG_GETSET failed ({e}); assuming interval set");
            true
        }
    };

    let elems = match nl::dump_set_elements(family, table, set).await {
        Ok(e) => e,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };

    let reduced = nl::reduce_intervals(elems, is_interval);
    if reduced.is_empty() {
        println!("(set {table}/{set} has no elements)");
        return ExitCode::SUCCESS;
    }
    for e in reduced {
        println!("{}", fmt::format_element(&e));
    }
    ExitCode::SUCCESS
}

async fn cmd_add(family: u8, table: &str, set: &str, element: &str, timeout_ms: Option<u64>) -> ExitCode {
    let (key, key_end) = match parse_element(element) {
        Ok(kv) => kv,
        Err(msg) => {
            eprintln!("error: {msg}");
            return ExitCode::from(2);
        }
    };

    match nl::add_set_element(family, table, set, &key, key_end.as_deref(), timeout_ms, false).await {
        Ok(()) => {
            if let Some(ms) = timeout_ms {
                println!("added {element} to {table}/{set} (timeout {})", fmt::format_duration(ms));
            } else {
                println!("added {element} to {table}/{set}");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error adding element: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn cmd_delete(family: u8, table: &str, set: &str, element: &str) -> ExitCode {
    let (key, key_end) = match parse_element(element) {
        Ok(kv) => kv,
        Err(msg) => {
            eprintln!("error: {msg}");
            return ExitCode::from(2);
        }
    };

    match nl::delete_set_element(family, table, set, &key, key_end.as_deref()).await {
        Ok(()) => {
            println!("deleted {element} from {table}/{set}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error deleting element: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn cmd_replace(
    family: u8,
    table: &str,
    set: &str,
    del_elem: &str,
    add_elem: &str,
    timeout_ms: Option<u64>,
) -> ExitCode {
    let (del_key, del_key_end) = match parse_element(del_elem) {
        Ok(kv) => kv,
        Err(msg) => {
            eprintln!("error: {msg}");
            return ExitCode::from(2);
        }
    };
    let (add_key, add_key_end) = match parse_element(add_elem) {
        Ok(kv) => kv,
        Err(msg) => {
            eprintln!("error: {msg}");
            return ExitCode::from(2);
        }
    };

    match nl::batch_add_and_delete_set_element(
        family, table, set,
        &del_key, del_key_end.as_deref(),
        &add_key, add_key_end.as_deref(),
        timeout_ms, false,
    )
    .await
    {
        Ok(()) => {
            if let Some(ms) = timeout_ms {
                println!(
                    "replaced {del_elem} → {add_elem} in {table}/{set} (timeout {})",
                    fmt::format_duration(ms),
                );
            } else {
                println!("replaced {del_elem} → {add_elem} in {table}/{set}");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error replacing element: {e}");
            ExitCode::FAILURE
        }
    }
}

// ---------------------------------------------------------------------------
// entry point
// ---------------------------------------------------------------------------

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    // Backward compat: nftse <family> <table> <set>  →  nftse list <family> <table> <set>
    let args: Vec<String> = {
        let raw: Vec<String> = std::env::args().collect();
        if raw.len() == 4 && raw.get(1).is_some_and(|s| is_family(s)) {
            vec![
                raw[0].clone(),
                "list".into(),
                raw[1].clone(),
                raw[2].clone(),
                raw[3].clone(),
            ]
        } else {
            raw
        }
    };

    let cli = Cli::parse_from(args);

    match cli.command {
        Command::List { family, table, set } => cmd_list(family, &table, &set).await,
        Command::Add { family, table, set, element, timeout } => {
            cmd_add(family, &table, &set, &element, timeout).await
        }
        Command::Delete { family, table, set, element } => cmd_delete(family, &table, &set, &element).await,
        Command::Replace { family, table, set, del_elem, add_elem, timeout } => {
            cmd_replace(family, &table, &set, &del_elem, &add_elem, timeout).await
        }
    }
}