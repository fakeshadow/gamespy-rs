//! Serve NAT negotiation protocol version 3, and version 3 and 4 together.
//!
//! Every value below is a placeholder. Fill in the bind address and the title
//! names your deployment serves; see `docs/natneg-versions.md` for what each
//! policy decides and why none of it is derived from the version byte.
//!
//! Run with `cargo run -p gamespy-runtime --example natneg_v3`.

use std::net::UdpSocket;
use std::time::Duration;

use gamespy_runtime::natneg::{self, Policy};
use gamespy_runtime::observe::Observer;

/// Placeholders. The SDK resolves `{game}.natneg1.gamespy.com` through
/// `natneg3` on UDP 27901 and probes all three; point every one of those names
/// at this process and bind all three ports to one registry, so a peer whose
/// NAT maps each socket separately is observed rather than guessed at.
const BIND: &str = "0.0.0.0:27901";
const TITLES: [&str; 1] = ["placeholdertitle"];

/// Diagnostics go wherever the embedding application wants them. This one
/// prints; a real deployment would route these into its own log.
struct Printer;

impl Observer for Printer {
    fn event(&self, service: &str, message: &str) {
        println!("[{service}] {message}");
    }
    fn peer_event(&self, service: &str, peer: std::net::SocketAddr, message: &str) {
        println!("[{service}] {peer}: {message}");
    }
}

fn main() -> Result<(), String> {
    let socket = UdpSocket::bind(BIND).map_err(|error| format!("bind {BIND}: {error}"))?;

    // Version 3 only, with the reply shapes, readiness rule, control endpoint,
    // rebinding rule, partner timeout and capacity bound a version 3
    // deployment established. `.accepting(natneg::BOTH_VERSIONS)` below is the
    // one change needed to serve version 4 on the same socket and registry.
    let policy = Policy::v3_compatible()
        .with_titles(TITLES.iter().map(|title| (*title).to_owned()).collect())
        // Tell a peer whose partner never announced the cookie, instead of
        // leaving it to burn the SDK's own 60-second PARTNER_WAIT_TIME. Sent
        // once: the client does not acknowledge a failure CONNECT.
        .with_partner_wait(Some(Duration::from_secs(30)));

    // Both generations on one listener, each negotiation kept in its own
    // version. This does *not* make a mixed-version pair playable: two peers
    // that announce one cookie in different versions are not introduced unless
    // `pair_across_versions` is set, which this project has no evidence for.
    let both = Policy {
        pair_across_versions: false,
        ..policy.clone().accepting(natneg::BOTH_VERSIONS)
    };
    let _ = &both;

    // Dropping the handle requests shutdown and joins the thread, so it has to
    // outlive the service.
    let listener = natneg::spawn_with_policy(socket, Printer, policy)?;

    println!("serving version 3 negotiation on {BIND}; press ctrl-c to stop");
    // A real application would park here on its own shutdown signal. This one
    // runs for a moment so the example terminates.
    std::thread::sleep(Duration::from_secs(1));

    listener
        .shutdown()
        .map_err(|_| "listener panicked".to_owned())
}
