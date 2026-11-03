# gamespy-rs

## Scope and purpose

`gamespy-rs` provides embeddable Rust libraries for implementing GameSpy-compatible services. It supports applications that need to interpret GameSpy protocol traffic and serve compatible clients. Compatibility is limited to the supported protocol layouts; it is not a claim of support for every game or GameSpy SDK version.

## Legal disclaimer

This is an independent project, not an official GameSpy product. It is not affiliated with or endorsed by GameSpy or the owners of games that use GameSpy services. Third-party names and trademarks belong to their respective owners and are used only to identify compatibility.

The source is distributed under the [MIT License](LICENSE), with the original copyright notice preserved. The software is provided "as is", without warranty, subject to the license's disclaimer of liability. This license does not grant rights to third-party games, assets, services, or trademarks.

## Public interfaces and DNS

The public service interfaces are closely tied to the DNS records and service hostnames used by clients. Correct integration requires those names to resolve to the intended service endpoints. DNS configuration remains the caller's responsibility; the libraries do not manage DNS records or client resolver settings.

Before using the public APIs, callers should read the [DNS overrides and service endpoints specification](crates/gamespy-runtime/src/lib.rs) and the relevant API documentation. These describe hostname mappings, transports, ports, endpoint relationships, and caller responsibilities. DNS resolution alone does not configure service ports, HTTP host handling, or TLS requirements.
