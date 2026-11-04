//! Embeddable GameSpy services. Each listener owns independent transient state.
//! Applications supply bound sockets, policy backends and logging; no storage or TLS dependency.
//!
//! # DNS overrides and service endpoints
//!
//! Availability, browser, GP and NAT also expose `spawn_multi_with_*` entry
//! points on these same transports. They select per-title backends from protocol
//! fields or validated tokens. Browser/GP follow-ups retain the selected backend;
//! QR2 requires a live source socket/instance binding; NAT separates named INIT
//! cookies by title. The caller supplies independent backends and title configs.
//! Unknown or ambiguous selectors are refused, not mapped to a default title.
//!
//! This crate handles traffic after it reaches an application-supplied socket.
//! It does not resolve client service names, configure DNS, edit hosts files, or
//! bind service ports. Configure the client's resolver to map its service names
//! to your reachable server IP, then bind the corresponding transports below.
//! DNS changes the destination IP, not the port, HTTP `Host`, or TLS server name.
//!
//! These are defaults from the pinned GameSpy SDK below, not names enforced by
//! this crate or a title-specific endpoint list. SDK builds can replace
//! `GSI_DOMAIN_NAME`, and client endpoint overrides can replace composed names.
//! `{game}` means the client's middleware game name, not its display title;
//! `{shard}` is the result of [`gamespy_proto::title::master_server_index`]
//! for the browser's query game. Concrete title names and client overrides
//! belong in the embedding application's private deployment configuration.
//!
//! | Service | SDK hostname pattern | Transport / conventional port | Runtime entry point |
//! | --- | --- | --- | --- |
//! | Availability | `{game}.available.gamespy.com` | UDP 27900 | [`availability::spawn_with_socket`] |
//! | QR2 registration | `{game}.master.gamespy.com` | UDP 27900 | [`availability::spawn_with_socket`] / [`qr2::handle`] |
//! | Browser list | `{game}.ms{shard}.gamespy.com` | TCP 28910 | [`browser::spawn_with_listener`] |
//! | GP presence | `gpcm.gamespy.com` | TCP 29900 | [`gp::spawn_with_listener`] |
//! | NAT negotiation | `{game}.natneg1.gamespy.com`, `{game}.natneg2.gamespy.com`, `{game}.natneg3.gamespy.com` | UDP 27901 | [`natneg::spawn_with_sockets`], or [`natneg::spawn_with_socket`] for one port |
//! | AuthService | `{game}.auth.pubsvs.gamespy.com` | HTTPS / TCP 443 | `auth::handle_request` (`soap` feature), application-owned TLS |
//! | SAKE storage and file downloads | `{game}.sake.gamespy.com` | HTTP / TCP 80 | `sake::serve_connection` (`soap` feature) / [`sake_file::handle_download`] |
//!
//! Port constants are available in [`gamespy_proto::ports`]; the supplied socket
//! determines the actual listening port. Availability and QR2 can share one UDP
//! socket. Multiple DNS names can reach one listener; UDP/TCP sockets do not
//! expose which DNS name the client resolved. HTTP parsing preserves `Host`,
//! but host-based routing and validation remain application policy. HTTPS also
//! requires a TLS configuration and certificate acceptable to the client.
//!
//! The referenced NAT SDK composes the title prefix before resolving its three
//! default labels (`natneg1.gamespy.com` through `natneg3.gamespy.com`). Explicit
//! client hostname overrides bypass that composition. Check the client's actual
//! queries before selecting bare or prefixed names; do not assume all SDK
//! versions and titles use the same names. If all three names reach this NAT
//! implementation, route them to the same listener so they share cookie state.
//!
//! Redirect only services you implement. GP presence does not implement GPSP
//! search, and SAKE file delivery does not implement a separate MOTD service.
//! SOAP namespace URIs are protocol identifiers, not additional DNS targets.
//! Verify resolution using the client's resolver and clear its cached results
//! before checking incoming service traffic.
//!
//! ## Public interface coverage
//!
//! The service entry points above cover every service implemented here.
//! Supporting types, constants and helpers follow their module's endpoint role:
//!
//! | Public interfaces | Endpoint relationship |
//! | --- | --- |
//! | [`availability::answer`] | Availability packet helper; no socket or DNS ownership. |
//! | [`browser::Config`], [`browser::Relay`], browser request/reply helpers | The browser endpoint above; helpers do not open connections. [`browser::Relay`] clones the application's QR2 socket so a relayed client message reaches a host from the address it heartbeats to. |
//! | [`gp::Config`], GP backend/login/message helpers and result types | The GP presence endpoint above; token resolution is not DNS resolution. |
//! | AuthService callbacks/result types (`soap`) | Request handling behind the application's authentication transport. |
//! | SAKE backend/diagnostics (`soap`), [`sake_file::File`] | Storage and downloads share the SAKE endpoint; no separate news hostname is required by these APIs. |
//! | [`http`] readers and SOAP serving | Generic framing on supplied streams; no default hostname, listener or TLS implementation. |
//! | [`tcp::Connection`], [`tcp::ShutdownConfig`], TCP spawn functions | Generic transport; no service hostname or default port. |
//! | [`listener::Listener`], [`listener::StopSignal`] | Lifecycle controls for existing listeners, not additional endpoints. |
//! | [`discovery`], [`registry`] | Registration/discovery state and policy; stored host addresses identify game hosts, not DNS service names. |
//! | [`session`] | Account/token/ticket state; no network endpoint. |
//! | [`observe`] | Diagnostics and byte-formatting helpers; service labels are not DNS names. |
//!
//! Game-host query/gameplay addresses advertised by browser and QR2 data are
//! separate from these backend service names. In particular,
//! [`discovery::Backend::query_port`] does not bind another backend listener.
//! `gamespy-proto` also exposes Competition codecs, but this runtime does not
//! implement a Competition listener; codecs alone do not establish an endpoint.
//!
//! ## Public source provenance
//!
//! The patterns above can be read independently of game files in the public
//! [GameSpy SDK source mirror](https://github.com/nitrocaster/GameSpy/tree/d1deb2d1a951cf77933dda040b8d311cc09815a7/src/GameSpy):
//! [default domain](https://github.com/nitrocaster/GameSpy/blob/d1deb2d1a951cf77933dda040b8d311cc09815a7/src/GameSpy/common/gsPlatform.h),
//! [availability](https://github.com/nitrocaster/GameSpy/blob/d1deb2d1a951cf77933dda040b8d311cc09815a7/src/GameSpy/common/gsAvailable.c),
//! [QR2](https://github.com/nitrocaster/GameSpy/blob/d1deb2d1a951cf77933dda040b8d311cc09815a7/src/GameSpy/qr2/qr2.c),
//! [browser](https://github.com/nitrocaster/GameSpy/blob/d1deb2d1a951cf77933dda040b8d311cc09815a7/src/GameSpy/serverbrowsing/sb_serverlist.c),
//! [browser port and shard count](https://github.com/nitrocaster/GameSpy/blob/d1deb2d1a951cf77933dda040b8d311cc09815a7/src/GameSpy/serverbrowsing/sb_internal.h),
//! [GP](https://github.com/nitrocaster/GameSpy/blob/d1deb2d1a951cf77933dda040b8d311cc09815a7/src/GameSpy/GP/gpiConnect.c),
//! [NAT labels](https://github.com/nitrocaster/GameSpy/blob/d1deb2d1a951cf77933dda040b8d311cc09815a7/src/GameSpy/natneg/nninternal.h)
//! and [composition](https://github.com/nitrocaster/GameSpy/blob/d1deb2d1a951cf77933dda040b8d311cc09815a7/src/GameSpy/natneg/natneg.c),
//! [AuthService](https://github.com/nitrocaster/GameSpy/blob/d1deb2d1a951cf77933dda040b8d311cc09815a7/src/GameSpy/webservices/AuthService.c),
//! [SAKE storage](https://github.com/nitrocaster/GameSpy/blob/d1deb2d1a951cf77933dda040b8d311cc09815a7/src/GameSpy/sake/sakeRequest.c)
//! and [file URLs](https://github.com/nitrocaster/GameSpy/blob/d1deb2d1a951cf77933dda040b8d311cc09815a7/src/GameSpy/sake/sakeMain.c).
pub mod natneg;
pub mod observe;

#[cfg(feature = "soap")]
pub mod auth;
pub mod availability;
pub mod browser;
pub mod discovery;
pub mod gp;
pub mod http;
pub mod listener;
pub mod qr2;
pub mod registry;
#[cfg(feature = "soap")]
pub mod sake;
pub mod sake_file;
pub mod session;
pub mod tcp;
