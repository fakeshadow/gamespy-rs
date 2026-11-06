# NAT negotiation: protocol versions 3 and 4

This service now serves negotiation protocol version 3 alongside version 4 on
one listener, from one codec and one negotiation engine. This document records
what actually differs between the two, what differs only between two *servers*,
and what a deployment has to choose.

## The short answer

**The version byte carries no layout difference.** Everything else that looked
like a version difference is server policy, and is configured as such.

## Sources

Two, and they are not equivalent:

- The pinned GameSpy SDK at
  [`d1deb2d`](https://github.com/nitrocaster/GameSpy/tree/d1deb2d1a951cf77933dda040b8d311cc09815a7/src/GameSpy/natneg):
  `nninternal.h` for the packet structs and constants, `natneg.c` for the
  client state machine, `natneg.h` for the magic and the result enums. This
  header is `#define NN_PROTVER 3`, with `//#define NN_PROTVER 2` commented out
  above it.
- A reference client binary this project disassembled, which writes `4` at
  offset 6 (`li r4, 4` at `0x00ae27d0`/`0x00ae2800`).

So the SDK source establishes **version 3** behaviour. Version 4's layout is
known from that binary, and it agrees with the version 3 structs field for
field. Neither source establishes universal compatibility with every SDK
generation, which is why version 2 — named but commented out, and never
observed here — is refused rather than guessed at.

## Wire layout

Identical in both versions. From `nninternal.h`, under `#pragma pack(1)`:

| Packet | Macro | Size | Body |
|---|---|---|---|
| header | `BASEPACKET_SIZE` | 12 | 6 magic, version, type, 4 cookie (big-endian) |
| INIT / INIT_ACK / REPORT_ACK | `INITPACKET_SIZE` | 21 | `porttype`, `clientindex`, `usegameport`, `localip`, `localport` |
| CONNECT / CONNECT_PING | `CONNECTPACKET_SIZE` | 20 | `remoteIP`, `remotePort`, `gotyourdata`, `finished` |
| REPORT | `REPORTPACKET_SIZE` | 73 | `porttype`, `clientindex`, `negResult`, `natType` (4), `natMappingScheme` (4), `gamename[50]` |

Both codecs read the same offsets, including the REPORT game name at 23, which
is only where it is because the struct is packed.

## Compatibility matrix

| Aspect | mkvsdcu v3 listener | gamespy-rs before | gamespy-rs now | Kind |
|---|---|---|---|---|
| Magic | 6 bytes, checked | same | same | wire |
| Version byte on receive | must equal 3 | **ignored** | must be in the configured set (`Policy::versions`), else `NatNegError::UnsupportedVersion` with the byte | wire |
| Version byte on send | always 3 | INIT_ACK/REPORT_ACK echoed; CONNECT hardcoded 4 | every reply encoded in the recipient's own version | wire |
| Accepted INIT length | `22..=71` (body plus a 1–50 byte game name) | `>= 12`, with a separate strict 23+ named-INIT parser for title routing | unchanged (both parsers kept) | server policy |
| INIT field validation | `port_type <= 3`, `client <= 1`, `usegameport <= 1` | none; absent fields take their zero meaning | unchanged in the codec; the engine reports a `port_type` above `NN_PT_NN3` as an anomaly | server policy |
| Private address | zero / unspecified / broadcast rejected at parse | passed through as sent, filtered in the engine (`usable_local`, which also rejects loopback and multicast) | unchanged | server policy |
| Title name | required on every INIT | optional; required only on a title-routing listener | unchanged | server policy |
| INIT_ACK | 21 bytes, fields set, body zero | 21 bytes, INIT body echoed | either, via `InitAckShape` | server policy |
| REPORT_ACK | 21 bytes | 73 bytes, report echoed | either, via `ReportAckShape` | server policy |
| CONNECT | 20 bytes, version 3, `finished` 0 or 1 | 20 bytes, version 4, `finished` always 0 | 20 bytes, recipient's version, `Outcome::{Introduced, NoPartner, InitTimedOut, Other}` | wire + policy |
| CONNECT retry | 1 s, 10 attempts, per pair, stopped by either side's ACK | 500 ms, 10 attempts, **per peer**, stopped by that peer's ACK | unchanged (per peer) | server policy |
| Readiness to pair | all three NN registrations, plus GP when `usegameport` | the first INIT | either, via `Readiness` | server policy |
| CONNECT delivered to | the `NN_PT_NN1` mapping | the latest INIT's source | either, via `ControlEndpoint` | server policy |
| Address advertised | GP mapping if `usegameport`, else NN1 | the lowest port type announced | unchanged (equivalent once all registrations are in) | server policy |
| Shared public address | partner's private address | partner's private address, with the reason logged | unchanged | server policy |
| Side identity | client index, with the source IP pinned | client index **and** host | unchanged; a duplicate index across hosts keeps both sides and is reported | server policy |
| Source rebinding | refused | followed, reported as an anomaly | either, via `Rebinding` | server policy |
| Partner timeout | 30 s, then `FINISHED_ERROR_DEADBEAT_PARTNER` once | none; the peer times out on its own | opt-in, via `Policy::partner_wait` | server policy |
| Capacity | 1024 pairs | unbounded | bounded, via `Policy::max_negotiations` (default 4096) | server policy |
| Expiry | 60 s from first INIT | 60 s from the last packet accepted from that side | unchanged | server policy |
| REPORT acknowledged | only from a registered client's control endpoint | always, even for an unknown cookie | unchanged | server policy |
| Mixed-version pairing | n/a (one version) | n/a (no version tracking) | refused unless `Policy::pair_across_versions`, and reported | server policy |

### Why the acknowledgement lengths are interchangeable

Both are correct, and this is checked by tests rather than asserted.

`NNProcessData` routes everything that is not CONNECT or CONNECT_PING through
`if (len < INITPACKET_SIZE) return;` — 21 bytes — and then into
`ProcessInitPacket`. In there:

- the `NN_INITACK` case reads exactly one field, `porttype`, bounds-checks it
  against `NN_PT_NN3`, and marks that source acknowledged;
- the `NN_REPORT_ACK` case reads **no body field at all**: it sets
  `ns_reportack`, fires the title's completed callback with the result the
  console already stored, and cancels the negotiator.

So a 21-byte REPORT_ACK and a 73-byte one are equally effective, and the extra
52 bytes the echo carries are read by nothing. Likewise the INIT_ACK body bytes
past `clientindex`.

### Why the version byte is not load-bearing on receive

`NNProcessData` checks the magic and the length. Nothing in the client's
receive path references `version` or `NN_PROTVER`; the constant appears only in
`SendInitPackets`, `SendConnectAck`, `SendPingPacket` and `SendReportPacket`.
Encoding a reply in the recipient's version is therefore a courtesy that cannot
hurt, not a requirement the wire enforces — and it is the reason nothing else
in this implementation may be decided from the version byte.

### Why a failure CONNECT is sent once and never retried

`ProcessConnectPacket` guards `SendConnectAck` with
`finished == FINISHED_NOERROR`, and treats any other value as a terminal error
it maps to a `NegotiateResult` and reports to the title. So:

- a success CONNECT must carry `finished == 0`, or this service would resend
  an introduction forever waiting for an acknowledgement that never comes;
- a failure CONNECT has no acknowledgement to wait for, so retrying it would
  be an unbounded loop. It is sent once and the cookie is then closed.

`FINISHED_NOERROR` is 0, `FINISHED_ERROR_DEADBEAT_PARTNER` is 1 and
`FINISHED_ERROR_INIT_PACKETS_TIMEDOUT` is 2.

## What a deployment chooses

`Policy::default()` is what this crate has always done, with both versions
accepted and the capacity bound applied. Nothing about an existing version 4
deployment's replies changes shape, and no new packet type appears, because
`partner_wait` defaults to `None`.

`Policy::v3_compatible()` is the mkvsdcu listener's behaviour: version 3 only,
`Readiness::AllRegistrations`, `ControlEndpoint::NegotiationMapping`,
`Rebinding::Pin`, the 21-byte acknowledgement shapes, a 30-second partner wait
and a 1024-negotiation bound.

Serving both on one listener is `Policy::v3_compatible().accepting(BOTH_VERSIONS)`.
That changes only the accepted version set: the policies above stay as they are,
because none of them is derived from the version.

**Serving both versions on one listener does not mean a version 3 console and a
version 4 console can play together.** Each participant's version is retained,
and a cookie announced in two different versions is not paired —
`Policy::pair_across_versions` exists to enable that deliberately, with the
pairing reported as an anomaly either way. This project has no evidence about
mixed-version play, and a listener's capabilities are not evidence about two
titles'.

## Behaviour changes in this release

Two, both in `gamespy-proto`:

1. `natneg::parse` and `parse_named_init*` now refuse a version byte that is
   neither 3 nor 4. They previously parsed any byte. A refusal carries the byte
   and the accepted set.
2. `natneg::Init`, `natneg::Report`, `Packet::ConnectAck` and `Packet::Unacted`
   gained a `version` field, so constructing them by literal needs updating.

And one in `gamespy-runtime`: the registry is now bounded at
`Policy::max_negotiations`, which previously had no limit. At the bound a *new*
cookie is refused; a negotiation already held is never evicted.

## Consumer migration note (mkvsdcu)

The shared implementation covers the v3 listener's negotiation engine in full.
Switching to it means:

**Removable**

- `crates/mkvsdcu-proto/src/natneg.rs` entirely. `gamespy_proto::natneg`
  parses the same packets and builds the same replies; `init_ack_fields`,
  `report_ack_shaped(.., InitBody)` and `connect_versioned(V3, .., Outcome)`
  produce the consumer's bytes exactly, which the shared crate's tests assert
  against the vectors from that module's own tests.
- `crates/mkvsdcu-server/src/natneg_listener.rs` entirely: `Rendezvous`,
  `Client`, `Pair`, the `handle`/`init`/`connects`/`abandon`/`expire`/`tick`
  state machine and the socket loop. Replace `natneg_listener::spawn(bind)`
  with a bound `UdpSocket` and
  `gamespy_runtime::natneg::spawn_with_policy(socket, observer, Policy::v3_compatible().with_titles(..))`.

**Behaviour the consumer gains**

- CONNECT retries become per peer rather than per pair, so one peer's
  acknowledgement no longer stops delivery to the other.
- A REPORT is acknowledged even for a cookie the service never paired, which
  releases a peer from `ns_reportsent` instead of leaving it to burn five
  resends.
- Diagnostics move from `println!` to the `Observer` trait, with per-packet
  field traces and named anomalies.
- Expiry is measured from the last packet accepted from a side rather than
  from the negotiation's first INIT, so a live peer is not swept mid-exchange.

**Remaining gaps and deliberate differences**

- Side identity is `(client index, host)`, not a client index with a pinned IP.
  Two peers that announce the same index from different hosts keep separate
  entries and are paired by host, with a `DuplicateClientIndex` anomaly. The
  consumer refused the second peer outright. Neither is wrong; this one
  completes a negotiation the other deadlocks, at the cost of accepting a pair
  that disagrees with the protocol about which side each one is.
- A REPORT is not source-validated against a registered client's control
  endpoint. That is deliberate, for the reason above.
- The INIT parser does not reject `client_index > 1` or a `port_type` above
  `NN_PT_NN3`; the engine records both as anomalies instead. A deployment that
  wants them refused needs a check this crate does not yet offer.
- CONNECT retry cadence is 500 ms (the SDK's `INIT_RETRY_TIME`) rather than
  the consumer's 1 s. Not configurable yet.
- `use_game_port` is not used to *select* the advertised mapping; the lowest
  announced port type is. These agree under
  `Readiness::AllRegistrations`, which is why the v3 policy sets it, but they
  can differ under `Readiness::OnFirstInit`.
- Nothing here has been validated against a console. See the test section of
  the changelog entry for what was actually run.

## Review findings and open work

`natneg-v3-findings.md` records a review of this implementation against the
pinned `NN_PROTVER 3` SDK sources, with the wire codec verified correct, five
ranked findings and the open TODOs for each. Findings 1 and 2 there fire only
under `Policy::v3_compatible()` and finding 4 only under `Policy::default()`,
so identify the configured policy before reading them. That document is
version 3 only; version 4 is reviewed separately.
