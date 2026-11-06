# NAT negotiation version 3: review findings and open work

Review of `gamespy-proto::natneg` and `gamespy-runtime::natneg` against the
GameSpy NAT Negotiation SDK C sources, 2026-11-06.

**Scope: protocol version 3 only.** Every claim below is sourced from a
`#define NN_PROTVER 3` SDK, so none of it carries to version 4 except where the
wire layout is shared. Version 4 adds at least one packet type the v3 header
does not define (`PREINIT_ACK`, `0x10`, which this crate parses as
`Packet::Unacted`) and is reviewed separately. Do not read a v3 finding as a v4
finding.

Nothing here has been reproduced against a console. The findings are derived
from reading the client's state machine; the log signatures are what each one
should look like in a capture, not observations.

## Status

Applied in the review pass, as provable corrections against the C reference:

- Finding 5, the socket/endpoint mismatch. `Side::mappings` now carries a
  `Mapping { socket, address }`, `control_endpoint` returns both, and the three
  senders take the socket from the endpoint they address. Covered by
  `a_connect_leaves_from_the_socket_that_observed_its_endpoint`.
- Finding 4's doc claims, which were the stated justification for the default
  and were false. Replaced with the quoted gate and the real trade.
- Finding 4's wasted re-arm. `arm_connect` no longer re-arms a CONNECT for a
  side that has acknowledged one. Covered by
  `an_acknowledged_connect_is_not_re_armed_for_a_new_address`.
- `acknowledge_connect`'s wrong claim about which socket a CONNECT_ACK leaves
  from.
- `usable_local` now rejects `169.254.0.0/16`.

Deliberately **not** applied, because they are trades rather than corrections
and want log or console evidence first: the `Readiness` default (see finding 4),
the same-subnet gate on private-address substitution (finding 3), and the
diagnostics under findings 1 and 2.

## Sources

Read-only reference, not copied into this project:

| File | SHA-256 |
| --- | --- |
| `natneg.c` | `BA33262B97F7B171D226A89C416468D5E5231B8976ADA9263BA6114A07BA3AC7` |
| `natneg.h` | `DE997FC3F5B9830406CD0F2015527EF757FB138FF3A9C461E3FFD2FAB257EF02` |
| `nninternal.h` | `94786CE023D80A10EF7F8381E81C3ED7AF7A72AE8B6C2967CED29EAE91DE24AC` |

From `https://github.com/openmoh/openmohaa` at revision
`a2f340195975f4f042e28a60b62561dd9a0b2700`, staged at
`ps3_private_server/.local/mk-vs-dc/work/sdk-openmohaa-natneg-20261028`.

Title-side facts are from `ps3_private_server/.local/mk-vs-dc/work/match-session-findings-20261028.md`.

## Verified correct: the wire codec

Checked exhaustively; no defects found. Recorded so this does not get
re-audited.

| This crate | SDK | |
| --- | --- | --- |
| `HEADER_LEN` 12, `INIT_WITH_ADDRESS_LEN` 21, `CONNECT_LEN` 20, `REPORT_LEN` 73 | `BASEPACKET_SIZE` 12, `+9`, `+8`, `+61` | ok |
| `LOCAL_ADDRESS_OFFSET` 15 | `INITPACKET_ADDRESS_OFFSET` = `BASEPACKET_SIZE + 3` | ok |
| `nat_bytes` at 15..23, game name at 23..73 | `natType` and `natMappingScheme` are 4-byte C enums, then `gamename[50]` | ok |
| cookie and `remotePort` big-endian, `remoteIP` as raw octets | `htonl` / `htons` / `s_addr` | ok |
| both acknowledgement shapes >= 21 bytes | `NNProcessData` requires `len >= INITPACKET_SIZE` for the init family | ok |
| `report_of` ignores offset 12 | `SendReportPacket` never assigns `porttype`; it is uninitialised stack | ok |
| GP and NN1 inits carry local port 0, later ones carry the real port, and `record_scoped` will not let a zero erase a known one | `SendInitPackets` fills the port only after those two sends | ok |

Two title-side facts worth keeping, both from the match-session findings:

- The title calls `NNBeginNegotiationWithSocket`, so `usegameport` is always 1
  and port type `NN_PT_GP` is always announced. `advertised_mapping` taking the
  lowest announced port type therefore resolves to the game socket, which is
  the socket `SendPingPacket` punches from. Correct.
- The cookie and client index are held by the title before negotiation starts
  and are not allocated by a server.

## Triage

Ranked for a version 3 deployment. Severity is "how badly it breaks a match",
not "how likely it is here".

| # | Finding | Fires under | Symptom |
| --- | --- | --- | --- |
| 1 | natneg2/natneg3 not pointed at this listener, against `AllRegistrations` | `v3_compatible` | universal, silent |
| 2 | `InvalidPinnedFields` on a client index outside 0/1 | `v3_compatible` | universal, silent |
| 3 | Private-address substitution under carrier-grade NAT | any | pair-dependent |
| 4 | `OnFirstInit` introduces on a partial mapping set and cannot correct it | `Policy::default()` only | intermittent |
| 5 | `NegotiationMapping` sends a CONNECT from the wrong socket | multi-socket only | universal, silent |

Findings 1 and 2 fire only under `Policy::v3_compatible()`; finding 4 fires
only under `Policy::default()`. They are mutually exclusive, so identify the
configured policy before reading the list.

## 1. `AllRegistrations` requires all three matchup names to arrive here

`is_ready` under `Readiness::AllRegistrations` requires port types 1, 2 and 3.
`SendInitPackets` sends `NN_PT_NN2` to matchup2 and `NN_PT_NN3` to matchup3, so
those two mappings only ever arrive if `{game}.natneg2` and `{game}.natneg3`
resolve to this listener. If they resolve somewhere else, readiness is never
satisfied and **no CONNECT is ever sent**.

Nothing reports it. `expired_partners` skips any negotiation with
`sides.len() >= 2`, and both consoles did register, so `partner_wait` never
fires and neither peer receives a failure CONNECT. The peers die on their own
init budget instead: they never receive acknowledgements for NN2/NN3, so they
never reach `ns_initack`, never start `PARTNER_WAIT_TIME` 60000, and fail at
`INIT_RETRY_TIME` 500 x `INIT_RETRY_COUNT` 10, about 5.5 s, with
`nr_inittimeout`.

This was already identified as a deployment gap in the match-session findings:
"Redirecting a subset leaves login and rooms working and silently breaks every
match. This was the gap: the deployment notes previously excluded `natneg*`."

Log signature: two inits per console, `port_type=0` and `port_type=1`, both
acknowledged, then `pairing <cookie> is held: index N is still missing port
type(s) 2, 3` repeating, and no `connect sent` line.

Retest trap: the client's matchup resolver caches each address for the process
lifetime, so a console that cached a wrong natneg2/natneg3 address needs a full
game restart to pick up a DNS fix. Leaving and re-entering online will not do
it.

- [ ] **TODO (diagnostic).** Emit a startup warning naming the readiness rule's
      dependency on all three matchup names, so this is visible without
      correlating per-cookie traces.
- [ ] **TODO (diagnostic).** When a negotiation has two sides and neither
      becomes ready within the client's own ~5.5 s init budget, log that the
      peers have already given up. Currently the "is held" line repeats with no
      indication that the window has closed.
- [ ] **TODO (decide).** Consider whether a pair stuck short of readiness should
      receive `FINISHED_ERROR_INIT_PACKETS_TIMEDOUT` rather than silence.
      Against: a failure CONNECT cannot be taken back, and the SDK's own rule is
      to wait. For: silence costs the title any error to show.

## 2. `Rebinding::Pin` drops inits for a client index outside 0/1

`accept_init` refuses with `InitRefusal::InvalidPinnedFields` when
`client_index` is not 0 or 1, or `port_type` exceeds `NN_PT_NN3`. The refusal
path returns before `acknowledge_init`, so the console receives **zero**
acknowledgements and fails at ~5.5 s with `nr_inittimeout`.

The index is supplied by the title, not by this server, so its values are an
open question rather than something the SDK settles. `Policy::default()` has no
index validation at all and `SideKey` separates same-index peers by host, so
this is a `v3_compatible`-only behaviour: a deployment that worked before
adopting the v3 policy and broke after should check this first.

Log signature: `drop trace: init for 0x... index=N port_type=M is not accepted,
and is not acknowledged: invalid pinned client index or port type`.

- [ ] **TODO (verify).** Read the actual client index values the title passes to
      `NNBeginNegotiationWithSocket` out of the eboot. If they are not 0/1, the
      pinned check is wrong for this title and must be relaxed.
- [ ] **TODO (diagnostic).** This refusal is indistinguishable in effect from a
      console that never sent an init. Promote it from `peer_event` to a
      warning, since it is unrecoverable for the peer rather than routine.

## 3. Private-address substitution assumes one NAT, not carrier-grade NAT

`connect_address` hands each peer the other's announced private address
whenever both reach this service from the same public address, on the reasoning
that they are behind one NAT. Under carrier-grade NAT they are not: both punch
unroutable addresses, which may not even belong to the same subnet.

The asymmetry that matters: `ProcessPingPacket` unconditionally overwrites
`guessedIP` and `guessedPort` from each ping's own source address, so handing
out public mappings self-corrects as soon as one direction's ping lands.
Handing out a private address gives that correction nothing to work from, so the
failure is terminal.

This path is needed — the match-session findings call the local address out as
"needed to connect two consoles behind one public address" — so it is the
unconditional trigger that is wrong, not the feature.

Log signature: `connect address for <cookie>: private 10.x.x.x:...` for a pair
that is not actually on one LAN.

- [ ] **TODO (fix, needs evidence).** Gate the substitution on the two peers'
      announced local addresses sharing a subnet, falling back to the public
      mapping otherwise. Held back deliberately: a same-subnet test is a guess
      about player topology, not a correction the C reference proves. It also
      does not cure the case it is aimed at — two households behind one
      carrier NAT both on `192.168.1.0/24` still pass it — and it could regress
      a genuine same-LAN pair on a routed home network. Wants a capture showing
      a `private` connect address for a pair that then fails.
- [ ] **TODO (consider).** A belt-and-braces alternative: send the public
      mapping and let ping source-learning converge, accepting that a same-LAN
      pair then needs hairpinning. Decide which failure is preferable rather
      than leaving it implicit.

## 4. `OnFirstInit` cannot correct an introduction the client has acted on

Two assertions in the `Readiness::OnFirstInit` doc comment are contradicted by
the SDK:

> `ProcessConnectPacket` in the referenced SDK acts on a CONNECT in any
> negotiation state

> if a later INIT reveals a better mapping the CONNECT is re-armed for the new
> address

`ProcessConnectPacket` acknowledges the CONNECT and then returns early:

```c
if (p->Packet.Connect.finished == FINISHED_NOERROR)
    SendConnectAck(neg, fromaddr);
if (neg->state >= ns_connectping)
    return; //don't process it any further
```

With `ns_initsent` 0, `ns_initack` 1, `ns_connectping` 2, only states 0 and 1
act on a CONNECT. **The first CONNECT a peer receives is final.** Later ones are
acknowledged while `guessedIP` and `guessedPort` are never updated, so the
re-arm in `arm_connect` produces a clean `connect_ack` for an introduction the
peer discarded.

Processing a CONNECT also moves the peer to `ns_connectping`, and
`NegotiateThink` resends inits only in `ns_initsent`, so an introduced peer
stops announcing port types it has not yet announced.

Scope: narrower than the state gate alone suggests. `SendInitPackets` emits all
four inits in the opening burst, before any CONNECT can round-trip, so mere
reordering loses nothing — the failure needs a GP datagram to actually be
**lost**, after which it is never resent and that peer's game-port mapping is
never learned.

**Confirmed for version 4 as well**, which matters because `OnFirstInit` is the
version 4 default. The Homefront EBOOT's CONNECT handler reads `neg->state` and
returns on `cmplwi r4, 4` / `bge` at `0x008663b4`; the value is 4 rather than 2
because two preinit states are inserted at the front of the enum. See
`natneg-v4-open-questions.md`.

- [x] **Fixed.** Both doc claims corrected, with the gate quoted from
      `natneg.c` and the real trade stated on each variant.
- [ ] **TODO (decide, needs evidence).** Whether `Readiness::AllRegistrations`
      should become the default. Left as `OnFirstInit` on purpose: switching it
      would import finding 1 into every **version 4** deployment, because a v4
      listener cannot use `v3_compatible()` and therefore runs the default. A
      deployment whose natneg2/natneg3 names do not reach it works today under
      `OnFirstInit` and would deadlock silently under `AllRegistrations`. Decide
      once a capture shows whether port types 2 and 3 arrive.
- [x] **Fixed.** `arm_connect` declines to re-arm once a side has acknowledged
      a CONNECT, so a settled delivery is no longer reopened and up to
      `CONNECT_ATTEMPTS` packets are no longer sent for an introduction the
      peer discards.

## 5. `NegotiationMapping` pairs a target address with the wrong socket

`Side.mappings` is `BTreeMap<u8, SocketAddr>`: it records which address each
port type came from but not which of this service's sockets observed it.
`Side.socket` is overwritten by every init and is not carried forward by
`record_scoped`, so it ends up being the socket of the **most recent** init.

All three senders then pair them up independently:

- `introduce` uses `socket: target.socket` with `target: control_endpoint(...)`
- `due_connects` does the same
- `expired_partners` does the same

`SendInitPackets` sends GP, NN1, NN2, NN3 in that order, so the last init
recorded is normally NN3. On a deployment with three bound addresses the CONNECT
therefore leaves the natneg3 socket addressed to the port the NAT opened for
natneg1, and any port-restricted or symmetric NAT drops it.

Not reachable on the single-socket deployment the example configures: with one
socket, `side.socket` is always 0 and there is only one socket to send from.
`ControlEndpoint::LatestInit` is also safe, because `side.address` and
`side.socket` come from the same init. This is latent, for whenever a multi-IP
deployment happens.

Covered by no test: `tests.rs` exercises `control_endpoint` in isolation,
single-socket.

- [x] **Fixed.** `mappings` is now `BTreeMap<u8, Mapping>`, carrying the socket
      that observed each address, and `control_endpoint` returns the pair so a
      target address cannot be matched with a socket that never saw it.
      `introduce`, `due_connects` and `expired_partners` all take the socket
      from the endpoint they address.
- [x] **Fixed.** `a_connect_leaves_from_the_socket_that_observed_its_endpoint`
      covers the three-socket case under both control endpoints. The per-port
      mapping trace now prints the socket too, since a reply from the wrong one
      is otherwise invisible in a capture.

## Smaller items

- [x] **Fixed.** `acknowledge_connect`'s comment claimed "the SDK sends its
      CONNECT_ACK from the socket that received the CONNECT". It does not —
      `SendConnectAck` always uses `neg->negotiateSock`. The behaviour was
      already right (any announced mapping is accepted); only the reason was
      wrong.
- [x] **Fixed.** `usable_local` now rejects `169.254.0.0/16`.
- [ ] **TODO (consider).** `expired_partners` counts `negotiation.sides.len()`
      including sides a sweep has not reclaimed yet. Self-heals within
      `SWEEP_INTERVAL`, so this is a latency wart rather than a defect.
- [ ] **TODO (consider).** A `NN_PROTVER 2` client — the version commented out
      above the pinned header's `#define` — is refused outright by
      `parse_accepting`. Decide whether that generation is in scope.

## Ceiling, not a defect

This service implements no NAT type detection. `NATify.c` is in the reference
set and the SDK's own `NNStartNatDetection` uses the three matchup addresses to
classify the NAT and derive a mapping scheme; this service records all three
mappings but only ever advertises one and performs no reachability or mapping
probe, which `prepare`'s capability trace already states.

A console behind a symmetric NAT therefore cannot be introduced, whatever else
is fixed. If failures turn out to be specific to one player's network rather
than universal, this is the likelier explanation than any finding above.

- [ ] **TODO (scope).** Decide whether NAT type detection and port prediction
      are in scope at all. If not, say so in the crate docs, so a symmetric-NAT
      failure is not re-debugged as a bug.
