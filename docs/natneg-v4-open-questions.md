# NAT negotiation version 4: the preinit phase

Companion to `natneg-v3-findings.md`, which reviews this implementation
against the pinned `NN_PROTVER 3` SDK C sources. **Little of that transfers to
version 4**, because version 4 has no source: it is read from client binaries.

Version 4 adds a **mandatory handshake before the INIT phase**. A server that
does not answer it never receives a single INIT, so nothing in the pairing
engine — readiness, control endpoint, rebinding, CONNECT delivery — ever runs.
This was the gap that made version 4 titles fail completely.

## Source

Homefront (PS3, `NPUB30572`, APP_VER 01.04), decrypted EBOOT:

| | |
| --- | --- |
| Path | `ps3_private_server/private-data/homefront/decrypt-20261102/EBOOT.elf` |
| SHA-256 | `c59b19062b7e0f008a92fe8417307b8a36dae9711f2a2ab00c7d4fa269dfbb34` |
| Format | ELF64, big-endian, `EM_PPC64` (machine 21), 32-bit pointers |
| Load mapping | both `PT_LOAD` segments at **VA = file offset + 0x10000** |
| TOC base | `0x1F1F4B0` (from the 32-bit OPD at `e_entry` `0x1F05210`) |

Read with Capstone 5.0.7; REA rejects PS3 PPC (`unsupported ELF architecture`),
and this project has no Ghidra configuration, so this follows the Capstone
workflow `ps3_private_server/docs/games/homefront/CURRENT.md` records.

### Locating the module

The six magic bytes occur exactly once, at **`0x1F51DA4`** in the writable data
segment — a non-`const` `NNMagicData[]`, as the SDK declares it. No code reads
that address; what *is* read, 51 times from `0x0086562c` onwards, is
**`0x1F51DAC`** (magic + 8, after padding), which is the next global in
`natneg.c`: `DArray negotiateList`. That pins the whole module to
**`0x00865000`-`0x00867800`**.

**Homefront is not the binary this crate's existing version 4 addresses came
from.** Those cite `0x00ae****` and debug strings such as "CONNECT or
CONNECT_PING packet too small, ignoring" at `0x0160c594`; Homefront has natneg
at `0x0086****` and contains **no** GameSpy debug strings at all, so
`gsDebugFormat` is compiled out. Two different titles, the same SDK
generation. Addresses below are Homefront's.

## The preinit exchange

| | |
| --- | --- |
| `NN_PREINIT` | type `0x0F`, sent by the client |
| `NN_PREINIT_ACK` | type `0x10`, sent by the server |
| Size | 18 bytes = `BASEPACKET_SIZE` 12 + 6 |
| Body | `clientindex` at 12, `state` at 13, a four-byte client id at 14 |

`NNProcessData` (`0x008660a0`) checks the magic against `0x1F51DA4` with a
six-byte `memcmp`, reads `ptype` from `data[7]`, and dispatches three ways:

```
0x008660f4  cmpwi r31,7 ; cmpwi r31,5 ; beq 0x866320   → CONNECT/CONNECT_PING, len >= 0x14
0x00866104  cmpwi r31,0x10 ; bne 0x86617c              → type 0x10, len >= 0x12 (18)
0x0086617c  cmpwi r30,0x15                             → init family, len >= 0x15 (21)
```

The handler for `0x10` (`0x008662b4`):

```
lwz r3,0x1c(r30) ; cmpwi r3,1 ; beq        → skip if already in state 1
stw r4,0x1c(r30)            (li r4,1)      → neg->state = 1
bdnzctrl                                   → progressCallback(1, userdata)
bl 0x854ba0 ; addic r3,r3,0x2710           → retryTime = now + 10000 ms
stw r4,0x34(r30)            (li r4,0xc)    → maxRetryCount = 12
lbz r3,0xbd(r1)                            → the packet's own state byte (offset 13)
cmpwi cr1,r3,2 ; cmpwi r3,1 ; crorc ; beq  → proceed only when it is 2
bl 0x865b18                                → SendInitPackets
```

`0x00865b18` is `SendInitPackets`, confirmed by its body: it loads
`NNMagicData`, writes `li r3,4` to buffer offset 6 (**version 4**), type 0 to
offset 7, the cookie to 8, `clientindex` to 13 and `usegameport` to 14
(`gameSock != -1`), then walks the local-IP list skipping `0x7F000001`.

**It has exactly two callers**, and both require the post-preinit state:

- `0x00866318`, the handler above, when the ack's `state` byte is 2;
- `0x00866d0c`, the retry loop, when `neg->state == 2`.

The retry loop (`0x00866c84`) dispatches on the same field: state 0 or 1
resends `NN_PREINIT` (built at `0x00866d14`, `li r4,0xf` at `0x00866d44`),
state 2 resends the INITs. The first `NN_PREINIT` is built in
`NNBeginNegotiation*` at `0x008659d8`-`0x00865a24`.

So the state field is an extended enum with two preinit states at the **front**:

| value | meaning |
| --- | --- |
| 0 | preinit sent |
| 1 | preinit acknowledged, waiting |
| 2 | init sent |
| 3 | init acknowledged |
| 4 | connect-ping |

`state == 2` is reachable only through a `PREINIT_ACK`. **No acknowledgement
means no INIT, ever.**

The two reply states are `WAITING` (1), which parks the peer on a 10-second
timer with 12 attempts — roughly two minutes, against the roughly 5.5 seconds
an init budget allows — and `READY` (2), which starts the INIT phase.

## What this build does

`Policy::serve_preinit` (default **true**) answers every `NN_PREINIT` with
`preinit_ack(.., preinit_state::READY)`: the request echoed, with offset 13 set
to 2 and the type set to `0x10`.

READY immediately, rather than WAITING until a partner appears, so a version 4
negotiation proceeds exactly as a version 3 one does and the existing engine,
`Policy::partner_wait` and the peer's own `PARTNER_WAIT_TIME` keep deciding
everything about waiting. No new registry state or timer is introduced.

This is the one place where a new packet type appears on the wire without being
opted into. The rest of `Policy` exists so an embedder's traffic does not change
shape on upgrade; that default was written when preinit was believed optional,
which the evidence above disproves. A version 3 deployment is unaffected,
because a version 3 client never sends the packet.

- [ ] **TODO (improve).** Use `WAITING` while a cookie has only one side, and
      `READY` once both have announced, so a lone peer is held for two minutes
      instead of failing on its init budget. Needs the cookie's sides tracked
      across the preinit phase, which a preinit carries almost nothing for: no
      port type, no mapping, no title name, only cookie and client index.
- [ ] **TODO (verify).** The client's own `state` byte, and the four-byte
      client id at offset 14. Both are echoed; neither has been traced to a
      use. If the id must match something, echoing is right anyway.

## Settled for version 4

- **Version byte is 4**, written at buffer offset 6 by both the preinit builder
  (`0x00865a08`) and `SendInitPackets` (`0x00865b78`).
- **The `ns_connectping` gate exists**, so `natneg-v3-findings.md` finding 4
  applies to version 4 — at a renumbered value. The CONNECT handler reads the
  `finished` byte at offset 19 (`lbz r3,0xc3(r1)`, buffer base `0xb0`), acks
  when it is zero, then:

  ```
  0x008663ac  lwz r4,0x1c(r29)        → neg->state
  0x008663b4  cmplwi r4, 4
  0x008663b8  bge 0x866278            → if (state >= ns_connectping) return
  0x008663c8  li r3,4                 → default nr_unknownerror
  ```

  So the first CONNECT a peer acts on is still final, and `Readiness::OnFirstInit`
  — the version 4 default — carries the risk that finding records.
- **`NegotiateResult` is unchanged**: `neg->result` is initialised to 5
  (`nr_noresult`) at `0x008659c0`, matching the version 3 enum.
- **The matchup hostnames are bare**: `natneg1.gamespy.com`,
  `natneg2.gamespy.com`, `natneg3.gamespy.com` at `0x1A5FE60`/`78`/`90`, a
  24-byte-stride `char[3][24]`, with **no** `%s.` gamename prefix — unlike
  their neighbours `%s.master.gamespy.com` and `%s.ms%d.gamespy.com`. So this
  title overrides `Matchup{1,2,3}Hostname` and resolves those three names
  verbatim. A deployment must redirect exactly those names, and **all three**,
  because the SDK's resolver returns an error unless every one resolves and
  then sends nothing at all.

## Still not transferable from version 3

- Retry budgets (`INIT_RETRY_*`, `PING_RETRY_*`, `REPORT_RETRY_*`) and
  `PARTNER_WAIT_TIME`. The preinit timer is read (10 s, 12 attempts); the rest
  are version 3 constants, including the ~5.5 s init budget that bounds every
  timing argument in the v3 findings.
- `SendConnectAck` sending from `negotiateSock` rather than the receiving socket.
- `SendInitPackets` ordering and the zero local port in the GP and NN1 packets.
- Whether `usegameport` is always 1. It is computed from `gameSock != -1`
  (`0x00865b90`), so it depends on how the title begins negotiation.

The wire layout of the shared types is confirmed identical: the 21-byte init
family and the 20-byte connect family, at the offsets this crate already used.
