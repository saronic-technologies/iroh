# Delegated UDP receive (dataplane multiplexing)

This fork adds a feature-gated API (`unstable-udp-delegation`) that lets an
external dataplane share the endpoint's UDP sockets — same source port, same
4-tuple, same NAT binding as the QUIC traffic — without its packets ever
entering the QUIC stack.

The intended consumer is an external packet processor — for example a single
synchronous OS thread that reads all datagrams from the endpoint's sockets,
processes its own wire format inline (no allocation, no async runtime), and
hands the QUIC packets back to iroh. Iroh continues to provide connection
management, NAT traversal/holepunching, multipath path selection and the
control plane, fully unmodified.

## The wire invariant

Iroh disables QUIC fixed-bit greasing (RFC 9287): see
`endpoint_config.grease_quic_bit(false)` in `iroh/src/socket.rs`. Because the
endpoint never advertises the greasing transport parameter, conformant peers
never send it QUIC packets with bit `0x40` cleared, and noq rejects any such
packet on receive.

Therefore, on a delegated socket:

- **first byte `& 0x40 != 0`** → QUIC. Must be re-injected into the endpoint.
- **first byte `0x00..=0x3F`** → free for non-QUIC dataplane formats.

Recommendations for dataplane wire formats:

- Keep every kind/discriminator value `<= 0x3F`. This is a hard protocol
  invariant; new kinds must never set bit `0x40`.
- Prefer starting kinds at `0x01` and reserving `0x00`. Iroh internally uses
  "first byte zeroed" as a *consumed packet* marker convention, and all-zero
  junk datagrams from the internet trivially match a `0x00` kind. Not required
  for correctness (the delegated receiver runs before anything else), but it
  removes an aliasing class for free.

Do not remove `grease_quic_bit(false)` without revisiting this design.

## Architecture

```
                     ┌────────────────────────────── process ─────────────────────────────┐
                     │                                                                    │
   UDP socket(s)     │   dataplane thread (sync, sole reader)          iroh / noq (tokio) │
  ┌─────────────┐    │  ┌──────────────────────────────┐              ┌─────────────────┐ │
  │ v4  :port   │───────▶ poll_recv (parking waker)    │              │ noq endpoint    │ │
  │ v6  :port   │    │  │  per GRO segment:            │  injection   │ driver          │ │
  └─────────────┘    │  │   byte0 >= 0x40 → inject ────┼──queue──────▶│ (QUIC only)     │ │
        ▲            │  │   byte0 <  0x40 → consumer,  │  (mpsc,      └─────────────────┘ │
        │            │  │     processed in place       │   waker)              │          │
        │            │  └──────────────┬───────────────┘                       │          │
        └────────────┼─── try_send ────┘ (dataplane TX, GSO)                   │          │
        └────────────┼─────────────────── QUIC TX (unchanged poll_send path) ◀─┘          │
                     └────────────────────────────────────────────────────────────────────┘
```

- **RX**: with `Builder::delegate_udp_recv()`, `IpTransport::poll_recv` stops
  reading the sockets and instead drains an injection queue
  (`iroh/src/socket/delegation.rs`). The delegated receiver is the only party
  polling the sockets. Dataplane datagrams are processed in the pump with no
  extra copies (kernel → pump buffer, processed in place); QUIC packets cost
  one small copy through the queue — acceptable because QUIC now carries only
  control-plane traffic.
- **TX**: both sides send on the same sockets concurrently.
  `DelegatedUdpSocket::try_send` is non-blocking, runtime-free, GSO-capable
  (`Transmit::segment_size`), and rebind-safe (lock-guarded fd access inside
  `netwatch`). QUIC TX is untouched.
- **Rebinds**: `netwatch::UdpSocket` swaps its fd *inside* the shared object on
  network changes, so handles stay valid. Watch
  `DelegatedUdpSocket::local_addr_watcher()` to track the current port.

## Receiver contract

Enabling delegation means **the endpoint receives nothing unless the pump
runs**. QUIC handshakes, address discovery (QAD), holepunching and keepalives
all depend on the pump re-injecting QUIC packets.

1. Poll every delegated socket handle continuously (one per bound socket,
   typically v4 + v6). `poll_recv` registers the supplied waker for
   readability; a `park`/`unpark` loop with a timeout safety-net works (see
   `iroh/tests/udp_delegation.rs` for the canonical pump).
2. Classify **per GRO segment**, not per buffer: on Linux one receive can
   carry up to `gro_segments()` coalesced datagrams (`meta.len` total,
   `meta.stride` each, last may be shorter). QUIC and dataplane packets share
   the 4-tuple, so a batch can mix both when sizes coincide.
3. Never block in the pump. Injection failure (`InjectError::Full`) and
   `try_send` `WouldBlock` are packet loss — drop and continue.
4. Size receive buffers to at least `1500 * gro_segments()` bytes.
5. Start the pump promptly after `bind()` (the socket buffer absorbs ~7 MiB
   meanwhile) and keep it alive until after `Endpoint::close()` — close frames
   flow through the pump too. Watchdog the pump thread: if it stalls, the
   control plane stalls with it.

Sizing note: keep dataplane datagrams within the underlay MTU — there is no
PMTUD on this path, and `may_fragment()` reports whether the OS might fragment.

## Remote address integration

A consumer that addresses remote endpoints directly needs to know where to
send: subscribe to `Connection::path_events()` / `Connection::paths()`.
`PathEvent::Selected` carries the concrete remote `TransportAddr` (a real
`SocketAddr` for IP paths) and fires on migration. When the selected path is a
relay, there is no direct UDP path — fall back to QUIC datagrams for that
remote or treat it as unreachable.

## Dependency pass-through

The delegation API deliberately exposes `noq_udp::Transmit` and
`noq_udp::RecvMeta` verbatim rather than wrapping them: any per-packet
capability the `noq-udp` dependency gains in the future (additional cmsg
metadata, send options, …) becomes available to delegated receivers
automatically, with no changes required in this crate.

## Fork bookkeeping

All logic lives in new files; upstream-tracked files got only insertions:

| File | Change |
|------|--------|
| `iroh/src/socket/delegation.rs` | **new** — handles, injection queue, docs |
| `iroh/tests/udp_delegation.rs` | **new** — e2e: QUIC through pump + raw datagrams |
| `iroh/src/socket/transports/ip.rs` | + `delegated_rx` field, `delegate_recv()`, `poll_recv_delegated()`, 3-line branch in `poll_recv` |
| `iroh/src/socket/transports.rs` | + `Transports::delegate_udp_recv()` |
| `iroh/src/socket.rs` | + module decl, `Options` field, bind wiring block, `Socket` field + accessor, comment at `grease_quic_bit` |
| `iroh/src/endpoint.rs` | + `Builder::delegate_udp_recv()`, `Endpoint::delegated_udp_sockets()` |
| `iroh/src/lib.rs` | + `unstable_udp_delegation` module |
| `iroh/Cargo.toml` | + `unstable-udp-delegation` feature |
