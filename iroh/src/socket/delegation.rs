//! Delegated receive path for the endpoint's UDP sockets.
//!
//! By default the endpoint owns the receive path of its UDP sockets: the QUIC
//! endpoint polls the sockets and consumes every datagram.  With *delegated
//! receive* that inverts: an external packet processor (e.g. a synchronous
//! dataplane thread) becomes the only reader of the sockets, classifies each
//! datagram, and re-injects the QUIC packets back into the endpoint through an
//! in-process queue.  Datagrams that are not QUIC (for example a custom
//! dataplane wire format) never touch the QUIC stack at all.
//!
//! This relies on a protocol invariant of iroh's QUIC configuration: the
//! endpoint disables QUIC fixed-bit greasing (RFC 9287), so every QUIC packet
//! iroh sends or accepts has bit `0x40` set in its first byte.  Any datagram
//! whose first byte is in `0x00..=0x3F` is therefore guaranteed not to be a
//! QUIC packet and may be consumed by the delegated receiver.  See
//! `DATAPLANE.md` in the repository root for the full design.
//!
//! # Contract
//!
//! Enabling delegation via `Builder::delegate_udp_recv` means the endpoint
//! stops reading its IP sockets entirely.  The holder of the
//! [`DelegatedUdpSocket`] handles **must** continuously poll them and inject
//! all QUIC packets; otherwise the endpoint receives nothing — connections,
//! address discovery and holepunching will silently stall.
//!
//! The handles stay valid across rebinds: the underlying socket object is
//! shared and swaps its file descriptor internally on rebind, and
//! [`DelegatedUdpSocket::local_addr`] reflects the current binding.

use std::{
    io,
    net::{IpAddr, SocketAddr},
    num::NonZeroUsize,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::Bytes;
use n0_watcher::Watcher;
use netwatch::UdpSocket;
use tokio::sync::mpsc;

/// Capacity (in datagrams) of the per-socket QUIC re-injection queue.
///
/// QUIC carries only control-plane traffic in a delegated setup, so this does
/// not need to scale with dataplane throughput.  When the queue is full,
/// [`DelegatedUdpSocket::inject_received`] fails and the packet should be
/// dropped; QUIC treats it as normal network loss.
pub(crate) const INJECTION_QUEUE_CAP: usize = 1024;

/// A datagram handed back to the endpoint by the delegated receiver.
#[derive(Debug)]
pub(crate) struct InjectedDatagram {
    /// The remote address the datagram was received from.
    pub(crate) src: SocketAddr,
    /// The local destination IP, if the receiver knows it (from `RecvMeta::dst_ip`).
    pub(crate) dst_ip: Option<IpAddr>,
    /// ECN bits of the received datagram, if any.
    pub(crate) ecn: Option<noq_udp::EcnCodepoint>,
    /// The datagram payload (exactly one datagram, not a GRO batch).
    pub(crate) payload: Bytes,
}

/// Receiving half of the injection queue, owned by the IP transport.
pub(crate) type InjectionReceiver = mpsc::Receiver<InjectedDatagram>;

/// Handle to one of the endpoint's UDP sockets whose receive path is delegated.
///
/// One handle exists per bound IP socket (typically one IPv4 and one IPv6).
/// The handle is cheaply cloneable and remains valid for the lifetime of the
/// endpoint, including across rebinds after network changes.
///
/// All methods are usable from a plain OS thread without an async runtime:
/// [`poll_recv`] takes a caller-supplied [`Context`] (e.g. built from a
/// thread-parking [`std::task::Wake`] implementation) and [`try_send`] /
/// [`inject_received`] are non-blocking.
///
/// [`poll_recv`]: DelegatedUdpSocket::poll_recv
/// [`try_send`]: DelegatedUdpSocket::try_send
/// [`inject_received`]: DelegatedUdpSocket::inject_received
#[cfg_attr(not(feature = "unstable-udp-delegation"), allow(unreachable_pub))]
#[derive(Debug, Clone)]
pub struct DelegatedUdpSocket {
    socket: Arc<UdpSocket>,
    bind_addr: SocketAddr,
    local_addr: n0_watcher::Direct<SocketAddr>,
    inject_tx: mpsc::Sender<InjectedDatagram>,
}

#[cfg_attr(not(feature = "unstable-udp-delegation"), allow(unreachable_pub))]
impl DelegatedUdpSocket {
    pub(crate) fn new(
        socket: Arc<UdpSocket>,
        bind_addr: SocketAddr,
        local_addr: n0_watcher::Direct<SocketAddr>,
        inject_tx: mpsc::Sender<InjectedDatagram>,
    ) -> Self {
        Self {
            socket,
            bind_addr,
            local_addr,
            inject_tx,
        }
    }

    /// The address this socket was configured to bind to.
    ///
    /// This may have port `0`; use [`local_addr`] for the actual binding.
    /// The IP family of this address identifies the socket (v4 vs v6).
    ///
    /// [`local_addr`]: DelegatedUdpSocket::local_addr
    pub fn bind_addr(&self) -> SocketAddr {
        self.bind_addr
    }

    /// Returns `true` if this is an IPv4 socket.
    pub fn is_ipv4(&self) -> bool {
        self.bind_addr.is_ipv4()
    }

    /// The currently bound local address.
    ///
    /// Updated when the socket rebinds after a network change.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr.clone().get()
    }

    /// Returns a [`Watcher`] for the currently bound local address.
    ///
    /// Yields a new value when the socket rebinds after a network change.
    /// Useful to keep receiver-side state keyed on the local port in sync.
    pub fn local_addr_watcher(&self) -> n0_watcher::Direct<SocketAddr> {
        self.local_addr.clone()
    }

    /// Polls the socket for received datagrams.
    ///
    /// This is the raw socket receive: it yields **all** datagrams arriving on
    /// the socket, QUIC and non-QUIC alike.  The caller is responsible for
    /// classification: any datagram (or GRO segment) whose first byte has bit
    /// `0x40` set is a QUIC packet and must be passed to
    /// [`inject_received`]; the rest are the caller's to consume.
    ///
    /// On platforms with GRO (Linux), one filled buffer may contain several
    /// coalesced datagrams: `meta.len` is the total length and `meta.stride`
    /// the size of each segment (the last may be shorter).  Classification
    /// must happen **per segment**.  Size each buffer to at least
    /// `1500 * gro_segments()` bytes to receive full batches.
    ///
    /// The caller must be the only party polling the socket for reads; the
    /// waker from `cx` is registered with the socket and invoked on
    /// readability.  Returns `Poll::Pending` indefinitely once the endpoint
    /// is closed.
    ///
    /// [`inject_received`]: DelegatedUdpSocket::inject_received
    pub fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [noq_udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.socket.poll_recv_noq(cx, bufs, metas)
    }

    /// Sends a datagram on the socket without blocking.
    ///
    /// Callable from any thread, no async runtime required.  Supports GSO via
    /// [`noq_udp::Transmit::segment_size`] (see [`max_gso_segments`]).
    ///
    /// Returns [`io::ErrorKind::WouldBlock`] if the socket send buffer is
    /// full or a rebind is in progress; dataplane callers should treat this
    /// as packet loss and drop.
    ///
    /// [`max_gso_segments`]: DelegatedUdpSocket::max_gso_segments
    pub fn try_send(&self, transmit: &noq_udp::Transmit<'_>) -> io::Result<()> {
        self.socket.try_send_noq(transmit)
    }

    /// Polls to send a datagram, registering the waker from `cx` on backpressure.
    pub fn poll_send(
        &self,
        cx: &mut Context<'_>,
        transmit: &noq_udp::Transmit<'_>,
    ) -> Poll<io::Result<()>> {
        self.socket.poll_send_noq(cx, transmit)
    }

    /// Hands a received QUIC datagram back to the endpoint.
    ///
    /// `src` is the remote address the datagram was received from: pass
    /// [`noq_udp::RecvMeta::addr`] through verbatim — do not canonicalize or
    /// otherwise rebuild it, so that scope id and flowinfo of IPv6 sources
    /// (e.g. link-local peers) are preserved for the reply path.  `dst_ip`
    /// and `ecn` should be copied from the [`noq_udp::RecvMeta`] if known.
    /// `payload` must be exactly one datagram (one GRO segment), not a batch.
    ///
    /// Non-blocking and callable from any thread.  On success the endpoint's
    /// driver is woken to process the packet.  Failure returns the payload
    /// back to the caller; a full queue should be treated as packet loss.
    pub fn inject_received(
        &self,
        src: SocketAddr,
        dst_ip: Option<IpAddr>,
        ecn: Option<noq_udp::EcnCodepoint>,
        payload: Bytes,
    ) -> Result<(), InjectError> {
        self.inject_tx
            .try_send(InjectedDatagram {
                src,
                dst_ip,
                ecn,
                payload,
            })
            .map_err(|err| match err {
                mpsc::error::TrySendError::Full(dgram) => InjectError::Full(dgram.payload),
                mpsc::error::TrySendError::Closed(dgram) => InjectError::Closed(dgram.payload),
            })
    }

    /// The maximum number of GSO segments [`try_send`] can send in one datagram batch.
    ///
    /// [`try_send`]: DelegatedUdpSocket::try_send
    pub fn max_gso_segments(&self) -> NonZeroUsize {
        self.socket.max_gso_segments()
    }

    /// The maximum number of GRO segments [`poll_recv`] may coalesce into one buffer.
    ///
    /// [`poll_recv`]: DelegatedUdpSocket::poll_recv
    pub fn gro_segments(&self) -> NonZeroUsize {
        self.socket.gro_segments()
    }

    /// Whether datagrams sent on this socket might be fragmented by the IP layer.
    pub fn may_fragment(&self) -> bool {
        self.socket.may_fragment()
    }
}

/// Error returned by [`DelegatedUdpSocket::inject_received`].
///
/// Both variants return the payload to the caller.
#[cfg_attr(not(feature = "unstable-udp-delegation"), allow(unreachable_pub))]
#[derive(Debug)]
pub enum InjectError {
    /// The injection queue is full; the endpoint driver is not keeping up.
    ///
    /// Treat as packet loss: QUIC recovers via retransmission.
    Full(Bytes),
    /// The endpoint side of the queue is gone (endpoint closed).
    Closed(Bytes),
}

impl std::fmt::Display for InjectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Full(_) => write!(f, "injection queue full"),
            Self::Closed(_) => write!(f, "endpoint closed"),
        }
    }
}

impl std::error::Error for InjectError {}
