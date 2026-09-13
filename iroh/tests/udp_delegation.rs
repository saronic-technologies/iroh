//! End-to-end tests for the delegated UDP receive path (`unstable-udp-delegation`).
//!
//! These tests emulate what an external dataplane does with the delegation API:
//! a plain OS thread (no async runtime) becomes the sole reader of the
//! endpoint's UDP sockets, classifies every datagram by its first byte, keeps
//! the non-QUIC ones (first byte `0x00..=0x3F`) and re-injects the QUIC ones
//! into the endpoint.  A full QUIC connection is established *through* that
//! pump, and raw datagrams are exchanged on the same sockets — the same
//! 4-tuple — concurrently with QUIC traffic.
#![cfg(all(feature = "unstable-udp-delegation", not(wasm_browser)))]

use std::{
    io::IoSliceMut,
    net::{Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
    thread,
};

use bytes::Bytes;
use iroh::{
    Endpoint, EndpointAddr, endpoint::presets, unstable_udp_delegation::DelegatedUdpSocket,
};
use n0_error::{Result, StdResultExt};
use n0_future::time::{self, Duration};

const ECHO_ALPN: &[u8] = b"delegation-echo";

/// First bytes `0x00..=0x3F` never collide with QUIC: iroh disables QUIC
/// fixed-bit greasing, so every QUIC packet has bit `0x40` set.
const MAX_NON_QUIC_KIND: u8 = 0x3F;

/// A waker that unparks the pump thread.
struct ThreadWaker(thread::Thread);

impl Wake for ThreadWaker {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.unpark();
    }
}

/// A datagram consumed by the pump (i.e. not QUIC).
#[derive(Debug)]
struct RawDatagram {
    src: SocketAddr,
    payload: Vec<u8>,
}

/// Spawns the "dataplane" thread: the sole reader of the delegated sockets.
///
/// QUIC datagrams are re-injected into the endpoint, everything else is
/// forwarded to `raw_tx` for the test to assert on.  Deliberately runs on a
/// plain `std::thread` with a parking waker to prove the API needs no runtime.
fn spawn_pump(
    name: &'static str,
    socks: Vec<DelegatedUdpSocket>,
    raw_tx: tokio::sync::mpsc::UnboundedSender<RawDatagram>,
    stop: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    thread::Builder::new()
        .name(format!("pump-{name}"))
        .spawn(move || {
            let waker = Waker::from(Arc::new(ThreadWaker(thread::current())));
            let mut cx = Context::from_waker(&waker);
            // One receive buffer per socket, sized for a full GRO batch.
            let mut backings: Vec<Vec<u8>> = socks
                .iter()
                .map(|s| vec![0u8; 1500 * s.gro_segments().get()])
                .collect();
            loop {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                let mut made_progress = false;
                for (sock, backing) in socks.iter().zip(backings.iter_mut()) {
                    let mut bufs = [IoSliceMut::new(backing.as_mut_slice())];
                    let mut metas = [noq_udp::RecvMeta::default()];
                    match sock.poll_recv(&mut cx, &mut bufs, &mut metas) {
                        Poll::Ready(Ok(n)) => {
                            made_progress = true;
                            for meta in metas.iter().take(n) {
                                if meta.len == 0 {
                                    continue;
                                }
                                let src = SocketAddr::new(
                                    meta.addr.ip().to_canonical(),
                                    meta.addr.port(),
                                );
                                // GRO can coalesce several datagrams into one buffer;
                                // classification must happen per stride segment.
                                let stride = if meta.stride == 0 {
                                    meta.len
                                } else {
                                    meta.stride
                                };
                                for segment in backing[..meta.len].chunks(stride) {
                                    if segment[0] > MAX_NON_QUIC_KIND {
                                        // QUIC: hand it back to the endpoint. The source
                                        // address is passed through verbatim (not
                                        // canonicalized) to preserve IPv6 scope ids.
                                        sock.inject_received(
                                            meta.addr,
                                            meta.dst_ip,
                                            meta.ecn,
                                            Bytes::copy_from_slice(segment),
                                        )
                                        .expect("injection queue closed or full");
                                    } else {
                                        // Ours: a dataplane datagram.
                                        raw_tx
                                            .send(RawDatagram {
                                                src,
                                                payload: segment.to_vec(),
                                            })
                                            .expect("test receiver dropped");
                                    }
                                }
                            }
                        }
                        Poll::Ready(Err(err)) => {
                            if stop.load(Ordering::Relaxed) {
                                return;
                            }
                            panic!("pump-{name} recv error: {err:#}");
                        }
                        Poll::Pending => {}
                    }
                }
                if !made_progress {
                    // Wakers fire on socket readability; the timeout is a
                    // safety net for the stop flag.
                    thread::park_timeout(Duration::from_millis(20));
                }
            }
        })
        .expect("failed to spawn pump thread")
}

/// Sends a raw datagram, retrying on `WouldBlock` (e.g. while a fresh socket's
/// write readiness is still unknown, or during a rebind).
fn send_raw(sock: &DelegatedUdpSocket, dst: SocketAddr, payload: &[u8]) {
    for _ in 0..500 {
        match sock.try_send(&noq_udp::Transmit {
            destination: dst,
            ecn: None,
            contents: payload,
            segment_size: None,
            src_ip: None,
        }) {
            Ok(()) => return,
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(1));
            }
            Err(err) => panic!("raw send failed: {err:#}"),
        }
    }
    panic!("raw send kept returning WouldBlock");
}

fn ipv4_handle(socks: &[DelegatedUdpSocket]) -> DelegatedUdpSocket {
    socks
        .iter()
        .find(|s| s.is_ipv4())
        .expect("no IPv4 socket bound")
        .clone()
}

fn dial_addr(socks: &[DelegatedUdpSocket]) -> SocketAddr {
    let port = ipv4_handle(socks).local_addr().port();
    assert_ne!(port, 0, "socket not bound");
    SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quic_and_raw_datagrams_via_delegated_recv() -> Result {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init()
        .ok();

    let server = Endpoint::builder(presets::Minimal)
        .alpns(vec![ECHO_ALPN.to_vec()])
        .delegate_udp_recv()
        .bind()
        .await?;
    let client = Endpoint::builder(presets::Minimal)
        .delegate_udp_recv()
        .bind()
        .await?;

    let server_socks = server.delegated_udp_sockets();
    let client_socks = client.delegated_udp_sockets();
    assert!(!server_socks.is_empty());
    assert!(!client_socks.is_empty());

    let stop = Arc::new(AtomicBool::new(false));
    let (server_raw_tx, mut server_raw_rx) = tokio::sync::mpsc::unbounded_channel();
    let (client_raw_tx, mut client_raw_rx) = tokio::sync::mpsc::unbounded_channel();
    let pumps = [
        spawn_pump("server", server_socks.clone(), server_raw_tx, stop.clone()),
        spawn_pump("client", client_socks.clone(), client_raw_tx, stop.clone()),
    ];

    // Server side: echo every bi stream on every connection.
    let server_task = tokio::spawn({
        let server = server.clone();
        async move {
            while let Some(incoming) = server.accept().await {
                let conn = incoming.await?;
                tokio::spawn(async move {
                    while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                        let msg = recv.read_to_end(64 * 1024).await.anyerr()?;
                        send.write_all(&msg).await.anyerr()?;
                        send.finish().anyerr()?;
                    }
                    n0_error::Ok(())
                });
            }
            n0_error::Ok(())
        }
    });

    // 1) A QUIC connection established entirely through the pump threads.
    let server_addr = dial_addr(&server_socks);
    let addr = EndpointAddr::new(server.id()).with_ip_addr(server_addr);
    let conn = time::timeout(Duration::from_secs(30), client.connect(addr, ECHO_ALPN))
        .await
        .std_context("connect timed out (pump not delivering QUIC packets?)")??;

    let (mut send, mut recv) = conn.open_bi().await.anyerr()?;
    send.write_all(b"hello through the pump").await.anyerr()?;
    send.finish().anyerr()?;
    let echoed = recv.read_to_end(64 * 1024).await.anyerr()?;
    assert_eq!(echoed, b"hello through the pump");

    // 2) Raw datagrams on the same sockets, both directions, including the
    //    kind-space boundary values.
    let client_v4 = ipv4_handle(&client_socks);
    let server_v4 = ipv4_handle(&server_socks);
    let client_addr = dial_addr(&client_socks);

    for kind in [0x00u8, 0x01, MAX_NON_QUIC_KIND] {
        let payload = [&[kind][..], b"raw-dataplane-payload"].concat();
        send_raw(&client_v4, server_addr, &payload);
        let received = time::timeout(Duration::from_secs(10), server_raw_rx.recv())
            .await
            .std_context("timed out waiting for raw datagram at server")?
            .expect("raw channel closed");
        assert_eq!(received.payload, payload);
        assert_eq!(received.src.port(), client_v4.local_addr().port());

        send_raw(&server_v4, client_addr, &payload);
        let received = time::timeout(Duration::from_secs(10), client_raw_rx.recv())
            .await
            .std_context("timed out waiting for raw datagram at client")?
            .expect("raw channel closed");
        assert_eq!(received.payload, payload);
    }

    // 3) Raw flood concurrent with QUIC traffic on the same 4-tuple: neither
    //    starves the other.
    const FLOOD: usize = 300;
    let flood_sender = {
        let client_v4 = client_v4.clone();
        tokio::task::spawn_blocking(move || {
            for i in 0..FLOOD {
                let payload = [0x01u8, (i >> 8) as u8, i as u8];
                send_raw(&client_v4, server_addr, &payload);
            }
        })
    };
    let quic_load = async {
        for _ in 0..20 {
            let (mut send, mut recv) = conn.open_bi().await.anyerr()?;
            send.write_all(&[0xAB; 4096]).await.anyerr()?;
            send.finish().anyerr()?;
            let echoed = recv.read_to_end(64 * 1024).await.anyerr()?;
            assert_eq!(echoed.len(), 4096);
        }
        n0_error::Ok(())
    };
    let raw_drain = async {
        let mut got = 0;
        while got < FLOOD {
            let dgram = server_raw_rx.recv().await.expect("raw channel closed");
            assert_eq!(dgram.payload[0], 0x01);
            got += 1;
        }
        n0_error::Ok(())
    };
    let (quic_res, raw_res) = tokio::join!(
        time::timeout(Duration::from_secs(60), quic_load),
        time::timeout(Duration::from_secs(60), raw_drain),
    );
    quic_res.std_context("QUIC load timed out during raw flood")??;
    raw_res.std_context("raw flood not fully delivered")??;
    flood_sender.await.anyerr()?;

    // Shutdown: close endpoints first (close frames still flow through the
    // pumps), then stop the pumps.
    conn.close(0u32.into(), b"done");
    client.close().await;
    server.close().await;
    server_task.abort();

    stop.store(true, Ordering::Relaxed);
    for pump in pumps {
        pump.thread().unpark();
        pump.join().expect("pump thread panicked");
    }

    Ok(())
}
