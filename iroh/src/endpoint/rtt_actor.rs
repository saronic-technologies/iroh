//! Actor which coordinates the congestion controller for the magic socket

use std::{pin::Pin, sync::Arc, task::Poll};

use iroh_base::NodeId;
use n0_future::{
    task::{self, AbortOnDropHandle},
    MergeUnbounded, Stream, StreamExt,
};
use tokio::sync::mpsc;
use tracing::{debug, info_span, Instrument};

use crate::{magicsock::ConnectionType, metrics::MagicsockMetrics, watchable::WatcherStream};

#[derive(Debug)]
pub(super) struct RttHandle {
    // We should and some point use this to propagate panics and errors.
    pub(super) _handle: AbortOnDropHandle<()>,
    pub(super) msg_tx: mpsc::Sender<RttMessage>,
}

impl RttHandle {
    pub(super) fn new(metrics: Arc<MagicsockMetrics>) -> Self {
        let mut actor = RttActor {
            connection_events: Default::default(),
            metrics,
        };
        let (msg_tx, msg_rx) = mpsc::channel(16);
        let handle = task::spawn(
            async move {
                actor.run(msg_rx).await;
            }
            .instrument(info_span!("rtt-actor")),
        );
        Self {
            _handle: AbortOnDropHandle::new(handle),
            msg_tx,
        }
    }
}

/// Messages to send to the [`RttActor`].
#[derive(Debug)]
pub(super) enum RttMessage {
    /// Informs the [`RttActor`] of a new connection is should monitor.
    NewConnection {
        /// The connection.
        connection: quinn::WeakConnectionHandle,
        /// Path changes for this connection from the magic socket.
        conn_type_changes: WatcherStream<ConnectionType>,
        /// For reporting-only, the Node ID of this connection.
        node_id: NodeId,
    },
}

/// Actor that watches magic socket path changes per connection.
///
/// Upstream uses it to reset the QUIC congestion controller on every path change; this
/// fork only keeps the connection metrics (see [`MappedStream::poll_next`]).
#[derive(derive_more::Debug)]
struct RttActor {
    /// Stream of connection type changes.
    #[debug("MergeUnbounded<WatcherStream<ConnectionType>>")]
    connection_events: MergeUnbounded<MappedStream>,
    metrics: Arc<MagicsockMetrics>,
}

#[derive(Debug)]
struct MappedStream {
    stream: WatcherStream<ConnectionType>,
    node_id: NodeId,
    /// Reference to the connection.
    connection: quinn::WeakConnectionHandle,
    /// This an indiciator of whether this connection was direct before.
    /// This helps establish metrics on number of connections that became direct.
    was_direct_before: bool,
}

struct ConnectionEvent {
    became_direct: bool,
}

impl Stream for MappedStream {
    type Item = ConnectionEvent;

    /// Observes a magic socket path change for the connection metrics.
    ///
    /// Upstream also resets the connection's congestion controller and RTT estimate here
    /// (`WeakConnectionHandle::network_path_changed`). That reset is deliberately NOT done:
    /// quinn's `pto_count` backoff exponent survives it (only an ACK clears it), so a
    /// `ConnectionType` flip during an outage leaves the next probe timeout at the initial
    /// RTT estimate times an already large backoff. On our links a flip is routinely a
    /// symptom of loss, not of a new path (trust expiry to `Mixed` when a relay URL is
    /// known, or a `Direct(a)` to `Direct(b)` candidate flip after a pong timeout), and the
    /// reset parks the sender for tens of seconds after the link is back. Keeping the
    /// measured RTT and congestion state lets the normal PTO schedule recover instead.
    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.stream).poll_next(cx) {
            Poll::Ready(Some(new_conn_type)) => {
                let mut became_direct = false;
                if self.connection.is_alive() {
                    debug!(
                        node_id = %self.node_id.fmt_short(),
                        new_type = ?new_conn_type,
                        "Network path changed, congestion controller state kept",
                    );
                    if !self.was_direct_before && matches!(new_conn_type, ConnectionType::Direct(_))
                    {
                        self.was_direct_before = true;
                        became_direct = true
                    }
                };
                Poll::Ready(Some(ConnectionEvent { became_direct }))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl RttActor {
    /// Runs the actor main loop.
    ///
    /// The main loop will finish when the sender is dropped.
    async fn run(&mut self, mut msg_rx: mpsc::Receiver<RttMessage>) {
        loop {
            tokio::select! {
                biased;
                msg = msg_rx.recv() => {
                    match msg {
                        Some(msg) => self.handle_msg(msg),
                        None => break,
                    }
                }
                event = self.connection_events.next(), if !self.connection_events.is_empty() => {
                    if event.map(|e| e.became_direct).unwrap_or(false) {
                        self.metrics.connection_became_direct.inc();
                    }
                }
            }
        }
        debug!("rtt-actor finished");
    }

    /// Handle actor messages.
    fn handle_msg(&mut self, msg: RttMessage) {
        match msg {
            RttMessage::NewConnection {
                connection,
                conn_type_changes,
                node_id,
            } => {
                self.handle_new_connection(connection, conn_type_changes, node_id);
            }
        }
    }

    /// Handles the new connection message.
    fn handle_new_connection(
        &mut self,
        connection: quinn::WeakConnectionHandle,
        conn_type_changes: WatcherStream<ConnectionType>,
        node_id: NodeId,
    ) {
        self.connection_events.push(MappedStream {
            stream: conn_type_changes,
            connection,
            node_id,
            was_direct_before: false,
        });
        self.metrics.connection_handshake_success.inc();
    }
}
