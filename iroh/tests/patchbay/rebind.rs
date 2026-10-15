//! NAT rebinding tests.
//!
//! A NAT that loses its mapping for a flow re-creates it on a new external port the next
//! time the inside host sends. To the remote, the same connection suddenly arrives from a
//! new address. noq migrates the path in place (same [`PathId`], new four-tuple); iroh must
//! surface the migration, or anything that addresses the remote by its selected path keeps
//! sending to the dead mapping.
//!
//! [`PathId`]: iroh::endpoint::PathId

use std::time::Duration;

use iroh::endpoint::PathEvent;
use n0_error::{Result, StackResultExt, StdResultExt, ensure_any};
use n0_future::StreamExt;
use n0_tracing_test::traced_test;
use patchbay::Nat;
use testdir::testdir;
use tokio::sync::oneshot;
use tracing::info;

use crate::util::{Pair, PathConnectionExt, lab_with_relay, ping_accept, ping_open};

/// The client's NAT remaps it while its direct path is live. On the server, the selected
/// path must follow the client to the new address — same path id, new remote address — and
/// `PathEvent::Migrated` plus a re-emitted `PathEvent::Selected` must announce it.
///
/// A symmetric NAT can also remap the client while the direct path is still settling, so the
/// path may migrate more than once: every migration must be announced, in order.
#[tokio::test]
#[traced_test]
async fn nat_rebinding_migrates_selected_path() -> Result {
    let (lab, relay_map, _relay_guard, guard) = lab_with_relay(testdir!()).await?;
    // Public server; the client sits behind a symmetric NAT with random ports, so a
    // flushed mapping comes back on a new external port.
    let public = lab.add_router("public").build().await?;
    let nat = lab.add_router("nat").nat(Nat::Corporate).build().await?;
    let server = lab.add_device("server").uplink(public.id()).build().await?;
    let client = lab.add_device("client").uplink(nat.id()).build().await?;

    let timeout = Duration::from_secs(15);
    let (rebound_tx, rebound_rx) = oneshot::channel();
    // The client closes the connection only once the server is done checking, so
    // neither side cuts the other off mid-step.
    let (checked_tx, checked_rx) = oneshot::channel();
    Pair::new(relay_map)
        .server(server, async move |_dev, _ep, conn| {
            let res: Result = async {
                conn.wait_ip(timeout).await.context("holepunch to direct")?;
                ping_accept(&conn, timeout)
                    .await
                    .context("ping before rebinding")?;
                // Let the direct path settle, so `before` is where it is when the NAT rebinds.
                tokio::time::sleep(Duration::from_millis(500)).await;
                let (path_id, before) = {
                    let paths = conn.paths();
                    let selected = paths
                        .iter()
                        .find(|p| p.is_selected())
                        .context("no selected path")?;
                    (selected.id(), selected.remote_addr().clone())
                };

                let mut events = conn.path_events();
                nat.flush_nat_state().await.context("flush client NAT")?;
                rebound_tx.send(()).ok();
                // The client's next packets leave the NAT on a new external port.
                ping_accept(&conn, timeout)
                    .await
                    .context("ping after rebinding")?;
                conn.wait_selected(timeout, |p| p.id() == path_id && p.remote_addr() != &before)
                    .await
                    .context("selected path did not follow the rebinding")?;

                // Collect the announcements until they go quiet. The migrations must chain
                // from `before`, and the selection must end where the last one points.
                let mut chain = vec![before.clone()];
                let mut last_selected = None;
                while let Ok(Some(event)) =
                    tokio::time::timeout(Duration::from_secs(1), events.next()).await
                {
                    match event {
                        PathEvent::Migrated {
                            id,
                            remote_addr,
                            prev_remote_addr,
                            ..
                        } if id == path_id => {
                            ensure_any!(
                                chain.last() == Some(&prev_remote_addr),
                                "Migrated from {prev_remote_addr}, but the path was announced at {:?}",
                                chain.last()
                            );
                            chain.push(remote_addr);
                        }
                        PathEvent::Selected {
                            id, remote_addr, ..
                        } if id == path_id => last_selected = Some(remote_addr),
                        _ => {}
                    }
                }
                let after = conn
                    .paths()
                    .get(path_id)
                    .context("rebound path closed")?
                    .remote_addr()
                    .clone();
                info!(?chain, "selected path migrated");
                ensure_any!(chain.len() > 1, "no PathEvent::Migrated for the rebound path");
                ensure_any!(
                    chain.last() == Some(&after),
                    "last Migrated points at {:?}, but the path is at {after}",
                    chain.last()
                );
                ensure_any!(
                    last_selected.as_ref() == Some(&after),
                    "last Selected points at {last_selected:?}, but the path is at {after}"
                );
                Ok(())
            }
            .await;
            // Release the client on failure too, so it is not left waiting.
            checked_tx.send(()).ok();
            tokio::time::timeout(timeout, conn.closed()).await.ok();
            res
        })
        .client(client, async move |_dev, _ep, conn| {
            conn.wait_ip(timeout).await.context("holepunch to direct")?;
            ping_open(&conn, timeout)
                .await
                .context("ping before rebinding")?;
            rebound_rx
                .await
                .std_context("server did not signal the rebinding")?;
            ping_open(&conn, timeout)
                .await
                .context("ping after rebinding")?;
            tokio::time::timeout(timeout, checked_rx).await.ok();
            conn.close(0u32.into(), b"bye");
            Ok(())
        })
        .run()
        .await?;

    guard.ok();
    Ok(())
}
