//! Example demonstrating FIPS-validated post-quantum crypto with iroh.
//!
//! This example uses the `AwsLcRsFipsCryptoConfig` which configures iroh to use
//! exclusively FIPS-approved cryptographic operations with X25519MLKEM768 as the
//! only key exchange group, providing post-quantum security.
//!
//! ## Usage
//!
//!     cargo run --example fips --features=aws-lc-rs-fips

use iroh::{
    AwsLcRsFipsCryptoConfig, Endpoint, EndpointAddr,
    endpoint::Connection,
    protocol::{AcceptError, ProtocolHandler, Router},
};
use n0_error::{Result, StdResultExt};

const ALPN: &[u8; 24] = b"iroh-example/fips-echo/0";

#[tokio::main]
async fn main() -> Result<()> {
    // Verify FIPS mode is active at runtime.
    aws_lc_rs::try_fips_mode().expect("FIPS mode must be enabled");
    println!("FIPS mode verified: active");

    let router = start_accept_side().await?;
    router.endpoint().online().await;

    let addr = router.endpoint().addr();
    println!("accepting endpoint addr: {addr:?}");

    connect_side(addr).await?;

    router.shutdown().await.anyerr()?;

    println!("FIPS PQC echo example completed successfully");
    Ok(())
}

async fn connect_side(addr: EndpointAddr) -> Result<()> {
    // Build the connecting endpoint with the FIPS PQC crypto config.
    let endpoint = Endpoint::builder()
        .crypto_config(AwsLcRsFipsCryptoConfig)
        .bind()
        .await?;

    println!("connecting with X25519MLKEM768 key exchange...");
    let conn = endpoint.connect(addr, ALPN).await?;
    println!("connection established (post-quantum FIPS TLS 1.3)");

    let (mut send, mut recv) = conn.open_bi().await.anyerr()?;

    let msg = b"Hello from a FIPS post-quantum world!";
    send.write_all(msg).await.anyerr()?;
    send.finish().anyerr()?;

    let response = recv.read_to_end(1000).await.anyerr()?;
    assert_eq!(&response, msg);
    println!(
        "echo verified: {:?}",
        std::str::from_utf8(&response).unwrap()
    );

    conn.close(0u32.into(), b"bye!");
    endpoint.close().await;
    Ok(())
}

async fn start_accept_side() -> Result<Router> {
    // Build the accepting endpoint with the FIPS PQC crypto config.
    let endpoint = Endpoint::builder()
        .crypto_config(AwsLcRsFipsCryptoConfig)
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await?;

    let router = Router::builder(endpoint).accept(ALPN, FipsEcho).spawn();

    Ok(router)
}

#[derive(Debug, Clone)]
struct FipsEcho;

impl ProtocolHandler for FipsEcho {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let endpoint_id = connection.remote_id();
        println!("accepted FIPS connection from {endpoint_id}");

        let (mut send, mut recv) = connection.accept_bi().await?;
        let bytes_sent = tokio::io::copy(&mut recv, &mut send).await?;
        println!("echoed {bytes_sent} byte(s)");
        send.finish()?;

        connection.closed().await;
        Ok(())
    }
}
