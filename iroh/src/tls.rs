//! TLS configuration for iroh.
//!
//! Currently there is one mechanism available:
//! - Raw Public Keys, using the TLS extension described in [RFC 7250]
//!
//! [RFC 7250]: https://datatracker.ietf.org/doc/html/rfc7250

use std::sync::Arc;

use iroh_base::SecretKey;
use noq::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::crypto::CryptoProvider;
use tracing::warn;

use self::resolver::ResolveRawPublicKeyCert;

pub(crate) mod misc;
pub(crate) mod name;
mod resolver;
mod verifier;

#[allow(deprecated)] // Re-export of backwards-compatibility item
pub use iroh_relay::tls::CaRootsConfig;
pub use iroh_relay::tls::CaTlsConfig;
#[cfg(with_crypto_provider)]
pub use iroh_relay::tls::default_provider;

/// Maximum amount of TLS tickets we will cache (by default) for 0-RTT connection
/// establishment.
///
/// 8 tickets per remote endpoint, 32 different endpoints would max out the required storage:
/// ~200 bytes per session + certificates (which are ~387 bytes)
/// So 8 * 32 * (200 + 387) = 150.272 bytes, assuming pointers to certificates
/// are never aliased pointers (they're Arc'ed).
/// I think 150KB is an acceptable default upper limit for such a cache.
pub(crate) const DEFAULT_MAX_TLS_TICKETS: usize = 8 * 32;

/// Parameters for constructing a [`TlsConfig`].
///
/// This bundles the TLS components that can be customized when building an
/// endpoint: certificate resolvers, certificate verifiers, session storage,
/// and ticket cache sizing. A default set of parameters is used by
/// [`TlsConfig::new_default`]; pass a custom instance to [`TlsConfig::new`]
/// to override individual components.
#[derive(Debug)]
pub struct EndpointTlsConfigParams {
    /// Resolver that provides the client certificate during TLS handshakes.
    pub client_cert_resolver: Arc<dyn rustls::client::ResolvesClientCert>,

    /// Resolver that provides the server certificate during TLS handshakes.
    pub server_cert_resolver: Arc<dyn rustls::server::ResolvesServerCert>,

    /// Verifier used to validate server certificates presented by peers.
    pub server_verifier: Arc<dyn rustls::client::danger::ServerCertVerifier>,

    /// Verifier used to validate client certificates presented by peers.
    pub client_verifier: Arc<dyn rustls::server::danger::ClientCertVerifier>,

    /// Storage backend for TLS client session data (tickets, etc.).
    pub session_store: Arc<dyn rustls::client::ClientSessionStore>,

    /// Crypto provider used for all TLS crypto operations
    pub crypto_provider: Arc<CryptoProvider>,
}

/// Configuration for TLS.
///
/// The main point of this struct is to keep state that should be kept the same
/// over multiple TLS sessions the same.
/// E.g. the `server_verifier` and `client_verifier` Arc pointers are checked to be
/// the same between different TLS session calls with 0-RTT data in rustls.
/// This makes sure that's the case.
#[derive(Debug)]
pub(crate) struct TlsConfig {
    pub(crate) secret_key: SecretKey,
    client_cert_resolver: Arc<dyn rustls::client::ResolvesClientCert>,
    server_cert_resolver: Arc<dyn rustls::server::ResolvesServerCert>,
    server_verifier: Arc<dyn rustls::client::danger::ServerCertVerifier>,
    client_verifier: Arc<dyn rustls::server::danger::ClientCertVerifier>,
    session_store: Arc<dyn rustls::client::ClientSessionStore>,
    crypto_provider: Arc<CryptoProvider>,
}

impl TlsConfig {
    pub(crate) fn new(
        secret_key: SecretKey,
        endpoint_tls_config_params: EndpointTlsConfigParams,
    ) -> Self {
        Self {
            secret_key,
            client_cert_resolver: endpoint_tls_config_params.client_cert_resolver,
            server_cert_resolver: endpoint_tls_config_params.server_cert_resolver,
            server_verifier: endpoint_tls_config_params.server_verifier,
            client_verifier: endpoint_tls_config_params.client_verifier,
            session_store: endpoint_tls_config_params.session_store,
            crypto_provider: endpoint_tls_config_params.crypto_provider,
        }
    }

    pub(crate) fn new_default(
        secret_key: SecretKey,
        max_tls_tickets: usize,
        crypto_provider: Arc<CryptoProvider>,
    ) -> Self {
        let cert_resolver = Arc::new(ResolveRawPublicKeyCert::new(&secret_key));

        let session_store = rustls::client::ClientSessionMemoryCache::new(max_tls_tickets);

        let endpoint_tls_config_params = EndpointTlsConfigParams {
            client_cert_resolver: cert_resolver.clone(),
            server_cert_resolver: cert_resolver,
            server_verifier: Arc::new(verifier::ServerCertificateVerifier),
            client_verifier: Arc::new(verifier::ClientCertificateVerifier),
            session_store: Arc::new(session_store),
            crypto_provider,
        };

        Self::new(secret_key, endpoint_tls_config_params)
    }

    /// Create a TLS client configuration.
    ///
    /// If *keylog* is `true` this will enable logging of the pre-master key to the file in the
    /// `SSLKEYLOGFILE` environment variable.  This can be used to inspect the traffic for
    /// debugging purposes.
    pub(crate) fn make_client_config(
        &self,
        keylog: bool,
    ) -> Result<QuicClientConfig, TlsConfigError> {
        let mut crypto = rustls::ClientConfig::builder_with_provider(self.crypto_provider.clone())
            .with_protocol_versions(verifier::PROTOCOL_VERSIONS)?
            .dangerous()
            .with_custom_certificate_verifier(self.server_verifier.clone())
            .with_client_cert_resolver(self.client_cert_resolver.clone());

        // TODO: enable/disable 0-RTT/storing tickets
        crypto.resumption = rustls::client::Resumption::store(self.session_store.clone());
        crypto.enable_early_data = true;

        if keylog {
            warn!("enabling SSLKEYLOGFILE for TLS pre-master keys");
            crypto.key_log = Arc::new(rustls::KeyLogFile::new());
        }

        let quic = QuicClientConfig::try_from(crypto)?;
        Ok(quic)
    }

    /// Create a TLS server configuration.
    ///
    /// If *keylog* is `true` this will enable logging of the pre-master key to the file in the
    /// `SSLKEYLOGFILE` environment variable.  This can be used to inspect the traffic for
    /// debugging purposes.
    pub(crate) fn make_server_config(
        &self,
        keylog: bool,
    ) -> Result<QuicServerConfig, TlsConfigError> {
        let mut crypto = rustls::ServerConfig::builder_with_provider(self.crypto_provider.clone())
            .with_protocol_versions(verifier::PROTOCOL_VERSIONS)?
            .with_client_cert_verifier(self.client_verifier.clone())
            .with_cert_resolver(self.server_cert_resolver.clone());
        if keylog {
            warn!("enabling SSLKEYLOGFILE for TLS pre-master keys");
            crypto.key_log = Arc::new(rustls::KeyLogFile::new());
        }

        // must be u32::MAX or 0 (the default). Any other value panics with QUIC
        // This is specified in RFC 9001: https://www.rfc-editor.org/rfc/rfc9001#section-4.6.1
        crypto.max_early_data_size = u32::MAX;
        let quic = QuicServerConfig::try_from(crypto)?;
        Ok(quic)
    }
}

#[allow(missing_docs)]
#[n0_error::stack_error(derive, add_meta, from_sources)]
#[non_exhaustive]
pub enum TlsConfigError {
    #[error(
        "The configured crypto provider is missing support for TLS13_AES_128_GCM_SHA256, which is required for QUIC initial packets."
    )]
    CryptoProviderNoInitialCipherSuite {
        #[error(std_err)]
        source: noq::crypto::rustls::NoInitialCipherSuite,
    },
    #[error("The configured crypto provider is incompatible with iroh and QUIC encryption")]
    CryptoProviderIncompatible {
        #[error(std_err)]
        source: rustls::Error,
    },
}
