//! Crypto provider configuration for iroh's TLS layer.
//!
//! This module defines the [`CryptoConfig`] trait which abstracts the crypto backend
//! used by iroh for TLS connections. It bundles three concerns:
//!
//! 1. The rustls [`CryptoProvider`] (cipher suites, key exchange groups, etc.)
//! 2. EdDSA signing key loading from PKCS#8 DER
//! 3. The set of signature verification algorithms used for peer verification
//!
//! # Built-in implementations
//!
//! - [`RingCryptoConfig`] (default)
//! - [`AwsLcRsFipsCryptoConfig`] (requires the `aws-lc-rs-fips` feature)
//!
//! # Custom implementations
//!
//! Users can implement this trait to use a custom crypto backend.
//!
//! [`CryptoProvider`]: rustls::crypto::CryptoProvider

use std::sync::Arc;

use rustls::{
    SignatureScheme,
    crypto::{CryptoProvider, WebPkiSupportedAlgorithms},
    sign::SigningKey,
    version::TLS13,
};
use webpki::ring as webpki_algs;
use webpki_types::PrivatePkcs8KeyDer;

/// A crypto configuration bundle for iroh's TLS layer.
///
/// This trait abstracts the crypto backend used by iroh for TLS connections.
/// Implement this trait to use a different crypto backend than the default (ring).
///
/// # Example
///
/// ```
/// use iroh::endpoint::RingCryptoConfig;
///
/// // Use the default ring-based crypto config explicitly
/// let ep = iroh::Endpoint::builder()
///     .crypto_config(RingCryptoConfig);
/// ```
pub trait CryptoConfig: std::fmt::Debug + Send + Sync + 'static {
    /// Returns the rustls [`CryptoProvider`] to use for TLS configuration.
    ///
    /// This provides cipher suites, key exchange groups, and other core TLS
    /// cryptographic primitives.
    ///
    /// [`CryptoProvider`]: rustls::crypto::CryptoProvider
    fn crypto_provider(&self) -> CryptoProvider;

    /// Load an EdDSA signing key from a PKCS#8 DER-encoded private key.
    ///
    /// This is used to create the TLS certificate resolver that signs
    /// handshake messages with the endpoint's secret key.
    fn load_eddsa_signing_key(
        &self,
        key_der: &PrivatePkcs8KeyDer<'_>,
    ) -> Result<Arc<dyn SigningKey>, rustls::Error>;

    /// Returns the set of signature verification algorithms for verifying
    /// peer certificates and TLS 1.3 handshake signatures.
    ///
    /// This should typically include at least ED25519 and the ECDSA variants
    /// needed for interoperability.
    fn supported_sig_algs(&self) -> WebPkiSupportedAlgorithms;

    /// Creates a [`rustls::ClientConfig`] for QUIC address discovery (QAD).
    ///
    /// This config is used for standard WebPKI-validated TLS connections to
    /// relay servers for address discovery, not for iroh peer-to-peer connections.
    ///
    /// The default implementation uses the crypto provider from [`Self::crypto_provider`]
    /// with the standard WebPKI root certificates and no client authentication.
    fn quic_address_discovery_client_config(&self) -> rustls::ClientConfig {
        let provider = self.crypto_provider();
        let root_store =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        rustls::ClientConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .expect("crypto provider supports the default protocol versions")
            .with_root_certificates(root_store)
            .with_no_client_auth()
    }
}

/// Crypto configuration using the `ring` backend.
///
/// This is the default crypto configuration for iroh endpoints.
#[derive(Debug, Clone, Copy, Default)]
pub struct RingCryptoConfig;

/// The supported signature algorithms for the ring crypto backend.
static RING_SUPPORTED_SIG_ALGS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        webpki_algs::ECDSA_P256_SHA256,
        webpki_algs::ECDSA_P256_SHA384,
        webpki_algs::ECDSA_P384_SHA256,
        webpki_algs::ECDSA_P384_SHA384,
        webpki_algs::ED25519,
    ],
    mapping: &[
        // Note: for TLS1.2 the curve is not fixed by SignatureScheme. For TLS1.3 it is.
        (
            SignatureScheme::ECDSA_NISTP384_SHA384,
            &[
                webpki_algs::ECDSA_P384_SHA384,
                webpki_algs::ECDSA_P256_SHA384,
            ],
        ),
        (
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &[
                webpki_algs::ECDSA_P256_SHA256,
                webpki_algs::ECDSA_P384_SHA256,
            ],
        ),
        (SignatureScheme::ED25519, &[webpki_algs::ED25519]),
    ],
};

impl CryptoConfig for RingCryptoConfig {
    fn crypto_provider(&self) -> CryptoProvider {
        rustls::crypto::ring::default_provider()
    }

    fn load_eddsa_signing_key(
        &self,
        key_der: &PrivatePkcs8KeyDer<'_>,
    ) -> Result<Arc<dyn SigningKey>, rustls::Error> {
        rustls::crypto::ring::sign::any_eddsa_type(key_der)
    }

    fn supported_sig_algs(&self) -> WebPkiSupportedAlgorithms {
        RING_SUPPORTED_SIG_ALGS.clone()
    }
}

/// The default crypto configuration.
pub type DefaultCryptoConfig = RingCryptoConfig;

/// FIPS-validated crypto configuration using the `aws-lc-rs` backend with
/// post-quantum key exchange.
///
/// This configuration uses exclusively FIPS-approved cryptographic operations
/// with X25519MLKEM768 as the only supported key exchange group, providing
/// post-quantum security through a hybrid classical/ML-KEM-768 scheme.
///
/// Only available when the `aws-lc-rs-fips` feature is enabled.
///
/// # Cipher configuration
///
/// - **Key exchange**: X25519MLKEM768 (hybrid X25519 + ML-KEM-768)
/// - **Cipher suites**: TLS 1.3 AES-256-GCM-SHA384 (preferred) and
///   AES-128-GCM-SHA256 (required by QUIC for initial handshake packets per RFC 9001)
/// - **Signatures**: ECDSA (P-256, P-384) and Ed25519
#[cfg(feature = "aws-lc-rs-fips")]
#[derive(Debug, Clone, Copy, Default)]
pub struct AwsLcRsFipsCryptoConfig;

#[cfg(feature = "aws-lc-rs-fips")]
mod aws_lc_rs_fips_impl {
    use super::*;
    use webpki::aws_lc_rs as webpki_algs;

    /// The supported signature algorithms for the aws-lc-rs FIPS crypto backend.
    static AWS_LC_RS_FIPS_SUPPORTED_SIG_ALGS: WebPkiSupportedAlgorithms =
        WebPkiSupportedAlgorithms {
            all: &[
                webpki_algs::ECDSA_P256_SHA256,
                webpki_algs::ECDSA_P256_SHA384,
                webpki_algs::ECDSA_P384_SHA256,
                webpki_algs::ECDSA_P384_SHA384,
                webpki_algs::ED25519,
            ],
            mapping: &[
                (
                    SignatureScheme::ECDSA_NISTP384_SHA384,
                    &[
                        webpki_algs::ECDSA_P384_SHA384,
                        webpki_algs::ECDSA_P256_SHA384,
                    ],
                ),
                (
                    SignatureScheme::ECDSA_NISTP256_SHA256,
                    &[
                        webpki_algs::ECDSA_P256_SHA256,
                        webpki_algs::ECDSA_P384_SHA256,
                    ],
                ),
                (SignatureScheme::ED25519, &[webpki_algs::ED25519]),
            ],
        };

    impl CryptoConfig for AwsLcRsFipsCryptoConfig {
        fn crypto_provider(&self) -> CryptoProvider {
            CryptoProvider {
                cipher_suites: vec![
                    // AES-256-GCM is the preferred negotiated cipher for data transfer.
                    rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384,
                    // AES-128-GCM is required by QUIC (RFC 9001) for initial handshake
                    // packets and must always be present.
                    rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256,
                ],
                kx_groups: vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768],
                ..rustls::crypto::aws_lc_rs::default_provider()
            }
        }

        fn load_eddsa_signing_key(
            &self,
            key_der: &PrivatePkcs8KeyDer<'_>,
        ) -> Result<Arc<dyn SigningKey>, rustls::Error> {
            rustls::crypto::aws_lc_rs::sign::any_eddsa_type(key_der)
        }

        fn supported_sig_algs(&self) -> WebPkiSupportedAlgorithms {
            AWS_LC_RS_FIPS_SUPPORTED_SIG_ALGS.clone()
        }

        fn quic_address_discovery_client_config(&self) -> rustls::ClientConfig {
            let provider = self.crypto_provider();
            let root_store =
                rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            rustls::ClientConfig::builder_with_provider(Arc::new(provider))
                .with_protocol_versions(&[&TLS13])
                .expect("crypto provider supports the default protocol versions")
                .with_root_certificates(root_store)
                .with_no_client_auth()
        }
    }
}
