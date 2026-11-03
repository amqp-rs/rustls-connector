//! Installs a process-level crypto provider, so it needs a test binary of its own.

use rustls_connector::{
    RustlsConnectorConfig,
    rustls::{
        self,
        crypto::{CryptoProvider, GetRandomFailed, KeyProvider, SecureRandom},
        pki_types::PrivateKeyDer,
        sign::SigningKey,
    },
};
use std::{io, sync::Arc};

#[derive(Debug)]
struct NoCrypto;

impl SecureRandom for NoCrypto {
    fn fill(&self, _: &mut [u8]) -> Result<(), GetRandomFailed> {
        Err(GetRandomFailed)
    }
}

impl KeyProvider for NoCrypto {
    fn load_private_key(
        &self,
        _: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn SigningKey>, rustls::Error> {
        Err(rustls::Error::General("no keys".into()))
    }
}

/// With a provider feature, the installed provider takes precedence over the selected one;
/// without, it is used instead of rustls's own selection, which would panic on it.
#[test]
fn installed_provider_is_used() {
    // No cipher suites, so no protocol version is supported.
    CryptoProvider {
        cipher_suites: Vec::new(),
        kx_groups: Vec::new(),
        signature_verification_algorithms: rustls::crypto::WebPkiSupportedAlgorithms {
            all: &[],
            mapping: &[],
        },
        secure_random: &NoCrypto,
        key_provider: &NoCrypto,
    }
    .install_default()
    .expect("no provider was installed yet");
    let err = RustlsConnectorConfig::default()
        .connector_with_no_client_auth()
        .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{err}");
}
