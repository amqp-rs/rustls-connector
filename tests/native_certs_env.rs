//! Sets `SSL_CERT_FILE`, so it needs a test binary of its own.
#![cfg(all(feature = "platform-verifier", feature = "native-certs"))]

use rustls_connector::{RustlsConnectorConfig, rustls_native_certs};

/// `with_native_certs()` decides whether the platform verifier needs the certificates from the
/// environment it loads them with, and later calls add to them.
#[test]
fn native_certs_decision_follows_their_environment() {
    // SAFETY: no other thread of this process reads or writes the environment meanwhile.
    unsafe {
        std::env::set_var(
            "SSL_CERT_FILE",
            concat!(env!("CARGO_MANIFEST_DIR"), "/test-data/ca.pem"),
        );
        std::env::remove_var("SSL_CERT_DIR");
    }
    let config = RustlsConnectorConfig::new_with_platform_verifier()
        .with_native_certs()
        .unwrap();
    // SAFETY: as above.
    unsafe { std::env::remove_var("SSL_CERT_FILE") };
    // It loads them itself on Unix systems other than Apple platforms, Android and wasm32.
    let needed = !cfg!(all(
        unix,
        not(target_os = "android"),
        not(target_vendor = "apple"),
        not(target_arch = "wasm32")
    ));
    let expect = |config: &RustlsConnectorConfig, certs: usize| {
        let debug = format!("{config:?}");
        assert!(
            debug.contains(&format!("native_certs: {certs},")),
            "{debug}"
        );
        assert!(
            debug.contains(&format!("native_certs_needed: {needed},")),
            "{debug}"
        );
    };
    expect(&config, 1);
    // A call loading the OS store adds its certificates, and keeps the decision of the first.
    let os_store = rustls_native_certs::load_native_certs().certs.len();
    if os_store > 0 {
        expect(&config.with_native_certs().unwrap(), 1 + os_store);
    }
}
