//! VLS (Validating Lightning Signer) gRPC Integration
//!
//! This module provides a gRPC endpoint that VLS can subscribe to and communicate through.
//! It creates the transport layer and keys manager for VLS integration.

#[cfg(feature = "vls")]
pub mod client;



#[cfg(not(feature = "vls"))]
pub mod client {
    //! VLS client stub when feature is disabled
    
    use std::fmt;
    use std::sync::Arc;
    use bitcoin::{Network, Address};
    use url::Url;
    use crate::vls::Shutter;
    
    #[derive(Debug)]
    pub struct VlsKeysManager;
    
    #[derive(Debug)]
    pub struct VlsError {
        pub message: String,
    }
    
    impl fmt::Display for VlsError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "VLS not enabled: {}", self.message)
        }
    }
    
    impl std::error::Error for VlsError {}
    
    pub async fn make_grpc_signer(
        _shutter: Shutter,
        _signer_handle: tokio::runtime::Handle,
        _vls_port: u16,
        _network: Network,
        _ldk_data_dir: String,
        _sweep_address: Address,
        _bitcoin_rpc_url: Url,
    ) -> Result<Arc<VlsKeysManager>, VlsError> {
        Err(VlsError { message: "VLS feature not enabled".to_string() })
    }
}


/// VLS gRPC endpoint status check
pub fn is_vls_available() -> bool {
    cfg!(feature = "vls")
}

/// Check if VLS feature is enabled
pub fn is_vls_enabled() -> bool {
    cfg!(feature = "vls")
}

/// Create VLS gRPC signer with HsmdService (main factory function)
#[cfg(feature = "vls")]
pub async fn make_grpc_signer(
    shutter: Shutter,
    signer_handle: tokio::runtime::Handle,
    vls_port: u16,
    network: bitcoin::Network,
    ldk_data_dir: String,
    sweep_address: bitcoin::Address,
    bitcoin_rpc_url: url::Url,
) -> Result<std::sync::Arc<client::VlsKeysManager>, client::VlsError> {
    client::make_grpc_signer(shutter, signer_handle, vls_port, network, ldk_data_dir, sweep_address, bitcoin_rpc_url).await
}

#[cfg(not(feature = "vls"))]
pub async fn make_grpc_signer(
    _shutter: Shutter,
    _signer_handle: tokio::runtime::Handle,
    _vls_port: u16,
    _network: bitcoin::Network,
    _ldk_data_dir: String,
    _sweep_address: bitcoin::Address,
    _bitcoin_rpc_url: url::Url,
) -> Result<std::sync::Arc<client::VlsKeysManager>, client::VlsError> {
    Err(client::VlsError { message: "VLS feature not enabled".to_string() })
}


/// Shutdown coordination type
#[derive(Clone)]
pub struct Shutter {
    pub trigger: triggered::Trigger,
    pub signal: triggered::Listener,
}

impl Shutter {
    /// There should only be one of these per process
    pub fn new() -> Self {
        let (trigger, signal) = triggered::trigger();
        let ctrlc_trigger = trigger.clone();
        ctrlc::set_handler(move || {
            tracing::info!("got termination signal");
            ctrlc_trigger.trigger();
        })
        .expect("Error setting Ctrl-C handler - do you have more than one?");

        Self { trigger, signal }
    }
}