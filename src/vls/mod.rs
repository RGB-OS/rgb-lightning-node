//! VLS (Validating Lightning Signer) gRPC Client
//!
//! This module provides a simple gRPC client for communicating with VLS daemon.
//! It works alongside the existing KeysManager without replacing it.

#[cfg(feature = "vls")]
pub mod client;

#[cfg(not(feature = "vls"))]
pub mod client {
    //! VLS client stub when feature is disabled
    
    use std::fmt;
    
    #[derive(Debug)]
    pub struct VlsClient;
    
    #[derive(Debug)]
    pub struct VlsError(String);
    
    impl fmt::Display for VlsError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "VLS not enabled: {}", self.0)
        }
    }
    
    impl std::error::Error for VlsError {}
    
    impl VlsClient {
        pub fn new(_endpoint: String) -> Self {
            Self
        }
        
        pub async fn ping(&self) -> Result<String, VlsError> {
            Err(VlsError("VLS feature not enabled".to_string()))
        }
        
        pub async fn get_node_id(&self) -> Result<String, VlsError> {
            Err(VlsError("VLS feature not enabled".to_string()))
        }
        
        pub async fn sign_invoice(&self, _invoice_data: &[u8]) -> Result<Vec<u8>, VlsError> {
            Err(VlsError("VLS feature not enabled".to_string()))
        }
        
        pub async fn sign_psbt(&self, _psbt_data: &[u8]) -> Result<Vec<u8>, VlsError> {
            Err(VlsError("VLS feature not enabled".to_string()))
        }
        
        pub async fn initialize(&self, _network: &str) -> Result<(), VlsError> {
            Err(VlsError("VLS feature not enabled".to_string()))
        }
    }
}

/// VLS client factory function
pub fn create_vls_client(endpoint: String) -> client::VlsClient {
    client::VlsClient::new(endpoint)
}

/// Check if VLS feature is enabled
pub fn is_vls_enabled() -> bool {
    cfg!(feature = "vls")
}
