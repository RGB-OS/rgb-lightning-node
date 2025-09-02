//! VLS (Validating Lightning Signer) gRPC Integration
//!
//! This module provides a gRPC endpoint that VLS can subscribe to and communicate through.
//! It creates the transport layer and keys manager for VLS integration.

#[cfg(feature = "vls")]
pub mod client;

/// Check if VLS feature is enabled
pub fn is_vls_enabled() -> bool {
    cfg!(feature = "vls")
}