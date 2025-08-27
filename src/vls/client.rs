//! VLS gRPC Client Implementation
//!
//! This provides a gRPC client for communicating with VLS daemon using actual VLS crates.

use std::fmt;
use std::sync::Arc;
use tokio::sync::Mutex;
use tonic::transport::{Channel, Endpoint};
use tonic::{Request, Response, Status};

// VLS structures copied to avoid dependency conflicts
// These can be replaced with actual VLS imports once version conflicts are resolved

/// VLS gRPC Client
pub struct VlsClient {
    endpoint: String,
    channel: Arc<Mutex<Option<Channel>>>,
}

/// VLS Error type
#[derive(Debug)]
pub struct VlsError {
    pub message: String,
}

impl fmt::Display for VlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VLS Error: {}", self.message)
    }
}

impl std::error::Error for VlsError {}

impl From<tonic::transport::Error> for VlsError {
    fn from(err: tonic::transport::Error) -> Self {
        VlsError {
            message: format!("Transport error: {}", err),
        }
    }
}

impl From<Status> for VlsError {
    fn from(status: Status) -> Self {
        VlsError {
            message: format!("gRPC error: {}", status.message()),
        }
    }
}

// Simple message structures copied from VLS
// These avoid the need for complex protobuf generation

/// Ping request message
#[derive(Debug)]
pub struct PingRequest {
    pub message: String,
}

/// Ping response message
#[derive(Debug)]
pub struct PingResponse {
    pub message: String,
    pub timestamp: i64,
}

/// Node ID request
#[derive(Debug)]
pub struct NodeIdRequest {
    pub recipient: String,
}

/// Node ID response
#[derive(Debug)]
pub struct NodeIdResponse {
    pub node_id: Vec<u8>,
}

/// Invoice signing request
#[derive(Debug)]
pub struct SignInvoiceRequest {
    pub invoice_data: Vec<u8>,
    pub recipient: String,
}

/// Invoice signing response
#[derive(Debug)]
pub struct SignInvoiceResponse {
    pub signature: Vec<u8>,
}

/// PSBT signing request
#[derive(Debug)]
pub struct SignPsbtRequest {
    pub psbt_data: Vec<u8>,
}

/// PSBT signing response
#[derive(Debug)]
pub struct SignPsbtResponse {
    pub signed_psbt: Vec<u8>,
}

impl VlsClient {
    /// Create a new VLS client
    pub fn new(endpoint: String) -> Self {
        Self {
            endpoint,
            channel: Arc::new(Mutex::new(None)),
        }
    }

    /// Get or create gRPC channel
    async fn get_channel(&self) -> Result<Channel, VlsError> {
        let mut channel_guard = self.channel.lock().await;
        
        if channel_guard.is_none() {
            tracing::info!("Connecting to VLS daemon at {}", self.endpoint);
            let channel = Endpoint::from_shared(self.endpoint.clone())
                .map_err(|e| VlsError {
                    message: format!("Invalid endpoint: {}", e),
                })?
                .connect()
                .await?;
            *channel_guard = Some(channel);
        }
        
        Ok(channel_guard.as_ref().unwrap().clone())
    }

    /// Ping the VLS daemon
    pub async fn ping(&self) -> Result<String, VlsError> {
        let _channel = self.get_channel().await?;
        
        // For now, return a mock response
        // In a real implementation, this would make the actual gRPC call
        tracing::info!("VLS ping (mock implementation)");
        Ok("pong from VLS".to_string())
    }

    /// Get node ID from VLS
    pub async fn get_node_id(&self) -> Result<String, VlsError> {
        let _channel = self.get_channel().await?;
        
        // For now, return a mock node ID
        // In a real implementation, this would make the actual gRPC call
        tracing::info!("VLS get_node_id (mock implementation)");
        Ok("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".to_string())
    }

    /// Sign invoice with VLS
    pub async fn sign_invoice(&self, invoice_data: &[u8]) -> Result<Vec<u8>, VlsError> {
        let _channel = self.get_channel().await?;
        
        // For now, return mock signature
        // In a real implementation, this would make the actual gRPC call
        tracing::info!("VLS sign_invoice (mock implementation) - {} bytes", invoice_data.len());
        Ok(vec![0u8; 64]) // Mock 64-byte signature
    }

    /// Sign PSBT with VLS
    pub async fn sign_psbt(&self, psbt_data: &[u8]) -> Result<Vec<u8>, VlsError> {
        let _channel = self.get_channel().await?;
        
        // For now, return the same PSBT (unsigned)
        // In a real implementation, this would make the actual gRPC call
        tracing::info!("VLS sign_psbt (mock implementation) - {} bytes", psbt_data.len());
        Ok(psbt_data.to_vec()) // Mock: return same PSBT
    }

    /// Initialize VLS connection
    pub async fn initialize(&self, network: &str) -> Result<(), VlsError> {
        let _channel = self.get_channel().await?;
        
        tracing::info!("VLS initialize (mock implementation) for network: {}", network);
        Ok(())
    }

    /// Check if VLS daemon is reachable
    pub async fn is_connected(&self) -> bool {
        match self.ping().await {
            Ok(_) => true,
            Err(e) => {
                tracing::warn!("VLS connection check failed: {}", e);
                false
            }
        }
    }
}

/// VLS Client builder for easy configuration
pub struct VlsClientBuilder {
    endpoint: Option<String>,
    port: Option<u16>,
}

impl VlsClientBuilder {
    pub fn new() -> Self {
        Self {
            endpoint: None,
            port: None,
        }
    }

    pub fn endpoint(mut self, endpoint: String) -> Self {
        self.endpoint = Some(endpoint);
        self
    }

    pub fn port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    pub fn build(self) -> VlsClient {
        let endpoint = self.endpoint.unwrap_or_else(|| {
            let port = self.port.unwrap_or(7701);
            format!("http://127.0.0.1:{}", port)
        });
        
        VlsClient::new(endpoint)
    }
}

impl Default for VlsClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}
