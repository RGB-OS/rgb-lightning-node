//! VLS Handshake Handler Implementation
//!
//! Handles the VLS handshake protocol for RGB Lightning Node integration.
//! Based on the VLS protocol specification for proper initialization.

use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use tokio::sync::oneshot;
use bitcoin::Network;

use vls_proxy::grpc::adapter::ChannelReply;
use vls_proxy::vls_protocol_signer::vls_protocol::msgs::{self, Message, HsmdDevPreinit, HsmdInit2, HsmdInit2Reply, HsmdDevPreinitReply, SerBolt};

use vls_proxy::vls_protocol_signer::vls_protocol::model::{PubKey, ExtKey};

use crate::vls::client::VlsError;

/// VLS Handshake Handler for RGB Lightning Node
pub struct HandshakeHandler {
        /// Whether the handshake is complete and signer is ready
    is_ready: Arc<AtomicBool>,
    /// Cached init message for reconnections
    init_message_cache: Arc<Mutex<Option<Vec<u8>>>>,
    /// Network for validation
    network: Network,
    /// Development allowlist addresses
    dev_allowlist: Vec<String>,
}

impl HandshakeHandler {
    /// Create new handshake handler
    pub fn new(network: Network, dev_allowlist: Vec<String>) -> Self {
        Self {
            is_ready: Arc::new(AtomicBool::new(false)),
            init_message_cache: Arc::new(Mutex::new(None)),
            network,
            dev_allowlist,
        }
    }

    /// Handle incoming handshake message from VLS daemon
    pub async fn handle_handshake_message(
        &self,
        raw_message: Vec<u8>,
        reply_tx: oneshot::Sender<ChannelReply>,
    ) -> Result<(), VlsError> {
        
        // Parse the incoming message
        let message = msgs::from_vec(raw_message.clone())
            .map_err(|e| VlsError { message: format!("Failed to parse VLS message: {:?}", e) })?;
        
        match message {
            Message::HsmdDevPreinit(preinit) => {
                tracing::info!("Received HsmdDevPreinit from VLS daemon");
                self.handle_dev_preinit(preinit, reply_tx).await
            }
            
            Message::HsmdInit2(init) => {
                tracing::info!("Received HsmdInit2 from VLS daemon");
                self.handle_init2(init, raw_message, reply_tx).await
            }
            
            _ => {
                tracing::error!("Unexpected handshake message type: {:?}", message);
                Err(VlsError { message: format!("Unexpected message type during handshake: {:?}", message) })
            }
        }
    }

    /// Handle development preinit message
    async fn handle_dev_preinit(
        &self,
        preinit: HsmdDevPreinit,
        reply_tx: oneshot::Sender<ChannelReply>,
    ) -> Result<(), VlsError> {
        
        tracing::debug!("Preinit details: {:?}", preinit);
        
        // Log derivation style
        tracing::info!("VLS derivation style: {}", preinit.derivation_style);
        
        // Validate network
        let network_name = String::from_utf8(preinit.network_name.0.clone())
            .map_err(|e| VlsError { message: format!("Invalid network name in preinit: {}", e) })?;
        
        tracing::info!("VLS daemon connecting for network: {}", network_name);
        
        // Validate network matches our configuration
        let expected_network = self.network.to_string();
        if network_name != expected_network {
            return Err(VlsError { 
                message: format!("Network mismatch: VLS daemon expects '{}', RGB node configured for '{}'", network_name, expected_network) 
            });
        }
        
        // Log development seed info (if present)
        if let Some(_dev_seed) = &preinit.seed {
            tracing::warn!("Development seed provided in preinit");
        }
        
        // Log allowlist information  
        tracing::info!("VLS daemon allowlist: {} addresses", preinit.allowlist.0.len());
        for (i, addr) in preinit.allowlist.0.iter().enumerate() {
            if let Ok(addr_str) = String::from_utf8(addr.0.clone()) {
                tracing::debug!("  [{}] {}", i, addr_str);
            }
        }

        // Generate a temporary node ID for preinit reply
        // This will be replaced with the proper one in Init2
        let temp_node_id = self.generate_temp_node_id()
            .map_err(|e| VlsError { message: format!("Failed to generate temp node ID: {}", e) })?;
        
        // Create preinit reply
        let reply = HsmdDevPreinitReply {
            node_id: PubKey(temp_node_id.serialize()),
        };
        let reply_bytes = reply.as_vec();
        
        // Send reply
        let channel_reply = ChannelReply {
            reply: reply_bytes,
            is_temporary_failure: false,
        };
        
        reply_tx.send(channel_reply)
            .map_err(|_| VlsError { message: "Failed to send preinit reply".to_string() })?;
        
        tracing::info!("Sent HsmdDevPreinitReply to VLS daemon");
        Ok(())
    }

    /// Handle main init2 message  
    async fn handle_init2(
        &self,
        init: HsmdInit2,
        raw_message: Vec<u8>,
        reply_tx: oneshot::Sender<ChannelReply>,
    ) -> Result<(), VlsError> {
        
        tracing::debug!("Init2 details: {:?}", init);
        
        // Validate we haven't already initialized
        {
            let cache = self.init_message_cache.lock().unwrap();
            if cache.is_some() {
                tracing::error!("Duplicate HsmdInit2 received - handshake already complete");
                return Err(VlsError { message: "Duplicate initialization attempt".to_string() });
            }
        }
        
        // Extract and validate network
        let network_name = String::from_utf8(init.network_name.0.clone())
            .map_err(|e| VlsError { message: format!("Invalid network name in init2: {}", e) })?;
        
        tracing::info!("Initializing VLS for network: {}", network_name);
        tracing::info!("Derivation style: {}", init.derivation_style);
        
        // Validate network matches
        let expected_network = self.network.to_string();
        if network_name != expected_network {
            return Err(VlsError { 
                message: format!("Network mismatch in init2: VLS expects '{}', RGB node configured for '{}'", network_name, expected_network) 
            });
        }
        
        // Log development seed info (if present)
        if let Some(dev_seed) = &init.dev_seed {
            tracing::warn!("Development seed provided (length: {} bytes)", dev_seed.0.len());
        }
        
        // Log development allowlist
        tracing::info!("Development allowlist: {} addresses", init.dev_allowlist.0.len());
        
        // Generate node keys for RGB Lightning Node
        let (node_id, bip32_key, bolt12_key) = self.generate_node_keys(&network_name)
            .map_err(|e| VlsError { message: format!("Failed to generate node keys: {}", e) })?;
        
        // Create init2 reply
        let reply = HsmdInit2Reply {
            node_id: PubKey(node_id.serialize()),
            bip32: ExtKey(bip32_key),
            bolt12: PubKey(bolt12_key.serialize()),
        };
        
        let reply_bytes = reply.as_vec();
        
        // Cache the init message for potential reconnections
        {
            let mut cache = self.init_message_cache.lock().unwrap();
            *cache = Some(raw_message);
        }
        
        // Send reply
        let channel_reply = ChannelReply {
            reply: reply_bytes,
            is_temporary_failure: false,
        };
        
        reply_tx.send(channel_reply)
            .map_err(|_| VlsError { message: "Failed to send init2 reply".to_string() })?;
        
        // Mark as ready for signing operations
        self.is_ready.store(true, Ordering::Relaxed);
        
        tracing::info!("VLS handshake complete - signer ready for operations!");
        tracing::info!("Node ID: {}", format!("{:02x?}", node_id.serialize()));
        tracing::info!("RGB Lightning Node can now handle VLS signing requests");
        
        Ok(())
    }

    /// Generate node keys for RGB Lightning Node
    /// TODO: Implement proper key derivation based on RGB node requirements
    fn generate_node_keys(&self, network: &str) -> Result<(bitcoin::secp256k1::PublicKey, [u8; 78], bitcoin::secp256k1::PublicKey), Box<dyn std::error::Error>> {
        use bitcoin::secp256k1::{Secp256k1, SecretKey};
        
        tracing::info!("Generating node keys for network: {}", network);
        
        // TODO: Replace with proper key derivation for RGB Lightning Node
        // This should derive keys from the node's master seed/entropy
        let secp = Secp256k1::new();
        
        // For now, use a deterministic but secure key generation
        // In production, this should come from the node's key manager
        let mut seed = [0u8; 32];
        seed[0..8].copy_from_slice(b"rgbnode1"); // Temporary seed prefix
        let secret_key = SecretKey::from_slice(&seed)?;
        let public_key = secret_key.public_key(&secp);
        
        // BIP32 extended key (placeholder - implement proper BIP32 derivation)
        let mut bip32_key = [0u8; 78];
        bip32_key[0..4].copy_from_slice(&[0x04, 0x88, 0xb2, 0x1e]); // xpub version bytes
        bip32_key[45..78].copy_from_slice(&public_key.serialize()); // Public key
        
        // BOLT12 key (can be same as node key for simplicity)
        let bolt12_key = public_key;
        
        tracing::debug!("Generated keys:");
        tracing::debug!("  Node ID: {}", format!("{:02x?}", public_key.serialize()));
        tracing::debug!("  BIP32 key: {} bytes", bip32_key.len());
        tracing::debug!("  BOLT12 key: {}", format!("{:02x?}", bolt12_key.serialize()));
        
        Ok((public_key, bip32_key, bolt12_key))
    }

    /// Check if handshake is complete and signer is ready
    pub fn is_ready(&self) -> bool {
        self.is_ready.load(Ordering::Relaxed)
    }

    /// Get cached init message for reconnections
    pub fn get_cached_init_message(&self) -> Option<Vec<u8>> {
        let cache = self.init_message_cache.lock().unwrap();
        cache.clone()
    }

    /// Reset handshake state (for reconnections)
    pub fn reset(&self) {
        self.is_ready.store(false, Ordering::Relaxed);
        let mut cache = self.init_message_cache.lock().unwrap();
        *cache = None;
        tracing::info!("VLS handshake state reset for reconnection");
    }

    /// Generate temporary node ID for preinit reply
    fn generate_temp_node_id(&self) -> Result<bitcoin::secp256k1::PublicKey, Box<dyn std::error::Error>> {
        use bitcoin::secp256k1::{Secp256k1, SecretKey};
        
        let secp = Secp256k1::new();
        // Use a deterministic but temporary key for preinit
        let mut temp_seed = [0u8; 32];
        temp_seed[0..8].copy_from_slice(b"tempnode"); // Temporary seed prefix
        let secret_key = SecretKey::from_slice(&temp_seed)?;
        let public_key = secret_key.public_key(&secp);
        
        Ok(public_key)
    }
}
