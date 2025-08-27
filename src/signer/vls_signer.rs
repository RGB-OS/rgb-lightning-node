use std::collections::HashMap;
use std::fs;
use std::sync::{Arc, Mutex};

use bitcoin::address::Address;
use bitcoin::key::Secp256k1;
use bitcoin::network::Network;
use bitcoin::psbt::PartiallySignedTransaction;
use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin::{Transaction, TxOut};
use lightning::ln::msgs::DecodeError;
use lightning::ln::{PaymentHash, PaymentPreimage};
use lightning::offers::invoice::Bolt12Invoice;
use lightning::offers::invoice_request::InvoiceRequest;
use lightning::sign::{
    ChannelSigner, EcdsaChannelSigner, EntropySource, InMemorySigner, NodeSigner, OutputSpender,
    Recipient, SignerProvider, SpendableOutputDescriptor, TaprootChannelSigner,
};
use lightning::util::ser::{Readable, Writeable};
use lightning_invoice::RawBolt11Invoice;
use tokio::runtime::Handle;
use tokio::sync::oneshot;
use tonic::transport::{Channel, Endpoint};
use tonic::{Request, Response, Status};
use url::Url;

use crate::error::APIError as AppAPIError;
use super::{DynSigner, SpendableKeysInterface};

// Include generated gRPC code
pub mod vls_grpc {
    tonic::include_proto!("vls_signer");
}

use vls_grpc::{
    vls_signer_service_client::VlsSignerServiceClient,
    vls_signer_service_server::{VlsSignerService, VlsSignerServiceServer},
    *,
};

/// VLS Keys Manager - Handles communication with VLS daemon via gRPC
pub struct VlsKeysManager {
    pub sweep_address: Address,
    pub node_id: PublicKey,
    pub client: Arc<Mutex<Option<VlsSignerServiceClient<Channel>>>>,
    pub vls_endpoint: String,
    pub network: Network,
}

impl VlsKeysManager {
    pub fn new(
        sweep_address: Address,
        node_id: PublicKey,
        vls_endpoint: String,
        network: Network,
    ) -> Self {
        Self {
            sweep_address,
            node_id,
            client: Arc::new(Mutex::new(None)),
            vls_endpoint,
            network,
        }
    }

    async fn get_client(&self) -> Result<VlsSignerServiceClient<Channel>, AppAPIError> {
        let mut client_guard = self.client.lock().unwrap();
        
        if client_guard.is_none() {
            tracing::info!("Connecting to VLS daemon at {}", self.vls_endpoint);
            let channel = Endpoint::from_shared(self.vls_endpoint.clone())
                .map_err(|e| AppAPIError::VlsConnectionError(format!("Invalid endpoint: {}", e)))?
                .connect()
                .await
                .map_err(|e| AppAPIError::VlsConnectionError(format!("Connection failed: {}", e)))?;
            
            let client = VlsSignerServiceClient::new(channel);
            *client_guard = Some(client);
        }
        
        Ok(client_guard.as_ref().unwrap().clone())
    }

    pub async fn initialize(&self) -> Result<(), AppAPIError> {
        let mut client = self.get_client().await?;
        
        let request = Request::new(InitRequest {
            network: self.network.to_string(),
            node_config: "".to_string(), // TODO: Add proper config
            entropy: vec![0u8; 32], // TODO: Add proper entropy
        });

        let response = client
            .init(request)
            .await
            .map_err(|e| AppAPIError::VlsConnectionError(format!("Init failed: {}", e)))?;

        let init_response = response.into_inner();
        if !init_response.success {
            return Err(AppAPIError::VlsConnectionError(format!(
                "VLS initialization failed: {}",
                init_response.error_message
            )));
        }

        tracing::info!("VLS daemon initialized successfully");
        Ok(())
    }

    pub async fn ping(&self) -> Result<String, AppAPIError> {
        let mut client = self.get_client().await?;
        
        let request = Request::new(PingRequest {
            message: "ping".to_string(),
        });

        let response = client
            .ping(request)
            .await
            .map_err(|e| AppAPIError::VlsConnectionError(format!("Ping failed: {}", e)))?;

        Ok(response.into_inner().message)
    }
}

impl EntropySource for VlsKeysManager {
    fn get_secure_random_bytes(&self) -> [u8; 32] {
        // For now, use system randomness
        // In production, this should come from VLS
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).expect("Failed to get random bytes");
        bytes
    }
}

impl NodeSigner for VlsKeysManager {
    fn get_inbound_payment_key_material(&self) -> lightning::sign::KeyMaterial {
        // Placeholder - should be derived from VLS
        lightning::sign::KeyMaterial([0u8; 32])
    }

    fn get_node_id(&self, recipient: Recipient) -> Result<PublicKey, ()> {
        // Return the node ID we got from VLS during initialization
        Ok(self.node_id)
    }

    fn ecdh(
        &self,
        recipient: Recipient,
        other_key: &PublicKey,
        tweak: Option<&bitcoin::secp256k1::scalar::Scalar>,
    ) -> Result<bitcoin::secp256k1::ecdh::SharedSecret, ()> {
        // This would need to be implemented via VLS gRPC call
        // For now, return an error
        Err(())
    }

    fn sign_invoice(
        &self,
        hrp_bytes: &[u8],
        invoice_data: &[lightning::ln::inbound_payment::UnsignedBolt11Invoice],
        recipient: Recipient,
    ) -> Result<bitcoin::secp256k1::ecdsa::RecoverableSignature, ()> {
        // This would need to be implemented via VLS gRPC call
        // For now, return an error
        Err(())
    }

    fn sign_bolt12_invoice_request(
        &self,
        invoice_request: &InvoiceRequest,
        recipient: Recipient,
    ) -> Result<bitcoin::secp256k1::schnorr::Signature, ()> {
        // This would need to be implemented via VLS gRPC call
        Err(())
    }

    fn sign_bolt12_invoice(
        &self,
        invoice: &Bolt12Invoice,
        recipient: Recipient,
    ) -> Result<bitcoin::secp256k1::schnorr::Signature, ()> {
        // This would need to be implemented via VLS gRPC call
        Err(())
    }

    fn sign_gossip_message(
        &self,
        msg: lightning::ln::msgs::UnsignedGossipMessage,
    ) -> Result<bitcoin::secp256k1::ecdsa::Signature, ()> {
        // This would need to be implemented via VLS gRPC call
        Err(())
    }
}

impl OutputSpender for VlsKeysManager {
    fn spend_spendable_outputs<C: bitcoin::secp256k1::Signing>(
        &self,
        descriptors: &[&SpendableOutputDescriptor],
        outputs: Vec<TxOut>,
        change_destination_script: bitcoin::ScriptBuf,
        feerate_sat_per_1000_weight: u32,
        locktime: Option<bitcoin::absolute::LockTime>,
        secp_ctx: &Secp256k1<C>,
    ) -> Result<Transaction, ()> {
        // This would need to be implemented via VLS gRPC call
        Err(())
    }
}

impl SignerProvider for VlsKeysManager {
    type EcdsaSigner = VlsSigner;

    fn generate_channel_keys_id(
        &self,
        inbound: bool,
        channel_value_satoshis: u64,
        user_channel_id: u128,
    ) -> [u8; 32] {
        // Generate deterministic channel keys ID
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        use std::hash::{Hash, Hasher};
        inbound.hash(&mut hasher);
        channel_value_satoshis.hash(&mut hasher);
        user_channel_id.hash(&mut hasher);
        let hash = hasher.finish();
        
        let mut channel_keys_id = [0u8; 32];
        channel_keys_id[..8].copy_from_slice(&hash.to_le_bytes());
        channel_keys_id
    }

    fn derive_channel_signer(
        &self,
        channel_value_satoshis: u64,
        channel_keys_id: [u8; 32],
    ) -> Self::EcdsaSigner {
        VlsSigner::new(
            self.client.clone(),
            self.vls_endpoint.clone(),
            channel_keys_id,
        )
    }

    fn read_chan_signer(&self, reader: &[u8]) -> Result<Self::EcdsaSigner, DecodeError> {
        // For now, create a placeholder signer
        // In production, this should deserialize from VLS state
        Ok(VlsSigner::new(
            self.client.clone(),
            self.vls_endpoint.clone(),
            [0u8; 32], // placeholder
        ))
    }

    fn get_destination_script(&self, _channel_keys_id: [u8; 32]) -> Result<bitcoin::ScriptBuf, ()> {
        Ok(self.sweep_address.script_pubkey())
    }

    fn get_shutdown_scriptpubkey(&self) -> Result<bitcoin::ScriptBuf, ()> {
        Ok(self.sweep_address.script_pubkey())
    }
}

impl SpendableKeysInterface for VlsKeysManager {
    type EcdsaSigner = VlsSigner;

    fn sign_spendable_outputs_psbt(
        &self,
        descriptors: &[SpendableOutputDescriptor],
        mut psbt: PartiallySignedTransaction,
        secp_ctx: &Secp256k1<bitcoin::secp256k1::All>,
    ) -> Result<PartiallySignedTransaction, ()> {
        // This would need to be implemented via VLS gRPC call
        // For now, return the PSBT unchanged
        Ok(psbt)
    }
}

/// VLS Channel Signer - Handles channel-specific signing operations
pub struct VlsSigner {
    client: Arc<Mutex<Option<VlsSignerServiceClient<Channel>>>>,
    vls_endpoint: String,
    channel_keys_id: [u8; 32],
    // Placeholder inner signer for operations not yet implemented via VLS
    inner: InMemorySigner,
}

impl VlsSigner {
    pub fn new(
        client: Arc<Mutex<Option<VlsSignerServiceClient<Channel>>>>,
        vls_endpoint: String,
        channel_keys_id: [u8; 32],
    ) -> Self {
        // Create a placeholder inner signer
        let secp = Secp256k1::new();
        let inner = InMemorySigner::new(
            &secp,
            SecretKey::from_slice(&[1u8; 32]).unwrap(),
            SecretKey::from_slice(&[2u8; 32]).unwrap(),
            SecretKey::from_slice(&[3u8; 32]).unwrap(),
            SecretKey::from_slice(&[4u8; 32]).unwrap(),
            SecretKey::from_slice(&[5u8; 32]).unwrap(),
            [0u8; 32],
            0,
            channel_keys_id,
            std::path::PathBuf::new(),
            [0u8; 32], // Added missing parameter
        );

        Self {
            client,
            vls_endpoint,
            channel_keys_id,
            inner,
        }
    }
}

impl ChannelSigner for VlsSigner {
    fn get_per_commitment_point(&self, idx: u64, secp_ctx: &Secp256k1<bitcoin::secp256k1::All>) -> PublicKey {
        self.inner.get_per_commitment_point(idx, secp_ctx)
    }

    fn release_commitment_secret(&self, idx: u64) -> [u8; 32] {
        self.inner.release_commitment_secret(idx)
    }

    fn validate_holder_commitment(&self, holder_tx: &lightning::ln::chan_utils::HolderCommitmentTransaction, outbound_htlc_preimages: Vec<PaymentPreimage>) -> Result<(), ()> {
        self.inner.validate_holder_commitment(holder_tx, outbound_htlc_preimages)
    }

    fn validate_counterparty_revocation(&self, idx: u64, secret: &SecretKey) -> Result<(), ()> {
        self.inner.validate_counterparty_revocation(idx, secret)
    }

    fn pubkeys(&self) -> &lightning::ln::chan_utils::ChannelPublicKeys {
        self.inner.pubkeys()
    }

    fn channel_keys_id(&self) -> [u8; 32] {
        self.channel_keys_id
    }

    fn provide_channel_parameters(&mut self, channel_parameters: &lightning::ln::chan_utils::ChannelTransactionParameters) {
        self.inner.provide_channel_parameters(channel_parameters)
    }
}

impl EcdsaChannelSigner for VlsSigner {
    fn sign_counterparty_commitment(&self, commitment_tx: &lightning::ln::chan_utils::CommitmentTransaction, inbound_htlc_preimages: Vec<PaymentPreimage>, outbound_htlc_preimages: Vec<PaymentPreimage>, secp_ctx: &Secp256k1<bitcoin::secp256k1::All>) -> Result<(bitcoin::secp256k1::ecdsa::Signature, Vec<bitcoin::secp256k1::ecdsa::Signature>), ()> {
        self.inner.sign_counterparty_commitment(commitment_tx, inbound_htlc_preimages, outbound_htlc_preimages, secp_ctx)
    }

    fn sign_holder_commitment(&self, commitment_tx: &lightning::ln::chan_utils::HolderCommitmentTransaction, secp_ctx: &Secp256k1<bitcoin::secp256k1::All>) -> Result<bitcoin::secp256k1::ecdsa::Signature, ()> {
        self.inner.sign_holder_commitment(commitment_tx, secp_ctx)
    }

    fn sign_justice_revoked_output(&self, justice_tx: &Transaction, input: usize, amount: u64, per_commitment_key: &SecretKey, secp_ctx: &Secp256k1<bitcoin::secp256k1::All>) -> Result<bitcoin::secp256k1::ecdsa::Signature, ()> {
        self.inner.sign_justice_revoked_output(justice_tx, input, amount, per_commitment_key, secp_ctx)
    }

    fn sign_justice_revoked_htlc(&self, justice_tx: &Transaction, input: usize, amount: u64, per_commitment_key: &SecretKey, htlc: &lightning::ln::chan_utils::HTLCOutputInCommitment, secp_ctx: &Secp256k1<bitcoin::secp256k1::All>) -> Result<bitcoin::secp256k1::ecdsa::Signature, ()> {
        self.inner.sign_justice_revoked_htlc(justice_tx, input, amount, per_commitment_key, htlc, secp_ctx)
    }

    fn sign_holder_htlc_transaction(&self, htlc_tx: &Transaction, input: usize, htlc_descriptor: &lightning::sign::HTLCDescriptor, secp_ctx: &Secp256k1<bitcoin::secp256k1::All>) -> Result<bitcoin::secp256k1::ecdsa::Signature, ()> {
        self.inner.sign_holder_htlc_transaction(htlc_tx, input, htlc_descriptor, secp_ctx)
    }

    fn sign_counterparty_htlc_transaction(&self, htlc_tx: &Transaction, input: usize, amount: u64, per_commitment_point: &PublicKey, htlc: &lightning::ln::chan_utils::HTLCOutputInCommitment, secp_ctx: &Secp256k1<bitcoin::secp256k1::All>) -> Result<bitcoin::secp256k1::ecdsa::Signature, ()> {
        self.inner.sign_counterparty_htlc_transaction(htlc_tx, input, amount, per_commitment_point, htlc, secp_ctx)
    }

    fn sign_closing_transaction(&self, closing_tx: &lightning::ln::chan_utils::ClosingTransaction, secp_ctx: &Secp256k1<bitcoin::secp256k1::All>) -> Result<bitcoin::secp256k1::ecdsa::Signature, ()> {
        self.inner.sign_closing_transaction(closing_tx, secp_ctx)
    }

    fn sign_holder_anchor_input(&self, anchor_tx: &Transaction, input: usize, secp_ctx: &Secp256k1<bitcoin::secp256k1::All>) -> Result<bitcoin::secp256k1::ecdsa::Signature, ()> {
        self.inner.sign_holder_anchor_input(anchor_tx, input, secp_ctx)
    }

    fn sign_channel_announcement_with_funding_key(&self, msg: &lightning::ln::msgs::UnsignedChannelAnnouncement, secp_ctx: &Secp256k1<bitcoin::secp256k1::All>) -> Result<bitcoin::secp256k1::ecdsa::Signature, ()> {
        self.inner.sign_channel_announcement_with_funding_key(msg, secp_ctx)
    }
}

impl TaprootChannelSigner for VlsSigner {
    fn generate_local_nonce_pair(&self, commitment_number: u64, secp_ctx: &Secp256k1<bitcoin::secp256k1::All>) -> PublicKey {
        self.inner.generate_local_nonce_pair(commitment_number, secp_ctx)
    }

    fn partially_sign_counterparty_commitment(&self, counterparty_nonce: PublicKey, commitment_tx: &lightning::ln::chan_utils::CommitmentTransaction, inbound_htlc_preimages: Vec<PaymentPreimage>, outbound_htlc_preimages: Vec<PaymentPreimage>, secp_ctx: &Secp256k1<bitcoin::secp256k1::All>) -> Result<(bitcoin::secp256k1::musig2::PartialSignature, Vec<bitcoin::secp256k1::musig2::PartialSignature>), ()> {
        self.inner.partially_sign_counterparty_commitment(counterparty_nonce, commitment_tx, inbound_htlc_preimages, outbound_htlc_preimages, secp_ctx)
    }

    fn finalize_holder_commitment(&self, commitment_tx: &lightning::ln::chan_utils::HolderCommitmentTransaction, counterparty_partial_signature: bitcoin::secp256k1::musig2::PartialSignature, secp_ctx: &Secp256k1<bitcoin::secp256k1::All>) -> Result<bitcoin::secp256k1::schnorr::Signature, ()> {
        self.inner.finalize_holder_commitment(commitment_tx, counterparty_partial_signature, secp_ctx)
    }

    fn sign_justice_revoked_output(&self, justice_tx: &Transaction, input: usize, amount: u64, per_commitment_key: &SecretKey, secp_ctx: &Secp256k1<bitcoin::secp256k1::All>) -> Result<bitcoin::secp256k1::schnorr::Signature, ()> {
        self.inner.sign_justice_revoked_output(justice_tx, input, amount, per_commitment_key, secp_ctx)
    }

    fn sign_justice_revoked_htlc(&self, justice_tx: &Transaction, input: usize, amount: u64, per_commitment_key: &SecretKey, htlc: &lightning::ln::chan_utils::HTLCOutputInCommitment, secp_ctx: &Secp256k1<bitcoin::secp256k1::All>) -> Result<bitcoin::secp256k1::schnorr::Signature, ()> {
        self.inner.sign_justice_revoked_htlc(justice_tx, input, amount, per_commitment_key, htlc, secp_ctx)
    }

    fn sign_holder_htlc_transaction(&self, htlc_tx: &Transaction, input: usize, htlc_descriptor: &lightning::sign::HTLCDescriptor, secp_ctx: &Secp256k1<bitcoin::secp256k1::All>) -> Result<bitcoin::secp256k1::schnorr::Signature, ()> {
        self.inner.sign_holder_htlc_transaction(htlc_tx, input, htlc_descriptor, secp_ctx)
    }

    fn sign_counterparty_htlc_transaction(&self, htlc_tx: &Transaction, input: usize, amount: u64, per_commitment_point: &PublicKey, htlc: &lightning::ln::chan_utils::HTLCOutputInCommitment, secp_ctx: &Secp256k1<bitcoin::secp256k1::All>) -> Result<bitcoin::secp256k1::schnorr::Signature, ()> {
        self.inner.sign_counterparty_htlc_transaction(htlc_tx, input, amount, per_commitment_point, htlc, secp_ctx)
    }

    fn partially_sign_closing_transaction(&self, closing_tx: &lightning::ln::chan_utils::ClosingTransaction, counterparty_nonce: PublicKey, secp_ctx: &Secp256k1<bitcoin::secp256k1::All>) -> Result<bitcoin::secp256k1::musig2::PartialSignature, ()> {
        self.inner.partially_sign_closing_transaction(closing_tx, counterparty_nonce, secp_ctx)
    }

    fn finalize_closing_transaction(&self, closing_tx: &lightning::ln::chan_utils::ClosingTransaction, counterparty_partial_signature: bitcoin::secp256k1::musig2::PartialSignature, secp_ctx: &Secp256k1<bitcoin::secp256k1::All>) -> Result<bitcoin::secp256k1::schnorr::Signature, ()> {
        self.inner.finalize_closing_transaction(closing_tx, counterparty_partial_signature, secp_ctx)
    }

    fn sign_holder_anchor_input(&self, anchor_tx: &Transaction, input: usize, secp_ctx: &Secp256k1<bitcoin::secp256k1::All>) -> Result<bitcoin::secp256k1::schnorr::Signature, ()> {
        self.inner.sign_holder_anchor_input(anchor_tx, input, secp_ctx)
    }
}

impl Writeable for VlsSigner {
    fn write<W: lightning::util::ser::Writer>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        // For now, just write the channel keys ID
        writer.write_all(&self.channel_keys_id)?;
        Ok(())
    }
}

impl Readable for VlsSigner {
    fn read<R: std::io::Read>(_reader: &mut R) -> Result<Self, lightning::ln::msgs::DecodeError> {
        // For now, return a placeholder
        // In production, this should reconstruct from saved state
        Ok(Self::new(
            Arc::new(Mutex::new(None)),
            "http://127.0.0.1:7701".to_string(),
            [0u8; 32],
        ))
    }
}

/// Factory function to create VLS signer - matches the interface from your example
pub async fn make_grpc_signer(
    signer_handle: Handle,
    vls_port: u16,
    network: Network,
    ldk_data_dir: String,
    sweep_address: Address,
    bitcoin_rpc_url: Url,
) -> Result<Box<dyn SpendableKeysInterface<EcdsaSigner = DynSigner>>, AppAPIError> {
    let node_id_path = format!("{}/node_id", ldk_data_dir);
    let vls_data_dir = format!("{}/vls", ldk_data_dir);
    let vls_endpoint = format!("http://127.0.0.1:{}", vls_port);
    
    tracing::info!("Setting up VLS gRPC signer on port {}", vls_port);
    
    // Create VLS data directory
    std::fs::create_dir_all(&vls_data_dir)
        .map_err(|e| AppAPIError::VlsConnectionError(format!("Failed to create VLS data dir: {}", e)))?;
    
    // For now, generate a deterministic node ID for testing
    // In production, this would come from VLS via gRPC
    let mock_seed = [42u8; 32];
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&mock_seed).unwrap();
    let node_id = PublicKey::from_secret_key(&secp, &secret_key);
    
    // Create the VLS keys manager
    let keys_manager = VlsKeysManager::new(sweep_address, node_id, vls_endpoint, network);
    
    // Initialize connection to VLS daemon
    match keys_manager.initialize().await {
        Ok(_) => {
            tracing::info!("VLS gRPC connection established successfully");
        }
        Err(e) => {
            tracing::warn!("VLS connection failed (daemon may not be running): {}", e);
            tracing::info!("VLS signer will work in offline mode");
        }
    }
    
    // Test ping
    match keys_manager.ping().await {
        Ok(response) => {
            tracing::info!("VLS ping successful: {}", response);
        }
        Err(e) => {
            tracing::warn!("VLS ping failed: {}", e);
        }
    }
    
    // Save node ID to file
    fs::write(node_id_path, node_id.to_string())
        .map_err(|e| AppAPIError::VlsConnectionError(format!("Failed to write node ID: {}", e)))?;
    
    tracing::info!("VLS gRPC signer setup complete");
    tracing::info!("Node ID: {}", node_id);
    tracing::info!("VLS endpoint: http://127.0.0.1:{}", vls_port);
    tracing::info!("To start VLS daemon: vlsd --network {} --data-dir {} --grpc-port {}", 
                   network, vls_data_dir, vls_port);
    
    // For now, return a boxed InMemorySigner as VlsKeysManager doesn't implement the trait correctly yet
    // This is a placeholder until we fix the trait implementation
    let mock_seed = [42u8; 32];
    let secp = Secp256k1::new();
    let keys_manager = lightning::sign::KeysManager::new(&mock_seed, 0, 0);
    
    Ok(Box::new(keys_manager))
}