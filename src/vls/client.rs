//! VLS gRPC Signer Implementation
//!
//! Based on lnrod architecture for VLS integration with Lightning Node.
//! Creates a gRPC endpoint with HsmdService that VLS can subscribe to and communicate through.

use std::fmt;
use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use bitcoin::{Address, Network};
use tokio::runtime::Handle;
use tokio::sync::mpsc::Sender;
use tokio::sync::oneshot;
use tokio::task;
use url::Url;
use async_trait::async_trait;
use anyhow::Result;


// VLS imports - using correct module paths from your VLS fork
use vls_proxy::grpc::adapter::{ChannelRequest, ClientId, HsmdService};
use vls_proxy::grpc::incoming::TcpIncoming;
use vls_proxy::grpc::signer_loop::InitMessageCache;
use vls_proxy::portfront::SignerPortFront;
use vls_proxy::vls_frontend::frontend::DummySourceFactory;
use vls_proxy::vls_frontend::Frontend;
use vls_proxy::vls_protocol_client::{ClientResult, Error, KeysManagerClient, SignerPort, Transport};
use vls_proxy::vls_protocol_signer::vls_protocol::model::PubKey;
use vls_proxy::vls_protocol_signer::vls_protocol::serde_bolt::{Array, WireString};
use vls_proxy::vls_protocol_signer::vls_protocol::msgs;
use lightning_signer::signer::derive::KeyDerivationStyle;
use lightning_signer::lightning::sign::{NodeSigner, Recipient};
use vls_proxy::lightning_signer;
use vls_proxy::vls_protocol_client;
use vls_proxy::vls_protocol_client::{DynKeysInterface, DynSigner, SpendableKeysInterface};
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

/// VLS gRPC Transport - handles communication with external VLS process
/// This creates the endpoint that VLS subscribes to
struct GrpcTransport {
    sender: Sender<ChannelRequest>,  // Channel to send requests to gRPC service
    handle: Handle,                  // Tokio runtime handle
}

impl GrpcTransport {
    async fn new(sender: Sender<ChannelRequest>) -> ClientResult<Self> {
        tracing::info!("Waiting for VLS signer connection");
        let handle = Handle::current();
        Ok(Self { sender, handle })
    }

    fn do_call(
        handle: &Handle,
        sender: Sender<ChannelRequest>,
        message: Vec<u8>,
        client_id: Option<ClientId>,
    ) -> ClientResult<Vec<u8>> {
        let join = handle.spawn_blocking(move || {
            Handle::current().block_on(Self::do_call_async(sender, message, client_id))
        });
        let result = task::block_in_place(|| handle.block_on(join))
            .map_err(|e| {
                tracing::error!("Failed to join transport task: {}", e);
                Error::Transport
            })?;
        result
    }

    async fn do_call_async(
        sender: Sender<ChannelRequest>,
        message: Vec<u8>,
        client_id: Option<ClientId>,
    ) -> ClientResult<Vec<u8>> {
        // Create a one-shot channel to receive the reply
        let (reply_tx, reply_rx) = oneshot::channel();

        // Send a request to the gRPC handler to send to VLS
        let request = ChannelRequest { client_id, message, reply_tx };

        // This can fail if gRPC adapter shut down
        sender.send(request).await.map_err(|e| {
            tracing::error!("Failed to send request to gRPC adapter: {}", e);
            Error::Transport
        })?;
        let reply = reply_rx.await.map_err(|e| {
            tracing::error!("Failed to receive reply from gRPC adapter: {}", e);
            Error::Transport
        })?;
        Ok(reply.reply)
    }
}

impl Transport for GrpcTransport {
    fn node_call(&self, message: Vec<u8>) -> ClientResult<Vec<u8>> {
        Self::do_call(&self.handle, self.sender.clone(), message, None)
    }

    fn call(&self, dbid: u64, peer_id: PubKey, message: Vec<u8>) -> ClientResult<Vec<u8>> {
        let client_id = Some(ClientId { peer_id: peer_id.0, dbid });
        Self::do_call(&self.handle, self.sender.clone(), message, client_id)
    }
}

/// VLS Keys Manager - wraps VLS protocol client for Lightning operations
pub struct VlsKeysManager {
    client: KeysManagerClient,  // VLS protocol client
    sweep_address: Address,     // Bitcoin address for sweeping funds
}

// VLS requires implementing NodeSigner and SignerProvider from lightning_signer
impl lightning_signer::lightning::sign::NodeSigner for VlsKeysManager {
    fn get_inbound_payment_key(&self) -> lightning_signer::lightning::ln::inbound_payment::ExpandedKey {
        self.client.get_inbound_payment_key()
    }

    fn get_node_id(&self, recipient: lightning_signer::lightning::sign::Recipient) -> Result<bitcoin::secp256k1::PublicKey, ()> {
        self.client.get_node_id(recipient)
    }

    fn ecdh(&self, recipient: lightning_signer::lightning::sign::Recipient, other_key: &bitcoin::secp256k1::PublicKey, tweak: Option<&bitcoin::secp256k1::Scalar>) -> Result<bitcoin::secp256k1::ecdh::SharedSecret, ()> {
        self.client.ecdh(recipient, other_key, tweak)
    }

    fn sign_invoice(&self, raw_invoice: &lightning_signer::lightning_invoice::RawBolt11Invoice, recipient: lightning_signer::lightning::sign::Recipient) -> Result<bitcoin::secp256k1::ecdsa::RecoverableSignature, ()> {
        self.client.sign_invoice(raw_invoice, recipient)
    }

    fn sign_gossip_message(&self, msg: lightning_signer::lightning::ln::msgs::UnsignedGossipMessage) -> Result<bitcoin::secp256k1::ecdsa::Signature, ()> {
        self.client.sign_gossip_message(msg)
    }

    fn sign_bolt12_invoice(&self, invoice: &lightning_signer::lightning::offers::invoice::UnsignedBolt12Invoice) -> Result<bitcoin::secp256k1::schnorr::Signature, ()> {
        self.client.sign_bolt12_invoice(invoice)
    }
}

impl lightning_signer::lightning::sign::SignerProvider for VlsKeysManager {
    type EcdsaSigner = DynSigner;

    fn generate_channel_keys_id(&self, inbound: bool, channel_value_satoshis: u64, user_channel_id: u128) -> [u8; 32] {
        self.client.generate_channel_keys_id(inbound, channel_value_satoshis, user_channel_id)
    }

    fn derive_channel_signer(&self, channel_value_satoshis: u64, channel_keys_id: [u8; 32]) -> Self::EcdsaSigner {
        // Wrap the SignerClient in DynSigner
        let signer_client = self.client.derive_channel_signer(channel_value_satoshis, channel_keys_id);
        DynSigner::new(signer_client)
    }
    

    fn read_chan_signer(&self, reader: &[u8]) -> Result<Self::EcdsaSigner, lightning_signer::lightning::ln::msgs::DecodeError> {
        let signer_client = self.client.read_chan_signer(reader)?;
        Ok(DynSigner::new(signer_client))
    }

    fn get_destination_script(&self, _channel_keys_id: [u8; 32]) -> Result<bitcoin::ScriptBuf, ()> {
        Ok(self.sweep_address.script_pubkey())
    }

    fn get_shutdown_scriptpubkey(&self) -> Result<lightning_signer::lightning::ln::script::ShutdownScript, ()> {
        self.client.get_shutdown_scriptpubkey()
    }
}

impl SpendableKeysInterface for VlsKeysManager {
    fn spend_spendable_outputs(
        &self,
        _descriptors: &[&lightning_signer::lightning::sign::SpendableOutputDescriptor],
        _outputs: Vec<bitcoin::TxOut>,
        _change_destination_script: bitcoin::ScriptBuf,
        _feerate_sat_per_1000_weight: u32,
        _secp_ctx: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>,
    ) -> anyhow::Result<bitcoin::Transaction> {
        anyhow::bail!("spend_spendable_outputs not yet implemented")
    }

    fn get_sweep_address(&self) -> Address {
        self.sweep_address.clone()
    }
}

/// Transport wrapper for SignerPort - bridges VLS transport to signer interface
struct TransportSignerPort {
    transport: Arc<dyn Transport>,
}

#[async_trait::async_trait]
impl SignerPort for TransportSignerPort {
    async fn handle_message(&self, message: Vec<u8>) -> ClientResult<Vec<u8>> {
        self.transport.node_call(message)
    }

    fn is_ready(&self) -> bool {
        true
    }
}

/// Main factory function to create VLS gRPC signer with HsmdService
/// This creates the complete gRPC endpoint that VLS can subscribe to and communicate through
pub async fn make_grpc_signer(
    shutter: Shutter,
    signer_handle: Handle,
    vls_port: u16,
    network: Network,
    ldk_data_dir: String,
    sweep_address: Address,
    bitcoin_rpc_url: Url,
) -> Box<dyn SpendableKeysInterface<EcdsaSigner = DynSigner>>  {
    let node_id_path = format!("{}/node_id", ldk_data_dir);
    let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, vls_port));
    
    tracing::info!("Setting up VLS gRPC endpoint with HsmdService");
    tracing::info!("Endpoint: {}:{}", addr.ip(), addr.port());
    tracing::info!("Network: {}", network);
    tracing::info!("VLS Fork: gitlab.com/dablanahuber/validating-lightning-signer.git@36ad8506");
    tracing::warn!("Ensure external VLS daemon is compatible with this protocol version");
    
    // Create TCP incoming connection handler for VLS to connect to
    let incoming = TcpIncoming::new(addr, false).await.expect("listen incoming");
    
    // Initialize message cache for VLS protocol state
    let init_message_cache = Arc::new(Mutex::new(InitMessageCache::new()));

    // Create HsmdService - this is the core gRPC service that VLS connects to
    let server = HsmdService::new(
        shutter.trigger.clone(),
        shutter.signal.clone(), 
        init_message_cache
    );
    let sender = server.sender();

    // Start the HsmdService (gRPC server) in background - this is the endpoint VLS subscribes to
    signer_handle.spawn(server.start(incoming, shutter.signal.clone()));

    // Create gRPC transport for communication with VLS
    let transport = Arc::new(
        signer_handle
            .spawn(GrpcTransport::new(sender))
            .await
            .expect("join")
            .expect("gRPC transport init"),
    );

    // Create source factory for VLS data management
    let source_factory = Arc::new(DummySourceFactory::new(ldk_data_dir, network));
    
    // Create signer port that bridges transport to VLS protocol
    let signer_port = Arc::new(TransportSignerPort { 
        transport: transport.clone(),
    });
    
    // Create frontend for VLS integration
    let frontend = Frontend::new(
        Arc::new(SignerPortFront::new(signer_port, network)),
        source_factory,
        bitcoin_rpc_url,
        shutter.signal.clone(),
    );

    // Create KeysManagerClient - this sends HsmdInit2 and should complete initialization
    // The initialization must complete before any AddBlock messages are sent
    tracing::info!("Creating VLS KeysManagerClient - this will complete VLS initialization");
    let client = KeysManagerClient::new(
        transport.clone(),
        network.to_string(),
        Some(KeyDerivationStyle::Ldk),
        None, // Avoid HsmdDevPreinit to prevent protocol errors
    );
    tracing::info!("VLS KeysManagerClient created successfully - initialization should be complete");
    
    // Give VLS time to transition from InitHandler to RootHandler
    // This prevents AddBlock messages from arriving while still in init mode
    tracing::info!("Waiting for VLS handler transition to complete...");
    tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
    
    // NOTE: for now the frontend must be started after the client is created
    // as the TransportSignerPort is always set to ready
    tracing::info!("Starting VLS frontend - AddBlock messages will now be sent");
    frontend.start();

    let node_id = client.get_node_id(Recipient::Node).expect("get node id");
    let keys_manager = VlsKeysManager { client, sweep_address };
    fs::write(node_id_path, node_id.to_string()).expect("write node_id");
 
 
    Box::new(keys_manager)

}

/// Get VLS gRPC endpoint information for external configuration
pub fn get_grpc_endpoint_info(vls_port: u16, network: Network) -> GrpcEndpointInfo {
    GrpcEndpointInfo {
        host: "127.0.0.1".to_string(),
        port: vls_port,
        network,
        hsmd_service_ready: true,
    }
}

/// VLS gRPC endpoint information
#[derive(Debug, Clone)]
pub struct GrpcEndpointInfo {
    pub host: String,
    pub port: u16,
    pub network: Network,
    pub hsmd_service_ready: bool,
}

impl fmt::Display for GrpcEndpointInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "VLS gRPC Endpoint: {}:{} (network: {}, HsmdService: {})",
            self.host, 
            self.port, 
            self.network, 
            if self.hsmd_service_ready { "ready" } else { "not ready" }
        )
    }
}