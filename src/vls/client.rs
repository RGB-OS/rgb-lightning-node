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

// Import Shutter from parent module
use super::Shutter;


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
) -> Result<Arc<VlsKeysManager>, VlsError> {
    let node_id_path = format!("{}/node_id", ldk_data_dir);
    let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, vls_port));
    
    tracing::info!("Setting up VLS gRPC endpoint with HsmdService");
    tracing::info!("Endpoint: {}:{}", addr.ip(), addr.port());
    tracing::info!("Network: {}", network);
    tracing::info!("VLS Fork: gitlab.com/dablanahuber/validating-lightning-signer.git@36ad8506");
    tracing::warn!("Ensure external VLS daemon is compatible with this protocol version");
    
    // Create TCP incoming connection handler for VLS to connect to
    let incoming = TcpIncoming::new(addr, false).await
        .map_err(|e| VlsError { message: format!("Failed to create TCP incoming: {}", e) })?;
    
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
            .map_err(|e| VlsError { message: format!("Failed to join GrpcTransport task: {}", e) })?
            .map_err(|e| VlsError { message: format!("Failed to initialize gRPC transport: {:?}", e) })?,
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
 
 
    Ok(Arc::new(keys_manager))
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