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
use lightning_signer::signer::derive::KeyDerivationStyle;

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
            Handle::current().block_on(Self::do_call_async(sender, message, client_id)).unwrap()
        });
        let result = task::block_in_place(|| handle.block_on(join)).expect("join");
        Ok(result)
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
        sender.send(request).await.map_err(|_| Error::Transport)?;
        let reply = reply_rx.await.map_err(|_| Error::Transport)?;
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
    
    tracing::info!("🔐 Setting up VLS gRPC endpoint with HsmdService");
    tracing::info!("   📍 Endpoint: {}:{}", addr.ip(), addr.port());
    tracing::info!("   🌐 Network: {}", network);
    
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
            .expect("join")
            .expect("gRPC transport init"),
    );

    // Create source factory for VLS data management
    let source_factory = Arc::new(DummySourceFactory::new(ldk_data_dir.clone(), network));
    
    // Create signer port that bridges transport to VLS protocol
    let signer_port = Arc::new(TransportSignerPort { transport: transport.clone() });
    
    // Create frontend for VLS integration
    let frontend = Frontend::new(
        Arc::new(SignerPortFront::new(signer_port, network)),
        source_factory,
        bitcoin_rpc_url,
        shutter.signal.clone(),
    );

    // Create development allowlist for sweep address
    let dev_allowlist = Array(vec![WireString(sweep_address.clone().to_string().into_bytes())]);
    
    // Create KeysManagerClient for VLS protocol communication
    let client = KeysManagerClient::new(
        transport,
        network.to_string(),
        Some(KeyDerivationStyle::Ldk),
        Some(dev_allowlist),
    );
    
    // NOTE: Frontend must be started after client is created
    // as the TransportSignerPort is always set to ready
    frontend.start();

    // Get node ID from VLS and persist it
    use lightning_signer::lightning::sign::{NodeSigner, Recipient};
    let node_id = client.get_node_id(Recipient::Node)
        .map_err(|e| VlsError { message: format!("Failed to get node ID from VLS: {:?}", e) })?;
    
    fs::write(&node_id_path, node_id.to_string())
        .map_err(|e| VlsError { message: format!("Failed to write node ID: {}", e) })?;

    tracing::info!("✅ VLS gRPC endpoint with HsmdService initialized successfully!");
    tracing::info!("   🚀 HsmdService running on {}:{}", addr.ip(), addr.port());
    tracing::info!("   🔑 Node ID: {}", node_id);
    tracing::info!("   📋 VLS daemon can now connect and subscribe to this endpoint");
    tracing::info!("   💡 Start VLS with: vlsd --network {} --grpc-port {}", network, vls_port);

    let keys_manager = VlsKeysManager {
        client,
        sweep_address,
    };

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