use clap::{value_parser, Parser};
use rgb_lib::BitcoinNetwork;
use std::path::PathBuf;

use crate::error::AppError;
use crate::utils::check_port_is_available;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path for the node storage directory
    storage_directory_path: PathBuf,

    /// Listening port of the daemon
    #[arg(long, default_value_t = 3001)]
    daemon_listening_port: u16,

    /// Listening port for LN peers
    #[arg(long, default_value_t = 9735)]
    ldk_peer_listening_port: u16,

    /// Bitcoin network
    #[arg(long, default_value_t = BitcoinNetwork::Testnet, value_parser = value_parser!(BitcoinNetwork))]
    network: BitcoinNetwork,

    /// Max allowed media size for upload (in MB)
    #[arg(long, default_value_t = 5)]
    max_media_upload_size_mb: u16,

    /// Enable VLS (Validating Lightning Signer) integration
    #[arg(long)]
    enable_vls: bool,

    /// VLS gRPC listening port
    #[arg(long, default_value_t = 7701)]
    vls_port: u16,

    /// Bitcoin RPC URL for VLS
    #[arg(long, default_value = "http://127.0.0.1:18443")]
    bitcoin_rpc_url: String,

    /// Bitcoin address for VLS sweep operations
    #[arg(long)]
    vls_sweep_address: Option<String>,
}

pub(crate) struct LdkUserInfo {
    pub(crate) storage_dir_path: PathBuf,
    pub(crate) daemon_listening_port: u16,
    pub(crate) ldk_peer_listening_port: u16,
    pub(crate) network: BitcoinNetwork,
    pub(crate) max_media_upload_size_mb: u16,
    pub(crate) enable_vls: bool,
    pub(crate) vls_port: u16,
    pub(crate) bitcoin_rpc_url: String,
    pub(crate) vls_sweep_address: Option<String>,
}

pub(crate) fn parse_startup_args() -> Result<LdkUserInfo, AppError> {
    let args = Args::parse();

    let network = args.network;

    let daemon_listening_port = args.daemon_listening_port;
    check_port_is_available(daemon_listening_port)?;
    let ldk_peer_listening_port = args.ldk_peer_listening_port;
    check_port_is_available(ldk_peer_listening_port)?;

    // Check VLS port availability if VLS is enabled
    if args.enable_vls {
        check_port_is_available(args.vls_port)?;
    }

    Ok(LdkUserInfo {
        storage_dir_path: args.storage_directory_path,
        daemon_listening_port,
        ldk_peer_listening_port,
        network,
        max_media_upload_size_mb: args.max_media_upload_size_mb,
        enable_vls: args.enable_vls,
        vls_port: args.vls_port,
        bitcoin_rpc_url: args.bitcoin_rpc_url,
        vls_sweep_address: args.vls_sweep_address,
    })
}
