use bitcoin::hashes::{sha256::Hash as Sha256, Hash};
use rand::RngCore;
use reqwest::StatusCode;
use serde::Serialize;
use std::net::SocketAddr;
use std::path::Path;
use time::OffsetDateTime;

use crate::{
    disk::{read_claimable_htlcs, CLAIMABLE_HTLCS_FNAME},
    error::APIError,
    utils::{hex_str, validate_and_parse_payment_hash, LDK_DIR},
};

use super::*;

const TEST_DIR_BASE: &str = "tmp/hodl_invoice/";

/// Generate a random preimage and its corresponding payment hash.
fn random_preimage_and_hash() -> (String, String) {
    let mut preimage = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut preimage);
    let preimage_hex = hex_str(&preimage);
    let payment_hash = hex_str(&Sha256::hash(&preimage).to_byte_array());
    (preimage_hex, payment_hash)
}

async fn setup_two_nodes_with_channel(
    test_dir_suffix: &str,
    port_offset: u16,
) -> (SocketAddr, SocketAddr, String, String) {
    let test_dir_base = format!("{TEST_DIR_BASE}{test_dir_suffix}/");
    let test_dir_node1 = format!("{test_dir_base}node1");
    let test_dir_node2 = format!("{test_dir_base}node2");
    let node1_port = NODE1_PEER_PORT + port_offset;
    let node2_port = NODE2_PEER_PORT + port_offset;
    let (node1_addr, _) = start_node(&test_dir_node1, node1_port, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, node2_port, false).await;

    fund_and_create_utxos(node1_addr, None).await;
    fund_and_create_utxos(node2_addr, None).await;

    let node2_pubkey = node_info(node2_addr).await.pubkey;
    let _channel = open_channel(
        node1_addr,
        &node2_pubkey,
        Some(node2_port),
        Some(500000),
        Some(0),
        None,
        None,
    )
    .await;

    (node1_addr, node2_addr, test_dir_node1, test_dir_node2)
}

async fn setup_single_node(test_dir_suffix: &str, port_offset: u16) -> (SocketAddr, String) {
    let test_dir_base = format!("{TEST_DIR_BASE}{test_dir_suffix}/");
    let test_dir_node1 = format!("{test_dir_base}node1");
    let node1_port = NODE1_PEER_PORT + port_offset;
    let (node1_addr, _) = start_node(&test_dir_node1, node1_port, false).await;
    fund_and_create_utxos(node1_addr, None).await;
    (node1_addr, test_dir_node1)
}

async fn invoice_post_expect_error<T: Serialize>(
    node_address: SocketAddr,
    path: &str,
    payload: &T,
    expected_status: StatusCode,
    expected_message: &str,
    expected_name: &str,
) {
    let res = reqwest::Client::new()
        .post(format!("http://{node_address}{path}"))
        .json(payload)
        .send()
        .await
        .unwrap();
    check_response_is_nok(res, expected_status, expected_message, expected_name).await;
}

async fn invoice_hodl_expect_error(
    node_address: SocketAddr,
    amt_msat: Option<u64>,
    expiry_sec: u32,
    payment_hash: String,
    expected_status: StatusCode,
    expected_message: &str,
    expected_name: &str,
) {
    println!("creating HODL invoice on node {node_address}");
    let payload = InvoiceHodlRequest {
        amt_msat,
        expiry_sec,
        asset_id: None,
        asset_amount: None,
        payment_hash,
        external_ref: None,
    };
    invoice_post_expect_error(
        node_address,
        "/invoice/hodl",
        &payload,
        expected_status,
        expected_message,
        expected_name,
    )
    .await;
}

async fn invoice_settle_expect_error(
    node_address: SocketAddr,
    payment_hash: String,
    payment_preimage: String,
    expected_status: StatusCode,
    expected_message: &str,
    expected_name: &str,
) {
    println!("settling HODL invoice {payment_hash} on node {node_address}");
    let payload = InvoiceSettleRequest {
        payment_hash,
        payment_preimage,
    };
    invoice_post_expect_error(
        node_address,
        "/invoice/settle",
        &payload,
        expected_status,
        expected_message,
        expected_name,
    )
    .await;
}

fn expect_api_ok<T>(result: Result<T, APIError>, context: &str) -> T {
    match result {
        Ok(value) => value,
        Err(err) => panic!("{context}: {err}"),
    }
}

/// Check if the claimable HTLC entry exists in the node's on-disk store.
fn claimable_exists(node_test_dir: &str, payment_hash_hex: &str) -> Result<bool, APIError> {
    let claimable_path = Path::new(node_test_dir)
        .join(LDK_DIR)
        .join(CLAIMABLE_HTLCS_FNAME);
    let storage = read_claimable_htlcs(&claimable_path);
    let hash = validate_and_parse_payment_hash(payment_hash_hex)?;
    Ok(storage.payments.contains_key(&hash))
}

/// Poll until the claimable entry appears or disappears (bounded by timeout).
async fn wait_for_claimable_state(
    node_test_dir: &str,
    payment_hash_hex: &str,
    expected: bool,
) -> Result<(), APIError> {
    let t_0 = OffsetDateTime::now_utc();
    loop {
        if claimable_exists(node_test_dir, payment_hash_hex)? == expected {
            return Ok(());
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 20.0 {
            return Err(APIError::Unexpected(format!(
                "claimable entry for {payment_hash_hex} did not reach state {expected}"
            )));
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn settle_hodl_invoice() {
    initialize();

    // Arrange: start two nodes, fund, and open a channel.
    let (node1_addr, node2_addr, _test_dir_node1, test_dir_node2) =
        setup_two_nodes_with_channel("settle", 0).await;

    // Arrange: create a HODL invoice with a fixed payment hash.
    let (preimage_hex, payment_hash_hex) = random_preimage_and_hash();
    let InvoiceHodlResponse { invoice, .. } =
        invoice_hodl(node2_addr, Some(50_000), 900, payment_hash_hex.clone()).await;
    let decoded = decode_ln_invoice(node1_addr, &invoice).await;
    assert_eq!(decoded.payment_hash, payment_hash_hex);

    // Act: pay the invoice; HODL keeps it pending and claimable.
    let _ = send_payment_with_status(node1_addr, invoice.clone(), HTLCStatus::Pending).await;
    assert!(matches!(invoice_status(node2_addr, &invoice).await, InvoiceStatus::Pending));
    expect_api_ok(
        wait_for_claimable_state(&test_dir_node2, &payment_hash_hex, true).await,
        "wait for claimable entry to appear",
    );

    // Act: settle with the chosen preimage.
    invoice_settle(node2_addr, payment_hash_hex.clone(), preimage_hex.clone()).await;

    // Assert: payer/payee succeed and claimable entry is removed.
    let payer_payment =
        wait_for_ln_payment(node1_addr, &decoded.payment_hash, HTLCStatus::Succeeded).await;
    assert_eq!(payer_payment.status, HTLCStatus::Succeeded);
    let payee_payment =
        wait_for_ln_payment(node2_addr, &decoded.payment_hash, HTLCStatus::Succeeded).await;
    assert_eq!(payee_payment.status, HTLCStatus::Succeeded);
    assert!(matches!(invoice_status(node2_addr, &invoice).await, InvoiceStatus::Succeeded));
    expect_api_ok(
        wait_for_claimable_state(&test_dir_node2, &payment_hash_hex, false).await,
        "wait for claimable entry to be removed",
    );
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn cancel_hodl_invoice() {
    initialize();

    // Arrange: start two nodes, fund, and open a channel.
    let (node1_addr, node2_addr, _test_dir_node1, test_dir_node2) =
        setup_two_nodes_with_channel("cancel", 10).await;

    // Arrange: create a HODL invoice with a fixed payment hash.
    let (_preimage_hex, payment_hash_hex) = random_preimage_and_hash();
    let InvoiceHodlResponse { invoice, .. } =
        invoice_hodl(node2_addr, Some(40_000), 900, payment_hash_hex.clone()).await;
    let decoded = decode_ln_invoice(node1_addr, &invoice).await;
    assert_eq!(decoded.payment_hash, payment_hash_hex);

    // Act: pay the invoice; it should be pending and claimable.
    let _ = send_payment_with_status(node1_addr, invoice.clone(), HTLCStatus::Pending).await;
    assert!(matches!(invoice_status(node2_addr, &invoice).await, InvoiceStatus::Pending));
    expect_api_ok(
        wait_for_claimable_state(&test_dir_node2, &payment_hash_hex, true).await,
        "wait for claimable entry to appear",
    );

    // Act: cancel and fail back the HTLC.
    invoice_cancel(node2_addr, payment_hash_hex.clone()).await;

    // Assert: payer fails, payee cancels, and claimable entry is removed.
    let payer_payment =
        wait_for_ln_payment(node1_addr, &decoded.payment_hash, HTLCStatus::Failed).await;
    assert_eq!(payer_payment.status, HTLCStatus::Failed);
    let payee_payment =
        wait_for_ln_payment(node2_addr, &decoded.payment_hash, HTLCStatus::Cancelled).await;
    assert_eq!(payee_payment.status, HTLCStatus::Cancelled);
    assert!(matches!(
        invoice_status(node2_addr, &invoice).await,
        InvoiceStatus::Cancelled
    ));
    expect_api_ok(
        wait_for_claimable_state(&test_dir_node2, &payment_hash_hex, false).await,
        "wait for claimable entry to be removed",
    );
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn expire_hodl_invoice() {
    initialize();

    // Arrange: start two nodes, fund, and open a channel.
    let (node1_addr, node2_addr, _test_dir_node1, test_dir_node2) =
        setup_two_nodes_with_channel("expiry", 20).await;

    // Arrange: create a short-expiry HODL invoice (20s).
    let (_preimage_hex, payment_hash_hex) = random_preimage_and_hash();
    // Use a small-but-not-too-small expiry to let the payment reach Pending
    // before the background expiry task fails it.
    let InvoiceHodlResponse { invoice, .. } =
        invoice_hodl(node2_addr, Some(30_000), 20, payment_hash_hex.clone()).await;
    let decoded = decode_ln_invoice(node1_addr, &invoice).await;
    assert_eq!(decoded.payment_hash, payment_hash_hex);

    // Act: pay and wait for the background expiry task to fail the HTLC.
    // Timing note: expiry is 20s, the expiry task runs every 30s, and the payment wait timeout
    // is 40s, so this should succeed on the next expiry tick.
    let _ = send_payment_with_status(node1_addr, invoice.clone(), HTLCStatus::Pending).await;
    expect_api_ok(
        wait_for_claimable_state(&test_dir_node2, &payment_hash_hex, true).await,
        "wait for claimable entry to appear",
    );

    // Assert: both sides see Failed and claimable entry is removed.
    let payer_payment =
        wait_for_ln_payment(node1_addr, &decoded.payment_hash, HTLCStatus::Failed).await;
    assert_eq!(payer_payment.status, HTLCStatus::Failed);
    let payee_payment =
        wait_for_ln_payment(node2_addr, &decoded.payment_hash, HTLCStatus::Failed).await;
    assert_eq!(payee_payment.status, HTLCStatus::Failed);
    assert!(matches!(invoice_status(node2_addr, &invoice).await, InvoiceStatus::Failed));
    expect_api_ok(
        wait_for_claimable_state(&test_dir_node2, &payment_hash_hex, false).await,
        "wait for claimable entry to be removed",
    );
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn reject_wrong_preimage_settle() {
    initialize();

    // Arrange: start two nodes, fund, and open a channel.
    let (node1_addr, node2_addr, _test_dir_node1, test_dir_node2) =
        setup_two_nodes_with_channel("wrong_preimage", 30).await;

    // Arrange: create a HODL invoice and pay it (pending).
    let (_preimage_hex, payment_hash_hex) = random_preimage_and_hash();
    let InvoiceHodlResponse { invoice, .. } =
        invoice_hodl(node2_addr, Some(35_000), 900, payment_hash_hex.clone()).await;
    let decoded = decode_ln_invoice(node1_addr, &invoice).await;
    assert_eq!(decoded.payment_hash, payment_hash_hex);

    let _ = send_payment_with_status(node1_addr, invoice.clone(), HTLCStatus::Pending).await;
    expect_api_ok(
        wait_for_claimable_state(&test_dir_node2, &payment_hash_hex, true).await,
        "wait for claimable entry to appear",
    );

    // Act: try to settle with a mismatching preimage.
    let (wrong_preimage_hex, _) = random_preimage_and_hash();
    invoice_settle_expect_error(
        node2_addr,
        payment_hash_hex.clone(),
        wrong_preimage_hex,
        StatusCode::BAD_REQUEST,
        "Invalid payment preimage",
        "InvalidPaymentPreimage",
    )
    .await;

    // Assert: invoice stays pending and claimable entry remains.
    assert!(matches!(invoice_status(node2_addr, &invoice).await, InvoiceStatus::Pending));
    expect_api_ok(
        wait_for_claimable_state(&test_dir_node2, &payment_hash_hex, true).await,
        "wait for claimable entry to remain",
    );
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn reject_duplicate_hodl_payment_hash() {
    initialize();

    // Arrange: start a node and fund it.
    let (node1_addr, _test_dir_node1) = setup_single_node("duplicate_hash", 40).await;

    // Arrange: create the first HODL invoice.
    let (_preimage_hex, payment_hash_hex) = random_preimage_and_hash();
    let InvoiceHodlResponse { invoice, .. } =
        invoice_hodl(node1_addr, Some(20_000), 900, payment_hash_hex.clone()).await;

    // Act: attempt to create another HODL invoice with the same hash.
    invoice_hodl_expect_error(
        node1_addr,
        Some(20_000),
        900,
        payment_hash_hex.clone(),
        StatusCode::BAD_REQUEST,
        "Payment hash already used",
        "PaymentHashAlreadyUsed",
    )
    .await;

    // Assert: the original invoice remains pending.
    assert!(matches!(invoice_status(node1_addr, &invoice).await, InvoiceStatus::Pending));
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn auto_claim_invoice_regression() {
    initialize();

    // Arrange: start two nodes, fund, and open a channel.
    let (node1_addr, node2_addr, _test_dir_node1, _test_dir_node2) =
        setup_two_nodes_with_channel("autoclaim", 50).await;

    // Act: create and pay a normal (auto-claim) invoice.
    let LNInvoiceResponse { invoice } = ln_invoice(node2_addr, Some(25_000), None, None, 900).await;
    let decoded = decode_ln_invoice(node1_addr, &invoice).await;

    let _ = send_payment_with_status(node1_addr, invoice.clone(), HTLCStatus::Succeeded).await;
    // Assert: both sides succeed and invoice status updates.
    let payer_payment =
        wait_for_ln_payment(node1_addr, &decoded.payment_hash, HTLCStatus::Succeeded).await;
    assert_eq!(payer_payment.status, HTLCStatus::Succeeded);
    let payee_payment =
        wait_for_ln_payment(node2_addr, &decoded.payment_hash, HTLCStatus::Succeeded).await;
    assert_eq!(payee_payment.status, HTLCStatus::Succeeded);
    assert!(matches!(invoice_status(node2_addr, &invoice).await, InvoiceStatus::Succeeded));
}
