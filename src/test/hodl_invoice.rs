use bitcoin::hashes::{sha256::Hash as Sha256, Hash};
use rand::RngCore;

use super::*;

const TEST_DIR_BASE: &str = "tmp/hodl_invoice/";

fn random_preimage_and_hash() -> (String, String) {
    let mut preimage = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut preimage);
    let preimage_hex = hex::encode(preimage);
    let payment_hash = hex::encode(Sha256::hash(&preimage).to_byte_array());
    (preimage_hex, payment_hash)
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn settle_hodl_invoice() {
    initialize();

    let test_dir_base = format!("{TEST_DIR_BASE}settle/");
    let test_dir_node1 = format!("{test_dir_base}node1");
    let test_dir_node2 = format!("{test_dir_base}node2");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr, None).await;
    fund_and_create_utxos(node2_addr, None).await;

    let node2_pubkey = node_info(node2_addr).await.pubkey;
    let _channel = open_channel(
        node1_addr,
        &node2_pubkey,
        Some(NODE2_PEER_PORT),
        Some(500000),
        Some(0),
        None,
        None,
    )
    .await;

    let (preimage_hex, payment_hash_hex) = random_preimage_and_hash();
    let InvoiceHodlResponse { invoice, .. } =
        invoice_hodl(node2_addr, Some(50_000), 900, payment_hash_hex.clone()).await;
    let decoded = decode_ln_invoice(node1_addr, &invoice).await;
    assert_eq!(decoded.payment_hash, payment_hash_hex);

    // Payer sees the payment pending until settle is called.
    let _ = send_payment_with_status(node1_addr, invoice.clone(), HTLCStatus::Pending).await;
    assert!(matches!(invoice_status(node2_addr, &invoice).await, InvoiceStatus::Pending));

    // Settle with the chosen preimage.
    invoice_settle(node2_addr, payment_hash_hex.clone(), preimage_hex.clone()).await;

    let payer_payment =
        wait_for_ln_payment(node1_addr, &decoded.payment_hash, HTLCStatus::Succeeded).await;
    assert_eq!(payer_payment.status, HTLCStatus::Succeeded);
    let payee_payment =
        wait_for_ln_payment(node2_addr, &decoded.payment_hash, HTLCStatus::Succeeded).await;
    assert_eq!(payee_payment.status, HTLCStatus::Succeeded);
    assert!(matches!(invoice_status(node2_addr, &invoice).await, InvoiceStatus::Succeeded));
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn cancel_hodl_invoice() {
    initialize();

    let test_dir_base = format!("{TEST_DIR_BASE}cancel/");
    let test_dir_node1 = format!("{test_dir_base}node1");
    let test_dir_node2 = format!("{test_dir_base}node2");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT + 10, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT + 10, false).await;

    fund_and_create_utxos(node1_addr, None).await;
    fund_and_create_utxos(node2_addr, None).await;

    let node2_pubkey = node_info(node2_addr).await.pubkey;
    let _channel = open_channel(
        node1_addr,
        &node2_pubkey,
        Some(NODE2_PEER_PORT + 10),
        Some(500000),
        Some(0),
        None,
        None,
    )
    .await;

    let (_preimage_hex, payment_hash_hex) = random_preimage_and_hash();
    let InvoiceHodlResponse { invoice, .. } =
        invoice_hodl(node2_addr, Some(40_000), 900, payment_hash_hex.clone()).await;
    let decoded = decode_ln_invoice(node1_addr, &invoice).await;
    assert_eq!(decoded.payment_hash, payment_hash_hex);

    let _ = send_payment_with_status(node1_addr, invoice.clone(), HTLCStatus::Pending).await;
    assert!(matches!(invoice_status(node2_addr, &invoice).await, InvoiceStatus::Pending));

    invoice_cancel(node2_addr, payment_hash_hex.clone()).await;

    let payer_payment =
        wait_for_ln_payment(node1_addr, &decoded.payment_hash, HTLCStatus::Failed).await;
    assert_eq!(payer_payment.status, HTLCStatus::Failed);
    let payee_payment =
        wait_for_ln_payment(node2_addr, &decoded.payment_hash, HTLCStatus::Cancelled).await;
    assert_eq!(payee_payment.status, HTLCStatus::Cancelled);
    assert!(matches!(invoice_status(node2_addr, &invoice).await, InvoiceStatus::Failed));
}
