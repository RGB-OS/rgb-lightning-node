use super::*;

const TEST_DIR_BASE: &str = "tmp/swap_roundtrip_buy_same_channel/";
const NODE1_PEER_PORT: u16 = 9821;
const NODE2_PEER_PORT: u16 = 9822;
const NODE3_PEER_PORT: u16 = 9823;

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn swap_roundtrip_buy_same_channel() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let test_dir_node2 = format!("{TEST_DIR_BASE}node2");
    let test_dir_node3 = format!("{TEST_DIR_BASE}node3");
    let (node1_addr, _) = start_node(test_dir_node1.clone(), NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(test_dir_node2.clone(), NODE2_PEER_PORT, false).await;
    let (node3_addr, _) = start_node(test_dir_node3.clone(), NODE3_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr).await;
    fund_and_create_utxos(node2_addr).await;
    fund_and_create_utxos(node3_addr).await;

    let asset_id = issue_asset(node1_addr).await;

    let node2_info = node_info(node2_addr).await;
    let node2_pubkey = node2_info.pubkey;

    let channel_12 = open_channel(
        node1_addr,
        &node2_pubkey,
        NODE2_PEER_PORT,
        Some(100000),
        Some(50000000),
        Some(600),
        Some(&asset_id),
    )
    .await;

    println!("\nsetup swap");
    let maker_addr = node1_addr;
    let taker_addr = node2_addr;
    let qty_from = 25000;
    let qty_to = 10;
    let maker_init_response =
        maker_init(maker_addr, qty_from, None, qty_to, Some(&asset_id), 3600).await;
    taker(taker_addr, maker_init_response.swapstring.clone()).await;

    let swaps_maker = list_swaps(maker_addr).await;
    assert!(swaps_maker.taker.is_empty());
    assert_eq!(swaps_maker.maker.len(), 1);
    let swap_maker = swaps_maker.maker.first().unwrap();
    assert_eq!(swap_maker.qty_from, qty_from);
    assert_eq!(swap_maker.qty_to, qty_to);
    assert_eq!(swap_maker.from_asset, None);
    assert_eq!(swap_maker.to_asset, Some(asset_id.clone()));
    assert_eq!(swap_maker.payment_hash, maker_init_response.payment_hash);
    assert_eq!(swap_maker.status, SwapStatus::Waiting);
    let swaps_taker = list_swaps(taker_addr).await;
    assert!(swaps_taker.maker.is_empty());
    assert_eq!(swaps_taker.taker.len(), 1);
    let swap_taker = swaps_taker.taker.first().unwrap();
    assert_eq!(swap_taker.qty_from, qty_from);
    assert_eq!(swap_taker.qty_to, qty_to);
    assert_eq!(swap_maker.from_asset, None);
    assert_eq!(swap_maker.to_asset, Some(asset_id.clone()));
    assert_eq!(swap_taker.payment_hash, maker_init_response.payment_hash);
    assert_eq!(swap_taker.status, SwapStatus::Waiting);

    println!("\nexecute swap");
    maker_execute(
        maker_addr,
        maker_init_response.swapstring,
        maker_init_response.payment_secret,
        node2_pubkey.clone(),
    )
    .await;

    let swaps_maker = list_swaps(maker_addr).await;
    assert_eq!(swaps_maker.maker.len(), 1);
    let swap_maker = swaps_maker.maker.first().unwrap();
    assert_eq!(swap_maker.status, SwapStatus::Pending);
    wait_for_swap_status(
        taker_addr,
        &maker_init_response.payment_hash,
        SwapStatus::Pending,
    )
    .await;

    wait_for_ln_balance(maker_addr, &asset_id, 590).await;
    wait_for_ln_balance(taker_addr, &asset_id, 10).await;

    println!("\nrestart nodes");
    shutdown(&[node1_addr, node2_addr]).await;
    let (node1_addr, _) = start_node(test_dir_node1.clone(), NODE1_PEER_PORT, true).await;
    let (node2_addr, _) = start_node(test_dir_node2.clone(), NODE2_PEER_PORT, true).await;
    let maker_addr = node1_addr;
    let taker_addr = node2_addr;

    println!("\ncheck off-chain balances and payments after nodes have restarted");
    let balance_1 = asset_balance(node1_addr, &asset_id).await;
    let balance_2 = asset_balance(node2_addr, &asset_id).await;
    assert_eq!(balance_1.offchain_outbound, 590);
    assert_eq!(balance_1.offchain_inbound, 10);
    assert_eq!(balance_2.offchain_outbound, 10);
    assert_eq!(balance_2.offchain_inbound, 590);

    let swaps_maker = list_swaps(maker_addr).await;
    assert_eq!(swaps_maker.maker.len(), 1);
    let swap_maker = swaps_maker.maker.first().unwrap();
    assert_eq!(swap_maker.status, SwapStatus::Succeeded);
    let swaps_taker = list_swaps(taker_addr).await;
    assert_eq!(swaps_taker.taker.len(), 1);
    let swap_taker = swaps_taker.taker.first().unwrap();
    assert_eq!(swap_taker.status, SwapStatus::Succeeded);

    let payments_maker = list_payments(maker_addr).await;
    assert!(payments_maker.is_empty());
    let payments_taker = list_payments(taker_addr).await;
    assert!(payments_taker.is_empty());

    println!("\nclose channels");
    close_channel(node1_addr, &channel_12.channel_id, &node2_pubkey, false).await;
    wait_for_balance(node1_addr, &asset_id, 990).await;
    wait_for_balance(node2_addr, &asset_id, 10).await;

    println!("\nspend assets");
    let recipient_id = rgb_invoice(node3_addr, None).await.recipient_id;
    send_asset(node1_addr, &asset_id, 200, recipient_id).await;
    mine(false);
    refresh_transfers(node3_addr).await;
    refresh_transfers(node3_addr).await;
    refresh_transfers(node1_addr).await;

    let recipient_id = rgb_invoice(node3_addr, None).await.recipient_id;
    send_asset(node2_addr, &asset_id, 5, recipient_id).await;
    mine(false);
    refresh_transfers(node3_addr).await;
    refresh_transfers(node3_addr).await;
    refresh_transfers(node2_addr).await;

    assert_eq!(asset_balance_spendable(node1_addr, &asset_id).await, 790);
    assert_eq!(asset_balance_spendable(node2_addr, &asset_id).await, 5);
    assert_eq!(asset_balance_spendable(node3_addr, &asset_id).await, 205);
}
