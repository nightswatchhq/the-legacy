use legacy_format::consistency::*;
fn transaction_row() -> legacy_format::transactions::TransactionRow {
    legacy_format::transactions::TransactionRow {
        block_number: 8192,
        transaction_index: 7,
        transaction_hash: [0x11; 32],
        tx_type: 2,
        nonce: u64::MAX,
        from: [0x22; 20],
        to: Some([0x33; 20]),
        value: vec![1, 2],
        gas_limit: 21000,
        gas_price: None,
        max_fee_per_gas: Some(vec![3]),
        max_priority_fee_per_gas: Some(vec![]),
        max_fee_per_blob_gas: None,
        input: vec![0xaa, 0xbb],
        access_list: Some(vec![0xc0]),
        blob_versioned_hashes: None,
        authorization_list: None,
        v_or_y_parity: Some(1),
        r: Some([0x44; 32]),
        s: Some([0x55; 32]),
        chain_id: Some(u64::MAX),
        source_hash: None,
        mint: None,
        is_system_tx: None,
        raw_envelope: Some(vec![2, 0xc0]),
    }
}

fn receipt_row() -> legacy_format::receipts::ReceiptRow {
    legacy_format::receipts::ReceiptRow {
        block_number: 8192,
        transaction_index: 7,
        transaction_hash: [0x11; 32],
        tx_type: 2,
        status: Some(1),
        post_state: None,
        cumulative_gas_used: u64::MAX,
        logs_bloom: [0x22; 256],
        gas_used: Some(21000),
        contract_address: Some([0x33; 20]),
        effective_gas_price: Some(vec![1, 2]),
        blob_gas_used: Some(131072),
        blob_gas_price: Some(vec![]),
        deposit_nonce: Some(u64::MAX),
        deposit_receipt_version: Some(1),
        l1_fee: Some(vec![3]),
        l1_gas_used: None,
        l1_gas_price: Some(vec![4]),
        l1_fee_scalar: Some(vec![0, 5]),
    }
}

fn log() -> legacy_format::logs::LogRow {
    legacy_format::logs::LogRow {
        block_number: 8192,
        transaction_index: 7,
        log_index: 0,
        transaction_hash: [0x11; 32],
        address: [0; 20],
        topics: vec![],
        data: vec![],
    }
}

#[test]
fn links_validate_keys_hashes_and_types_but_not_missing_pairs() {
    let tx = transaction_row();
    let mut receipt = receipt_row();
    transaction_receipt_links(std::slice::from_ref(&tx), std::slice::from_ref(&receipt)).unwrap();
    receipt.tx_type = 0;
    assert!(transaction_receipt_links(&[tx], &[receipt]).is_err());
    transaction_receipt_links(&[], &[]).unwrap(); // Not proof of completeness.
}

#[test]
fn logs_require_matching_key_and_hash_on_both_paths() {
    let mut log = log();
    let tx = transaction_row();
    let receipt = receipt_row();
    log_transaction_links(std::slice::from_ref(&log), std::slice::from_ref(&tx)).unwrap();
    log_receipt_links(std::slice::from_ref(&log), std::slice::from_ref(&receipt)).unwrap();
    for kind in 0..3 {
        log = self::log();
        match kind {
            0 => log.block_number += 1,
            1 => log.transaction_index += 1,
            _ => log.transaction_hash = [0; 32],
        }
        assert!(
            log_transaction_links(std::slice::from_ref(&log), std::slice::from_ref(&tx)).is_err()
        );
        assert!(
            log_receipt_links(std::slice::from_ref(&log), std::slice::from_ref(&receipt)).is_err()
        );
    }
    assert!(log_receipt_links(&[self::log()], &[]).is_err());
}

#[test]
fn public_link_checks_reject_unvalidated_disorder_and_duplicate_rows() {
    let tx = transaction_row();
    let receipt = receipt_row();
    assert!(transaction_receipt_links(
        &[tx.clone(), tx.clone()],
        &[receipt.clone(), receipt.clone()]
    )
    .is_err());
    assert!(log_transaction_links(&[], &[tx.clone(), tx]).is_err());
    assert!(log_receipt_links(&[], &[receipt.clone(), receipt]).is_err());
}

#[test]
fn receipt_blooms_group_logs_and_check_receipts_without_logs() {
    use legacy_format::bloom::{logs_bloom, receipt_blooms};
    let mut first = log();
    first.topics = vec![[1; 32], [2; 32], [3; 32], [4; 32]];
    let mut second = first.clone();
    second.log_index = 1;
    second.address = [5; 20];
    let logs = [first, second];
    let mut receipt = receipt_row();
    receipt.logs_bloom = logs_bloom(&logs).unwrap();
    let mut empty = receipt.clone();
    empty.transaction_index += 1;
    empty.logs_bloom = [0; 256];
    receipt_blooms(&logs, &[receipt.clone(), empty.clone()]).unwrap();
    empty.logs_bloom[0] = 1;
    assert!(receipt_blooms(&logs, &[receipt.clone(), empty]).is_err());
    receipt.logs_bloom[0] ^= 1;
    assert!(receipt_blooms(&logs, &[receipt]).is_err());
    receipt_blooms(&[], &[]).unwrap();
}

#[test]
fn blooms_cover_addresses_and_topics_but_not_data_or_multiplicity() {
    use legacy_format::bloom::logs_bloom;
    let mut row = log();
    row.topics = vec![[1; 32]];
    let expected = logs_bloom(std::slice::from_ref(&row)).unwrap();
    row.data = vec![0xff; 100];
    assert_eq!(logs_bloom(std::slice::from_ref(&row)).unwrap(), expected);
    let mut repeated = row.clone();
    repeated.log_index += 1;
    assert_eq!(logs_bloom(&[row.clone(), repeated]).unwrap(), expected);
    row.address = [0xff; 20];
    assert_ne!(logs_bloom(std::slice::from_ref(&row)).unwrap(), expected);
    row = log();
    row.topics = vec![[2; 32]];
    assert_ne!(logs_bloom(&[row]).unwrap(), expected);
    assert_eq!(logs_bloom(&[]).unwrap(), [0; 256]);
}

#[test]
fn bloom_checker_does_not_silently_drop_orphan_or_disordered_logs() {
    use legacy_format::bloom::receipt_blooms;
    let row = log();
    assert!(receipt_blooms(std::slice::from_ref(&row), &[]).is_err());
    let mut receipt = receipt_row();
    receipt.transaction_hash = [0xff; 32];
    assert!(receipt_blooms(std::slice::from_ref(&row), &[receipt]).is_err());
    assert!(receipt_blooms(&[row.clone(), row], &[receipt_row()]).is_err());
}
