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

fn header(block_number: u64) -> legacy_format::headers::HeaderRow {
    legacy_format::headers::HeaderRow {
        block_number,
        block_hash: [0; 32],
        parent_hash: [0; 32],
        ommers_hash: [0; 32],
        beneficiary: [0; 20],
        state_root: [0; 32],
        transactions_root: [0; 32],
        receipts_root: [0; 32],
        logs_bloom: [0; 256],
        difficulty: vec![],
        gas_limit: 0,
        gas_used: 0,
        timestamp: 0,
        extra_data: vec![],
        mix_hash: [0; 32],
        nonce: [0; 8],
        base_fee_per_gas: None,
        withdrawals_root: None,
        blob_gas_used: None,
        excess_blob_gas: None,
        parent_beacon_block_root: None,
        requests_hash: None,
        total_difficulty: None,
    }
}

#[test]
fn header_blooms_or_receipts_and_reset_at_block_boundaries() {
    use legacy_format::bloom::header_blooms;
    let mut first = receipt_row();
    first.logs_bloom = [0; 256];
    first.logs_bloom[0] = 1;
    let mut second = first.clone();
    second.transaction_index += 1;
    second.logs_bloom[0] = 3;
    let mut third = first.clone();
    third.block_number += 2;
    third.logs_bloom[255] = 128;
    let mut headers = [header(8192), header(8193), header(8194)];
    headers[0].logs_bloom[0] = 3;
    headers[2].logs_bloom[0] = 1;
    headers[2].logs_bloom[255] = 128;
    let receipts = [first, second, third];
    header_blooms(&headers, &receipts).unwrap();
    headers[1].logs_bloom[0] = 1;
    assert_eq!(
        header_blooms(&headers, &receipts),
        Err(ConsistencyError::HeaderBloom(8193))
    );
    header_blooms(&[header(0)], &[]).unwrap();
    header_blooms(&[], &[]).unwrap();
}

#[test]
fn header_blooms_reject_receipts_outside_or_between_supplied_headers() {
    use legacy_format::bloom::header_blooms;
    let mut receipt = receipt_row();
    receipt.logs_bloom = [0; 256];
    for headers in [
        vec![],
        vec![header(8191)],
        vec![header(8193)],
        vec![header(8191), header(8193)],
    ] {
        assert_eq!(
            header_blooms(&headers, std::slice::from_ref(&receipt)),
            Err(ConsistencyError::MissingHeader(8192))
        );
    }
}

#[test]
fn header_bloom_api_checks_order_and_shape_before_merging() {
    use legacy_format::bloom::header_blooms;
    assert!(header_blooms(&[header(1), header(0)], &[]).is_err());
    assert!(header_blooms(&[header(0), header(0)], &[]).is_err());
    let mut receipt = receipt_row();
    receipt.status = Some(2);
    assert!(header_blooms(&[header(8192)], &[receipt]).is_err());
}
