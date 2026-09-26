use legacy_format::ethereum_transactions::{
    transaction_hash, transaction_root, verify_transaction_roots, TransactionEncodingError,
};
use legacy_format::headers::HeaderRow;
use legacy_format::transactions::TransactionRow;

fn transaction(index: u32, tx_type: u8, raw_envelope: Vec<u8>) -> TransactionRow {
    TransactionRow {
        block_number: 42,
        transaction_index: index,
        transaction_hash: transaction_hash(&raw_envelope),
        tx_type,
        nonce: 0,
        from: [0; 20],
        to: None,
        value: vec![],
        gas_limit: 0,
        gas_price: None,
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
        max_fee_per_blob_gas: None,
        input: vec![],
        access_list: None,
        blob_versioned_hashes: None,
        authorization_list: None,
        v_or_y_parity: None,
        r: None,
        s: None,
        chain_id: None,
        source_hash: None,
        mint: None,
        is_system_tx: None,
        raw_envelope: Some(raw_envelope),
    }
}

fn header(root: [u8; 32]) -> HeaderRow {
    HeaderRow {
        block_number: 42,
        block_hash: [0; 32],
        parent_hash: [0; 32],
        ommers_hash: [0; 32],
        beneficiary: [0; 20],
        state_root: [0; 32],
        transactions_root: root,
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
fn roots_use_raw_legacy_and_typed_envelopes() {
    let rows = [
        transaction(0, 0, vec![0xc0]),
        transaction(1, 2, vec![2, 0xc0]),
    ];
    let root = transaction_root(42, &rows).unwrap();
    assert_eq!(
        hex::encode(root),
        "739d87be98f2f8b2bcdd543b37ec9c1eca2d811f456bcd1be33af40c091847ef"
    );
    assert!(verify_transaction_roots(&[header(root)], &rows).is_ok());
    assert_eq!(
        verify_transaction_roots(&[header([0; 32])], &rows),
        Err(TransactionEncodingError::Root(42))
    );
}

#[test]
fn roots_reject_missing_mismatched_and_noncontiguous_envelopes() {
    let mut row = transaction(0, 2, vec![2, 0xc0]);
    row.raw_envelope = None;
    assert_eq!(
        transaction_root(42, &[row]),
        Err(TransactionEncodingError::MissingEnvelope(42, 0))
    );
    let mut row = transaction(0, 2, vec![2, 0xc0]);
    row.transaction_hash = [0; 32];
    assert_eq!(
        transaction_root(42, &[row]),
        Err(TransactionEncodingError::Hash(42, 0))
    );
    let row = transaction(1, 2, vec![2, 0xc0]);
    assert_eq!(
        transaction_root(42, &[row]),
        Err(TransactionEncodingError::BlockRows(42))
    );
    let row = transaction(0, 2, vec![0xc0]);
    assert_eq!(
        transaction_root(42, &[row]),
        Err(TransactionEncodingError::Envelope(42, 0))
    );
}
