use legacy_format::transactions::{content_hash, validate_rows, TransactionError, TransactionRow};
fn fixture() -> TransactionRow {
    TransactionRow {
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

#[test]
fn canonical_row_matches_independent_vector() {
    let expected = hex::decode(include_str!("fixtures/transaction_v1.hex").trim()).unwrap();
    assert_eq!(fixture().canonical_bytes().unwrap(), expected);
}

#[test]
fn raw_envelope_does_not_change_content_identity_but_null_and_zero_do() {
    let row = fixture();
    let expected = content_hash(std::slice::from_ref(&row)).unwrap();
    let mut changed = row.clone();
    changed.raw_envelope = None;
    assert_eq!(
        content_hash(std::slice::from_ref(&changed)).unwrap(),
        expected
    );
    changed.raw_envelope = Some(vec![0xff; 1000]);
    assert_eq!(
        content_hash(std::slice::from_ref(&changed)).unwrap(),
        expected
    );
    changed.max_priority_fee_per_gas = None;
    assert_ne!(content_hash(&[changed]).unwrap(), expected);
}

#[test]
fn rejects_duplicate_disordered_and_nonminimal_rows() {
    let row = fixture();
    assert_eq!(
        validate_rows(&[row.clone(), row.clone()]),
        Err(TransactionError::OutOfOrder)
    );
    let mut next = row.clone();
    next.block_number += 1;
    assert!(validate_rows(&[row.clone(), next.clone()]).is_ok());
    assert_eq!(
        validate_rows(&[next, row.clone()]),
        Err(TransactionError::OutOfOrder)
    );
    let mut malformed = row.clone();
    malformed.value = vec![0];
    assert!(malformed.canonical_bytes().is_err());
    let mut malformed = row;
    malformed.mint = Some(vec![1; 33]);
    assert!(malformed.canonical_bytes().is_err());
}

#[test]
fn parity_representation_handles_large_chain_ids_without_truncating_v() {
    let mut row = fixture();
    row.tx_type = 0;
    for parity in [0, 1] {
        row.v_or_y_parity = Some(parity);
        assert!(row.canonical_bytes().is_ok());
    }
    row.v_or_y_parity = Some(37);
    assert_eq!(row.canonical_bytes(), Err(TransactionError::Parity));
    row.chain_id = None;
    for parity in [27, 28] {
        row.v_or_y_parity = Some(parity);
        assert!(row.canonical_bytes().is_ok());
    }
    row.v_or_y_parity = Some(0);
    assert_eq!(row.canonical_bytes(), Err(TransactionError::Parity));
    row.tx_type = 0x7e;
    row.v_or_y_parity = None;
    assert!(row.canonical_bytes().is_ok());
}
