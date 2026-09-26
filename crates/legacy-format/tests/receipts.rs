use legacy_format::receipts::{content_hash, validate_rows, ReceiptError, ReceiptRow};
fn fixture() -> ReceiptRow {
    ReceiptRow {
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

#[test]
fn both_outcome_encodings_match_independent_vectors() {
    let mut row = fixture();
    assert_eq!(
        row.canonical_bytes().unwrap(),
        hex::decode(include_str!("fixtures/receipt_status_v1.hex").trim()).unwrap()
    );
    row.status = None;
    row.post_state = Some([0x44; 32]);
    assert_eq!(
        row.canonical_bytes().unwrap(),
        hex::decode(include_str!("fixtures/receipt_state_v1.hex").trim()).unwrap()
    );
}

#[test]
fn exactly_one_outcome_and_boolean_status_are_required() {
    let mut row = fixture();
    row.status = None;
    assert_eq!(row.canonical_bytes(), Err(ReceiptError::Outcome));
    row.post_state = Some([0; 32]);
    assert!(row.canonical_bytes().is_ok());
    row.status = Some(1);
    assert_eq!(row.canonical_bytes(), Err(ReceiptError::Outcome));
    row.post_state = None;
    row.status = Some(2);
    assert_eq!(row.canonical_bytes(), Err(ReceiptError::Status));
    row.status = Some(0);
    assert!(row.canonical_bytes().is_ok());
}

#[test]
fn magnitudes_are_minimal_but_scalar_is_opaque() {
    let mut row = fixture();
    assert!(row.canonical_bytes().is_ok()); // scalar begins with zero
    row.effective_gas_price = Some(vec![0]);
    assert!(row.canonical_bytes().is_err());
    row.effective_gas_price = Some(vec![0xff; 32]);
    assert!(row.canonical_bytes().is_ok());
    row.l1_gas_used = Some(vec![1; 33]);
    assert!(row.canonical_bytes().is_err());
}

#[test]
fn null_empty_and_zero_have_distinct_identity() {
    let mut row = fixture();
    let hash = content_hash(std::slice::from_ref(&row)).unwrap();
    row.blob_gas_price = None;
    assert_ne!(content_hash(std::slice::from_ref(&row)).unwrap(), hash);
    let hash = content_hash(std::slice::from_ref(&row)).unwrap();
    row.status = Some(0);
    assert_ne!(content_hash(std::slice::from_ref(&row)).unwrap(), hash);
    assert_eq!(content_hash(&[]).unwrap(), legacy_format::hash::blake3(&[]));
}

#[test]
fn rows_are_strictly_ordered_but_slices_need_not_be_contiguous() {
    let row = fixture();
    let mut next = row.clone();
    next.transaction_index += 10;
    assert!(validate_rows(&[row.clone(), next.clone()]).is_ok());
    assert_eq!(
        validate_rows(&[next, row.clone()]),
        Err(ReceiptError::OutOfOrder)
    );
    assert_eq!(
        validate_rows(&[row.clone(), row]),
        Err(ReceiptError::OutOfOrder)
    );
}
