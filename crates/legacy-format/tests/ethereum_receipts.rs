use legacy_format::ethereum_receipts::{
    receipt_envelope, receipt_trie_entry, ReceiptEncodingError,
};
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
        transaction_hash: [0x11; 32],
        log_index: 100,
        address: [0x11; 20],
        topics: vec![[0x33; 32], [0; 32]],
        data: (0..56).collect(),
    }
}

#[test]
fn legacy_failure_and_pre_byzantium_vectors() {
    let mut receipt = receipt_row();
    receipt.tx_type = 0;
    receipt.status = Some(0);
    receipt.cumulative_gas_used = 0;
    receipt.logs_bloom = [0; 256];
    assert_eq!(
        hex::encode(receipt_envelope(&receipt, &[]).unwrap()),
        include_str!("fixtures/receipt_failure_rlp.hex").trim()
    );
    receipt.status = None;
    receipt.post_state = Some([0x44; 32]);
    receipt.cumulative_gas_used = 21000;
    assert_eq!(
        hex::encode(receipt_envelope(&receipt, &[]).unwrap()),
        include_str!("fixtures/receipt_state_rlp.hex").trim()
    );
}

#[test]
fn nested_logs_and_all_typed_envelopes_match_independent_rlp() {
    let mut receipt = receipt_row();
    receipt.tx_type = 0;
    receipt.cumulative_gas_used = 50000;
    let first = log();
    let mut second = first.clone();
    second.log_index += 1;
    second.address = [0x55; 20];
    second.topics.clear();
    second.data.clear();
    let logs = [first, second];
    let expected = hex::decode(include_str!("fixtures/receipt_logs_rlp.hex").trim()).unwrap();
    assert_eq!(receipt_envelope(&receipt, &logs).unwrap(), expected);
    for kind in 1..=4 {
        receipt.tx_type = kind;
        let encoded = receipt_envelope(&receipt, &logs).unwrap();
        assert_eq!(encoded[0], kind);
        assert_eq!(&encoded[1..], expected);
    }
}

#[test]
fn keys_are_rlp_indices_and_convenience_fields_are_not_in_the_value() {
    let mut receipt = receipt_row();
    let value = receipt_envelope(&receipt, &[]).unwrap();
    receipt.gas_used = None;
    receipt.contract_address = None;
    receipt.effective_gas_price = None;
    receipt.blob_gas_used = None;
    receipt.blob_gas_price = None;
    receipt.deposit_nonce = None;
    receipt.deposit_receipt_version = None;
    receipt.l1_fee = None;
    receipt.l1_gas_used = None;
    receipt.l1_gas_price = None;
    receipt.l1_fee_scalar = None;
    for (index, expected) in [
        (0, "80"),
        (1, "01"),
        (127, "7f"),
        (128, "8180"),
        (256, "820100"),
        (u32::MAX, "84ffffffff"),
    ] {
        receipt.transaction_index = index;
        let (key, encoded) = receipt_trie_entry(&receipt, &[]).unwrap();
        assert_eq!(hex::encode(key), expected);
        assert_eq!(encoded, value);
    }
}

#[test]
fn unsupported_types_and_typed_state_roots_are_rejected() {
    let mut receipt = receipt_row();
    for kind in [5, 0x7e, 0xff] {
        receipt.tx_type = kind;
        assert_eq!(
            receipt_envelope(&receipt, &[]),
            Err(ReceiptEncodingError::UnsupportedType(kind))
        );
    }
    receipt.tx_type = 2;
    receipt.status = None;
    receipt.post_state = Some([0; 32]);
    assert_eq!(
        receipt_envelope(&receipt, &[]),
        Err(ReceiptEncodingError::TypedState)
    );
    receipt.post_state = None;
    assert!(receipt_envelope(&receipt, &[]).is_err());
}

#[test]
fn misplaced_logs_and_invalid_rows_are_not_silently_encoded() {
    let receipt = receipt_row();
    for kind in 0..4 {
        let mut row = log();
        match kind {
            0 => row.block_number += 1,
            1 => row.transaction_index += 1,
            2 => row.transaction_hash = [0xff; 32],
            _ => row.topics = vec![[0; 32]; 5],
        }
        assert!(receipt_envelope(&receipt, &[row]).is_err());
    }
    assert!(receipt_envelope(&receipt, &[log(), log()]).is_err());
    let mut invalid = receipt;
    invalid.status = Some(2);
    assert!(receipt_envelope(&invalid, &[]).is_err());
}
