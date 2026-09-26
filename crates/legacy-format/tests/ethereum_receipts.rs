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

// Independent, deliberately simple recursive MPT used only as a test oracle. Production uses
// Alloy's streaming hash builder. Child nodes shorter than 32 bytes are embedded, not hashed.
fn reference_root(values: &[Vec<u8>]) -> [u8; 32] {
    use alloy_rlp::Encodable;
    use sha3::{Digest, Keccak256};
    fn string(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        bytes.encode(&mut out);
        out
    }
    fn list(fields: Vec<Vec<u8>>) -> Vec<u8> {
        let payload: Vec<u8> = fields.into_iter().flatten().collect();
        let mut out = Vec::new();
        alloy_rlp::Header {
            list: true,
            payload_length: payload.len(),
        }
        .encode(&mut out);
        out.extend(payload);
        out
    }
    fn path(nibbles: &[u8], leaf: bool) -> Vec<u8> {
        let odd = nibbles.len() % 2;
        let mut out = vec![(u8::from(leaf) * 2 + odd as u8) << 4];
        if odd != 0 {
            out[0] |= nibbles[0];
        }
        for pair in nibbles[odd..].chunks(2) {
            out.push(pair[0] * 16 + pair[1]);
        }
        string(&out)
    }
    fn child(node: Vec<u8>) -> Vec<u8> {
        if node.len() < 32 {
            node
        } else {
            string(&Keccak256::digest(node))
        }
    }
    fn node(items: &[(Vec<u8>, Vec<u8>)], depth: usize) -> Vec<u8> {
        if items.len() == 1 {
            return list(vec![path(&items[0].0[depth..], true), string(&items[0].1)]);
        }
        let mut common = depth;
        while items.iter().all(|item| {
            item.0.get(common).is_some() && item.0.get(common) == items[0].0.get(common)
        }) {
            common += 1;
        }
        if common > depth {
            return list(vec![
                path(&items[0].0[depth..common], false),
                child(node(items, common)),
            ]);
        }
        let mut fields = Vec::new();
        for nibble in 0..16 {
            let group: Vec<_> = items
                .iter()
                .filter(|item| item.0.get(depth) == Some(&nibble))
                .cloned()
                .collect();
            fields.push(if group.is_empty() {
                string(&[])
            } else {
                child(node(&group, depth + 1))
            });
        }
        fields.push(
            items
                .iter()
                .find(|item| item.0.len() == depth)
                .map_or_else(|| string(&[]), |item| string(&item.1)),
        );
        list(fields)
    }
    let items: Vec<_> = values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let mut key = Vec::new();
            index.encode(&mut key);
            (
                key.into_iter()
                    .flat_map(|byte| [byte >> 4, byte & 15])
                    .collect(),
                value.clone(),
            )
        })
        .collect();
    Keccak256::digest(if items.is_empty() {
        vec![0x80]
    } else {
        node(&items, 0)
    })
    .into()
}

#[test]
fn receipt_roots_match_independent_mpt_across_rlp_index_boundaries() {
    use legacy_format::ethereum_receipts::receipt_root;
    assert_eq!(
        hex::encode(receipt_root(8192, &[], &[]).unwrap()),
        "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
    );
    for count in [1, 2, 127, 128, 129, 257] {
        let rows: Vec<_> = (0..count)
            .map(|index| {
                let mut row = receipt_row();
                row.transaction_index = index;
                row.tx_type = (index % 5) as u8;
                row.cumulative_gas_used = u64::from(index + 1) * 21000;
                row
            })
            .collect();
        let values: Vec<_> = rows
            .iter()
            .map(|row| receipt_envelope(row, &[]).unwrap())
            .collect();
        assert_eq!(
            receipt_root(8192, &rows, &[]).unwrap(),
            reference_root(&values),
            "count {count}"
        );
    }
}

#[test]
fn receipt_root_rejects_slices_unknown_types_and_orphan_logs() {
    use legacy_format::ethereum_receipts::receipt_root;
    let mut row = receipt_row();
    assert!(receipt_root(8192, std::slice::from_ref(&row), &[]).is_err()); // starts at seven
    row.transaction_index = 0;
    assert!(receipt_root(8193, std::slice::from_ref(&row), &[]).is_err());
    let mut gap = row.clone();
    gap.transaction_index = 2;
    assert!(receipt_root(8192, &[row.clone(), gap], &[]).is_err());
    row.tx_type = 0x7e;
    assert!(receipt_root(8192, &[row], &[]).is_err());
    assert!(receipt_root(8192, &[], &[log()]).is_err());
}
