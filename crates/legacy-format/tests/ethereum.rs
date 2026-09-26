use legacy_format::{ethereum, headers::HeaderRow};
use serde_json::Value;

fn fixture() -> HeaderRow {
    let v: Value = serde_json::from_str(include_str!("fixtures/prague_header.json")).unwrap();
    let bytes = |key: &str| hex::decode(v[key].as_str().unwrap().trim_start_matches("0x")).unwrap();
    let number = |key: &str| {
        u64::from_str_radix(v[key].as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
    };
    HeaderRow {
        block_number: number("number"),
        block_hash: bytes("hash").try_into().unwrap(),
        parent_hash: bytes("parentHash").try_into().unwrap(),
        ommers_hash: bytes("sha3Uncles").try_into().unwrap(),
        beneficiary: bytes("miner").try_into().unwrap(),
        state_root: bytes("stateRoot").try_into().unwrap(),
        transactions_root: bytes("transactionsRoot").try_into().unwrap(),
        receipts_root: bytes("receiptsRoot").try_into().unwrap(),
        logs_bloom: bytes("logsBloom").try_into().unwrap(),
        difficulty: vec![],
        gas_limit: number("gasLimit"),
        gas_used: number("gasUsed"),
        timestamp: number("timestamp"),
        extra_data: bytes("extraData"),
        mix_hash: bytes("mixHash").try_into().unwrap(),
        nonce: bytes("nonce").try_into().unwrap(),
        base_fee_per_gas: Some(vec![7]),
        withdrawals_root: Some(bytes("withdrawalsRoot").try_into().unwrap()),
        blob_gas_used: Some(number("blobGasUsed")),
        excess_blob_gas: Some(number("excessBlobGas")),
        parent_beacon_block_root: Some(bytes("parentBeaconBlockRoot").try_into().unwrap()),
        requests_hash: Some(bytes("requestsHash").try_into().unwrap()),
        total_difficulty: None,
    }
}

#[test]
fn published_prague_header_hash() {
    let mut row = fixture();
    ethereum::verify_header(&row).unwrap();
    row.total_difficulty = Some(vec![1, 2, 3]);
    ethereum::verify_header(&row).unwrap();
    row.gas_used += 1;
    assert_eq!(
        ethereum::verify_header(&row),
        Err(ethereum::Error::Hash(row.block_number))
    );
}

#[test]
fn extension_shapes_and_integer_encoding() {
    for mask in 0u8..64 {
        let mut row = fixture();
        if mask & 1 == 0 {
            row.base_fee_per_gas = None;
        }
        if mask & 2 == 0 {
            row.withdrawals_root = None;
        }
        if mask & 4 == 0 {
            row.blob_gas_used = None;
        }
        if mask & 8 == 0 {
            row.excess_blob_gas = None;
        }
        if mask & 16 == 0 {
            row.parent_beacon_block_root = None;
        }
        if mask & 32 == 0 {
            row.requests_hash = None;
        }
        let result = ethereum::header_rlp(&row);
        if !matches!(mask, 0 | 1 | 3 | 31 | 63) {
            assert_eq!(result, Err(ethereum::Error::Extensions(row.block_number)));
            continue;
        }
        let encoded = result.unwrap();
        let mut input = encoded.as_slice();
        let header = alloy_rlp::Header::decode(&mut input).unwrap();
        assert!(header.list);
        assert_eq!(header.payload_length, input.len());
        let mut fields = Vec::new();
        while !input.is_empty() {
            let field = alloy_rlp::Header::decode(&mut input).unwrap();
            assert!(!field.list);
            fields.push(input[..field.payload_length].to_vec());
            input = &input[field.payload_length..];
        }
        assert_eq!(fields.len(), 15 + mask.count_ones() as usize);
        assert!(fields[7].is_empty()); // integer zero, not a single zero byte
        assert_eq!(fields[8], [3, 21]); // block number, in consensus order
        assert_eq!(fields[14], [0; 8]); // nonce is fixed bytes, not an integer
    }
}

#[test]
fn rejects_nonminimal_magnitudes_without_truncating_u256() {
    let mut row = fixture();
    row.base_fee_per_gas = Some(vec![0, 1]);
    assert!(ethereum::header_hash(&row).is_err());
    row.base_fee_per_gas = Some(vec![0xff; 32]);
    assert!(ethereum::header_hash(&row).is_ok());
    row.difficulty = vec![0];
    assert!(ethereum::header_hash(&row).is_err());
}
