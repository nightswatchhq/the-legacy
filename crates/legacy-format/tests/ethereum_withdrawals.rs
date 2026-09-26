use legacy_format::ethereum_withdrawals::{
    verify_withdrawal_roots, withdrawal_envelope, withdrawal_root, WithdrawalEncodingError,
};
use legacy_format::headers::HeaderRow;
use legacy_format::withdrawals::WithdrawalRow;

fn withdrawal(index: u64, validator_index: u64, amount: u64) -> WithdrawalRow {
    WithdrawalRow {
        block_number: 42,
        index,
        validator_index,
        address: [0x11; 20],
        amount,
    }
}

fn header(root: Option<[u8; 32]>) -> HeaderRow {
    HeaderRow {
        block_number: 42,
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
        withdrawals_root: root,
        blob_gas_used: None,
        excess_blob_gas: None,
        parent_beacon_block_root: None,
        requests_hash: None,
        total_difficulty: None,
    }
}

#[test]
fn envelopes_and_roots_preserve_global_index_but_use_block_position_as_key() {
    let rows = [withdrawal(127, 128, 1), withdrawal(130, 256, 2)];
    assert_eq!(
        hex::encode(withdrawal_envelope(&rows[0]).unwrap()),
        "d97f818094111111111111111111111111111111111111111101"
    );
    let root = withdrawal_root(42, &rows).unwrap();
    assert_eq!(
        hex::encode(root),
        "3d653f826660d645424b56c710087c4fc58f016bd6b9074a7adf9b13d8b61f99"
    );
    assert!(verify_withdrawal_roots(&[header(Some(root))], &rows).is_ok());
    assert_eq!(
        verify_withdrawal_roots(&[header(Some([0; 32]))], &rows),
        Err(WithdrawalEncodingError::Root(42))
    );
}

#[test]
fn roots_reject_rows_without_matching_post_shapella_headers() {
    let row = withdrawal(1, 2, 3);
    assert_eq!(
        withdrawal_root(
            42,
            &[WithdrawalRow {
                block_number: 43,
                ..row.clone()
            }]
        ),
        Err(WithdrawalEncodingError::BlockRows(42))
    );
    assert_eq!(
        verify_withdrawal_roots(&[header(None)], std::slice::from_ref(&row)),
        Err(WithdrawalEncodingError::Presence(42))
    );
    let mut zero = row;
    zero.amount = 0;
    assert!(withdrawal_envelope(&zero).is_err());
}
