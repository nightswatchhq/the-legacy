//! Ethereum's 2048-bit log bloom. This commits neither log data nor multiplicity.

use crate::{
    consistency::{self, ConsistencyError},
    logs::{LogError, LogRow},
    receipts::ReceiptRow,
};
use sha3::{Digest, Keccak256};

fn accrue(bloom: &mut [u8; 256], value: &[u8]) {
    let digest = Keccak256::digest(value);
    for pair in digest[..6].as_chunks::<2>().0 {
        let bit = usize::from(u16::from_be_bytes([pair[0], pair[1]]) & 2047);
        bloom[255 - bit / 8] |= 1 << (bit % 8);
    }
}

/// Hash addresses and topics only. Empty logs produce an all-zero bloom.
pub fn logs_bloom(logs: &[LogRow]) -> Result<[u8; 256], LogError> {
    crate::logs::validate_rows(logs)?;
    let mut bloom = [0; 256];
    for log in logs {
        accrue(&mut bloom, &log.address);
        for topic in &log.topics {
            accrue(&mut bloom, topic);
        }
    }
    Ok(bloom)
}

/// Require exact equality, including zero blooms for receipts with no supplied logs.
/// Orphans and hash mismatches are rejected before aggregation. Missing logs can still be
/// hidden by bloom collisions or deleting a receipt too; this does not prove completeness.
pub fn receipt_blooms(logs: &[LogRow], receipts: &[ReceiptRow]) -> Result<(), ConsistencyError> {
    consistency::log_receipt_links(logs, receipts)?;
    let mut cursor = 0;
    for receipt in receipts {
        let start = cursor;
        while cursor < logs.len()
            && (logs[cursor].block_number, logs[cursor].transaction_index) == receipt.sort_key()
        {
            cursor += 1;
        }
        if logs_bloom(&logs[start..cursor])? != receipt.logs_bloom {
            return Err(ConsistencyError::Bloom(
                receipt.block_number,
                receipt.transaction_index,
            ));
        }
    }
    Ok(())
}

/// OR receipt blooms per block and compare every supplied header, including empty blocks.
/// Receipt blooms need not have been checked against logs. This reports aggregation only.
pub fn header_blooms(
    headers: &[crate::headers::HeaderRow],
    receipts: &[ReceiptRow],
) -> Result<(), ConsistencyError> {
    crate::headers::validate_rows(headers)?;
    crate::receipts::validate_rows(receipts)?;
    let mut cursor = 0;
    for header in headers {
        let mut expected = [0; 256];
        while let Some(receipt) = receipts.get(cursor) {
            if receipt.block_number < header.block_number {
                return Err(ConsistencyError::MissingHeader(receipt.block_number));
            }
            if receipt.block_number != header.block_number {
                break;
            }
            for (target, byte) in expected.iter_mut().zip(receipt.logs_bloom) {
                *target |= byte;
            }
            cursor += 1;
        }
        if expected != header.logs_bloom {
            return Err(ConsistencyError::HeaderBloom(header.block_number));
        }
    }
    if let Some(receipt) = receipts.get(cursor) {
        return Err(ConsistencyError::MissingHeader(receipt.block_number));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_keccak_bits_have_big_endian_byte_order() {
        // Keccak256("") starts c5d2460186f7: bit positions 1490, 1537 and 1783.
        let mut actual = [0; 256];
        accrue(&mut actual, b"");
        let mut expected = [0; 256];
        expected[69] = 4;
        expected[63] = 2;
        expected[33] = 128;
        assert_eq!(actual, expected);
    }

    #[test]
    fn agrees_with_geth_published_bloom_vector() {
        // Public TestBloomExtensively inputs and digest from core/types/bloom9_test.go.
        // https://github.com/ethereum/go-ethereum/blob/master/core/types/bloom9_test.go
        let mut bloom = [0; 256];
        for i in 0..100 {
            accrue(
                &mut bloom,
                format!("xxxxxxxxxx data {i} yyyyyyyyyyyyyy").as_bytes(),
            );
        }
        assert_eq!(
            hex::encode(Keccak256::digest(bloom)),
            "c8d3ca65cdb4874300a9e39475508f23ed6da09fdbc487f89a2dcf50b09eb263"
        );
    }
}
