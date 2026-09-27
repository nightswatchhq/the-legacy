//! In-memory hash indexes for one relic (RFC-0001 §7.2 and §7.3).
//!
//! Each index is a sorted array of fixed-width records plus a Parquet split-block bloom.
//! A bloom miss is absent. A hit is only a candidate: the caller still reads the row and
//! checks the hash. Nothing here is written into the manifest.

use parquet::bloom_filter::Sbbf;

/// Same false-positive probability as the logs column blooms. This is a lookup filter,
/// not a verification result.
const FPP: f64 = 0.01;

#[derive(Clone, Debug)]
pub struct BlockHashIndex {
    inner: Sorted<u64>,
}

#[derive(Clone, Debug)]
pub struct TxHashIndex {
    inner: Sorted<(u64, u32)>,
}

#[derive(Clone, Debug)]
struct Sorted<T> {
    records: Vec<([u8; 32], T)>,
    bloom: Sbbf,
}

impl BlockHashIndex {
    pub fn build(rows: &[([u8; 32], u64)]) -> Result<Self, String> {
        Ok(Self {
            inner: Sorted::build(rows.iter().map(|(hash, block)| (*hash, *block)))?,
        })
    }

    pub fn find(&self, hash: &[u8; 32]) -> Option<u64> {
        self.inner.find(hash).copied()
    }
}

impl TxHashIndex {
    pub fn build(rows: &[([u8; 32], u64, u32)]) -> Result<Self, String> {
        Ok(Self {
            inner: Sorted::build(
                rows.iter()
                    .map(|(hash, block, index)| (*hash, (*block, *index))),
            )?,
        })
    }

    pub fn find(&self, hash: &[u8; 32]) -> Option<(u64, u32)> {
        self.inner.find(hash).copied()
    }
}

impl<T: Copy> Sorted<T> {
    fn build(rows: impl Iterator<Item = ([u8; 32], T)>) -> Result<Self, String> {
        let mut records: Vec<_> = rows.collect();
        records.sort_by_key(|record| record.0);
        let mut bloom = if records.is_empty() {
            Sbbf::new_with_num_of_bytes(0)
        } else {
            Sbbf::new_with_ndv_fpp(records.len() as u64, FPP).map_err(|error| error.to_string())?
        };
        for (hash, _) in &records {
            bloom.insert(&hash[..]);
        }
        Ok(Self { records, bloom })
    }

    fn find(&self, hash: &[u8; 32]) -> Option<&T> {
        if self.records.is_empty() || !self.bloom.check(&hash[..]) {
            return None;
        }
        let index = self.records.partition_point(|record| record.0 < *hash);
        let record = self.records.get(index)?;
        (record.0 == *hash).then_some(&record.1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bloom_hit_returns_the_sorted_record_and_a_miss_returns_nothing() {
        let blocks =
            BlockHashIndex::build(&[([0x22; 32], 9), ([0x11; 32], 4), ([0x33; 32], 1)]).unwrap();
        assert_eq!(blocks.find(&[0x11; 32]), Some(4));
        assert_eq!(blocks.find(&[0x33; 32]), Some(1));
        assert_eq!(blocks.find(&[0x44; 32]), None);

        let txs = TxHashIndex::build(&[([0xaa; 32], 7, 3), ([0xbb; 32], 8, 0)]).unwrap();
        assert_eq!(txs.find(&[0xaa; 32]), Some((7, 3)));
        assert_eq!(txs.find(&[0xcc; 32]), None);
        assert_eq!(TxHashIndex::build(&[]).unwrap().find(&[0xaa; 32]), None);
    }

    #[test]
    fn every_inserted_hash_is_found() {
        let rows: Vec<_> = (0..200u32)
            .map(|n| {
                let mut hash = [0u8; 32];
                hash[..4].copy_from_slice(&n.to_be_bytes());
                (hash, u64::from(n), n)
            })
            .collect();
        let index = TxHashIndex::build(&rows).unwrap();
        for (hash, block, tx_index) in rows {
            assert_eq!(index.find(&hash), Some((block, tx_index)));
        }
    }
}
