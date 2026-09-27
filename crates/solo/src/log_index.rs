//! In-memory log bitmaps for one relic file.
//!
//! Address maps use row numbers. Topic maps use row groups, which is as far as RFC-0001 §7.1
//! goes. The bitmaps describe this Parquet framing, so they are rebuilt from the file whose
//! BLAKE3 matched the manifest. They are not written into the manifest and they are not a pact
//! commitment. A topic hit still means "scan that row group"; the rows are checked again.

use std::collections::BTreeMap;

use legacy_parquet::logs::GroupedLog;
use roaring::RoaringBitmap;

#[derive(Clone, Debug)]
pub struct LogIndex {
    addresses: BTreeMap<[u8; 20], Posting>,
    topics: [BTreeMap<[u8; 32], RoaringBitmap>; 4],
    blocks: BTreeMap<u64, RoaringBitmap>,
    group_starts: Vec<u32>,
    group_ends: Vec<u32>,
}

#[derive(Clone, Debug)]
struct Posting {
    rows: RoaringBitmap,
    groups: RoaringBitmap,
}

pub struct Candidates {
    rows: RoaringBitmap,
    groups: Vec<u32>,
}

impl Candidates {
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    pub fn groups(&self) -> &[u32] {
        &self.groups
    }

    pub fn contains_row(&self, row: u32) -> bool {
        self.rows.contains(row)
    }
}

impl LogIndex {
    pub fn build(rows: &[GroupedLog]) -> Result<Self, String> {
        let mut index = Self {
            addresses: BTreeMap::new(),
            topics: [
                BTreeMap::new(),
                BTreeMap::new(),
                BTreeMap::new(),
                BTreeMap::new(),
            ],
            blocks: BTreeMap::new(),
            group_starts: Vec::new(),
            group_ends: Vec::new(),
        };
        for row in rows {
            let group = usize::try_from(row.group).map_err(|_| "row group overflow".to_string())?;
            if index.group_starts.len() == group {
                index.group_starts.push(row.row);
                index.group_ends.push(row.row);
            } else if index.group_starts.len() != group + 1 {
                return Err("log row groups are not contiguous".into());
            }
            *index.group_ends.last_mut().expect("group was opened") =
                row.row.checked_add(1).ok_or("log row index overflow")?;
            index
                .addresses
                .entry(row.log.address)
                .or_insert_with(|| Posting {
                    rows: RoaringBitmap::new(),
                    groups: RoaringBitmap::new(),
                });
            let posting = index
                .addresses
                .get_mut(&row.log.address)
                .expect("just inserted");
            posting.rows.insert(row.row);
            posting.groups.insert(row.group);
            for (position, topic) in row.log.topics.iter().enumerate() {
                index.topics[position]
                    .entry(*topic)
                    .or_default()
                    .insert(row.group);
            }
            index
                .blocks
                .entry(row.log.block_number)
                .or_default()
                .insert(row.row);
        }
        Ok(index)
    }

    pub fn candidates(
        &self,
        from: u64,
        to: u64,
        addresses: Option<&[[u8; 20]]>,
        topics: &[Option<Vec<[u8; 32]>>],
    ) -> Candidates {
        let mut rows = RoaringBitmap::new();
        for (&block, bitmap) in &self.blocks {
            if (from..=to).contains(&block) {
                rows |= bitmap;
            }
        }
        let mut groups = self.groups_touched(&rows);
        if let Some(addresses) = addresses {
            let mut address_rows = RoaringBitmap::new();
            let mut address_groups = RoaringBitmap::new();
            for address in addresses {
                if let Some(posting) = self.addresses.get(address) {
                    address_rows |= &posting.rows;
                    address_groups |= &posting.groups;
                }
            }
            rows &= address_rows;
            groups &= address_groups;
        }
        for (position, position_topics) in topics.iter().enumerate() {
            let Some(allowed) = position_topics else {
                continue;
            };
            let mut topic_groups = RoaringBitmap::new();
            for topic in allowed {
                if let Some(bitmap) = self.topics[position].get(topic) {
                    topic_groups |= bitmap;
                }
            }
            groups &= topic_groups;
            rows &= self.rows_in_groups(&groups);
        }
        rows &= self.rows_in_groups(&groups);
        let groups = self.groups_touched(&rows).iter().collect();
        Candidates { rows, groups }
    }

    fn groups_touched(&self, rows: &RoaringBitmap) -> RoaringBitmap {
        let mut groups = RoaringBitmap::new();
        for row in rows {
            if let Some(group) = self.group_of(row) {
                groups.insert(group as u32);
            }
        }
        groups
    }

    fn rows_in_groups(&self, groups: &RoaringBitmap) -> RoaringBitmap {
        let mut rows = RoaringBitmap::new();
        for group in groups {
            let group = group as usize;
            if let (Some(&start), Some(&end)) =
                (self.group_starts.get(group), self.group_ends.get(group))
            {
                if start < end {
                    rows.insert_range(start..=end - 1);
                }
            }
        }
        rows
    }

    fn group_of(&self, row: u32) -> Option<usize> {
        let group = self.group_starts.partition_point(|start| *start <= row);
        let group = group.checked_sub(1)?;
        let end = *self.group_ends.get(group)?;
        (row < end).then_some(group)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use legacy_format::logs::LogRow;

    fn log(block: u64, address: u8, topic: u8) -> LogRow {
        LogRow {
            block_number: block,
            transaction_index: 0,
            log_index: 0,
            transaction_hash: [0; 32],
            address: [address; 20],
            topics: vec![[topic; 32]],
            data: vec![],
        }
    }

    #[test]
    fn address_and_topic_bitmaps_select_one_row_group() {
        let rows = vec![
            GroupedLog {
                group: 0,
                row: 0,
                log: log(1, 0x11, 0x22),
            },
            GroupedLog {
                group: 1,
                row: 1,
                log: log(2, 0x33, 0x44),
            },
        ];
        let index = LogIndex::build(&rows).unwrap();
        let hit = index.candidates(1, 2, Some(&[[0x33; 20]]), &[Some(vec![[0x44; 32]])]);
        assert_eq!(hit.groups(), &[1]);
        assert!(hit.contains_row(1));
        assert!(!hit.contains_row(0));
        let miss = index.candidates(1, 1, Some(&[[0x33; 20]]), &[]);
        assert!(miss.is_empty());
    }
}
