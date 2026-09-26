//! The v1 transaction table. Decoding does not verify envelopes, signatures or trie roots.

use std::sync::Arc;

use arrow_array::builder::{BinaryBuilder, FixedSizeBinaryBuilder};
use arrow_array::{
    Array, ArrayRef, BinaryArray, BooleanArray, FixedSizeBinaryArray, RecordBatch, UInt32Array,
    UInt64Array, UInt8Array,
};
use arrow_schema::{DataType, Field, Schema, SchemaRef};
use bytes::Bytes;
use legacy_format::hash::blake3;
use legacy_format::transactions::{content_hash, validate_rows, TransactionRow};
use legacy_format::{FileEntry, Table};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use parquet::arrow::ArrowWriter;
use parquet::basic::Encoding;
use parquet::file::properties::WriterProperties;

use crate::{Error, Result};

pub fn schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        Field::new("block_number", DataType::UInt64, false),
        Field::new("transaction_index", DataType::UInt32, false),
        Field::new("transaction_hash", DataType::FixedSizeBinary(32), false),
        Field::new("type", DataType::UInt8, false),
        Field::new("nonce", DataType::UInt64, false),
        Field::new("from", DataType::FixedSizeBinary(20), false),
        Field::new("to", DataType::FixedSizeBinary(20), true),
        Field::new("value", DataType::Binary, false),
        Field::new("gas_limit", DataType::UInt64, false),
        Field::new("gas_price", DataType::Binary, true),
        Field::new("max_fee_per_gas", DataType::Binary, true),
        Field::new("max_priority_fee_per_gas", DataType::Binary, true),
        Field::new("max_fee_per_blob_gas", DataType::Binary, true),
        Field::new("input", DataType::Binary, false),
        Field::new("access_list", DataType::Binary, true),
        Field::new("blob_versioned_hashes", DataType::Binary, true),
        Field::new("authorization_list", DataType::Binary, true),
        Field::new("v_or_y_parity", DataType::UInt8, true),
        Field::new("r", DataType::FixedSizeBinary(32), true),
        Field::new("s", DataType::FixedSizeBinary(32), true),
        Field::new("chain_id", DataType::UInt64, true),
        Field::new("source_hash", DataType::FixedSizeBinary(32), true),
        Field::new("mint", DataType::Binary, true),
        Field::new("is_system_tx", DataType::Boolean, true),
        Field::new("raw_envelope", DataType::Binary, true),
    ]))
}

pub fn writer_properties() -> WriterProperties {
    let mut builder = crate::writer::properties();
    for name in ["block_number", "transaction_index", "nonce", "gas_limit"] {
        builder = builder.set_column_encoding(name.into(), Encoding::DELTA_BINARY_PACKED);
    }
    for name in ["type", "from", "to", "chain_id"] {
        builder = builder.set_column_dictionary_enabled(name.into(), true);
    }
    builder
        .set_column_encoding("is_system_tx".into(), Encoding::RLE)
        .build()
}

pub fn write_transactions(rows: &[TransactionRow]) -> Result<(Vec<u8>, FileEntry)> {
    write_with_target(rows, crate::writer::ROW_GROUP_BYTES)
}

fn write_with_target(rows: &[TransactionRow], target: usize) -> Result<(Vec<u8>, FileEntry)> {
    let hash = content_hash(rows)?;
    let mut bytes = Vec::new();
    let metadata = {
        let mut writer = ArrowWriter::try_new(&mut bytes, schema(), Some(writer_properties()))?;
        let mut start = 0;
        let mut size = 0;
        for (index, row) in rows.iter().enumerate() {
            // Raw envelopes are excluded from identity, but still consume the row-group budget.
            let row_size = row.canonical_bytes()?.len().saturating_add(
                row.raw_envelope
                    .as_ref()
                    .map_or(0, |v| v.len().saturating_add(8)),
            );
            if index > start && row_size > target.saturating_sub(size) {
                writer.write(&to_batch(&rows[start..index])?)?;
                writer.flush()?;
                start = index;
                size = 0;
            }
            size = size.saturating_add(row_size);
        }
        if start < rows.len() {
            writer.write(&to_batch(&rows[start..])?)?;
        }
        writer.finish()?
    };
    let entry = FileEntry {
        name: Table::Transactions.file_name().into(),
        table: Table::Transactions,
        byte_size: bytes.len() as u64,
        blake3: blake3(&bytes),
        content_hash: hash,
        row_count: rows.len() as u64,
        row_groups: metadata
            .num_row_groups()
            .try_into()
            .map_err(|_| Error::TooManyRowGroups)?,
    };
    Ok((bytes, entry))
}

pub fn read_transactions(bytes: Bytes) -> Result<Vec<TransactionRow>> {
    let builder = ParquetRecordBatchReaderBuilder::try_new(bytes)?;
    check_schema(builder.schema())?;
    let count = builder.metadata().file_metadata().num_rows();
    let mut rows = Vec::new();
    for batch in builder.build()? {
        rows.extend(from_batch(&batch?)?);
    }
    if i64::try_from(rows.len()).ok() != Some(count) {
        return Err(Error::Row(
            "decoded transaction count differs from the footer".into(),
        ));
    }
    validate_rows(&rows)?;
    Ok(rows)
}

fn integers(values: impl IntoIterator<Item = Option<u64>>) -> ArrayRef {
    Arc::new(values.into_iter().collect::<UInt64Array>())
}

fn fixed_column<const N: usize>(
    values: impl IntoIterator<Item = Option<[u8; N]>>,
) -> Result<ArrayRef> {
    let mut builder = FixedSizeBinaryBuilder::new(N as i32);
    for value in values {
        match value {
            Some(bytes) => builder.append_value(bytes)?,
            None => builder.append_null(),
        }
    }
    Ok(Arc::new(builder.finish()))
}

fn binary_column<'a>(values: impl IntoIterator<Item = Option<&'a [u8]>>) -> Result<ArrayRef> {
    let mut builder = BinaryBuilder::new();
    let mut length = 0usize;
    for value in values {
        if let Some(bytes) = value {
            length = length
                .checked_add(bytes.len())
                .filter(|n| *n <= i32::MAX as usize)
                .ok_or_else(|| {
                    Error::Row("transaction binary column exceeds Arrow offset limit".into())
                })?;
            builder.append_value(bytes);
        } else {
            builder.append_null();
        }
    }
    Ok(Arc::new(builder.finish()))
}

fn to_batch(rows: &[TransactionRow]) -> Result<RecordBatch> {
    let columns: Vec<ArrayRef> = vec![
        integers(rows.iter().map(|r| Some(r.block_number))),
        Arc::new(
            rows.iter()
                .map(|r| Some(r.transaction_index))
                .collect::<UInt32Array>(),
        ),
        fixed_column(rows.iter().map(|r| Some(r.transaction_hash)))?,
        Arc::new(rows.iter().map(|r| Some(r.tx_type)).collect::<UInt8Array>()),
        integers(rows.iter().map(|r| Some(r.nonce))),
        fixed_column(rows.iter().map(|r| Some(r.from)))?,
        fixed_column(rows.iter().map(|r| r.to))?,
        binary_column(rows.iter().map(|r| Some(r.value.as_slice())))?,
        integers(rows.iter().map(|r| Some(r.gas_limit))),
        binary_column(rows.iter().map(|r| r.gas_price.as_deref()))?,
        binary_column(rows.iter().map(|r| r.max_fee_per_gas.as_deref()))?,
        binary_column(rows.iter().map(|r| r.max_priority_fee_per_gas.as_deref()))?,
        binary_column(rows.iter().map(|r| r.max_fee_per_blob_gas.as_deref()))?,
        binary_column(rows.iter().map(|r| Some(r.input.as_slice())))?,
        binary_column(rows.iter().map(|r| r.access_list.as_deref()))?,
        binary_column(rows.iter().map(|r| r.blob_versioned_hashes.as_deref()))?,
        binary_column(rows.iter().map(|r| r.authorization_list.as_deref()))?,
        Arc::new(rows.iter().map(|r| r.v_or_y_parity).collect::<UInt8Array>()),
        fixed_column(rows.iter().map(|r| r.r))?,
        fixed_column(rows.iter().map(|r| r.s))?,
        integers(rows.iter().map(|r| r.chain_id)),
        fixed_column(rows.iter().map(|r| r.source_hash))?,
        binary_column(rows.iter().map(|r| r.mint.as_deref()))?,
        Arc::new(
            rows.iter()
                .map(|r| r.is_system_tx)
                .collect::<BooleanArray>(),
        ),
        binary_column(rows.iter().map(|r| r.raw_envelope.as_deref()))?,
    ];
    Ok(RecordBatch::try_new(schema(), columns)?)
}

fn check_schema(actual: &Schema) -> Result<()> {
    let expected = schema();
    if actual.fields().len() != expected.fields().len() {
        return Err(Error::Schema(
            "expected exactly 25 v1 transaction columns".into(),
        ));
    }
    for (actual, expected) in actual.fields().iter().zip(expected.fields()) {
        if actual.name() != expected.name()
            || actual.data_type() != expected.data_type()
            || actual.is_nullable() != expected.is_nullable()
        {
            return Err(Error::Schema(format!(
                "expected {expected:?}, got {actual:?}"
            )));
        }
    }
    Ok(())
}

fn column<T: 'static>(batch: &RecordBatch, index: usize) -> Result<&T> {
    batch
        .column(index)
        .as_any()
        .downcast_ref::<T>()
        .ok_or_else(|| Error::Schema(format!("unexpected transaction array at column {index}")))
}

fn integer_at(batch: &RecordBatch, column_index: usize, row: usize) -> Result<Option<u64>> {
    let array = column::<UInt64Array>(batch, column_index)?;
    Ok((!array.is_null(row)).then(|| array.value(row)))
}

fn u32_at(batch: &RecordBatch, column_index: usize, row: usize) -> Result<Option<u32>> {
    let array = column::<UInt32Array>(batch, column_index)?;
    Ok((!array.is_null(row)).then(|| array.value(row)))
}

fn u8_at(batch: &RecordBatch, column_index: usize, row: usize) -> Result<Option<u8>> {
    let array = column::<UInt8Array>(batch, column_index)?;
    Ok((!array.is_null(row)).then(|| array.value(row)))
}

fn bool_at(batch: &RecordBatch, column_index: usize, row: usize) -> Result<Option<bool>> {
    let array = column::<BooleanArray>(batch, column_index)?;
    Ok((!array.is_null(row)).then(|| array.value(row)))
}

fn binary_at(batch: &RecordBatch, column_index: usize, row: usize) -> Result<Option<Vec<u8>>> {
    let array = column::<BinaryArray>(batch, column_index)?;
    Ok((!array.is_null(row)).then(|| array.value(row).to_vec()))
}

fn fixed_at<const N: usize>(
    batch: &RecordBatch,
    column_index: usize,
    row: usize,
) -> Result<Option<[u8; N]>> {
    let array = column::<FixedSizeBinaryArray>(batch, column_index)?;
    if array.is_null(row) {
        return Ok(None);
    }
    Ok(Some(array.value(row).try_into().map_err(|_| {
        Error::Row(format!("expected {N}-byte transaction field"))
    })?))
}

fn required<T>(value: Option<T>, name: &str) -> Result<T> {
    value.ok_or_else(|| Error::Row(format!("null in required transaction field {name}")))
}

fn from_batch(batch: &RecordBatch) -> Result<Vec<TransactionRow>> {
    check_schema(batch.schema().as_ref())?;
    let mut rows = Vec::with_capacity(batch.num_rows());
    for i in 0..batch.num_rows() {
        rows.push(TransactionRow {
            block_number: required(integer_at(batch, 0, i)?, "block_number")?,
            transaction_index: required(u32_at(batch, 1, i)?, "transaction_index")?,
            transaction_hash: required(fixed_at(batch, 2, i)?, "transaction_hash")?,
            tx_type: required(u8_at(batch, 3, i)?, "tx_type")?,
            nonce: required(integer_at(batch, 4, i)?, "nonce")?,
            from: required(fixed_at(batch, 5, i)?, "from")?,
            to: fixed_at(batch, 6, i)?,
            value: required(binary_at(batch, 7, i)?, "value")?,
            gas_limit: required(integer_at(batch, 8, i)?, "gas_limit")?,
            gas_price: binary_at(batch, 9, i)?,
            max_fee_per_gas: binary_at(batch, 10, i)?,
            max_priority_fee_per_gas: binary_at(batch, 11, i)?,
            max_fee_per_blob_gas: binary_at(batch, 12, i)?,
            input: required(binary_at(batch, 13, i)?, "input")?,
            access_list: binary_at(batch, 14, i)?,
            blob_versioned_hashes: binary_at(batch, 15, i)?,
            authorization_list: binary_at(batch, 16, i)?,
            v_or_y_parity: u8_at(batch, 17, i)?,
            r: fixed_at(batch, 18, i)?,
            s: fixed_at(batch, 19, i)?,
            chain_id: integer_at(batch, 20, i)?,
            source_hash: fixed_at(batch, 21, i)?,
            mint: binary_at(batch, 22, i)?,
            is_system_tx: bool_at(batch, 23, i)?,
            raw_envelope: binary_at(batch, 24, i)?,
        });
    }
    Ok(rows)
}
#[cfg(test)]
mod tests {
    use super::*;
    use parquet::basic::{Compression, Type};
    use parquet::file::reader::{FileReader, SerializedFileReader};
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

    fn rows() -> Vec<TransactionRow> {
        let first = fixture();
        let mut second = first.clone();
        second.transaction_index = 8;
        second.tx_type = 0x7e;
        second.to = None;
        second.gas_price = Some(vec![]);
        second.max_fee_per_gas = None;
        second.max_priority_fee_per_gas = None;
        second.max_fee_per_blob_gas = Some(vec![0xff; 32]);
        second.access_list = None;
        second.blob_versioned_hashes = Some(vec![0xc0]);
        second.authorization_list = Some(vec![0xc0]);
        second.v_or_y_parity = None;
        second.r = None;
        second.s = None;
        second.chain_id = None;
        second.source_hash = Some([0x66; 32]);
        second.mint = Some(vec![]);
        second.is_system_tx = Some(false);
        second.raw_envelope = None;
        let mut third = second.clone();
        third.transaction_index = u32::MAX;
        third.block_number = u64::MAX;
        third.is_system_tx = Some(true);
        vec![first, second, third]
    }

    #[test]
    fn round_trip_preserves_every_column_and_unsigned_width() {
        let rows = rows();
        let (bytes, entry) = write_transactions(&rows).unwrap();
        assert_eq!(entry.row_count, 3);
        assert_eq!(entry.blake3, blake3(&bytes));
        assert_eq!(entry.content_hash, content_hash(&rows).unwrap());
        assert_eq!(read_transactions(bytes.into()).unwrap(), rows);
    }

    #[test]
    fn raw_envelope_changes_file_identity_and_counts_towards_group_budget() {
        let mut first = fixture();
        first.raw_envelope = None;
        let mut second = first.clone();
        second.transaction_index += 1;
        let target = first.canonical_bytes().unwrap().len() * 2;
        let (_, exact) = write_with_target(&[first.clone(), second.clone()], target).unwrap();
        assert_eq!(exact.row_groups, 1);
        first.raw_envelope = Some(vec![0x88; target]);
        let (bytes, split) = write_with_target(&[first.clone(), second.clone()], target).unwrap();
        assert_eq!(split.row_groups, 2);
        assert_ne!(split.blake3, exact.blake3);
        assert_eq!(split.content_hash, exact.content_hash);
        let reader = SerializedFileReader::new(Bytes::from(bytes.clone())).unwrap();
        assert_eq!(reader.metadata().row_group(0).num_rows(), 1);
        assert_eq!(
            read_transactions(bytes.into()).unwrap(),
            vec![first, second]
        );
    }

    #[test]
    fn empty_table_and_deterministic_framing() {
        let (bytes, entry) = write_transactions(&[]).unwrap();
        assert_eq!((entry.row_count, entry.row_groups), (0, 0));
        assert_eq!(entry.content_hash, blake3(&[]));
        assert!(read_transactions(bytes.into()).unwrap().is_empty());
        assert_eq!(
            write_transactions(&rows()).unwrap(),
            write_transactions(&rows()).unwrap()
        );
    }

    #[test]
    fn physical_schema_and_column_encodings_match_spec() {
        let reader =
            SerializedFileReader::new(Bytes::from(write_transactions(&rows()).unwrap().0)).unwrap();
        let metadata = reader.metadata();
        assert_eq!(
            metadata.file_metadata().created_by(),
            Some(crate::writer::CREATED_BY)
        );
        let columns = metadata.file_metadata().schema_descr().columns();
        assert_eq!(columns.len(), 25);
        for i in [1, 3, 17] {
            assert_eq!(columns[i].physical_type(), Type::INT32);
        }
        assert_eq!(columns[23].physical_type(), Type::BOOLEAN);
        for (i, width) in [(2, 32), (5, 20), (6, 20), (18, 32), (19, 32), (21, 32)] {
            assert_eq!(columns[i].physical_type(), Type::FIXED_LEN_BYTE_ARRAY);
            assert_eq!(columns[i].type_length(), width);
        }
        for (i, column) in metadata.row_group(0).columns().iter().enumerate() {
            assert!(matches!(column.compression(), Compression::ZSTD(_)));
            assert!(column.statistics().is_some());
            let encoding = if [0, 1, 4, 8].contains(&i) {
                Encoding::DELTA_BINARY_PACKED
            } else if [3, 5, 6, 20].contains(&i) {
                Encoding::RLE_DICTIONARY
            } else if i == 23 {
                Encoding::RLE
            } else {
                Encoding::PLAIN
            };
            assert!(column.encodings().any(|e| e == encoding), "column {i}");
        }
    }

    #[test]
    fn reader_and_writer_reject_invalid_rows_including_across_groups() {
        for malformed in [
            vec![fixture(), fixture()],
            {
                let mut r = rows();
                r.reverse();
                r
            },
            {
                let mut r = fixture();
                r.value = vec![0];
                vec![r]
            },
            {
                let mut r = fixture();
                r.v_or_y_parity = Some(37);
                vec![r]
            },
        ] {
            assert!(write_transactions(&malformed).is_err());
            let mut bytes = Vec::new();
            let mut writer =
                ArrowWriter::try_new(&mut bytes, schema(), Some(writer_properties())).unwrap();
            for row in malformed {
                writer.write(&to_batch(&[row]).unwrap()).unwrap();
                writer.flush().unwrap();
            }
            writer.close().unwrap();
            assert!(read_transactions(bytes.into()).is_err());
        }
    }

    #[test]
    fn schema_and_truncation_are_not_silently_accepted() {
        let batch = to_batch(&rows()).unwrap();
        for projection in [vec![0], (0..25).rev().collect()] {
            let projected = batch.project(&projection).unwrap();
            let mut bytes = Vec::new();
            let mut writer = ArrowWriter::try_new(&mut bytes, projected.schema(), None).unwrap();
            writer.write(&projected).unwrap();
            writer.close().unwrap();
            assert!(matches!(
                read_transactions(bytes.into()),
                Err(Error::Schema(_))
            ));
        }
        let (mut bytes, _) = write_transactions(&rows()).unwrap();
        bytes.truncate(bytes.len() - 8);
        assert!(read_transactions(bytes.into()).is_err());
    }
}
