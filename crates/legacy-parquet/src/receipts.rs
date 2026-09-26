//! The v1 receipt table. Decoding does not verify trie roots, blooms or cross-table agreement.

use std::sync::Arc;

use arrow_array::builder::{BinaryBuilder, FixedSizeBinaryBuilder};
use arrow_array::{
    Array, ArrayRef, BinaryArray, FixedSizeBinaryArray, RecordBatch, UInt32Array, UInt64Array,
    UInt8Array,
};
use arrow_schema::{DataType, Field, Schema, SchemaRef};
use bytes::Bytes;
use legacy_format::hash::blake3;
use legacy_format::receipts::{content_hash, validate_rows, ReceiptRow};
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
        Field::new("status", DataType::UInt8, true),
        Field::new("post_state", DataType::FixedSizeBinary(32), true),
        Field::new("cumulative_gas_used", DataType::UInt64, false),
        Field::new("logs_bloom", DataType::FixedSizeBinary(256), false),
        Field::new("gas_used", DataType::UInt64, true),
        Field::new("contract_address", DataType::FixedSizeBinary(20), true),
        Field::new("effective_gas_price", DataType::Binary, true),
        Field::new("blob_gas_used", DataType::UInt64, true),
        Field::new("blob_gas_price", DataType::Binary, true),
        Field::new("deposit_nonce", DataType::UInt64, true),
        Field::new("deposit_receipt_version", DataType::UInt8, true),
        Field::new("l1_fee", DataType::Binary, true),
        Field::new("l1_gas_used", DataType::Binary, true),
        Field::new("l1_gas_price", DataType::Binary, true),
        Field::new("l1_fee_scalar", DataType::Binary, true),
    ]))
}

pub fn writer_properties() -> WriterProperties {
    let mut builder = crate::writer::properties();
    for name in [
        "block_number",
        "transaction_index",
        "cumulative_gas_used",
        "gas_used",
        "blob_gas_used",
        "deposit_nonce",
    ] {
        builder = builder.set_column_encoding(name.into(), Encoding::DELTA_BINARY_PACKED);
    }
    for name in [
        "type",
        "status",
        "contract_address",
        "deposit_receipt_version",
    ] {
        builder = builder.set_column_dictionary_enabled(name.into(), true);
    }
    builder.build()
}

pub fn write_receipts(rows: &[ReceiptRow]) -> Result<(Vec<u8>, FileEntry)> {
    write_with_target(rows, crate::writer::ROW_GROUP_BYTES)
}

fn write_with_target(rows: &[ReceiptRow], target: usize) -> Result<(Vec<u8>, FileEntry)> {
    let hash = content_hash(rows)?;
    let mut bytes = Vec::new();
    let metadata = {
        let mut writer = ArrowWriter::try_new(&mut bytes, schema(), Some(writer_properties()))?;
        let mut start = 0;
        let mut size = 0;
        for (index, row) in rows.iter().enumerate() {
            let row_size = row.canonical_bytes()?.len();
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
        name: Table::Receipts.file_name().into(),
        table: Table::Receipts,
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

pub fn read_receipts(bytes: Bytes) -> Result<Vec<ReceiptRow>> {
    let builder = ParquetRecordBatchReaderBuilder::try_new(bytes)?;
    check_schema(builder.schema())?;
    let count = builder.metadata().file_metadata().num_rows();
    let mut rows = Vec::new();
    for batch in builder.build()? {
        rows.extend(from_batch(&batch?)?);
    }
    if i64::try_from(rows.len()).ok() != Some(count) {
        return Err(Error::Row(
            "decoded receipt count differs from the footer".into(),
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
                    Error::Row("receipt binary column exceeds Arrow offset limit".into())
                })?;
            builder.append_value(bytes);
        } else {
            builder.append_null();
        }
    }
    Ok(Arc::new(builder.finish()))
}

fn to_batch(rows: &[ReceiptRow]) -> Result<RecordBatch> {
    let columns: Vec<ArrayRef> = vec![
        integers(rows.iter().map(|r| Some(r.block_number))),
        Arc::new(
            rows.iter()
                .map(|r| Some(r.transaction_index))
                .collect::<UInt32Array>(),
        ),
        fixed_column(rows.iter().map(|r| Some(r.transaction_hash)))?,
        Arc::new(rows.iter().map(|r| Some(r.tx_type)).collect::<UInt8Array>()),
        Arc::new(rows.iter().map(|r| r.status).collect::<UInt8Array>()),
        fixed_column(rows.iter().map(|r| r.post_state))?,
        integers(rows.iter().map(|r| Some(r.cumulative_gas_used))),
        fixed_column(rows.iter().map(|r| Some(r.logs_bloom)))?,
        integers(rows.iter().map(|r| r.gas_used)),
        fixed_column(rows.iter().map(|r| r.contract_address))?,
        binary_column(rows.iter().map(|r| r.effective_gas_price.as_deref()))?,
        integers(rows.iter().map(|r| r.blob_gas_used)),
        binary_column(rows.iter().map(|r| r.blob_gas_price.as_deref()))?,
        integers(rows.iter().map(|r| r.deposit_nonce)),
        Arc::new(
            rows.iter()
                .map(|r| r.deposit_receipt_version)
                .collect::<UInt8Array>(),
        ),
        binary_column(rows.iter().map(|r| r.l1_fee.as_deref()))?,
        binary_column(rows.iter().map(|r| r.l1_gas_used.as_deref()))?,
        binary_column(rows.iter().map(|r| r.l1_gas_price.as_deref()))?,
        binary_column(rows.iter().map(|r| r.l1_fee_scalar.as_deref()))?,
    ];
    Ok(RecordBatch::try_new(schema(), columns)?)
}

fn check_schema(actual: &Schema) -> Result<()> {
    let expected = schema();
    if actual.fields().len() != expected.fields().len() {
        return Err(Error::Schema(
            "expected exactly 19 v1 receipt columns".into(),
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
        .ok_or_else(|| Error::Schema(format!("unexpected receipt array at column {index}")))
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
        Error::Row(format!("expected {N}-byte receipt field"))
    })?))
}

fn required<T>(value: Option<T>, name: &str) -> Result<T> {
    value.ok_or_else(|| Error::Row(format!("null in required receipt field {name}")))
}

fn from_batch(batch: &RecordBatch) -> Result<Vec<ReceiptRow>> {
    check_schema(batch.schema().as_ref())?;
    let mut rows = Vec::with_capacity(batch.num_rows());
    for i in 0..batch.num_rows() {
        rows.push(ReceiptRow {
            block_number: required(integer_at(batch, 0, i)?, "block_number")?,
            transaction_index: required(u32_at(batch, 1, i)?, "transaction_index")?,
            transaction_hash: required(fixed_at(batch, 2, i)?, "transaction_hash")?,
            tx_type: required(u8_at(batch, 3, i)?, "tx_type")?,
            status: u8_at(batch, 4, i)?,
            post_state: fixed_at(batch, 5, i)?,
            cumulative_gas_used: required(integer_at(batch, 6, i)?, "cumulative_gas_used")?,
            logs_bloom: required(fixed_at(batch, 7, i)?, "logs_bloom")?,
            gas_used: integer_at(batch, 8, i)?,
            contract_address: fixed_at(batch, 9, i)?,
            effective_gas_price: binary_at(batch, 10, i)?,
            blob_gas_used: integer_at(batch, 11, i)?,
            blob_gas_price: binary_at(batch, 12, i)?,
            deposit_nonce: integer_at(batch, 13, i)?,
            deposit_receipt_version: u8_at(batch, 14, i)?,
            l1_fee: binary_at(batch, 15, i)?,
            l1_gas_used: binary_at(batch, 16, i)?,
            l1_gas_price: binary_at(batch, 17, i)?,
            l1_fee_scalar: binary_at(batch, 18, i)?,
        });
    }
    Ok(rows)
}
#[cfg(test)]
mod tests {
    use super::*;
    use parquet::basic::{Compression, Type};
    use parquet::file::reader::{FileReader, SerializedFileReader};
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

    fn rows() -> Vec<ReceiptRow> {
        let first = fixture();
        let mut second = first.clone();
        second.transaction_index += 1;
        second.tx_type = 0;
        second.status = None;
        second.post_state = Some([0x44; 32]);
        second.gas_used = None;
        second.contract_address = None;
        second.effective_gas_price = None;
        second.blob_gas_used = None;
        second.blob_gas_price = None;
        second.deposit_nonce = None;
        second.deposit_receipt_version = None;
        second.l1_fee = None;
        second.l1_gas_used = Some(vec![0xff; 32]);
        second.l1_gas_price = None;
        second.l1_fee_scalar = None;
        let mut third = second.clone();
        third.block_number = u64::MAX;
        third.transaction_index = u32::MAX;
        third.tx_type = 0x7e;
        third.status = Some(0);
        third.post_state = None;
        third.deposit_receipt_version = Some(u8::MAX);
        vec![first, second, third]
    }

    #[test]
    fn round_trip_preserves_every_column_and_unsigned_width() {
        let rows = rows();
        let (bytes, entry) = write_receipts(&rows).unwrap();
        assert_eq!(entry.row_count, 3);
        assert_eq!(entry.blake3, blake3(&bytes));
        assert_eq!(entry.content_hash, content_hash(&rows).unwrap());
        assert_eq!(read_receipts(bytes.into()).unwrap(), rows);
    }

    #[test]
    fn empty_table_and_deterministic_framing() {
        let (bytes, entry) = write_receipts(&[]).unwrap();
        assert_eq!((entry.row_count, entry.row_groups), (0, 0));
        assert_eq!(entry.content_hash, blake3(&[]));
        assert!(read_receipts(bytes.into()).unwrap().is_empty());
        assert_eq!(
            write_receipts(&rows()).unwrap(),
            write_receipts(&rows()).unwrap()
        );
    }

    #[test]
    fn row_group_budget_exact_fit_and_oversized_row_preserve_identity() {
        let first = fixture();
        let mut second = first.clone();
        second.transaction_index += 1;
        let target = first.canonical_bytes().unwrap().len() * 2;
        let rows = [first, second];
        let (_, exact) = write_with_target(&rows, target).unwrap();
        let (bytes, split) = write_with_target(&rows, target - 1).unwrap();
        assert_eq!(exact.row_groups, 1);
        assert_eq!(split.row_groups, 2);
        assert_ne!(exact.blake3, split.blake3);
        assert_eq!(exact.content_hash, split.content_hash);
        assert_eq!(read_receipts(bytes.into()).unwrap(), rows);
        let (bytes, oversized) = write_with_target(&rows, 1).unwrap();
        assert_eq!(oversized.row_groups, 2);
        assert_eq!(read_receipts(bytes.into()).unwrap(), rows);
    }

    #[test]
    fn physical_schema_and_encodings_match_spec() {
        let reader =
            SerializedFileReader::new(Bytes::from(write_receipts(&rows()).unwrap().0)).unwrap();
        let metadata = reader.metadata();
        assert_eq!(
            metadata.file_metadata().created_by(),
            Some(crate::writer::CREATED_BY)
        );
        let columns = metadata.file_metadata().schema_descr().columns();
        assert_eq!(columns.len(), 19);
        for i in [1, 3, 4, 14] {
            assert_eq!(columns[i].physical_type(), Type::INT32);
        }
        for (i, width) in [(2, 32), (5, 32), (7, 256), (9, 20)] {
            assert_eq!(columns[i].physical_type(), Type::FIXED_LEN_BYTE_ARRAY);
            assert_eq!(columns[i].type_length(), width);
        }
        for (i, column) in metadata.row_group(0).columns().iter().enumerate() {
            assert!(matches!(column.compression(), Compression::ZSTD(_)));
            assert!(column.statistics().is_some());
            let encoding = if [0, 1, 6, 8, 11, 13].contains(&i) {
                Encoding::DELTA_BINARY_PACKED
            } else if [3, 4, 9, 14].contains(&i) {
                Encoding::RLE_DICTIONARY
            } else {
                Encoding::PLAIN
            };
            assert!(column.encodings().any(|e| e == encoding), "column {i}");
        }
    }

    #[test]
    fn writer_and_reader_reject_invalid_rows_across_groups() {
        for malformed in [
            vec![fixture(), fixture()],
            {
                let mut r = rows();
                r.reverse();
                r
            },
            {
                let mut r = fixture();
                r.status = None;
                vec![r]
            },
            {
                let mut r = fixture();
                r.post_state = Some([0; 32]);
                vec![r]
            },
            {
                let mut r = fixture();
                r.status = Some(2);
                vec![r]
            },
            {
                let mut r = fixture();
                r.blob_gas_price = Some(vec![0]);
                vec![r]
            },
        ] {
            assert!(write_receipts(&malformed).is_err());
            let mut bytes = Vec::new();
            let mut writer =
                ArrowWriter::try_new(&mut bytes, schema(), Some(writer_properties())).unwrap();
            for row in malformed {
                writer.write(&to_batch(&[row]).unwrap()).unwrap();
                writer.flush().unwrap();
            }
            writer.close().unwrap();
            assert!(read_receipts(bytes.into()).is_err());
        }
    }

    #[test]
    fn reader_rejects_missing_reordered_and_wrong_width_columns() {
        let batch = to_batch(&rows()).unwrap();
        let mut fields = schema().fields().to_vec();
        fields[7] = Arc::new(Field::new(
            "logs_bloom",
            DataType::FixedSizeBinary(32),
            false,
        ));
        let mut columns = batch.columns().to_vec();
        columns[7] = fixed_column([Some([0; 32]); 3]).unwrap();
        let bad_bloom = RecordBatch::try_new(Arc::new(Schema::new(fields)), columns).unwrap();
        for malformed in [
            batch.project(&[0]).unwrap(),
            batch.project(&(0..19).rev().collect::<Vec<_>>()).unwrap(),
            bad_bloom,
        ] {
            let mut bytes = Vec::new();
            let mut writer = ArrowWriter::try_new(&mut bytes, malformed.schema(), None).unwrap();
            writer.write(&malformed).unwrap();
            writer.close().unwrap();
            assert!(matches!(read_receipts(bytes.into()), Err(Error::Schema(_))));
        }
        let (mut bytes, _) = write_receipts(&rows()).unwrap();
        bytes.truncate(bytes.len() - 8);
        assert!(read_receipts(bytes.into()).is_err());
    }
}
