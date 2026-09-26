//! The complete v1 header table. Decoding does not authenticate the stored block hashes.

use std::sync::Arc;

use arrow_array::builder::{BinaryBuilder, FixedSizeBinaryBuilder};
use arrow_array::{Array, ArrayRef, BinaryArray, FixedSizeBinaryArray, RecordBatch, UInt64Array};
use arrow_schema::{DataType, Field, Schema, SchemaRef};
use bytes::Bytes;
use legacy_format::hash::blake3;
use legacy_format::headers::{content_hash, validate_rows, HeaderRow};
use legacy_format::{FileEntry, Table};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use parquet::arrow::ArrowWriter;
use parquet::basic::Encoding;
use parquet::file::properties::WriterProperties;

use crate::{Error, Result};

pub fn schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        Field::new("block_number", DataType::UInt64, false),
        Field::new("block_hash", DataType::FixedSizeBinary(32), false),
        Field::new("parent_hash", DataType::FixedSizeBinary(32), false),
        Field::new("ommers_hash", DataType::FixedSizeBinary(32), false),
        Field::new("beneficiary", DataType::FixedSizeBinary(20), false),
        Field::new("state_root", DataType::FixedSizeBinary(32), false),
        Field::new("transactions_root", DataType::FixedSizeBinary(32), false),
        Field::new("receipts_root", DataType::FixedSizeBinary(32), false),
        Field::new("logs_bloom", DataType::FixedSizeBinary(256), false),
        Field::new("difficulty", DataType::Binary, false),
        Field::new("gas_limit", DataType::UInt64, false),
        Field::new("gas_used", DataType::UInt64, false),
        Field::new("timestamp", DataType::UInt64, false),
        Field::new("extra_data", DataType::Binary, false),
        Field::new("mix_hash", DataType::FixedSizeBinary(32), false),
        Field::new("nonce", DataType::FixedSizeBinary(8), false),
        Field::new("base_fee_per_gas", DataType::Binary, true),
        Field::new("withdrawals_root", DataType::FixedSizeBinary(32), true),
        Field::new("blob_gas_used", DataType::UInt64, true),
        Field::new("excess_blob_gas", DataType::UInt64, true),
        Field::new(
            "parent_beacon_block_root",
            DataType::FixedSizeBinary(32),
            true,
        ),
        Field::new("requests_hash", DataType::FixedSizeBinary(32), true),
        Field::new("total_difficulty", DataType::Binary, true),
    ]))
}

pub fn writer_properties() -> WriterProperties {
    let mut builder = crate::writer::properties();
    for name in [
        "block_number",
        "gas_limit",
        "gas_used",
        "timestamp",
        "blob_gas_used",
        "excess_blob_gas",
    ] {
        builder = builder.set_column_encoding(name.into(), Encoding::DELTA_BINARY_PACKED);
    }
    for name in ["ommers_hash", "beneficiary"] {
        builder = builder.set_column_dictionary_enabled(name.into(), true);
    }
    builder.build()
}

pub fn write_headers(rows: &[HeaderRow]) -> Result<(Vec<u8>, FileEntry)> {
    write_with_target(rows, crate::writer::ROW_GROUP_BYTES)
}

fn write_with_target(rows: &[HeaderRow], target: usize) -> Result<(Vec<u8>, FileEntry)> {
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
        name: Table::Headers.file_name().into(),
        table: Table::Headers,
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

pub fn read_headers(bytes: Bytes) -> Result<Vec<HeaderRow>> {
    let builder = ParquetRecordBatchReaderBuilder::try_new(bytes)?;
    check_schema(builder.schema())?;
    let count = builder.metadata().file_metadata().num_rows();
    let mut rows = Vec::new();
    for batch in builder.build()? {
        rows.extend(from_batch(&batch?)?);
    }
    if i64::try_from(rows.len()).ok() != Some(count) {
        return Err(Error::Row(
            "decoded header count differs from the footer".into(),
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
                    Error::Row("header binary column exceeds Arrow offset limit".into())
                })?;
            builder.append_value(bytes);
        } else {
            builder.append_null();
        }
    }
    Ok(Arc::new(builder.finish()))
}

fn to_batch(rows: &[HeaderRow]) -> Result<RecordBatch> {
    let columns = vec![
        integers(rows.iter().map(|r| Some(r.block_number))),
        fixed_column(rows.iter().map(|r| Some(r.block_hash)))?,
        fixed_column(rows.iter().map(|r| Some(r.parent_hash)))?,
        fixed_column(rows.iter().map(|r| Some(r.ommers_hash)))?,
        fixed_column(rows.iter().map(|r| Some(r.beneficiary)))?,
        fixed_column(rows.iter().map(|r| Some(r.state_root)))?,
        fixed_column(rows.iter().map(|r| Some(r.transactions_root)))?,
        fixed_column(rows.iter().map(|r| Some(r.receipts_root)))?,
        fixed_column(rows.iter().map(|r| Some(r.logs_bloom)))?,
        binary_column(rows.iter().map(|r| Some(r.difficulty.as_slice())))?,
        integers(rows.iter().map(|r| Some(r.gas_limit))),
        integers(rows.iter().map(|r| Some(r.gas_used))),
        integers(rows.iter().map(|r| Some(r.timestamp))),
        binary_column(rows.iter().map(|r| Some(r.extra_data.as_slice())))?,
        fixed_column(rows.iter().map(|r| Some(r.mix_hash)))?,
        fixed_column(rows.iter().map(|r| Some(r.nonce)))?,
        binary_column(rows.iter().map(|r| r.base_fee_per_gas.as_deref()))?,
        fixed_column(rows.iter().map(|r| r.withdrawals_root))?,
        integers(rows.iter().map(|r| r.blob_gas_used)),
        integers(rows.iter().map(|r| r.excess_blob_gas)),
        fixed_column(rows.iter().map(|r| r.parent_beacon_block_root))?,
        fixed_column(rows.iter().map(|r| r.requests_hash))?,
        binary_column(rows.iter().map(|r| r.total_difficulty.as_deref()))?,
    ];
    Ok(RecordBatch::try_new(schema(), columns)?)
}

fn check_schema(actual: &Schema) -> Result<()> {
    let expected = schema();
    if actual.fields().len() != expected.fields().len() {
        return Err(Error::Schema(
            "expected exactly 23 v1 header columns".into(),
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
        .ok_or_else(|| Error::Schema(format!("unexpected header array at column {index}")))
}

fn integer_at(batch: &RecordBatch, column_index: usize, row: usize) -> Result<Option<u64>> {
    let array = column::<UInt64Array>(batch, column_index)?;
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
        Error::Row(format!("expected {N}-byte header field"))
    })?))
}

fn required<T>(value: Option<T>, name: &str) -> Result<T> {
    value.ok_or_else(|| Error::Row(format!("null in required header field {name}")))
}

fn from_batch(batch: &RecordBatch) -> Result<Vec<HeaderRow>> {
    check_schema(batch.schema().as_ref())?;
    let mut rows = Vec::with_capacity(batch.num_rows());
    for i in 0..batch.num_rows() {
        rows.push(HeaderRow {
            block_number: required(integer_at(batch, 0, i)?, "block_number")?,
            block_hash: required(fixed_at(batch, 1, i)?, "block_hash")?,
            parent_hash: required(fixed_at(batch, 2, i)?, "parent_hash")?,
            ommers_hash: required(fixed_at(batch, 3, i)?, "ommers_hash")?,
            beneficiary: required(fixed_at(batch, 4, i)?, "beneficiary")?,
            state_root: required(fixed_at(batch, 5, i)?, "state_root")?,
            transactions_root: required(fixed_at(batch, 6, i)?, "transactions_root")?,
            receipts_root: required(fixed_at(batch, 7, i)?, "receipts_root")?,
            logs_bloom: required(fixed_at(batch, 8, i)?, "logs_bloom")?,
            difficulty: required(binary_at(batch, 9, i)?, "difficulty")?,
            gas_limit: required(integer_at(batch, 10, i)?, "gas_limit")?,
            gas_used: required(integer_at(batch, 11, i)?, "gas_used")?,
            timestamp: required(integer_at(batch, 12, i)?, "timestamp")?,
            extra_data: required(binary_at(batch, 13, i)?, "extra_data")?,
            mix_hash: required(fixed_at(batch, 14, i)?, "mix_hash")?,
            nonce: required(fixed_at(batch, 15, i)?, "nonce")?,
            base_fee_per_gas: binary_at(batch, 16, i)?,
            withdrawals_root: fixed_at(batch, 17, i)?,
            blob_gas_used: integer_at(batch, 18, i)?,
            excess_blob_gas: integer_at(batch, 19, i)?,
            parent_beacon_block_root: fixed_at(batch, 20, i)?,
            requests_hash: fixed_at(batch, 21, i)?,
            total_difficulty: binary_at(batch, 22, i)?,
        });
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use parquet::basic::{Compression, Type};
    use parquet::file::reader::{FileReader, SerializedFileReader};

    fn row() -> HeaderRow {
        HeaderRow {
            block_number: 1,
            block_hash: [0x11; 32],
            parent_hash: [0x22; 32],
            ommers_hash: [0x33; 32],
            beneficiary: [0x44; 20],
            state_root: [0x55; 32],
            transactions_root: [0x66; 32],
            receipts_root: [0x77; 32],
            logs_bloom: [0x88; 256],
            difficulty: vec![1, 0],
            gas_limit: u64::MAX,
            gas_used: 21_000,
            timestamp: u64::MAX,
            extra_data: vec![0xaa; 100],
            mix_hash: [0x99; 32],
            nonce: [0xaa; 8],
            base_fee_per_gas: None,
            withdrawals_root: None,
            blob_gas_used: None,
            excess_blob_gas: None,
            parent_beacon_block_root: None,
            requests_hash: None,
            total_difficulty: Some(vec![0xff; 32]),
        }
    }

    fn fixtures() -> Vec<HeaderRow> {
        let old = row();
        let mut london = old.clone();
        london.block_number = 2;
        london.base_fee_per_gas = Some(vec![]);
        let mut recent = london.clone();
        recent.block_number = 3;
        recent.difficulty.clear();
        recent.total_difficulty = None;
        recent.withdrawals_root = Some([1; 32]);
        recent.blob_gas_used = Some(0);
        recent.excess_blob_gas = Some(u64::MAX);
        recent.parent_beacon_block_root = Some([2; 32]);
        recent.requests_hash = Some([3; 32]);
        vec![old, london, recent]
    }

    #[test]
    fn round_trip_preserves_all_columns_nulls_zeroes_and_unsigned_values() {
        let rows = fixtures();
        let (bytes, entry) = write_headers(&rows).unwrap();
        let decoded = read_headers(bytes.clone().into()).unwrap();
        assert_eq!(decoded, rows);
        assert_eq!(entry.content_hash, content_hash(&decoded).unwrap());
        assert_eq!(entry.blake3, blake3(&bytes));
        assert_eq!(entry.row_count, 3);
        assert_eq!(entry.row_groups, 1);
    }

    #[test]
    fn empty_table_is_readable_but_is_not_a_complete_relic() {
        let (bytes, entry) = write_headers(&[]).unwrap();
        assert!(read_headers(bytes.into()).unwrap().is_empty());
        assert_eq!((entry.row_count, entry.row_groups), (0, 0));
        assert_eq!(
            entry.content_hash.to_hex(),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }

    #[test]
    fn framing_changes_file_identity_not_content_identity() {
        let rows = fixtures();
        let normal = write_headers(&rows).unwrap();
        assert_eq!(normal, write_headers(&rows).unwrap());
        let split = write_with_target(&rows, 1).unwrap();
        assert_eq!(split.1.row_groups, 3);
        assert_ne!(split.1.blake3, normal.1.blake3);
        assert_eq!(split.1.content_hash, normal.1.content_hash);
        assert_eq!(read_headers(split.0.into()).unwrap(), rows);
    }

    #[test]
    fn physical_schema_and_encodings_match_the_rfc() {
        let reader =
            SerializedFileReader::new(Bytes::from(write_headers(&fixtures()).unwrap().0)).unwrap();
        let metadata = reader.metadata();
        let columns = metadata.file_metadata().schema_descr().columns();
        assert_eq!(columns.len(), 23);
        assert_eq!(columns[8].physical_type(), Type::FIXED_LEN_BYTE_ARRAY);
        assert_eq!(columns[8].type_length(), 256);
        assert_eq!(columns[15].type_length(), 8);
        assert_eq!(columns[9].physical_type(), Type::BYTE_ARRAY);
        for i in [0, 10, 11, 12, 18, 19] {
            assert!(metadata
                .row_group(0)
                .column(i)
                .encodings()
                .any(|e| e == Encoding::DELTA_BINARY_PACKED));
        }
        for i in [3, 4] {
            assert!(metadata
                .row_group(0)
                .column(i)
                .encodings()
                .any(|e| e == Encoding::RLE_DICTIONARY));
        }
        for column in metadata.row_group(0).columns() {
            assert!(matches!(column.compression(), Compression::ZSTD(_)));
            assert!(column.statistics().is_some());
        }
    }

    #[test]
    fn malformed_integer_and_duplicate_headers_fail_on_both_paths() {
        let mut invalid = row();
        invalid.difficulty = vec![0];
        for rows in [vec![invalid], vec![row(), row()]] {
            assert!(write_headers(&rows).is_err());
            let mut bytes = Vec::new();
            let mut writer =
                ArrowWriter::try_new(&mut bytes, schema(), Some(writer_properties())).unwrap();
            writer.write(&to_batch(&rows).unwrap()).unwrap();
            writer.close().unwrap();
            assert!(read_headers(bytes.into()).is_err());
        }
    }

    #[test]
    fn missing_columns_and_truncated_files_are_rejected() {
        let batch = to_batch(&fixtures())
            .unwrap()
            .project(&(0..22).collect::<Vec<_>>())
            .unwrap();
        let mut bytes = Vec::new();
        let mut writer = ArrowWriter::try_new(&mut bytes, batch.schema(), None).unwrap();
        writer.write(&batch).unwrap();
        writer.close().unwrap();
        assert!(matches!(read_headers(bytes.into()), Err(Error::Schema(_))));
        let (mut bytes, _) = write_headers(&fixtures()).unwrap();
        bytes.truncate(bytes.len() - 8);
        assert!(read_headers(bytes.into()).is_err());
    }
}
