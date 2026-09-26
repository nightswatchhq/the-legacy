//! The v1 withdrawals codec. No withdrawal-root or fork-activation checks are performed here.

use std::sync::Arc;

use arrow_array::builder::FixedSizeBinaryBuilder;
use arrow_array::{Array, ArrayRef, FixedSizeBinaryArray, RecordBatch, UInt64Array};
use arrow_schema::{DataType, Field, Schema, SchemaRef};
use bytes::Bytes;
use legacy_format::hash::blake3;
use legacy_format::withdrawals::{content_hash, validate_rows, WithdrawalRow, CANONICAL_ROW_BYTES};
use legacy_format::{FileEntry, Table};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use parquet::arrow::ArrowWriter;
use parquet::basic::Encoding;
use parquet::file::properties::WriterProperties;

use crate::{Error, Result};

pub fn schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        Field::new("block_number", DataType::UInt64, false),
        Field::new("index", DataType::UInt64, false),
        Field::new("validator_index", DataType::UInt64, false),
        Field::new("address", DataType::FixedSizeBinary(20), false),
        Field::new("amount", DataType::UInt64, false),
    ]))
}

pub fn writer_properties() -> WriterProperties {
    let mut builder = crate::writer::properties();
    for name in ["block_number", "index", "validator_index", "amount"] {
        builder = builder.set_column_encoding(name.into(), Encoding::DELTA_BINARY_PACKED);
    }
    builder
        .set_column_dictionary_enabled("address".into(), true)
        .build()
}

pub fn write_withdrawals(rows: &[WithdrawalRow]) -> Result<(Vec<u8>, FileEntry)> {
    write_with_target(rows, crate::writer::ROW_GROUP_BYTES)
}

fn write_with_target(rows: &[WithdrawalRow], target: usize) -> Result<(Vec<u8>, FileEntry)> {
    let hash = content_hash(rows)?;
    let mut bytes = Vec::new();
    let metadata = {
        let mut writer = ArrowWriter::try_new(&mut bytes, schema(), Some(writer_properties()))?;
        // Every field is required and fixed-width, so the canonical row budget is exact.
        for chunk in rows.chunks((target / CANONICAL_ROW_BYTES).max(1)) {
            writer.write(&to_batch(chunk)?)?;
            writer.flush()?;
        }
        writer.finish()?
    };
    let entry = FileEntry {
        name: Table::Withdrawals.file_name().into(),
        table: Table::Withdrawals,
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

pub fn read_withdrawals(bytes: Bytes) -> Result<Vec<WithdrawalRow>> {
    let builder = ParquetRecordBatchReaderBuilder::try_new(bytes)?;
    check_schema(builder.schema())?;
    let expected_rows = builder.metadata().file_metadata().num_rows();
    let mut rows = Vec::new();
    for batch in builder.build()? {
        rows.extend(from_batch(&batch?)?);
    }
    if i64::try_from(rows.len()).ok() != Some(expected_rows) {
        return Err(Error::Row(
            "decoded withdrawal count differs from the file footer".into(),
        ));
    }
    validate_rows(&rows)?;
    Ok(rows)
}

fn to_batch(rows: &[WithdrawalRow]) -> Result<RecordBatch> {
    let mut addresses = FixedSizeBinaryBuilder::new(20);
    for row in rows {
        addresses.append_value(row.address)?;
    }
    let columns: Vec<ArrayRef> = vec![
        Arc::new(UInt64Array::from_iter_values(
            rows.iter().map(|r| r.block_number),
        )),
        Arc::new(UInt64Array::from_iter_values(rows.iter().map(|r| r.index))),
        Arc::new(UInt64Array::from_iter_values(
            rows.iter().map(|r| r.validator_index),
        )),
        Arc::new(addresses.finish()),
        Arc::new(UInt64Array::from_iter_values(rows.iter().map(|r| r.amount))),
    ];
    Ok(RecordBatch::try_new(schema(), columns)?)
}

fn check_schema(actual: &Schema) -> Result<()> {
    let expected = schema();
    if actual.fields().len() != expected.fields().len() {
        return Err(Error::Schema(
            "expected exactly five v1 withdrawal columns".into(),
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

fn from_batch(batch: &RecordBatch) -> Result<Vec<WithdrawalRow>> {
    check_schema(batch.schema().as_ref())?;
    if batch.columns().iter().any(|c| c.null_count() != 0) {
        return Err(Error::Row("null in a required withdrawal column".into()));
    }
    let integers = [0, 1, 2, 4].map(|i| {
        batch
            .column(i)
            .as_any()
            .downcast_ref::<UInt64Array>()
            .ok_or_else(|| Error::Schema(format!("expected uint64 at withdrawal column {i}")))
    });
    let [blocks, indices, validators, amounts] = integers;
    let (blocks, indices, validators, amounts) = (blocks?, indices?, validators?, amounts?);
    let addresses = batch
        .column(3)
        .as_any()
        .downcast_ref::<FixedSizeBinaryArray>()
        .ok_or_else(|| Error::Schema("expected fixed binary withdrawal address".into()))?;
    (0..batch.num_rows())
        .map(|i| {
            Ok(WithdrawalRow {
                block_number: blocks.value(i),
                index: indices.value(i),
                validator_index: validators.value(i),
                address: addresses
                    .value(i)
                    .try_into()
                    .map_err(|_| Error::Row("expected 20-byte address".into()))?,
                amount: amounts.value(i),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use parquet::basic::{Compression, Type};
    use parquet::file::reader::{FileReader, SerializedFileReader};

    fn fixtures() -> Vec<WithdrawalRow> {
        (0..5)
            .map(|i| WithdrawalRow {
                block_number: 17_000_000 + i / 2,
                index: 1_000_000 + i,
                validator_index: u64::MAX - i,
                address: [0xab; 20],
                amount: u64::MAX - i,
            })
            .collect()
    }

    #[test]
    fn round_trip_keeps_unsigned_fields_and_gwei() {
        let rows = fixtures();
        let (bytes, entry) = write_withdrawals(&rows).unwrap();
        assert_eq!(entry.row_count, 5);
        assert_eq!(entry.row_groups, 1);
        assert_eq!(entry.byte_size, bytes.len() as u64);
        assert_eq!(entry.blake3, blake3(&bytes));
        let decoded = read_withdrawals(bytes.into()).unwrap();
        assert_eq!(decoded, rows);
        assert_eq!(entry.content_hash, content_hash(&decoded).unwrap());
    }

    #[test]
    fn empty_file_and_deterministic_framing() {
        let (bytes, entry) = write_withdrawals(&[]).unwrap();
        assert_eq!((entry.row_count, entry.row_groups), (0, 0));
        assert_eq!(entry.content_hash, content_hash(&[]).unwrap());
        assert!(read_withdrawals(bytes.into()).unwrap().is_empty());
        assert_eq!(
            write_withdrawals(&fixtures()).unwrap(),
            write_withdrawals(&fixtures()).unwrap()
        );
    }

    #[test]
    fn row_groups_obey_exact_canonical_budget_without_changing_identity() {
        let rows = fixtures();
        let (bytes, split) = write_with_target(&rows, CANONICAL_ROW_BYTES * 2).unwrap();
        let (_, single) = write_withdrawals(&rows).unwrap();
        assert_eq!(split.row_groups, 3);
        assert_ne!(split.blake3, single.blake3);
        assert_eq!(split.content_hash, single.content_hash);
        let reader = SerializedFileReader::new(Bytes::from(bytes.clone())).unwrap();
        assert_eq!(
            reader
                .metadata()
                .row_groups()
                .iter()
                .map(|r| r.num_rows())
                .collect::<Vec<_>>(),
            [2, 2, 1]
        );
        assert_eq!(read_withdrawals(bytes.into()).unwrap(), rows);
    }

    #[test]
    fn footer_matches_withdrawal_profile() {
        let reader =
            SerializedFileReader::new(Bytes::from(write_withdrawals(&fixtures()).unwrap().0))
                .unwrap();
        let metadata = reader.metadata();
        assert_eq!(
            metadata.file_metadata().created_by(),
            Some(crate::writer::CREATED_BY)
        );
        let columns = metadata.file_metadata().schema_descr().columns();
        assert_eq!(columns[3].physical_type(), Type::FIXED_LEN_BYTE_ARRAY);
        assert_eq!(columns[3].type_length(), 20);
        for i in [0, 1, 2, 4] {
            assert_eq!(columns[i].physical_type(), Type::INT64);
            let column = metadata.row_group(0).column(i);
            assert!(column
                .encodings()
                .any(|e| e == Encoding::DELTA_BINARY_PACKED));
            assert!(column.statistics().is_some());
            assert!(matches!(column.compression(), Compression::ZSTD(_)));
        }
        assert!(metadata
            .row_group(0)
            .column(3)
            .encodings()
            .any(|e| e == Encoding::RLE_DICTIONARY));
    }

    #[test]
    fn writer_and_reader_reject_disorder_and_zero_amounts() {
        for malformed in [
            {
                let mut rows = fixtures();
                rows.swap(0, 4);
                rows
            },
            {
                let mut rows = fixtures();
                rows[0].amount = 0;
                rows
            },
        ] {
            assert!(write_withdrawals(&malformed).is_err());
            let mut bytes = Vec::new();
            let mut writer =
                ArrowWriter::try_new(&mut bytes, schema(), Some(writer_properties())).unwrap();
            for row in malformed {
                writer.write(&to_batch(&[row]).unwrap()).unwrap();
                writer.flush().unwrap();
            }
            writer.close().unwrap();
            assert!(read_withdrawals(bytes.into()).is_err());
        }
    }

    #[test]
    fn reader_rejects_wrong_schema_and_truncation() {
        let batch = to_batch(&fixtures())
            .unwrap()
            .project(&[0, 2, 1, 3, 4])
            .unwrap();
        let mut bytes = Vec::new();
        let mut writer =
            ArrowWriter::try_new(&mut bytes, batch.schema(), Some(writer_properties())).unwrap();
        writer.write(&batch).unwrap();
        writer.close().unwrap();
        assert!(matches!(
            read_withdrawals(bytes.into()),
            Err(Error::Schema(_))
        ));
        let (mut bytes, _) = write_withdrawals(&fixtures()).unwrap();
        bytes.truncate(bytes.len() - 8);
        assert!(read_withdrawals(bytes.into()).is_err());
    }
}
