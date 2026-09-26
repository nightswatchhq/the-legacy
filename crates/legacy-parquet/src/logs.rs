//! The v1 logs schema, writer settings, and checked conversion back to canonical rows.

use std::sync::Arc;

use arrow_array::builder::{BinaryBuilder, FixedSizeBinaryBuilder};
use arrow_array::{
    Array, ArrayRef, BinaryArray, FixedSizeBinaryArray, RecordBatch, UInt32Array, UInt64Array,
};
use arrow_schema::{DataType, Field, Schema, SchemaRef};
use bytes::Bytes;
use legacy_format::hash::blake3;
use legacy_format::logs::{content_hash, validate_rows, LogRow};
use legacy_format::{FileEntry, Table};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use parquet::arrow::ArrowWriter;
use parquet::basic::Encoding;
use parquet::file::properties::WriterProperties;

use crate::{Error, Result};

pub use crate::writer::{CREATED_BY, PAGE_BYTES, ROW_GROUP_BYTES};

pub fn schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        Field::new("block_number", DataType::UInt64, false),
        Field::new("transaction_index", DataType::UInt32, false),
        Field::new("log_index", DataType::UInt32, false),
        Field::new("transaction_hash", DataType::FixedSizeBinary(32), false),
        Field::new("address", DataType::FixedSizeBinary(20), false),
        Field::new("topic0", DataType::FixedSizeBinary(32), true),
        Field::new("topic1", DataType::FixedSizeBinary(32), true),
        Field::new("topic2", DataType::FixedSizeBinary(32), true),
        Field::new("topic3", DataType::FixedSizeBinary(32), true),
        Field::new("data", DataType::Binary, false),
    ]))
}

/// Pin the writer choices explicitly; framing remains distinct from canonical content identity.
pub fn writer_properties() -> WriterProperties {
    let mut builder = crate::writer::properties();
    for name in ["block_number", "transaction_index", "log_index"] {
        builder = builder.set_column_encoding(name.into(), Encoding::DELTA_BINARY_PACKED);
    }
    for name in ["address", "topic0"] {
        builder = builder.set_column_dictionary_enabled(name.into(), true);
    }
    for name in ["address", "topic0", "topic1", "topic2", "topic3"] {
        builder = builder
            .set_column_bloom_filter_enabled(name.into(), true)
            .set_column_bloom_filter_fpp(name.into(), 0.01)
            .set_column_bloom_filter_max_ndv(name.into(), 100_000);
    }
    builder.build()
}

/// Encode a local table and return the file metadata needed by a future relic sealer.
/// This does not assert full block coverage, finality, receipt inclusion, or checkpoint trust.
pub fn write_logs(rows: &[LogRow]) -> Result<(Vec<u8>, FileEntry)> {
    write_with_row_group_target(rows, ROW_GROUP_BYTES)
}

fn write_with_row_group_target(rows: &[LogRow], target: usize) -> Result<(Vec<u8>, FileEntry)> {
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
        name: Table::Logs.file_name().to_owned(),
        table: Table::Logs,
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

/// Read a complete v1 logs table, rejecting incompatible schemas and malformed row order.
/// File hashes and chain commitments must be checked separately by the caller.
pub fn read_logs(bytes: Bytes) -> Result<Vec<LogRow>> {
    let builder = ParquetRecordBatchReaderBuilder::try_new(bytes)?;
    check_schema(builder.schema())?;
    let expected_rows = builder.metadata().file_metadata().num_rows();
    let mut rows = Vec::new();
    for batch in builder.build()? {
        rows.extend(from_batch(&batch?)?);
    }
    if i64::try_from(rows.len()).ok() != Some(expected_rows) {
        return Err(Error::Row(
            "decoded row count differs from the file footer".into(),
        ));
    }
    validate_rows(&rows)?;
    Ok(rows)
}

fn to_batch(rows: &[LogRow]) -> Result<RecordBatch> {
    // Arrow Binary has signed 32-bit offsets even though canonical lengths are u64.
    let data_size = rows
        .iter()
        .try_fold(0usize, |total, row| total.checked_add(row.data.len()));
    if data_size.is_none_or(|size| size > i32::MAX as usize) {
        return Err(Error::Row(
            "data exceeds the Arrow Binary offset limit for one row group".into(),
        ));
    }
    let mut hashes = FixedSizeBinaryBuilder::new(32);
    let mut addresses = FixedSizeBinaryBuilder::new(20);
    let mut topics: [_; 4] = std::array::from_fn(|_| FixedSizeBinaryBuilder::new(32));
    let mut data = BinaryBuilder::new();
    for row in rows {
        hashes.append_value(row.transaction_hash)?;
        addresses.append_value(row.address)?;
        for (index, builder) in topics.iter_mut().enumerate() {
            if let Some(topic) = row.topics.get(index) {
                builder.append_value(topic)?;
            } else {
                builder.append_null();
            }
        }
        data.append_value(&row.data);
    }
    let mut columns: Vec<ArrayRef> = vec![
        Arc::new(UInt64Array::from_iter_values(
            rows.iter().map(|r| r.block_number),
        )),
        Arc::new(UInt32Array::from_iter_values(
            rows.iter().map(|r| r.transaction_index),
        )),
        Arc::new(UInt32Array::from_iter_values(
            rows.iter().map(|r| r.log_index),
        )),
        Arc::new(hashes.finish()),
        Arc::new(addresses.finish()),
    ];
    columns.extend(topics.iter_mut().map(|b| Arc::new(b.finish()) as ArrayRef));
    columns.push(Arc::new(data.finish()));
    Ok(RecordBatch::try_new(schema(), columns)?)
}

fn check_schema(actual: &Schema) -> Result<()> {
    let expected = schema();
    if actual.fields().len() != expected.fields().len() {
        return Err(Error::Schema("expected exactly ten v1 columns".into()));
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
        .ok_or_else(|| Error::Schema(format!("unexpected array type at column {index}")))
}

fn fixed<const N: usize>(array: &FixedSizeBinaryArray, row: usize) -> Result<[u8; N]> {
    array
        .value(row)
        .try_into()
        .map_err(|_| Error::Row(format!("expected {N} bytes")))
}

fn from_batch(batch: &RecordBatch) -> Result<Vec<LogRow>> {
    check_schema(batch.schema().as_ref())?;
    for (field, column) in batch.schema().fields().iter().zip(batch.columns()) {
        if !field.is_nullable() && column.null_count() != 0 {
            return Err(Error::Row(format!(
                "null in required column {}",
                field.name()
            )));
        }
    }
    let blocks = column::<UInt64Array>(batch, 0)?;
    let transactions = column::<UInt32Array>(batch, 1)?;
    let indices = column::<UInt32Array>(batch, 2)?;
    let hashes = column::<FixedSizeBinaryArray>(batch, 3)?;
    let addresses = column::<FixedSizeBinaryArray>(batch, 4)?;
    let topics = (5..9)
        .map(|i| column::<FixedSizeBinaryArray>(batch, i))
        .collect::<Result<Vec<_>>>()?;
    let data = column::<BinaryArray>(batch, 9)?;
    let mut rows = Vec::with_capacity(batch.num_rows());
    for index in 0..batch.num_rows() {
        let mut row_topics = Vec::new();
        let mut absent = false;
        for topic in &topics {
            if topic.is_null(index) {
                absent = true;
            } else {
                if absent {
                    return Err(Error::Row("non-null topic after a null topic".into()));
                }
                row_topics.push(fixed(topic, index)?);
            }
        }
        rows.push(LogRow {
            block_number: blocks.value(index),
            transaction_index: transactions.value(index),
            log_index: indices.value(index),
            transaction_hash: fixed(hashes, index)?,
            address: fixed(addresses, index)?,
            topics: row_topics,
            data: data.value(index).to_vec(),
        });
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use parquet::basic::{Compression, Type};
    use parquet::column::page::Page;
    use parquet::file::reader::{FileReader, SerializedFileReader};

    fn fixtures() -> Vec<LogRow> {
        (0..5)
            .map(|index| LogRow {
                block_number: 20_078_592,
                transaction_index: index,
                log_index: index,
                transaction_hash: [index as u8; 32],
                address: [0xab; 20],
                topics: (0..index).map(|topic| [topic as u8; 32]).collect(),
                data: vec![0xcd; index as usize],
            })
            .collect()
    }

    fn encode_batch(batch: &RecordBatch) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut writer =
            ArrowWriter::try_new(&mut bytes, batch.schema(), Some(writer_properties())).unwrap();
        writer.write(batch).unwrap();
        writer.close().unwrap();
        bytes
    }

    #[test]
    fn round_trip_preserves_every_topic_count_and_both_hashes() {
        let rows = fixtures();
        let (bytes, entry) = write_logs(&rows).unwrap();
        assert_eq!(entry.name, "logs.parquet");
        assert_eq!(entry.table, Table::Logs);
        assert_eq!(entry.byte_size, bytes.len() as u64);
        assert_eq!(entry.row_count, 5);
        assert_eq!(entry.row_groups, 1);
        assert_eq!(entry.blake3, blake3(&bytes));
        let read = read_logs(bytes.into()).unwrap();
        assert_eq!(read, rows);
        assert_eq!(entry.content_hash, content_hash(&read).unwrap());
    }

    #[test]
    fn empty_table_is_a_readable_file_with_no_row_groups() {
        let (bytes, entry) = write_logs(&[]).unwrap();
        assert_eq!(entry.row_count, 0);
        assert_eq!(entry.row_groups, 0);
        assert_eq!(entry.content_hash, content_hash(&[]).unwrap());
        assert!(read_logs(bytes.into()).unwrap().is_empty());
    }

    #[test]
    fn unsigned_values_above_signed_ranges_survive() {
        let mut rows = fixtures();
        for (index, row) in rows.iter_mut().enumerate() {
            row.block_number = u64::MAX;
            row.transaction_index = u32::MAX - 4 + index as u32;
            row.log_index = row.transaction_index;
        }
        assert_eq!(
            read_logs(write_logs(&rows).unwrap().0.into()).unwrap(),
            rows
        );
    }

    #[test]
    fn same_input_produces_identical_file_bytes() {
        assert_eq!(
            write_logs(&fixtures()).unwrap(),
            write_logs(&fixtures()).unwrap()
        );
    }

    #[test]
    fn row_group_framing_does_not_change_content_identity() {
        let rows = fixtures();
        let (single, a) = write_logs(&rows).unwrap();
        let (multiple, b) = write_with_row_group_target(&rows, 1).unwrap();
        assert_eq!(b.row_groups, 5);
        assert_ne!(single, multiple);
        assert_ne!(a.blake3, b.blake3);
        assert_eq!(a.content_hash, b.content_hash);
        assert_eq!(
            content_hash(&read_logs(multiple.into()).unwrap()).unwrap(),
            a.content_hash
        );
    }

    #[test]
    fn row_group_cut_includes_an_exact_fit() {
        let mut rows = fixtures();
        for row in &mut rows {
            row.topics.clear();
            row.data.clear();
        }
        let target = rows[0].canonical_bytes().unwrap().len() * 2;
        let (bytes, entry) = write_with_row_group_target(&rows, target).unwrap();
        assert_eq!(entry.row_groups, 3);
        let reader = SerializedFileReader::new(Bytes::from(bytes)).unwrap();
        let counts: Vec<_> = reader
            .metadata()
            .row_groups()
            .iter()
            .map(|r| r.num_rows())
            .collect();
        assert_eq!(counts, [2, 2, 1]);
    }

    #[test]
    fn footer_records_physical_schema_compression_statistics_and_blooms() {
        let (bytes, _) = write_logs(&fixtures()).unwrap();
        let reader = SerializedFileReader::new(Bytes::from(bytes)).unwrap();
        let metadata = reader.metadata();
        assert_eq!(metadata.file_metadata().created_by(), Some(CREATED_BY));
        let columns = metadata.file_metadata().schema_descr().columns();
        assert_eq!(columns[0].physical_type(), Type::INT64);
        assert_eq!(columns[1].physical_type(), Type::INT32);
        assert_eq!(columns[3].physical_type(), Type::FIXED_LEN_BYTE_ARRAY);
        assert_eq!(columns[3].type_length(), 32);
        assert_eq!(columns[4].type_length(), 20);
        assert_eq!(columns[9].physical_type(), Type::BYTE_ARRAY);
        let group = metadata.row_group(0);
        for column in group.columns() {
            assert!(matches!(column.compression(), Compression::ZSTD(_)));
            assert!(column.statistics().is_some());
        }
        for index in 0..3 {
            assert!(group
                .column(index)
                .encodings()
                .any(|e| e == Encoding::DELTA_BINARY_PACKED));
        }
        for index in [4, 5] {
            assert!(group
                .column(index)
                .encodings()
                .any(|e| e == Encoding::RLE_DICTIONARY));
        }
        for index in 4..9 {
            assert!(group.column(index).bloom_filter_offset().is_some());
        }
        for index in 0..10 {
            let row_group = reader.get_row_group(0).unwrap();
            let pages = row_group.get_column_page_reader(index).unwrap();
            let mut data_pages = 0;
            for page in pages {
                match page.unwrap() {
                    Page::DataPageV2 { .. } => data_pages += 1,
                    Page::DictionaryPage { .. } => {}
                    Page::DataPage { .. } => panic!("writer emitted a V1 data page"),
                }
            }
            assert!(data_pages > 0);
        }
    }

    #[test]
    fn writer_refuses_invalid_rows() {
        let mut rows = fixtures();
        rows.swap(0, 1);
        assert!(matches!(write_logs(&rows), Err(Error::Logs(_))));
        rows = fixtures();
        rows[0].topics = vec![[0; 32]; 5];
        assert!(matches!(write_logs(&rows), Err(Error::Logs(_))));
    }

    #[test]
    fn reader_refuses_disorder_across_row_groups() {
        let mut rows = fixtures();
        rows.swap(0, 4);
        let mut bytes = Vec::new();
        let mut writer =
            ArrowWriter::try_new(&mut bytes, schema(), Some(writer_properties())).unwrap();
        for row in rows {
            writer.write(&to_batch(&[row]).unwrap()).unwrap();
            writer.flush().unwrap();
        }
        writer.close().unwrap();
        assert!(matches!(read_logs(bytes.into()), Err(Error::Logs(_))));
    }

    #[test]
    fn reader_refuses_topic_holes() {
        let batch = to_batch(&fixtures()).unwrap();
        let mut columns = batch.columns().to_vec();
        columns.swap(5, 8);
        let malformed = RecordBatch::try_new(schema(), columns).unwrap();
        assert!(matches!(
            read_logs(encode_batch(&malformed).into()),
            Err(Error::Row(_))
        ));
    }

    #[test]
    fn reader_refuses_missing_reordered_and_wrong_width_columns() {
        let batch = to_batch(&fixtures()).unwrap();
        for projection in [
            &[0, 1, 2, 3, 4, 5, 6, 7, 8][..],
            &[0, 2, 1, 3, 4, 5, 6, 7, 8, 9],
        ] {
            let malformed = batch.project(projection).unwrap();
            assert!(matches!(
                read_logs(encode_batch(&malformed).into()),
                Err(Error::Schema(_))
            ));
        }
        let mut fields: Vec<_> = schema()
            .fields()
            .iter()
            .map(|f| f.as_ref().clone())
            .collect();
        fields[4] = Field::new("address", DataType::FixedSizeBinary(32), false);
        let mut columns = batch.columns().to_vec();
        columns[4] = columns[3].clone();
        let malformed = RecordBatch::try_new(Arc::new(Schema::new(fields)), columns).unwrap();
        assert!(matches!(
            read_logs(encode_batch(&malformed).into()),
            Err(Error::Schema(_))
        ));
    }

    #[test]
    fn truncated_file_is_an_error_not_an_empty_table() {
        let (mut bytes, _) = write_logs(&fixtures()).unwrap();
        bytes.truncate(bytes.len() - 8);
        assert!(read_logs(bytes.into()).is_err());
        assert!(read_logs(Bytes::new()).is_err());
    }
}
