//! Shared v1 writer profile. Table modules select their column encodings on top of this.

use parquet::basic::{Compression, Encoding, ZstdLevel};
use parquet::file::properties::{
    EnabledStatistics, WriterProperties, WriterPropertiesBuilder, WriterVersion,
};

pub const CREATED_BY: &str = "the-legacy/spec-1";
pub const ROW_GROUP_BYTES: usize = 128 * 1024 * 1024;
pub const PAGE_BYTES: usize = 1024 * 1024;

pub(crate) fn properties() -> WriterPropertiesBuilder {
    WriterProperties::builder()
        .set_writer_version(WriterVersion::PARQUET_2_0)
        .set_created_by(CREATED_BY.to_owned())
        .set_compression(Compression::ZSTD(
            ZstdLevel::try_new(3).expect("valid fixed zstd level"),
        ))
        .set_max_row_group_row_count(None)
        // Table codecs cut on canonical byte lengths, not the library's encoded-size estimate.
        .set_max_row_group_bytes(None)
        .set_data_page_size_limit(PAGE_BYTES)
        .set_data_page_row_count_limit(usize::MAX)
        .set_dictionary_page_size_limit(PAGE_BYTES)
        .set_write_batch_size(1024)
        .set_dictionary_enabled(false)
        .set_encoding(Encoding::PLAIN)
        .set_statistics_enabled(EnabledStatistics::Page)
}
