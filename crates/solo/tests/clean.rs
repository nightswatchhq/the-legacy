//! End-to-end over the actual binary: seal a small chain, write it out, and let `solo clean` read
//! it back. Unit tests prove the hash chain; this proves the thing a mirror operator types.

use std::path::{Path, PathBuf};
use std::process::Command;

use legacy_format::hash::blake3;
use legacy_format::manifest::{Boundary, FileEntry, Manifest, Table};
use legacy_format::{pact, Hash32};

fn manifest(index: u64) -> Manifest {
    let mut m = Manifest::new(
        1,
        "Silo 1",
        index,
        Boundary {
            start_block_hash: blake3(format!("start{index}").as_bytes()),
            end_block_hash: blake3(format!("end{index}").as_bytes()),
            parent_hash_of_start: blake3(format!("end{}", index.wrapping_sub(1)).as_bytes()),
        },
    );
    m.files.push(FileEntry {
        name: Table::Headers.file_name().into(),
        table: Table::Headers,
        byte_size: 4096,
        blake3: blake3(format!("headers{index}").as_bytes()),
        content_hash: blake3(format!("headers{index}/rows").as_bytes()),
        row_count: 8192,
        row_groups: 1,
    });
    m
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("the-legacy-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_chain(dir: &Path, n: u64) -> Vec<PathBuf> {
    let mut ms: Vec<Manifest> = (0..n).map(manifest).collect();
    pact::seal_chain(None, &mut ms).unwrap();
    ms.iter()
        .map(|m| {
            let path = dir.join(format!("{:06}.json", m.relic_index()));
            std::fs::write(&path, m.to_canonical_bytes().unwrap()).unwrap();
            path
        })
        .collect()
}

fn solo(args: &[&PathBuf], flags: &[&str]) -> std::process::Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_solo"));
    cmd.arg("clean");
    for a in args {
        cmd.arg(a);
    }
    for f in flags {
        cmd.arg(f);
    }
    cmd.output().unwrap()
}

#[test]
fn clean_accepts_a_sealed_chain_and_prints_its_head_root() {
    let dir = scratch("clean-ok");
    let paths = write_chain(&dir, 3);
    let refs: Vec<&PathBuf> = paths.iter().collect();

    let out = solo(&refs, &["--json"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["checks"]["pact_chain"], "pass");
    assert_eq!(report["relics"], 3);
    assert_eq!(report["block_range"]["end"], 24575);
    // The report must keep saying what it did not do. If this assertion ever has to be relaxed it
    // should be because the check was implemented, not because the wording got more comfortable.
    assert!(report["checks"]["file_hashes"]
        .as_str()
        .unwrap()
        .starts_with("not checked"));

    let mut sealed: Vec<Manifest> = (0..3).map(manifest).collect();
    let head = pact::seal_chain(None, &mut sealed).unwrap();
    assert_eq!(report["pact_root"], head.to_hex());

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn clean_rejects_a_relic_edited_after_sealing() {
    let dir = scratch("clean-tampered");
    let paths = write_chain(&dir, 3);

    let mut middle: Manifest = serde_json::from_slice(&std::fs::read(&paths[1]).unwrap()).unwrap();
    middle.files[0].blake3 = Hash32::ZERO;
    std::fs::write(&paths[1], middle.to_canonical_bytes().unwrap()).unwrap();

    let refs: Vec<&PathBuf> = paths.iter().collect();
    let out = solo(&refs, &[]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("relic 1"), "{stderr}");

    std::fs::remove_dir_all(&dir).ok();
}

// Deliberately incomplete header schema: until the header codec exists, a byte/metadata check
// must not upgrade this to "header contents verified". Everything here is synthetic.
fn header_fixture(start: u64) -> (Vec<u8>, FileEntry) {
    use arrow_array::{RecordBatch, UInt64Array};
    use arrow_schema::{DataType, Field, Schema};
    use parquet::arrow::ArrowWriter;
    use std::sync::Arc;

    let schema = Arc::new(Schema::new(vec![Field::new(
        "block_number",
        DataType::UInt64,
        false,
    )]));
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![Arc::new(UInt64Array::from_iter_values(start..start + 8192))],
    )
    .unwrap();
    let mut bytes = Vec::new();
    let mut writer = ArrowWriter::try_new(&mut bytes, schema, None).unwrap();
    writer.write(&batch).unwrap();
    writer.close().unwrap();
    let entry = FileEntry {
        name: "headers.parquet".into(),
        table: Table::Headers,
        byte_size: bytes.len() as u64,
        blake3: blake3(&bytes),
        content_hash: Hash32::ZERO,
        row_count: 8192,
        row_groups: 1,
    };
    (bytes, entry)
}

fn log_fixture(block: u64) -> (Vec<u8>, FileEntry) {
    legacy_parquet::logs::write_logs(&[legacy_format::logs::LogRow {
        block_number: block,
        transaction_index: 0,
        log_index: 0,
        transaction_hash: [0x11; 32],
        address: [0x22; 20],
        topics: vec![[0x33; 32]],
        data: vec![0xaa, 0xbb],
    }])
    .unwrap()
}

fn withdrawal_fixture(block: u64) -> (Vec<u8>, FileEntry) {
    legacy_parquet::withdrawals::write_withdrawals(&[legacy_format::withdrawals::WithdrawalRow {
        block_number: block,
        index: block,
        validator_index: 7,
        address: [0x44; 20],
        amount: 32_000_000_000,
    }])
    .unwrap()
}

fn write_local_chain(dir: &Path, n: u64) -> Vec<PathBuf> {
    let mut manifests: Vec<_> = (0..n)
        .map(|i| {
            let mut m = manifest(i);
            m.chain_id = 31337;
            m.silo = "synthetic test fixtures, not chain history".into();
            m.files.clear();
            let relic_dir = dir.join(format!("{i:06}"));
            std::fs::create_dir_all(&relic_dir).unwrap();
            for (bytes, entry) in [
                header_fixture(i * 8192),
                log_fixture(i * 8192 + 1),
                withdrawal_fixture(i * 8192 + 2),
            ] {
                std::fs::write(relic_dir.join(&entry.name), bytes).unwrap();
                m.files.push(entry);
            }
            m
        })
        .collect();
    pact::seal_chain(None, &mut manifests).unwrap();
    manifests
        .iter()
        .map(|m| {
            let path = dir.join(format!("{:06}/manifest.json", m.relic_index()));
            std::fs::write(&path, m.to_canonical_bytes().unwrap()).unwrap();
            path
        })
        .collect()
}

fn reseal_first(path: &Path, mutate: impl FnOnce(&mut Manifest)) {
    let mut m: Manifest = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    mutate(&mut m);
    pact::seal_chain(None, std::slice::from_mut(&mut m)).unwrap();
    std::fs::write(path, m.to_canonical_bytes().unwrap()).unwrap();
}

fn assert_failed(out: &std::process::Output, text: &str) {
    assert!(
        !out.status.success(),
        "unexpected success: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        out.stdout.is_empty(),
        "a failed run must not print a success report"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains(text), "expected {text:?} in {stderr}");
}

#[test]
fn file_cleaning_reports_precisely_which_tables_were_decoded() {
    let dir = scratch("local-success");
    let paths = write_local_chain(&dir, 2);
    let out = solo(&paths.iter().collect::<Vec<_>>(), &["--files", "--json"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    for check in ["file_hashes", "file_sizes", "parquet_counts"] {
        assert_eq!(report["checks"][check], "pass");
    }
    assert!(report["checks"]["content_hashes"]
        .as_str()
        .unwrap()
        .starts_with("partial"));
    assert_eq!(report["files"].as_array().unwrap().len(), 6);
    for file in report["files"].as_array().unwrap() {
        assert_eq!(file["checks"]["blake3"], "pass");
        let status = file["checks"]["content_hash"].as_str().unwrap();
        if file["table"] == "headers" {
            assert!(status.starts_with("not checked"));
            assert!(file["checks"]["schema"]
                .as_str()
                .unwrap()
                .starts_with("not checked"));
        } else {
            assert_eq!(status, "pass");
            assert_eq!(file["checks"]["block_range"], "pass");
        }
    }
    for check in [
        "transactions_root",
        "receipts_root",
        "withdrawals_root",
        "checkpoint_anchor",
        "header_linkage",
        "table_completeness",
        "producer_signatures",
        "era1_accumulator",
        "finality",
        "index_sidecars",
    ] {
        assert!(report["checks"][check]
            .as_str()
            .unwrap()
            .starts_with("not checked"));
    }
    let prose = solo(&[&paths[0]], &["--files"]);
    assert!(prose.status.success());
    let text = String::from_utf8(prose.stdout).unwrap();
    assert!(text.contains("headers.parquet: schema/rows/content hash/block bounds: not checked"));
    assert!(text.contains("withdrawals.parquet: schema/rows/content hash/block bounds: pass"));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_changed_byte_in_the_last_relic_fails_the_whole_run() {
    let dir = scratch("local-corrupt");
    let paths = write_local_chain(&dir, 2);
    let file = paths[1].parent().unwrap().join("logs.parquet");
    let mut bytes = std::fs::read(&file).unwrap();
    bytes[8] ^= 1;
    std::fs::write(&file, bytes).unwrap();
    let out = solo(&paths.iter().collect::<Vec<_>>(), &["--files", "--json"]);
    assert_failed(&out, "BLAKE3 does not match");
    assert!(String::from_utf8_lossy(&out.stderr).contains("000001/logs.parquet"));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn missing_truncated_and_nonregular_files_fail_but_manifest_only_mode_still_works() {
    for kind in ["missing", "truncated", "directory"] {
        let dir = scratch(&format!("local-{kind}"));
        let paths = write_local_chain(&dir, 1);
        let file = paths[0].parent().unwrap().join("logs.parquet");
        let expected = match kind {
            "missing" => {
                std::fs::remove_file(&file).unwrap();
                "reading"
            }
            "truncated" => {
                std::fs::write(&file, b"PAR1").unwrap();
                "byte_size"
            }
            _ => {
                std::fs::remove_file(&file).unwrap();
                std::fs::create_dir(&file).unwrap();
                "expected a regular file"
            }
        };
        assert_failed(&solo(&[&paths[0]], &["--files"]), expected);
        assert!(solo(&[&paths[0]], &["--json"]).status.success());
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn sealed_manifest_lies_about_hashes_and_counts_are_detected() {
    for (number, field) in [
        "content_hash",
        "withdrawals_content_hash",
        "row_count",
        "row_groups",
        "byte_size",
        "spec_version",
    ]
    .iter()
    .enumerate()
    {
        let dir = scratch(&format!("local-claim-{number}"));
        let paths = write_local_chain(&dir, 1);
        reseal_first(&paths[0], |m| match *field {
            "content_hash" => m.files[1].content_hash = Hash32::ZERO,
            "withdrawals_content_hash" => m.files[2].content_hash = Hash32::ZERO,
            "row_count" => m.files[1].row_count += 1,
            "row_groups" => m.files[1].row_groups += 1,
            "byte_size" => m.files[1].byte_size += 1,
            "spec_version" => m.spec_version += 1,
            _ => unreachable!(),
        });
        let expected = if *field == "withdrawals_content_hash" {
            "content_hash"
        } else {
            field
        };
        assert_failed(&solo(&[&paths[0]], &["--files", "--json"]), expected);
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn correctly_hashed_rows_outside_the_relic_are_rejected() {
    for (number, (bytes, entry)) in [log_fixture(8192), withdrawal_fixture(8192)]
        .into_iter()
        .enumerate()
    {
        let dir = scratch(&format!("local-range-{number}"));
        let paths = write_local_chain(&dir, 1);
        std::fs::write(paths[0].parent().unwrap().join(&entry.name), bytes).unwrap();
        reseal_first(&paths[0], |m| {
            let table = entry.table;
            *m.files.iter_mut().find(|f| f.table == table).unwrap() = entry;
        });
        assert_failed(&solo(&[&paths[0]], &["--files"]), "outside the relic range");
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn valid_file_hash_does_not_excuse_a_wrong_table_schema_or_invalid_parquet() {
    for malformed_parquet in [false, true] {
        let dir = scratch(&format!("local-schema-{malformed_parquet}"));
        let paths = write_local_chain(&dir, 1);
        let (mut bytes, mut entry) = header_fixture(0);
        entry.table = Table::Logs;
        entry.name = "logs.parquet".into();
        if malformed_parquet {
            bytes.fill(0);
            entry.blake3 = blake3(&bytes);
        }
        std::fs::write(paths[0].parent().unwrap().join(&entry.name), bytes).unwrap();
        reseal_first(&paths[0], |m| m.files[1] = entry);
        let out = solo(&[&paths[0]], &["--files"]);
        assert_failed(
            &out,
            if malformed_parquet {
                "Parquet"
            } else {
                "schema"
            },
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn after_is_predecessor_context_not_a_claim_about_its_files() {
    let dir = scratch("local-after");
    let paths = write_local_chain(&dir, 2);
    std::fs::remove_file(paths[0].parent().unwrap().join("headers.parquet")).unwrap();
    let out = solo(
        &[&paths[1]],
        &["--files", "--json", "--after", paths[0].to_str().unwrap()],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["relics"], 1);
    assert!(report["files"]
        .as_array()
        .unwrap()
        .iter()
        .all(|f| f["relic_index"] == 1));
    assert!(report["scope"]
        .as_str()
        .unwrap()
        .contains("predecessor context"));
    std::fs::remove_dir_all(dir).unwrap();
}

#[cfg(unix)]
#[test]
fn table_symlinks_are_not_followed() {
    let dir = scratch("local-symlink");
    let paths = write_local_chain(&dir, 1);
    let file = paths[0].parent().unwrap().join("logs.parquet");
    let target = dir.join("outside.parquet");
    std::fs::rename(&file, &target).unwrap();
    std::os::unix::fs::symlink(&target, &file).unwrap();
    assert_failed(&solo(&[&paths[0]], &["--files"]), "expected a regular file");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn headers_only_reports_no_decoded_checks_rather_than_partial_success() {
    let dir = scratch("local-headers-only");
    let paths = write_local_chain(&dir, 1);
    reseal_first(&paths[0], |m| m.files.retain(|f| f.table == Table::Headers));
    let out = solo(&[&paths[0]], &["--files", "--json"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["checks"]["file_hashes"], "pass");
    assert!(report["checks"]["content_hashes"]
        .as_str()
        .unwrap()
        .starts_with("not checked"));
    std::fs::remove_dir_all(dir).unwrap();
}
