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
