//! The binary, a local relic, and a TCP client. Unit tests cover filter arithmetic.

use std::io::{BufRead, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use legacy_format::hash::blake3;
use legacy_format::headers::HeaderRow;
use legacy_format::logs::LogRow;
use legacy_format::manifest::{Boundary, Manifest};
use legacy_format::receipts::ReceiptRow;
use legacy_format::transactions::TransactionRow;
use legacy_format::{pact, Hash32};
use serde_json::Value;
use sha3::{Digest, Keccak256};

struct Server {
    child: Child,
    addr: String,
    // Held open so the child's println does not die with a broken pipe.
    _stdout: std::process::ChildStdout,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn serve(dir: &Path, config: &str) -> Server {
    let path = dir.join("solo.toml");
    std::fs::write(&path, config).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_solo"))
        .args(["serve", "--config"])
        .arg(&path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut reader = std::io::BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    let n = reader.read_line(&mut line).unwrap();
    if n == 0 {
        let mut err = String::new();
        child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut err)
            .unwrap();
        panic!("solo exited before listening: {err}");
    }
    let addr = line
        .trim()
        .strip_prefix("listening ")
        .unwrap_or_else(|| panic!("unexpected startup line {line}"))
        .to_string();
    Server {
        child,
        addr,
        _stdout: reader.into_inner(),
    }
}

fn rpc(addr: &str, body: &str) -> (String, Value) {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let request = format!(
        "POST / HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).unwrap();
    let mut buf = String::new();
    stream.read_to_string(&mut buf).unwrap();
    let (headers, body) = buf.split_once("\r\n\r\n").expect("http response");
    (headers.to_string(), serde_json::from_str(body).unwrap())
}

fn call(addr: &str, method: &str, params: Value) -> Value {
    let body =
        serde_json::json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}).to_string();
    let (headers, value) = rpc(addr, &body);
    assert!(headers.contains("200"), "{headers}");
    value
}

#[test]
fn sealed_only_serves_history_and_names_what_it_did_not_check() {
    let dir = std::env::temp_dir().join(format!("solo-serve-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let manifest = write_corpus(&dir);
    let server = serve(
        &dir,
        &format!(
            "bind = \"127.0.0.1:0\"\nmanifests = [{}]\n\n[limits]\ngetlogs_max_blocks = 10\ngetlogs_max_results = 1\nbatch_max = 2\n",
            toml_string(&manifest)
        ),
    );

    let chain = call(&server.addr, "eth_chainId", json_empty());
    assert_eq!(chain["result"], "0x7a69");
    let head = call(&server.addr, "eth_blockNumber", json_empty());
    assert_eq!(head["result"], "0x1fff");
    let (headers, _) = rpc(
        &server.addr,
        &serde_json::json!({"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]})
            .to_string(),
    );
    assert!(headers.contains("X-Legacy-Sealed-Head: 8191"), "{headers}");
    assert_eq!(
        call(&server.addr, "eth_syncing", json_empty())["result"],
        false
    );

    let block = call(
        &server.addr,
        "eth_getBlockByNumber",
        serde_json::json!(["0x0", false]),
    );
    assert_eq!(block["result"]["uncles"], serde_json::json!([]));
    assert!(block["result"].get("size").is_none());
    assert_eq!(block["result"]["transactions"].as_array().unwrap().len(), 1);
    let hash = block["result"]["transactions"][0]
        .as_str()
        .unwrap()
        .to_string();

    let full = call(
        &server.addr,
        "eth_getBlockByNumber",
        serde_json::json!(["latest", true]),
    );
    assert!(full["result"]["transactions"]
        .as_array()
        .unwrap()
        .is_empty());
    let full0 = call(
        &server.addr,
        "eth_getBlockByNumber",
        serde_json::json!(["0x0", true]),
    );
    assert_eq!(
        full0["result"]["transactions"][0]["from"],
        hex20(&[0x44; 20])
    );
    assert_eq!(full0["result"]["transactions"][0]["v"], "0x1b");

    let tx = call(
        &server.addr,
        "eth_getTransactionByHash",
        serde_json::json!([hash]),
    );
    assert_eq!(tx["result"]["blockNumber"], "0x0");
    let missing = call(
        &server.addr,
        "eth_getTransactionByHash",
        serde_json::json!(["0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]),
    );
    assert!(missing["result"].is_null());
    assert!(missing["error"].is_null());

    let receipt = call(
        &server.addr,
        "eth_getTransactionReceipt",
        serde_json::json!([hash]),
    );
    assert_eq!(receipt["result"]["status"], "0x1");
    assert_eq!(receipt["result"]["logs"].as_array().unwrap().len(), 2);
    assert_eq!(receipt["result"]["logs"][0]["removed"], false);

    let one = call(
        &server.addr,
        "eth_getLogs",
        serde_json::json!([{
            "fromBlock": "0x0",
            "toBlock": "0x0",
            "address": hex20(&[0x11; 20]),
        }]),
    );
    assert_eq!(one["result"].as_array().unwrap().len(), 1);

    let too_many = call(
        &server.addr,
        "eth_getLogs",
        serde_json::json!([{"fromBlock": "0x0", "toBlock": "0x0"}]),
    );
    assert_eq!(too_many["error"]["code"], -32005);
    assert_eq!(too_many["error"]["data"]["reason"], "too_many_results");

    let wide = call(
        &server.addr,
        "eth_getLogs",
        serde_json::json!([{"fromBlock": "0x0", "toBlock": "0x14"}]),
    );
    assert_eq!(wide["error"]["data"]["reason"], "too_many_blocks");

    let above = call(
        &server.addr,
        "eth_getBlockByNumber",
        serde_json::json!(["0x2000", false]),
    );
    assert_eq!(above["error"]["code"], -32005);
    assert_eq!(above["error"]["data"]["reason"], "above_sealed_head");
    assert_eq!(above["error"]["data"]["sealed_head"], 8191);
    assert!(!above["error"]["message"].as_str().unwrap().contains("0x"));

    let pending = call(
        &server.addr,
        "eth_getBlockByNumber",
        serde_json::json!(["pending", false]),
    );
    assert_eq!(pending["error"]["code"], -32004);

    let state = call(&server.addr, "eth_call", serde_json::json!([{}, "latest"]));
    assert_eq!(state["error"]["code"], -32004);

    let caps = call(&server.addr, "legacy_capabilities", json_empty());
    assert_eq!(caps["result"]["mode"], "sealed-only");
    assert_eq!(caps["result"]["sealed_head"], 8191);
    assert_eq!(
        caps["result"]["sidecars"],
        serde_json::json!(["blockhash", "logs.addr", "logs.topics", "txhash"])
    );
    assert_eq!(caps["result"]["cleaning"]["file_hashes"], true);
    assert_eq!(caps["result"]["cleaning"]["transactions_root"], false);
    assert_eq!(caps["result"]["cleaning"]["checkpoint_anchor"], false);
    assert!(caps["result"]["tables"]
        .as_array()
        .unwrap()
        .iter()
        .any(|t| t == "logs"));
    assert!(caps["result"]["tables"]
        .as_array()
        .unwrap()
        .iter()
        .all(|t| t != "withdrawals"));

    let batch = rpc(
        &server.addr,
        &serde_json::json!([
            {"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]},
            {"jsonrpc":"2.0","id":2,"method":"eth_blockNumber","params":[]},
            {"jsonrpc":"2.0","id":3,"method":"eth_blockNumber","params":[]},
        ])
        .to_string(),
    );
    assert_eq!(batch.1["error"]["data"]["reason"], "batch_too_large");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn an_empty_config_does_not_invent_a_head() {
    let dir = std::env::temp_dir().join(format!("solo-serve-empty-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let server = serve(&dir, "bind = \"127.0.0.1:0\"\nmanifests = []\n");
    let (headers, value) = rpc(
        &server.addr,
        &serde_json::json!({"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]})
            .to_string(),
    );
    assert_eq!(value["error"]["code"], -32002);
    assert!(!headers.contains("X-Legacy-Sealed-Head"));
    let caps = call(&server.addr, "legacy_capabilities", json_empty());
    assert!(caps["result"]["sealed_head"].is_null());
    assert_eq!(caps["result"]["cleaning"]["file_hashes"], false);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn upstream_in_the_config_is_refused() {
    let dir = std::env::temp_dir().join(format!("solo-serve-up-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("solo.toml");
    std::fs::write(
        &path,
        "bind = \"127.0.0.1:0\"\nmanifests = []\n\n[upstream]\nurl = \"http://127.0.0.1:1\"\n",
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_solo"))
        .args(["serve", "--config"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let err = String::from_utf8_lossy(&output.stderr);
    assert!(err.contains("upstream"), "{err}");
    std::fs::remove_dir_all(&dir).ok();
}

fn json_empty() -> Value {
    serde_json::json!([])
}

fn hex20(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn toml_string(path: &Path) -> String {
    format!("\"{}\"", path.display())
}

fn write_corpus(dir: &Path) -> PathBuf {
    let logs = vec![
        LogRow {
            block_number: 0,
            transaction_index: 0,
            log_index: 0,
            transaction_hash: [0xab; 32],
            address: [0x11; 20],
            topics: vec![[0x22; 32]],
            data: vec![0x01],
        },
        LogRow {
            block_number: 0,
            transaction_index: 0,
            log_index: 1,
            transaction_hash: [0xab; 32],
            address: [0x66; 20],
            topics: vec![[0x77; 32]],
            data: vec![0x02],
        },
    ];
    let bloom = legacy_format::bloom::logs_bloom(&logs).unwrap();
    let ommers = Keccak256::digest([0xc0]).into();
    let mut parent = [0x11; 32];
    let headers: Vec<_> = (0..8192)
        .map(|number| {
            let hash = *blake3(format!("serve{number}").as_bytes()).as_bytes();
            let row = HeaderRow {
                block_number: number,
                block_hash: hash,
                parent_hash: parent,
                ommers_hash: ommers,
                beneficiary: [0x33; 20],
                state_root: [0; 32],
                transactions_root: [0; 32],
                receipts_root: [0; 32],
                logs_bloom: if number == 0 { bloom } else { [0; 256] },
                difficulty: vec![1],
                gas_limit: 30_000_000,
                gas_used: 0,
                timestamp: number,
                extra_data: vec![],
                mix_hash: [0; 32],
                nonce: [0; 8],
                base_fee_per_gas: None,
                withdrawals_root: None,
                blob_gas_used: None,
                excess_blob_gas: None,
                parent_beacon_block_root: None,
                requests_hash: None,
                total_difficulty: None,
            };
            parent = hash;
            row
        })
        .collect();
    let tx = TransactionRow {
        block_number: 0,
        transaction_index: 0,
        transaction_hash: [0xab; 32],
        tx_type: 0,
        nonce: 7,
        from: [0x44; 20],
        to: Some([0x55; 20]),
        value: vec![1],
        gas_limit: 21_000,
        gas_price: Some(vec![1]),
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
        max_fee_per_blob_gas: None,
        input: vec![0xaa],
        access_list: None,
        blob_versioned_hashes: None,
        authorization_list: None,
        v_or_y_parity: Some(27),
        r: Some([0x02; 32]),
        s: Some([0x03; 32]),
        chain_id: None,
        source_hash: None,
        mint: None,
        is_system_tx: None,
        raw_envelope: None,
    };
    let receipt = ReceiptRow {
        block_number: 0,
        transaction_index: 0,
        transaction_hash: [0xab; 32],
        tx_type: 0,
        status: Some(1),
        post_state: None,
        cumulative_gas_used: 0,
        logs_bloom: bloom,
        gas_used: Some(0),
        contract_address: None,
        effective_gas_price: Some(vec![1]),
        blob_gas_used: None,
        blob_gas_price: None,
        deposit_nonce: None,
        deposit_receipt_version: None,
        l1_fee: None,
        l1_gas_used: None,
        l1_gas_price: None,
        l1_fee_scalar: None,
    };
    let (header_bytes, header_entry) = legacy_parquet::headers::write_headers(&headers).unwrap();
    let (tx_bytes, tx_entry) = legacy_parquet::transactions::write_transactions(&[tx]).unwrap();
    let (receipt_bytes, receipt_entry) =
        legacy_parquet::receipts::write_receipts(&[receipt]).unwrap();
    let (log_bytes, log_entry) = legacy_parquet::logs::write_logs(&logs).unwrap();
    let relic = dir.join("000000");
    std::fs::create_dir_all(&relic).unwrap();
    std::fs::write(relic.join("headers.parquet"), header_bytes).unwrap();
    std::fs::write(relic.join("transactions.parquet"), tx_bytes).unwrap();
    std::fs::write(relic.join("receipts.parquet"), receipt_bytes).unwrap();
    std::fs::write(relic.join("logs.parquet"), log_bytes).unwrap();
    let mut manifest = Manifest::new(
        31337,
        "serve-test",
        0,
        Boundary {
            start_block_hash: Hash32::new(headers[0].block_hash),
            end_block_hash: Hash32::new(headers[8191].block_hash),
            parent_hash_of_start: Hash32::new(headers[0].parent_hash),
        },
    );
    manifest.files = vec![header_entry, tx_entry, receipt_entry, log_entry];
    pact::seal_chain(None, std::slice::from_mut(&mut manifest)).unwrap();
    let path = relic.join("manifest.json");
    std::fs::write(&path, manifest.to_canonical_bytes().unwrap()).unwrap();
    path
}
