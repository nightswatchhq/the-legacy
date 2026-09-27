//! JSON-RPC over one admitted corpus.
//!
//! Block hashes and transaction hashes are resolved through in-memory indexes built at admit
//! time. A hit still reads that relic's table and checks the stored hash. The indexes are not
//! in the manifest.
//! `uncles` is an empty array only when `sha3Uncles` is the empty-list hash. Otherwise it is null:
//! uncle headers are not stored, and an empty array would be a claim we cannot make.
//! A logs range that passes the sealed head is rejected whole. Nothing is truncated.

use alloy_rlp::Header as RlpHeader;
use legacy_format::headers::HeaderRow;
use legacy_format::logs::LogRow;
use legacy_format::receipts::ReceiptRow;
use legacy_format::transactions::TransactionRow;
use legacy_format::withdrawals::WithdrawalRow;
use legacy_format::Table;
use legacy_reader::Corpus;
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};

use crate::clean_files::{self, LocalReport};
use crate::config::{Config, Limits};
use crate::hash_index::{BlockHashIndex, TxHashIndex};
use crate::log_index::LogIndex;

/// Ethereum's empty Merkle Patricia trie root.
const EMPTY_TRIE_ROOT: [u8; 32] = [
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
];

pub struct Snapshot {
    corpus: Option<Corpus>,
    limits: Limits,
    report: Option<LocalReport>,
    logs: Vec<RelicLogs>,
    block_hashes: Vec<RelicBlockHashes>,
    /// `None` when any relic could not be indexed, in which case lookups scan.
    tx_hashes: Option<Vec<RelicTxHashes>>,
}

struct RelicBlockHashes {
    index: BlockHashIndex,
}

struct RelicTxHashes {
    index: TxHashIndex,
}

struct RelicLogs {
    relic: u64,
    index: LogIndex,
}

impl Snapshot {
    pub fn open(config: &Config) -> Result<Self, Box<dyn std::error::Error>> {
        if config.manifests.is_empty() {
            return Ok(Self {
                corpus: None,
                limits: config.limits.clone(),
                report: None,
                logs: Vec::new(),
                block_hashes: Vec::new(),
                tx_hashes: None,
            });
        }
        let corpus = Corpus::open_local(&config.manifests)?;
        let manifests: Vec<_> = corpus.manifests().cloned().collect();
        let report = clean_files::check(&config.manifests, &manifests)?;
        let mut logs = Vec::new();
        for grouped in corpus.grouped_logs()? {
            let index = LogIndex::build(&grouped.rows)
                .map_err(|error| format!("relic {} log index: {error}", grouped.relic))?;
            logs.push(RelicLogs {
                relic: grouped.relic,
                index,
            });
        }
        let spans: Vec<_> = corpus
            .manifests()
            .map(|manifest| {
                (
                    manifest.relic_index(),
                    manifest.block_range.start,
                    manifest.block_range.end,
                )
            })
            .collect();
        let mut block_hashes = Vec::new();
        let mut tx_hashes = Vec::new();
        let mut tx_complete = true;
        for (relic, start, end) in spans {
            let headers = corpus.headers(start..=end)?;
            let block_rows: Vec<_> = headers
                .iter()
                .map(|header| (header.block_hash, header.block_number))
                .collect();
            block_hashes.push(RelicBlockHashes {
                index: BlockHashIndex::build(&block_rows)
                    .map_err(|error| format!("relic {relic} block hash index: {error}"))?,
            });
            match corpus.transactions(start..=end) {
                Ok(transactions) => {
                    let rows: Vec<_> = transactions
                        .iter()
                        .map(|tx| (tx.transaction_hash, tx.block_number, tx.transaction_index))
                        .collect();
                    tx_hashes.push(RelicTxHashes {
                        index: TxHashIndex::build(&rows).map_err(|error| {
                            format!("relic {relic} transaction hash index: {error}")
                        })?,
                    });
                }
                Err(legacy_reader::Error::MissingTable { .. })
                    if headers
                        .iter()
                        .all(|header| header.transactions_root == EMPTY_TRIE_ROOT) =>
                {
                    tx_hashes.push(RelicTxHashes {
                        index: TxHashIndex::build(&[]).map_err(|error| {
                            format!("relic {relic} transaction hash index: {error}")
                        })?,
                    });
                }
                Err(legacy_reader::Error::MissingTable { .. }) => tx_complete = false,
                Err(error) => return Err(error.into()),
            }
        }
        Ok(Self {
            corpus: Some(corpus),
            limits: config.limits.clone(),
            report: Some(report),
            logs,
            block_hashes,
            tx_hashes: tx_complete.then_some(tx_hashes),
        })
    }

    pub fn head(&self) -> Option<u64> {
        self.corpus.as_ref().and_then(Corpus::sealed_head)
    }

    pub fn chain_id(&self) -> Option<u64> {
        self.corpus.as_ref().and_then(Corpus::chain_id)
    }

    pub fn checked_line(&self) -> String {
        let Some(report) = &self.report else {
            return "checked     nothing; no sealed corpus is admitted".into();
        };
        let mut parts = vec![
            "manifest structure",
            "relic linkage",
            "pact chain",
            "file hashes and implemented table codecs",
        ];
        if flag(&status(report, |relic| relic.transactions_root)) {
            parts.push("transaction trie roots");
        }
        if flag(&status(report, |relic| relic.receipts_root)) {
            parts.push("receipt trie roots");
        }
        if flag(&status(report, |relic| relic.withdrawals_root)) {
            parts.push("withdrawal trie roots");
        }
        if flag(&status(report, |relic| relic.era1_accumulator)) {
            parts.push("era1 accumulator");
        }
        format!("checked     {}", parts.join(", "))
    }

    pub fn not_checked_line(&self) -> String {
        let Some(report) = &self.report else {
            return "NOT checked file hashes, trie roots, era1 accumulator, finality, checkpoint anchor".into();
        };
        let mut parts = Vec::new();
        for (name, value) in [
            (
                "transaction trie roots",
                status(report, |relic| relic.transactions_root),
            ),
            (
                "receipt trie roots",
                status(report, |relic| relic.receipts_root),
            ),
            (
                "withdrawal trie roots",
                status(report, |relic| relic.withdrawals_root),
            ),
            (
                "era1 accumulator",
                status(report, |relic| relic.era1_accumulator),
            ),
        ] {
            if !flag(&value) {
                parts.push(format!("{name}: {value}"));
            }
        }
        parts.push("checkpoint anchor: not checked (not implemented)".into());
        parts.push("finality: not checked (not implemented)".into());
        format!("NOT checked {}", parts.join("; "))
    }
}

pub fn parse_error() -> Value {
    failure(Value::Null, -32700, "parse error", None)
}

pub fn dispatch(snapshot: &Snapshot, value: Value) -> Value {
    if let Some(batch) = value.as_array() {
        if batch.is_empty() {
            return failure(Value::Null, -32600, "invalid request", None);
        }
        if batch.len() > snapshot.limits.batch_max {
            return failure(
                Value::Null,
                -32005,
                "the-legacy: batch exceeds batch_max",
                Some(json!({
                    "reason": "batch_too_large",
                    "limit": snapshot.limits.batch_max,
                })),
            );
        }
        return Value::Array(
            batch
                .iter()
                .filter(|item| item.get("id").is_some())
                .map(|item| one(snapshot, item))
                .collect(),
        );
    }
    if value.get("method").is_some() && value.get("id").is_none() {
        return Value::Null;
    }
    one(snapshot, &value)
}

fn one(snapshot: &Snapshot, request: &Value) -> Value {
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let Some(method) = request.get("method").and_then(Value::as_str) else {
        return failure(id, -32600, "invalid request", None);
    };
    let params = request.get("params").cloned().unwrap_or(json!([]));
    match call(snapshot, method, &params) {
        Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
        Err(error) => failure(id, error.code, &error.message, error.data),
    }
}

struct RpcError {
    code: i64,
    message: String,
    data: Option<Value>,
}

fn call(snapshot: &Snapshot, method: &str, params: &Value) -> Result<Value, RpcError> {
    match method {
        "eth_chainId" => snapshot
            .chain_id()
            .map(hex_u64)
            .map(Value::String)
            .ok_or_else(unavailable),
        "eth_blockNumber" => snapshot
            .head()
            .map(hex_u64)
            .map(Value::String)
            .ok_or_else(unavailable),
        "eth_syncing" => {
            snapshot.head().ok_or_else(unavailable)?;
            Ok(Value::Bool(false))
        }
        "web3_clientVersion" => Ok(Value::String(format!("solo/{}", env!("CARGO_PKG_VERSION")))),
        "net_version" => snapshot
            .chain_id()
            .map(|id| Value::String(id.to_string()))
            .ok_or_else(unavailable),
        "legacy_capabilities" => Ok(capabilities(snapshot)),
        "eth_getBlockByNumber" => get_block_by_number(snapshot, params),
        "eth_getBlockByHash" => get_block_by_hash(snapshot, params),
        "eth_getBlockTransactionCountByNumber" => transaction_count_by_number(snapshot, params),
        "eth_getBlockTransactionCountByHash" => transaction_count_by_hash(snapshot, params),
        "eth_getTransactionByHash" => transaction_by_hash(snapshot, params),
        "eth_getTransactionByBlockNumberAndIndex" => transaction_by_number_index(snapshot, params),
        "eth_getTransactionByBlockHashAndIndex" => transaction_by_hash_index(snapshot, params),
        "eth_getTransactionReceipt" => receipt_by_hash(snapshot, params),
        "eth_getBlockReceipts" => block_receipts(snapshot, params),
        "eth_getLogs" => get_logs(snapshot, params),
        "eth_call"
        | "eth_estimateGas"
        | "eth_getBalance"
        | "eth_getCode"
        | "eth_getStorageAt"
        | "eth_getTransactionCount"
        | "debug_traceCall" => Err(state(method)),
        "eth_sendRawTransaction"
        | "eth_feeHistory"
        | "eth_gasPrice"
        | "eth_maxPriorityFeePerGas" => Err(unsupported(format!(
            "the-legacy: {method} is not served without an upstream"
        ))),
        "eth_newFilter" | "eth_getFilterChanges" | "eth_uninstallFilter" => Err(unsupported(
            "the-legacy: log filters are not implemented; call eth_getLogs".into(),
        )),
        other if other.starts_with("net_") || other.starts_with("web3_") => Err(unsupported(
            format!("the-legacy: {other} is not served without an upstream"),
        )),
        _ => Err(RpcError {
            code: -32601,
            message: "method not found".into(),
            data: None,
        }),
    }
}

fn get_block_by_number(snapshot: &Snapshot, params: &Value) -> Result<Value, RpcError> {
    let (tag, full) = block_params(params)?;
    let number = resolve_tag(snapshot, tag)?;
    block_at(snapshot, number, full)
}

fn get_block_by_hash(snapshot: &Snapshot, params: &Value) -> Result<Value, RpcError> {
    let items = params_array(params, 2)?;
    let hash = parse_hash(
        items[0]
            .as_str()
            .ok_or_else(|| invalid("block hash must be a string"))?,
    )?;
    let full = parse_bool(&items[1])?;
    let Some(header) = find_header_by_hash(snapshot, &hash)? else {
        return Ok(Value::Null);
    };
    encode_block(snapshot, &header, full)
}

fn transaction_count_by_number(snapshot: &Snapshot, params: &Value) -> Result<Value, RpcError> {
    let items = params_array(params, 1)?;
    let tag = items[0]
        .as_str()
        .ok_or_else(|| invalid("block tag must be a string"))?;
    let number = resolve_tag(snapshot, tag)?;
    let header = require_header(snapshot, number)?;
    Ok(Value::String(hex_u64(
        transactions_of(snapshot, &header)?.len() as u64,
    )))
}

fn transaction_count_by_hash(snapshot: &Snapshot, params: &Value) -> Result<Value, RpcError> {
    let items = params_array(params, 1)?;
    let hash = parse_hash(
        items[0]
            .as_str()
            .ok_or_else(|| invalid("block hash must be a string"))?,
    )?;
    let Some(header) = find_header_by_hash(snapshot, &hash)? else {
        return Ok(Value::Null);
    };
    Ok(Value::String(hex_u64(
        transactions_of(snapshot, &header)?.len() as u64,
    )))
}

fn transaction_by_hash(snapshot: &Snapshot, params: &Value) -> Result<Value, RpcError> {
    let items = params_array(params, 1)?;
    let hash = parse_hash(
        items[0]
            .as_str()
            .ok_or_else(|| invalid("transaction hash must be a string"))?,
    )?;
    let Some((header, tx)) = find_transaction(snapshot, &hash)? else {
        return Ok(Value::Null);
    };
    encode_transaction(snapshot, &header, &tx)
}

fn transaction_by_number_index(snapshot: &Snapshot, params: &Value) -> Result<Value, RpcError> {
    let items = params_array(params, 2)?;
    let tag = items[0]
        .as_str()
        .ok_or_else(|| invalid("block tag must be a string"))?;
    let index = parse_u64(
        items[1]
            .as_str()
            .ok_or_else(|| invalid("index must be a quantity"))?,
    )?;
    let number = resolve_tag(snapshot, tag)?;
    transaction_at_index(snapshot, number, index)
}

fn transaction_by_hash_index(snapshot: &Snapshot, params: &Value) -> Result<Value, RpcError> {
    let items = params_array(params, 2)?;
    let hash = parse_hash(
        items[0]
            .as_str()
            .ok_or_else(|| invalid("block hash must be a string"))?,
    )?;
    let index = parse_u64(
        items[1]
            .as_str()
            .ok_or_else(|| invalid("index must be a quantity"))?,
    )?;
    let Some(header) = find_header_by_hash(snapshot, &hash)? else {
        return Ok(Value::Null);
    };
    transaction_at_index(snapshot, header.block_number, index)
}

fn receipt_by_hash(snapshot: &Snapshot, params: &Value) -> Result<Value, RpcError> {
    let items = params_array(params, 1)?;
    let hash = parse_hash(
        items[0]
            .as_str()
            .ok_or_else(|| invalid("transaction hash must be a string"))?,
    )?;
    let Some((header, tx)) = find_transaction(snapshot, &hash)? else {
        return Ok(Value::Null);
    };
    let Some(receipt) = receipt_of(snapshot, &tx)? else {
        return Ok(Value::Null);
    };
    let logs = logs_of(snapshot, header.block_number)?
        .into_iter()
        .filter(|log| log.transaction_index == tx.transaction_index)
        .collect::<Vec<_>>();
    encode_receipt(&header, &tx, &receipt, &logs)
}

fn block_receipts(snapshot: &Snapshot, params: &Value) -> Result<Value, RpcError> {
    let items = params_array(params, 1)?;
    let tag = items[0]
        .as_str()
        .ok_or_else(|| invalid("block tag must be a string"))?;
    let number = resolve_tag(snapshot, tag)?;
    let header = require_header(snapshot, number)?;
    let transactions = transactions_of(snapshot, &header)?;
    let receipts = receipts_of(snapshot, &header)?;
    let logs = if receipts.is_empty() {
        Vec::new()
    } else {
        logs_of(snapshot, number)?
    };
    let mut out = Vec::with_capacity(receipts.len());
    for receipt in &receipts {
        let Some(tx) = transactions
            .iter()
            .find(|tx| tx.transaction_index == receipt.transaction_index)
        else {
            return Err(failed(format!(
                "the-legacy: receipt {} in block {number} has no transaction",
                receipt.transaction_index
            )));
        };
        let own: Vec<_> = logs
            .iter()
            .filter(|log| log.transaction_index == receipt.transaction_index)
            .cloned()
            .collect();
        out.push(encode_receipt(&header, tx, receipt, &own)?);
    }
    Ok(Value::Array(out))
}

fn get_logs(snapshot: &Snapshot, params: &Value) -> Result<Value, RpcError> {
    let Some(query) = log_query(snapshot, params)? else {
        return Ok(json!([]));
    };
    let headers = rows(snapshot.corpus()?.headers(query.from..=query.to))?;
    let mut by_block = std::collections::BTreeMap::new();
    for header in headers {
        by_block.insert(header.block_number, header.block_hash);
    }
    let mut matched = Vec::new();
    for relic in snapshot.corpus()?.manifests() {
        if relic.block_range.end < query.from || relic.block_range.start > query.to {
            continue;
        }
        let Some(index) = snapshot
            .logs
            .iter()
            .find(|index| index.relic == relic.relic_index())
        else {
            return Err(failed(format!(
                "the-legacy: logs table is not in relic {}",
                relic.relic_index()
            )));
        };
        let candidates = index.index.candidates(
            query.from,
            query.to,
            query.addresses.as_deref(),
            &query.topics,
        );
        if candidates.is_empty() {
            continue;
        }
        let decoded = snapshot
            .corpus()?
            .logs_in_groups(index.relic, candidates.groups())
            .map_err(reader)?;
        for row in decoded {
            if !candidates.contains_row(row.row) || !log_matches(&row.log, &query) {
                continue;
            }
            let Some(hash) = by_block.get(&row.log.block_number) else {
                return Err(failed(format!(
                    "the-legacy: log in block {} has no header in the admitted corpus",
                    row.log.block_number
                )));
            };
            matched.push(encode_log(&row.log, hash));
            if matched.len() > snapshot.limits.getlogs_max_results as usize {
                return Err(limit(
                    "the-legacy: eth_getLogs result exceeds getlogs_max_results",
                    json!({
                        "reason": "too_many_results",
                        "limit": snapshot.limits.getlogs_max_results,
                        "sealed_head": snapshot.head(),
                    }),
                ));
            }
        }
    }
    Ok(Value::Array(matched))
}

struct LogQuery {
    from: u64,
    to: u64,
    addresses: Option<Vec<[u8; 20]>>,
    /// `None` at a position is a wildcard. An empty outer list filters nothing.
    topics: Vec<Option<Vec<[u8; 32]>>>,
}

fn log_query(snapshot: &Snapshot, params: &Value) -> Result<Option<LogQuery>, RpcError> {
    let head = snapshot.head().ok_or_else(unavailable)?;
    let empty = Value::Object(serde_json::Map::new());
    let filter = match params.as_array().map(Vec::as_slice) {
        None => return Err(invalid("params must be an array")),
        Some([]) => &empty,
        Some([filter]) => filter,
        Some(_) => return Err(invalid("eth_getLogs takes one filter")),
    };
    let object = filter
        .as_object()
        .ok_or_else(|| invalid("log filter must be an object"))?;
    if object.contains_key("blockHash")
        && (object.contains_key("fromBlock") || object.contains_key("toBlock"))
    {
        return Err(invalid(
            "blockHash cannot be combined with fromBlock or toBlock",
        ));
    }
    let (from, to) = if let Some(hash) = object.get("blockHash") {
        let hash = parse_hash(
            hash.as_str()
                .ok_or_else(|| invalid("blockHash must be a string"))?,
        )?;
        let Some(header) = find_header_by_hash(snapshot, &hash)? else {
            return Ok(None);
        };
        (header.block_number, header.block_number)
    } else {
        let from = match object.get("fromBlock") {
            Some(value) => resolve_tag(
                snapshot,
                value
                    .as_str()
                    .ok_or_else(|| invalid("fromBlock must be a string"))?,
            )?,
            None => head,
        };
        let to = match object.get("toBlock") {
            Some(value) => resolve_tag(
                snapshot,
                value
                    .as_str()
                    .ok_or_else(|| invalid("toBlock must be a string"))?,
            )?,
            None => head,
        };
        (from, to)
    };
    check_range(head, from, to, snapshot.limits.getlogs_max_blocks)?;
    let addresses = match object.get("address") {
        None => None,
        Some(Value::String(text)) => Some(vec![parse_address(text.as_str())?]),
        Some(Value::Array(values)) => Some(
            values
                .iter()
                .map(|value| {
                    parse_address(
                        value
                            .as_str()
                            .ok_or_else(|| invalid("address must be a string"))?,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?,
        ),
        Some(_) => return Err(invalid("address must be a string or an array")),
    };
    let topics = match object.get("topics") {
        None => Vec::new(),
        Some(Value::Array(values)) => {
            if values.len() > 4 {
                return Err(invalid("a log filter has at most four topic positions"));
            }
            values
                .iter()
                .map(parse_topic_position)
                .collect::<Result<Vec<_>, _>>()?
        }
        Some(_) => return Err(invalid("topics must be an array")),
    };
    Ok(Some(LogQuery {
        from,
        to,
        addresses,
        topics,
    }))
}

fn parse_topic_position(value: &Value) -> Result<Option<Vec<[u8; 32]>>, RpcError> {
    match value {
        Value::Null => Ok(None),
        Value::String(text) => Ok(Some(vec![parse_hash(text)?])),
        Value::Array(values) => Ok(Some(
            values
                .iter()
                .map(|item| {
                    parse_hash(
                        item.as_str()
                            .ok_or_else(|| invalid("topic must be a string"))?,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?,
        )),
        _ => Err(invalid(
            "topic position must be null, a hash, or an array of hashes",
        )),
    }
}

fn log_matches(log: &LogRow, query: &LogQuery) -> bool {
    if let Some(addresses) = &query.addresses {
        if !addresses.iter().any(|address| address == &log.address) {
            return false;
        }
    }
    for (index, position) in query.topics.iter().enumerate() {
        let Some(allowed) = position else {
            continue;
        };
        let Some(topic) = log.topics.get(index) else {
            return false;
        };
        if !allowed.iter().any(|candidate| candidate == topic) {
            return false;
        }
    }
    true
}

fn check_range(head: u64, from: u64, to: u64, max_blocks: u64) -> Result<(), RpcError> {
    if to < from {
        return Err(invalid("fromBlock is after toBlock"));
    }
    if from > head || to > head {
        return Err(above_head(head));
    }
    let span = to - from + 1;
    if span > max_blocks {
        return Err(limit(
            "the-legacy: eth_getLogs range exceeds getlogs_max_blocks",
            json!({
                "reason": "too_many_blocks",
                "limit": max_blocks,
                "sealed_head": head,
            }),
        ));
    }
    Ok(())
}

fn block_at(snapshot: &Snapshot, number: u64, full: bool) -> Result<Value, RpcError> {
    let Some(header) = header_at(snapshot, number)? else {
        return Ok(Value::Null);
    };
    encode_block(snapshot, &header, full)
}

fn transaction_at_index(snapshot: &Snapshot, number: u64, index: u64) -> Result<Value, RpcError> {
    let Some(header) = header_at(snapshot, number)? else {
        return Ok(Value::Null);
    };
    let Some(index) = u32::try_from(index).ok() else {
        return Ok(Value::Null);
    };
    let Some(tx) = transactions_of(snapshot, &header)?
        .into_iter()
        .find(|tx| tx.transaction_index == index)
    else {
        return Ok(Value::Null);
    };
    encode_transaction(snapshot, &header, &tx)
}

fn encode_block(snapshot: &Snapshot, header: &HeaderRow, full: bool) -> Result<Value, RpcError> {
    let transactions = transactions_of(snapshot, header)?;
    let tx_json = if full {
        let mut encoded = Vec::with_capacity(transactions.len());
        for tx in &transactions {
            encoded.push(encode_transaction(snapshot, header, tx)?);
        }
        Value::Array(encoded)
    } else {
        Value::Array(
            transactions
                .iter()
                .map(|tx| Value::String(hex_fixed(&tx.transaction_hash)))
                .collect(),
        )
    };
    let mut block = json!({
        "number": hex_u64(header.block_number),
        "hash": hex_fixed(&header.block_hash),
        "parentHash": hex_fixed(&header.parent_hash),
        "sha3Uncles": hex_fixed(&header.ommers_hash),
        "miner": hex_fixed(&header.beneficiary),
        "stateRoot": hex_fixed(&header.state_root),
        "transactionsRoot": hex_fixed(&header.transactions_root),
        "receiptsRoot": hex_fixed(&header.receipts_root),
        "logsBloom": hex_fixed(&header.logs_bloom),
        "difficulty": hex_uint(&header.difficulty),
        "gasLimit": hex_u64(header.gas_limit),
        "gasUsed": hex_u64(header.gas_used),
        "timestamp": hex_u64(header.timestamp),
        "extraData": hex_fixed(&header.extra_data),
        "mixHash": hex_fixed(&header.mix_hash),
        "nonce": hex_fixed(&header.nonce),
        "transactions": tx_json,
        "uncles": uncles(&header.ommers_hash),
    });
    let object = block.as_object_mut().expect("object");
    if let Some(value) = &header.base_fee_per_gas {
        object.insert("baseFeePerGas".into(), Value::String(hex_uint(value)));
    }
    if let Some(root) = header.withdrawals_root {
        object.insert("withdrawalsRoot".into(), Value::String(hex_fixed(&root)));
        object.insert(
            "withdrawals".into(),
            Value::Array(withdrawal_json(&withdrawals_of(snapshot, header)?)?),
        );
    }
    if let Some(value) = header.blob_gas_used {
        object.insert("blobGasUsed".into(), Value::String(hex_u64(value)));
    }
    if let Some(value) = header.excess_blob_gas {
        object.insert("excessBlobGas".into(), Value::String(hex_u64(value)));
    }
    if let Some(root) = header.parent_beacon_block_root {
        object.insert(
            "parentBeaconBlockRoot".into(),
            Value::String(hex_fixed(&root)),
        );
    }
    if let Some(root) = header.requests_hash {
        object.insert("requestsHash".into(), Value::String(hex_fixed(&root)));
    }
    if let Some(value) = &header.total_difficulty {
        object.insert("totalDifficulty".into(), Value::String(hex_uint(value)));
    }
    Ok(block)
}

fn uncles(ommers_hash: &[u8; 32]) -> Value {
    if *ommers_hash == empty_ommers_hash() {
        json!([])
    } else {
        Value::Null
    }
}

fn empty_ommers_hash() -> [u8; 32] {
    Keccak256::digest([0xc0]).into()
}

fn encode_transaction(
    snapshot: &Snapshot,
    header: &HeaderRow,
    tx: &TransactionRow,
) -> Result<Value, RpcError> {
    let mut object = serde_json::Map::new();
    object.insert("hash".into(), json!(hex_fixed(&tx.transaction_hash)));
    object.insert("nonce".into(), json!(hex_u64(tx.nonce)));
    object.insert("blockHash".into(), json!(hex_fixed(&header.block_hash)));
    object.insert("blockNumber".into(), json!(hex_u64(header.block_number)));
    object.insert(
        "transactionIndex".into(),
        json!(hex_u64(u64::from(tx.transaction_index))),
    );
    object.insert("from".into(), json!(hex_fixed(&tx.from)));
    object.insert(
        "to".into(),
        match tx.to {
            Some(address) => Value::String(hex_fixed(&address)),
            None => Value::Null,
        },
    );
    object.insert("value".into(), json!(hex_uint(&tx.value)));
    object.insert("gas".into(), json!(hex_u64(tx.gas_limit)));
    object.insert("input".into(), json!(hex_fixed(&tx.input)));
    object.insert("type".into(), json!(hex_u64(u64::from(tx.tx_type))));
    if let Some(price) = gas_price(snapshot, tx)? {
        object.insert("gasPrice".into(), Value::String(price));
    }
    if let Some(value) = &tx.max_fee_per_gas {
        object.insert("maxFeePerGas".into(), Value::String(hex_uint(value)));
    }
    if let Some(value) = &tx.max_priority_fee_per_gas {
        object.insert(
            "maxPriorityFeePerGas".into(),
            Value::String(hex_uint(value)),
        );
    }
    if let Some(value) = &tx.max_fee_per_blob_gas {
        object.insert("maxFeePerBlobGas".into(), Value::String(hex_uint(value)));
    }
    if let Some(v) = transaction_v(tx) {
        object.insert("v".into(), Value::String(v));
    }
    if tx.tx_type != 0 {
        if let Some(parity) = tx.v_or_y_parity {
            object.insert("yParity".into(), Value::String(hex_u64(u64::from(parity))));
        }
    }
    if let Some(r) = tx.r {
        object.insert("r".into(), Value::String(hex_fixed(&r)));
    }
    if let Some(s) = tx.s {
        object.insert("s".into(), Value::String(hex_fixed(&s)));
    }
    if let Some(chain_id) = tx.chain_id {
        object.insert("chainId".into(), Value::String(hex_u64(chain_id)));
    }
    if let Some(list) = &tx.access_list {
        object.insert("accessList".into(), access_list(list)?);
    }
    Ok(Value::Object(object))
}

fn gas_price(snapshot: &Snapshot, tx: &TransactionRow) -> Result<Option<String>, RpcError> {
    if let Some(price) = &tx.gas_price {
        return Ok(Some(hex_uint(price)));
    }
    if tx.tx_type != 2 {
        return Ok(None);
    }
    let Some(receipt) = receipt_of(snapshot, tx)? else {
        return Ok(None);
    };
    Ok(receipt
        .effective_gas_price
        .as_ref()
        .map(|price| hex_uint(price)))
}

fn transaction_v(tx: &TransactionRow) -> Option<String> {
    let parity = tx.v_or_y_parity?;
    if tx.tx_type == 0 {
        return Some(match tx.chain_id {
            None => hex_u64(u64::from(parity)),
            Some(chain_id) => hex_u128(u128::from(chain_id) * 2 + 35 + u128::from(parity)),
        });
    }
    Some(hex_u64(u64::from(parity)))
}

fn encode_receipt(
    header: &HeaderRow,
    tx: &TransactionRow,
    receipt: &ReceiptRow,
    logs: &[LogRow],
) -> Result<Value, RpcError> {
    let mut object = serde_json::Map::new();
    object.insert(
        "transactionHash".into(),
        json!(hex_fixed(&receipt.transaction_hash)),
    );
    object.insert(
        "transactionIndex".into(),
        json!(hex_u64(u64::from(receipt.transaction_index))),
    );
    object.insert("blockHash".into(), json!(hex_fixed(&header.block_hash)));
    object.insert("blockNumber".into(), json!(hex_u64(header.block_number)));
    object.insert("from".into(), json!(hex_fixed(&tx.from)));
    object.insert(
        "to".into(),
        match tx.to {
            Some(address) => Value::String(hex_fixed(&address)),
            None => Value::Null,
        },
    );
    object.insert(
        "cumulativeGasUsed".into(),
        json!(hex_u64(receipt.cumulative_gas_used)),
    );
    object.insert("logsBloom".into(), json!(hex_fixed(&receipt.logs_bloom)));
    object.insert(
        "logs".into(),
        Value::Array(
            logs.iter()
                .map(|log| encode_log(log, &header.block_hash))
                .collect(),
        ),
    );
    object.insert("type".into(), json!(hex_u64(u64::from(receipt.tx_type))));
    object.insert(
        "contractAddress".into(),
        match receipt.contract_address {
            Some(address) => Value::String(hex_fixed(&address)),
            None => Value::Null,
        },
    );
    if let Some(status) = receipt.status {
        object.insert("status".into(), Value::String(hex_u64(u64::from(status))));
    }
    if let Some(root) = receipt.post_state {
        object.insert("root".into(), Value::String(hex_fixed(&root)));
    }
    if let Some(gas) = receipt.gas_used {
        object.insert("gasUsed".into(), Value::String(hex_u64(gas)));
    }
    if let Some(price) = &receipt.effective_gas_price {
        object.insert("effectiveGasPrice".into(), Value::String(hex_uint(price)));
    }
    Ok(Value::Object(object))
}

fn encode_log(log: &LogRow, block_hash: &[u8; 32]) -> Value {
    json!({
        "removed": false,
        "logIndex": hex_u64(u64::from(log.log_index)),
        "transactionIndex": hex_u64(u64::from(log.transaction_index)),
        "transactionHash": hex_fixed(&log.transaction_hash),
        "blockHash": hex_fixed(block_hash),
        "blockNumber": hex_u64(log.block_number),
        "address": hex_fixed(&log.address),
        "data": hex_fixed(&log.data),
        "topics": log.topics.iter().map(|topic| hex_fixed(topic)).collect::<Vec<_>>(),
    })
}

fn withdrawal_json(rows: &[WithdrawalRow]) -> Result<Vec<Value>, RpcError> {
    Ok(rows
        .iter()
        .map(|row| {
            json!({
                "index": hex_u64(row.index),
                "validatorIndex": hex_u64(row.validator_index),
                "address": hex_fixed(&row.address),
                "amount": hex_u64(row.amount),
            })
        })
        .collect())
}

fn capabilities(snapshot: &Snapshot) -> Value {
    let cleaning = |name: fn(&clean_files::RelicReport) -> &'static str| {
        snapshot
            .report
            .as_ref()
            .is_some_and(|report| flag(&status(report, name)))
    };
    json!({
        "chain_id": snapshot.chain_id(),
        "spec_version": snapshot.corpus.as_ref().and_then(|corpus| corpus.manifests().next().map(|manifest| manifest.spec_version)),
        "sealed_head": snapshot.head(),
        "head_pact_root": snapshot.corpus.as_ref().and_then(|corpus| corpus.manifests().last().map(|manifest| format!("0x{}", manifest.pact_root.to_hex()))),
        "mode": "sealed-only",
        "limits": {
            "getlogs_max_blocks": snapshot.limits.getlogs_max_blocks,
            "getlogs_max_results": snapshot.limits.getlogs_max_results,
            "batch_max": snapshot.limits.batch_max,
        },
        "tables": guaranteed_tables(snapshot),
        "sidecars": sidecars(snapshot),
        "cleaning": {
            "manifest_structure": snapshot.report.is_some(),
            "relic_linkage": snapshot.report.is_some(),
            "pact_chain": snapshot.report.is_some(),
            "file_hashes": snapshot.report.is_some(),
            "transactions_root": cleaning(|relic| relic.transactions_root),
            "receipts_root": cleaning(|relic| relic.receipts_root),
            "withdrawals_root": cleaning(|relic| relic.withdrawals_root),
            "checkpoint_anchor": false,
        },
        "mirrors": [],
    })
}

fn sidecars(snapshot: &Snapshot) -> Vec<&'static str> {
    let mut names = log_sidecars(snapshot);
    if !snapshot.block_hashes.is_empty() {
        names.push("blockhash");
    }
    if snapshot.tx_hashes.is_some() {
        names.push("txhash");
    }
    names.sort_unstable();
    names
}

fn log_sidecars(snapshot: &Snapshot) -> Vec<&'static str> {
    let Some(corpus) = &snapshot.corpus else {
        return Vec::new();
    };
    let manifests: Vec<_> = corpus.manifests().collect();
    if manifests.is_empty() {
        return Vec::new();
    }
    let covered = manifests.iter().all(|manifest| {
        manifest.files.iter().any(|file| file.table == Table::Logs)
            && snapshot
                .logs
                .iter()
                .any(|index| index.relic == manifest.relic_index())
    });
    if covered {
        vec!["logs.addr", "logs.topics"]
    } else {
        Vec::new()
    }
}

fn guaranteed_tables(snapshot: &Snapshot) -> Vec<&'static str> {
    let Some(corpus) = &snapshot.corpus else {
        return Vec::new();
    };
    let manifests: Vec<_> = corpus.manifests().collect();
    if manifests.is_empty() {
        return Vec::new();
    }
    [
        Table::Headers,
        Table::Transactions,
        Table::Receipts,
        Table::Logs,
        Table::Withdrawals,
        Table::Traces,
    ]
    .into_iter()
    .filter(|table| {
        manifests
            .iter()
            .all(|manifest| manifest.files.iter().any(|file| file.table == *table))
    })
    .map(table_name)
    .collect()
}

fn table_name(table: Table) -> &'static str {
    match table {
        Table::Headers => "headers",
        Table::Transactions => "transactions",
        Table::Receipts => "receipts",
        Table::Logs => "logs",
        Table::Withdrawals => "withdrawals",
        Table::Traces => "traces",
    }
}

fn status(report: &LocalReport, field: fn(&clean_files::RelicReport) -> &'static str) -> String {
    if report.relics.is_empty() {
        return "not checked (no relic data read)".into();
    }
    let first = field(&report.relics[0]);
    if report.relics.iter().all(|relic| field(relic) == first) {
        first.to_string()
    } else {
        clean_files::summarize(&report.relics, field).to_string()
    }
}

fn flag(status: &str) -> bool {
    status == "pass"
}

fn resolve_tag(snapshot: &Snapshot, tag: &str) -> Result<u64, RpcError> {
    let head = snapshot.head().ok_or_else(unavailable)?;
    match tag {
        "latest" | "safe" | "finalized" => Ok(head),
        "earliest" => Ok(0),
        "pending" => Err(unsupported("the-legacy: pending is unsupported".into())),
        quantity => {
            let number = parse_u64(quantity)?;
            if number > head {
                return Err(above_head(head));
            }
            Ok(number)
        }
    }
}

fn block_params(params: &Value) -> Result<(&str, bool), RpcError> {
    let items = params_array(params, 2)?;
    let tag = items[0]
        .as_str()
        .ok_or_else(|| invalid("block tag must be a string"))?;
    Ok((tag, parse_bool(&items[1])?))
}

fn params_array(params: &Value, count: usize) -> Result<&Vec<Value>, RpcError> {
    let Some(items) = params.as_array() else {
        return Err(invalid("params must be an array"));
    };
    if items.len() != count {
        return Err(invalid(format!(
            "expected {count} parameters, found {}",
            items.len()
        )));
    }
    Ok(items)
}

fn parse_bool(value: &Value) -> Result<bool, RpcError> {
    value.as_bool().ok_or_else(|| invalid("expected a boolean"))
}

fn parse_u64(text: &str) -> Result<u64, RpcError> {
    let Some(digits) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) else {
        return Err(invalid(format!("{text} is not a hex quantity")));
    };
    if digits.is_empty() {
        return Err(invalid("empty hex quantity"));
    }
    u64::from_str_radix(digits, 16).map_err(|_| invalid(format!("{text} is not a u64 quantity")))
}

fn parse_hash(text: &str) -> Result<[u8; 32], RpcError> {
    parse_fixed(text, "hash")
}

fn parse_address(text: &str) -> Result<[u8; 20], RpcError> {
    parse_fixed(text, "address")
}

fn parse_fixed<const N: usize>(text: &str, kind: &str) -> Result<[u8; N], RpcError> {
    let Some(digits) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) else {
        return Err(invalid(format!("{kind} must be hex")));
    };
    let bytes = hex::decode(digits).map_err(|_| invalid(format!("{kind} is not hex")))?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| invalid(format!("{kind} has {} bytes", bytes.len())))
}

fn hex_u64(value: u64) -> String {
    if value == 0 {
        "0x0".into()
    } else {
        format!("0x{value:x}")
    }
}

fn hex_u128(value: u128) -> String {
    if value == 0 {
        "0x0".into()
    } else {
        format!("0x{value:x}")
    }
}

fn hex_fixed(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn hex_uint(bytes: &[u8]) -> String {
    match bytes.iter().position(|byte| *byte != 0) {
        None => "0x0".into(),
        Some(start) => format!("0x{}", hex::encode(&bytes[start..])),
    }
}

fn header_at(snapshot: &Snapshot, number: u64) -> Result<Option<HeaderRow>, RpcError> {
    let rows = rows(snapshot.corpus()?.headers(number..=number))?;
    Ok(rows.into_iter().next())
}

fn require_header(snapshot: &Snapshot, number: u64) -> Result<HeaderRow, RpcError> {
    header_at(snapshot, number)?
        .ok_or_else(|| failed(format!("the-legacy: block {number} has no header")))
}

fn find_header_by_hash(
    snapshot: &Snapshot,
    hash: &[u8; 32],
) -> Result<Option<HeaderRow>, RpcError> {
    snapshot.head().ok_or_else(unavailable)?;
    for index in &snapshot.block_hashes {
        let Some(number) = index.index.find(hash) else {
            continue;
        };
        let Some(header) = header_at(snapshot, number)? else {
            return Err(failed(
                "the-legacy: block hash index pointed at a missing header",
            ));
        };
        if header.block_hash != *hash {
            return Err(failed(
                "the-legacy: block hash index pointed at a different header",
            ));
        }
        return Ok(Some(header));
    }
    Ok(None)
}

fn find_transaction(
    snapshot: &Snapshot,
    hash: &[u8; 32],
) -> Result<Option<(HeaderRow, TransactionRow)>, RpcError> {
    snapshot.head().ok_or_else(unavailable)?;
    let Some(indexes) = &snapshot.tx_hashes else {
        return find_transaction_scan(snapshot, hash);
    };
    for index in indexes {
        let Some((block, tx_index)) = index.index.find(hash) else {
            continue;
        };
        let header = require_header(snapshot, block)?;
        let Some(tx) = transactions_of(snapshot, &header)?
            .into_iter()
            .find(|tx| tx.transaction_index == tx_index)
        else {
            return Err(failed(
                "the-legacy: transaction hash index pointed at a missing transaction",
            ));
        };
        if tx.transaction_hash != *hash {
            return Err(failed(
                "the-legacy: transaction hash index pointed at a different transaction",
            ));
        }
        return Ok(Some((header, tx)));
    }
    Ok(None)
}

fn find_transaction_scan(
    snapshot: &Snapshot,
    hash: &[u8; 32],
) -> Result<Option<(HeaderRow, TransactionRow)>, RpcError> {
    let head = snapshot.head().ok_or_else(unavailable)?;
    let transactions = match snapshot.corpus()?.transactions(0..=head) {
        Ok(rows) => rows,
        Err(legacy_reader::Error::MissingTable { .. }) => {
            return Err(failed(
                "the-legacy: transactions table is not in the admitted corpus",
            ))
        }
        Err(error) => return Err(reader(error)),
    };
    let Some(tx) = transactions
        .into_iter()
        .find(|tx| tx.transaction_hash == *hash)
    else {
        return Ok(None);
    };
    let header = require_header(snapshot, tx.block_number)?;
    Ok(Some((header, tx)))
}

fn transactions_of(
    snapshot: &Snapshot,
    header: &HeaderRow,
) -> Result<Vec<TransactionRow>, RpcError> {
    table_rows(
        snapshot
            .corpus()?
            .transactions(header.block_number..=header.block_number),
        header.transactions_root == EMPTY_TRIE_ROOT,
    )
    .map(|rows| {
        rows.into_iter()
            .filter(|tx| tx.block_number == header.block_number)
            .collect()
    })
}

fn receipts_of(snapshot: &Snapshot, header: &HeaderRow) -> Result<Vec<ReceiptRow>, RpcError> {
    table_rows(
        snapshot
            .corpus()?
            .receipts(header.block_number..=header.block_number),
        header.receipts_root == EMPTY_TRIE_ROOT,
    )
    .map(|rows| {
        rows.into_iter()
            .filter(|receipt| receipt.block_number == header.block_number)
            .collect()
    })
}

fn logs_of(snapshot: &Snapshot, block: u64) -> Result<Vec<LogRow>, RpcError> {
    rows(snapshot.corpus()?.logs(block..=block)).map(|rows| {
        rows.into_iter()
            .filter(|log| log.block_number == block)
            .collect()
    })
}

fn withdrawals_of(snapshot: &Snapshot, header: &HeaderRow) -> Result<Vec<WithdrawalRow>, RpcError> {
    // A header that carries a withdrawals root has a list, possibly empty. A missing table is not
    // that empty list.
    let _ = header;
    rows(
        snapshot
            .corpus()?
            .withdrawals(header.block_number..=header.block_number),
    )
    .map(|rows| {
        rows.into_iter()
            .filter(|row| row.block_number == header.block_number)
            .collect()
    })
}

fn receipt_of(snapshot: &Snapshot, tx: &TransactionRow) -> Result<Option<ReceiptRow>, RpcError> {
    let header = require_header(snapshot, tx.block_number)?;
    Ok(receipts_of(snapshot, &header)?
        .into_iter()
        .find(|receipt| receipt.transaction_index == tx.transaction_index))
}

fn table_rows<T>(
    result: Result<Vec<T>, legacy_reader::Error>,
    empty_root: bool,
) -> Result<Vec<T>, RpcError> {
    match result {
        Ok(rows) => Ok(rows),
        Err(legacy_reader::Error::MissingTable { .. }) if empty_root => Ok(Vec::new()),
        Err(error) => Err(reader(error)),
    }
}

fn rows<T>(result: Result<Vec<T>, legacy_reader::Error>) -> Result<Vec<T>, RpcError> {
    result.map_err(reader)
}

fn access_list(raw: &[u8]) -> Result<Value, RpcError> {
    let mut entries = Vec::new();
    for item in rlp_list(raw)? {
        let fields = rlp_list(item)?;
        if fields.len() != 2 {
            return Err(failed("the-legacy: access list entry is not a pair"));
        }
        let address = rlp_bytes::<20>(fields[0])?;
        let mut keys = Vec::new();
        for key in rlp_list(fields[1])? {
            keys.push(hex_fixed(&rlp_bytes::<32>(key)?));
        }
        entries.push(json!({
            "address": hex_fixed(&address),
            "storageKeys": keys,
        }));
    }
    Ok(Value::Array(entries))
}

fn rlp_list(bytes: &[u8]) -> Result<Vec<&[u8]>, RpcError> {
    let mut rest = bytes;
    match RlpHeader::decode_raw(&mut rest) {
        Ok(alloy_rlp::PayloadView::List(items)) if rest.is_empty() => Ok(items),
        _ => Err(failed("the-legacy: stored access list is not an RLP list")),
    }
}

fn rlp_bytes<const N: usize>(item: &[u8]) -> Result<[u8; N], RpcError> {
    let mut rest = item;
    let payload = RlpHeader::decode_bytes(&mut rest, false)
        .map_err(|_| failed("the-legacy: access list field is not an RLP string"))?;
    if !rest.is_empty() || payload.len() != N {
        return Err(failed("the-legacy: access list field has the wrong width"));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(payload);
    Ok(out)
}

fn unavailable() -> RpcError {
    RpcError {
        code: -32002,
        message: "the-legacy: no sealed corpus is admitted".into(),
        data: None,
    }
}

fn above_head(head: u64) -> RpcError {
    RpcError {
        code: -32005,
        message: format!(
            "the-legacy: block above sealed head {head}; configure an upstream or retry after the next seal"
        ),
        data: Some(json!({"reason": "above_sealed_head", "sealed_head": head})),
    }
}

fn state(method: &str) -> RpcError {
    unsupported(format!(
        "the-legacy: historical state is out of scope; route {method} to an archive node"
    ))
}

fn unsupported(message: String) -> RpcError {
    RpcError {
        code: -32004,
        message,
        data: None,
    }
}

fn invalid(message: impl Into<String>) -> RpcError {
    RpcError {
        code: -32602,
        message: message.into(),
        data: None,
    }
}

fn failed(message: impl Into<String>) -> RpcError {
    RpcError {
        code: -32001,
        message: message.into(),
        data: None,
    }
}

fn limit(message: &str, data: Value) -> RpcError {
    RpcError {
        code: -32005,
        message: message.into(),
        data: Some(data),
    }
}

fn reader(error: legacy_reader::Error) -> RpcError {
    failed(format!("the-legacy: {error}"))
}

fn failure(id: Value, code: i64, message: &str, data: Option<Value>) -> Value {
    let mut error = json!({"code": code, "message": message});
    if let Some(data) = data {
        error
            .as_object_mut()
            .expect("object")
            .insert("data".into(), data);
    }
    json!({"jsonrpc": "2.0", "id": id, "error": error})
}

impl Snapshot {
    fn corpus(&self) -> Result<&Corpus, RpcError> {
        self.corpus.as_ref().ok_or_else(unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_above_the_head_are_not_truncated() {
        let error = check_range(10, 0, 11, 100).unwrap_err();
        assert_eq!(error.code, -32005);
        assert_eq!(error.data.as_ref().unwrap()["reason"], "above_sealed_head");
        assert_eq!(error.data.as_ref().unwrap()["sealed_head"], 10);
    }

    #[test]
    fn wide_ranges_fail_instead_of_returning_a_prefix() {
        let error = check_range(1000, 0, 10, 10).unwrap_err();
        assert_eq!(error.data.unwrap()["reason"], "too_many_blocks");
    }

    #[test]
    fn topic_positions_are_and_of_ors_with_null_wildcards() {
        let log = LogRow {
            block_number: 1,
            transaction_index: 0,
            log_index: 0,
            transaction_hash: [0; 32],
            address: [0x11; 20],
            topics: vec![[0x22; 32], [0x33; 32]],
            data: vec![],
        };
        let query = |topics: Vec<Option<Vec<[u8; 32]>>>| LogQuery {
            from: 0,
            to: 1,
            addresses: Some(vec![[0x11; 20]]),
            topics,
        };
        assert!(log_matches(
            &log,
            &query(vec![None, Some(vec![[0x33; 32]])])
        ));
        assert!(log_matches(
            &log,
            &query(vec![Some(vec![[0x22; 32], [0x44; 32]])])
        ));
        assert!(!log_matches(&log, &query(vec![Some(vec![[0x44; 32]])])));
        assert!(!log_matches(
            &log,
            &query(vec![None, None, Some(vec![[0x55; 32]])])
        ));
    }

    #[test]
    fn eip155_v_uses_a_wide_integer() {
        let tx = sample_tx(Some(1), 0);
        assert_eq!(transaction_v(&tx).unwrap(), "0x25");
        let huge = sample_tx(Some(u64::MAX), 1);
        let v = transaction_v(&huge).unwrap();
        assert_eq!(v, format!("0x{:x}", u128::from(u64::MAX) * 2 + 36));
    }

    #[test]
    fn uncles_are_empty_only_for_the_empty_list_hash() {
        assert_eq!(uncles(&empty_ommers_hash()), json!([]));
        assert_eq!(uncles(&[0xab; 32]), Value::Null);
    }

    fn sample_tx(chain_id: Option<u64>, parity: u8) -> TransactionRow {
        TransactionRow {
            block_number: 0,
            transaction_index: 0,
            transaction_hash: [0; 32],
            tx_type: 0,
            nonce: 0,
            from: [0; 20],
            to: None,
            value: vec![],
            gas_limit: 21_000,
            gas_price: Some(vec![1]),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            max_fee_per_blob_gas: None,
            input: vec![],
            access_list: None,
            blob_versioned_hashes: None,
            authorization_list: None,
            v_or_y_parity: Some(parity),
            r: Some([1; 32]),
            s: Some([1; 32]),
            chain_id,
            source_hash: None,
            mint: None,
            is_system_tx: None,
            raw_envelope: None,
        }
    }
}
