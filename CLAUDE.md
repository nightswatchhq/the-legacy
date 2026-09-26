# the-legacy

A sealed, verifiable history corpus for EVM chains, plus the binary that serves it.
**[RFC-0001](docs/rfcs/0001-the-legacy.md) is the specification. This repository implements it.**
[RFC-0002](docs/rfcs/0002-the-backfill-layer.md) proposes the backfill follow-up; its §8 lists
implementation-linked amendments, not already supported interfaces.

## Ground rules

1. **The RFC is normative.** If the code and RFC-0001 disagree, one of them is a bug; say which
   before changing either. A spec change and the code change that follows it belong in the same PR.
2. **Never overstate verification.** Every report, log line, doc and README row must say what was
   actually checked and what was not. `solo clean` currently checks manifest structure, relic
   linkage and the pact chain by default. `--files` adds local byte integrity, Parquet counts and
   decoded checks for all five core tables, including header coverage and stored links. It
   reconstructs Ethereum header hashes through Prague for chain ID 1 only and checks transaction,
   receipt and log references plus receipt/header blooms where the required tables exist. Chain
   ID 1 also checks receipt/header execution gas accounting. Fees, other derived fields, other
   chain profiles, completeness, execution/fork validity and checkpoint trust remain
   unchecked; consistency is not chain trust.
   This is the single most important rule in the repo: the whole project's
   value is that its claims are true.
3. **Traces are not header-committed.** No cryptographic claim about the traces tier is acceptable
   anywhere - code, comments, docs, marketing. Cross-producer agreement or local re-execution, and
   that is the lot (§6.8, §16).
4. **Relics are immutable.** Nothing rewrites a sealed relic. Schema evolution is additive and
   nullable; a `spec_version` bump applies only to newly sealed relics (§12.5).
5. **Seal only past finality.** A relic covers 8192 blocks and is sealed once its entire range is
   final. Tip handling lives outside relics (§11.2).

## Shape

- `crates/legacy-format` - geometry, canonical JSON (JCS), manifests, the pact chain, the registry.
  Canonical row primitives, headers/transactions/receipts/logs/withdrawals rows and their content hashes
  live here. Ethereum receipt trie-leaf encoding exists for legacy and types 1..=4; trie
  construction and root verification do not.
  No Parquet, no object storage, no JSON-RPC. Shadow and Solo agree on what a relic is by depending
  on this, not by both being careful.
- `crates/legacy-parquet` - Parquet schemas, shared writer profile and codecs for the implemented
  tables, plus verification against manifest file claims. No sealing, consensus validation or
  checkpoint verification.
- `crates/shadow` - the six ingestion sources (§11). All skeleton so far.
- `crates/solo` - serving (§13) and cleaning (§10). Manifest checks and optional local file checks
  exist; serving, trie rebuilding and checkpoint anchoring do not.

## Working

- Rust, no unsafe, comments explain *why* rather than restating the code.
- `cargo fmt --all`, `cargo clippy --all-targets -- -D warnings`, `cargo test`, `cargo deny check`
  all green before a commit. `yatr ci` runs the four.
- The MSRV in `Cargo.toml` is the toolchain that has actually been built and tested on. Lowering it
  needs a green run on the lower toolchain, not optimism.
- No em dashes in prose. Hyphens, or restructure.
- Branches `pete/<short-description>`. Commit messages single-line, no body, no AI attribution.
