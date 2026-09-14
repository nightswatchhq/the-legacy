# the-legacy

A sealed, verifiable history corpus for EVM chains, plus the binary that serves it.
**[RFC-0001](docs/rfcs/0001-the-legacy.md) is the specification. This repository implements it.**

## Ground rules

1. **The RFC is normative.** If the code and RFC-0001 disagree, one of them is a bug; say which
   before changing either. A spec change and the code change that follows it belong in the same PR.
2. **Never overstate verification.** Every report, log line, doc and README row must say what was
   actually checked and what was not. `solo clean` currently checks manifest structure, relic
   linkage and the pact chain, and nothing else - it says so, and it keeps saying so until each
   remaining check is real. This is the single most important rule in the repo: the whole project's
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
  No Parquet, no object storage, no JSON-RPC. Shadow and Solo agree on what a relic is by depending
  on this, not by both being careful.
- `crates/shadow` - the six ingestion sources (§11). All skeleton so far.
- `crates/solo` - serving (§13) and cleaning (§10). Only cleaning's manifest half exists.

## Working

- Rust, no unsafe, comments explain *why* rather than restating the code.
- `cargo fmt --all`, `cargo clippy --all-targets -- -D warnings`, `cargo test`, `cargo deny check`
  all green before a commit. `yatr ci` runs the four.
- The MSRV in `Cargo.toml` is the toolchain that has actually been built and tested on. Lowering it
  needs a green run on the lower toolchain, not optimism.
- No em dashes in prose. Hyphens, or restructure.
- Branches `pete/<short-description>`. Commit messages single-line, no body, no AI attribution.
