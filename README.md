# the-legacy

> **Everything from before, sealed, kept by one small process.**
> An open, verifiable, mirrorable history corpus for EVM chains, and a thin Rust binary that serves
> it.

[![ci](https://github.com/nightswatchhq/the-legacy/actions/workflows/ci.yml/badge.svg)](https://github.com/nightswatchhq/the-legacy/actions/workflows/ci.yml)

EIP-4444 makes historical execution data a second-class citizen of the base protocol at exactly the
moment demand for it is climbing. The existing answers are each half of one: era1 and Portal are
verifiable but not query-friendly; Reth static files and Erigon snapshots are client-internal
formats rather than specs; cryo writes excellent Parquet with no manifest, verification or serving
story; HyperSync is closed and SQD is token-gated.

The Legacy is the spec for the missing half, plus the code to produce and serve it. Finalized
history - headers, transactions, receipts, logs, withdrawals, optionally call traces - is sealed
into immutable 8192-block segments called **relics**: plain Apache Parquet plus a canonical
manifest. Manifests chain into a **pact**, one root hash per chain per height, so two mirrors
compare their entire corpus in a single 32-byte exchange and localise any disagreement in O(log n)
requests. Nothing in it privileges the producer: every file is content-addressed, every sidecar is
rebuildable, and **cleaning** rebuilds the transactions, receipts and withdrawals tries and checks
them against the block headers.

**Read [RFC-0001](docs/rfcs/0001-the-legacy.md) first.** It is the specification; this repository is
its implementation.

## Status

Early. The spec is written, the format layer is implemented and tested, and **nothing serves
anything yet.** Precisely:

| | state |
|---|---|
| RFC-0001 | written, Draft |
| Relic geometry, canonical JSON (JCS), manifests, pact chain, registry | implemented, 42 tests |
| `solo clean` (manifest structure, relic linkage, pact chain) | implemented |
| Parquet tables, index sidecars | not started |
| Trie rebuilding, checkpoint anchoring | not started |
| `solo serve`, all six Shadow sources | not started |

`solo clean` says out loud which checks it performed and which it did not, and will keep doing so
until each one is real. A verification report that implies more than it checked is worse than no
report at all.

## Try it

```sh
cargo run -p solo -- relic 20086783
```

```
block       20086783
relic       2451  (002451)
blocks      20078592..=20086783
prefix      legacy/v1/1/relics/002451
```

```sh
cargo run -p shadow -- plan --from 20078592 --to 20090000
```

```
blocks 20078592..=20090000 cover 2 relic(s), 2451..=2452
  002451  blocks 20078592..=20086783  legacy/v1/1/relics/002451
  002452  blocks 20086784..=20094975  legacy/v1/1/relics/002452  (partial: the relic is sealed only once its whole range is past finality)
```

## Layout

```
crates/legacy-format   the executable half of the spec: geometry, JCS, manifests, pact, registry
crates/shadow          the ingesters that transcode chain history into relics
crates/solo            the serving binary, and the cleaning that verifies what you are served
docs/rfcs/             RFC-0001 and successors
```

`legacy-format` deliberately knows nothing about Parquet, object storage or JSON-RPC. Shadow and
Solo agree on what a relic *is* by depending on it, rather than by both being careful.

## Working on it

```sh
yatr ci     # fmt-check, lint, test, deny - the same four everywhere in this org
yatr test
```

or the long way round with `cargo fmt --all`, `cargo clippy --all-targets -- -D warnings`,
`cargo test`, `cargo deny check`.

## Licence

MIT or Apache-2.0, at your option.
