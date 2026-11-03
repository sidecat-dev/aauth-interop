# aauth-interop

Runs [aauth-rust](https://gitlab.com/sidecat-dev/aauth-rust) and
[aauth-go](https://gitlab.com/sidecat-dev/aauth-go) against each other over
real HTTPS, the way a developer building on them would, and records what works.

A Rust runner links the aauth-rust crates and starts a Go fleet built from
aauth-go. Between them they run Agents, Agent Providers, Person Servers, Access
Servers, Resources and supervision servers in both languages on loopback TLS,
and drive 127 cases across them: Rust against Rust, Go against Go, and every
mixed pairing the cases name. Each case records what it observed (statuses,
headers, token claims, counts of handler runs) and whether that met its
expectation. Some cases also check that the libraries' documentation describes
the APIs they use.

This is not a conformance suite. [aauth-conformance](https://gitlab.com/sidecat-dev/aauth-conformance)
tests one role of one implementation against the drafts' clauses, with a
harness that uses neither library. This project uses both libraries on purpose
and asks whether they work together.

## Requirements

- Linux (tested on x86_64) with git, a C compiler, and
  [rustup](https://rustup.rs/). The run builds with the toolchain the Rust
  target pins in its `rust-toolchain.toml` (Rust 1.99.1 at
  `v0.1.0-alpha.17`); rustup downloads it on first use.
- Go 1.25 or later.
- Network access to gitlab.com, crates.io and the Go module proxy. The two
  checkouts, the release build and the Go build cache took about 600 MB in the
  last run, on top of the Rust toolchain and the crate and Go module caches.

## Run it

```sh
git clone https://gitlab.com/sidecat-dev/aauth-interop.git
cd aauth-interop
./run.sh --rust-ref v0.1.0-alpha.17 --go-ref 0e2447b
```

`run.sh` clones both libraries into `targets/`, checks out the requested refs
detached, builds the runner against `targets/aauth-rust`, builds the Go fleet
against `targets/aauth-go`, and runs every case. A ref can be a tag, a branch
or a commit. The first build downloads crates and takes a while; the cases
then run in under two minutes.

The run prints one line per case, then a summary and the results path:

```text
[QA-A1] PASS: person=200 class_exchange=200 rt_aud=https://fed-as.example ...
...
[SUMMARY] total=127 met_expectation=127 failed=0 failed_ids=[]
results: runs/20261031T220000Z-rust-10cacbf7-go-0e2447bc/results.json
```

`run.sh` exits 0 when every case met its expectation and 1 otherwise.

Last run: 2026-10-31 on Linux x86_64 (Rust 1.99.1, Go 1.27.1), aauth-rust
`v0.1.0-alpha.17` (`10cacbf`) and aauth-go `0e2447b`, runner `f5d61fd`: 127 of
127 cases met their expectation (106 verified working, 15 defect resolved, 6
boundary pinned). Its `results.json` and transcript are in
[reports/run-02-alpha17-0e2447b/](reports/run-02-alpha17-0e2447b/).

To test unmerged work, point at another repository or branch; a local clone's
path works as a URL:

```sh
./run.sh --rust-repo https://gitlab.com/you/aauth-rust.git --rust-ref my-branch --go-ref main
./run.sh --rust-ref v0.1.0-alpha.17 --go-repo ../aauth-go --go-ref my-branch
```

Only committed work is tested. `run.sh` refuses to touch a checkout in
`targets/` that has local changes. Use `--out DIR` to choose the results
directory; it must be new or empty.

To run the runner by hand after a build:

```sh
runner/target/release/aauth-interop-runner --go-source targets/aauth-go --out-dir runs/by-hand
```

## Read the results

Each run directory holds:

- `results.json`: the full record. `qa-report.json` is a copy under an older
  name.
- `qa-transcript.log`: the printed lines.
- `go-fleet-workdir/`: the generated Go module that was built and run.
- the stores the cases opened, for inspection.

`results.json` has `targets` (path, commit, `git describe`, dirty flag and
origin of each library and of this runner), the counts, `failed_count`,
`failed_ids`, and one entry per case:

```json
{
  "id": "QA-A1",
  "category": "A. Go Federated Resource + Access Server + Federated PS + Rust Agent",
  "title": "Federated Class Document Exchange & Rust Agent Delivery Verification",
  "classification": "VERIFIED_WORKING",
  "passed_expectation": true,
  "summary": "Person token=200, Resource token aud=https://fed-as.example, ...",
  "evidence": { "class_exchange_status": 200, "counts": { "...": 0 } }
}
```

`classification` says what kind of result the case records when it meets its
expectation: `VERIFIED_WORKING`, `DEFECT_RESOLVED` (a defect an earlier run
found, now fixed), `BOUNDARY_PINNED` (a known limit, kept on purpose) or
`DEFECT_CONFIRMED`. `passed_expectation` says whether it did. A case with
`passed_expectation: false` is a failure whatever its classification; its
transcript line reads `FAIL`. [CASES.md](CASES.md) lists every case.

## What the results do not cover

- Everything runs on loopback with self-signed certificates for `*.example`
  names. No public DNS, no real certificates, no network faults.
- Cases test the combinations they name, not every combination of roles and
  languages.
- The documentation cases (QA-J7, QA-K8, QA-M8, QA-N10, QA-O7, QA-P11, QA-Q6,
  QA-R7, QA-S8, QA-T7, and parts of QA-I1) look for exact sentences in the
  libraries' Markdown files. When a library rewords its docs, these cases fail
  until they are updated; read such a failure as "check the docs", not as a
  library defect.
- Some Go cases run named `go test` packages inside the aauth-go checkout as
  part of their evidence.
- Fixture keys, including `runner/src/rsa-*.der`, are throwaway test keys.

## The newcomer test

[NEWCOMER.md](NEWCOMER.md) is a by-hand procedure: someone new to both
libraries builds an agent and an API in each language from the documentation
alone, and `newcomer/check.sh` checks each agent against each API. Its record
template is [newcomer/RECORD-TEMPLATE.md](newcomer/RECORD-TEMPLATE.md).

## Layout

| Path | What |
| --- | --- |
| `run.sh` | fetch the targets, build, run |
| `runner/src/` | the Rust runner; `main.rs` holds groups A to I and starts everything |
| `runner/fleet/` | the Go fleet; the runner embeds these files and writes them into the generated module |
| `CASES.md` | every case by group, with its source files |
| `NEWCOMER.md`, `newcomer/` | the newcomer test |
| `reports/` | results of recorded runs, one folder per run |
| `targets/`, `runs/` | created by `run.sh`; not committed |

## Add a case

Add it to the group of the feature it tests, or start a new letter for a new
round. Take the next free id in that group; never reuse or renumber one. Record
what you observed in `evidence`, set `passed_expectation` from explicit checks
on those observations, and push one transcript line that starts with the id.
Add the case to CASES.md.

## License

MIT. See [LICENSE](LICENSE).
