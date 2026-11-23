# HTTPS compatibility on the working-group heads

The full loopback HTTPS runner completed 127 cases. **105 met expectations and
22 did not.** The process returned status 1. Both language targets and the
runner were clean at the recorded revisions.

| Input | Revision |
| --- | --- |
| aauth-go !2 | `c0b552ff7939d5fab74664386e5d6225d0c26ca4` |
| aauth-rust !9 | `2da0d17ab431ddb32533e8a336e2d85d908a87dc` |
| Tested runner | `8b57b89404abc45d697b476075543528898a1bf9` |

Ran on Linux x86-64 with Rust 1.99.1 and Go 1.27.1.

```sh
CARGO_BUILD_JOBS=2 GOMAXPROCS=2 ./run.sh \
  --go-ref c0b552ff7939d5fab74664386e5d6225d0c26ca4 \
  --rust-ref 2da0d17ab431ddb32533e8a336e2d85d908a87dc
```

The passing cases include 88 classified as verified working, 12 previously
resolved defects, and five intentional boundaries. Mixed-language chaining
and root revocation in both directions passed (QA-R3). Bidirectional cached
signature negotiation and recovery passed (QA-M6).

| Unmet checks | Cases and observed scope |
| --- | --- |
| 10 documentation audits | J7, K8, M8, N10, O7, P11, Q6, R7, S8, T7. These include old release literals, old conformance wording, and the missing historical `PACKAGE-README.md`. |
| 9 wire or boundary checks | E2 observed 202 where the old held-request test expected refusal. M1 missed parts of the multi-algorithm direction and algorithm negotiation. Q5 and T4 missed an expected metered-release refusal. S2 and S4–S6 missed four-party supervision expectations. T2 missed a chained budget ceiling expectation. |
| 3 aggregate checks | R6, S7, T6 restate failures in their constituent cases. Their failure does not add another wire mismatch. |

The per-case [result summary](results-summary.json) preserves every outcome.
Failing wire expectations need individual triage before they can be called
library regressions. The prior clean run remains tied to its historical
runner and library pins.

The release runner's SHA-256 was
`8af0aa7e59ae06b555ac2e9b78b37b7d0ecb5bd3968269c4b2c8c3ddfc25bcbb`.
