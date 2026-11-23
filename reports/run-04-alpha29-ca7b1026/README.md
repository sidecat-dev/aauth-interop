# HTTPS interoperability at the merged working-group revisions

All **127 of 127** expectations passed on the Linux x86-64 build droplet.
The runner exited 0. In the [case summary](results-summary.json), 107 cases
verify working behavior, 15 verify resolved defects, and five verify
documented boundaries.

| Input | Commit |
| --- | --- |
| Go | `ca7b1026f01ea7bed27b7a45935951be1473567b` |
| Rust | `b3637f52746b37c245533b9aefd2a50aee37dde6` |
| Tested runner | `646dca79b382df7ae9f0b94e2a5ec2c789229265` |

```sh
CARGO_BUILD_JOBS=2 GOMAXPROCS=2 ./run.sh \
  --go-ref ca7b1026f01ea7bed27b7a45935951be1473567b \
  --rust-ref b3637f52746b37c245533b9aefd2a50aee37dde6
```

The library trees match the pre-merge working-group heads. The runner has
nine updated wire or boundary expectations and ten updated documentation
audits. All 19 passed, along with the three dependent rollups. The suite
exercised both language directions for narrowed supervision and the Go
Resource's metered release via a Rust Person Server and a Go Access Server.

The [pre-refresh run](../run-03-alpha29-c0b552ff/) records the earlier
105 of 127 result with the original expectations.
