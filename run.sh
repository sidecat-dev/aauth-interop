#!/usr/bin/env bash
# Fetch aauth-rust and aauth-go at the requested refs, build the runner
# against them and run every case. See README.md.
set -euo pipefail

usage() {
  cat <<'EOF'
usage: ./run.sh --rust-ref REF --go-ref REF [options]

  --rust-ref REF    aauth-rust tag, branch or commit, for example v0.1.0-alpha.17
  --go-ref REF      aauth-go tag, branch or commit, for example 0e2447b
  --rust-repo URL   default https://gitlab.com/sidecat-dev/aauth-rust.git
  --go-repo URL     default https://gitlab.com/sidecat-dev/aauth-go.git
  --out DIR         new or empty results directory; default
                    runs/<UTC time>-rust-<commit>-go-<commit>

The targets are cloned into targets/aauth-rust and targets/aauth-go and
checked out detached at the requested refs. A URL can also be a path to a
local clone. Exit status: 0 when every case meets its expectation, 1 when a
case misses it or the run fails, 2 for a usage error.
EOF
}

root=$(cd "$(dirname "$0")" && pwd)
rust_repo=https://gitlab.com/sidecat-dev/aauth-rust.git
go_repo=https://gitlab.com/sidecat-dev/aauth-go.git
rust_ref= go_ref= out=

while [ $# -gt 0 ]; do
  case "$1" in
    --rust-ref) rust_ref=${2:?}; shift 2 ;;
    --go-ref) go_ref=${2:?}; shift 2 ;;
    --rust-repo) rust_repo=${2:?}; shift 2 ;;
    --go-repo) go_repo=${2:?}; shift 2 ;;
    --out) out=${2:?}; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
if [ -z "$rust_ref" ] || [ -z "$go_ref" ]; then
  usage >&2
  exit 2
fi
for tool in git cargo go; do
  command -v "$tool" >/dev/null || { echo "run.sh: $tool is not on PATH" >&2; exit 1; }
done

# fetch_target NAME URL REF: clone or update targets/NAME and check out REF
# detached. Prints the resolved commit.
fetch_target() {
  local dir=$root/targets/$1 url=$2 ref=$3 commit
  if [ ! -d "$dir/.git" ]; then
    mkdir -p "$root/targets"
    git clone --quiet "$url" "$dir" >&2
  else
    if [ -n "$(git -C "$dir" status --porcelain)" ]; then
      echo "run.sh: $dir has local changes; remove them or the directory first" >&2
      exit 1
    fi
    git -C "$dir" remote set-url origin "$url"
    git -C "$dir" fetch --quiet --tags --force origin >&2
  fi
  commit=$(git -C "$dir" rev-parse --verify --quiet "refs/remotes/origin/$ref^{commit}" ||
    git -C "$dir" rev-parse --verify --quiet "refs/tags/$ref^{commit}" ||
    git -C "$dir" rev-parse --verify --quiet "$ref^{commit}" ||
    { git -C "$dir" fetch --quiet origin "$ref" >&2 &&
      git -C "$dir" rev-parse --verify --quiet "FETCH_HEAD^{commit}"; }) ||
    { echo "run.sh: $ref not found in $url" >&2; exit 1; }
  git -C "$dir" checkout --quiet --detach "$commit"
  echo "$commit"
}

rust_commit=$(fetch_target aauth-rust "$rust_repo" "$rust_ref")
go_commit=$(fetch_target aauth-go "$go_repo" "$go_ref")
echo "aauth-rust $rust_ref = $rust_commit ($rust_repo)"
echo "aauth-go   $go_ref = $go_commit ($go_repo)"

# Build with the toolchain the Rust target pins, unless the caller chose one.
toolchain_file=$root/targets/aauth-rust/rust-toolchain.toml
if [ -z "${RUSTUP_TOOLCHAIN:-}" ] && command -v rustup >/dev/null && [ -f "$toolchain_file" ]; then
  channel=$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$toolchain_file")
  if [ -n "$channel" ]; then
    export RUSTUP_TOOLCHAIN=$channel
  fi
fi

if [ -z "$out" ]; then
  out=$root/runs/$(date -u +%Y%m%dT%H%M%SZ)-rust-${rust_commit:0:8}-go-${go_commit:0:8}
fi
mkdir -p "$(dirname "$out")"

cargo build --release --manifest-path "$root/runner/Cargo.toml"
status=0
cargo run --quiet --release --manifest-path "$root/runner/Cargo.toml" -- \
  --rust-source "$root/targets/aauth-rust" \
  --go-source "$root/targets/aauth-go" \
  --out-dir "$out" || status=$?
if [ -f "$out/results.json" ]; then
  echo "results: $out/results.json"
fi
exit "$status"
