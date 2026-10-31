#!/usr/bin/env bash
# Check one newcomer agent against one newcomer API. See NEWCOMER.md.
set -euo pipefail

usage() {
  cat <<'USAGE'
usage: newcomer/check.sh --url URL --agent 'COMMAND' [--cacert FILE]

  --url URL       the API's protected endpoint, for example https://127.0.0.1:8443/hello
  --agent CMD     command that makes a signed GET of the URL given as its last
                  argument and prints the HTTP status on its first output line
  --cacert FILE   certificate for curl to trust for an https URL; without it
                  the unsigned probe skips certificate checks

Checks:
  unsigned  a plain GET is answered 401 with an AAuth-Requirement header
  signed    the agent's GET is answered 200
Exit status: 0 when both checks pass, 1 otherwise, 2 for a usage error.
USAGE
}

url= agent= cacert=
while [ $# -gt 0 ]; do
  case "$1" in
    --url) url=${2:?}; shift 2 ;;
    --agent) agent=${2:?}; shift 2 ;;
    --cacert) cacert=${2:?}; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
if [ -z "$url" ] || [ -z "$agent" ]; then
  usage >&2
  exit 2
fi

tls=(--insecure)
if [ -n "$cacert" ]; then
  tls=(--cacert "$cacert")
fi

ok=true
headers=$(curl --silent --show-error "${tls[@]}" --dump-header - --output /dev/null "$url" || true)
status=$(printf '%s\n' "$headers" | awk 'NR==1 {print $2}')
requirement=$(printf '%s\n' "$headers" | tr -d '\r' | grep -i '^aauth-requirement:' | head -1 || true)
if [ "$status" = 401 ] && [ -n "$requirement" ]; then
  echo "unsigned: PASS $status $requirement"
else
  echo "unsigned: FAIL status=${status:-none} ${requirement:-no AAuth-Requirement header}"
  ok=false
fi

agent_output=$(bash -c "$agent \"\$1\"" agent "$url" 2>&1 || true)
agent_status=$(printf '%s\n' "$agent_output" | head -1 | grep -o '[0-9]\{3\}' | head -1 || true)
if [ "$agent_status" = 200 ]; then
  echo "signed: PASS 200"
else
  echo "signed: FAIL status=${agent_status:-none}"
  printf '%s\n' "$agent_output" | head -20 | sed 's/^/  agent: /'
  ok=false
fi

$ok
