#!/usr/bin/env bash
# Companion destination fixture for build-test-policy.sh: six objects only.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: build-test-conflicts.sh --prefix SOURCE_PREFIX [--execute --session FILE]

Use exactly the prefix used by build-test-policy.sh in the source domain.
No seed is needed: the two equivalent definitions are fixed in that script.
Default: print commands only. --execute stages six destination objects.
Use a NEW dedicated session in the DESTINATION lab domain. Review and publish
it before scanning the migration. On failure, discard before retrying.
EOF
}
execute=false
session=''
prefix=''
while (($#)); do
  case "$1" in
    --execute) execute=true; shift ;;
    --session|--prefix)
      (($# >= 2)) || { usage >&2; exit 2; }
      case "$1" in
        --session) session=$2 ;;
        --prefix) prefix=$2 ;;
      esac
      shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
[[ "$prefix" =~ ^[A-Za-z][A-Za-z0-9_-]{0,39}$ ]] || {
  echo 'Supply --prefix with the source fixture prefix (1–40 letters/digits/_/-, starting with a letter).' >&2
  exit 2
}
response=''
if $execute; then
  [[ -r "$session" ]] || { echo 'Supply --session with a readable destination login JSON file.' >&2; exit 2; }
  command -v mgmt_cli >/dev/null
  command -v jq >/dev/null
  umask 077
  response=$(mktemp)
fi
trap 'status=$?; if [[ -n "$response" ]]; then rm -f "$response"; fi; exit "$status"' EXIT
trap 'echo "Stopped at line $LINENO. Changes are unpublished; discard the dedicated destination session before retrying." >&2' ERR

api() {
  if $execute; then
    if ! mgmt_cli "$@" -s "$session" --format json >"$response"; then
      cat "$response" >&2
      return 1
    fi
    if ! jq -e 'type == "object" and (has("code") | not)' "$response" >/dev/null; then
      cat "$response" >&2
      return 1
    fi
  else
    printf 'mgmt_cli '
    printf '%q ' "$@" -s "${session:-destination-session.json}" --format json
    printf '\n'
  fi
}

# Conflict values cannot match the source generator's 10.x addresses or ports
# (40010–55499). Names intentionally match; nothing existing is overwritten.
api add host name "${prefix}_Host_1" ipv4-address 192.0.2.11 color red \
  comments 'Fixture: expect name conflict, different IPv4 address'
api add network name "${prefix}_Net_1" subnet 198.51.100.0 mask-length 24 color red \
  comments 'Fixture: expect name conflict, different subnet'
api add service-tcp name "${prefix}_TCP_1" port 65001 color red \
  comments 'Fixture: expect name conflict, different TCP port'
api add network name "${prefix}_Host_2" subnet 203.0.113.0 mask-length 24 color red \
  comments 'Fixture: expect name conflict, host in source but network here'

# These definitions do not depend on the source random seed. Different comments
# and colors should not affect semantic equivalence in the migration planner.
api add service-icmp name "${prefix}_ICMP_0" icmp-type 0 color green \
  comments 'Fixture: expect reuse, equivalent ICMP service'
dns_prefix=${prefix//_/-}
api add dns-domain name ".lab-0.$dns_prefix.invalid" is-sub-domain true color green \
  comments 'Fixture: expect reuse, equivalent DNS domain'

echo '# Expected in a clean destination: four name conflicts and two reused objects.' >&2
if $execute; then
  echo 'Staged six objects. Review and publish the dedicated destination session, then scan the migration.' >&2
else
  echo '# Preview only. Add --execute --session FILE to stage in the destination domain.' >&2
fi
