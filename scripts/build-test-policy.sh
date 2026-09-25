#!/usr/bin/env bash
# Check Point lab fixture: 200 custom objects, 100 rules, 10 sections.
# Requires Bash 3.2+; live execution also requires mgmt_cli and jq.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: build-test-policy.sh [--execute --session FILE] [--prefix NAME] [--seed N]

Default: print commands only. --execute stages changes in the supplied session.
Use a NEW, dedicated login session in your SOURCE lab domain.
Nothing is published or installed. On failure, partial changes remain in that
session; discard it before retrying. Use a fresh prefix for each run.
EOF
}
execute=false
session=''
prefix="CMA_LAB_$(date +%Y%m%d_%H%M%S)"
seed=$RANDOM
while (($#)); do
  case "$1" in
    --execute) execute=true; shift ;;
    --session|--prefix|--seed)
      (($# >= 2)) || { usage >&2; exit 2; }
      case "$1" in
        --session) session=$2 ;;
        --prefix) prefix=$2 ;;
        --seed) seed=$2 ;;
      esac
      shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
[[ "$prefix" =~ ^[A-Za-z][A-Za-z0-9_-]{0,39}$ ]] || {
  echo 'Prefix must start with a letter and contain 1–40 letters/digits/_/-.' >&2; exit 2;
}
[[ "$seed" =~ ^[0-9]{1,5}$ ]] && ((10#$seed <= 32767)) || {
  echo 'Seed must be an integer from 0 to 32767.' >&2; exit 2;
}
RANDOM=$((10#$seed))
package="${prefix}_Policy"
layer="${prefix}_Test_Access"
response=''
if $execute; then
  [[ -r "$session" ]] || { echo 'Supply --session with a readable login JSON file.' >&2; exit 2; }
  command -v mgmt_cli >/dev/null
  command -v jq >/dev/null
  umask 077
  response=$(mktemp)
fi
trap 'status=$?; if [[ -n "$response" ]]; then rm -f "$response"; fi; exit "$status"' EXIT
trap 'echo "Stopped at line $LINENO. Changes are unpublished; discard the dedicated session before retrying." >&2' ERR

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
    printf '%q ' "$@" -s "${session:-session.json}" --format json
    printf '\n'
  fi
}

# Do not assume which default layers add-package creates on this release.
api add access-layer name "$layer" firewall true add-default-rule false
api add package name "$package" access true threat-prevention false
attach=(name "$package")
n=1
if $execute; then
  api show package name "$package" details-level full
  if jq -e 'any(.["access-layers"][]?; .domain["domain-type"] == "global domain")' "$response" >/dev/null; then
    echo 'Global policy is assigned to this domain. Resolve the lab assignment before generating a migration fixture, then discard this dedicated session and retry.' >&2
    exit 1
  fi
  # Missing/null means no attached layers. Reject malformed entries before writes.
  jq -e '(.["access-layers"] // []) | type == "array" and all(.[]; (.name | type == "string" and length > 0))' "$response" >/dev/null
  n=1
  while IFS= read -r default_layer; do
    attach+=("access-layers.remove.$n" "$default_layer")
    n=$((n+1))
  done < <(jq -r '(.["access-layers"] // [])[] | .name' "$response")
else
  echo '# Execution also discovers and detaches any package default layers; it does not delete them.' >&2
fi
# R82.10 does not reliably apply add and remove together; send separate calls.
api set package name "$package" access-layers.add.1.name "$layer" access-layers.add.1.position 1
if ((n > 1)); then api set package "${attach[@]}"; fi
if $execute; then
  api show package name "$package" details-level full
  jq -e --arg name "$layer" '.["access-layers"] | length == 1 and .[0].name == $name' "$response" >/dev/null
fi


colors=(red blue green yellow orange purple cyan pink)
objects=0
add_object() {
  local kind=$1 name=$2
  shift 2
  api add "$kind" name "$name" "$@" color "${colors[RANDOM % ${#colors[@]}]}" \
    comments "Synthetic migration fixture; prefix=$prefix seed=$seed"
  objects=$((objects + 1))
}
hosts=(); networks=(); ranges=(); dns=(); tcp=(); udp=(); icmp=()
addresses=(); services=()
# Disjoint address blocks and unique high ports avoid internal overlap.
# Existing destination objects can still overlap these lab values.
octet=$((RANDOM % 200 + 20))
port_base=$((RANDOM % 15000 + 40000))
echo "# Package: $package; seed: $seed; mode: execute=$execute" >&2
for ((i=1; i<=70; i++)); do
  name="${prefix}_Host_$i"; hosts+=("$name"); addresses+=("$name")
  add_object host "$name" ipv4-address "10.$octet.0.$i"
done
for ((i=1; i<=40; i++)); do
  name="${prefix}_Net_$i"; networks+=("$name"); addresses+=("$name")
  add_object network "$name" subnet "10.$octet.$i.0" mask-length "$((24 + RANDOM % 3))"
done
for ((i=1; i<=20; i++)); do
  name="${prefix}_Range_$i"; ranges+=("$name"); addresses+=("$name")
  add_object address-range "$name" ip-address-first "10.$octet.$((100+i)).10" \
    ip-address-last "10.$octet.$((100+i)).$((30+RANDOM%150))"
done
for ((i=1; i<=20; i++)); do
  name="${prefix}_TCP_$i"; tcp+=("$name"); services+=("$name")
  port=$((port_base+i*10))
  if ((i % 4 == 0)); then port="$port-$((port+3))"; fi
  add_object service-tcp "$name" port "$port"
  name="${prefix}_UDP_$i"; udp+=("$name"); services+=("$name")
  add_object service-udp "$name" port "$((port_base+500+i))"
done
icmp_types=(0 3 4 5 8 9 10 11 12 13)
for ((i=0; i<10; i++)); do
  name="${prefix}_ICMP_$i"; icmp+=("$name"); services+=("$name")
  add_object service-icmp "$name" icmp-type "${icmp_types[i]}"
  # DNS objects use real DNS syntax, under the reserved .invalid TLD.
  dns_prefix=${prefix//_/-}
  name=".lab-$i.$dns_prefix.invalid"; dns+=("$name"); addresses+=("$name")
  add_object dns-domain "$name" is-sub-domain true
done
add_group() {
  local kind=$1 name=$2 n=1 member
  shift 2
  local args=()
  for member in "$@"; do args+=("members.$n" "$member"); n=$((n+1)); done
  add_object "$kind" "$name" "${args[@]}"
}
add_group group "${prefix}_Hosts_A" "${hosts[@]:0:35}"
add_group group "${prefix}_Hosts_B" "${hosts[@]:35:35}"
add_group group "${prefix}_Networks" "${networks[@]}"
add_group group "${prefix}_Ranges" "${ranges[@]}"
add_group group "${prefix}_DNS" "${dns[@]}"
# Exclusion groups require recursively IP-based members; keep DNS separate.
add_group group "${prefix}_All_Addresses" "${prefix}_Hosts_A" "${prefix}_Hosts_B" \
  "${prefix}_Networks" "${prefix}_Ranges"
add_group service-group "${prefix}_TCP" "${tcp[@]}"
add_group service-group "${prefix}_UDP" "${udp[@]}"
add_group service-group "${prefix}_ICMP" "${icmp[@]}"
add_object group-with-exclusion "${prefix}_Except_Hosts_A" \
  include "${prefix}_All_Addresses" except "${prefix}_Hosts_A"
[[ "$objects" -eq 200 ]]


headers=('Infrastructure & shared services' 'Application frontends' 'Database access'
  'Operations & monitoring' 'Partner connectivity' 'Development & QA'
  'DNS & discovery' 'Restricted segments' 'Disabled & exception tests' 'Egress & cleanup')
actions=(Accept Drop Reject)
for ((i=1; i<=100; i++)); do
  if (((i-1) % 10 == 0)); then
    api add access-section layer "$layer" position bottom name "${headers[(i-1)/10]}"
  fi
  src=${addresses[RANDOM % ${#addresses[@]}]}
  dst=${addresses[RANDOM % ${#addresses[@]}]}
  svc=${services[RANDOM % ${#services[@]}]}
  action=${actions[RANDOM % 3]}
  enabled=true; track=Log; extra=()
  if ((i % 7 == 0)); then enabled=false; fi
  if ((i % 4 == 0)); then track=None; fi
  if ((i % 11 == 0)); then extra+=(source-negate true); fi
  if ((i % 13 == 0)); then extra+=(destination-negate true); fi
  if ((i % 9 == 0)); then extra+=(source.2 "${hosts[RANDOM % 70]}"); fi
  # Disabled coverage rules ensure every custom object is reachable by migration.
  if ((i == 1)); then
    src="${prefix}_All_Addresses"; dst=Any; svc="${prefix}_TCP"; enabled=false
    extra+=(source.2 "${prefix}_DNS" service.2 "${prefix}_UDP" service.3 "${prefix}_ICMP")
  elif ((i == 2)); then
    src="${prefix}_Except_Hosts_A"; dst=Any; enabled=false
  elif ((i == 100)); then
    src=Any; dst=Any; svc=Any; action=Drop; enabled=true; track=Log; extra=()
  fi
  api add access-rule layer "$layer" position bottom name "${prefix}_Rule_$i" \
    source.1 "$src" destination.1 "$dst" service.1 "$svc" action "$action" \
    track.type "$track" enabled "$enabled" comments "Synthetic rule $i; seed=$seed" ${extra[@]+"${extra[@]}"}
done
if $execute; then
  api show access-rulebase name "$layer" limit 500 details-level full
  jq -e '[.. | objects | select(.type? == "access-rule") | .uid] | unique | length == 100' "$response" >/dev/null
  echo "Staged $package: 200 objects, 100 rules, 10 sections. Review in SmartConsole." >&2
  echo "Publish the dedicated session when ready, then scan this package in Single Policy Move." >&2
else
  echo '# Preview complete: 200 objects, 100 rules, 10 sections. Add --execute --session FILE to stage.' >&2
fi
