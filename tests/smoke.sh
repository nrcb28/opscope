#!/usr/bin/env bash
set -euo pipefail

project="$(cd "$(dirname "$0")/../src/Opscope" && pwd)/Opscope.csproj"
temp="$(mktemp -d "${TMPDIR:-/tmp}/opscope-smoke.XXXXXX")"
trap 'rm -rf "$temp"' EXIT

dotnet build "$project" -c Release --nologo

# Findings (exit 1) are valid collection results; only operational errors fail smoke.
run_collector() {
  local status=0
  dotnet run --project "$project" -c Release --no-build -- "$@" || status=$?
  if [ "$status" -gt 1 ]; then return "$status"; fi
  return 0
}
json="$(run_collector snapshot --json --no-services --top 3)"
printf '%s' "$json" | grep -q '"platform"'
printf '%s' "$json" | grep -q '"usedPercent"'

tools_status=0
tools_json="$(dotnet run --project "$project" -c Release --no-build -- tools --json)" || tools_status=$?
if [ "$tools_status" -ne 0 ]; then
  echo "tools command failed with exit $tools_status:" >&2
  printf '%s\n' "$tools_json" >&2
  exit "$tools_status"
fi
printf '%s' "$tools_json" | grep -q '"tools"'
if printf '%s' "$tools_json" | grep -Eq '"security": "(writable-by-non-owner|not-executable|untrusted-path|reparse-point|inspection-error)'; then
  echo 'tool inventory reported an unsafe executable' >&2
  exit 1
fi

path_tools="$(PATH="$temp/not-a-tool:$PATH" dotnet run --project "$project" -c Release --no-build -- tools --json)"
if printf '%s' "$path_tools" | grep -q "$temp/not-a-tool"; then
  echo 'tool resolution changed under a polluted PATH' >&2
  exit 1
fi

redacted_json="$(run_collector snapshot --json --redact --no-processes --no-network --no-services)"
printf '%s' "$redacted_json" | grep -q '"hostname": "\[redacted-host\]"'
printf '%s' "$redacted_json" | grep -q '"currentUser": "\[redacted-user\]"'
if printf '%s' "$redacted_json" | grep -q '"path": "'; then
  echo 'redacted snapshot contains a tool path' >&2
  exit 1
fi

redacted_tools="$(dotnet run --project "$project" -c Release --no-build -- tools --json --redact)"
if printf '%s' "$redacted_tools" | grep -q '"path": "'; then
  echo 'redacted tool inventory contains a path' >&2
  exit 1
fi

redacted_doctor="$(run_collector doctor --json --redact --no-processes --no-network --no-services)"
printf '%s' "$redacted_doctor" | grep -q '"host": "\[redacted-host\]"'

if [ "$(id -u)" -ne 0 ]; then
  spoofed_euid="$(env EUID=0 dotnet run --project "$project" -c Release --no-build -- snapshot --json --no-processes --no-network --no-services)" || [ "$?" -eq 1 ]
  if printf '%s' "$spoofed_euid" | grep -q '"isElevated": true'; then
    echo 'Linux elevation detection trusted the spoofable EUID environment variable' >&2
    exit 1
  fi
fi

deep_baseline="$temp/deep-baseline.json"
: > "$deep_baseline"
for _ in $(seq 1 70); do printf '{"x":' >> "$deep_baseline"; done
printf '0' >> "$deep_baseline"
for _ in $(seq 1 70); do printf '}' >> "$deep_baseline"; done
set +e
dotnet run --project "$project" -c Release --no-build -- diff "$deep_baseline" --json --no-processes --no-network --no-services >/dev/null 2>&1
deep_status=$?
set -e
if [ "$deep_status" -ne 2 ]; then
  echo "deeply nested baseline was not rejected (exit $deep_status)" >&2
  exit 1
fi

baseline="$temp/baseline.json"
run_collector snapshot --json --out "$baseline" --no-processes --no-network --no-services >/dev/null
diff_json="$(run_collector diff "$baseline" --json --no-processes --no-network --no-services)"
printf '%s' "$diff_json" | grep -q '"metrics"'

bundle="$temp/smoke.zip"
run_collector bundle --out "$bundle" --no-services --no-network --top 1
test -s "$bundle"
bundle_dir="$temp/bundle-inspect"
mkdir -p "$bundle_dir"
unzip -q -o "$bundle" -d "$bundle_dir"
grep -q '"hostname": "\[redacted-host\]"' "$bundle_dir/snapshot.json"
! grep -q 'commandLine' "$bundle_dir/snapshot.json"
! grep -Eq 'commandLine|"path"[[:space:]]*:' "$bundle_dir/findings.json"

echo 'opscope smoke test passed'

