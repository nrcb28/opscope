#!/usr/bin/env bash
set -euo pipefail

project="$(cd "$(dirname "$0")/../src/Opscope" && pwd)/Opscope.csproj"
temp="${TMPDIR:-/tmp}/opscope-smoke"
mkdir -p "$temp"

dotnet build "$project" -c Release --nologo
json="$(dotnet run --project "$project" -c Release --no-build -- snapshot --json --no-services --top 3)"
printf '%s' "$json" | grep -q '"platform"'
printf '%s' "$json" | grep -q '"usedPercent"'

baseline="$temp/baseline.json"
dotnet run --project "$project" -c Release --no-build -- snapshot --json --out "$baseline" --no-processes --no-network --no-services >/dev/null
diff_json="$(dotnet run --project "$project" -c Release --no-build -- diff "$baseline" --json --no-processes --no-network --no-services)"
printf '%s' "$diff_json" | grep -q '"metrics"'

bundle="$temp/smoke.zip"
dotnet run --project "$project" -c Release --no-build -- bundle --out "$bundle" --no-services --no-network --top 1
test -s "$bundle"

echo 'opscope smoke test passed'

