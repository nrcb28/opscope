$ErrorActionPreference = 'Stop'
$project = Join-Path $PSScriptRoot '..\src\Opscope\Opscope.csproj'
$tempRoot = if ([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) { [IO.Path]::GetTempPath() } else { $env:RUNNER_TEMP }
$temp = Join-Path $tempRoot 'opscope-smoke'
New-Item -ItemType Directory -Force -Path $temp | Out-Null

dotnet build $project -c Release --nologo
$json = dotnet run --project $project -c Release --no-build -- snapshot --json --no-services --top 3 | ConvertFrom-Json
if ([string]::IsNullOrWhiteSpace($json.host.platform)) { throw 'host.platform missing' }
if ($json.processes.Count -gt 3) { throw "expected at most 3 processes, got $($json.processes.Count)" }
if ($null -eq $json.memory.usedPercent) { throw 'memory.usedPercent missing' }

$baseline = Join-Path $temp 'baseline.json'
dotnet run --project $project -c Release --no-build -- snapshot --json --out $baseline --no-processes --no-network --no-services | Out-Host
$diff = dotnet run --project $project -c Release --no-build -- diff $baseline --json --no-processes --no-network --no-services | ConvertFrom-Json
if ($null -eq $diff.metrics) { throw 'diff.metrics missing' }

$bundle = Join-Path $temp 'smoke.zip'
dotnet run --project $project -c Release --no-build -- bundle --out $bundle --no-services --no-network --top 1 | Out-Host
if (-not (Test-Path $bundle)) { throw 'bundle was not created' }
if ((Get-Item $bundle).Length -lt 100) { throw 'bundle is unexpectedly small' }
$bundleDir = Join-Path $temp 'bundle-inspect'
Expand-Archive -LiteralPath $bundle -DestinationPath $bundleDir -Force
$bundleSnapshot = Get-Content -Raw (Join-Path $bundleDir 'snapshot.json') | ConvertFrom-Json
if ($bundleSnapshot.host.hostname -ne '[redacted-host]') { throw 'bundle host was not redacted' }
if ($bundleSnapshot.processes | Where-Object { $_.PSObject.Properties.Name -contains 'commandLine' -and $_.commandLine }) { throw 'bundle contains a process command line' }

Write-Host 'opscope smoke test passed'

