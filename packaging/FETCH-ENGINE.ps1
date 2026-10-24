# Fetch the open-source MIT-licensed Python signing engine at a pinned commit.
# Does not fetch Apple account credentials. Run on Windows in repo root.
param([string]$Commit = 'be811fcaea8556fe5108dd25279d626fa0d56435')
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root
if (-not (Get-Command git -ErrorAction SilentlyContinue)) { throw 'Git is required to assemble the bundled signing engine' }
$checkout = Join-Path $root '.upstream\ipaside'
if (-not (Test-Path (Join-Path $checkout '.git'))) {
    New-Item -ItemType Directory -Force '.upstream' | Out-Null
    & git clone 'https://github.com/pwnapplehat/iPASide.git' $checkout
    if ($LASTEXITCODE -ne 0) { throw 'Clone of iPASide failed' }
}
& git -C $checkout fetch --depth 1 origin $Commit
if ($LASTEXITCODE -ne 0) { throw 'Unable to fetch the pinned iPASide version' }
& git -C $checkout checkout --force --detach $Commit
if ($LASTEXITCODE -ne 0) { throw 'Unable to checkout pinned iPASide version' }
$actual = (& git -C $checkout rev-parse HEAD).Trim()
if ($actual -ne $Commit) { throw "Unexpected upstream commit: $actual" }
Write-Host "Verified iPASide source at $actual"
