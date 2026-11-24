# Verify AWS credentials, scan the account, then write the audit report.
# Usage: scripts\scan_aws.ps1 [scan options, e.g. --profile audit --region us-east-1 --label prod]
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

$activate = ".venv\Scripts\Activate.ps1"
if (-not (Test-Path $activate)) {
    Write-Error "No .venv found. Run: python -m venv .venv; pip install -r requirements.txt"
    exit 1
}
. $activate

# `scan` runs the credential preflight (sts:GetCallerIdentity) and exits non-zero without credentials.
python -m app.cli scan @args
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$out = python -m app.cli report
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$out
Write-Host "Open the report: $(($out -split ': ', 2)[1])"
