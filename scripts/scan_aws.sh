#!/usr/bin/env bash
# Verify AWS credentials, scan the account, then write the audit report.
# Usage: scripts/scan_aws.sh [scan options, e.g. --profile audit --region us-east-1 --label prod]
set -euo pipefail
cd "$(dirname "$0")/.."

if [ -f .venv/bin/activate ]; then
  source .venv/bin/activate
elif [ -f .venv/Scripts/activate ]; then
  source .venv/Scripts/activate
else
  echo "No .venv found. Run: python -m venv .venv && pip install -r requirements.txt" >&2
  exit 1
fi

# `scan` runs the credential preflight (sts:GetCallerIdentity) and exits non-zero without credentials.
python -m app.cli scan "$@"

out=$(python -m app.cli report)
echo "$out"
echo "Open the report: ${out##*: }"
