# CloudAudit360

**CloudAudit360: read-only AWS security and compliance auditing. Collect, assess, map to frameworks, score risk, and report.**

CloudAudit360 connects to an AWS account with read-only credentials and collects the configuration of IAM, S3, EC2/VPC, CloudTrail, GuardDuty, KMS and RDS. It runs about 20 security checks on that data and maps every result to ISO 27001, NIST 800-53 and CIS AWS Foundations controls. It then scores compliance per framework and keeps a risk register (likelihood × impact, treatment, exceptions) with SHA-256-hashed evidence. Results go into HTML/PDF audit and technical reports, and a web dashboard shows them.

## Prerequisites

- Python 3.11+
- An AWS account you own or are authorized to audit

## 1. Create a read-only IAM identity

In the AWS console, create an IAM user (or a role you can assume or reach through SSO) with exactly these AWS-managed policies:

- `SecurityAudit`
- `ViewOnlyAccess`

For an IAM user, create an access key under **Security credentials → Create access key → CLI**.

## 2. Quick start

```bash
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\Activate.ps1
pip install -r requirements.txt

aws configure --profile audit        # paste the read-only access key
export AWS_PROFILE=audit             # Windows: $env:AWS_PROFILE = "audit"

python -m app.cli scan               # scan the account
python -m app.cli report             # HTML audit report for the latest scan
python -m app.cli serve              # dashboard at http://127.0.0.1:8000
```

Sign in to the dashboard as **admin / admin**. On first sign-in you have to choose a new password before anything else is available.

No `.env` file is needed. The database, the admin user and a session secret (kept in `.secret_key`) are created on first run. Copy `.env.example` to `.env` only to set `AWS_PROFILE` / `AWS_REGIONS` or override another default.

Run `python -m app.cli help` (or `-h`) for every command, and `python -m app.cli help scan` for one command's options and examples. If you forget the dashboard password, `python -m app.cli reset-admin` sets it back to `admin` and asks for a new one at the next sign-in.

Or run `scripts/scan_aws.sh` (or `scripts\scan_aws.ps1`), which checks the credentials, scans and writes the report in one go.

### Scan options

| Option | Meaning |
|---|---|
| `--profile NAME` | AWS profile to use (default: `AWS_PROFILE`, then the standard boto3 chain) |
| `--region R` | Region to scan; repeat for several. Default: `AWS_REGIONS`, then the profile's region, then every enabled region |
| `--label TEXT` | Free-form label such as `prod` or `weekly` |

`scan` first calls `sts:GetCallerIdentity` and prints the account and identity it will use. If one service is denied (for example, missing permissions), it is reported, the scan continues, and those checks are recorded as `ERROR` rather than passing.

### Report options

`python -m app.cli report [--scan N] [--type audit|technical] [--format html|pdf]`

PDF output needs `pip install weasyprint` (plus its system libraries). Without it, the report is written as HTML.

## What is collected and checked

| Service | Collected | Checks |
|---|---|---|
| IAM | password policy, users, MFA, access keys, root status, admin policies | `iam_root_mfa_enabled`, `iam_root_no_access_keys`, `iam_user_mfa_enabled`, `iam_password_policy_strong`, `iam_access_key_rotated_90d`, `iam_no_wildcard_admin_policy` |
| S3 | buckets, public access block, encryption, versioning, policy | `s3_public_access_blocked`, `s3_encryption_enabled`, `s3_versioning_enabled`, `s3_tls_only_policy` |
| EC2 / VPC | security groups, VPCs, flow logs, EBS default encryption (per region) | `sg_no_ssh_open_world`, `sg_no_rdp_open_world`, `sg_no_all_traffic_open_world`, `vpc_flow_logs_enabled`, `ebs_default_encryption` |
| CloudTrail | trails and logging status | `cloudtrail_enabled_multiregion`, `cloudtrail_log_validation` |
| GuardDuty | detectors (per region) | `guardduty_enabled` |
| KMS | customer-managed keys and rotation (per region) | `kms_key_rotation_enabled` |
| RDS | DB instances (per region) | `rds_encrypted` |

## Frameworks mapped

- ISO/IEC 27001:2022 Annex A
- NIST SP 800-53
- CIS AWS Foundations Benchmark

Control catalogue and mappings live in `data/frameworks/`, and risk scoring settings in `data/risk_config.yaml`.

## Dashboard

`python -m app.cli serve` starts the dashboard. Sign in as `admin` / `admin` the first time (or `ADMIN_USERNAME` / `ADMIN_PASSWORD` if you set them in `.env`); the default password must be changed before you continue. Any user can change their password later from the header. Pages: Overview, Trends, Findings, Compliance, Risk register, Scans (history and compare), Reviews, Reports.

## Safety notes

- CloudAudit360 only makes read-only AWS calls (`Describe*`, `List*`, `Get*`), and a test enforces this.
- Credentials come from your AWS profile or environment. They are never stored in the database or in `.env.example`.
- Never commit `.env`, `~/.aws/credentials` or access keys.
- Use a dedicated read-only identity. Deactivate or delete its access keys when you no longer need them.

## Tests

```bash
pytest -q
```

Tests use a temporary database and mocked AWS (`moto`), so they never touch your data or account.

## More

Design, data model, scoring method and API: [`docs/CloudAudit360_SPEC.md`](docs/CloudAudit360_SPEC.md).
