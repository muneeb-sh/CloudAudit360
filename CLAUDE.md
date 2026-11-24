# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

CloudAudit360: read-only AWS security and compliance auditing. It collects AWS config, runs ~20 built-in checks, maps results to ISO 27001 / NIST 800-53 / CIS AWS controls, scores compliance and risk, and produces reports plus a FastAPI dashboard. Full design: `docs/CloudAudit360_SPEC.md`.

## Commands

Windows dev box; the venv is `.venv` (`.venv\Scripts\Activate.ps1`, or call `.venv/Scripts/python` directly).

```bash
pip install -r requirements.txt
pytest -q                                   # all tests
pytest -q tests/test_checks.py::test_secure_account_passes_every_check   # single test
python -m app.cli help [COMMAND]            # usage + examples (also -h / --help)
python -m app.cli init                      # optional: create DB, seed frameworks, create admin (serve/scan/report do it too)
python -m app.cli reset-admin [--yes]       # admin password back to "admin", forced change at next sign-in
python -m app.cli scan [--profile P] [--region R ...] [--label L]
python -m app.cli report [--scan N] [--type audit|technical] [--format html|pdf]
python -m app.cli serve [--port 8000]       # or: uvicorn app.main:app
```

There is no linter config. Settings come from an optional `.env` (see `.env.example`) via `app/config.py` (pydantic-settings); every setting has a working default.

## Architecture

The scan pipeline is `app/pipeline.py:run_scan`: **Collect → Assess → Risk register → Compliance → Reviews**. The CLI, `POST /scans` (web) and `POST /api/scans` all call it.

- **Collect** (`app/collector/aws_collector.py`): uses the boto3 session from `pipeline.aws_session` (standard credential chain; `AWS_PROFILE` from `.env` is passed explicitly). Global services are IAM, S3 and CloudTrail. Regional services (EC2/VPC, GuardDuty, KMS, RDS) loop over `resolve_regions()`. Each service/region sits in its own try/except, and failures go into a `CollectErrors` dict instead of aborting. Output is `Snapshot` rows (`service`, `resource_id`, `config_json`) plus SHA-256-hashed `Evidence` files and upserted `Asset` rows.
- **Snapshot shape is a contract with the checks.** Checks receive `{service: {resource_id: config}}`. Region-scoped singletons are aggregated into one snapshot keyed by region (e.g. `ec2/"ebs-default-encryption"` → `{"Regions": {region: bool}}`, `guardduty/"detectors"`, `ec2/"vpc-flow-logs"` → `{"Vpcs", "FlowLogs"}`, `kms/"keys"`). The account ID lives at `iam/"account"/AccountId`; checks read it via `registry.account_id()`. If you change the collector output, update the checks and the inline snapshots in `tests/test_checks.py`.
- **Assess** (`app/assessment/`): checks are functions registered with `@register_check("check_id")` in `checks/*.py`. Importing `app.assessment.checks` registers them. They return `NormalizedFinding` (`app/schemas.py`) with PASS/FAIL. `engine.apply_collect_errors` maps a check to its service by check-id prefix (`CHECK_SERVICE`), so a new check needs a prefix that is in that map. Failed collection turns findings into ERROR, so missing data never reads as PASS. `persist_findings` creates `Asset` rows for ARNs it hasn't seen.
- **Risk register** (`app/grc/register.py`, scoring in `grc/risk.py` + `data/risk_config.yaml`): one `Risk` per `finding_key = check_id + asset ARN`. FAIL creates or updates the risk; a later PASS marks it mitigated; ERROR is ignored. **Real ARNs matter**: placeholder or duplicate ARNs collapse distinct issues into one risk.
- **Compliance** (`app/grc/compliance.py`): `CheckControlMap` (from `data/frameworks/mapping.yaml`) links check IDs to controls (`controls.yaml`). A control is FAIL if any linked finding fails, EXCEPTION if all failures have active exceptions, NOT_ASSESSED if there are no results or only ERRORs, otherwise PASS. `framework_scores()` feeds the dashboard, CLI summary and reports.
- **Seeding** (`app/seed.py`): `seed_reference` (controls, mappings, policies; idempotent) runs on every app startup. `ensure_admin` also runs on startup and in the CLI: it creates `ADMIN_USERNAME`/`ADMIN_PASSWORD` (default admin/admin) if missing and never touches an existing user. With the default password, `User.must_change_password` is set, and the middleware in `app/main.py` sends every request except `/login`, `/logout`, `/change-password`, `/static` and `/health` to `/change-password` (`/api` gets a 403) until it is changed. `SECRET_KEY` defaults to a key generated once into `.secret_key`. `.env` is optional.
- **Late columns**: there are no migrations, so columns added to existing tables go in `app/db.py:_LATE_COLUMNS` and `init_db` adds them to old database files.
- **Web** (`app/main.py`, `app/web/routes_*.py`): server-rendered Jinja2 + Tailwind/Chart.js from CDN, with session-cookie auth (`app/auth.py`, roles admin/auditor/viewer). The JSON API lives under `/api`.
- **Reports** (`app/reporting/builder.py`): Jinja2 HTML. PDF via WeasyPrint is optional and lazily imported; it falls back to HTML.
- **DB**: SQLAlchemy 2.x, `Base.metadata.create_all` (no migrations). `Scan.environment` is a legacy column kept for old SQLite files. Use `label`.

## Rules

- **Git attribution:** never add Claude as a co-author or contributor. Commit messages and PR descriptions get no `Co-Authored-By: Claude` trailer and no "Generated with Claude Code" line, so Claude never shows up among the GitHub contributors.

- **AWS calls must stay read-only** (`Describe*`/`List*`/`Get*`). `tests/test_collector.py` enforces this under `moto` by recording every operation name.
- Tests: `tests/conftest.py` sets `DATABASE_URL` to a temp SQLite file and strips AWS credentials *before* any `app` import (the engine is created at import time), and redirects evidence/report output dirs. Keep new tests behind that conftest; never point tests at the real `cloudaudit360.db`.
- No demo mode, fixtures, Terraform labs, Docker or external scanner adapters. These were removed on purpose. `NormalizedFinding.source` is a free string so external scanners can be added later.
