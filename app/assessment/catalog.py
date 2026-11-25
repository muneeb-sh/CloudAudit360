"""Cloud-security metadata per check (data/check_catalog.yaml).

Drives the Shared Responsibility view, the Attack Surface view and the CLI remediation
shown for failed findings. Shared by the web pages and the technical report.
"""

from __future__ import annotations

from collections import defaultdict
from functools import lru_cache

import yaml

from app.config import DATA_DIR
from app.models import Finding

DOMAINS = [
    "Identity & access",
    "Data protection",
    "Network security",
    "Compute & workload",
    "Logging & monitoring",
]
SERVICE_MODELS = ["Infrastructure", "Container", "Abstracted", "Account-wide"]

# What AWS secures vs. what the customer secures, per service model (AWS Shared Responsibility Model).
SERVICE_MODEL_INFO = {
    "Infrastructure": {
        "examples": "EC2, EBS, VPC",
        "aws": "Physical data centres, hardware, hypervisor, global network",
        "customer": "Guest OS, patching, security groups, IMDS settings, disk encryption, data",
    },
    "Container": {
        "examples": "RDS",
        "aws": "Hardware, OS, database engine patching, backups infrastructure",
        "customer": "Network reachability, encryption settings, DB users and access",
    },
    "Abstracted": {
        "examples": "S3, KMS, CloudTrail, GuardDuty",
        "aws": "Everything that runs the service, including its platform and OS",
        "customer": "Data, bucket and key policies, encryption, enabling logging and detection",
    },
    "Account-wide": {
        "examples": "IAM",
        "aws": "The IAM service itself",
        "customer": "Users, MFA, credentials, least-privilege policies (applies to every model)",
    },
}


@lru_cache
def load_catalog() -> dict[str, dict]:
    with (DATA_DIR / "check_catalog.yaml").open(encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def entry(check_id: str) -> dict:
    return load_catalog().get(check_id, {})


def responsibility_matrix(findings: list[Finding]) -> dict:
    """Counts of PASS/FAIL/other per (domain, service model), plus per-domain totals."""
    cells: dict[tuple[str, str], dict[str, int]] = defaultdict(lambda: {"PASS": 0, "FAIL": 0, "OTHER": 0})
    domains: dict[str, dict[str, int]] = defaultdict(lambda: {"PASS": 0, "FAIL": 0, "OTHER": 0})
    for f in findings:
        meta = entry(f.check_id)
        domain = meta.get("domain", "Other")
        model = meta.get("service_model", "Account-wide")
        bucket = f.status if f.status in ("PASS", "FAIL") else "OTHER"
        cells[(domain, model)][bucket] += 1
        domains[domain][bucket] += 1
    return {
        "domains": [d for d in DOMAINS if d in domains] + sorted(set(domains) - set(DOMAINS)),
        "models": SERVICE_MODELS,
        "model_info": SERVICE_MODEL_INFO,
        "cells": dict(cells),
        "domain_totals": dict(domains),
    }


def attack_surface(findings: list[Finding]) -> dict:
    """Internet-exposure findings grouped by asset, failing assets first."""
    exposed = [f for f in findings if entry(f.check_id).get("internet_exposure")]
    by_asset: dict[str, dict] = {}
    for f in exposed:
        key = f.asset.arn if f.asset else f"{f.check_id}:{f.id}"
        row = by_asset.setdefault(key, {"asset": f.asset, "fails": [], "passes": 0})
        if f.status == "FAIL":
            row["fails"].append(f)
        elif f.status == "PASS":
            row["passes"] += 1
    rows = sorted(
        (r for r in by_asset.values() if r["fails"]),
        key=lambda r: (-len(r["fails"]), r["asset"].name if r["asset"] else ""),
    )
    failing = [f for f in exposed if f.status == "FAIL"]

    def count(*check_ids: str) -> int:
        return len({f.asset_id for f in failing if f.check_id in check_ids})

    return {
        "rows": rows,
        "checked_resources": sum(1 for r in by_asset.values() if r["asset"] is not None),
        "exposed_resources": len(rows),
        "open_admin_ports": count("sg_no_ssh_open_world", "sg_no_rdp_open_world", "sg_no_all_traffic_open_world"),
        "public_data_stores": count("s3_public_access_blocked", "rds_not_public", "ec2_no_public_snapshots"),
        "imdsv1_instances": count("ec2_imdsv2_required"),
    }
