"""EC2 compute checks: instance metadata (IMDSv2) and public snapshot / AMI sharing."""

from __future__ import annotations

from typing import Any

from app.assessment.registry import register_check
from app.schemas import NormalizedFinding


def _none_found(check_id: str, title: str, severity: str, what: str) -> list[NormalizedFinding]:
    return [
        NormalizedFinding(
            check_id=check_id,
            source="custom",
            title=title,
            description=f"No {what} found.",
            severity=severity,
            status="PASS",
            evidence={},
            remediation="N/A",
        )
    ]


@register_check("ec2_imdsv2_required")
def ec2_imdsv2_required(snapshots: dict[str, Any]) -> list[NormalizedFinding]:
    instances = snapshots.get("ec2", {}).get("instances", {}).get("Instances", [])
    findings = []
    for inst in instances:
        if inst.get("State", {}).get("Name") == "terminated":
            continue
        meta = inst.get("MetadataOptions", {})
        required = meta.get("HttpTokens") == "required" or meta.get("HttpEndpoint") == "disabled"
        iid = inst.get("InstanceId")
        findings.append(
            NormalizedFinding(
                check_id="ec2_imdsv2_required",
                source="custom",
                asset_arn=inst.get("Arn"),
                title=f"IMDSv2 required: {iid} ({inst.get('Region', '')})",
                description=(
                    "EC2 instances should require IMDSv2 session tokens. IMDSv1 lets an SSRF "
                    "bug in an application read the instance role's credentials (Capital One 2019)."
                ),
                severity="high",
                status="PASS" if required else "FAIL",
                evidence={
                    "InstanceId": iid,
                    "Region": inst.get("Region"),
                    "MetadataOptions": meta,
                    "PublicIpAddress": inst.get("PublicIpAddress"),
                    "IamInstanceProfile": inst.get("IamInstanceProfile"),
                },
                remediation="Set the instance metadata option HttpTokens=required (IMDSv2 only).",
            )
        )
    return findings or _none_found("ec2_imdsv2_required", "IMDSv2 required", "high", "EC2 instances")


@register_check("ec2_no_public_snapshots")
def ec2_no_public_snapshots(snapshots: dict[str, Any]) -> list[NormalizedFinding]:
    cfg = snapshots.get("ec2", {}).get("snapshots-images", {})
    findings = []
    for kind, items, id_key in (
        ("EBS snapshot", cfg.get("Snapshots", []), "SnapshotId"),
        ("AMI", cfg.get("Images", []), "ImageId"),
    ):
        for item in items:
            public = bool(item.get("Public"))
            rid = item.get(id_key)
            findings.append(
                NormalizedFinding(
                    check_id="ec2_no_public_snapshots",
                    source="custom",
                    asset_arn=item.get("Arn"),
                    title=f"{kind} not public: {rid} ({item.get('Region', '')})",
                    description=(
                        f"A public {kind} can be copied by any AWS account, exposing disk "
                        "contents such as data, secrets and keys."
                    ),
                    severity="critical",
                    status="FAIL" if public else "PASS",
                    evidence={
                        "Type": kind,
                        "Id": rid,
                        "Region": item.get("Region"),
                        "Public": public,
                        "Encrypted": item.get("Encrypted"),
                    },
                    remediation=f"Remove the public ('all') launch/create-volume permission from the {kind}.",
                )
            )
    return findings or _none_found(
        "ec2_no_public_snapshots", "EBS snapshots and AMIs not public", "critical", "snapshots or AMIs"
    )
