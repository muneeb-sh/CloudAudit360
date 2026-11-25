from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import yaml

from app.assessment.registry import account_id, register_check
from app.config import DATA_DIR
from app.schemas import NormalizedFinding


def _risk_cfg() -> dict:
    with (DATA_DIR / "risk_config.yaml").open(encoding="utf-8") as f:
        return yaml.safe_load(f)


def _iam_snapshots(snapshots: dict[str, Any]) -> dict[str, Any]:
    return snapshots.get("iam", {}).get("account", {})


def _age_days(value: Any, now: datetime | None = None) -> int | None:
    """Days since an AWS timestamp (datetime or ISO string); None if missing/unparseable."""
    if not value or value == "None":
        return None
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return ((now or datetime.now(timezone.utc)) - value).days


def _no_users(check_id: str, title: str, severity: str) -> list[NormalizedFinding]:
    return [
        NormalizedFinding(
            check_id=check_id,
            source="custom",
            asset_arn=None,
            title=title,
            description="No IAM users found to assess.",
            severity=severity,
            status="PASS",
            evidence={"Users": []},
            remediation="N/A",
        )
    ]


@register_check("iam_root_mfa_enabled")
def iam_root_mfa_enabled(snapshots: dict[str, Any]) -> list[NormalizedFinding]:
    cfg = _iam_snapshots(snapshots)
    root = cfg.get("Root", {})
    enabled = bool(root.get("MFAEnabled"))
    return [
        NormalizedFinding(
            check_id="iam_root_mfa_enabled",
            source="custom",
            asset_arn=f"arn:aws:iam::{account_id(snapshots)}:root",
            title="Root account MFA enabled",
            description="The AWS root account must have MFA enabled.",
            severity="critical",
            status="PASS" if enabled else "FAIL",
            evidence={"Root": root},
            remediation="Enable a virtual or hardware MFA device on the root account.",
        )
    ]


@register_check("iam_root_no_access_keys")
def iam_root_no_access_keys(snapshots: dict[str, Any]) -> list[NormalizedFinding]:
    cfg = _iam_snapshots(snapshots)
    root = cfg.get("Root", {})
    present = bool(root.get("AccessKeysPresent"))
    return [
        NormalizedFinding(
            check_id="iam_root_no_access_keys",
            source="custom",
            asset_arn=f"arn:aws:iam::{account_id(snapshots)}:root",
            title="Root account has no access keys",
            description="Root access keys must not exist.",
            severity="critical",
            status="FAIL" if present else "PASS",
            evidence={"Root": root},
            remediation="Delete any root access keys and use IAM users/roles instead.",
        )
    ]


@register_check("iam_user_mfa_enabled")
def iam_user_mfa_enabled(snapshots: dict[str, Any]) -> list[NormalizedFinding]:
    cfg = _iam_snapshots(snapshots)
    findings: list[NormalizedFinding] = []
    for user in cfg.get("Users", []):
        has_mfa = bool(user.get("MFADevices"))
        findings.append(
            NormalizedFinding(
                check_id="iam_user_mfa_enabled",
                source="custom",
                asset_arn=user.get("Arn"),
                title=f"MFA enabled for IAM user {user.get('UserName')}",
                description="IAM users with console access should have MFA enabled.",
                severity="high",
                status="PASS" if has_mfa else "FAIL",
                evidence={"UserName": user.get("UserName"), "MFADevices": user.get("MFADevices", [])},
                remediation="Enable MFA for the IAM user in the AWS console.",
            )
        )
    if not findings:
        findings.append(
            NormalizedFinding(
                check_id="iam_user_mfa_enabled",
                source="custom",
                asset_arn=None,
                title="MFA enabled for IAM users",
                description="No IAM users found to assess.",
                severity="high",
                status="PASS",
                evidence={"Users": []},
                remediation="N/A",
            )
        )
    return findings


@register_check("iam_password_policy_strong")
def iam_password_policy_strong(snapshots: dict[str, Any]) -> list[NormalizedFinding]:
    cfg = _iam_snapshots(snapshots)
    policy = cfg.get("PasswordPolicy") or {}
    req = _risk_cfg().get("password_policy", {})
    checks = {
        "min_length": policy.get("MinimumPasswordLength", 0) >= req.get("min_length", 14),
        "symbols": policy.get("RequireSymbols") is True if req.get("require_symbols") else True,
        "numbers": policy.get("RequireNumbers") is True if req.get("require_numbers") else True,
        "upper": policy.get("RequireUppercaseCharacters") is True
        if req.get("require_uppercase")
        else True,
        "lower": policy.get("RequireLowercaseCharacters") is True
        if req.get("require_lowercase")
        else True,
    }
    ok = all(checks.values())
    return [
        NormalizedFinding(
            check_id="iam_password_policy_strong",
            source="custom",
            asset_arn=f"arn:aws:iam::{account_id(snapshots)}:root",
            title="Strong IAM password policy",
            description="Password policy must enforce length >= 14 and complexity.",
            severity="medium",
            status="PASS" if ok else "FAIL",
            evidence={"PasswordPolicy": policy, "Checks": checks},
            remediation="Update the account password policy to require 14+ chars and complexity.",
        )
    ]


@register_check("iam_access_key_rotated_90d")
def iam_access_key_rotated_90d(snapshots: dict[str, Any]) -> list[NormalizedFinding]:
    cfg = _iam_snapshots(snapshots)
    max_age = _risk_cfg().get("access_key_max_age_days", 90)
    now = datetime.now(timezone.utc)
    findings: list[NormalizedFinding] = []
    for user in cfg.get("Users", []):
        for key in user.get("AccessKeys", []):
            created = key.get("CreateDate")
            age_days = _age_days(created, now)
            stale = age_days is not None and age_days > max_age
            findings.append(
                NormalizedFinding(
                    check_id="iam_access_key_rotated_90d",
                    source="custom",
                    asset_arn=user.get("Arn"),
                    title=f"Access key rotation for {user.get('UserName')}",
                    description=f"Access keys must be rotated within {max_age} days.",
                    severity="medium",
                    status="FAIL" if stale else "PASS",
                    evidence={
                        "AccessKeyId": key.get("AccessKeyId"),
                        "CreateDate": str(created),
                        "AgeDays": age_days,
                    },
                    remediation="Rotate the access key and deactivate the old key.",
                )
            )
    if not findings:
        findings.append(
            NormalizedFinding(
                check_id="iam_access_key_rotated_90d",
                source="custom",
                asset_arn=None,
                title="Access key rotation",
                description="No access keys found.",
                severity="medium",
                status="PASS",
                evidence={},
                remediation="N/A",
            )
        )
    return findings


@register_check("iam_no_wildcard_admin_policy")
def iam_no_wildcard_admin_policy(snapshots: dict[str, Any]) -> list[NormalizedFinding]:
    cfg = _iam_snapshots(snapshots)
    wildcards = cfg.get("WildcardAdminPolicies", [])
    # Users with AdministratorAccess are reported per user by iam_user_no_admin_access.
    # Stable account-level ARN so PASS/FAIL map to the same risk register key
    return [
        NormalizedFinding(
            check_id="iam_no_wildcard_admin_policy",
            source="custom",
            asset_arn=f"arn:aws:iam::{account_id(snapshots)}:root",
            title="No wildcard (*:*) customer-managed IAM policies",
            description="Attached customer-managed policies must not grant Action:* on Resource:*.",
            severity="high",
            status="FAIL" if wildcards else "PASS",
            evidence={"WildcardAdminPolicies": wildcards},
            remediation="Replace Action:*/Resource:* statements with least-privilege policies.",
        )
    ]


@register_check("iam_user_no_admin_access")
def iam_user_no_admin_access(snapshots: dict[str, Any]) -> list[NormalizedFinding]:
    findings = []
    for user in _iam_snapshots(snapshots).get("Users", []):
        attached = [p.get("PolicyName") for p in user.get("AttachedPolicies", [])]
        is_admin = "AdministratorAccess" in attached
        findings.append(
            NormalizedFinding(
                check_id="iam_user_no_admin_access",
                source="custom",
                asset_arn=user.get("Arn"),
                title=f"IAM user {user.get('UserName')} has no AdministratorAccess",
                description=(
                    "Long-lived IAM users should not hold full administrator rights; use "
                    "short-lived roles (SSO / AssumeRole) for administration."
                ),
                severity="high",
                status="FAIL" if is_admin else "PASS",
                evidence={"UserName": user.get("UserName"), "AttachedPolicies": attached},
                remediation="Detach AdministratorAccess and grant admin through an assumable role instead.",
            )
        )
    return findings or _no_users("iam_user_no_admin_access", "No IAM users with AdministratorAccess", "high")


@register_check("iam_no_user_attached_policies")
def iam_no_user_attached_policies(snapshots: dict[str, Any]) -> list[NormalizedFinding]:
    findings = []
    for user in _iam_snapshots(snapshots).get("Users", []):
        attached = [p.get("PolicyName") for p in user.get("AttachedPolicies", [])]
        inline = list(user.get("InlinePolicyNames", []))
        findings.append(
            NormalizedFinding(
                check_id="iam_no_user_attached_policies",
                source="custom",
                asset_arn=user.get("Arn"),
                title=f"IAM user {user.get('UserName')} gets permissions only through groups/roles",
                description="Permissions should be granted via groups or roles, not policies attached directly to users.",
                severity="low",
                status="FAIL" if attached or inline else "PASS",
                evidence={"UserName": user.get("UserName"), "AttachedPolicies": attached,
                          "InlinePolicies": inline},
                remediation="Move the user's policies to an IAM group and add the user to that group.",
            )
        )
    return findings or _no_users(
        "iam_no_user_attached_policies", "IAM permissions granted through groups", "low"
    )


@register_check("iam_unused_credentials_90d")
def iam_unused_credentials_90d(snapshots: dict[str, Any]) -> list[NormalizedFinding]:
    max_age = _risk_cfg().get("access_key_max_age_days", 90)
    now = datetime.now(timezone.utc)
    findings = []
    for user in _iam_snapshots(snapshots).get("Users", []):
        stale: list[str] = []
        user_age = _age_days(user.get("CreateDate"), now)
        if user.get("HasConsolePassword"):
            pw_age = _age_days(user.get("PasswordLastUsed"), now)
            if (pw_age is None and (user_age or 0) > max_age) or (pw_age or 0) > max_age:
                stale.append("console password" + (" never used" if pw_age is None else f" unused {pw_age}d"))
        for key in user.get("AccessKeys", []):
            if key.get("Status", "Active") != "Active":
                continue
            used_age = _age_days((key.get("LastUsed") or {}).get("LastUsedDate"), now)
            key_age = _age_days(key.get("CreateDate"), now)
            if (used_age is None and (key_age or 0) > max_age) or (used_age or 0) > max_age:
                stale.append(f"access key {key.get('AccessKeyId')}"
                             + (" never used" if used_age is None else f" unused {used_age}d"))
        findings.append(
            NormalizedFinding(
                check_id="iam_unused_credentials_90d",
                source="custom",
                asset_arn=user.get("Arn"),
                title=f"No unused credentials for IAM user {user.get('UserName')}",
                description=f"Console passwords and access keys unused for {max_age}+ days should be disabled.",
                severity="medium",
                status="FAIL" if stale else "PASS",
                evidence={"UserName": user.get("UserName"), "Stale": stale,
                          "PasswordLastUsed": str(user.get("PasswordLastUsed"))},
                remediation="Disable the unused console password and deactivate/delete unused access keys.",
            )
        )
    return findings or _no_users("iam_unused_credentials_90d", "No unused IAM credentials", "medium")
