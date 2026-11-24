"""Read-only AWS configuration collector.

Only Describe*/List*/Get* calls are made (enforced by tests/test_collector.py).
Each service is collected independently: a failure (e.g. AccessDenied) is recorded
in the returned errors and the scan continues with the remaining services.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError
from sqlalchemy.orm import Session

from app.config import EVIDENCE_DIR, get_settings
from app.models import Asset, Evidence, Scan, Snapshot

logger = logging.getLogger(__name__)

Progress = Callable[[str], None]
# service -> {"messages": [...], "complete": bool}; complete=True means no data was collected
CollectErrors = dict[str, dict[str, Any]]


def _sha256_payload(payload: Any) -> str:
    raw = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def resolve_regions(session: boto3.Session, cli_regions: tuple[str, ...] | list[str] = ()) -> list[str]:
    """CLI --region > AWS_REGIONS > profile default region > all enabled regions."""
    if cli_regions:
        return list(cli_regions)
    env_regions = [r.strip() for r in get_settings().aws_regions.split(",") if r.strip()]
    if env_regions:
        return env_regions
    if session.region_name:
        return [session.region_name]
    ec2 = session.client("ec2", region_name="us-east-1")
    return sorted(r["RegionName"] for r in ec2.describe_regions()["Regions"])


def _paginate(client, op: str, key: str, **kwargs) -> list:
    out: list = []
    for page in client.get_paginator(op).paginate(**kwargs):
        out.extend(page.get(key, []))
    return out


def _upsert_asset(
    db: Session,
    *,
    arn: str,
    type_: str,
    service: str,
    name: str,
    region: str,
    criticality: int = 2,
    exposure: str = "private",
    owner: str | None = None,
    tags: dict | None = None,
) -> Asset:
    asset = db.query(Asset).filter(Asset.arn == arn).first()
    if asset is None:
        asset = Asset(arn=arn)
        db.add(asset)
    asset.type = type_
    asset.service = service
    asset.name = name
    asset.region = region
    asset.criticality = criticality
    asset.exposure = exposure
    asset.owner = owner
    asset.tags_json = tags or {}
    db.flush()
    return asset


def _store_snapshot(db: Session, scan: Scan, service: str, resource_id: str, config: dict) -> Snapshot:
    # boto3 returns datetimes; the JSON column needs plain JSON types.
    config = json.loads(json.dumps(config, default=str))
    snap = Snapshot(
        scan_id=scan.id,
        service=service,
        resource_id=resource_id,
        config_json=config,
        collected_at=_utcnow(),
    )
    db.add(snap)
    db.flush()

    digest = _sha256_payload(config)
    safe_rid = resource_id.replace("/", "_").replace(":", "_")
    evidence_path = EVIDENCE_DIR / f"scan_{scan.id}" / f"{service}_{snap.id}_{safe_rid}.json"
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    evidence_path.write_text(json.dumps(config, indent=2, default=str), encoding="utf-8")
    db.add(
        Evidence(
            scan_id=scan.id,
            finding_id=None,
            kind="snapshot",
            path_or_json=str(evidence_path),
            sha256=digest,
        )
    )
    return snap


def _criticality_from_tags(tags: dict | None) -> int:
    if not tags:
        return 2
    raw = tags.get("criticality") or tags.get("Criticality")
    try:
        val = int(raw)
        return val if val in (1, 2, 3) else 2
    except (TypeError, ValueError):
        return 2


def _is_wildcard_admin(document: dict) -> bool:
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for st in statements:
        if st.get("Effect") != "Allow":
            continue
        actions = st.get("Action", [])
        resources = st.get("Resource", [])
        actions = [actions] if isinstance(actions, str) else actions
        resources = [resources] if isinstance(resources, str) else resources
        if "*" in actions and "*" in resources:
            return True
    return False


# --- global services -------------------------------------------------------


def _collect_iam(db: Session, scan: Scan, session: boto3.Session, account_id: str) -> str:
    iam = session.client("iam")
    account_summary = iam.get_account_summary().get("SummaryMap", {})
    try:
        password_policy = iam.get_account_password_policy().get("PasswordPolicy", {})
    except iam.exceptions.NoSuchEntityException:
        password_policy = {}

    users_detail = []
    for user in _paginate(iam, "list_users", "Users"):
        uname = user["UserName"]
        mfa = _paginate(iam, "list_mfa_devices", "MFADevices", UserName=uname)
        keys = _paginate(iam, "list_access_keys", "AccessKeyMetadata", UserName=uname)
        key_details = []
        for key in keys:
            last_used = iam.get_access_key_last_used(AccessKeyId=key["AccessKeyId"]).get(
                "AccessKeyLastUsed", {}
            )
            key_details.append({**key, "LastUsed": last_used})
        attached = _paginate(iam, "list_attached_user_policies", "AttachedPolicies", UserName=uname)
        users_detail.append(
            {**user, "MFADevices": mfa, "AccessKeys": key_details, "AttachedPolicies": attached}
        )
        is_admin = any(p.get("PolicyName") == "AdministratorAccess" for p in attached)
        _upsert_asset(
            db,
            arn=user["Arn"],
            type_="iam-user",
            service="iam",
            name=uname,
            region="global",
            criticality=3 if is_admin else 2,
            exposure="internal",
        )

    # Customer-managed policies granting Action:* on Resource:*
    wildcard_policies = []
    for pol in _paginate(iam, "list_policies", "Policies", Scope="Local", OnlyAttached=True):
        version = iam.get_policy_version(
            PolicyArn=pol["Arn"], VersionId=pol["DefaultVersionId"]
        )["PolicyVersion"]
        doc = version.get("Document", {})
        if isinstance(doc, str):
            doc = json.loads(doc)
        if _is_wildcard_admin(doc):
            wildcard_policies.append({"PolicyName": pol["PolicyName"], "Arn": pol["Arn"]})

    keys_present = bool(account_summary.get("AccountAccessKeysPresent", 0))
    iam_config = {
        "AccountId": account_id,
        "AccountSummary": account_summary,
        "PasswordPolicy": password_policy,
        "Users": users_detail,
        "WildcardAdminPolicies": wildcard_policies,
        "Root": {
            "MFAEnabled": bool(account_summary.get("AccountMFAEnabled", 0)),
            "AccessKeysPresent": keys_present,
            "AccessKeys": [{"present": keys_present}],
        },
    }
    _store_snapshot(db, scan, "iam", "account", iam_config)
    _upsert_asset(
        db,
        arn=f"arn:aws:iam::{account_id}:root",
        type_="iam-root",
        service="iam",
        name="root",
        region="global",
        criticality=3,
        exposure="internal",
    )
    return f"{len(users_detail)} users"


def _collect_s3(db: Session, scan: Scan, session: boto3.Session, account_id: str) -> str:
    s3 = session.client("s3")
    buckets = s3.list_buckets().get("Buckets", [])
    for bucket in buckets:
        name = bucket["Name"]
        cfg: dict[str, Any] = {"Name": name, "CreationDate": str(bucket.get("CreationDate"))}
        try:
            region = s3.get_bucket_location(Bucket=name).get("LocationConstraint") or "us-east-1"
        except ClientError:
            region = "unknown"
        cfg["Region"] = region
        # Missing configuration raises ClientError (e.g. NoSuchBucketPolicy) -> treat as unset.
        lookups = [
            ("PublicAccessBlock", lambda: s3.get_public_access_block(Bucket=name).get(
                "PublicAccessBlockConfiguration", {}), {}),
            ("Encryption", lambda: s3.get_bucket_encryption(Bucket=name).get(
                "ServerSideEncryptionConfiguration", {}), {}),
            ("Versioning", lambda: s3.get_bucket_versioning(Bucket=name), {}),
            ("Logging", lambda: s3.get_bucket_logging(Bucket=name).get("LoggingEnabled"), None),
            ("Policy", lambda: s3.get_bucket_policy(Bucket=name).get("Policy"), None),
            ("ACL", lambda: s3.get_bucket_acl(Bucket=name), {}),
        ]
        for key, fn, default in lookups:
            try:
                cfg[key] = fn()
            except ClientError:
                cfg[key] = default
        for key in ("Versioning", "ACL"):
            cfg[key].pop("ResponseMetadata", None)

        pab = cfg.get("PublicAccessBlock") or {}
        is_public = not all(
            pab.get(k, False)
            for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
        )
        _upsert_asset(
            db,
            arn=f"arn:aws:s3:::{name}",
            type_="s3-bucket",
            service="s3",
            name=name,
            region=region,
            criticality=2,
            exposure="public" if is_public else "private",
        )
        _store_snapshot(db, scan, "s3", name, cfg)
    return f"{len(buckets)} buckets"


def _collect_cloudtrail(db: Session, scan: Scan, session: boto3.Session, region: str) -> str:
    ct = session.client("cloudtrail", region_name=region)
    trails = ct.describe_trails(includeShadowTrails=True).get("trailList", [])
    trail_status = []
    for trail in trails:
        status = ct.get_trail_status(Name=trail.get("TrailARN") or trail["Name"])
        status.pop("ResponseMetadata", None)
        trail_status.append({**trail, "Status": status})
    _store_snapshot(db, scan, "cloudtrail", "trails", {"Trails": trail_status})
    return f"{len(trails)} trails"


# --- regional services -----------------------------------------------------


def _collect_ec2(db, scan, session, regions, account_id, errors) -> str:
    vpcs: list[dict] = []
    flow_logs: list[dict] = []
    ebs_default: dict[str, bool] = {}
    volumes: list[dict] = []
    sg_count = 0
    for region in regions:
        try:
            ec2 = session.client("ec2", region_name=region)
            for sg in _paginate(ec2, "describe_security_groups", "SecurityGroups"):
                open_world = any(
                    r.get("CidrIp") == "0.0.0.0/0"
                    for perm in sg.get("IpPermissions", [])
                    for r in perm.get("IpRanges", [])
                )
                arn = f"arn:aws:ec2:{region}:{sg.get('OwnerId', account_id)}:security-group/{sg['GroupId']}"
                _upsert_asset(
                    db,
                    arn=arn,
                    type_="security-group",
                    service="ec2",
                    name=sg.get("GroupName", sg["GroupId"]),
                    region=region,
                    exposure="public" if open_world else "private",
                )
                _store_snapshot(db, scan, "ec2", sg["GroupId"], {"SecurityGroup": sg, "Region": region, "Arn": arn})
                sg_count += 1
            vpcs += [
                {"VpcId": v["VpcId"], "OwnerId": v.get("OwnerId", account_id), "Region": region}
                for v in _paginate(ec2, "describe_vpcs", "Vpcs")
            ]
            flow_logs += [{**fl, "Region": region} for fl in _paginate(ec2, "describe_flow_logs", "FlowLogs")]
            ebs_default[region] = bool(ec2.get_ebs_encryption_by_default().get("EbsEncryptionByDefault"))
            volumes += [{**v, "Region": region} for v in _paginate(ec2, "describe_volumes", "Volumes")]
        except Exception as exc:  # noqa: BLE001
            _record_error(errors, "ec2", region, exc)
    _store_snapshot(db, scan, "ec2", "vpc-flow-logs", {"Vpcs": vpcs, "FlowLogs": flow_logs})
    _store_snapshot(db, scan, "ec2", "ebs-default-encryption", {"Regions": ebs_default})
    _store_snapshot(db, scan, "ec2", "ebs-volumes", {"Volumes": volumes})
    return f"{sg_count} security groups, {len(vpcs)} VPCs"


def _collect_guardduty(db, scan, session, regions, account_id, errors) -> str:
    by_region: dict[str, list[str]] = {}
    for region in regions:
        try:
            gd = session.client("guardduty", region_name=region)
            by_region[region] = _paginate(gd, "list_detectors", "DetectorIds")
        except Exception as exc:  # noqa: BLE001
            _record_error(errors, "guardduty", region, exc)
    _store_snapshot(db, scan, "guardduty", "detectors", {"Regions": by_region})
    return f"enabled in {sum(1 for d in by_region.values() if d)}/{len(by_region)} regions"


def _collect_kms(db, scan, session, regions, account_id, errors) -> str:
    key_details = []
    for region in regions:
        try:
            kms = session.client("kms", region_name=region)
            for key in _paginate(kms, "list_keys", "Keys"):
                kid = key["KeyId"]
                meta = kms.describe_key(KeyId=kid).get("KeyMetadata", {})
                rotation = False
                # Rotation status only applies to enabled, symmetric customer-managed keys.
                if meta.get("KeyManager") == "CUSTOMER" and meta.get("KeyState") == "Enabled":
                    try:
                        rotation = kms.get_key_rotation_status(KeyId=kid).get("KeyRotationEnabled", False)
                    except ClientError:
                        pass
                key_details.append({**meta, "KeyRotationEnabled": rotation, "Region": region})
                if meta.get("KeyManager") == "CUSTOMER":
                    _upsert_asset(
                        db,
                        arn=meta.get("Arn", f"arn:aws:kms:{region}:{account_id}:key/{kid}"),
                        type_="kms-key",
                        service="kms",
                        name=meta.get("Description") or kid,
                        region=region,
                    )
        except Exception as exc:  # noqa: BLE001
            _record_error(errors, "kms", region, exc)
    _store_snapshot(db, scan, "kms", "keys", {"Keys": key_details})
    customer = sum(1 for k in key_details if k.get("KeyManager") == "CUSTOMER")
    return f"{customer} customer-managed keys"


def _collect_rds(db, scan, session, regions, account_id, errors) -> str:
    count = 0
    for region in regions:
        try:
            rds = session.client("rds", region_name=region)
            for inst in _paginate(rds, "describe_db_instances", "DBInstances"):
                ident = inst["DBInstanceIdentifier"]
                arn = inst.get("DBInstanceArn") or f"arn:aws:rds:{region}:{account_id}:db:{ident}"
                _upsert_asset(
                    db,
                    arn=arn,
                    type_="rds-instance",
                    service="rds",
                    name=ident,
                    region=region,
                    criticality=_criticality_from_tags(
                        {t["Key"]: t["Value"] for t in inst.get("TagList", [])}
                    ),
                    exposure="public" if inst.get("PubliclyAccessible") else "private",
                )
                _store_snapshot(db, scan, "rds", f"{region}/{ident}", {"DBInstance": inst})
                count += 1
        except Exception as exc:  # noqa: BLE001
            _record_error(errors, "rds", region, exc)
    return f"{count} DB instances"


def _record_error(errors: CollectErrors, service: str, region: str | None, exc: Exception) -> None:
    msg = f"{region}: {exc}" if region else str(exc)
    logger.warning("Collect %s failed: %s", service, msg)
    entry = errors.setdefault(service, {"messages": [], "failed_regions": 0, "complete": False})
    entry["messages"].append(msg)
    if region is None:
        entry["complete"] = True
    else:
        entry["failed_regions"] += 1


def collect(
    db: Session,
    scan: Scan,
    *,
    session: boto3.Session,
    regions: list[str],
    account_id: str,
    progress: Progress = lambda _msg: None,
) -> tuple[list[Snapshot], CollectErrors]:
    """Collect AWS configuration into snapshots. Returns (snapshots, errors)."""
    errors: CollectErrors = {}
    home_region = session.region_name or regions[0]

    global_steps = [
        ("IAM", "iam", lambda: _collect_iam(db, scan, session, account_id)),
        ("S3", "s3", lambda: _collect_s3(db, scan, session, account_id)),
        ("CloudTrail", "cloudtrail", lambda: _collect_cloudtrail(db, scan, session, home_region)),
    ]
    regional_steps = [
        ("EC2/VPC", "ec2", _collect_ec2),
        ("GuardDuty", "guardduty", _collect_guardduty),
        ("KMS", "kms", _collect_kms),
        ("RDS", "rds", _collect_rds),
    ]

    for label, service, fn in global_steps:
        try:
            progress(f"  {label:<10} ok ({fn()})")
        except Exception as exc:  # noqa: BLE001
            _record_error(errors, service, None, exc)
            progress(f"  {label:<10} ERROR ({exc})")
        db.flush()

    for label, service, fn in regional_steps:
        summary = fn(db, scan, session, regions, account_id, errors)
        err = errors.get(service)
        if err and err["failed_regions"] >= len(regions):
            err["complete"] = True
        if err:
            state = "ERROR" if err["complete"] else f"partial ({err['failed_regions']} region(s) failed)"
            progress(f"  {label:<10} {state}: {err['messages'][0]}")
        else:
            progress(f"  {label:<10} ok ({summary})")
        db.flush()

    snapshots = db.query(Snapshot).filter(Snapshot.scan_id == scan.id).all()
    return snapshots, errors
