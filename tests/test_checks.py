from app.assessment.engine import apply_collect_errors, run_custom_checks

REQUIRED = {
    "iam_root_mfa_enabled", "iam_root_no_access_keys", "iam_user_mfa_enabled",
    "iam_password_policy_strong", "iam_access_key_rotated_90d", "iam_no_wildcard_admin_policy",
    "s3_public_access_blocked", "s3_encryption_enabled", "s3_versioning_enabled", "s3_tls_only_policy",
    "sg_no_ssh_open_world", "sg_no_rdp_open_world", "sg_no_all_traffic_open_world",
    "vpc_flow_logs_enabled", "cloudtrail_enabled_multiregion", "cloudtrail_log_validation",
    "guardduty_enabled", "ebs_default_encryption", "rds_encrypted", "kms_key_rotation_enabled",
    "ec2_imdsv2_required", "ec2_no_public_snapshots", "rds_not_public", "iam_user_no_admin_access",
    "iam_no_user_attached_policies", "iam_unused_credentials_90d", "sg_default_restricts_all",
}
ACCT = "111122223333"
USER_ARN = f"arn:aws:iam::{ACCT}:user/alice"
SG_ARN = f"arn:aws:ec2:eu-west-1:{ACCT}:security-group/sg-1"
INSTANCE_ARN = f"arn:aws:ec2:eu-west-1:{ACCT}:instance/i-1"
SNAP_ARN = f"arn:aws:ec2:eu-west-1:{ACCT}:snapshot/snap-1"
OLD = "2020-01-01 00:00:00+00:00"
TLS_POLICY = (
    '{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"*",'
    '"Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}'
)
PAB_ON = {k: True for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")}


def insecure() -> dict:
    return {
        "iam": {"account": {
            "AccountId": ACCT,
            "PasswordPolicy": {"MinimumPasswordLength": 8},
            "Root": {"MFAEnabled": False, "AccessKeysPresent": True},
            "WildcardAdminPolicies": [{"PolicyName": "god", "Arn": "x"}],
            "Users": [{
                "UserName": "alice", "Arn": USER_ARN, "MFADevices": [], "CreateDate": OLD,
                "AccessKeys": [{"AccessKeyId": "AKIA1", "CreateDate": OLD, "Status": "Active", "LastUsed": {}}],
                "AttachedPolicies": [{"PolicyName": "AdministratorAccess"}],
                "InlinePolicyNames": ["inline-admin"], "HasConsolePassword": True, "PasswordLastUsed": OLD,
            }],
        }},
        "s3": {"logs": {"Name": "logs", "PublicAccessBlock": {}, "Encryption": {}, "Versioning": {}, "Policy": None}},
        "ec2": {
            "sg-1": {"Arn": SG_ARN, "Region": "eu-west-1", "SecurityGroup": {"GroupId": "sg-1", "GroupName": "default", "IpPermissions": [
                {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                {"IpProtocol": "tcp", "FromPort": 0, "ToPort": 65535, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
            ]}},
            "vpc-flow-logs": {"Vpcs": [{"VpcId": "vpc-1", "Region": "eu-west-1", "OwnerId": ACCT}], "FlowLogs": []},
            "ebs-default-encryption": {"Regions": {"eu-west-1": False}},
            "instances": {"Instances": [{"InstanceId": "i-1", "Arn": INSTANCE_ARN, "Region": "eu-west-1",
                                         "MetadataOptions": {"HttpTokens": "optional", "HttpEndpoint": "enabled"}}]},
            "snapshots-images": {"Snapshots": [{"SnapshotId": "snap-1", "Arn": SNAP_ARN, "Public": True}], "Images": []},
        },
        "cloudtrail": {"trails": {"Trails": [{"Name": "t", "IsMultiRegionTrail": True,
                                              "LogFileValidationEnabled": False, "Status": {"IsLogging": False}}]}},
        "guardduty": {"detectors": {"Regions": {"eu-west-1": []}}},
        "kms": {"keys": {"Keys": [{"KeyId": "k1", "Arn": "arn:k1", "KeyManager": "CUSTOMER", "KeyRotationEnabled": False}]}},
        "rds": {"eu-west-1/db1": {"DBInstance": {"DBInstanceIdentifier": "db1", "StorageEncrypted": False, "PubliclyAccessible": True}}},
    }


def secure() -> dict:
    return {
        "iam": {"account": {
            "AccountId": ACCT,
            "PasswordPolicy": {"MinimumPasswordLength": 14, "RequireSymbols": True, "RequireNumbers": True,
                               "RequireUppercaseCharacters": True, "RequireLowercaseCharacters": True},
            "Root": {"MFAEnabled": True, "AccessKeysPresent": False},
            "WildcardAdminPolicies": [],
            "Users": [{"UserName": "alice", "Arn": USER_ARN, "MFADevices": [{"SerialNumber": "m"}],
                       "AccessKeys": [], "AttachedPolicies": []}],
        }},
        "s3": {"logs": {"Name": "logs", "PublicAccessBlock": PAB_ON,
                        "Encryption": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]},
                        "Versioning": {"Status": "Enabled"}, "Policy": TLS_POLICY}},
        "ec2": {
            "sg-1": {"Arn": SG_ARN, "Region": "eu-west-1", "SecurityGroup": {"GroupId": "sg-1", "GroupName": "default",
                                                                   "IpPermissions": [], "IpPermissionsEgress": []}},
            "vpc-flow-logs": {"Vpcs": [{"VpcId": "vpc-1", "Region": "eu-west-1", "OwnerId": ACCT}],
                              "FlowLogs": [{"ResourceId": "vpc-1"}]},
            "ebs-default-encryption": {"Regions": {"eu-west-1": True}},
            "instances": {"Instances": [{"InstanceId": "i-1", "Arn": INSTANCE_ARN, "Region": "eu-west-1",
                                         "MetadataOptions": {"HttpTokens": "required"}}]},
            "snapshots-images": {"Snapshots": [{"SnapshotId": "snap-1", "Arn": SNAP_ARN, "Public": False}], "Images": []},
        },
        "cloudtrail": {"trails": {"Trails": [{"Name": "t", "IsMultiRegionTrail": True,
                                              "LogFileValidationEnabled": True, "Status": {"IsLogging": True}}]}},
        "guardduty": {"detectors": {"Regions": {"eu-west-1": ["d1"]}}},
        "kms": {"keys": {"Keys": [{"KeyId": "k1", "Arn": "arn:k1", "KeyManager": "CUSTOMER", "KeyRotationEnabled": True}]}},
        "rds": {"eu-west-1/db1": {"DBInstance": {"DBInstanceIdentifier": "db1", "StorageEncrypted": True, "PubliclyAccessible": False}}},
    }


def test_insecure_account_fails_every_check():
    findings = run_custom_checks(insecure())
    failed = {f.check_id for f in findings if f.status == "FAIL"}
    assert failed == REQUIRED
    assert not [f for f in findings if f.status == "ERROR"]


def test_secure_account_passes_every_check():
    findings = run_custom_checks(secure())
    assert {f.check_id for f in findings} == REQUIRED
    assert all(f.status == "PASS" for f in findings), [f.check_id for f in findings if f.status != "PASS"]


def test_findings_use_real_account_and_region_arns():
    by_check = {f.check_id: f for f in run_custom_checks(insecure())}
    assert by_check["iam_root_mfa_enabled"].asset_arn == f"arn:aws:iam::{ACCT}:root"
    assert by_check["sg_no_ssh_open_world"].asset_arn == SG_ARN
    assert by_check["guardduty_enabled"].asset_arn == f"arn:aws:guardduty:eu-west-1:{ACCT}:detector"


def test_stopped_multiregion_trail_fails():
    findings = run_custom_checks(insecure())
    trail = next(f for f in findings if f.check_id == "cloudtrail_enabled_multiregion")
    assert trail.status == "FAIL"


def test_failed_service_becomes_error_not_pass():
    snaps = secure()
    snaps["ec2"] = {}  # nothing collected
    findings = apply_collect_errors(
        run_custom_checks(snaps), {"ec2": {"messages": ["AccessDenied"], "complete": True}}
    )
    ec2_checks = [f for f in findings if f.check_id.startswith(("sg_", "vpc_", "ebs_", "ec2_"))]
    assert ec2_checks and all(f.status == "ERROR" for f in ec2_checks)
    assert all(f.status == "PASS" for f in findings if f.check_id.startswith("iam_"))


def test_every_check_is_mapped_and_catalogued():
    import yaml

    from app.assessment import catalog
    from app.assessment.registry import get_registered_checks
    from app.config import DATA_DIR

    run_custom_checks({})  # registers checks
    mapping = yaml.safe_load((DATA_DIR / "frameworks" / "mapping.yaml").read_text(encoding="utf-8"))
    for check_id in get_registered_checks():
        assert mapping.get(check_id), f"{check_id} missing from mapping.yaml"
        meta = catalog.entry(check_id)
        assert meta.get("domain") in catalog.DOMAINS, check_id
        assert meta.get("service_model") in catalog.SERVICE_MODELS, check_id
        assert meta.get("cli") and meta.get("console"), check_id
        assert isinstance(meta.get("internet_exposure"), bool), check_id


def test_recently_used_credentials_pass():
    from datetime import datetime, timezone

    snaps = secure()
    now = datetime.now(timezone.utc).isoformat()
    snaps["iam"]["account"]["Users"][0].update(
        {"HasConsolePassword": True, "PasswordLastUsed": now, "CreateDate": OLD,
         "AccessKeys": [{"AccessKeyId": "AKIA2", "CreateDate": OLD, "Status": "Active",
                         "LastUsed": {"LastUsedDate": now}}]}
    )
    finding = next(f for f in run_custom_checks(snaps) if f.check_id == "iam_unused_credentials_90d")
    assert finding.status == "PASS", finding.evidence
