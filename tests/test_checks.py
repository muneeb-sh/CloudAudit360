from app.assessment.engine import apply_collect_errors, run_custom_checks

REQUIRED = {
    "iam_root_mfa_enabled", "iam_root_no_access_keys", "iam_user_mfa_enabled",
    "iam_password_policy_strong", "iam_access_key_rotated_90d", "iam_no_wildcard_admin_policy",
    "s3_public_access_blocked", "s3_encryption_enabled", "s3_versioning_enabled", "s3_tls_only_policy",
    "sg_no_ssh_open_world", "sg_no_rdp_open_world", "sg_no_all_traffic_open_world",
    "vpc_flow_logs_enabled", "cloudtrail_enabled_multiregion", "cloudtrail_log_validation",
    "guardduty_enabled", "ebs_default_encryption", "rds_encrypted", "kms_key_rotation_enabled",
}
ACCT = "111122223333"
USER_ARN = f"arn:aws:iam::{ACCT}:user/alice"
SG_ARN = f"arn:aws:ec2:eu-west-1:{ACCT}:security-group/sg-1"
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
                "UserName": "alice", "Arn": USER_ARN, "MFADevices": [],
                "AccessKeys": [{"AccessKeyId": "AKIA1", "CreateDate": "2020-01-01 00:00:00+00:00"}],
                "AttachedPolicies": [{"PolicyName": "AdministratorAccess"}],
            }],
        }},
        "s3": {"logs": {"Name": "logs", "PublicAccessBlock": {}, "Encryption": {}, "Versioning": {}, "Policy": None}},
        "ec2": {
            "sg-1": {"Arn": SG_ARN, "Region": "eu-west-1", "SecurityGroup": {"GroupId": "sg-1", "IpPermissions": [
                {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                {"IpProtocol": "tcp", "FromPort": 0, "ToPort": 65535, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
            ]}},
            "vpc-flow-logs": {"Vpcs": [{"VpcId": "vpc-1", "Region": "eu-west-1", "OwnerId": ACCT}], "FlowLogs": []},
            "ebs-default-encryption": {"Regions": {"eu-west-1": False}},
        },
        "cloudtrail": {"trails": {"Trails": [{"Name": "t", "IsMultiRegionTrail": True,
                                              "LogFileValidationEnabled": False, "Status": {"IsLogging": False}}]}},
        "guardduty": {"detectors": {"Regions": {"eu-west-1": []}}},
        "kms": {"keys": {"Keys": [{"KeyId": "k1", "Arn": "arn:k1", "KeyManager": "CUSTOMER", "KeyRotationEnabled": False}]}},
        "rds": {"eu-west-1/db1": {"DBInstance": {"DBInstanceIdentifier": "db1", "StorageEncrypted": False}}},
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
            "sg-1": {"Arn": SG_ARN, "Region": "eu-west-1", "SecurityGroup": {"GroupId": "sg-1", "IpPermissions": []}},
            "vpc-flow-logs": {"Vpcs": [{"VpcId": "vpc-1", "Region": "eu-west-1", "OwnerId": ACCT}],
                              "FlowLogs": [{"ResourceId": "vpc-1"}]},
            "ebs-default-encryption": {"Regions": {"eu-west-1": True}},
        },
        "cloudtrail": {"trails": {"Trails": [{"Name": "t", "IsMultiRegionTrail": True,
                                              "LogFileValidationEnabled": True, "Status": {"IsLogging": True}}]}},
        "guardduty": {"detectors": {"Regions": {"eu-west-1": ["d1"]}}},
        "kms": {"keys": {"Keys": [{"KeyId": "k1", "Arn": "arn:k1", "KeyManager": "CUSTOMER", "KeyRotationEnabled": True}]}},
        "rds": {"eu-west-1/db1": {"DBInstance": {"DBInstanceIdentifier": "db1", "StorageEncrypted": True}}},
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
    ec2_checks = [f for f in findings if f.check_id.startswith(("sg_", "vpc_", "ebs_"))]
    assert ec2_checks and all(f.status == "ERROR" for f in ec2_checks)
    assert all(f.status == "PASS" for f in findings if f.check_id.startswith("iam_"))
