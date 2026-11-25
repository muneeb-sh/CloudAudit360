"""Seed a local moto_server with a realistic mix of secure and insecure AWS resources.

Writes ONLY to the fake AWS at --endpoint (default http://127.0.0.1:5000). It refuses
any endpoint that is not localhost, so it can never touch a real AWS account.

Usage (PowerShell, from the CloudAudit360 folder):
    # terminal 1, leave running. Skipping moto's ~1000 built-in AMIs/snapshots keeps results readable;
    # loading managed policies gives the real AWS AdministratorAccess policy.
    $env:MOTO_EC2_LOAD_DEFAULT_AMIS = "false"; $env:MOTO_IAM_LOAD_MANAGED_POLICIES = "true"
    .venv\\Scripts\\moto_server.exe

    # terminal 2
    .venv\\Scripts\\python ..\\..\\seed_moto.py --reset
    # then set the env vars this script prints and run the scan

Designed to light up every CloudAudit360 feature: each check gets at least one FAIL and,
where moto allows it, one PASS; the Attack Surface page gets open ports, public data
stores and IMDSv1 instances; two regions exercise the per-region checks.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from urllib.parse import urlparse

import boto3
from botocore.exceptions import ClientError

HOME = "us-east-1"
SECOND = "eu-west-1"
REGIONS = (HOME, SECOND)
ACCOUNT = "123456789012"  # moto's default account

parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("--endpoint", default="http://127.0.0.1:5000", help="moto_server URL")
parser.add_argument("--reset", action="store_true", help="wipe all moto state before seeding")
args = parser.parse_args()

ENDPOINT = args.endpoint.rstrip("/")
if urlparse(ENDPOINT).hostname not in ("127.0.0.1", "localhost", "::1"):
    sys.exit(f"Refusing to seed {ENDPOINT}: only a local moto_server is allowed.")

# Explicit fake credentials + endpoint on every client: ignores AWS_PROFILE and real keys.
session = boto3.Session(aws_access_key_id="testing", aws_secret_access_key="testing", region_name=HOME)


def client(service: str, region: str = HOME):
    return session.client(service, region_name=region, endpoint_url=ENDPOINT)


def step(msg: str) -> None:
    print(f"  - {msg}")


try:
    if args.reset:
        urllib.request.urlopen(urllib.request.Request(f"{ENDPOINT}/moto-api/reset", method="POST"), timeout=10)
        print("moto state reset.")
    iam = client("iam")
    iam.get_user(UserName="alice")
    sys.exit("Already seeded (user 'alice' exists). Re-run with --reset to start over.")
except ClientError:
    pass  # NoSuchEntity: fresh server, carry on
except OSError as exc:
    sys.exit(f"Cannot reach moto_server at {ENDPOINT} ({exc}). Start .venv\\Scripts\\moto_server.exe first.")

print(f"Seeding fake AWS account {ACCOUNT} at {ENDPOINT}")

# ---------------------------------------------------------------- IAM (Account-wide)
print("IAM")
iam.update_account_password_policy(MinimumPasswordLength=8)  # weak -> iam_password_policy_strong FAIL
step("weak password policy (8 chars, no complexity)")

wildcard = iam.create_policy(PolicyName="AdminStar", PolicyDocument=json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}))["Policy"]
scoped = iam.create_policy(PolicyName="S3ReadReports", PolicyDocument=json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"],
                   "Resource": ["arn:aws:s3:::finance-reports", "arn:aws:s3:::finance-reports/*"]}]}))["Policy"]

# Good practice: permissions through a group
iam.create_group(GroupName="analysts")
iam.attach_group_policy(GroupName="analysts", PolicyArn=scoped["Arn"])


def admin_access_arn() -> str:
    """AWS-managed AdministratorAccess if moto loaded managed policies, else a same-named local copy."""
    try:
        return iam.get_policy(PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")["Policy"]["Arn"]
    except ClientError:
        return iam.create_policy(PolicyName="AdministratorAccess", PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}))["Policy"]["Arn"]


ADMIN = admin_access_arn()


def mfa_for(user: str) -> None:
    dev = iam.create_virtual_mfa_device(VirtualMFADeviceName=f"{user}-mfa")["VirtualMFADevice"]
    iam.enable_mfa_device(UserName=user, SerialNumber=dev["SerialNumber"],
                          AuthenticationCode1="123456", AuthenticationCode2="654321")


# alice: the worst user - no MFA, console password, access key, wildcard + inline + AdministratorAccess
iam.create_user(UserName="alice", Tags=[{"Key": "team", "Value": "ops"}])
iam.create_login_profile(UserName="alice", Password="Summer2024!")
iam.create_access_key(UserName="alice")
iam.attach_user_policy(UserName="alice", PolicyArn=wildcard["Arn"])
iam.attach_user_policy(UserName="alice", PolicyArn=ADMIN)
iam.put_user_policy(UserName="alice", PolicyName="inline-ec2-all", PolicyDocument=json.dumps({
    "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "ec2:*", "Resource": "*"}]}))
step("alice: no MFA, AdministratorAccess, *:* policy, inline policy, access key")

# bob: the model user - MFA, console password, permissions only via group
iam.create_user(UserName="bob")
iam.create_login_profile(UserName="bob", Password="C0rrect-Horse-Battery!")
mfa_for("bob")
iam.add_user_to_group(GroupName="analysts", UserName="bob")
step("bob: MFA + group permissions (passes every IAM user check)")

# ci-deploy: machine user with a key, directly attached policy, no MFA
iam.create_user(UserName="ci-deploy")
iam.create_access_key(UserName="ci-deploy")
iam.attach_user_policy(UserName="ci-deploy", PolicyArn=scoped["Arn"])
step("ci-deploy: access key, policy attached directly, no MFA")

# carol: MFA but AdministratorAccess directly
iam.create_user(UserName="carol")
mfa_for("carol")
iam.attach_user_policy(UserName="carol", PolicyArn=ADMIN)
step("carol: MFA but AdministratorAccess on the user")

# ---------------------------------------------------------------- KMS (Abstracted)
print("KMS")
key_ids = {}
for region in REGIONS:
    kms = client("kms", region)
    good = kms.create_key(Description=f"app-data-{region} (rotated)")["KeyMetadata"]["KeyId"]
    kms.enable_key_rotation(KeyId=good)
    kms.create_key(Description=f"legacy-{region} (not rotated)")
    key_ids[region] = good
step("one rotated + one unrotated customer key per region")

# ---------------------------------------------------------------- S3 (Abstracted)
print("S3")
s3 = client("s3")
PAB_ALL = {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}


def tls_only(bucket: str, extra: list | None = None) -> str:
    return json.dumps({"Version": "2012-10-17", "Statement": [
        {"Sid": "DenyInsecureTransport", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
         "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
         "Condition": {"Bool": {"aws:SecureTransport": "false"}}}, *(extra or [])]})


def hardened_bucket(name: str, extra_policy: list | None = None) -> None:
    s3.create_bucket(Bucket=name)
    s3.put_public_access_block(Bucket=name, PublicAccessBlockConfiguration=PAB_ALL)
    s3.put_bucket_encryption(Bucket=name, ServerSideEncryptionConfiguration={"Rules": [
        {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms", "KMSMasterKeyID": key_ids[HOME]}}]})
    s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_policy(Bucket=name, Policy=tls_only(name, extra_policy))


hardened_bucket("audit-logs-central", [
    {"Sid": "CloudTrailWrite", "Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"},
     "Action": ["s3:GetBucketAcl", "s3:PutObject"],
     "Resource": ["arn:aws:s3:::audit-logs-central", "arn:aws:s3:::audit-logs-central/*"]}])
hardened_bucket("finance-reports")
step("audit-logs-central, finance-reports: fully hardened")

s3.create_bucket(Bucket="public-website-assets")  # no PAB, no encryption, no versioning, no TLS policy
s3.put_object(Bucket="public-website-assets", Key="index.html", Body=b"<h1>hello</h1>")
step("public-website-assets: no public access block / encryption / versioning / TLS")

s3.create_bucket(Bucket="customer-exports")
s3.put_public_access_block(Bucket="customer-exports", PublicAccessBlockConfiguration={
    **PAB_ALL, "BlockPublicPolicy": False, "RestrictPublicBuckets": False})  # partially open
s3.put_bucket_encryption(Bucket="customer-exports", ServerSideEncryptionConfiguration={"Rules": [
    {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]})
step("customer-exports: encrypted but public access block only half on, no versioning")

# ---------------------------------------------------------------- CloudTrail / GuardDuty
print("Logging & detection")
ct = client("cloudtrail")
ct.create_trail(Name="org-trail", S3BucketName="audit-logs-central", IsMultiRegionTrail=True,
                EnableLogFileValidation=True, IncludeGlobalServiceEvents=True)
ct.start_logging(Name="org-trail")
ct.create_trail(Name="legacy-trail", S3BucketName="audit-logs-central", IsMultiRegionTrail=False,
                EnableLogFileValidation=False)  # never started, no validation
step("org-trail: multi-region + validation; legacy-trail: single-region, no validation, stopped")
client("guardduty", HOME).create_detector(Enable=True)
step(f"GuardDuty on in {HOME}, OFF in {SECOND}")

# ---------------------------------------------------------------- EC2 / VPC / EBS (Infrastructure)
print("EC2 / VPC / EBS")


def default_vpc(ec2) -> str:
    return ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])["Vpcs"][0]["VpcId"]


def sg(ec2, vpc: str, name: str, desc: str, rules: list) -> str:
    gid = ec2.create_security_group(GroupName=name, Description=desc, VpcId=vpc)["GroupId"]
    if rules:
        ec2.authorize_security_group_ingress(GroupId=gid, IpPermissions=rules)
    return gid


def lock_default_sg(ec2, vpc: str) -> None:
    grp = ec2.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vpc]},
                                                {"Name": "group-name", "Values": ["default"]}])["SecurityGroups"][0]
    if grp.get("IpPermissions"):
        ec2.revoke_security_group_ingress(GroupId=grp["GroupId"], IpPermissions=grp["IpPermissions"])
    if grp.get("IpPermissionsEgress"):
        ec2.revoke_security_group_egress(GroupId=grp["GroupId"], IpPermissions=grp["IpPermissionsEgress"])


def world(port: int) -> dict:
    return {"IpProtocol": "tcp", "FromPort": port, "ToPort": port, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}


_base_amis: dict[str, str] = {}


def base_ami(ec2) -> str:
    """Our own base AMI per region, so seeding works with or without moto's built-in AMIs."""
    region = ec2.meta.region_name
    if region not in _base_amis:
        _base_amis[region] = ec2.register_image(
            Name=f"base-linux-{region}", RootDeviceName="/dev/xvda", VirtualizationType="hvm",
            BlockDeviceMappings=[{"DeviceName": "/dev/xvda", "Ebs": {"VolumeSize": 8}}])["ImageId"]
    return _base_amis[region]


def launch(ec2, name: str, imds: str, sg_ids: list[str], extra_tags: dict | None = None) -> str:
    # NOTE: moto ignores MetadataOptions, so every instance reports IMDSv1 when scanned.
    ami = base_ami(ec2)
    tags = [{"Key": "Name", "Value": name}] + [{"Key": k, "Value": v} for k, v in (extra_tags or {}).items()]
    return ec2.run_instances(
        ImageId=ami, MinCount=1, MaxCount=1, InstanceType="t3.micro", SecurityGroupIds=sg_ids,
        MetadataOptions={"HttpTokens": imds, "HttpEndpoint": "enabled"},
        TagSpecifications=[{"ResourceType": "instance", "Tags": tags}],
    )["Instances"][0]["InstanceId"]


ec2 = client("ec2", HOME)
vpc1 = default_vpc(ec2)  # default VPC: no flow logs, default SG keeps allow-all egress
open_ssh_rdp = sg(ec2, vpc1, "legacy-admin", "SSH+RDP from anywhere", [world(22), world(3389)])
open_all = sg(ec2, vpc1, "debug-all-open", "all traffic from anywhere",
              [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
web = sg(ec2, vpc1, "web-https", "HTTPS from the internet only", [world(443)])
step("default VPC: no flow logs, SGs open on 22/3389 and all traffic, web SG on 443")

bastion = launch(ec2, "legacy-bastion", "optional", [open_ssh_rdp], {"criticality": "3"})
web_srv = launch(ec2, "web-01", "optional", [web])
app_srv = launch(ec2, "app-01", "required", [web])
step("instances: legacy-bastion + web-01 on IMDSv1, app-01 on IMDSv2 (see note at the end)")

vpc2 = ec2.create_vpc(CidrBlock="10.50.0.0/16", TagSpecifications=[
    {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": "prod-private"}]}])["Vpc"]["VpcId"]
ec2.create_flow_logs(ResourceIds=[vpc2], ResourceType="VPC", TrafficType="ALL",
                     LogDestinationType="s3", LogDestination="arn:aws:s3:::audit-logs-central")
lock_default_sg(ec2, vpc2)
step("prod-private VPC: flow logs on, default SG locked down")

vol_db = ec2.create_volume(AvailabilityZone=f"{HOME}a", Size=8, Encrypted=False)["VolumeId"]
vol_ok = ec2.create_volume(AvailabilityZone=f"{HOME}a", Size=8, Encrypted=True)["VolumeId"]
leaked = ec2.create_snapshot(VolumeId=vol_db, Description="db-backup-2023 (shared publicly!)")["SnapshotId"]
ec2.modify_snapshot_attribute(SnapshotId=leaked, Attribute="createVolumePermission",
                              OperationType="add", GroupNames=["all"])
ec2.create_snapshot(VolumeId=vol_ok, Description="app-backup (private)")
step("EBS snapshots: one public (db-backup), one private")

golden = ec2.create_image(InstanceId=app_srv, Name="golden-app-ami")["ImageId"]
public_ami = ec2.create_image(InstanceId=web_srv, Name="web-ami-shared")["ImageId"]
ec2.modify_image_attribute(ImageId=public_ami, LaunchPermission={"Add": [{"Group": "all"}]})
step("AMIs: golden-app-ami private, web-ami-shared public")
step(f"EBS default encryption OFF in {HOME}")

ec2_eu = client("ec2", SECOND)
ec2_eu.enable_ebs_encryption_by_default()
vpc_eu = default_vpc(ec2_eu)
eu_sg = sg(ec2_eu, vpc_eu, "eu-app", "internal only", [
    {"IpProtocol": "tcp", "FromPort": 8080, "ToPort": 8080, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}])
launch(ec2_eu, "eu-app-01", "required", [eu_sg])
step(f"{SECOND}: EBS default encryption ON, IMDSv2 instance, internal-only SG, no GuardDuty")

# ---------------------------------------------------------------- RDS (Container)
print("RDS")
rds = client("rds", HOME)
for name, encrypted, public, crit in (
    ("customers-db", False, True, "3"),   # unencrypted AND internet-facing: top of the risk register
    ("analytics-db", True, True, "2"),    # encrypted but public
    ("orders-db", True, False, "3"),      # the secure one
):
    rds.create_db_instance(
        DBInstanceIdentifier=name, DBInstanceClass="db.t3.micro", Engine="postgres",
        MasterUsername="dbadmin", MasterUserPassword="Password123!", AllocatedStorage=20,
        StorageEncrypted=encrypted, PubliclyAccessible=public,
        Tags=[{"Key": "criticality", "Value": crit}],
    )
step("customers-db: unencrypted + public; analytics-db: public; orders-db: encrypted + private")

# ---------------------------------------------------------------- done
acct = client("sts").get_caller_identity()["Account"]
snap_count = len(ec2.describe_snapshots(OwnerIds=["self"])["Snapshots"])
if snap_count > 50:
    print(f"\nWARNING: moto has {snap_count} snapshots (its built-in AMIs). Restart moto_server with\n"
          '  $env:MOTO_EC2_LOAD_DEFAULT_AMIS = "false"\nand re-run with --reset for readable results.')
print(f"""
Seeded fake AWS account {acct}.

moto limitations (these checks cannot show their full range here):
  - iam_access_key_rotated_90d / iam_unused_credentials_90d always PASS: moto cannot backdate keys/logins.
  - ec2_imdsv2_required always FAILs: moto does not store instance MetadataOptions, so app-01 and
    eu-app-01 (launched IMDSv2-only) still report IMDSv1. On real AWS they would PASS.
  - Root MFA (FAIL) / root keys (PASS) come from moto's fixed account summary.

Now scan it (same PowerShell window):
  $env:AWS_ENDPOINT_URL      = "{ENDPOINT}"
  $env:AWS_ACCESS_KEY_ID     = "testing"
  $env:AWS_SECRET_ACCESS_KEY = "testing"
  $env:AWS_DEFAULT_REGION    = "{HOME}"
  Remove-Item Env:AWS_PROFILE -ErrorAction SilentlyContinue
  .venv\\Scripts\\python -m app.cli scan --region {HOME} --region {SECOND} --label moto-demo

Then open /attack-surface, /responsibility and a failed finding in the dashboard.
""")
