"""Collector runs against moto-mocked AWS: read-only calls only, full pipeline works."""

import os

import boto3
import pytest
from moto import mock_aws

from app.db import Base, SessionLocal, engine
from app.models import Finding
from app.pipeline import caller_identity, run_scan
from app.seed import seed_reference

READ_ONLY_PREFIXES = ("Describe", "List", "Get")


@pytest.fixture()
def aws(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    with mock_aws():
        yield boto3.Session(region_name="us-east-1")


@pytest.fixture()
def db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    seed_reference(session)
    yield session
    session.close()


def _seed_insecure_resources(session: boto3.Session) -> None:
    iam = session.client("iam")
    iam.create_user(UserName="alice")
    iam.create_access_key(UserName="alice")
    session.client("s3").create_bucket(Bucket="audit-test-bucket")
    ec2 = session.client("ec2")
    vpc_id = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    sg = ec2.create_security_group(GroupName="open-ssh", Description="x", VpcId=vpc_id)
    ec2.authorize_security_group_ingress(
        GroupId=sg["GroupId"],
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
    )
    ami = ec2.describe_images()["Images"][0]["ImageId"]
    ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1,
                      MetadataOptions={"HttpTokens": "optional"})
    vol = ec2.create_volume(AvailabilityZone="us-east-1a", Size=1)
    snap = ec2.create_snapshot(VolumeId=vol["VolumeId"])
    ec2.modify_snapshot_attribute(SnapshotId=snap["SnapshotId"], Attribute="createVolumePermission",
                                  OperationType="add", GroupNames=["all"])


def test_collector_only_makes_read_only_calls(aws, db):
    _seed_insecure_resources(aws)

    calls: list[str] = []
    # botocore emits "before-call.<service>.<Operation>" for every API request.
    aws.events.register("before-call", lambda event_name, **_: calls.append(event_name.split(".")[-1]))

    scan = run_scan(db, label="moto", session=aws, regions=["us-east-1"], identity=caller_identity(aws))

    assert calls, "no AWS calls recorded"
    writes = sorted({op for op in calls if not op.startswith(READ_ONLY_PREFIXES)})
    assert writes == [], f"non read-only AWS calls: {writes}"

    assert scan.status == "completed"
    findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
    by_check = {}
    for f in findings:
        by_check.setdefault(f.check_id, []).append(f.status)
    assert "FAIL" in by_check["sg_no_ssh_open_world"]
    assert "FAIL" in by_check["s3_public_access_blocked"]
    assert by_check["iam_user_mfa_enabled"] == ["FAIL"]
    assert by_check["ec2_imdsv2_required"] == ["FAIL"]
    assert "FAIL" in by_check["ec2_no_public_snapshots"]
    assert "FAIL" in by_check["sg_default_restricts_all"]  # default SG keeps its allow-all egress
    assert by_check["iam_no_user_attached_policies"] == ["PASS"]


def test_access_denied_service_is_error_and_scan_continues(aws, db, monkeypatch):
    from app.collector import aws_collector

    def denied(*_a, **_k):
        raise RuntimeError("AccessDenied: s3:ListAllMyBuckets")

    monkeypatch.setattr(aws_collector, "_collect_s3", denied)
    scan = run_scan(db, session=aws, regions=["us-east-1"], identity=caller_identity(aws))

    assert scan.status == "completed"
    s3 = db.query(Finding).filter(Finding.scan_id == scan.id, Finding.check_id.like("s3_%")).all()
    assert s3 and all(f.status == "ERROR" for f in s3)
    iam = db.query(Finding).filter(Finding.scan_id == scan.id, Finding.check_id.like("iam_%")).all()
    assert iam and all(f.status != "ERROR" for f in iam)


def test_no_real_credentials_leak_into_tests():
    assert "AWS_PROFILE" not in os.environ
