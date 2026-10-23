from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from conftest import load_lambda

ALL_ON = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


def client_error(code, op="Test"):
    return ClientError({"Error": {"Code": code, "Message": "x"}}, op)


def make_event(event_name="PutBucketPublicAccessBlock", bucket="my-bucket"):
    detail = {
        "eventName": event_name,
        "userIdentity": {"arn": "arn:aws:iam::123456789012:user/tester"},
        "sourceIPAddress": "1.2.3.4",
        "eventTime": "2026-10-23T10:00:00Z",
    }
    if bucket:
        detail["requestParameters"] = {"bucketName": bucket}
    return {"detail": detail}


@pytest.fixture
def s3mod(monkeypatch):
    monkeypatch.setenv("INCIDENT_TABLE", "soar-incidents")
    monkeypatch.setenv(
        "SNS_TOPIC_ARN", "arn:aws:sns:ap-south-1:123456789012:security-alerts"
    )
    mod = load_lambda("s3_remediation.py", "s3_remediation")
    mod.s3 = MagicMock()
    mod.sns = MagicMock()
    mod.table = MagicMock()
    return mod


def set_block(mod, settings):
    mod.s3.get_public_access_block.return_value = {
        "PublicAccessBlockConfiguration": settings
    }


# ---------- is_fully_blocked ----------

def test_fully_blocked_when_all_on(s3mod):
    set_block(s3mod, ALL_ON)
    assert s3mod.is_fully_blocked("b") is True


def test_not_blocked_when_one_off_or_missing(s3mod):
    set_block(s3mod, {**ALL_ON, "BlockPublicPolicy": False})
    assert s3mod.is_fully_blocked("b") is False
    set_block(s3mod, {"BlockPublicAcls": True})
    assert s3mod.is_fully_blocked("b") is False


def test_not_blocked_when_no_config(s3mod):
    s3mod.s3.get_public_access_block.side_effect = client_error(
        "NoSuchPublicAccessBlockConfiguration"
    )
    assert s3mod.is_fully_blocked("b") is False


def test_other_client_error_is_raised(s3mod):
    s3mod.s3.get_public_access_block.side_effect = client_error("AccessDenied")
    with pytest.raises(ClientError):
        s3mod.is_fully_blocked("b")


# ---------- lambda_handler ----------

def test_ignores_unrelated_event(s3mod):
    result = s3mod.lambda_handler(make_event("CreateBucket"), None)
    assert result == {"status": "ignored"}
    s3mod.s3.put_public_access_block.assert_not_called()
    s3mod.sns.publish.assert_not_called()


def test_ignores_event_without_bucket(s3mod):
    result = s3mod.lambda_handler(make_event(bucket=None), None)
    assert result == {"status": "ignored"}
    s3mod.s3.put_public_access_block.assert_not_called()


def test_already_private_stops_loop(s3mod):
    set_block(s3mod, ALL_ON)
    result = s3mod.lambda_handler(make_event(), None)
    assert result == {"status": "already_private"}
    s3mod.s3.put_public_access_block.assert_not_called()
    s3mod.sns.publish.assert_not_called()
    s3mod.table.put_item.assert_not_called()


@pytest.mark.parametrize(
    "event_name",
    [
        "PutBucketPublicAccessBlock",
        "DeleteBucketPublicAccessBlock",
        "PutBucketPolicy",
        "PutBucketAcl",
    ],
)
def test_remediates_relevant_events(s3mod, event_name):
    set_block(s3mod, {**ALL_ON, "BlockPublicAcls": False})
    result = s3mod.lambda_handler(make_event(event_name), None)

    assert result == {"status": "FIXED"}
    s3mod.s3.put_public_access_block.assert_called_once_with(
        Bucket="my-bucket", PublicAccessBlockConfiguration=s3mod.BLOCK_ALL
    )
    s3mod.sns.publish.assert_called_once()
    item = s3mod.table.put_item.call_args.kwargs["Item"]
    assert item["type"] == "S3_PUBLIC_ACCESS"
    assert item["resource"] == "my-bucket"
    assert item["action"] == "BLOCK_PUBLIC_ACCESS_RESTORED"
    assert item["trigger_event"] == event_name


def test_failed_remediation_is_reported(s3mod):
    set_block(s3mod, {})
    s3mod.s3.put_public_access_block.side_effect = client_error("AccessDenied")

    result = s3mod.lambda_handler(make_event(), None)

    assert result == {"status": "FAILED: AccessDenied"}
    item = s3mod.table.put_item.call_args.kwargs["Item"]
    assert item["action"] == "REMEDIATION_FAILED"
    subject = s3mod.sns.publish.call_args.kwargs["Subject"]
    assert "FAILED: AccessDenied" in subject


def test_dynamodb_failure_does_not_break_alert(s3mod):
    set_block(s3mod, {})
    s3mod.table.put_item.side_effect = Exception("dynamo down")

    result = s3mod.lambda_handler(make_event(), None)

    assert result == {"status": "FIXED"}
    s3mod.sns.publish.assert_called_once()


def test_sns_subject_is_capped_at_100_chars(s3mod):
    set_block(s3mod, {})
    s3mod.lambda_handler(make_event(bucket="b" * 120), None)
    subject = s3mod.sns.publish.call_args.kwargs["Subject"]
    assert len(subject) <= 100