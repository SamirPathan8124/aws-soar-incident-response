from unittest.mock import MagicMock

import pytest

from conftest import load_lambda

ADMIN_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
USER_ARN = "arn:aws:iam::123456789012:user/tester"


def make_event(event_name, user_type="IAMUser", params=None, arn=USER_ARN):
    return {
        "detail": {
            "eventName": event_name,
            "userIdentity": {"type": user_type, "arn": arn},
            "requestParameters": params,
            "sourceIPAddress": "1.2.3.4",
            "eventTime": "2026-10-23T10:00:00Z",
        }
    }


@pytest.fixture
def iam(monkeypatch):
    monkeypatch.setenv("INCIDENT_TABLE", "soar-incidents")
    monkeypatch.setenv(
        "SNS_TOPIC_ARN", "arn:aws:sns:ap-south-1:123456789012:security-alerts"
    )
    mod = load_lambda("iam_detection.py", "iam_detection")
    mod.sns = MagicMock()
    mod.table = MagicMock()
    return mod


# ---------- classify ----------

def test_classify_root_console_login(iam):
    detail = make_event("ConsoleLogin", user_type="Root")["detail"]
    assert iam.classify(detail) == (
        "ROOT_CONSOLE_LOGIN", "HIGH", "Root user signed in to the console"
    )


def test_classify_ignores_non_root_console_login(iam):
    detail = make_event("ConsoleLogin", user_type="IAMUser")["detail"]
    assert iam.classify(detail) is None


def test_classify_access_key_for_named_user(iam):
    detail = make_event("CreateAccessKey", params={"userName": "bob"})["detail"]
    assert iam.classify(detail) == (
        "IAM_ACCESS_KEY_CREATED", "MEDIUM", "New access key created for user: bob"
    )


@pytest.mark.parametrize("params", [None, {}])
def test_classify_access_key_for_self(iam, params):
    detail = make_event("CreateAccessKey", params=params)["detail"]
    assert iam.classify(detail) == (
        "IAM_ACCESS_KEY_CREATED", "MEDIUM", "New access key created for user: self"
    )


@pytest.mark.parametrize(
    "event_name, params, target",
    [
        ("AttachUserPolicy", {"userName": "alice", "policyArn": ADMIN_ARN}, "alice"),
        ("AttachRolePolicy", {"roleName": "deploy-role", "policyArn": ADMIN_ARN}, "deploy-role"),
        ("AttachGroupPolicy", {"groupName": "admins", "policyArn": ADMIN_ARN}, "admins"),
    ],
)
def test_classify_admin_policy_attached(iam, event_name, params, target):
    detail = make_event(event_name, params=params)["detail"]
    assert iam.classify(detail) == (
        "ADMIN_POLICY_ATTACHED", "HIGH", f"AdministratorAccess attached to: {target}"
    )


def test_classify_admin_policy_without_target(iam):
    detail = make_event("AttachUserPolicy", params={"policyArn": ADMIN_ARN})["detail"]
    assert iam.classify(detail) == (
        "ADMIN_POLICY_ATTACHED", "HIGH", "AdministratorAccess attached to: unknown"
    )


@pytest.mark.parametrize(
    "policy_arn",
    [
        "arn:aws:iam::aws:policy/PowerUserAccess",
        "arn:aws:iam::aws:policy/ReadOnlyAccess",
        "arn:aws:iam::123456789012:policy/MyAdministratorAccess",
    ],
)
def test_classify_ignores_non_admin_policy(iam, policy_arn):
    detail = make_event(
        "AttachUserPolicy", params={"userName": "alice", "policyArn": policy_arn}
    )["detail"]
    assert iam.classify(detail) is None


def test_classify_ignores_unrelated_event(iam):
    detail = make_event("DescribeInstances")["detail"]
    assert iam.classify(detail) is None


# ---------- lambda_handler ----------

def test_handler_ignores_unrelated_event(iam):
    result = iam.lambda_handler(make_event("DescribeInstances"), None)

    assert result == {"status": "ignored"}
    iam.sns.publish.assert_not_called()
    iam.table.put_item.assert_not_called()


def test_handler_ignores_event_without_detail(iam):
    result = iam.lambda_handler({}, None)

    assert result == {"status": "ignored"}
    iam.sns.publish.assert_not_called()


def test_handler_logs_root_login_incident(iam):
    root_arn = "arn:aws:iam::123456789012:root"
    event = make_event("ConsoleLogin", user_type="Root", arn=root_arn)
    result = iam.lambda_handler(event, None)

    assert result == {"status": "alerted", "type": "ROOT_CONSOLE_LOGIN"}
    item = iam.table.put_item.call_args.kwargs["Item"]
    assert item["type"] == "ROOT_CONSOLE_LOGIN"
    assert item["severity"] == "HIGH"
    assert item["action"] == "ALERT_SENT"
    assert item["resource"] == "Root user signed in to the console"
    assert item["actor"] == root_arn
    assert item["source_ip"] == "1.2.3.4"
    assert item["trigger_event"] == "ConsoleLogin"


def test_handler_publishes_alert(iam):
    event = make_event("ConsoleLogin", user_type="Root")
    iam.lambda_handler(event, None)

    kwargs = iam.sns.publish.call_args.kwargs
    assert kwargs["TopicArn"] == iam.TOPIC_ARN
    assert kwargs["Subject"] == "[HIGH] SOAR: ROOT_CONSOLE_LOGIN"
    assert "Severity: HIGH" in kwargs["Message"]
    assert f"Done by: {USER_ARN}" in kwargs["Message"]
    assert "Source IP: 1.2.3.4" in kwargs["Message"]
    assert "Time: 2026-10-23T10:00:00Z" in kwargs["Message"]


def test_handler_access_key_is_medium_severity(iam):
    event = make_event("CreateAccessKey", params={"userName": "soar-test-user"})
    result = iam.lambda_handler(event, None)

    assert result == {"status": "alerted", "type": "IAM_ACCESS_KEY_CREATED"}
    subject = iam.sns.publish.call_args.kwargs["Subject"]
    assert subject == "[MEDIUM] SOAR: IAM_ACCESS_KEY_CREATED"


def test_handler_uses_unknown_when_fields_missing(iam):
    event = {"detail": {"eventName": "CreateAccessKey"}}
    result = iam.lambda_handler(event, None)

    assert result["status"] == "alerted"
    item = iam.table.put_item.call_args.kwargs["Item"]
    assert item["actor"] == "unknown"
    assert item["source_ip"] == "unknown"
    message = iam.sns.publish.call_args.kwargs["Message"]
    assert "Time: unknown" in message


def test_handler_dynamodb_failure_does_not_break_alert(iam):
    iam.table.put_item.side_effect = Exception("dynamo down")

    result = iam.lambda_handler(make_event("ConsoleLogin", user_type="Root"), None)

    assert result["status"] == "alerted"
    iam.sns.publish.assert_called_once()