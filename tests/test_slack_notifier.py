import json
from unittest.mock import MagicMock

import pytest

WEBHOOK = "https://hooks.slack.test/abc"


def make_event(*messages, subject="Test Alert"):
    return {
        "Records": [
            {"Sns": {"Subject": subject, "Message": m}} for m in messages
        ]
    }


@pytest.fixture
def wired(slack, monkeypatch):
    """SSM aur urlopen ko fake kar deta hai."""
    ssm_mock = MagicMock()
    ssm_mock.get_parameter.return_value = {"Parameter": {"Value": WEBHOOK}}
    monkeypatch.setattr(slack, "ssm", ssm_mock)
    urlopen_mock = MagicMock()
    monkeypatch.setattr(slack.urllib.request, "urlopen", urlopen_mock)
    return slack, ssm_mock, urlopen_mock


@pytest.mark.parametrize(
    "text, expected",
    [
        ("Root login detected", "🔴 HIGH"),
        ("New access key created", "🔴 HIGH"),
        ("SSH open on sg-123", "🔴 HIGH"),
        ("cidr 0.0.0.0/0 found", "🔴 HIGH"),
        ("S3 bucket changed", "🟠 MEDIUM"),
        ("public access enabled", "🟠 MEDIUM"),
        ("something harmless", "🟡 LOW"),
        ("SSH rule on S3 bucket", "🔴 HIGH"),  # HIGH ko MEDIUM se priority
    ],
)
def test_get_severity(slack, text, expected):
    assert slack.get_severity(text) == expected


def test_handler_sends_formatted_payload(wired):
    slack, _, urlopen_mock = wired
    result = slack.lambda_handler(make_event("Root login", subject="ALERT"), None)

    assert result == {"status": "sent"}
    req = urlopen_mock.call_args[0][0]
    assert req.full_url == WEBHOOK
    body = json.loads(req.data.decode("utf-8"))
    assert "🔴 HIGH" in body["text"]
    assert "ALERT" in body["text"]


def test_handler_uses_default_subject(wired):
    slack, _, urlopen_mock = wired
    event = {"Records": [{"Sns": {"Subject": None, "Message": "hello"}}]}
    slack.lambda_handler(event, None)

    body = json.loads(urlopen_mock.call_args[0][0].data.decode("utf-8"))
    assert "Security Alert" in body["text"]


def test_handler_truncates_long_message(wired):
    slack, _, urlopen_mock = wired
    slack.lambda_handler(make_event("x" * 5000), None)

    body = json.loads(urlopen_mock.call_args[0][0].data.decode("utf-8"))
    assert body["text"].count("x") == 2500


def test_webhook_is_cached_across_records(wired):
    slack, ssm_mock, urlopen_mock = wired
    slack.lambda_handler(make_event("one", "two"), None)

    assert urlopen_mock.call_count == 2
    assert ssm_mock.get_parameter.call_count == 1