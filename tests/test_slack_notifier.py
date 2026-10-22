import json
from unittest.mock import patch

import slack_notifier


def test_severity_high_for_ssh():
    assert "HIGH" in slack_notifier.get_severity("SSH open to 0.0.0.0/0")


def test_severity_high_for_root():
    assert "HIGH" in slack_notifier.get_severity("Root login detected")


def test_severity_medium_for_s3():
    assert "MEDIUM" in slack_notifier.get_severity("S3 bucket public access detected")


def test_severity_low_for_other():
    assert "LOW" in slack_notifier.get_severity("Backup completed")


def test_handler_posts_to_slack():
    event = {"Records": [{"Sns": {"Subject": "TEST: SSH open", "Message": "msg"}}]}
    with patch.object(slack_notifier, "get_webhook", return_value="https://hooks.slack.test/x"), \
         patch("slack_notifier.urllib.request.urlopen") as mock_open:
        result = slack_notifier.lambda_handler(event, None)

    assert result == {"status": "sent"}
    req = mock_open.call_args[0][0]
    body = json.loads(req.data.decode("utf-8"))
    assert "HIGH" in body["text"]
    assert "TEST: SSH open" in body["text"]


def test_handler_uses_default_subject():
    event = {"Records": [{"Sns": {"Message": "something happened"}}]}
    with patch.object(slack_notifier, "get_webhook", return_value="https://hooks.slack.test/x"), \
         patch("slack_notifier.urllib.request.urlopen") as mock_open:
        slack_notifier.lambda_handler(event, None)

    body = json.loads(mock_open.call_args[0][0].data.decode("utf-8"))
    assert "Security Alert" in body["text"]


def test_webhook_is_cached():
    slack_notifier._webhook = None
    with patch.object(slack_notifier.ssm, "get_parameter",
                      return_value={"Parameter": {"Value": "https://hooks.slack.test/x"}}) as mock_get:
        assert slack_notifier.get_webhook() == "https://hooks.slack.test/x"
        slack_notifier.get_webhook()
    assert mock_get.call_count == 1
