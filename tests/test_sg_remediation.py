from unittest.mock import MagicMock

import pytest

from conftest import load_lambda

WORLD_V4 = {"CidrIp": "0.0.0.0/0"}
WORLD_V6 = {"CidrIpv6": "::/0"}


def make_event(sg_id="sg-123", event_name="AuthorizeSecurityGroupIngress"):
    return {
        "detail": {
            "eventName": event_name,
            "requestParameters": {"groupId": sg_id},
            "userIdentity": {"arn": "arn:aws:iam::123456789012:user/tester"},
            "sourceIPAddress": "1.2.3.4",
        }
    }


@pytest.fixture
def sgmod(monkeypatch):
    monkeypatch.setenv("INCIDENT_TABLE", "soar-incidents")
    monkeypatch.setenv(
        "SNS_TOPIC_ARN", "arn:aws:sns:ap-south-1:123456789012:security-alerts"
    )
    mod = load_lambda("sg_remediation.py", "sg_remediation")
    mod.ec2 = MagicMock()
    mod.sns = MagicMock()
    mod.table = MagicMock()
    return mod


def set_perms(mod, perms):
    mod.ec2.describe_security_groups.return_value = {
        "SecurityGroups": [{"IpPermissions": perms}]
    }


# ---------- covers_ssh ----------

@pytest.mark.parametrize(
    "perm, expected",
    [
        ({"IpProtocol": "-1"}, True),
        ({"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22}, True),
        ({"IpProtocol": "tcp", "FromPort": 0, "ToPort": 65535}, True),
        ({"IpProtocol": "tcp", "FromPort": 1, "ToPort": 21}, False),
        ({"IpProtocol": "tcp", "FromPort": 23, "ToPort": 100}, False),
        ({"IpProtocol": "udp", "FromPort": 22, "ToPort": 22}, False),
        ({"IpProtocol": "tcp"}, False),
    ],
)
def test_covers_ssh(sgmod, perm, expected):
    assert sgmod.covers_ssh(perm) is expected


# ---------- lambda_handler: kuch nahi karna ----------

def test_ignores_open_non_ssh_port(sgmod):
    set_perms(sgmod, [{
        "IpProtocol": "tcp", "FromPort": 80, "ToPort": 80,
        "IpRanges": [WORLD_V4], "Ipv6Ranges": [],
    }])
    result = sgmod.lambda_handler(make_event(), None)

    assert result == {"status": "no_open_ssh"}
    sgmod.ec2.revoke_security_group_ingress.assert_not_called()
    sgmod.sns.publish.assert_not_called()
    sgmod.table.put_item.assert_not_called()


def test_ignores_ssh_restricted_to_private_cidr(sgmod):
    set_perms(sgmod, [{
        "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
        "IpRanges": [{"CidrIp": "10.0.0.0/8"}], "Ipv6Ranges": [],
    }])
    result = sgmod.lambda_handler(make_event(), None)

    assert result == {"status": "no_open_ssh"}
    sgmod.ec2.revoke_security_group_ingress.assert_not_called()


# ---------- lambda_handler: remediation ----------

def test_revokes_open_ipv4_ssh(sgmod):
    set_perms(sgmod, [{
        "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
        "IpRanges": [WORLD_V4], "Ipv6Ranges": [],
    }])
    result = sgmod.lambda_handler(make_event(), None)

    assert result == {"status": "remediated", "security_group": "sg-123"}
    sgmod.ec2.revoke_security_group_ingress.assert_called_once_with(
        GroupId="sg-123",
        IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
            "IpRanges": [WORLD_V4],
        }],
    )
    sgmod.sns.publish.assert_called_once()
    subject = sgmod.sns.publish.call_args.kwargs["Subject"]
    assert subject == "SOAR: open SSH rule removed"


def test_revokes_open_ipv6_ssh(sgmod):
    set_perms(sgmod, [{
        "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
        "IpRanges": [], "Ipv6Ranges": [WORLD_V6],
    }])
    sgmod.lambda_handler(make_event(), None)

    sgmod.ec2.revoke_security_group_ingress.assert_called_once_with(
        GroupId="sg-123",
        IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
            "Ipv6Ranges": [WORLD_V6],
        }],
    )


def test_revokes_v4_and_v6_in_one_permission(sgmod):
    set_perms(sgmod, [{
        "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
        "IpRanges": [WORLD_V4], "Ipv6Ranges": [WORLD_V6],
    }])
    sgmod.lambda_handler(make_event(), None)

    sgmod.ec2.revoke_security_group_ingress.assert_called_once_with(
        GroupId="sg-123",
        IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
            "IpRanges": [WORLD_V4], "Ipv6Ranges": [WORLD_V6],
        }],
    )


def test_revokes_all_traffic_rule_without_ports(sgmod):
    set_perms(sgmod, [{
        "IpProtocol": "-1", "IpRanges": [WORLD_V4], "Ipv6Ranges": [],
    }])
    sgmod.lambda_handler(make_event(), None)

    sgmod.ec2.revoke_security_group_ingress.assert_called_once_with(
        GroupId="sg-123",
        IpPermissions=[{"IpProtocol": "-1", "IpRanges": [WORLD_V4]}],
    )


def test_only_world_cidr_is_revoked_other_cidrs_kept(sgmod):
    set_perms(sgmod, [{
        "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
        "IpRanges": [WORLD_V4, {"CidrIp": "10.0.0.0/8"}], "Ipv6Ranges": [],
    }])
    sgmod.lambda_handler(make_event(), None)

    revoked = sgmod.ec2.revoke_security_group_ingress.call_args.kwargs[
        "IpPermissions"
    ][0]
    assert revoked["IpRanges"] == [WORLD_V4]


def test_multiple_open_rules_all_revoked(sgmod):
    set_perms(sgmod, [
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
         "IpRanges": [WORLD_V4], "Ipv6Ranges": []},
        {"IpProtocol": "tcp", "FromPort": 0, "ToPort": 65535,
         "IpRanges": [WORLD_V4], "Ipv6Ranges": []},
    ])
    sgmod.lambda_handler(make_event(), None)

    assert sgmod.ec2.revoke_security_group_ingress.call_count == 2
    message = sgmod.sns.publish.call_args.kwargs["Message"]
    assert "Rules removed: 2" in message


# ---------- incident logging ----------

def test_incident_is_logged_with_event_details(sgmod):
    set_perms(sgmod, [{
        "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
        "IpRanges": [WORLD_V4], "Ipv6Ranges": [],
    }])
    sgmod.lambda_handler(make_event(), None)

    item = sgmod.table.put_item.call_args.kwargs["Item"]
    assert item["type"] == "OPEN_SSH_SECURITY_GROUP"
    assert item["resource"] == "sg-123"
    assert item["severity"] == "HIGH"
    assert item["action"] == "REVOKED_RULE"
    assert item["actor"] == "arn:aws:iam::123456789012:user/tester"
    assert item["source_ip"] == "1.2.3.4"
    assert item["trigger_event"] == "AuthorizeSecurityGroupIngress"


def test_dynamodb_failure_does_not_break_alert(sgmod):
    set_perms(sgmod, [{
        "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
        "IpRanges": [WORLD_V4], "Ipv6Ranges": [],
    }])
    sgmod.table.put_item.side_effect = Exception("dynamo down")

    result = sgmod.lambda_handler(make_event(), None)

    assert result["status"] == "remediated"
    sgmod.sns.publish.assert_called_once()