import os
import uuid
from datetime import datetime, timezone

import boto3

ec2 = boto3.client("ec2")
sns = boto3.client("sns")
table = boto3.resource("dynamodb").Table(os.environ["INCIDENT_TABLE"])
TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
PORT = 22


def log_incident(incident_type, resource, severity, action, event):
    try:
        detail = event.get("detail", {})
        table.put_item(Item={
            "incident_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": incident_type,
            "resource": resource,
            "severity": severity,
            "action": action,
            "actor": detail.get("userIdentity", {}).get("arn", "unknown"),
            "source_ip": detail.get("sourceIPAddress", "unknown"),
            "trigger_event": detail.get("eventName", "unknown"),
        })
    except Exception as e:
        print(f"Incident log failed: {e}")


def covers_ssh(p):
    proto = p.get("IpProtocol")
    if proto == "-1":
        return True
    if proto != "tcp":
        return False
    return p.get("FromPort", 0) <= PORT <= p.get("ToPort", 0)


def lambda_handler(event, context):
    sg_id = event["detail"]["requestParameters"]["groupId"]
    sg = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]
    removed = []

    for p in sg["IpPermissions"]:
        if not covers_ssh(p):
            continue
        v4 = [r for r in p.get("IpRanges", []) if r.get("CidrIp") == "0.0.0.0/0"]
        v6 = [r for r in p.get("Ipv6Ranges", []) if r.get("CidrIpv6") == "::/0"]
        if not v4 and not v6:
            continue

        perm = {"IpProtocol": p["IpProtocol"]}
        if p["IpProtocol"] != "-1":
            perm["FromPort"] = p["FromPort"]
            perm["ToPort"] = p["ToPort"]
        if v4:
            perm["IpRanges"] = [{"CidrIp": "0.0.0.0/0"}]
        if v6:
            perm["Ipv6Ranges"] = [{"CidrIpv6": "::/0"}]

        ec2.revoke_security_group_ingress(GroupId=sg_id, IpPermissions=[perm])
        removed.append(perm)

    if not removed:
        print(f"{sg_id} has no open SSH rule. Nothing to do.")
        return {"status": "no_open_ssh"}

    msg = (
        "SSH open to the world detected and handled.\n"
        f"Security group: {sg_id}\n"
        f"Trigger event: {event['detail'].get('eventName')}\n"
        f"Rules removed: {len(removed)}"
    )
    print(msg)
    log_incident("OPEN_SSH_SECURITY_GROUP", sg_id, "HIGH", "REVOKED_RULE", event)
    sns.publish(TopicArn=TOPIC_ARN, Subject="SOAR: open SSH rule removed", Message=msg)
    return {"status": "remediated", "security_group": sg_id}