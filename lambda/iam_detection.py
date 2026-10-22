import os
import uuid
from datetime import datetime, timezone

import boto3

REGION = "ap-south-1"
sns = boto3.client("sns", region_name=REGION)
table = boto3.resource("dynamodb", region_name=REGION).Table(os.environ["INCIDENT_TABLE"])
TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]


def classify(detail):
    name = detail.get("eventName")
    ident = detail.get("userIdentity", {})
    params = detail.get("requestParameters") or {}

    if name == "ConsoleLogin" and ident.get("type") == "Root":
        return "ROOT_CONSOLE_LOGIN", "HIGH", "Root user signed in to the console"

    if name == "CreateAccessKey":
        target = params.get("userName", "self")
        return "IAM_ACCESS_KEY_CREATED", "MEDIUM", f"New access key created for user: {target}"

    if name in ("AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy"):
        if params.get("policyArn", "").endswith("/AdministratorAccess"):
            target = (
                params.get("userName")
                or params.get("roleName")
                or params.get("groupName")
                or "unknown"
            )
            return "ADMIN_POLICY_ATTACHED", "HIGH", f"AdministratorAccess attached to: {target}"

    return None


def lambda_handler(event, context):
    detail = event.get("detail", {})
    result = classify(detail)
    if result is None:
        print(f"Ignoring event: {detail.get('eventName')}")
        return {"status": "ignored"}

    incident_type, severity, summary = result
    actor = detail.get("userIdentity", {}).get("arn", "unknown")
    ip = detail.get("sourceIPAddress", "unknown")
    when = detail.get("eventTime", "unknown")

    try:
        table.put_item(Item={
            "incident_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": incident_type,
            "resource": summary,
            "severity": severity,
            "action": "ALERT_SENT",
            "actor": actor,
            "source_ip": ip,
            "trigger_event": detail.get("eventName", "unknown"),
        })
    except Exception as e:
        print(f"Incident log failed: {e}")

    message = (
        f"IAM security event detected.\n\n"
        f"Type: {incident_type}\n"
        f"Severity: {severity}\n"
        f"Details: {summary}\n"
        f"Done by: {actor}\n"
        f"Source IP: {ip}\n"
        f"Time: {when}"
    )
    print(message)
    sns.publish(
        TopicArn=TOPIC_ARN,
        Subject=f"[{severity}] SOAR: {incident_type}"[:100],
        Message=message,
    )
    return {"status": "alerted", "type": incident_type}