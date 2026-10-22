import json
import os
import urllib.request
import boto3

ssm = boto3.client("ssm")
_webhook = None

def get_webhook():
    global _webhook
    if _webhook is None:
        resp = ssm.get_parameter(
            Name=os.environ["WEBHOOK_PARAM"], WithDecryption=True
        )
        _webhook = resp["Parameter"]["Value"]
    return _webhook

def get_severity(text):
    t = text.upper()
    if any(k in t for k in ["ROOT", "ACCESS KEY", "SSH", "0.0.0.0"]):
        return "🔴 HIGH"
    if any(k in t for k in ["S3", "PUBLIC"]):
        return "🟠 MEDIUM"
    return "🟡 LOW"

def lambda_handler(event, context):
    for record in event["Records"]:
        sns = record["Sns"]
        subject = sns.get("Subject") or "Security Alert"
        message = sns["Message"]
        severity = get_severity(subject + " " + message)

        payload = {
            "text": f"*{severity}* | {subject}\n```{message[:2500]}```"
        }
        req = urllib.request.Request(
            get_webhook(),
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        urllib.request.urlopen(req, timeout=5)
    return {"status": "sent"}