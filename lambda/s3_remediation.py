import os
import boto3
from botocore.exceptions import ClientError

s3 = boto3.client("s3")
sns = boto3.client("sns")

TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]

BLOCK_ALL = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


def is_fully_blocked(bucket):
    """True if all four Block Public Access settings are ON."""
    try:
        cfg = s3.get_public_access_block(Bucket=bucket)
        settings = cfg["PublicAccessBlockConfiguration"]
        return all(settings.get(key, False) for key in BLOCK_ALL)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "NoSuchPublicAccessBlockConfiguration":
            return False
        raise


def lambda_handler(event, context):
    detail = event.get("detail", {})
    bucket = detail.get("requestParameters", {}).get("bucketName")
    event_name = detail.get("eventName", "unknown")
    user = detail.get("userIdentity", {}).get("arn", "unknown")
    ip = detail.get("sourceIPAddress", "unknown")
    when = detail.get("eventTime", "unknown")

    RELEVANT_EVENTS = {
        "PutBucketPublicAccessBlock",
        "DeleteBucketPublicAccessBlock",
        "PutBucketPolicy",
        "PutBucketAcl",
    }
    if event_name not in RELEVANT_EVENTS:
        print(f"Ignoring unrelated event: {event_name}")
        return {"status": "ignored"}

    if not bucket:
        print("No bucket name in event, nothing to do.")
        return {"status": "ignored"}

    # Our own fix also creates a CloudTrail event. If the bucket is
    # already fully blocked, stop here (prevents an endless loop).
    if is_fully_blocked(bucket):
        print(f"{bucket} is already private. Nothing to do.")
        return {"status": "already_private"}

    status = "FIXED"
    try:
        s3.put_public_access_block(
            Bucket=bucket,
            PublicAccessBlockConfiguration=BLOCK_ALL,
        )
    except ClientError as e:
        status = f"FAILED: {e.response['Error']['Code']}"

    message = (
        f"S3 public access detected and handled.\n\n"
        f"Bucket: {bucket}\n"
        f"Trigger event: {event_name}\n"
        f"Done by: {user}\n"
        f"Source IP: {ip}\n"
        f"Time: {when}\n"
        f"Action: Block Public Access re-enabled\n"
        f"Result: {status}"
    )
    sns.publish(
        TopicArn=TOPIC_ARN,
        Subject=f"[SECURITY] S3 bucket {bucket}: {status}"[:100],
        Message=message,
    )
    print(message)
    return {"status": status}
