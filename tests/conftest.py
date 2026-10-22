import os
import sys

os.environ.setdefault("AWS_DEFAULT_REGION", "ap-south-1")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("WEBHOOK_PARAM", "/soar/slack-webhook-url")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lambda"))