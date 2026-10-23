import importlib.util
import os
import pathlib

import pytest

# boto3 client import time pe ban jata hai, isliye region/creds pehle set karo
os.environ.setdefault("AWS_DEFAULT_REGION", "ap-south-1")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

LAMBDA_DIR = pathlib.Path(__file__).resolve().parent.parent / "lambda"


def load_lambda(filename, name):
    spec = importlib.util.spec_from_file_location(name, LAMBDA_DIR / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def slack(monkeypatch):
    monkeypatch.setenv("WEBHOOK_PARAM", "/soar/slack-webhook-url")
    mod = load_lambda("slack_notifier.py", "slack_notifier")
    mod._webhook = None
    return mod