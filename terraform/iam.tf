data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

# ---------- S3 remediation role ----------
resource "aws_iam_role" "s3_remediation" {
  name               = "soar-s3-remediation-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
  tags               = { Project = var.project }
}

data "aws_iam_policy_document" "s3_remediation" {
  statement {
    actions   = ["s3:GetBucketPublicAccessBlock", "s3:PutBucketPublicAccessBlock"]
    resources = ["arn:aws:s3:::*"]
  }
  statement {
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.security_alerts.arn]
  }
  statement {
    actions   = ["dynamodb:PutItem"]
    resources = [aws_dynamodb_table.incidents.arn]
  }
}

resource "aws_iam_role_policy" "s3_remediation" {
  name   = "soar-s3-remediation-policy"
  role   = aws_iam_role.s3_remediation.id
  policy = data.aws_iam_policy_document.s3_remediation.json
}

resource "aws_iam_role_policy_attachment" "s3_remediation_logs" {
  role       = aws_iam_role.s3_remediation.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# ---------- Security Group remediation role ----------
resource "aws_iam_role" "sg_remediation" {
  name               = "soar-sg-remediation-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
  tags               = { Project = var.project }
}

data "aws_iam_policy_document" "sg_remediation" {
  statement {
    actions   = ["ec2:DescribeSecurityGroups"]
    resources = ["*"]
  }
  statement {
    actions   = ["ec2:RevokeSecurityGroupIngress"]
    resources = ["arn:aws:ec2:${var.region}:${data.aws_caller_identity.current.account_id}:security-group/*"]
  }
  statement {
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.security_alerts.arn]
  }
  statement {
    actions   = ["dynamodb:PutItem"]
    resources = [aws_dynamodb_table.incidents.arn]
  }
}

resource "aws_iam_role_policy" "sg_remediation" {
  name   = "soar-sg-remediation-policy"
  role   = aws_iam_role.sg_remediation.id
  policy = data.aws_iam_policy_document.sg_remediation.json
}

resource "aws_iam_role_policy_attachment" "sg_remediation_logs" {
  role       = aws_iam_role.sg_remediation.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# ---------- IAM detection role ----------
resource "aws_iam_role" "iam_detection" {
  name               = "soar-iam-detection-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
  tags               = { Project = var.project }
}

data "aws_iam_policy_document" "iam_detection" {
  statement {
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.security_alerts.arn]
  }
  statement {
    actions   = ["dynamodb:PutItem"]
    resources = [aws_dynamodb_table.incidents.arn]
  }
}

resource "aws_iam_role_policy" "iam_detection" {
  name   = "soar-iam-detection-policy"
  role   = aws_iam_role.iam_detection.id
  policy = data.aws_iam_policy_document.iam_detection.json
}

resource "aws_iam_role_policy_attachment" "iam_detection_logs" {
  role       = aws_iam_role.iam_detection.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# ---------- Slack notifier role ----------
resource "aws_iam_role" "slack_notifier" {
  name               = "soar-slack-notifier-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
  tags               = { Project = var.project }
}

data "aws_iam_policy_document" "slack_notifier" {
  statement {
    actions = ["ssm:GetParameter"]
    resources = [
      "arn:aws:ssm:${var.region}:${data.aws_caller_identity.current.account_id}:parameter/soar/slack-webhook-url"
    ]
  }
}

resource "aws_iam_role_policy" "slack_notifier" {
  name   = "soar-slack-notifier-policy"
  role   = aws_iam_role.slack_notifier.id
  policy = data.aws_iam_policy_document.slack_notifier.json
}

resource "aws_iam_role_policy_attachment" "slack_notifier_logs" {
  role       = aws_iam_role.slack_notifier.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "xray" {
  for_each = {
    s3    = aws_iam_role.s3_remediation.name
    sg    = aws_iam_role.sg_remediation.name
    iam   = aws_iam_role.iam_detection.name
    slack = aws_iam_role.slack_notifier.name
  }

  role       = each.value
  policy_arn = "arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess"
}