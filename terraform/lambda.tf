# Console mein handler lambda_function.lambda_handler hai, isliye
# zip ke andar file ka naam lambda_function.py rakha hai.

data "archive_file" "s3_remediation" {
  type        = "zip"
  output_path = "${path.module}/build/s3_remediation.zip"
  source {
    content  = file("${path.module}/../lambda/s3_remediation.py")
    filename = "lambda_function.py"
  }
}

data "archive_file" "sg_remediation" {
  type        = "zip"
  output_path = "${path.module}/build/sg_remediation.zip"
  source {
    content  = file("${path.module}/../lambda/sg_remediation.py")
    filename = "lambda_function.py"
  }
}

data "archive_file" "iam_detection" {
  type        = "zip"
  output_path = "${path.module}/build/iam_detection.zip"
  source {
    content  = file("${path.module}/../lambda/iam_detection.py")
    filename = "lambda_function.py"
  }
}

data "archive_file" "slack_notifier" {
  type        = "zip"
  output_path = "${path.module}/build/slack_notifier.zip"
  source {
    content  = file("${path.module}/../lambda/slack_notifier.py")
    filename = "lambda_function.py"
  }
}

resource "aws_lambda_function" "s3_remediation" {
  #checkov:skip=CKV_AWS_272:Code signing needs an AWS Signer pipeline, overkill for this project
  #checkov:skip=CKV_AWS_117:VPC needs a NAT gateway (cost); function only calls AWS APIs and Slack
  #checkov:skip=CKV_AWS_116:Failures are caught by CloudWatch alarms to SNS; DLQ is in Future Work
  #checkov:skip=CKV_AWS_115:Reserved concurrency can fail on new accounts with low limits; in Future Work
  #checkov:skip=CKV_AWS_173:Env vars hold no secrets (table name, topic ARN, SSM path)
  tracing_config {
    mode = "Active"
  }
  function_name    = "soar-s3-remediation"
  role             = aws_iam_role.s3_remediation.arn
  runtime          = "python3.12"
  handler          = "lambda_function.lambda_handler"
  filename         = data.archive_file.s3_remediation.output_path
  source_code_hash = data.archive_file.s3_remediation.output_base64sha256
  timeout          = 30

  environment {
    variables = {
      INCIDENT_TABLE = aws_dynamodb_table.incidents.name
      SNS_TOPIC_ARN  = aws_sns_topic.security_alerts.arn
    }
  }

  tags = { Project = var.project }
}

resource "aws_lambda_function" "sg_remediation" {
  #checkov:skip=CKV_AWS_272:Code signing needs an AWS Signer pipeline, overkill for this project
  #checkov:skip=CKV_AWS_117:VPC needs a NAT gateway (cost); function only calls AWS APIs and Slack
  #checkov:skip=CKV_AWS_116:Failures are caught by CloudWatch alarms to SNS; DLQ is in Future Work
  #checkov:skip=CKV_AWS_115:Reserved concurrency can fail on new accounts with low limits; in Future Work
  #checkov:skip=CKV_AWS_173:Env vars hold no secrets (table name, topic ARN, SSM path)
  tracing_config {
    mode = "Active"
  }
  function_name    = "soar-sg-remediation"
  role             = aws_iam_role.sg_remediation.arn
  runtime          = "python3.12"
  handler          = "lambda_function.lambda_handler"
  filename         = data.archive_file.sg_remediation.output_path
  source_code_hash = data.archive_file.sg_remediation.output_base64sha256
  timeout          = 30

  environment {
    variables = {
      INCIDENT_TABLE = aws_dynamodb_table.incidents.name
      SNS_TOPIC_ARN  = aws_sns_topic.security_alerts.arn
    }
  }

  tags = { Project = var.project }
}

# IAM events us-east-1 mein aate hain, isliye ye Lambda wahan hai
resource "aws_lambda_function" "iam_detection" {
  #checkov:skip=CKV_AWS_272:Code signing needs an AWS Signer pipeline, overkill for this project
  #checkov:skip=CKV_AWS_117:VPC needs a NAT gateway (cost); function only calls AWS APIs and Slack
  #checkov:skip=CKV_AWS_116:Failures are caught by CloudWatch alarms to SNS; DLQ is in Future Work
  #checkov:skip=CKV_AWS_115:Reserved concurrency can fail on new accounts with low limits; in Future Work
  #checkov:skip=CKV_AWS_173:Env vars hold no secrets (table name, topic ARN, SSM path)
  tracing_config {
    mode = "Active"
  }
  provider         = aws.use1
  function_name    = "soar-iam-detection"
  role             = aws_iam_role.iam_detection.arn
  runtime          = "python3.12"
  handler          = "lambda_function.lambda_handler"
  filename         = data.archive_file.iam_detection.output_path
  source_code_hash = data.archive_file.iam_detection.output_base64sha256
  timeout          = 30

  environment {
    variables = {
      INCIDENT_TABLE = aws_dynamodb_table.incidents.name
      SNS_TOPIC_ARN  = aws_sns_topic.security_alerts.arn
    }
  }

  tags = { Project = var.project }
}

resource "aws_lambda_function" "slack_notifier" {
  #checkov:skip=CKV_AWS_272:Code signing needs an AWS Signer pipeline, overkill for this project
  #checkov:skip=CKV_AWS_117:VPC needs a NAT gateway (cost); function only calls AWS APIs and Slack
  #checkov:skip=CKV_AWS_116:Failures are caught by CloudWatch alarms to SNS; DLQ is in Future Work
  #checkov:skip=CKV_AWS_115:Reserved concurrency can fail on new accounts with low limits; in Future Work
  #checkov:skip=CKV_AWS_173:Env vars hold no secrets (table name, topic ARN, SSM path)
  tracing_config {
    mode = "Active"
  }
  function_name    = "soar-slack-notifier"
  role             = aws_iam_role.slack_notifier.arn
  runtime          = "python3.12"
  handler          = "lambda_function.lambda_handler"
  filename         = data.archive_file.slack_notifier.output_path
  source_code_hash = data.archive_file.slack_notifier.output_base64sha256
  timeout          = 10

  environment {
    variables = {
      WEBHOOK_PARAM = "/soar/slack-webhook-url"
    }
  }

  tags = { Project = var.project }
}

# SNS security-alerts -> Slack notifier Lambda
resource "aws_lambda_permission" "sns_invoke_slack" {
  statement_id  = "AllowSNSInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.slack_notifier.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.security_alerts.arn
}

resource "aws_sns_topic_subscription" "slack" {
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.slack_notifier.arn
}