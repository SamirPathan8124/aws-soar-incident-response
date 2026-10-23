# ---------- S3 public access rule (ap-south-1) ----------
resource "aws_cloudwatch_event_rule" "s3_public_access" {
  name        = "soar-s3-public-access-rule"
  description = "Detect changes to S3 public access settings"

  event_pattern = jsonencode({
    source        = ["aws.s3"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["s3.amazonaws.com"]
      eventName = [
        "PutBucketPublicAccessBlock",
        "DeleteBucketPublicAccessBlock",
        "PutBucketPolicy",
        "PutBucketAcl"
      ]
    }
  })

  tags = { Project = var.project }
}

resource "aws_cloudwatch_event_target" "s3_public_access" {
  rule = aws_cloudwatch_event_rule.s3_public_access.name
  arn  = aws_lambda_function.s3_remediation.arn
}

resource "aws_lambda_permission" "events_invoke_s3" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.s3_remediation.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.s3_public_access.arn
}

# ---------- Security group open SSH rule (ap-south-1) ----------
resource "aws_cloudwatch_event_rule" "sg_open_ssh" {
  name        = "soar-sg-open-ssh-rule"
  description = "Detect new security group ingress rules"

  event_pattern = jsonencode({
    source        = ["aws.ec2"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["ec2.amazonaws.com"]
      eventName   = ["AuthorizeSecurityGroupIngress"]
    }
  })

  tags = { Project = var.project }
}

resource "aws_cloudwatch_event_target" "sg_open_ssh" {
  rule = aws_cloudwatch_event_rule.sg_open_ssh.name
  arn  = aws_lambda_function.sg_remediation.arn
}

resource "aws_lambda_permission" "events_invoke_sg" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.sg_remediation.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.sg_open_ssh.arn
}

# ---------- IAM / root detection rule (us-east-1) ----------
resource "aws_cloudwatch_event_rule" "iam_detection" {
  provider    = aws.use1
  name        = "soar-iam-detection-rule"
  description = "Detect root console login, access key creation, admin policy attach"

  event_pattern = jsonencode({
    source        = ["aws.iam", "aws.signin"]
    "detail-type" = ["AWS API Call via CloudTrail", "AWS Console Sign In via CloudTrail"]
    detail = {
      eventName = [
        "ConsoleLogin",
        "CreateAccessKey",
        "AttachUserPolicy",
        "AttachRolePolicy",
        "AttachGroupPolicy"
      ]
    }
  })

  tags = { Project = var.project }
}

resource "aws_cloudwatch_event_target" "iam_detection" {
  provider = aws.use1
  rule     = aws_cloudwatch_event_rule.iam_detection.name
  arn      = aws_lambda_function.iam_detection.arn
}

resource "aws_lambda_permission" "events_invoke_iam" {
  provider      = aws.use1
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.iam_detection.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.iam_detection.arn
}