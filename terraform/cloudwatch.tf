# Teen Lambdas ke liye error alarms (iam-detection us-east-1 mein hai,
# uska alarm Limitations and Future Work mein hai)
locals {
  monitored_lambdas = {
    "soar-s3-remediation" = aws_lambda_function.s3_remediation.function_name
    "soar-sg-remediation" = aws_lambda_function.sg_remediation.function_name
    "soar-slack-notifier" = aws_lambda_function.slack_notifier.function_name
  }
}

resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  for_each = local.monitored_lambdas

  alarm_name          = "${each.key}-errors"
  alarm_description   = "Errors in Lambda ${each.value}"
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = each.value
  }

  alarm_actions = [aws_sns_topic.security_alerts.arn]

  tags = { Project = var.project }
}