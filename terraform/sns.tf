resource "aws_sns_topic" "security_alerts" {
  name              = "security-alerts"
  kms_master_key_id = "alias/aws/sns"

  tags = {
    Project = var.project
  }
}