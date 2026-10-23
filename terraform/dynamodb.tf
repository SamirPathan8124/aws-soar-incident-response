resource "aws_dynamodb_table" "incidents" {
  #checkov:skip=CKV_AWS_119:Table uses AWS-managed encryption; a customer-managed KMS key adds cost and key policy overhead
  name         = "soar-incidents"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "incident_id"

  attribute {
    name = "incident_id"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled = true
  }

  tags = {
    Project = var.project
  }
}