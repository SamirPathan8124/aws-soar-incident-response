variable "region" {
  description = "Main region for the SOAR resources"
  type        = string
  default     = "ap-south-1"
}

variable "project" {
  description = "Project tag value"
  type        = string
  default     = "aws-soar-incident-response"
}