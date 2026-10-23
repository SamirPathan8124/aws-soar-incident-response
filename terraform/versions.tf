terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }
}

provider "aws" {
  region = var.region
}

# IAM events global hote hain, isliye IAM detection Lambda us-east-1 mein hai
provider "aws" {
  alias  = "use1"
  region = "us-east-1"
}