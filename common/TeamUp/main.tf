locals {
    aws_region  = "ap-northeast-2"
    route53     = "sjna.xyz"
    
    
    user_default_tags = {
        SERVICE_NAME = "TeamUp"
        IAC_TOOL     = "terraform"
    }

}

#todo default tag적용

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }

  backend "s3" {
      bucket         = "teamup-terraform-backend"
      key            = "terraform/teamup.tfstate"
      region         = "ap-northeast-2"
      dynamodb_table = "teamup-common-terraform-backend"
  }
}

resource "aws_s3_bucket" "teamup-terraform-backend" {
    bucket        = "teamup-terraform-backend"
    force_destroy = true
}

resource "aws_dynamodb_table" "teamup-common-terraform-backend" {
    name           = "teamup-common-terraform-backend"
    hash_key       = "LockID"
    billing_mode   = "PAY_PER_REQUEST"

    attribute {
        name = "LockID"
        type = "S"
    }
}

provider "aws" {
  region  = local.aws_region

  default_tags {
    tags = local.user_default_tags
  }
}

data "aws_route53_zone" "zone" {
  name         = local.route53
  private_zone = false
}

