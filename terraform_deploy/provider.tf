terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
    }
  }
}

provider "aws" {
  default_tags {
    tags = local.default_tags
  }
}
