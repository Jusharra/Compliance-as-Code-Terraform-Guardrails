terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.52"
    }
  }
}
provider "aws" {
  region = var.region
}

# Secondary provider for replication destination (us-west-2)
provider "aws" {
  alias  = "replica"
  region = "us-west-2"
}

