terraform {
  backend "s3" {
    bucket         = "cac-guardrails-state-1397728376"
    key            = "project04/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "cac-guardrails-locks"
    encrypt        = true
  }
}
