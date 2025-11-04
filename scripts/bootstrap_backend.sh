#!/usr/bin/env bash
set -euo pipefail

# ---------- Config ----------
AWS_REGION="${AWS_REGION:-us-east-1}"
TF_BACKEND_BUCKET="${TF_BACKEND_BUCKET:-cac-guardrails-state-$RANDOM$RANDOM}"
TF_BACKEND_TABLE="${TF_BACKEND_TABLE:-cac-guardrails-locks}"
TF_DIR="${TF_DIR:-terraform}"
# ----------------------------

echo "🔧 Bootstrapping backend in $AWS_REGION"
aws sts get-caller-identity >/dev/null

# Check if bucket exists (idempotent)
if ! aws s3api head-bucket --bucket "$TF_BACKEND_BUCKET" 2>/dev/null; then
  echo "🪣 Creating S3 bucket: $TF_BACKEND_BUCKET"

  if [ "$AWS_REGION" = "us-east-1" ]; then
    # us-east-1 CANNOT include create-bucket-configuration
    aws s3api create-bucket --bucket "$TF_BACKEND_BUCKET"
  else
    aws s3api create-bucket \
      --bucket "$TF_BACKEND_BUCKET" \
      --region "$AWS_REGION" \
      --create-bucket-configuration "LocationConstraint=$AWS_REGION"
  fi

  # Versioning for state history
  aws s3api put-bucket-versioning \
    --bucket "$TF_BACKEND_BUCKET" \
    --versioning-configuration Status=Enabled

  # (Optional, good hygiene) Block public access
  aws s3api put-public-access-block \
    --bucket "$TF_BACKEND_BUCKET" \
    --public-access-block-configuration \
      'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'
else
  echo "🪣 S3 bucket already exists: $TF_BACKEND_BUCKET"
fi

# DynamoDB lock table (idempotent)
if ! aws dynamodb describe-table --table-name "$TF_BACKEND_TABLE" >/dev/null 2>&1; then
  echo "📚 Creating DynamoDB table: $TF_BACKEND_TABLE"
  aws dynamodb create-table \
    --table-name "$TF_BACKEND_TABLE" \
    --attribute-definitions AttributeName=LockID,AttributeType=S \
    --key-schema AttributeName=LockID,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST
  aws dynamodb wait table-exists --table-name "$TF_BACKEND_TABLE"
else
  echo "📚 DynamoDB table already exists: $TF_BACKEND_TABLE"
fi

# Write backend.tf with your values
cat > "${TF_DIR}/backend.tf" <<EOF
terraform {
  backend "s3" {
    bucket         = "${TF_BACKEND_BUCKET}"
    key            = "project04/terraform.tfstate"
    region         = "${AWS_REGION}"
    dynamodb_table = "${TF_BACKEND_TABLE}"
    encrypt        = true
  }
}
EOF

echo "✅ Backend ready
  bucket:  ${TF_BACKEND_BUCKET}
  table:   ${TF_BACKEND_TABLE}
  region:  ${AWS_REGION}
  file:    ${TF_DIR}/backend.tf"
