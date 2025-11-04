#!/usr/bin/env bash
set -euo pipefail

# ---------- Config ----------
TF_DIR="${TF_DIR:-terraform}"
REGION="${REGION:-us-east-1}"
NAME_PREFIX="${NAME_PREFIX:-cac-demo}"
TAGS_JSON="${TAGS_JSON:-{\"Project\":\"Compliance-as-Code-Guardrails\"}}"
# ----------------------------

command -v terraform >/dev/null || { echo "Terraform is required"; exit 1; }
command -v aws >/dev/null || { echo "AWS CLI is required"; exit 1; }

mkdir -p reports

# Optional policy tools
HAS_CHECKOV=0; command -v checkov >/dev/null && HAS_CHECKOV=1
HAS_CONFTEST=0; command -v conftest >/dev/null && HAS_CONFTEST=1

echo "🧹 terraform fmt"
terraform -chdir="$TF_DIR" fmt -recursive

echo "🔐 validate AWS identity"
aws sts get-caller-identity >/dev/null

echo "📦 terraform init"
terraform -chdir="$TF_DIR" init -input=false -upgrade

echo "✅ terraform validate"
terraform -chdir="$TF_DIR" validate

echo "🗺️  terraform plan"
terraform -chdir="$TF_DIR" plan \
  -var="region=${REGION}" \
  -var="name_prefix=${NAME_PREFIX}" \
  -var="tags=${TAGS_JSON}" \
  -out "plan.out" \
  -input=false

echo "🚀 terraform apply"
terraform -chdir="$TF_DIR" apply -input=false -auto-approve "plan.out"

echo "📝 export plan JSON to reports/"
terraform -chdir="$TF_DIR" show -json "plan.out" > ./../reports/plan.json

if [ "$HAS_CHECKOV" -eq 1 ]; then
  echo "🔎 Checkov"
  checkov -f reports/plan.json -o json --compact > reports/checkov.json || true
  checkov -f reports/plan.json -o cli | tee reports/checkov_cli.txt || true
fi

if [ "$HAS_CONFTEST" -eq 1 ]; then
  echo "🧩 Conftest"
  conftest test reports/plan.json --policy policy/conftest | tee reports/conftest.txt || true
fi

echo "📄 Generate summary"
{
  echo "# Compliance Report (Local)"
  echo
  echo "## Inputs"
  echo "- region: ${REGION}"
  echo "- name_prefix: ${NAME_PREFIX}"
  echo
  if [ -f reports/checkov.json ]; then
    echo "## Checkov Summary"
    jq -r '.summary | "Passed: \(.passed), Failed: \(.failed), Skipped: \(.skipped), ParsingErrors: \(.parsing_errors)"' reports/checkov.json || echo "_No JSON output_"
    echo
  fi
  echo "## Conftest Findings"
  echo '```'
  ( test -f reports/conftest.txt && cat reports/conftest.txt ) || echo "No OPA findings"
  echo '```'
} > reports/compliance_report.md

echo "✅ Deploy complete. See ./reports"
