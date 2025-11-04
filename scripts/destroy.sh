#!/usr/bin/env bash
set -euo pipefail

TF_DIR="${TF_DIR:-terraform}"

echo "⚠️  This will destroy Terraform-managed resources in ${TF_DIR}"
read -r -p "Type 'destroy' to continue: " CONFIRM
[ "$CONFIRM" = "destroy" ] || { echo "Aborted"; exit 1; }

terraform -chdir="$TF_DIR" init -input=false
terraform -chdir="$TF_DIR" destroy -auto-approve
echo "🧹 Destroy complete."
