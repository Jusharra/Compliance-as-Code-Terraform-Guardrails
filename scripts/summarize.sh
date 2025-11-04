#!/usr/bin/env bash
set -euo pipefail
mkdir -p reports
echo "# Compliance Report (NIST 800-53 mapping)" > reports/compliance_report.md
echo "" >> reports/compliance_report.md
echo "## Checkov Summary" >> reports/compliance_report.md
jq -r '
  def sev(s): if s==null then "UNKNOWN" else s end;
  .summary | "Passed: \(.passed), Failed: \(.failed), Skipped: \(.skipped), ParsingErrors: \(.parsing_errors)"' \
  reports/checkov.json >> reports/compliance_report.md || echo "_No JSON output_"

echo "" >> reports/compliance_report.md
echo "## Conftest Findings" >> reports/compliance_report.md
if [ -s reports/conftest.txt ]; then
  echo '```' >> reports/compliance_report.md
  cat reports/conftest.txt >> reports/compliance_report.md
  echo '```' >> reports/compliance_report.md
else
  echo "_No OPA findings_" >> reports/compliance_report.md
fi

cat > reports/which_controls.md <<'EOF'
## Controls enforced
- AC-6 Least Privilege → OPA (deny Action:*), Checkov custom
- SC-7 Boundary Protection → OPA ingress rule check, Checkov net checks
- SC-13 Cryptographic Protection → S3 SSE-KMS via Checkov / OPA
- AU-12 Audit Generation → CloudTrail multi-region OPA check
- CM-6 Configuration Settings → Required tags via OPA
EOF

