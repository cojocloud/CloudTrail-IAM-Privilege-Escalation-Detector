# CloudTrail IAM Privilege-Escalation Detector

A serverless AWS detection pipeline that identifies IAM privilege-escalation attempts in near real time — specifically, a principal (role/user) modifying IAM policies attached to **itself**, a common post-compromise technique (MITRE ATT&CK **T1548.005** — Abuse Elevation Control Mechanism: Temporary Elevated Cloud Access).

When it fires, it can either just alert (SNS/Slack) or auto-quarantine the offending principal by attaching a `DenyAll` policy — configurable per environment.

```
CloudTrail (management events)
        │
        ▼
  EventBridge rule  ──match on IAM write APIs──▶  Lambda (detector.py)
        │                                              │
        │                                     is target == caller?
        │                                              │
        │                                     ┌────────┴────────┐
        │                                     ▼                 ▼
        │                                 benign            suspicious
        │                                 (log only)             │
        │                                                        ▼
        │                                          SNS alert + optional
        │                                          auto-quarantine (deny-all
        │                                          policy attached to role)
```

## Why this matters (the pitch)

Attackers who land a low-privilege credential frequently try to widen it before pivoting further — attaching a permissive managed policy, adding an inline policy, or creating a new policy version with broader access. Native GuardDuty coverage for this is good but not exhaustive, and this project shows you can build a **targeted, explainable, tunable** detection instead of relying solely on a vendor black box.

## What's in this repo

| Path | Purpose |
|---|---|
| `terraform/` | Deploys the EventBridge rule, Lambda, IAM roles, and SNS topic |
| `lambda/detector.py` | Parses the CloudTrail event, decides benign vs. suspicious, alerts/remediates |
| `sigma/iam_privesc_self_modify.yml` | Portable detection rule (SIEM-agnostic — Splunk, Elastic, Sentinel via `sigma-cli`) |
| `athena/hunt_query.sql` | Historical threat-hunting query against CloudTrail logs already in S3 |
| `test/sample_cloudtrail_events.json` | Fabricated events (1 benign, 1 malicious) for offline unit testing |
| `test/simulate_attack.py` | Live-fire test script — assumes a sandbox role and triggers the real detection in a test AWS account |

## Detected event types

- `PutRolePolicy` / `PutUserPolicy` / `PutGroupPolicy` — inline policy attach
- `AttachRolePolicy` / `AttachUserPolicy` / `AttachGroupPolicy` — managed policy attach
- `CreatePolicyVersion` — new default policy version (can silently widen access)
- `UpdateAssumeRolePolicy` — widens who can assume a role
- `CreateAccessKey` — new key for a user that already has an active one (backdoor credential)

## Quick start

```bash
# 1. Deploy
cd terraform
terraform init
terraform apply -var="alert_email=you@example.com" -var="auto_remediate=false"

# 2. Unit-test the parsing logic offline (no AWS needed)
cd ../test
python3 -m pytest simulate_attack.py --offline   # or: python3 detector_test.py

# 3. Live-fire test in a sandbox AWS account (creates a throwaway low-priv role,
#    assumes it, and calls PutRolePolicy on itself — exactly the attack pattern)
python3 simulate_attack.py --live
```

You should see a CloudWatch Logs entry from the Lambda within a few seconds of the
`simulate_attack.py --live` run, and (if `alert_email` was set) an email/SNS alert.

## Tuning for a real environment

Before running this anywhere near production, you MUST tune the exclusion list in
`lambda/detector.py` (`KNOWN_AUTOMATION_PRINCIPALS`). Every real AWS account has
legitimate automation — Terraform CI roles, CDK deploy roles, AWS SSO/Control Tower
service roles — that routinely touches IAM policies. Pull a week of real CloudTrail
data and use it to build this list from evidence, not guesswork; the
`athena/hunt_query.sql` query is a good starting point for that exercise.


## Limitations / honest scope notes

- This uses **CloudTrail management events**, which have ~a few minutes of delivery
  latency in the standard trail — for sub-second response you'd route through
  CloudTrail's EventBridge near-real-time delivery (used here) rather than polling S3.
- The self-target check is intentionally simple (string match on caller vs. target
  role/user name). A production version should also flag cross-principal escalation
  (A grants B new permissions) — noted as a "next step" rather than implemented, to
  keep this POC focused and explainable.
- Auto-remediation is off by default for a reason: a false positive that quarantines
  a CI/CD deploy role can break production deploys. Treat `auto_remediate=true` as an
  intentional, reviewed decision, not a default.
