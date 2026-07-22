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

## Step-by-step implementation guide

This walks through deploying and validating the whole pipeline from scratch, in a personal/sandbox AWS account.

### 0. Prerequisites

- An AWS account you're comfortable creating IAM roles and a Lambda in (a personal sandbox account, not production)
- AWS CLI installed and configured with credentials that can create IAM roles, Lambda functions, EventBridge rules, and SNS topics (effectively admin in the sandbox account)
- [Terraform](https://developer.hashicorp.com/terraform/install) >= 1.5
- Python 3.12 and `boto3` installed locally (`pip install boto3 --break-system-packages` or in a venv)
- CloudTrail already enabled in the account/region, with management events. This project does **not** create the trail itself — check under CloudTrail → Trails in the console. Trails created after 2021 deliver to EventBridge by default; if yours is older, enable "Amazon EventBridge" delivery under the trail's settings.

### 1. Get the code

```bash
unzip cloudtrail-privesc-detector.zip
cd cloudtrail-privesc-detector
```

### 2. Review what's about to be deployed

Skim `terraform/main.tf` and `terraform/lambda.tf` before applying anything — you should always know what a Terraform module creates in your account. In short, this deploys:

- One Lambda function (`iam-privesc-detector`)
- One IAM role for that Lambda, scoped to CloudWatch Logs, publishing to one SNS topic, and attaching an inline policy *only* if it's named exactly `SecurityQuarantineDenyAll` (it cannot perform any other IAM write action)
- One EventBridge rule matching the 9 monitored IAM event names
- One SNS topic, plus an email subscription if you provide one

### 3. Configure variables

Copy the example and fill in your own values, or pass them as `-var` flags — both are shown below.

```bash
cd terraform
cat > terraform.tfvars <<EOF
aws_region              = "us-east-1"
alert_email              = "you@example.com"
auto_remediate           = "false"   # keep false until you've tuned exclusions - see step 8
excluded_arn_substrings  = "break-glass-admin,terraform-ci,cdk-deploy-role"
EOF
```

### 4. Deploy

```bash
terraform init
terraform plan     # read this output - confirm it matches step 2's expectations
terraform apply
```

Type `yes` to confirm. Terraform will print the Lambda name, function ARN, SNS topic ARN, and EventBridge rule name as outputs when it's done.

### 5. Confirm the SNS subscription

If you set `alert_email`, check your inbox for a "AWS Notification - Subscription Confirmation" email and click **Confirm subscription**. Alerts won't arrive until this is confirmed — this is an SNS requirement, not something Terraform can do for you.

### 6. Run the offline unit tests

These don't touch AWS at all — they replay fabricated CloudTrail events from `test/sample_cloudtrail_events.json` straight through `lambda/detector.py`'s logic, with `boto3` mocked out. Good for confirming the detection logic itself before you trust it against real infrastructure.

```bash
cd ../test
python3 detector_test.py
```

You should see 4 tests pass: a malicious self-target gets flagged, a benign different-target call doesn't, an excluded automation principal is skipped, and (with auto-remediate on) the quarantine policy attaches to the right role.

### 7. Run the live-fire simulation

This is the real end-to-end check: it creates a throwaway low-privilege role in your sandbox account, assumes it, and has it call `PutRolePolicy` on itself — the exact attack pattern the pipeline is built to catch.

```bash
python3 simulate_attack.py --live
```

Then check, in order:

1. **CloudWatch Logs** → `/aws/lambda/iam-privesc-detector` → look for a log entry within ~10-30 seconds showing `"status": "suspicious"` for the `PutRolePolicy` call.
2. **Your inbox** (if `alert_email` was set) → an email alert with the caller ARN, event name, and source IP.
3. **IAM console** (if you set `auto_remediate = "true"`) → the sandbox role should now have an inline policy named `SecurityQuarantineDenyAll`.

The script cleans up the sandbox role automatically after ~15 seconds unless you pass `--skip-cleanup`.

### 8. Tune the exclusion list before trusting this anywhere real

This is the step most POCs skip, and the one that matters most. Run the Athena hunt query against a real account's CloudTrail logs (or your sandbox's, after a few days of normal use):

```bash
# In Athena, against a Glue table over your CloudTrail S3 bucket:
# paste the contents of athena/hunt_query.sql and run it
```

Look at which `caller_arn` values show up doing legitimate, repeated IAM changes — CI/CD deploy roles, IaC pipelines, SSO/Control Tower service roles — and add distinguishing substrings for them to `excluded_arn_substrings` in `terraform.tfvars`, then `terraform apply` again to pick up the change.

### 9. (Optional) Turn on auto-remediation deliberately

Once you trust the exclusion list, flip it on:

```bash
terraform apply -var="auto_remediate=true"
```

Re-run step 7 to confirm the quarantine actually attaches. Treat this as a reviewed decision each time you touch it, not a default — a false positive here can lock a real automation role out of IAM entirely.

### 10. Tear down

When you're done demoing this, remove everything it created:

```bash
cd terraform
terraform destroy
```

## Resume framing (suggested bullet points)

- *"Designed and deployed a serverless CloudTrail-based detection pipeline (EventBridge + Lambda) identifying IAM self-privilege-escalation attempts (MITRE T1548.005), with configurable auto-remediation via IAM deny-policy quarantine."*
- *"Built a portable Sigma detection rule and Athena hunt query to support both real-time alerting and historical threat hunting across CloudTrail logs."*
- *"Wrote an offensive test harness simulating the privilege-escalation attack path in a sandbox account to validate detection coverage end-to-end."*

## Limitations / honest scope notes (worth saying in an interview)

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
