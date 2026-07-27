# How the Live-Fire Simulation Works (No Second AWS User Required)

`test/simulate_attack.py` is step 7 in the main README. The question it
always raises: the detector is built to catch one principal escalating its
*own* privileges — so how do you test that with a personal sandbox account
that only has one IAM user in it?

**You don't need a second user.** The script uses your one (effectively
admin) user to manufacture a throwaway low-privileged role, then briefly
*becomes* that role via `sts:AssumeRole` to perform the actual attack. Your
original user and the "attacker" identity in the simulation are never the
same set of credentials at the moment the escalation happens.

## Walkthrough

The script runs four steps, in order (`test/simulate_attack.py`):

### 1. Create a throwaway role — `create_sandbox_role()`

Your admin user calls `iam.create_role()` to create
`privesc-poc-sandbox-role`. Its trust policy allows anyone to assume it, but
only if they present a specific `ExternalId` (`privesc-poc-demo`) — this
keeps it from being assumable by anything else in the account by accident.
Sandbox-only pattern; never open a trust policy like this in production.

### 2. Make it look low-privileged — `attach_baseline_readonly()`

Attaches AWS's managed `ReadOnlyAccess` policy to the new role. This is the
"before" state: a role that can look at things but shouldn't be able to
touch IAM.

### 3. Assume it, then escalate — `assume_and_escalate()`

This is the step that matters:

1. Calls `sts.assume_role()` against `privesc-poc-sandbox-role`, getting
   back **temporary credentials scoped to that role** — not your original
   user's credentials.
2. Builds a brand-new `boto3` IAM client using *only* those temporary
   credentials.
3. Acting as that scoped-down identity, calls `put_role_policy()` to grant
   `privesc-poc-sandbox-role` a policy allowing `Action: "*", Resource: "*"`
   — on itself.

That last call — a principal running `PutRolePolicy` against its own
role/user name — is exactly the MITRE ATT&CK **T1548.005** pattern
(self-modification for privilege elevation) this whole project exists to
detect. Your admin user never calls `PutRolePolicy` directly, so it doesn't
trip the detector itself — only the assumed role's action does.

### 4. Clean up — `cleanup()`

Removes the inline policy (and the quarantine policy, if auto-remediation
attached one), detaches `ReadOnlyAccess`, and deletes the role. Runs
automatically ~15 seconds after step 3 unless you pass `--skip-cleanup`.

## Diagram

```
 Your one admin user
        │
        │ iam:CreateRole, iam:AttachRolePolicy
        ▼
 privesc-poc-sandbox-role  (ReadOnlyAccess only — "low-privileged")
        │
        │ sts:AssumeRole  (your admin user assumes it)
        ▼
 Temporary credentials, scoped to privesc-poc-sandbox-role
        │
        │ iam:PutRolePolicy — target = itself
        ▼
 CloudTrail event: caller == target  ───▶  EventBridge ───▶ Lambda (detector.py)
                                                                   │
                                                          "status": "suspicious"
                                                          SNS alert (+ optional quarantine)
```

## Permissions your one user needs

Since the script both sets up and tears down the sandbox role, and assumes
it in between, your admin/sandbox user's credentials need at least:

- `iam:CreateRole`
- `iam:AttachRolePolicy`
- `iam:PutRolePolicy`
- `iam:DetachRolePolicy`
- `iam:DeleteRolePolicy`
- `iam:DeleteRole`
- `sts:AssumeRole`

If you're running this under a scoped-down profile rather than a broadly
admin sandbox user, confirm these explicitly before running step 7 — a
missing permission here will fail the simulation setup itself, not the
detection logic.

## Running it

```bash
cd test
python3 simulate_attack.py --live
```

Then check, per README step 7: CloudWatch Logs for `iam-privesc-detector`
(`"status": "suspicious"` within ~10-30s), your inbox if `alert_email` was
set, and the IAM console if `auto_remediate = "true"`.
