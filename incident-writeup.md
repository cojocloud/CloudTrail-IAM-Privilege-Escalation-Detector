# Incident Writeup: Attempted IAM Self-Privilege-Escalation via Compromised Application Role

**Severity:** High &nbsp;|&nbsp; **Status:** Contained &nbsp;|&nbsp; **Date:** 2026-07-19 &nbsp;|&nbsp; **Author:** [Your Name], DevSecOps

---

## Summary

An assumed-role session for `app-readonly-role` — an application role scoped to read-only S3 and CloudWatch access — attempted to grant itself full administrative permissions by attaching an inline IAM policy to itself. The activity was detected within seconds by a custom EventBridge/Lambda detection pipeline and automatically quarantined before any follow-on API calls succeeded. No production impact occurred. This writeup documents the detection, response, and root cause of how the credential was likely obtained, based on a simulated exercise run against a sandbox AWS account to validate the detection pipeline end-to-end.

## Timeline (UTC)

| Time | Event |
|---|---|
| 14:31:52 | Anomalous `sts:AssumeRole` for `app-readonly-role` from an unrecognized source IP (`203.0.113.42`), outside the CI/CD IP range this role normally operates from. |
| 14:32:07 | `PutRolePolicy` call from the assumed session, attaching an inline policy named `SelfGrantedAdminAccess` granting `Action: *`, `Resource: *` to `app-readonly-role` itself. |
| 14:32:09 | EventBridge rule `iam-self-privilege-escalation` matched the CloudTrail event and invoked the detection Lambda. |
| 14:32:10 | Lambda confirmed the policy target (`roleName`) matched the calling principal's own session-issuer name — a self-targeted IAM modification, not excluded by the known-automation allowlist. |
| 14:32:10 | Lambda attached a `SecurityQuarantineDenyAll` inline policy to `app-readonly-role`, blocking all further API actions from that role. |
| 14:32:11 | SNS alert published to on-call channel with caller ARN, source IP, and the exact API call made. |
| 14:41:00 | On-call engineer acknowledged, confirmed the quarantine was in place, and began investigation. |
| 15:20:00 | Root cause identified (see below); credential rotated; quarantine policy left in place pending full review. |

## Detection

Built and deployed ahead of this incident: a CloudTrail-driven detection pipeline (EventBridge rule → Lambda) that flags any of `PutRolePolicy`, `AttachRolePolicy`, `PutUserPolicy`, `AttachUserPolicy`, `CreatePolicyVersion`, `UpdateAssumeRolePolicy`, or `CreateAccessKey` where the **target** of the change matches the **calling principal's own identity** — the signature of self-privilege-escalation (MITRE ATT&CK **T1548.005**). The rule excludes known automation principals (CI/CD deploy roles, break-glass admin) to reduce noise.

Mean time to detect: **~3 seconds** from API call to quarantine. This is materially faster than relying on daily/weekly log review or a SIEM correlation search running on a batch schedule — the entire value of the pipeline is compressing "attacker escalates privileges" and "role is deauthorized" into the same few seconds.

## Root cause

Investigation traced the anomalous source IP to a leaked long-term access key for `app-readonly-role`, which had been embedded in a CI configuration file committed to a repository with looser branch-protection rules than the org's main services. The key had been valid for 11 days before use in this incident. Contributing factors:

- `app-readonly-role` used a **long-term access key** rather than short-lived credentials via OIDC federation, so the leak had a long viable window.
- No secret-scanning was enabled on the repository in question at the time of the leak.
- The role's `ReadOnlyAccess` managed policy did not explicitly deny `iam:PutRolePolicy` / `iam:AttachRolePolicy` — `ReadOnlyAccess` blocks most write actions but IAM self-modification on a role's *own* resource is a known gap attackers rely on.

## Remediation

- **Immediate:** Quarantine policy (automated) blocked all further actions from the compromised role; access key deactivated and deleted.
- **Short-term:** Enabled secret scanning (push protection) on the affected repository and audited other repos for the same gap.
- **Short-term:** Added an explicit `Deny` on `iam:Put*Policy` / `iam:Attach*Policy` / `iam:CreatePolicyVersion` targeting the role's own ARN to all read-only service roles, as defense-in-depth on top of detection.
- **Medium-term:** Migrated `app-readonly-role` and similar service roles from long-term access keys to short-lived credentials via OIDC federation (GitHub Actions OIDC provider), removing the class of leaked-long-term-key risk entirely.

## Lessons learned

1. **Detection closed a real gap that policy alone didn't cover.** `ReadOnlyAccess` sounds like it should prevent this, but IAM self-modification is a documented exception attackers specifically target — detection was the actual control that stopped this, not the managed policy.
2. **Auto-remediation only works because it's narrowly scoped.** The quarantine Lambda can *only* attach a policy named exactly `SecurityQuarantineDenyAll` — it has no broader IAM write access — so a false positive here fails safe (an over-quarantined role, not a runaway automation with broad IAM permissions).
3. **The underlying credential hygiene issue (long-term keys, no secret scanning) mattered more than the detection itself.** Detection bought time and prevented impact; it didn't fix why a viable credential existed for 11 days. Both layers are necessary.

---
*This writeup documents a simulated exercise (`test/simulate_attack.py`) run against a sandbox AWS account to validate the detection pipeline described in the [cloudtrail-privesc-detector](.) project, formatted as a real incident postmortem would be.*
