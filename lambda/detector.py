"""
CloudTrail IAM Privilege-Escalation Detector
=============================================
Triggered by an EventBridge rule matching specific IAM write API calls
(delivered via CloudTrail's EventBridge integration). Flags cases where a
principal modifies IAM policy attached to *itself* -- a classic post-compromise
privilege escalation pattern (MITRE ATT&CK T1548.005).

Env vars:
  SNS_TOPIC_ARN     - where to send alerts
  AUTO_REMEDIATE    - "true"/"false" - if true, attaches a DenyAll policy to the
                       offending role/user on detection
  EXCLUDED_ARN_SUBSTRINGS - comma-separated substrings; any caller ARN containing
                       one of these is treated as known-good automation and skipped
"""

import json
import logging
import os
from datetime import datetime, timezone

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

iam = boto3.client("iam")
sns = boto3.client("sns")

SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")
AUTO_REMEDIATE = os.environ.get("AUTO_REMEDIATE", "false").lower() == "true"

# Known-good automation principals. TUNE THIS with real data before using in
# a live environment -- see athena/hunt_query.sql for how to build this list.
DEFAULT_EXCLUSIONS = ["break-glass-admin", "terraform-ci", "cdk-deploy-role"]
EXCLUDED_ARN_SUBSTRINGS = [
    s.strip()
    for s in os.environ.get(
        "EXCLUDED_ARN_SUBSTRINGS", ",".join(DEFAULT_EXCLUSIONS)
    ).split(",")
    if s.strip()
]

# The IAM write APIs we care about, and the requestParameters key that names
# the *target* of the change for each one.
MONITORED_EVENTS = {
    "PutRolePolicy": "roleName",
    "AttachRolePolicy": "roleName",
    "PutUserPolicy": "userName",
    "AttachUserPolicy": "userName",
    "PutGroupPolicy": "groupName",
    "AttachGroupPolicy": "groupName",
    "CreatePolicyVersion": None,  # target is the policy ARN, handled separately
    "UpdateAssumeRolePolicy": "roleName",
    "CreateAccessKey": "userName",
}

QUARANTINE_POLICY_DOCUMENT = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "QuarantineDenyAll",
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {
                    "StringNotEquals": {"aws:PrincipalTag/QuarantineException": "true"}
                },
            }
        ],
    }
)


def _caller_identity_name(detail: dict) -> str | None:
    """Best-effort extraction of the 'name' of the calling principal, so we can
    compare it against the resource being modified."""
    user_identity = detail.get("userIdentity", {})
    session_issuer = user_identity.get("sessionContext", {}).get("sessionIssuer", {})
    if session_issuer.get("userName"):
        return session_issuer["userName"]
    if user_identity.get("userName"):
        return user_identity["userName"]
    arn = user_identity.get("arn", "")
    # arn:aws:iam::123456789012:role/my-role  or .../user/my-user
    if "/" in arn:
        return arn.rsplit("/", 1)[-1]
    return None


def _is_excluded(caller_arn: str) -> bool:
    return any(substr in caller_arn for substr in EXCLUDED_ARN_SUBSTRINGS)


def _is_self_target(event_name: str, detail: dict, caller_name: str | None) -> bool:
    if caller_name is None:
        return False
    request_params = detail.get("requestParameters") or {}
    target_key = MONITORED_EVENTS.get(event_name)

    if event_name == "CreatePolicyVersion":
        # Target is a managed policy ARN; treat as self-target if the caller's
        # own name appears in the policy ARN/name (heuristic -- refine with
        # real data, e.g. by resolving policy attachments).
        policy_arn = request_params.get("policyArn", "")
        return caller_name in policy_arn

    if target_key is None:
        return False
    target_value = request_params.get(target_key, "")
    return target_value == caller_name


def _publish_alert(subject: str, message: str):
    if not SNS_TOPIC_ARN:
        logger.warning(
            "SNS_TOPIC_ARN not set; skipping alert publish. Message: %s", message
        )
        return
    sns.publish(TopicArn=SNS_TOPIC_ARN, Subject=subject[:100], Message=message)


def _quarantine(principal_type: str, principal_name: str):
    """Attach an inline DenyAll policy to the offending role or user."""
    try:
        if principal_type == "role":
            iam.put_role_policy(
                RoleName=principal_name,
                PolicyName="SecurityQuarantineDenyAll",
                PolicyDocument=QUARANTINE_POLICY_DOCUMENT,
            )
        elif principal_type == "user":
            iam.put_user_policy(
                UserName=principal_name,
                PolicyName="SecurityQuarantineDenyAll",
                PolicyDocument=QUARANTINE_POLICY_DOCUMENT,
            )
        logger.info("Quarantined %s %s", principal_type, principal_name)
        return True
    except Exception as exc:  # noqa: BLE001 - want to alert regardless of failure cause
        logger.error(
            "Failed to quarantine %s %s: %s", principal_type, principal_name, exc
        )
        return False


def handler(event, context):  # noqa: ARG001 - context required by Lambda signature
    """
    Expects an EventBridge event wrapping a CloudTrail record, e.g.:
    { "detail": { "eventName": "PutRolePolicy", "userIdentity": {...}, ... } }
    """
    detail = event.get(
        "detail", event
    )  # allow raw CloudTrail records for local testing
    event_name = detail.get("eventName")

    if event_name not in MONITORED_EVENTS:
        logger.info("Ignoring unmonitored event: %s", event_name)
        return {"status": "ignored", "eventName": event_name}

    caller_arn = detail.get("userIdentity", {}).get("arn", "unknown")
    if _is_excluded(caller_arn):
        logger.info("Caller %s matches exclusion list; skipping.", caller_arn)
        return {"status": "excluded", "caller": caller_arn}

    caller_name = _caller_identity_name(detail)
    self_target = _is_self_target(event_name, detail, caller_name)

    if not self_target:
        logger.info(
            "Event %s by %s did not target caller's own identity; logging only.",
            event_name,
            caller_arn,
        )
        return {"status": "benign", "eventName": event_name, "caller": caller_arn}

    # --- Suspicious: self-targeted IAM privilege modification ---
    timestamp = detail.get("eventTime", datetime.now(timezone.utc).isoformat())
    source_ip = detail.get("sourceIPAddress", "unknown")

    message_lines = [
        "IAM PRIVILEGE ESCALATION ALERT",
        f"Event:      {event_name}",
        f"Caller ARN: {caller_arn}",
        f"Time:       {timestamp}",
        f"Source IP:  {source_ip}",
        f"Request:    {json.dumps(detail.get('requestParameters', {}))}",
    ]

    remediated = False
    if AUTO_REMEDIATE and caller_name:
        # Note: assumed-role sessions carry ARNs like
        # arn:aws:sts::acct:assumed-role/RoleName/SessionName -- NOT
        # arn:aws:iam::acct:role/RoleName -- so check assumed-role first.
        if ":assumed-role/" in caller_arn or ":role/" in caller_arn:
            principal_type = "role"
        else:
            principal_type = "user"
        remediated = _quarantine(principal_type, caller_name)
        message_lines.append(
            f"Auto-remediation: {'quarantine policy attached' if remediated else 'FAILED - manual action required'}"
        )
    else:
        message_lines.append("Auto-remediation: disabled (alert only)")

    message = "\n".join(message_lines)
    logger.warning(message)
    _publish_alert(f"[HIGH] IAM privesc: {event_name} by {caller_arn}", message)

    return {
        "status": "suspicious",
        "eventName": event_name,
        "caller": caller_arn,
        "remediated": remediated,
    }
