"""
Live-fire test harness: creates a throwaway low-privilege IAM role in a
SANDBOX AWS account, assumes it, and has it call PutRolePolicy on ITSELF --
the exact privilege-escalation pattern this project detects.

DO NOT run this against a production account. It creates and deletes a real
IAM role. Intended for a personal/sandbox AWS account for demo purposes.

Usage:
    python3 simulate_attack.py --live

What it proves: a few seconds after this runs, CloudWatch Logs for the
`iam-privesc-detector` Lambda should show a "suspicious" result, and (if
alert_email was set in Terraform) an SNS email alert should arrive.
"""

import argparse
import json
import sys
import time

import boto3
from botocore.exceptions import ClientError

ROLE_NAME = "privesc-poc-sandbox-role"
TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"AWS": "*"},  # sandbox only -- never do this in prod
            "Action": "sts:AssumeRole",
            "Condition": {"StringEquals": {"sts:ExternalId": "privesc-poc-demo"}},
        }
    ],
}

ESCALATION_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
}


def create_sandbox_role(iam):
    print(f"[1/4] Creating sandbox role '{ROLE_NAME}'...")
    try:
        resp = iam.create_role(
            RoleName=ROLE_NAME,
            AssumeRolePolicyDocument=json.dumps(TRUST_POLICY),
            Description="Throwaway role for privesc detector POC demo",
            Tags=[{"Key": "Purpose", "Value": "privesc-detector-demo"}],
        )
        return resp["Role"]["Arn"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "EntityAlreadyExists":
            print("    Role already exists, reusing it.")
            return iam.get_role(RoleName=ROLE_NAME)["Role"]["Arn"]
        raise


def attach_baseline_readonly(iam):
    print(
        "[2/4] Attaching baseline read-only policy (simulating a low-priv identity)..."
    )
    iam.attach_role_policy(
        RoleName=ROLE_NAME, PolicyArn="arn:aws:iam::aws:policy/ReadOnlyAccess",
    )
    # IAM changes can take a few seconds to propagate.
    time.sleep(8)


def assume_and_escalate(sts, account_id):
    print("[3/4] Assuming the low-priv role, then calling PutRolePolicy on itself...")
    assumed = sts.assume_role(
        RoleArn=f"arn:aws:iam::{account_id}:role/{ROLE_NAME}",
        RoleSessionName="privesc-poc-demo-session",
        ExternalId="privesc-poc-demo",
    )
    creds = assumed["Credentials"]
    scoped_iam = boto3.client(
        "iam",
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )
    # THIS is the detected event: the assumed role grants itself admin.
    scoped_iam.put_role_policy(
        RoleName=ROLE_NAME,
        PolicyName="SelfGrantedAdminAccess",
        PolicyDocument=json.dumps(ESCALATION_POLICY),
    )
    print("    Escalation attempt sent. This is the event the detector should flag.")


def cleanup(iam):
    print("[4/4] Cleaning up sandbox role...")
    for policy_name in ["SelfGrantedAdminAccess", "SecurityQuarantineDenyAll"]:
        try:
            iam.delete_role_policy(RoleName=ROLE_NAME, PolicyName=policy_name)
        except ClientError:
            pass
    try:
        iam.detach_role_policy(
            RoleName=ROLE_NAME, PolicyArn="arn:aws:iam::aws:policy/ReadOnlyAccess"
        )
    except ClientError:
        pass
    try:
        iam.delete_role(RoleName=ROLE_NAME)
        print("    Done.")
    except ClientError as e:
        print(f"    Cleanup warning: {e}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--live",
        action="store_true",
        help="Actually run against AWS (sandbox account only)",
    )
    parser.add_argument(
        "--skip-cleanup",
        action="store_true",
        help="Leave the sandbox role in place afterward",
    )
    args = parser.parse_args()

    if not args.live:
        print("This is a live-fire script. Re-run with --live to execute against AWS.")
        print("(This safety gate exists so the script can't run by accident.)")
        sys.exit(0)

    iam = boto3.client("iam")
    sts = boto3.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    print(
        f"Running against account {account_id}. Ctrl+C now if this isn't your sandbox."
    )
    time.sleep(3)

    create_sandbox_role(iam)
    attach_baseline_readonly(iam)
    assume_and_escalate(sts, account_id)

    print(
        "\nCheck CloudWatch Logs for the 'iam-privesc-detector' Lambda in the next ~30s."
    )
    print(
        "Expect: status='suspicious', an SNS alert, and (if AUTO_REMEDIATE=true) a quarantine policy."
    )

    if not args.skip_cleanup:
        time.sleep(15)  # give the detector time to run before we tear things down
        cleanup(iam)


if __name__ == "__main__":
    main()
