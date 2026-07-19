"""
Offline unit tests for lambda/detector.py using fabricated CloudTrail events.
No AWS credentials required -- boto3 clients are mocked.

Run:  python3 test/detector_test.py
"""

import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lambda"))

with open(
    os.path.join(os.path.dirname(__file__), "sample_cloudtrail_events.json")
) as f:
    SAMPLE_EVENTS = json.load(f)


class DetectorTests(unittest.TestCase):
    def setUp(self):
        # Patch boto3 clients before importing the module under test so the
        # module-level `iam = boto3.client("iam")` calls don't hit real AWS.
        patcher_iam = patch("boto3.client")
        self.mock_boto_client = patcher_iam.start()
        self.addCleanup(patcher_iam.stop)

        self.mock_iam = MagicMock()
        self.mock_sns = MagicMock()

        def client_side_effect(service_name, *args, **kwargs):
            return {"iam": self.mock_iam, "sns": self.mock_sns}[service_name]

        self.mock_boto_client.side_effect = client_side_effect

        global detector
        import detector  # noqa: PLC0415 - intentional late import after mocking

        detector.iam = self.mock_iam
        detector.sns = self.mock_sns
        detector.SNS_TOPIC_ARN = "arn:aws:sns:us-east-1:123456789012:test-topic"
        detector.AUTO_REMEDIATE = False

    def test_malicious_self_target_flagged(self):
        result = detector.handler(SAMPLE_EVENTS["malicious_self_target"], None)
        self.assertEqual(result["status"], "suspicious")
        self.mock_sns.publish.assert_called_once()

    def test_benign_different_target_not_flagged(self):
        result = detector.handler(SAMPLE_EVENTS["benign_different_target"], None)
        self.assertEqual(result["status"], "benign")
        self.mock_sns.publish.assert_not_called()

    def test_excluded_automation_skipped(self):
        result = detector.handler(SAMPLE_EVENTS["benign_excluded_automation"], None)
        self.assertEqual(result["status"], "excluded")
        self.mock_sns.publish.assert_not_called()

    def test_auto_remediate_quarantines_role(self):
        detector.AUTO_REMEDIATE = True
        result = detector.handler(SAMPLE_EVENTS["malicious_self_target"], None)
        self.assertEqual(result["status"], "suspicious")
        self.assertTrue(result["remediated"])
        self.mock_iam.put_role_policy.assert_called_once()
        call_kwargs = self.mock_iam.put_role_policy.call_args.kwargs
        self.assertEqual(call_kwargs["RoleName"], "app-readonly-role")
        self.assertEqual(call_kwargs["PolicyName"], "SecurityQuarantineDenyAll")


if __name__ == "__main__":
    unittest.main(verbosity=2)
