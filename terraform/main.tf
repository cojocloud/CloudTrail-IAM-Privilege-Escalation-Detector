terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

data "aws_caller_identity" "current" {}

# ---------------------------------------------------------------------------
# SNS topic for alerts
# ---------------------------------------------------------------------------
resource "aws_sns_topic" "privesc_alerts" {
  name = "iam-privesc-detector-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.alert_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.privesc_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# ---------------------------------------------------------------------------
# EventBridge rule - matches CloudTrail-delivered IAM write events
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "iam_privesc" {
  name        = "iam-self-privilege-escalation"
  description = "Matches IAM policy-modification API calls for privesc detection"

  event_pattern = jsonencode({
    source      = ["aws.iam"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "PutRolePolicy",
        "AttachRolePolicy",
        "PutUserPolicy",
        "AttachUserPolicy",
        "PutGroupPolicy",
        "AttachGroupPolicy",
        "CreatePolicyVersion",
        "UpdateAssumeRolePolicy",
        "CreateAccessKey",
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule      = aws_cloudwatch_event_rule.iam_privesc.name
  target_id = "iam-privesc-detector-lambda"
  arn       = aws_lambda_function.detector.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.detector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.iam_privesc.arn
}
