output "lambda_function_name" {
  value = aws_lambda_function.detector.function_name
}

output "lambda_function_arn" {
  value = aws_lambda_function.detector.arn
}

output "sns_topic_arn" {
  value = aws_sns_topic.privesc_alerts.arn
}

output "eventbridge_rule_name" {
  value = aws_cloudwatch_event_rule.iam_privesc.name
}

output "note_on_cloudtrail_prereq" {
  value = "This assumes CloudTrail is already enabled in this account/region with management events delivered to EventBridge (default for trails created after 2021, or enable via CloudTrail console > Event Delivery). This module does not create the trail itself."
}
