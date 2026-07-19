data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/../lambda/detector.py"
  output_path = "${path.module}/build/detector.zip"
}

resource "aws_iam_role" "lambda_exec" {
  name = "iam-privesc-detector-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "lambda_permissions" {
  name = "iam-privesc-detector-lambda-policy"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Logging"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Sid      = "PublishAlerts"
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.privesc_alerts.arn
      },
      {
        # Scoped to the quarantine-only action this function performs.
        # Does NOT grant broad IAM write access.
        Sid    = "QuarantineRemediation"
        Effect = "Allow"
        Action = [
          "iam:PutRolePolicy",
          "iam:PutUserPolicy",
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "iam:PolicyName" = "SecurityQuarantineDenyAll"
          }
        }
      },
    ]
  })
}

resource "aws_lambda_function" "detector" {
  function_name    = "iam-privesc-detector"
  role             = aws_iam_role.lambda_exec.arn
  handler          = "detector.handler"
  runtime          = "python3.12"
  timeout          = 15
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      SNS_TOPIC_ARN           = aws_sns_topic.privesc_alerts.arn
      AUTO_REMEDIATE          = var.auto_remediate
      EXCLUDED_ARN_SUBSTRINGS = var.excluded_arn_substrings
    }
  }
}

resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${aws_lambda_function.detector.function_name}"
  retention_in_days = 30
}
