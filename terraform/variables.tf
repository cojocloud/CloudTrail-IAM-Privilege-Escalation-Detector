variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "us-east-1"
}

variable "alert_email" {
  description = "Email address to subscribe to the SNS alert topic (leave blank to skip)"
  type        = string
  default     = ""
}

variable "auto_remediate" {
  description = "If true, automatically attaches a DenyAll quarantine policy to the offending principal"
  type        = string
  default     = "false"
}

variable "excluded_arn_substrings" {
  description = "Comma-separated list of ARN substrings to treat as known-good automation (exclude from alerting)"
  type        = string
  default     = "break-glass-admin,terraform-ci,cdk-deploy-role"
}
