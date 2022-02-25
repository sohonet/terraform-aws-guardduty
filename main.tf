#-----------------------------------------------------------------------------------------------------------------------
# Subscribe the Acccount to GuardDuty
#-----------------------------------------------------------------------------------------------------------------------
resource "aws_guardduty_detector" "guardduty" {
  enable                       = module.this.enabled
  finding_publishing_frequency = var.finding_publishing_frequency
}

data "aws_caller_identity" "current" {}

#-----------------------------------------------------------------------------------------------------------------------
# Add KMS Key for SNS Topic
#-----------------------------------------------------------------------------------------------------------------------
data "aws_iam_policy_document" "kms_key_iam_policy_document" {

  /* Default policy to grant IAM root account full access to manage the key */
  statement {
    sid       = "Enable IAM User Permissions"
    effect    = "Allow"
    resources = ["*"]
    actions   = ["kms:*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  statement {
    sid = "Allow CWE to use the key"

    principals {
      identifiers = ["events.amazonaws.com"]
      type        = "Service"
    }
    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey"
    ]

    resources = [
      "*",
    ]
  }
}

module "kms_key" {
  source  = "cloudposse/kms-key/aws"
  version = "0.11.0"

  name                    = "guardduty-sns"
  description             = "KMS key for Guard Duty SNS Topic"
  deletion_window_in_days = 10
  enable_key_rotation     = true
  alias                   = "alias/guardduty-sns"
  policy                  = data.aws_iam_policy_document.kms_key_iam_policy_document.json
}

#-----------------------------------------------------------------------------------------------------------------------
# Optionally configure Event Bridge Rules and SNS subscriptions
# https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cwe-integration-types.html
# https://docs.aws.amazon.com/AmazonCloudWatch/latest/events/resource-based-policies-cwe.html#sns-permissions
#-----------------------------------------------------------------------------------------------------------------------
module "sns_topic" {

  source  = "cloudposse/sns-topic/aws"
  version = "0.20.1"
  count   = local.create_sns_topic ? 1 : 0

  subscribers       = var.subscribers
  sqs_dlq_enabled   = false
  kms_master_key_id = module.kms_key.key_id

  attributes = concat(module.this.attributes, ["guardduty"])
  context    = module.this.context
}

module "findings_label" {
  source  = "cloudposse/label/null"
  version = "0.25.0"

  attributes = concat(module.this.attributes, ["guardduty", "findings"])
  context    = module.this.context
}

resource "aws_sns_topic_policy" "sns_topic_publish_policy" {
  count  = module.this.enabled && local.create_sns_topic ? 1 : 0
  arn    = local.findings_notification_arn
  policy = data.aws_iam_policy_document.sns_topic_policy[0].json
}

data "aws_iam_policy_document" "sns_topic_policy" {
  count     = module.this.enabled && local.create_sns_topic ? 1 : 0
  policy_id = "GuardDutyPublishToSNS"
  statement {
    sid = ""
    actions = [
      "sns:Publish"
    ]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    resources = [module.sns_topic[0].sns_topic.arn]
    effect    = "Allow"
  }
}

resource "aws_cloudwatch_event_rule" "findings" {
  count       = local.enable_cloudwatch == true ? 1 : 0
  name        = module.findings_label.id
  description = "GuardDuty Findings"
  tags        = module.this.tags

  event_pattern = jsonencode(
    {
      "source" : [
        "aws.guardduty"
      ],
      "detail-type" : [
        var.cloudwatch_event_rule_pattern_detail_type
      ]
    }
  )
}

resource "aws_cloudwatch_event_target" "imported_findings" {
  count = local.enable_notifications == true ? 1 : 0
  rule  = aws_cloudwatch_event_rule.findings[0].name
  arn   = local.findings_notification_arn
}

#-----------------------------------------------------------------------------------------------------------------------
# Locals and Data References
#-----------------------------------------------------------------------------------------------------------------------
locals {
  enable_cloudwatch         = module.this.enabled && (var.enable_cloudwatch || local.enable_notifications)
  enable_notifications      = module.this.enabled && (var.create_sns_topic || var.findings_notification_arn != null)
  create_sns_topic          = module.this.enabled && var.create_sns_topic
  findings_notification_arn = local.enable_notifications ? (var.findings_notification_arn != null ? var.findings_notification_arn : module.sns_topic[0].sns_topic.arn) : null
}
