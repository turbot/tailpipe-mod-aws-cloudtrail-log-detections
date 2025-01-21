locals {
  ses_common_tags = merge(local.aws_cloudtrail_log_detections_common_tags, {
    service = "AWS/SES"
  })
}

benchmark "ses_detections" {
  title       = "SES Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for SES events."
  type        = "detection"
  children = [
    detection.ses_email_sending_enabled,
    detection.ses_identity_feedback_forwarding_disabled,
  ]

  tags = merge(local.ses_common_tags, {
    type = "Benchmark"
  })
}

detection "ses_email_sending_enabled" {
  title           = "Detect SES Sending Email Enabled"
  description     = "Detect when AWS SES email sending was enabled, which may allow resumption of email campaigns that could be used for spam or phishing attacks."
  documentation   = file("./detections/docs/ses_email_sending_enabled.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.ses_email_sending_enabled

  tags = merge(local.ses_common_tags, {
    mitre_attack_ids = "TA0005:T1566"
  })
}

query "ses_email_sending_enabled" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_name}
    from
      aws_cloudtrail_log
    where
      event_name = 'UpdateAccountSendingEnabled'
      -- Check specifically for enabling email sending
      and (request_parameters -> 'enabled') = true
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "ses_identity_feedback_forwarding_disabled" {
  title           = "SES Identity Feedback Forwarding Disabled"
  description     = "Detect when AWS SES feedback forwarding is disabled for an identity, which may allow attackers to evade monitoring of bounce or complaint notifications, enabling undetected spam or phishing attacks."
  documentation   = file("./detections/docs/ses_identity_feedback_forwarding_disabled.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.ses_identity_feedback_forwarding_disabled

  tags = merge(local.ses_common_tags, {
    mitre_attack_ids = "TA0005:T1070"
  })
}

query "ses_identity_feedback_forwarding_disabled" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_name}
    from
      aws_cloudtrail_log
    where
      event_name = 'SetIdentityFeedbackForwardingEnabled'
      -- Check specifically for disabling feedback forwarding
      and (request_parameters -> 'forwardingEnabled') = false
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}
