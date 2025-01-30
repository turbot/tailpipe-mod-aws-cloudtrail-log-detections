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
    detection.ses_identity_feedback_forwarding_disabled,
  ]

  tags = merge(local.ses_common_tags, {
    type = "Benchmark"
  })
}

detection "ses_identity_feedback_forwarding_disabled" {
  title           = "SES Identity Feedback Forwarding Disabled"
  description     = "Detect when AWS SES feedback forwarding was disabled for an identity, which may allow attackers to evade monitoring of bounce or complaint notifications, enabling undetected spam or phishing attacks."
  documentation   = file("./detections/docs/ses_identity_feedback_forwarding_disabled.md")
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.ses_identity_feedback_forwarding_disabled

  tags = merge(local.ses_common_tags, {
    mitre_attack_ids = "TA0005:T1562.008"
  })
}

query "ses_identity_feedback_forwarding_disabled" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_name}
    from
      aws_cloudtrail_log
    where
      event_source = 'ses.amazonaws.com'
      and event_name = 'SetIdentityFeedbackForwardingEnabled'
      and (request_parameters -> 'forwardingEnabled') = false
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}
