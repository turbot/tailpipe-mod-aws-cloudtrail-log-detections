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
    detection.ses_identity_policy_modified_with_wildcard_or_external_access,
    detection.ses_email_sending_enabled,
    detection.ses_feedback_forwarding_disabled,
  ]

  tags = merge(local.ses_common_tags, {
    type = "Benchmark"
  })
}

detection "ses_identity_policy_modified_with_wildcard_or_external_access" {
  title           = "SES Identity Policy Modified With Wildcard or External Access"
  description     = "Detect when an AWS SES identity policy was modified to include wildcard permissions or grant access to external accounts, potentially allowing unauthorized email sending and enabling phishing, spam, or data exfiltration."
  documentation   = file("./detections/docs/ses_identity_policy_modified_with_wildcard_or_external_access.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.ses_identity_policy_modified_with_wildcard_or_external_access

  tags = merge(local.ses_common_tags, {
    mitre_attack_ids = "TA0006:T1556"
  })
}

query "ses_identity_policy_modified_with_wildcard_or_external_access" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_name}
    from
      aws_cloudtrail_log
    where
      event_name = 'PutIdentityPolicy'
      and (
        -- Detect wildcard principal
        (request_parameters ->> 'policy') like '%"AWS":"*"%' 

        -- Detect risky actions such as SendEmail or SendRawEmail
        or (request_parameters ->> 'policy') like '%"Action":"SES:SendEmail"%'
        or (request_parameters ->> 'policy') like '%"Action":"SES:SendRawEmail"%'

        -- Detect wildcard resource access
        or (request_parameters ->> 'policy') like '%"Resource":"*"%' 
      )
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
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
      and (request_parameters ->> 'enabled')::bool = true
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "ses_feedback_forwarding_disabled" {
  title           = "SES Feedback Forwarding Disabled"
  description     = "Detect when AWS SES feedback forwarding was disabled, which may allow attackers to evade monitoring of bounce or complaint notifications, enabling undetected spam or phishing attacks."
  documentation   = file("./detections/docs/ses_feedback_forwarding_disabled.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.ses_feedback_forwarding_disabled

  tags = merge(local.ses_common_tags, {
    mitre_attack_ids = "TA0005:T1070"
  })
}

query "ses_feedback_forwarding_disabled" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_name}
    from
      aws_cloudtrail_log
    where
      event_name = 'SetIdentityFeedbackForwardingEnabled'
      -- Check specifically for disabling feedback forwarding
      and (request_parameters ->> 'forwardingEnabled')::bool = false
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}
