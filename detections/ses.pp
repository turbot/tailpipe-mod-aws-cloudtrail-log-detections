locals {
  ses_common_tags = merge(local.aws_cloudtrail_log_detections_common_tags, {
    service = "AWS/SES"
  })

  detect_ses_unauthorized_email_collections_sql_columns                                             = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.name')")
  detect_ses_identity_policy_modifications_with_wildcard_permissions_or_external_access_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.name')")
  detect_ses_sending_enabled_sql_columns                                                            = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.name')")
  detect_ses_sending_rate_limit_increase_sql_columns                                                = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.name')")
  detect_ses_feedback_forwarding_disabled_sql_columns                                               = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.name')")
}

benchmark "ses_detections" {
  title       = "SES Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for SES events."
  type        = "detection"
  children = [
    detection.detect_ses_unauthorized_email_collections,
    detection.detect_ses_identity_policy_modifications_with_wildcard_permissions_or_external_access,
    detection.detect_ses_sending_enabled,
    detection.detect_ses_sending_rate_limit_increase,
    detection.detect_ses_feedback_forwarding_disabled,
  ]

  tags = merge(local.ses_common_tags, {
    type = "Benchmark"
  })
}

detection "detect_ses_unauthorized_email_collections" {
  title           = "Detect SES Unauthorized Email Collections"
  description     = "Detect unauthorized attempts to read, download, or collect emails using AWS Simple Email Service (SES). This activity may indicate data exfiltration or unauthorized access to sensitive email communications."
  severity        = "medium"
  display_columns = local.detection_display_columns
  documentation   = file("./detections/docs/detect_ses_unauthorized_email_collections.md")
  query           = query.detect_ses_unauthorized_email_collections

  tags = merge(local.ses_common_tags, {
    mitre_attack_ids = "TA0009:T1114.001"
  })
}

query "detect_ses_unauthorized_email_collections" {
  sql = <<-EOQ
    select
      ${local.detect_ses_unauthorized_email_collections_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'email.amazonaws.com'
      and event_name in (
        'SendEmail',
        'VerifyEmailIdentity',
        'DeleteIdentity'
      )
      and (json_extract_string(user_identity, '$.type') = 'IAMUser' or json_extract_string(user_identity, '$.type') = 'AssumedRole')
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "detect_ses_identity_policy_modifications_with_wildcard_permissions_or_external_access" {
  title           = "Detect SES Identity Policy Modifications with Wildcard Permissions or External Access"
  description     = "Detect changes to AWS SES identity policies that grant permissions to all users (wildcards) or external accounts. These changes can allow unauthorized email sending, enabling phishing, spam, or data exfiltration."
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.detect_ses_identity_policy_modifications_with_wildcard_permissions_or_external_access

  tags = merge(local.ses_common_tags, {
    mitre_attack_ids = "TA0006:T1556"
  })
}

query "detect_ses_identity_policy_modifications_with_wildcard_permissions_or_external_access" {
  sql = <<-EOQ
    select
      ${local.detect_ses_identity_policy_modifications_with_wildcard_permissions_or_external_access_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_name in ('PutIdentityPolicy', 'DeleteIdentityPolicy')
      and (
        -- Detect wildcard principal
        json_extract_string(request_parameters, '$.policy') like '%"AWS":"*"%' 

        -- Detect risky actions such as SendEmail or SendRawEmail
        or json_extract_string(request_parameters, '$.policy') like '%"Action":"SES:SendEmail"%'
        or json_extract_string(request_parameters, '$.policy') like '%"Action":"SES:SendRawEmail"%'

        -- Detect wildcard resource access
        or json_extract_string(request_parameters, '$.policy') like '%"Resource":"*"%' 
      )
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "detect_ses_sending_enabled" {
  title           = "Detect SES Sending Enabled"
  description     = "Detect when AWS SES email sending is enabled. Enabling email sending may allow resumption of email campaigns, potentially used for spam or phishing attacks."
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.detect_ses_sending_enabled

  tags = merge(local.ses_common_tags, {
    mitre_attack_ids = "TA0005:T1566"
  })
}

query "detect_ses_sending_enabled" {
  sql = <<-EOQ
    select
      ${local.detect_ses_sending_enabled_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_name = 'UpdateAccountSendingEnabled'
      -- Check specifically for enabling email sending
      and json_extract_string(request_parameters, '$.enabled') = 'true'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "detect_ses_sending_rate_limit_increase" {
  title           = "Detect SES Sending Rate Limit Increase"
  description     = "Detect increases in AWS SES sending rate limits. Sudden increases may indicate preparation for bulk email campaigns, potentially for spam or phishing attacks."
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.detect_ses_sending_rate_limit_increase

  tags = merge(local.ses_common_tags, {
    mitre_attack_ids = "TA0001:T1566"
  })
}

query "detect_ses_sending_rate_limit_increase" {
  sql = <<-EOQ
    select
      ${local.detect_ses_sending_rate_limit_increase_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_name = 'UpdateAccountSendingRateLimit'
      -- Check for rate limit increases above 50 emails/sec (adjustable threshold)
      and json_extract_string(request_parameters, '$.maxSendingRate')::float > 50
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "detect_ses_feedback_forwarding_disabled" {
  title           = "Detect SES Feedback Forwarding Disabled"
  description     = "Detect when AWS SES feedback forwarding is disabled. Disabling feedback forwarding may allow attackers to evade monitoring of bounce or complaint notifications, enabling undetected spam or phishing attacks."
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.detect_ses_feedback_forwarding_disabled

  tags = merge(local.ses_common_tags, {
    mitre_attack_ids = "TA0005:T1070"
  })
}

query "detect_ses_feedback_forwarding_disabled" {
  sql = <<-EOQ
    select
      ${local.detect_ses_feedback_forwarding_disabled_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_name = 'SetIdentityFeedbackForwardingEnabled'
      -- Check specifically for disabling feedback forwarding
      and json_extract_string(request_parameters, '$.forwardingEnabled') = 'false'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}
