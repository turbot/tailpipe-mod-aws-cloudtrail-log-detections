locals {
  cloudtrail_logs_detect_ses_unauthorized_email_collections_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
}

benchmark "cloudtrail_logs_ses_detections" {
  title       = "CloudTrail Log SES Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail's SES logs."
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_ses_unauthorized_email_collections,
  ]

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    type    = "Benchmark"
    service = "AWS/SES"
  })
}

detection "cloudtrail_logs_detect_ses_unauthorized_email_collections" {
  title       = "Detect Email Collection via AWS SES"
  description = "Detect unauthorized attempts to read or download emails using AWS SES."
  severity    = "medium"
  documentation = file("./detections/docs/cloudtrail_logs_detect_ses_unauthorized_email_collections.md")
  query       = query.cloudtrail_logs_detect_ses_unauthorized_email_collections

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0009:T1114.001"
  })
}

query "cloudtrail_logs_detect_ses_unauthorized_email_collections" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_ses_unauthorized_email_collections_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'email.amazonaws.com'
      and event_name in (
        'SendEmail',
        'VerifyEmailIdentity',
        'DeleteIdentity'
      )
      and (user_identity.type = 'IAMUser' or user_identity.type = 'AssumedRole')
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}