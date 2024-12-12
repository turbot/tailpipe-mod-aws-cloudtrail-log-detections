locals {
  cloudtrail_logs_detect_ssm_parameter_store_access_sql_columns    = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
}

benchmark "cloudtrail_logs_ssm_detections" {
  title       = "CloudTrail Log SSM Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail's SSM logs."
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_secrets_manager_secret_access,
  ]

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    type    = "Benchmark"
    service = "AWS/SSM"
  })
}

detection "cloudtrail_logs_detect_ssm_parameter_store_access" {
  title       = "Detect SSM Parameters Store Secret Access"
  description = "Detect when a secret is accessed from AWS SSM Parameter Store."
  severity    = "high"
  query       = query.cloudtrail_logs_detect_ssm_parameter_store_access

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0006:T1552.007"
  })
}

query "cloudtrail_logs_detect_ssm_parameter_store_access" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_ssm_parameter_store_access_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ssm.amazonaws.com'
      and event_name = 'GetParameter'
      and cast(request_parameters ->> 'withDecryption' as text) = 'true'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

