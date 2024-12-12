locals {
  cloudtrail_logs_detect_secrets_manager_secret_access_sql_columns    = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.secretId")
}

benchmark "cloudtrail_logs_secretsmanager_detections" {
  title       = "CloudTrail Log Secrets Manager Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail's Secrets Manager logs."
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_secrets_manager_secret_access,
  ]

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    type    = "Benchmark"
    service = "AWS/SecretsManager"
  })
}

detection "cloudtrail_logs_detect_secrets_manager_secret_access" {
  title       = "Detect Secrets Manager Secrets Access"
  description = "Detect when secrets are accessed from AWS Secrets Manager."
  severity    = "high"
  query       = query.cloudtrail_logs_detect_secrets_manager_secret_access

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0006:T1552.007"
  })
}

query "cloudtrail_logs_detect_secrets_manager_secret_access" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_secrets_manager_secret_access_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'secretsmanager.amazonaws.com'
      and event_name = 'GetSecretValue'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}
