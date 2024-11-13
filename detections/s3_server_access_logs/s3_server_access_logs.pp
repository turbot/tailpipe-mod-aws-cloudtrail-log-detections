locals {
  s3_server_access_log_detection_common_tags = merge(local.aws_detections_common_tags, {
    service = "AWS/S3"
  })
}

detection_benchmark "s3_server_access_logs_detections" {
  title       = "S3 Server Access Log Detections"
  description = "This detection_benchmark contains recommendations when scanning S3 server access logs."
  type        = "detection"
  children = [
    detection.s3_server_access_logs_detect_access_errors,
    detection.s3_server_access_logs_detect_insecure_access,
  ]

  tags = merge(local.s3_server_access_log_detection_common_tags, {
    type = "Benchmark"
  })
}

detection "s3_server_access_logs_detect_access_errors" {
  title       = "Detect Access Errors in S3 Server Access Logs"
  description = "Detect server access request errors to check for possible brute force attacks."
  severity    = "low"
  query       = query.s3_server_access_logs_detect_access_errors

  tags = merge(local.s3_server_access_log_detection_common_tags, {
    mitre_attack_ids = "TA0007:T1619"
  })
}

detection "s3_server_access_logs_detect_insecure_access" {
  title       = "Detect Insecure Access in S3 Server Access Logs"
  description = "Detect insecure server access requests to check for possible application misconfigurations."
  severity    = "low"
  query       = query.s3_server_access_logs_detect_insecure_access

  tags = merge(local.s3_server_access_log_detection_common_tags, {
    mitre_attack_ids = "TA0009:T1530"
  })
}

query "s3_server_access_logs_detect_access_errors" {
  sql = <<-EOQ
    select
      ${local.s3_server_access_log_detection_sql_columns}
    from
      aws_s3_server_access_log
    where
      operation ilike 'REST.%.OBJECT'
      and not starts_with(user_agent, 'aws-internal')
      and http_status in (403, 405)
    order by
      timestamp desc
  EOQ
}

query "s3_server_access_logs_detect_insecure_access" {
  sql = <<-EOQ
    select
      ${local.s3_server_access_log_detection_sql_columns}
    from
      aws_s3_server_access_log
    where
      operation ilike 'REST.%.OBJECT' -- Ignore S3 initiated events
      and (cipher_suite is null or tls_version is null)
    order by
      timestamp desc
  EOQ
}
