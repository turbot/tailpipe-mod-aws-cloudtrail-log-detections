locals {
  s3_server_access_logs_common_tags = merge(local.aws_common_tags, {
    service = "AWS/S3"
  })
}

detection_benchmark "s3_server_access_logs_detections" {
  title       = "S3 Server Access Log Detections"
  description = "This detection_benchmark contains recommendations when scanning S3 server access logs."
  type        = "detection"
  children = [
    detection.s3_server_access_logs_access_errors,
    detection.s3_server_access_logs_insecure_access,
  ]

  tags = merge(local.s3_server_access_logs_common_tags, {
    type = "Benchmark"
  })
}

detection "s3_server_access_logs_access_errors" {
  title       = "Check S3 Server Access Logs for Access Errors"
  description = "Detect server access requests that resulted in access errors."
  severity    = "low"
  query       = query.s3_server_access_logs_access_errors

  tags = merge(local.s3_server_access_logs_common_tags, {
    mitre_attack_ids = "TA0007:T1619"
  })
}

detection "s3_server_access_logs_insecure_access" {
  title       = "Check S3 Server Access Logs for Insecure Access"
  description = "Detect server access requests that were insecure requests."
  severity    = "low"
  query       = query.s3_server_access_logs_insecure_access

  tags = merge(local.s3_server_access_logs_common_tags, {
    mitre_attack_ids = "TA0009:T1530"
  })
}

query "s3_server_access_logs_access_errors" {
  sql = <<-EOQ
    select
      ${local.common_dimensions_s3_server_access_logs_sql}
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

query "s3_server_access_logs_insecure_access" {
  sql = <<-EOQ
    select
      ${local.common_dimensions_s3_server_access_logs_sql}
    from
      aws_s3_server_access_log
    where
      operation ilike 'REST.%.OBJECT' -- Ignore S3 initiated events
      and (cipher_suite is null or tls_version is null)
    order by
      timestamp desc
  EOQ
}
