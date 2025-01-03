benchmark "cloudtrail_log_error_detections" {
  title       = "CloudTrail Log Error Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs."
  type        = "detection"
  children = [
    detection.cloudtrail_logs_detect_errors,
  ]

  tags = {
    type    = "Benchmark"
    service = "AWS/CloudTrail"
  }
}


detection "cloudtrail_logs_detect_errors" {
  title       = "Detect CloudTrail Log Errors"
  description = "Detect CloudTrail log errors."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_errors
}

query "cloudtrail_logs_detect_errors" {
  sql = <<-EOQ
    select
      epoch_ms(tp_timestamp) as timestamp,
      string_split(event_source, '.')[1] || ':' || event_name as operation,
      --__RESOURCE_SQL__ as resource,
      user_identity.arn as actor,
      tp_source_ip as source_ip,
      tp_index::varchar as account_id,
      aws_region as region,
      error_code,
      error_message,
      tp_id as source_id,
      *
    from
      aws_cloudtrail_log
    where
      error_code is not null
    order by
      event_time desc;
  EOQ
}
