benchmark "cloudtrail_log_detections_view" {
  title       = "CloudTrail Log Detections View"
  description = "This benchmark contains recommendations when scanning CloudTrail logs."
  type        = "detection"
  children = [
    detection.detect_all,
  ]

  tags = {
    type    = "Benchmark"
    service = "AWS/CloudTrail"
  }
}


detection "detect_all" {
  title       = "Detect CloudTrail Logs"
  description = "Detect CloudTrail log errors."
  severity    = "low"
  query       = query.detect_all
}

query "detect_all" {
  sql = <<-EOQ
    select
      epoch_ms(tp_timestamp) as timestamp,
      string_split(event_source, '.')[1] || ':' || event_name as operation,
      --__RESOURCE_SQL__ as resource,
      user_identity.arn as actor,
      tp_source_ip as source_ip,
      tp_index::varchar as account_id,
      aws_region as region,
      tp_id as source_id,
      *
    from
      aws_cloudtrail_log
    order by
      event_time desc
    limit 10000;
  EOQ
}
