locals {
  cloudtrail_logs_detect_cloudfront_distribution_updates_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
}

benchmark "cloudtrail_logs_cloudfront_detections" {
  title       = "CloudTrail Log Cloudfront Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail's Cloudfront logs"
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_cloudfront_distribution_updates
  ]

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    type    = "Benchmark"
    service = "AWS/Cloudfront"
  })
}

detection "cloudtrail_logs_detect_cloudfront_distribution_updates" {
  title       = "Detect Exfiltration via CloudFront"
  description = "Detect unusual data download activity using CloudFront."
  severity    = "medium"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_cloudfront_distribution_updates.md")
  query       = query.cloudtrail_logs_detect_cloudfront_distribution_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0010:T1048"
  })
}

query "cloudtrail_logs_detect_cloudfront_distribution_updates" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_cloudfront_distribution_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'cloudfront.amazonaws.com'
      and event_name in ('CreateDistribution', 'UpdateDistribution', 'DeleteDistribution')
      and request_parameters.protocol_policy not in ('https-only')
    order by
      event_time desc;
  EOQ
}
