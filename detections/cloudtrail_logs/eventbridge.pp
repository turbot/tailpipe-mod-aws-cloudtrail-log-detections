locals {
  cloudtrail_logs_detect_eventbridge_rule_deletion_updates_sql_columns      = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
}

benchmark "cloudtrail_logs_eventbridge_detections" {
  title       = "CloudTrail Log EventBridge Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail's EventBridge logs"
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_eventbridge_rule_disabled_or_deletion_updates,
  ]

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    type    = "Benchmark"
    service = "AWS/Eventbridge"
  })
}

detection "cloudtrail_logs_detect_eventbridge_rule_disabled_or_deletion_updates" {
  title       = "Detect EventBridge Rules Disabled or Deletion Updates"
  description = "Detect EventBridge rules disabled or deletion updates to check for unauthorized changes."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_eventbridge_rule_disabled_or_deletion_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

query "cloudtrail_logs_detect_eventbridge_rule_disabled_or_deletion_updates" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_eventbridge_rule_deletion_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'eventbridge.amazonaws.com'
      and event_name in ('DeleteRule', 'DisableRule')
      and error_code is null
    order by
      event_time desc;
  EOQ
}
