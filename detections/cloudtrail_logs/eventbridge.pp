locals {
  cloudtrail_log_detection_eventbridge_common_tags = merge(local.cloudtrail_log_detection_common_tags, {
    service = "AWS/EventBridge"
  })

  cloudtrail_logs_detect_disabled_eventbridge_rules_sql_columns  = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.name')")
  cloudtrail_logs_detect_eventbridge_rule_deletions_sql_columns  = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.name')")
}

benchmark "cloudtrail_logs_eventbridge_detections" {
  title       = "EventBridge Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for EventBridge events."
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_eventbridge_rule_deletions,
    detection.cloudtrail_logs_detect_disabled_eventbridge_rules
  ]

  tags = merge(local.cloudtrail_log_detection_eventbridge_common_tags, {
    type    = "Benchmark"
  })
}

detection "cloudtrail_logs_detect_disabled_eventbridge_rules" {
  title       = "Detect Disabled EventBridge Rules"
  description = "Detect when EventBridge rules are disabled. Disabling EventBridge rules can disrupt automated workflows, scheduled tasks, and alerting mechanisms, potentially preventing the detection or mitigation of malicious activities."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_disabled_eventbridge_rules

  tags = merge(local.cloudtrail_log_detection_eventbridge_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001"
  })
}

detection "cloudtrail_logs_detect_eventbridge_rule_deletions" {
  title       = "Detect EventBridge Rule Deletion"
  description = "Detect when EventBridge rules are deleted. Deleting EventBridge rules can disrupt critical automation and monitoring workflows, potentially allowing malicious activities to go undetected or unmitigated."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_eventbridge_rule_deletions

  tags = merge(local.cloudtrail_log_detection_eventbridge_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

query "cloudtrail_logs_detect_disabled_eventbridge_rules" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_disabled_eventbridge_rules_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'eventbridge.amazonaws.com'
      and event_name = 'DisableRule'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_eventbridge_rule_deletions" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_eventbridge_rule_deletions_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'eventbridge.amazonaws.com'
      and event_name = 'DeleteRule'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}
