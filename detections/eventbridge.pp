locals {
  eventbridge_common_tags = merge(local.aws_cloudtrail_log_detections_common_tags, {
    service = "AWS/EventBridge"
  })

  detect_disabled_eventbridge_rules_sql_columns  = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.name')")
  detect_eventbridge_rule_deletions_sql_columns  = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.name')")
}

benchmark "eventbridge_detections" {
  title       = "EventBridge Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for EventBridge events."
  type        = "detection"
  children    = [
    detection.detect_eventbridge_rule_deletions,
    detection.detect_disabled_eventbridge_rules
  ]

  tags = merge(local.eventbridge_common_tags, {
    type    = "Benchmark"
  })
}

detection "detect_disabled_eventbridge_rules" {
  title           = "Detect Disabled EventBridge Rules"
  description     = "Detect when EventBridge rules are disabled. Disabling EventBridge rules can disrupt automated workflows, scheduled tasks, and alerting mechanisms, potentially preventing the detection or mitigation of malicious activities."
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.detect_disabled_eventbridge_rules

  tags = merge(local.eventbridge_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001"
  })
}

detection "detect_eventbridge_rule_deletions" {
  title           = "Detect EventBridge Rule Deletion"
  description     = "Detect when EventBridge rules are deleted. Deleting EventBridge rules can disrupt critical automation and monitoring workflows, potentially allowing malicious activities to go undetected or unmitigated."
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.detect_eventbridge_rule_deletions

  tags = merge(local.eventbridge_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

query "detect_disabled_eventbridge_rules" {
  sql = <<-EOQ
    select
      ${local.detect_disabled_eventbridge_rules_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'eventbridge.amazonaws.com'
      and event_name = 'DisableRule'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "detect_eventbridge_rule_deletions" {
  sql = <<-EOQ
    select
      ${local.detect_eventbridge_rule_deletions_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'eventbridge.amazonaws.com'
      and event_name = 'DeleteRule'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}
