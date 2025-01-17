locals {
  eventbridge_common_tags = merge(local.aws_cloudtrail_log_detections_common_tags, {
    service = "AWS/EventBridge"
  })

}

benchmark "eventbridge_detections" {
  title       = "EventBridge Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for EventBridge events."
  type        = "detection"
  children = [
    detection.eventbridge_rules_deleted,
    detection.eventbridge_rules_disabled
  ]

  tags = merge(local.eventbridge_common_tags, {
    type = "Benchmark"
  })
}

detection "eventbridge_rules_disabled" {
  title           = "EventBridge Rules Disabled"
  description     = "Detect when EventBridge rules were disabled to check for disruptions to automated workflows, scheduled tasks, and alerting mechanisms, which could prevent detection or mitigation of malicious activities."
  # documentation   = file("./detections/docs/detect_eventbridge_rules_disabled.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.eventbridge_rules_disabled

  tags = merge(local.eventbridge_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001"
  })
}

detection "eventbridge_rules_deleted" {
  title           = "EventBridge Rules Deleted"
  description     = "Detect when EventBridge rules were deleted to check for disruptions to critical automation and monitoring workflows, potentially allowing malicious activities to go undetected or unmitigated."
  # documentation   = file("./detections/docs/detect_eventbridge_rule_deletions.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.eventbridge_rules_deleted

  tags = merge(local.eventbridge_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

query "eventbridge_rules_disabled" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_eventbridge_rule_name}
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

query "eventbridge_rules_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_eventbridge_rule_name}
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
