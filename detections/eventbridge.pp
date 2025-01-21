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
    detection.eventbridge_rule_deleted,
    detection.eventbridge_rule_disabled
  ]

  tags = merge(local.eventbridge_common_tags, {
    type = "Benchmark"
  })
}

detection "eventbridge_rule_disabled" {
  title       = "EventBridge Rule Disabled"
  description = "Detect when a EventBridge rule was disabled to check for disruptions to critical automation and monitoring workflows, potentially allowing malicious activities to go undetected or unmitigated."
  # documentation   = file("./detections/docs/detect_eventbridge_rule_disabled.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.eventbridge_rule_disabled

  tags = merge(local.eventbridge_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001"
  })
}

detection "eventbridge_rule_deleted" {
  title       = "EventBridge Rule Deleted"
  description = "Detect when a EventBridge rule was deleted to check for unauthorized changes that could reduce visibility into critical automation and monitoring workflows, potentially hindering threat detection and compliance efforts."
  # documentation   = file("./detections/docs/detect_eventbridge_rule_deletions.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.eventbridge_rule_deleted

  tags = merge(local.eventbridge_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

query "eventbridge_rule_disabled" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_name}
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

query "eventbridge_rule_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_name}
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
