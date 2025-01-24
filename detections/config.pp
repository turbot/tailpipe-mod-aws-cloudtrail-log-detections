locals {
  config_common_tags = merge(local.aws_cloudtrail_log_detections_common_tags, {
    service = "AWS/Config"
  })

}

benchmark "config_detections" {
  title       = "Config Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for Config events."
  type        = "detection"
  children = [
    detection.config_configuration_recorder_stopped,
    detection.config_rule_deleted,
  ]

  tags = merge(local.config_common_tags, {
    type = "Benchmark"
  })
}

detection "config_rule_deleted" {
  title           = "Config Rule Deleted"
  description     = "Detect when a Config rule was deleted to check for unauthorized changes that could reduce visibility into configuration changes, potentially hindering compliance monitoring and threat detection efforts."
  documentation   = file("./detections/docs/config_rule_deleted.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.config_rule_deleted

  tags = merge(local.config_common_tags, {
    mitre_attack_ids = "T1562.001"
  })
}

query "config_rule_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_config_rule_name}
    from
      aws_cloudtrail_log
    where
      event_source = 'config.amazonaws.com'
      and event_name = 'DeleteConfigRule'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "config_configuration_recorder_stopped" {
  title           = "Config Configuration Recorder Stopped"
  description     = "Detect when a Config configuration recorder was stopped to check for unauthorized changes that could reduce visibility into configuration changes, potentially hindering compliance monitoring and threat detection efforts."
  documentation   = file("./detections/docs/config_configuration_recorder_stopped.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.config_configuration_recorder_stopped

  tags = merge(local.config_common_tags, {
    mitre_attack_ids = "TA0005:T1562"
  })
}

query "config_configuration_recorder_stopped" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_config_record_name}
    from
      aws_cloudtrail_log
    where
      event_source = 'config.amazonaws.com'
      and event_name = 'StopConfigurationRecorder'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}
