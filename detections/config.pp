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
    detection.config_rules_deleted,
    detection.config_configuration_recorders_recording_stopped,
  ]

  tags = merge(local.config_common_tags, {
    type = "Benchmark"
  })
}

detection "config_rules_deleted" {
  title       = "Config Rules Deleted"
  description = "Detect when Config rules were deleted to check for changes that could disrupt compliance monitoring or remove critical guardrails, potentially allowing unauthorized configuration changes."
  # documentation   = file("./detections/docs/detect_config_rule_deletions.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.config_rules_deleted

  tags = merge(local.config_common_tags, {
    mitre_attack_ids = "T1562.001"
  })
}

query "config_rules_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_config_rule_name}
    from
      aws_cloudtrail_log
    where
      event_source = 'config.amazonaws.com'
      and event_name in ('DeleteConfigRule', 'DeleteOrganizationConfigRule', 'DeleteConfigurationAggregator', 'DeleteConformancePack', 'DeleteOrganizationConformancePack', 'DeleteRemediationConfiguration', 'DeleteRetentionConfiguration')
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "config_configuration_recorders_recording_stopped" {
  title           = "Config Configuration Recorders Recording Stopped"
  description     = "Detect when Config configuration recorders were stopped to check for changes that could disrupt compliance monitoring and auditing, potentially obscuring unauthorized activity."
  # documentation   = file("./detections/docs/detect_config_configuration_recorders_with_recording_stopped.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.config_configuration_recorders_recording_stopped

  tags = merge(local.config_common_tags, {
    mitre_attack_ids = "TA0005:T1562"
  })
}

query "config_configuration_recorders_recording_stopped" {
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
