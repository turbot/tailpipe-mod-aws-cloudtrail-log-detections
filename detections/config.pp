locals {
  config_common_tags = merge(local.aws_cloudtrail_log_detections_common_tags, {
    service = "AWS/Config"
  })

  detect_config_rule_deletions_sql_columns        = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.configRuleName')")
  detect_config_configuration_recorders_with_recording_stopped_sql_columns  = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.configurationRecorderName')")
}

benchmark "config_detections" {
  title       = "Config Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for Config events."
  type        = "detection"
  children    = [
    detection.detect_config_rule_deletions,
    detection.detect_config_configuration_recorders_with_recording_stopped,
  ]

  tags = merge(local.config_common_tags, {
    type    = "Benchmark"
  })
}

detection "detect_config_rule_deletions" {
  title           = "Detect Config Rule Deletions"
  description     = "Detect the deletions of Config service rules to check for changes that could disrupt compliance monitoring or remove critical guardrails."
  documentation   = file("./detections/docs/detect_config_rule_deletions.md")
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.detect_config_rule_deletions

  tags = merge(local.config_common_tags, {
    mitre_attack_ids = "T1562.001"
  })
}

query "detect_config_rule_deletions" {
  sql = <<-EOQ
    select
      ${local.detect_config_rule_deletions_sql_columns}
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

detection "detect_config_configuration_recorders_with_recording_stopped" {
  title           = "Detect Config Configuration Recorders With Recording Stopped"
  description     = "Detect when configuration recorders are stopped to check for changes that could disrupt compliance monitoring and auditing, potentially obscuring unauthorized activity."
  documentation   = file("./detections/docs/detect_config_configuration_recorders_with_recording_stopped.md")
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.detect_config_configuration_recorders_with_recording_stopped

  tags = merge(local.config_common_tags, {
    mitre_attack_ids = "TA0005:T1562"
  })
}

query "detect_config_configuration_recorders_with_recording_stopped" {
  sql = <<-EOQ
    select
      ${local.detect_config_configuration_recorders_with_recording_stopped_sql_columns}
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
