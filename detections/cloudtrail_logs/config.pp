locals {
  cloudtrail_logs_detect_config_service_rule_delete_sql_columns                  = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.configRuleName")
  cloudtrail_logs_detect_configuration_recorder_stop_sql_columns                 = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.configurationRecorderName")
}

benchmark "cloudtrail_logs_config_detections" {
  title       = "Config Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail's Config logs"
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_config_service_rule_delete,
    detection.cloudtrail_logs_detect_configuration_recorder_stop,
  ]

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    type    = "Benchmark"
    service = "AWS/Config"
  })
}

detection "cloudtrail_logs_detect_config_service_rule_delete" {
  title       = "Detect Config Service Rules Deletions"
  description = "Detect the deletions of Config service rules."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_config_service_rule_delete

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "T1562.001"
  })
}

detection "cloudtrail_logs_detect_configuration_recorder_stop" {
  title       = "Detect Configuration Recorders Stopped"
  description = "Detect when configuration recorders are stopped."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_configuration_recorder_stop

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0005.T1562"
  })
}

query "cloudtrail_logs_detect_config_service_rule_delete" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_config_service_rule_delete_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'config.amazonaws.com'
      and event_name in ('DeleteConfigRule', 'DeleteOrganizationConfigRule', 'DeleteConfigurationAggregator', 'DeleteConfigurationRecorder', 'DeleteConformancePack', 'DeleteOrganizationConformancePack', 'DeleteDeliveryChannel', 'DeleteRemediationConfiguration', 'DeleteRetentionConfiguration')
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_configuration_recorder_stop" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_configuration_recorder_stop_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'config.amazonaws.com'
      and event_name = 'StopConfigurationRecorder'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}