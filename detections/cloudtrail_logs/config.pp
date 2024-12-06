benchmark "cloudtrail_logs_config_detections" {
  title       = "CloudTrail Log Config Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail's Config logs"
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_config_service_rule_delete,
    detection.cloudtrail_logs_detect_configuration_recorder_stop,
  ]
}

detection "cloudtrail_logs_detect_config_service_rule_delete" {
  title       = "Detect Config Service Rule Deleted"
  description = "Detect the deletion of config service rule."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_config_service_rule_delete

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "T1562.001"
  })
}

detection "cloudtrail_logs_detect_configuration_recorder_stop" {
  title       = "Detect Configuration Recorder Stopped"
  description = "Detect when the configuration recorder is stopped."
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
      and error_code is null
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
      and error_code is null
    order by
      event_time desc;
  EOQ
}