locals {
  cloudtrail_logs_detect_config_service_rule_deletions_sql_columns        = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.configRuleName")
  cloudtrail_logs_detect_configuration_recorder_stop_updates_sql_columns  = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.configurationRecorderName")
}

benchmark "cloudtrail_logs_config_detections" {
  title       = "Config Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail's Config logs"
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_config_service_rule_deletions,
    detection.cloudtrail_logs_detect_configuration_recorder_stop_updates,
    detection.cloudtrail_logs_detect_config_service_delivery_channel_deletions,
    detection.cloudtrail_logs_detect_config_service_configuration_recorder_deletions,
  ]

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    type    = "Benchmark"
    service = "AWS/Config"
  })
}

detection "cloudtrail_logs_detect_config_service_rule_deletions" {
  title       = "Detect Config Service Rules Deletions"
  description = "Detect the deletions of Config service rules."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_config_service_rule_deletions

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "T1562.001"
  })
}

detection "cloudtrail_logs_detect_config_service_delivery_channel_deletions" {
  title       = "Detect Config Service Delivery Channel Deletions"
  description = "Detect the deletions of Config service delivery channels."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_config_service_delivery_channel_deletions

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "T1562.001"
  })
}

query "cloudtrail_logs_detect_config_service_delivery_channel_deletions" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_config_service_rule_deletions_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'config.amazonaws.com'
      and event_name = 'DeleteDeliveryChannel'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_config_service_configuration_recorder_deletions" {
  title       = "Detect Config Service Configuration Recorder Deletions"
  description = "Detect the deletions of Config service configuration recorder."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_config_service_configuration_recorder_deletions

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "T1562.001"
  })
}

query "cloudtrail_logs_detect_config_service_configuration_recorder_deletions" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_config_service_rule_deletions_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'config.amazonaws.com'
      and event_name = 'DeleteConfigurationRecorder'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_configuration_recorder_stop_updates" {
  title       = "Detect Configuration Recorder Stop Updates"
  description = "Detect when configuration recorders are stopped."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_configuration_recorder_stop_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0005.T1562"
  })
}

query "cloudtrail_logs_detect_config_service_rule_deletions" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_config_service_rule_deletions_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'config.amazonaws.com'
      and event_name in ('DeleteConfigRule', 'DeleteOrganizationConfigRule', 'DeleteConfigurationAggregator', 'DeleteConformancePack', 'DeleteOrganizationConformancePack', 'DeleteRemediationConfiguration', 'DeleteRetentionConfiguration')
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_configuration_recorder_stop_updates" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_configuration_recorder_stop_updates_sql_columns}
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