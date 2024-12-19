locals {
  cloudtrail_log_detection_ssm_common_tags = merge(local.cloudtrail_log_detection_common_tags, {
    service = "AWS/SSM"
  })

  cloudtrail_logs_detect_ssm_with_unauthorized_input_captures_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.name')")
  cloudtrail_logs_detect_ssm_with_unauthorized_data_access_from_local_systems_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.documentName')")
}

benchmark "cloudtrail_logs_ssm_detections" {
  title       = "SSM Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for SSM events."
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_ssm_with_unauthorized_input_captures,
    detection.cloudtrail_logs_detect_ssm_with_unauthorized_data_access_from_local_systems
  ]

  tags = merge(local.cloudtrail_log_detection_ssm_common_tags, {
    type    = "Benchmark"
  })
}

detection "cloudtrail_logs_detect_ssm_with_unauthorized_input_captures" {
  title           = "Detect Input Capture via AWS Services"
  description     = "Detect unauthorized input capture, such as keyboard input logging in AWS Systems Manager."
  severity        = "high"
  display_columns = local.cloudtrail_log_detection_display_columns
  documentation   = file("./detections/docs/cloudtrail_logs_detect_ssm_with_unauthorized_input_captures.md")
  query           = query.cloudtrail_logs_detect_ssm_with_unauthorized_input_captures

  tags = merge(local.cloudtrail_log_detection_ssm_common_tags, {
    mitre_attack_ids = "TA0009:T1056"
  })
}

detection "cloudtrail_logs_detect_ssm_with_unauthorized_data_access_from_local_systems" {
  title           = "Detect SSM with unauthorized data access from local systems"
  description     = "Detect attempts to use (SSM) to access local system data without authorization. This activity may indicate malicious attempts to collect sensitive information, such as configuration files, credentials, or logs, from compromised systems."
  severity        = "high"
  display_columns = local.cloudtrail_log_detection_display_columns
  documentation   = file("./detections/docs/cloudtrail_logs_detect_ssm_with_unauthorized_data_access_from_local_systems.md")
  query           = query.cloudtrail_logs_detect_ssm_with_unauthorized_data_access_from_local_systems

  tags = merge(local.cloudtrail_log_detection_ssm_common_tags, {
    mitre_attack_ids = "TA0009:T1005"
  })
}

query "cloudtrail_logs_detect_ssm_with_unauthorized_data_access_from_local_systems" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_ssm_with_unauthorized_data_access_from_local_systems_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ssm.amazonaws.com'
      and event_name = 'SendCommand'
      and json_extract_string(request_parameters, '$.documentName') = 'AWS-RunShellScript'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

// TODO: rename this
query "cloudtrail_logs_detect_ssm_with_unauthorized_input_captures" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_ssm_with_unauthorized_input_captures_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ssm.amazonaws.com'
      and event_name = 'StartSession'
      and json_extract_string(request_parameters, '$.documentName') = 'AWS-StartPortForwardingSession'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}
