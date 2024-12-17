locals {
  cloudtrail_logs_detect_ssm_unauthorized_input_captures_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
  cloudtrail_logs_detect_ssm_unauthorized_data_access_from_local_systems_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.documentName")
}

benchmark "cloudtrail_logs_ssm_detections" {
  title       = "CloudTrail Log SSM Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail's SSM logs."
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_ssm_unauthorized_input_captures,
    detection.cloudtrail_logs_detect_ssm_unauthorized_data_access_from_local_systems
  ]

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    type    = "Benchmark"
    service = "AWS/SSM"
  })
}

detection "cloudtrail_logs_detect_ssm_unauthorized_input_captures" {
  title       = "Detect Input Capture via AWS Services"
  description = "Detect unauthorized input capture, such as keyboard input logging in AWS Systems Manager."
  severity    = "high"
  documentation = file("./detections/docs/cloudtrail_logs_detect_ssm_unauthorized_input_captures.md")
  query       = query.cloudtrail_logs_detect_ssm_unauthorized_input_captures

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0009:T1056"
  })
}

// TODO: rename this
detection "cloudtrail_logs_detect_ssm_unauthorized_data_access_from_local_systems" {
  title       = "Detect Data Collection from Local System"
  description = "Detect attempts to access local system data using SSM or other AWS services."
  severity    = "high"
  documentation = file("./detections/docs/cloudtrail_logs_detect_ssm_unauthorized_data_access_from_local_systems.md")
  query       = query.cloudtrail_logs_detect_ssm_unauthorized_data_access_from_local_systems

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0009:T1005"
  })
}

query "cloudtrail_logs_detect_ssm_unauthorized_data_access_from_local_systems" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_ssm_unauthorized_data_access_from_local_systems_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ssm.amazonaws.com'
      and event_name = 'SendCommand'
      and cast(request_parameters ->> 'documentName' as text) = 'AWS-RunShellScript'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

// TODO: rename this
query "cloudtrail_logs_detect_ssm_unauthorized_input_captures" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_ssm_unauthorized_input_captures_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ssm.amazonaws.com'
      and event_name = 'StartSession'
      and request_parameters.documentName = 'AWS-StartPortForwardingSession'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

