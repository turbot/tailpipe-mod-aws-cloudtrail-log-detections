locals {
  ssm_common_tags = merge(local.aws_cloudtrail_log_detections_common_tags, {
    service = "AWS/SSM"
  })

  ssm_document_with_unauthorized_data_access_from_local_system_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.documentName')")
  ssm_document_shared_publicly_sql_columns                         = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.name')")
}

benchmark "ssm_detections" {
  title       = "SSM Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for SSM events."
  type        = "detection"
  children = [
    detection.ssm_document_with_unauthorized_input_capture,
    detection.ssm_document_with_unauthorized_data_access_from_local_system,
    detection.ssm_document_shared_publicly,
  ]

  tags = merge(local.ssm_common_tags, {
    type = "Benchmark"
  })
}

detection "ssm_document_with_unauthorized_input_capture" {
  title           = "SSM Document with Unauthorized Input Capture"
  description     = "Detect when an AWS Systems Manager document was created or updated with unauthorized input capture, such as keyboard input logging, to check for potential risks of data exfiltration or credential theft."
  documentation   = file("./detections/docs/ssm_document_with_unauthorized_input_capture.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.ssm_document_with_unauthorized_input_capture

  tags = merge(local.ssm_common_tags, {
    mitre_attack_ids = "TA0009:T1056"
  })
}

detection "ssm_document_with_unauthorized_data_access_from_local_system" {
  title           = "SSM Document with Unauthorized Data Access from Local System"
  description     = "Detect when an AWS Systems Manager document was used to access local system data without authorization to check for potential risks of sensitive information collection, such as configuration files, credentials, or logs, from compromised systems."
  documentation   = file("./detections/docs/ssm_document_with_unauthorized_data_access_from_local_system.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.ssm_document_with_unauthorized_data_access_from_local_system

  tags = merge(local.ssm_common_tags, {
    mitre_attack_ids = "TA0009:T1005"
  })
}

query "ssm_document_with_unauthorized_data_access_from_local_system" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_document_name}
    from
      aws_cloudtrail_log
    where
      event_source = 'ssm.amazonaws.com'
      and event_name = 'SendCommand'
      and (request_parameters ->> 'documentName') = 'AWS-RunShellScript'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "ssm_document_with_unauthorized_input_capture" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_name}
    from
      aws_cloudtrail_log
    where
      event_source = 'ssm.amazonaws.com'
      and event_name = 'StartSession'
      and (request_parameters ->> 'documentName') = 'AWS-StartPortForwardingSession'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "ssm_document_shared_publicly" {
  title           = "SSM Document Shared Publicly"
  description     = "Detect when an AWS Systems Manager document was shared publicly to check for potential risks of exposing sensitive configurations, scripts, or automation workflows to unauthorized access."
  documentation   = file("./detections/docs/ssm_document_shared_publicly.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.ssm_document_shared_publicly

  tags = merge(local.ssm_common_tags, {
    mitre_attack_ids = "TA0010:T1567"
  })
}

query "ssm_document_shared_publicly" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_name}
    from
      aws_cloudtrail_log
    where
      event_name = 'ModifyDocumentPermission'
      and (request_parameters ->> '$.permissions') like '%All%'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}
