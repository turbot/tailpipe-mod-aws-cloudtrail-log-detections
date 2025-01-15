locals {
  ssm_common_tags = merge(local.aws_cloudtrail_log_detections_common_tags, {
    service = "AWS/SSM"
  })

  detect_ssm_documents_with_unauthorized_input_captures_sql_columns                 = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.name')")
  detect_ssm_documents_with_unauthorized_data_access_from_local_systems_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.documentName')")
  detect_public_access_granted_to_ssm_documents_sql_columns                         = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.name')")
}

benchmark "ssm_detections" {
  title       = "SSM Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for SSM events."
  type        = "detection"
  children = [
    detection.detect_ssm_documents_with_unauthorized_input_captures,
    detection.detect_ssm_documents_with_unauthorized_data_access_from_local_systems,
    detection.detect_public_access_granted_to_ssm_documents,
  ]

  tags = merge(local.ssm_common_tags, {
    type = "Benchmark"
  })
}

detection "detect_ssm_documents_with_unauthorized_input_captures" {
  title           = "Detect SSM with Unauthorized Input Captures"
  description     = "Detect unauthorized input capture, such as keyboard input logging in AWS Systems Manager."
  severity        = "high"
  display_columns = local.detection_display_columns
  #documentation   = file("./detections/docs/detect_ssm_documents_with_unauthorized_input_captures.md")
  query = query.detect_ssm_documents_with_unauthorized_input_captures

  tags = merge(local.ssm_common_tags, {
    mitre_attack_ids = "TA0009:T1056"
  })
}

detection "detect_ssm_documents_with_unauthorized_data_access_from_local_systems" {
  title           = "Detect SSM with Unauthorized Data Access from Local Systems"
  description     = "Detect attempts to use (SSM) to access local system data without authorization. This activity may indicate malicious attempts to collect sensitive information, such as configuration files, credentials, or logs, from compromised systems."
  severity        = "high"
  display_columns = local.detection_display_columns
  #documentation   = file("./detections/docs/detect_ssm_documents_with_unauthorized_data_access_from_local_systems.md")
  query = query.detect_ssm_documents_with_unauthorized_data_access_from_local_systems

  tags = merge(local.ssm_common_tags, {
    mitre_attack_ids = "TA0009:T1005"
  })
}

query "detect_ssm_documents_with_unauthorized_data_access_from_local_systems" {
  sql = <<-EOQ
    select
      ${local.detect_ssm_documents_with_unauthorized_data_access_from_local_systems_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ssm.amazonaws.com'
      and event_name = 'SendCommand'
      and json_extract_string(request_parameters, '$.documentName') = 'AWS-RunShellScript'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "detect_ssm_documents_with_unauthorized_input_captures" {
  sql = <<-EOQ
    select
      ${local.detect_ssm_documents_with_unauthorized_input_captures_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ssm.amazonaws.com'
      and event_name = 'StartSession'
      and json_extract_string(request_parameters, '$.documentName') = 'AWS-StartPortForwardingSession'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "detect_public_access_granted_to_ssm_documents" {
  title           = "Detect Public Access Granted to SSM Documents"
  description     = "Detect when an AWS Systems Manager document is shared publicly. Publicly shared documents can expose sensitive configurations, scripts, or automation workflows to unauthorized access."
  severity        = "critical"
  display_columns = local.detection_display_columns
  query           = query.detect_public_access_granted_to_ssm_documents

  tags = merge(local.ssm_common_tags, {
    mitre_attack_ids = "TA0010:T1567"
  })
}

query "detect_public_access_granted_to_ssm_documents" {
  sql = <<-EOQ
    select
      ${local.detect_public_access_granted_to_ssm_documents_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_name = 'ModifyDocumentPermission'
      and json_extract_string(request_parameters, '$.permissions') like '%All%'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}
