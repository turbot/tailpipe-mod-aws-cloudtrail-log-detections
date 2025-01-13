locals {
  cloudtrail_log_detection_ssm_common_tags = merge(local.cloudtrail_log_detection_common_tags, {
    service = "AWS/SSM"
  })

  cloudtrail_logs_detect_ssm_documents_with_unauthorized_input_captures_sql_columns                 = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.name')")
  cloudtrail_logs_detect_ssm_documents_with_unauthorized_data_access_from_local_systems_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.documentName')")
  cloudtrail_logs_detect_ssm_parameters_with_encryption_disabled_sql_columns              = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.name')")
  cloudtrail_logs_detect_public_access_granted_to_ssm_documents_sql_columns               = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.name')")
}

benchmark "cloudtrail_logs_ssm_detections" {
  title       = "SSM Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for SSM events."
  type        = "detection"
  children = [
    detection.cloudtrail_logs_detect_ssm_documents_with_unauthorized_input_captures,
    detection.cloudtrail_logs_detect_ssm_documents_with_unauthorized_data_access_from_local_systems,
    detection.cloudtrail_logs_detect_ssm_parameters_with_encryption_disabled,
    detection.cloudtrail_logs_detect_public_access_granted_to_ssm_documents,
  ]

  tags = merge(local.cloudtrail_log_detection_ssm_common_tags, {
    type = "Benchmark"
  })
}

detection "cloudtrail_logs_detect_ssm_documents_with_unauthorized_input_captures" {
  title           = "Detect SSM with Unauthorized Input Captures"
  description     = "Detect unauthorized input capture, such as keyboard input logging in AWS Systems Manager."
  severity        = "high"
  display_columns = local.cloudtrail_log_detection_display_columns
  #documentation   = file("./detections/docs/detect_ssm_documents_with_unauthorized_input_captures.md")
  query = query.cloudtrail_logs_detect_ssm_documents_with_unauthorized_input_captures

  tags = merge(local.cloudtrail_log_detection_ssm_common_tags, {
    mitre_attack_ids = "TA0009:T1056"
  })
}

detection "cloudtrail_logs_detect_ssm_documents_with_unauthorized_data_access_from_local_systems" {
  title           = "Detect SSM with Unauthorized Data Access from Local Systems"
  description     = "Detect attempts to use (SSM) to access local system data without authorization. This activity may indicate malicious attempts to collect sensitive information, such as configuration files, credentials, or logs, from compromised systems."
  severity        = "high"
  display_columns = local.cloudtrail_log_detection_display_columns
  #documentation   = file("./detections/docs/detect_ssm_documents_with_unauthorized_data_access_from_local_systems.md")
  query = query.cloudtrail_logs_detect_ssm_documents_with_unauthorized_data_access_from_local_systems

  tags = merge(local.cloudtrail_log_detection_ssm_common_tags, {
    mitre_attack_ids = "TA0009:T1005"
  })
}

query "cloudtrail_logs_detect_ssm_documents_with_unauthorized_data_access_from_local_systems" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_ssm_documents_with_unauthorized_data_access_from_local_systems_sql_columns}
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

query "cloudtrail_logs_detect_ssm_documents_with_unauthorized_input_captures" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_ssm_documents_with_unauthorized_input_captures_sql_columns}
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

detection "cloudtrail_logs_detect_ssm_parameters_with_encryption_disabled" {
  title           = "Detect SSM Parameters with Encryption Disabled"
  description     = "Detect when AWS Systems Manager parameters are accessed with encryption disabled. Accessing parameters without encryption can expose sensitive information stored as plain text."
  severity        = "high"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_ssm_parameters_with_encryption_disabled

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0006:T1552"
  })
}

query "cloudtrail_logs_detect_ssm_parameters_with_encryption_disabled" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_ssm_parameters_with_encryption_disabled_sql_columns}
    from
      aws_cloudtrail_log
    where
      -- Include both creation/modification and retrieval scenarios
      event_name in ('PutParameter', 'GetParameter')
      and (
        -- Check if parameter is stored as plaintext
        (event_name = 'PutParameter' and json_extract_string(request_parameters, '$.type') = 'String')
        or
        -- Check if parameter is retrieved without decryption
        (event_name = 'GetParameter' and json_extract_string(request_parameters, '$.withDecryption') = 'false')
      )
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_public_access_granted_to_ssm_documents" {
  title           = "Detect Public Access Granted to SSM Documents"
  description     = "Detect when an AWS Systems Manager document is shared publicly. Publicly shared documents can expose sensitive configurations, scripts, or automation workflows to unauthorized access."
  severity        = "critical"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_public_access_granted_to_ssm_documents

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0010:T1567"
  })
}

query "cloudtrail_logs_detect_public_access_granted_to_ssm_documents" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_public_access_granted_to_ssm_documents_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_name = 'ModifyDocumentPermission'
      and json_extract_string(request_parameters, '$.permissions') like '%All%'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}
