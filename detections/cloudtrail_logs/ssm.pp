locals {
  cloudtrail_logs_detect_ssm_parameter_store_access_sql_columns    = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
  cloudtrail_logs_detect_ssm_run_command_sql_columns    = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.documentName")
  cloudtrail_logs_detect_ssm_unauthorized_input_captures_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
  cloudtrail_logs_detect_ssm_unauthorized_data_access_from_local_systems_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.documentName")
}

benchmark "cloudtrail_logs_ssm_detections" {
  title       = "CloudTrail Log SSM Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail's SSM logs."
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_secrets_manager_secret_access,
    detection.cloudtrail_logs_detect_ssm_run_command,
    detection.cloudtrail_logs_detect_ssm_unauthorized_input_captures,
    detection.cloudtrail_logs_detect_ssm_unauthorized_data_access_from_local_systems
  ]

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    type    = "Benchmark"
    service = "AWS/SSM"
  })
}

detection "cloudtrail_logs_detect_ssm_parameter_store_access" {
  title       = "Detect SSM Parameter Store Secret Access"
  description = "Detect when a secret is accessed from AWS SSM Parameter Store."
  severity    = "high"
  query       = query.cloudtrail_logs_detect_ssm_parameter_store_access

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0006:T1552.007"
  })
}

detection "cloudtrail_logs_detect_ssm_run_command" {
  title       = "Detect SSM Run Command Execution"
  description = "Detect execution of commands on EC2 instances via AWS SSM Run Command."
  severity    = "high"
  query       = query.cloudtrail_logs_detect_ssm_run_command

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0002:T1059"
  })
}

detection "cloudtrail_logs_detect_ssm_unauthorized_input_captures" {
  title       = "Detect Input Capture via AWS Services"
  description = "Detect unauthorized input capture, such as keyboard input logging in AWS Systems Manager."
  severity    = "high"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_ssm_unauthorized_input_captures.md")
  query       = query.cloudtrail_logs_detect_ssm_unauthorized_input_captures

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0009:T1056"
  })
}

detection "cloudtrail_logs_detect_ssm_unauthorized_data_access_from_local_systems" {
  title       = "Detect Data Collection from Local System"
  description = "Detect attempts to access local system data using SSM or other AWS services."
  severity    = "high"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_ssm_unauthorized_data_access_from_local_systems.md")
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
      and event_name in ('SendCommand', 'GetCommandInvocation')
      and request_parameters.documentName = 'AWS-RunShellScript'
      and error_code is null
    order by
      event_time desc;
  EOQ
}

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
      and error_code is null
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_ssm_parameter_store_access" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_ssm_parameter_store_access_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ssm.amazonaws.com'
      and event_name = 'GetParameter'
      and cast(request_parameters ->> 'withDecryption' as text) = 'true'
      and error_code is null
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_ssm_run_command" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_ssm_run_command_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ssm.amazonaws.com'
      and event_name = 'SendCommand'
      and error_code is null
    order by
      event_time desc;
  EOQ
}
