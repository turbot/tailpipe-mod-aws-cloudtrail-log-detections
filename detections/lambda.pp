locals {
  cloudtrail_log_detection_lambda_common_tags = merge(local.cloudtrail_log_detection_common_tags, {
    service = "AWS/Lambda"
  })

  cloudtrail_logs_detect_public_access_granted_to_lambda_functions_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.functionName')")
  cloudtrail_logs_detect_lambda_function_code_updates_without_publish_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.functionName')")
  cloudtrail_logs_detect_lambda_functions_with_unencrypted_environment_variables_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.functionName')")
  cloudtrail_logs_detect_lambda_functions_with_unencrypted_code_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.functionName')")
}

benchmark "cloudtrail_logs_lambda_detections" {
  title       = "Lambda Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for Lambda events."
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_public_access_granted_to_lambda_functions,
    detection.cloudtrail_logs_detect_lambda_function_code_updates_without_publish,
    detection.cloudtrail_logs_detect_lambda_functions_with_unencrypted_environment_variables,
    detection.cloudtrail_logs_detect_lambda_functions_with_unencrypted_code,
  ]

  tags = merge(local.cloudtrail_log_detection_lambda_common_tags, {
    type = "Benchmark"
  })
}

detection "cloudtrail_logs_detect_public_access_granted_to_lambda_functions" {
  title           = "Detect Public Access Granted to Lambda Functions"
  description     = "Detect when a public policy is added to a Lambda function to check for unintended exposure, which could allow unauthorized users to invoke the function and potentially exploit sensitive operations."
  severity        = "high"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_public_access_granted_to_lambda_functions

  tags = merge(local.cloudtrail_log_detection_lambda_common_tags, {
    mitre_attack_ids = "TA0001:T1190"
  })
}

query "cloudtrail_logs_detect_public_access_granted_to_lambda_functions" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_public_access_granted_to_lambda_functions_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'lambda.amazonaws.com'
      and event_name like 'AddPermission%'
      and json_extract_string(request_parameters, '$.principal') = '*'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_lambda_function_code_updates_without_publish" {
  title           = "Detect Lambda Function Code Updates Without Publish"
  description     = "Detect when a Lambda function's code is updated but not published, potentially indicating unapproved testing or staging of code."
  severity        = "low"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_lambda_function_code_updates_without_publish

  tags = merge(local.cloudtrail_log_detection_lambda_common_tags, {
    mitre_attack_ids = "TA0003:T1078"
  })
}

query "cloudtrail_logs_detect_lambda_function_code_updates_without_publish" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_lambda_function_code_updates_without_publish_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'lambda.amazonaws.com'
      and event_name = 'UpdateFunctionCode'
      and json_extract_string(request_parameters, '$.publish') = 'false'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_lambda_functions_with_unencrypted_environment_variables" {
  title           = "Detect Lambda Functions with Unencrypted Environment Variables"
  description     = "Detect when Lambda functions are created or updated with environment variables that are not encrypted, which could expose sensitive information to unauthorized access."
  severity        = "high"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_lambda_functions_with_unencrypted_environment_variables

  tags = merge(local.cloudtrail_log_detection_lambda_common_tags, {
    mitre_attack_ids = "TA0006:T1552"
  })
}

query "cloudtrail_logs_detect_lambda_functions_with_unencrypted_environment_variables" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_lambda_functions_with_unencrypted_environment_variables_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'lambda.amazonaws.com'
      and event_name in ('CreateFunction', 'UpdateFunctionConfiguration')
      and json_extract_string(request_parameters, '$.environment.Variables') not like '%"SecureString":true%'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_lambda_functions_with_unencrypted_code" {
  title           = "Detect Lambda Functions with Unencrypted Code"
  description     = "Detect when Lambda functions are created or updated with code that is not encrypted, which could expose sensitive information to unauthorized access."
  severity        = "high"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_lambda_functions_with_unencrypted_code

  tags = merge(local.cloudtrail_log_detection_lambda_common_tags, {
    mitre_attack_ids = "TA0006:T1552"
  })
}

query "cloudtrail_logs_detect_lambda_functions_with_unencrypted_code" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_lambda_functions_with_unencrypted_code_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'lambda.amazonaws.com'
      and event_name in ('CreateFunction', 'UpdateFunctionCode')
      and json_extract_string(request_parameters, '$.zipFile') not like '%UkVE%3D%'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}
