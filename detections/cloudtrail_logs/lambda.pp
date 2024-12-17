locals {
  cloudtrail_log_detection_lambda_common_tags = merge(local.cloudtrail_log_detection_common_tags, {
    service = "AWS/Lambda"
  })

  cloudtrail_logs_detect_public_access_granted_to_lambda_functions_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.functionName")
}

benchmark "cloudtrail_log_detections_lambda" {
  title       = "Lambda Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for Lambda events."
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_public_access_granted_to_lambda_functions,
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
  query           = query.cloudtrail_logs_detect_lambda_funtion_public_permission_added

  tags = merge(local.cloudtrail_log_detection_lambda_common_tags, {
    mitre_attack_ids = "TA0001:T1190"
  })
}

query "cloudtrail_logs_detect_lambda_funtion_public_permission_added" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_public_access_granted_to_lambda_functions_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'lambda.amazonaws.com'
      and event_name like 'AddPermission%'
      and (request_parameters ->> 'principal') = '*'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}
