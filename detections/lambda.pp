locals {
  lambda_common_tags = merge(local.aws_cloudtrail_log_detections_common_tags, {
    service = "AWS/Lambda"
  })
}

benchmark "lambda_detections" {
  title       = "Lambda Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for Lambda events."
  type        = "detection"
  children    = [
    detection.lambda_function_created_with_function_code_encryption_at_rest_disabled,
    detection.lambda_function_granted_public_access,
  ]

  tags = merge(local.lambda_common_tags, {
    type = "Benchmark"
  })
}

detection "lambda_function_granted_public_access" {
  title           = "Lambda Function Granted Public Access"
  description     = "Detect when public access was granted to a Lambda function, potentially exposing it to unauthorized users who could invoke the function and exploit sensitive operations."
  documentation   = file("./detections/docs/lambda_function_granted_public_access.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.lambda_function_granted_public_access

  tags = merge(local.lambda_common_tags, {
    mitre_attack_ids = "TA0001:T1190"
  })
}

query "lambda_function_granted_public_access" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_function_name}
    from
      aws_cloudtrail_log
    where
      event_source = 'lambda.amazonaws.com'
      and event_name like 'AddPermission%'
      and (request_parameters ->> 'principal') = '*'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "lambda_function_created_with_function_code_encryption_at_rest_disabled" {
  title           = "Lambda Function Created With Function Code Encryption at Rest Disabled"
  description     = "Detect when a Lambda function was created without encryption at rest enabled for its code, potentially exposing sensitive information to unauthorized access."
  documentation   = file("./detections/docs/lambda_function_created_with_function_code_encryption_at_rest_disabled.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.lambda_function_created_with_function_code_encryption_at_rest_disabled

  tags = merge(local.lambda_common_tags, {
    mitre_attack_ids = "TA0006:T1552.001"
  })
}

query "lambda_function_created_with_function_code_encryption_at_rest_disabled" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_function_name}
    from
      aws_cloudtrail_log
    where
      event_source = 'lambda.amazonaws.com'
      and event_name like 'CreateFunction%'
      and (request_parameters -> 'code' ->> 'sourceKMSKeyArn') = ''
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}
