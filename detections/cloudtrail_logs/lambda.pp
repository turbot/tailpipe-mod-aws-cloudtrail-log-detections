locals {
  cloudtrail_logs_detect_lambda_funtion_public_permission_added_sql_columns    = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.functionName")
}

benchmark "cloudtrail_logs_lambda_detections" {
  title       = "CloudTrail Log Lambda Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail's Lambda logs"
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_efs_deletion_updates,
  ]

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    type    = "Benchmark"
    service = "AWS/Lambda"
  })
}

detection "cloudtrail_logs_detect_lambda_funtion_public_permission_added" {
  title       = "Detect Lambda Function with Public Policy"
  description = "Detect when a Lambda function's permissions allow public invocation, which might be exploited."
  severity    = "high"
  query       = query.cloudtrail_logs_detect_lambda_funtion_public_permission_added

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0001:T1190"
  })
}

query "cloudtrail_logs_detect_lambda_funtion_public_permission_added" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_lambda_funtion_public_permission_added_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'lambda.amazonaws.com'
      and event_name like 'AddPermission%
      and (request_parameters ->> 'principal') = '*'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}