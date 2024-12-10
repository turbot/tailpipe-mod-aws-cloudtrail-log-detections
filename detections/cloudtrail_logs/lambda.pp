locals {
  cloudtrail_logs_detect_lambda_invocation_sql_columns    = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.functionName")
}

benchmark "cloudtrail_logs_lambda_detections" {
  title       = "CloudTrail Log Lambda Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail's Lambda logs."
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_lambda_invocation,
  ]

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    type    = "Benchmark"
    service = "AWS/Lambda"
  })
}

detection "cloudtrail_logs_detect_lambda_invocation" {
  title       = "Detect AWS Lambda Function Invocation"
  description = "Detect when an AWS Lambda function is invoked."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_lambda_invocation

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0002:T1059"
  })
}

query "cloudtrail_logs_detect_lambda_invocation" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_lambda_invocation_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'lambda.amazonaws.com'
      and event_name = 'Invoke'
      and error_code is null
    order by
      event_time desc;
  EOQ
}
