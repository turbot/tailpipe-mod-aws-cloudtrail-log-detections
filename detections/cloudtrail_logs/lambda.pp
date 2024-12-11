locals {
  cloudtrail_logs_detect_lambda_invocation_in_short_time_sql_columns    = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.functionName")
}

benchmark "cloudtrail_logs_lambda_detections" {
  title       = "CloudTrail Log Lambda Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail's Lambda logs."
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_lambda_invocation_in_short_time,
  ]

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    type    = "Benchmark"
    service = "AWS/Lambda"
  })
}

detection "cloudtrail_logs_detect_lambda_invocation_in_short_time" {
  title       = "Detect AWS Lambda Functions Invocations in Short Time"
  description = "Detect when AWS Lambda functions are invoked multiple times within a short period."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_lambda_invocation_in_short_time

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0002:T1059"
  })
}

query "cloudtrail_logs_detect_lambda_invocation_in_short_time" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_lambda_invocation_in_short_time_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'lambda.amazonaws.com'
      and event_name = 'Invoke'
      and error_code IS NULL
      and event_time > NOW() - INTERVAL '1 hour'
    group by
      request_parameters.functionName
    having
      count(*) > 100       -- Threshold for high-volume invocation
    ORDER by
      invocation_count desc;
  EOQ
}
