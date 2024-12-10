locals {
  cloudtrail_logs_detect_step_function_execution_sql_columns    = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.stateMachineArn")
}

benchmark "cloudtrail_logs_step_function_detections" {
  title       = "CloudTrail Log Step Functions Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail's Step Functions logs."
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_step_function_execution
  ]

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    type    = "Benchmark"
    service = "AWS/StepFunctions"
  })
}

detection "cloudtrail_logs_detect_step_function_execution" {
  title       = "Detect Step Functions State Machine Execution"
  description = "Detect execution of an AWS Step Functions state machine."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_step_function_execution

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0002:T1059"
  })
}

query "cloudtrail_logs_detect_step_function_execution" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_step_function_execution_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'states.amazonaws.com'
      and event_name = 'StartExecution'
      and error_code is null
    order by
      event_time desc;
  EOQ
}
