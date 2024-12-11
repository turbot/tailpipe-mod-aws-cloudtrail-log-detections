locals {
  cloudtrail_logs_detect_ecs_task_execution_sql_columns    = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.cluster")
}

benchmark "cloudtrail_logs_ecs_detections" {
  title       = "CloudTrail Log ECS Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail's ECS logs."
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_ecs_task_execution,
  ]

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    type    = "Benchmark"
    service = "AWS/ECS"
  })
}

detection "cloudtrail_logs_detect_ecs_task_execution" {
  title       = "Detect ECS Task Execution"
  description = "Detect execution of tasks within an ECS cluster."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_ecs_task_execution

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0002:T1072"
  })
}

query "cloudtrail_logs_detect_ecs_task_execution" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_ecs_task_execution_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ecs.amazonaws.com'
      and event_name = 'RunTask'
      and error_code is null
    order by
      event_time desc;
  EOQ
}
