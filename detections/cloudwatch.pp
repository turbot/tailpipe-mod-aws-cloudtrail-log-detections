locals {
  cloudwatch_common_tags = merge(local.aws_cloudtrail_log_detections_common_tags, {
    service = "AWS/CloudWatch"
  })
}

benchmark "cloudwatch_detections" {
  title       = "CloudWatch Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for CloudWatch events."
  type        = "detection"
  children = [
    detection.cloudwatch_log_group_created_with_encryption_disabled
  ]

  tags = merge(local.cloudwatch_common_tags, {
    type = "Benchmark"
  })
}

detection "cloudwatch_log_group_created_with_encryption_disabled" {
  title           = "CloudWatch Log Group Created with Encryption Disabled"
  description     = "Detect when a CloudWatch log group was created with encryption disabled to check for potential risks of data exposure and non-compliance with security policies."
  documentation   = file("./detections/docs/cloudwatch_log_group_created_with_encryption_disabled.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.cloudwatch_log_group_created_with_encryption_disabled

  tags = merge(local.cloudwatch_common_tags, {
    mitre_attack_ids = "TA0005:T1578.005"
  })
}

query "cloudwatch_log_group_created_with_encryption_disabled" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_log_group_name}
    from
      aws_cloudtrail_log
    where
      event_source = 'logs.amazonaws.com'
      and event_name = 'CreateLogGroup'
      and (request_parameters ->> 'kmsKeyId') is null
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}
