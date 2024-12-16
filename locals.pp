// Benchmarks and controls for specific services should override the "service" tag
locals {
  aws_detections_common_tags = {
    category = "Detection"
    plugin   = "aws"
    service  = "AWS"
  }
}

locals {
  # Local internal variables to build the SQL select clause for common
  # dimensions. Do not edit directly.
  cloudtrail_log_detection_sql_columns = <<-EOQ
  tp_timestamp as timestamp,
  string_split(event_source, '.')[1] || ':' || event_name as operation,
  __RESOURCE_SQL__ as resource,
  user_identity.arn as actor,
  tp_source_ip as source_ip,
  tp_index as account_id,
  aws_region as region,
  tp_id as source_id,
  *
  EOQ

  // Keep same order as SQL statement for easier readability
  cloudtrail_log_detection_display_columns = [
    "timestamp",
    "operation",
    "resource",
    "actor",
    "source_ip",
    "account_id",
    "region",
    "source_id"
  ]

  cloudtrail_log_detections_where_conditions = <<-EOQ
  and error_code is null
  EOQ

  elb_access_log_detection_sql_columns = <<-EOQ
  tp_timestamp as timestamp,
  request as operation,
  elb as resource,
  conn_trace_id as actor, -- TODO: What to use here?
  tp_source_ip as source_ip,
  tp_index::varchar as account_id,
  'us-east-1' as region, -- TODO: Use tp_location when available
  tp_id as source_id,
  *
  EOQ

  guardduty_finding_log_detection_sql_columns = <<-EOQ
  tp_timestamp as timestamp,
  title as operation,
  resource_type as resource,
  action_type as actor,
  tp_source_ip as source_ip,
  tp_index::varchar as account_id,
  'us-east-1' as region, -- TODO: Use tp_location when available
  tp_id as source_id,
  *
  EOQ

  s3_server_access_log_detection_sql_columns = <<-EOQ
  tp_timestamp as timestamp,
  operation as operation,
  bucket as resource,
  requester as actor, -- TODO: What to use here?
  tp_source_ip as source_ip,
  tp_index::varchar as account_id,
  'us-east-1' as region, -- TODO: Use tp_location when available
  tp_id as source_id,
  *
  EOQ
}
