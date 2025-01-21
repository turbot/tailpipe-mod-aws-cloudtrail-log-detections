// Benchmarks and controls for specific services should override the "service" tag
locals {
  aws_cloudtrail_log_detections_common_tags = {
    category = "Detections"
    plugin   = "aws"
    service  = "AWS/CloudTrail"
  }
}

locals {
  # Local internal variables to build the SQL select clause for common
  # dimensions. Do not edit directly.
  detection_sql_columns = <<-EOQ
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
}

locals {
  # Local internal variables to build the SQL select clause for common
  # dimensions. Do not edit directly.
  detection_sql_resource_column_empty = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "''")
  detection_sql_resource_column_region = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "aws_region")
  detection_sql_resource_column_request_parameters_name = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'name'")
  detection_sql_resource_column_request_parameters_snapshot_id = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'snapshotId'")
  detection_sql_resource_column_response_elements_snapshot_id = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "response_elements ->> 'snapshotId'")

  // Keep same order as SQL statement for easier readability
  detection_display_columns = [
    "timestamp",
    "operation",
    "resource",
    "actor",
    "source_ip",
    "account_id",
    "region",
    "source_id"
  ]

  detection_sql_where_conditions = <<-EOQ
  and error_code is null
  EOQ
}
