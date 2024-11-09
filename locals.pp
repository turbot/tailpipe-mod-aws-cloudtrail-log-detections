// Benchmarks and controls for specific services should override the "service" tag
locals {
  aws_common_tags = {
    category = "Security"
    plugin   = "aws"
    service  = "AWS"
  }
}

locals {
  # Local internal variables to build the SQL select clause for common
  # dimensions. Do not edit directly.
  common_dimensions_cloudtrail_logs_sql = <<-EOQ
  epoch_ms(tp_timestamp) as timestamp,
  string_split(event_source, '.')[1] || ':' || event_name as operation,
  __RESOURCE_SQL__ as resource,
  user_identity.arn as actor,
  tp_source_ip as source_ip,
  tp_index::varchar as account_id,
  aws_region as region,
  tp_id as source_id,
  *
  EOQ

  // Keep same order as SQL statement for easier readability
  cloudtrail_logs_default_columns = [
    "timestamp",
    "operation",
    "resource",
    "actor",
    "source_ip",
    "account_id",
    "region",
    "source_id"
  ]

  common_dimensions_elb_access_logs_sql = <<-EOQ
  epoch_ms(tp_timestamp) as timestamp,
  request as operation,
  elb as resource,
  conn_trace_id as actor, -- TODO: What to use here?
  tp_source_ip as source_ip,
  tp_index::varchar as account_id,
  'us-east-1' as region, -- TODO: Use tp_location when available
  tp_id as source_id,
  *
  EOQ

  common_dimensions_s3_server_access_logs_sql = <<-EOQ
  epoch_ms(tp_timestamp) as timestamp,
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
