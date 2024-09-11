// Benchmarks and controls for specific services should override the "service" tag
locals {
  aws_common_tags = {
    category = "Security"
    plugin   = "aws"
    service  = "AWS"
  }
}

locals {
  # Local internal variable to build the SQL select clause for common
  # dimensions using a table name qualifier if required. Do not edit directly.
  common_dimensions_cloudtrail_log_sql = <<-EOQ
  epoch_ms(tp_timestamp) as timestamp,
  user_identity.arn as actor_id,
  tp_source_ip as source_ip_address,
  string_split(event_source, '.')[1] || ':' || event_name as operation,
  tp_connection::varchar as index, -- TODO: Change to tp_index with newer data without varchar cast
  aws_region as location,
  tp_id as tp_log_id,
  EOQ
}
