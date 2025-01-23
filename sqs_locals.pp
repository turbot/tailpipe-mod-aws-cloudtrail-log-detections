locals {
  # Local internal variables to build the SQL select clause for common
  detection_sql_resource_column_request_parameters_or_response_elements_queue_url = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "COALESCE(response_elements ->> 'queueUrl', request_parameters ->> 'queueUrl')")
}
