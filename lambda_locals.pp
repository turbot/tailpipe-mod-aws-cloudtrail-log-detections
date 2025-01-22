locals {
  # Local internal variables to build the SQL select clause for common
  detection_sql_resource_column_request_parameters_function_name = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'functionName'")
}
