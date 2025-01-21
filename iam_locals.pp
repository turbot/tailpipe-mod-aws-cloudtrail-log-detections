locals {
  # Local internal variables to build the SQL select clause for common
  detection_sql_resource_column_request_parameters_user_name = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'userName'")
  detection_sql_resource_column_request_parameters_role_arn = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters -> 'role' ->> 'arn'")
  detection_sql_resource_column_request_parameters_role_name = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'roleName'")
  detection_sql_resource_column_request_parameters_policy_name = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'policyName'")
}
