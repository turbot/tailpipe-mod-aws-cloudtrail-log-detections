locals {
  # Local internal variables to build the SQL select clause for common
  detection_sql_resource_column_request_parameters_user_data = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'userData'")
  detection_sql_resource_column_request_parameters_instance_id = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'instanceId'")
  detection_sql_resource_column_request_parameters_image_id = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'imageId'")
  detection_sql_resource_column_request_parameters_source_image_id = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'sourceImageId'")
}
