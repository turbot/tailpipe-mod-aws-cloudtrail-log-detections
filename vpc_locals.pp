locals {
  # Local internal variables to build the SQL select clause for common
  detection_sql_resource_column_request_parameters_vpc_id = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'vpcId'")
  detection_sql_resource_column_request_parameters_traffic_mirror_target_id = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'trafficMirrorTargetId'")
  detection_sql_resource_column_request_parameters_network_acl_id = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'networkAclId'")
  detection_sql_resource_column_request_parameters_network_route_table_id = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'routeTableId'")
  detection_sql_resource_column_request_parameters_network_security_group_id = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'groupId'")
  detection_sql_resource_column_request_parameters_network_flow_log_id = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'flowLogIds'")
  detection_sql_resource_column_request_parameters_network_association_id = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'associationId'")
}
