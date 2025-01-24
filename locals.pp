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
  detection_sql_resource_column_empty                                                = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "''")
  detection_sql_resource_column_region                                               = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "aws_region")
  detection_sql_resource_column_request_parameters_alarm_name                        = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'alarmName'")
  detection_sql_resource_column_request_parameters_bucket_name                       = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'bucketName'")
  detection_sql_resource_column_request_parameters_codebuild_project_arn             = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'projectArn'")
  detection_sql_resource_column_request_parameters_config_record_name                = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'configurationRecorderName'")
  detection_sql_resource_column_request_parameters_config_rule_name                  = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'configRuleName'")
  detection_sql_resource_column_request_parameters_db_cluster_identifier             = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'dBClusterIdentifier'")
  detection_sql_resource_column_request_parameters_db_instance_identifier            = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'dBInstanceIdentifier'")
  detection_sql_resource_column_request_parameters_detector_id                       = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'detectorId'")
  detection_sql_resource_column_request_parameters_document_name                     = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'documentName'")
  detection_sql_resource_column_request_parameters_domain_name                       = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'domainName'")
  detection_sql_resource_column_request_parameters_file_system_id_or_mount_target_id = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "coalesce(request_parameters ->> 'fileSystemId', request_parameters ->> 'mountTargetId')")
  detection_sql_resource_column_request_parameters_function_name                     = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'functionName'")
  detection_sql_resource_column_request_parameters_hosted_zone_id                    = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'hostedZoneId'")
  detection_sql_resource_column_request_parameters_image_id                          = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'imageId'")
  detection_sql_resource_column_request_parameters_instance_id                       = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'instanceId'")
  detection_sql_resource_column_request_parameters_key_id                            = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'keyId'")
  detection_sql_resource_column_request_parameters_log_group_name                    = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'logGroupName'")
  detection_sql_resource_column_request_parameters_name                              = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'name'")
  detection_sql_resource_column_request_parameters_network_acl_id                    = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'networkAclId'")
  detection_sql_resource_column_request_parameters_network_association_id            = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'associationId'")
  detection_sql_resource_column_request_parameters_network_flow_log_id               = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'flowLogIds'")
  detection_sql_resource_column_request_parameters_network_route_table_id            = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'routeTableId'")
  detection_sql_resource_column_request_parameters_network_security_group_id         = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'groupId'")
  detection_sql_resource_column_request_parameters_or_response_elements_queue_url    = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "coalesce(response_elements ->> 'queueUrl', request_parameters ->> 'queueUrl')")
  detection_sql_resource_column_request_parameters_policy_name                       = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'policyName'")
  detection_sql_resource_column_request_parameters_resource_arn                      = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'resourceArn'")
  detection_sql_resource_column_request_parameters_rest_api_name                     = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters -> 'createRestApiInput' ->> 'name'")
  detection_sql_resource_column_request_parameters_role_arn                          = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters -> 'role' ->> 'arn'")
  detection_sql_resource_column_request_parameters_role_name                         = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'roleName'")
  detection_sql_resource_column_request_parameters_snapshot_id                       = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'snapshotId'")
  detection_sql_resource_column_request_parameters_source_image_id                   = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'sourceImageId'")
  detection_sql_resource_column_request_parameters_topic_arn                         = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'topicArn'")
  detection_sql_resource_column_request_parameters_traffic_mirror_target_id          = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'trafficMirrorTargetId'")
  detection_sql_resource_column_request_parameters_user_data                         = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'userData'")
  detection_sql_resource_column_request_parameters_user_name                         = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'userName'")
  detection_sql_resource_column_request_parameters_vpc_id                            = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'vpcId'")
  detection_sql_resource_column_response_elements_snapshot_id                        = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "response_elements ->> 'snapshotId'")
  detection_sql_resource_column_root                                                 = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "user_identity.type")

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
