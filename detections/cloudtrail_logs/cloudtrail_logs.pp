locals {
  cloudtrail_log_detection_common_tags = merge(local.aws_detections_common_tags, {
    service = "AWS/CloudTrail"
  })

  # Store the replace logic in local variables
  cloudtrail_logs_detect_cloudtrail_trail_updates_sql_columns                  = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
  cloudtrail_logs_detect_ec2_security_group_ingress_egress_updates_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.groupId")
  # TODO: How to handle multiple possible resource paths? Split detection per event type?
  cloudtrail_logs_detect_iam_entities_created_without_cloudformation_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "response_elements.role.arn")
  cloudtrail_logs_detect_iam_root_console_logins_sql_columns                     = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "''")
  cloudtrail_logs_detect_iam_user_login_profile_updates_sql_columns              = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.userName")
  cloudtrail_logs_detect_codebuild_project_visibility_updates_sql_columns        = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.projectArn")
  cloudtrail_logs_detect_ec2_ebs_encryption_disabled_updates_sql_columns         = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "recipient_account_id")
  cloudtrail_logs_detect_ec2_gateway_updates_sql_columns                         = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.internetGatewayId")
  cloudtrail_logs_detect_ec2_network_acl_updates_sql_columns                     = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.networkAclId")
  cloudtrail_logs_detect_route_table_updates_sql_columns                         = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.routeTableId")
  # TODO: Get an array of instanceIds. Need to extract it and convert it into a string?
  cloudtrail_logs_detect_stopped_ec2_instances_sql_columns                            = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.instancesSet.items")
  cloudtrail_logs_detect_vpc_updates_sql_columns                                  = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.vpcId")
  cloudtrail_logs_detect_rds_instance_pulicly_accessible_sql_columns              = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.dbInstanceIdentifier")
  cloudtrail_logs_detect_route53_domain_transfered_to_another_account_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.domainName")
  cloudtrail_logs_detect_route53_associate_vpc_with_hosted_zone_sql_columns       = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.hostedZoneId")
  cloudtrail_logs_detect_ec2_full_network_packet_capture_updates_sql_columns      = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "response_elements.trafficMirrorTargetId")
  cloudtrail_logs_detect_waf_web_acl_deletion_updates_sql_columns                 = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.id")
  // TODO: Get an array of flowLogIds. Need to extract it and convert it into a string?
  cloudtrail_logs_detect_ec2_flow_logs_deletion_updates_sql_columns         = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.flowLogIds")
  cloudtrail_logs_detect_guardduty_detector_deletion_updates_sql_columns    = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.detectorId")
  cloudtrail_logs_detect_ec2_snapshot_updates_sql_columns                   = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.snapshotId")
  cloudtrail_logs_detect_eventbridge_rule_deletion_updates_sql_columns      = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
  cloudtrail_logs_detect_ec2_ami_updates_sql_columns                        = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
  cloudtrail_logs_detect_efs_deletion_updates_sql_columns                   = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "coalesce(request_parameters.fileSystemId, request_parameters.mountTargetId)")
  cloudtrail_logs_detect_cloudwatch_log_group_deletion_updates_sql_columns  = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.logGroupName")
  cloudtrail_logs_detect_cloudwatch_log_stream_deletion_updates_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.logStreamName")
  cloudtrail_logs_detect_cloudwatch_alarm_deletion_updates_sql_columns      = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.alarmNames")
  cloudtrail_logs_detect_s3_bucket_deleted_sql_columns                           = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.bucketName")
  cloudtrail_logs_detect_rds_manual_snapshot_created_sql_columns                 = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.dBInstanceIdentifier")
  cloudtrail_logs_detect_rds_master_pass_updated_sql_columns                     = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.dBInstanceIdentifier")
  cloudtrail_logs_detect_rds_publicrestore_sql_columns                           = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.dBInstanceIdentifier")
  cloudtrail_logs_detect_s3_bucket_policy_modified_sql_columns                   = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.bucketName")
  cloudtrail_logs_detect_waf_disassociation_sql_columns                          = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.resourceArn")
  cloudtrail_logs_detect_iam_group_read_only_events_sql_columns                  = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.groupName")
  cloudtrail_logs_detect_iam_policy_modified_sql_columns                         = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.policyArn")
  cloudtrail_logs_detect_config_service_rule_delete_sql_columns                  = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.configRuleName")
  cloudtrail_logs_detect_configuration_recorder_stop_sql_columns                 = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.configurationRecorderName")
  cloudtrail_logs_detect_rds_db_instance_cluster_stop_sql_columns                = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "coalesce(request_parameters.dBInstanceIdentifier, request_parameters.dBClusterIdentifier)")
  cloudtrail_logs_detect_rds_db_snapshot_delete_sql_columns                      = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.dBSnapshotIdentifier")
  cloudtrail_logs_detect_rds_db_instance_cluster_deletion_protection_disable_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "coalesce(request_parameters.dBInstanceIdentifier, request_parameters.dBClusterIdentifier)")
}

benchmark "cloudtrail_log_detections" {
  title       = "CloudTrail Log Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs."
  type        = "detection"
  children = [
    benchmark.cloudtrail_logs_cloudtrail_detections,
    benchmark.cloudtrail_logs_cloudwatch_detections,
    benchmark.cloudtrail_logs_codebuild_detections,
    benchmark.cloudtrail_logs_codebuild_detections,
    benchmark.cloudtrail_logs_config_detections,
    benchmark.cloudtrail_logs_ebs_detections,
    benchmark.cloudtrail_logs_ec2_detections,
    benchmark.cloudtrail_logs_efs_detections,
    benchmark.cloudtrail_logs_eventbridge_detections,
    benchmark.cloudtrail_logs_guardduty_detections,
    benchmark.cloudtrail_logs_iam_detections,
    benchmark.cloudtrail_logs_rds_detections,
    benchmark.cloudtrail_logs_route53_detections,
    benchmark.cloudtrail_logs_s3_detections,
    benchmark.cloudtrail_logs_vpc_detections,
    benchmark.cloudtrail_logs_waf_detections,
  ]

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    type = "Benchmark"
  })
}

