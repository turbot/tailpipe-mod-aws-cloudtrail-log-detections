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
  cloudtrail_logs_detect_stopped_instances_sql_columns                            = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.instancesSet.items")
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
    detection.cloudtrail_logs_detect_cloudtrail_trail_updates,
    detection.cloudtrail_logs_detect_iam_entities_created_without_cloudformation,
    detection.cloudtrail_logs_detect_iam_root_console_logins,
    detection.cloudtrail_logs_detect_iam_user_login_profile_updates,
    detection.cloudtrail_logs_detect_codebuild_project_visibility_updates,
    detection.cloudtrail_logs_detect_ec2_ebs_encryption_disabled_updates,
    detection.cloudtrail_logs_detect_route_table_updates,
    detection.cloudtrail_logs_detect_stopped_instances,
    detection.cloudtrail_logs_detect_vpc_updates,
    detection.cloudtrail_logs_detect_route53_domain_transfered_to_another_account,
    detection.cloudtrail_logs_detect_route53_domain_transfer_lock_disabled_updates,
    detection.cloudtrail_logs_detect_route53_associate_vpc_with_hosted_zone,
    detection.cloudtrail_logs_detect_waf_web_acl_deletion_updates,
    detection.cloudtrail_logs_detect_guardduty_detector_deletion_updates,
    detection.cloudtrail_logs_detect_eventbridge_rule_disabled_or_deletion_updates,
    detection.cloudtrail_logs_detect_efs_deletion_updates,
    detection.cloudtrail_logs_detect_cloudwatch_log_group_deletion_updates,
    detection.cloudtrail_logs_detect_cloudwatch_log_stream_deletion_updates,
    detection.cloudtrail_logs_detect_cloudwatch_alarm_deletion_updates,
    detection.cloudtrail_logs_detect_waf_disassociation,
    detection.cloudtrail_logs_detect_iam_group_read_only_events,
    detection.cloudtrail_logs_detect_iam_policy_modified,
    detection.cloudtrail_logs_detect_config_service_rule_delete,
    detection.cloudtrail_logs_detect_configuration_recorder_stop,
  ]

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    type = "Benchmark"
  })
}

/*
 * Detections
 */

detection "cloudtrail_logs_detect_cloudtrail_trail_updates" {
  title       = "Detect CloudTrail Trail Updates"
  description = "Detect CloudTrail trail changes to check if logging was stopped."
  severity    = "medium"
  documentation        = file("./detections/docs/cloudtrail_logs_detect_cloudtrail_trail_updates.md")
  query       = query.cloudtrail_logs_detect_cloudtrail_trail_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1562:001"
  })
}

detection "cloudtrail_logs_detect_iam_entities_created_without_cloudformation" {
  title       = "Detect IAM Entities Created Without CloudFormation"
  description = "Detect IAM entities created without CloudFormation to check for mismanaged permissions."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_iam_entities_created_without_cloudformation

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0003:T1136"
  })
}

detection "cloudtrail_logs_detect_iam_user_login_profile_updates" {
  title       = "Detect IAM User Login Profile Updates"
  description = "Detect IAM user login profile updates to check for password updates and usage."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_iam_user_login_profile_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0003:T1098,TA0005:T1108,TA0005:T1550,TA0008:T1550"
  })
}

detection "cloudtrail_logs_detect_iam_root_console_logins" {
  title       = "Detect IAM Root Console Logins"
  description = "Detect IAM root user console logins to check for any actions performed by the root user."
  severity    = "high"
  query       = query.cloudtrail_logs_detect_iam_root_console_logins

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
}

detection "cloudtrail_logs_detect_codebuild_project_visibility_updates" {
  title       = "Detect CodeBuild Project Visibility Updates"
  description = "Detect CodeBuild project visibility updates to check whether projects are publicly accessible."
  severity    = "high"
  query       = query.cloudtrail_logs_detect_codebuild_project_visibility_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0010:T1567"
  })
}

detection "cloudtrail_logs_detect_ec2_ebs_encryption_disabled_updates" {
  title       = "Detect EC2 EBS Encryption Disabled Updates"
  description = "Detect EC2 EBS encryption disabled updates to check for data at rest encryption."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_ec2_ebs_encryption_disabled_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0003:T1486,TA0040:T1565"
  })
}



detection "cloudtrail_logs_detect_ec2_network_acl_updates" {
  title       = "Detect EC2 Gateway Updates"
  description = "Detect EC2 gateway updates to check for changes in network configurations."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_ec2_network_acl_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1562"
  })
}

detection "cloudtrail_logs_detect_route_table_updates" {
  title       = "Detect Route Table Updates"
  description = "Detect route table updates to check for changes in network configurations."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_route_table_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0010:T1048"
  })
}

detection "cloudtrail_logs_detect_stopped_instances" {
  title       = "Detect Stopped Instances"
  description = "Detect stopped instances to check for unauthorized changes."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_stopped_instances

  tags = local.cloudtrail_log_detection_common_tags
}

detection "cloudtrail_logs_detect_vpc_updates" {
  title       = "Detect VPC Updates"
  description = "Detect VPC updates to check for changes in network configurations."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_vpc_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1562"
  })
}

detection "cloudtrail_logs_detect_route53_domain_transfered_to_another_account" {
  title       = "Detect Route53 Domain Transfered to Another Account"
  description = "Detect Route53 domain transfered to another account to check for unauthorized domain transfers."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_route53_domain_transfered_to_another_account

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "cloudtrail_logs_detect_route53_domain_transfer_lock_disabled_updates" {
  title       = "Detect Route53 Domain Transfer Lock Disabled"
  description = "Detect Route53 domain transfer lock disabled to check for unauthorized domain transfers."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_route53_domain_transfer_lock_disabled_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "cloudtrail_logs_detect_route53_associate_vpc_with_hosted_zone" {
  title       = "Detect Route53 Associate VPC with Hosted Zone"
  description = "Detect Route53 associate VPC with hosted zone to check for unauthorized VPC associations."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_route53_associate_vpc_with_hosted_zone

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "cloudtrail_logs_detect_waf_web_acl_deletion_updates" {
  title       = "Detect WAF Web ACL Deletion Updates"
  description = "Detect WAF web ACL deletion updates to check for unauthorized changes."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_waf_web_acl_deletion_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "cloudtrail_logs_detect_guardduty_detector_deletion_updates" {
  title       = "Detect GuardDuty Detector Deletion Updates"
  description = "Detect GuardDuty detector deletion updates to check for unauthorized changes."
  severity    = "high"
  query       = query.cloudtrail_logs_detect_guardduty_detector_deletion_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "cloudtrail_logs_detect_eventbridge_rule_disabled_or_deletion_updates" {
  title       = "Detect EventBridge Rule Disabled or Deletion Updates"
  description = "Detect EventBridge rule disabled or deletion updates to check for unauthorized changes."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_eventbridge_rule_disabled_or_deletion_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "cloudtrail_logs_detect_efs_deletion_updates" {
  title       = "Detect EFS Deletion Updates"
  description = "Detect EFS deletion events to monitor for unauthorized changes or potential disruptions. This includes tracking the deletion of file systems, mount targets, and related resources to ensure any unexpected activity is identified and addressed promptly."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_efs_deletion_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "cloudtrail_logs_detect_cloudwatch_log_group_deletion_updates" {
  title       = "Detect CloudWatch Log Group Deletion Updates"
  description = "Detect CloudWatch log group deletion updates to check for unauthorized changes."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_cloudwatch_log_group_deletion_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "cloudtrail_logs_detect_cloudwatch_log_stream_deletion_updates" {
  title       = "Detect CloudWatch Log Stream Deletion Updates"
  description = "Detect CloudWatch log stream deletion updates to check for unauthorized changes."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_cloudwatch_log_stream_deletion_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "cloudtrail_logs_detect_cloudwatch_alarm_deletion_updates" {
  title       = "Detect CloudWatch Alarm Deletion Updates"
  description = "Detect CloudWatch alarm deletion updates to check for unauthorized changes."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_cloudwatch_alarm_deletion_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "cloudtrail_logs_detect_waf_disassociation" {
  title       = "Detect WAF Disassociation"
  description = "Detect when WAF is disassociated."
  severity    = "high"
  query       = query.cloudtrail_logs_detect_waf_disassociation

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0004:T1498"
  })
}

detection "cloudtrail_logs_detect_iam_group_read_only_events" {
  title       = "Detect IAM Group Read Only Event"
  description = "Detect IAM group read only event"
  severity    = "low"
  query       = query.cloudtrail_logs_detect_iam_group_read_only_events


  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
   })
}

detection "cloudtrail_logs_detect_iam_policy_modified" {
  title       = "Detect IAM Policy Modified"
  description = "Detect when IAM policy is modified."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_iam_policy_modified

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0004:T1548"
  })
}

detection "cloudtrail_logs_detect_config_service_rule_delete" {
  title       = "Detect Config Service Rule Deleted"
  description = "Detect the deletion of config service rule."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_config_service_rule_delete

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "T1562.001"
  })
}

detection "cloudtrail_logs_detect_configuration_recorder_stop" {
  title       = "Detect Configuration Recorder Stopped"
  description = "Detect when the configuration recorder is stopped."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_configuration_recorder_stop

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0005.T1562"
  })
}

/*
 * Queries
 */

query "cloudtrail_logs_detect_cloudtrail_trail_updates" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_cloudtrail_trail_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'cloudtrail.amazonaws.com'
      and event_name in ('DeleteTrail', 'StopLogging', 'UpdateTrail')
      and error_code is null
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_iam_entities_created_without_cloudformation" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_iam_entities_created_without_cloudformation_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'iam.amazonaws.com'
      and (user_identity.invoked_by) != 'cloudformation.amazonaws.com'
      and event_name in ('BatchCreateUser', 'CreateGroup', 'CreateInstanceProfile', 'CreatePolicy', 'CreatePolicyVersion', 'CreateRole', 'CreateServiceLinkedRole', 'CreateUser')
      and error_code is null
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_iam_root_console_logins" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_iam_root_console_logins_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'signin.amazonaws.com'
      and event_name = 'ConsoleLogin'
      and (user_identity.type) = 'Root'
      and (response_elements.ConsoleLogin) = 'Success'
      and error_code is null
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_iam_user_login_profile_updates" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_iam_user_login_profile_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'iam.amazonaws.com'
      and event_name = 'UpdateLoginProfile'
      and error_code is null
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_codebuild_project_visibility_updates" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_codebuild_project_visibility_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'codebuild.amazonaws.com'
      and event_name = 'UpdateProjectVisibility'
      and (request_parameters.projectVisibility) = 'PUBLIC_READ'
      and error_code is null
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_ec2_ebs_encryption_disabled_updates" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_ec2_ebs_encryption_disabled_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'DisableEbsEncryptionByDefault'
      and error_code is null
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_route_table_updates" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_route_table_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name in ('DisassociateRouteTable', 'DeleteRoute', 'DeleteRouteTable', 'ReplaceRoute', 'ReplaceRouteTableAssociation')
      and error_code is null
    order by
      event_time desc;
  EOQ
}

//TODO: do we need all the event names? Check what might be helpful in detection
query "cloudtrail_logs_detect_vpc_updates" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_vpc_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_name in ('DeleteVpc', 'ModifyVpcAttribute', 'AcceptVpcPeeringConnection', 'DeleteVpcPeeringConnection', 'RejectVpcPeeringConnection', 'CreateVpcPeeringConnection', 'AttachClassicLinkVpc', 'DetachClassicLinkVpc', 'EnableVpcClassicLink', 'DisableVpcClassicLink')
      and error_code is null
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_stopped_instances" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_stopped_instances_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'StopInstances'
      and error_code is null
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_route53_domain_transfered_to_another_account" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_route53_domain_transfered_to_another_account_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'route53.amazonaws.com'
      and event_name = 'TransferDomainToAnotherAwsAccount'
      and error_code is null
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_route53_domain_transfer_lock_disabled_updates" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_route53_domain_transfered_to_another_account_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'route53.amazonaws.com'
      and event_name = 'DisableDomainTransferLock'
      and error_code is null
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_route53_associate_vpc_with_hosted_zone" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_route53_associate_vpc_with_hosted_zone_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'route53.amazonaws.com'
      and event_name = 'AssociateVPCWithHostedZone'
      and error_code is null
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_waf_web_acl_deletion_updates" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_waf_web_acl_deletion_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_name = 'DeleteWebACL'
      and error_code is null
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_guardduty_detector_deletion_updates" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_guardduty_detector_deletion_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'guardduty.amazonaws.com'
      and event_name = 'DeleteDetector'
      and error_code is null
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_eventbridge_rule_disabled_or_deletion_updates" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_eventbridge_rule_deletion_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'eventbridge.amazonaws.com'
      and event_name in ('DeleteRule', 'DisableRule')
      and error_code is null
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_efs_deletion_updates" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_efs_deletion_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'elasticfilesystem.amazonaws.com'
      and event_name in ('DeleteMountTarget', 'DeleteFileSystem', 'DeleteTags', 'DeleteFile', 'DeleteMountTargetSecurityGroups')
      and error_code is null
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_cloudwatch_log_group_deletion_updates" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_cloudwatch_log_group_deletion_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'logs.amazonaws.com'
      and event_name = 'DeleteLogGroup'
      and error_code is null
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_cloudwatch_log_stream_deletion_updates" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_cloudwatch_log_stream_deletion_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'logs.amazonaws.com'
      and event_name = 'DeleteLogStream'
      and error_code is null
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_cloudwatch_alarm_deletion_updates" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_cloudwatch_alarm_deletion_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'monitoring.amazonaws.com'
      and event_name = 'DeleteAlarms'
      and error_code is null
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_waf_disassociation" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_waf_disassociation_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_name = 'DisassociateWebACL'
      and error_code is null
    order by
      event_time desc;
  EOQ
}

// TODO: It does not reflect anything dangerous and can be removed
query "cloudtrail_logs_detect_iam_group_read_only_events" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_iam_group_read_only_events_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_name in ('GetGroup', 'GetGroupPolicy', 'ListAttachedGroupPolicies', 'ListGroupPolicies', 'ListGroups', 'ListGroupsForUser')
      and error_code is null
    order by
      event_time desc;
  EOQ
}

// TODO: Break it down to individual resource, like role, group, user
query "cloudtrail_logs_detect_iam_policy_modified" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_iam_policy_modified_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_name in ('DeleteGroupPolicy', 'DeleteRolePolicy', 'DeleteUserPolicy', 'PutGroupPolicy', 'PutRolePolicy', 'PutUserPolicy', 'CreatePolicy', 'DeletePolicy', 'CreatePolicyVersion', 'DeletePolicyVersion', 'AttachRolePolicy', 'DetachRolePolicy', 'AttachUserPolicy', 'DetachUserPolicy', 'AttachGroupPolicy', 'DetachGroupPolicy')
      and error_code is null
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_config_service_rule_delete" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_config_service_rule_delete_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'config.amazonaws.com'
      and event_name in ('DeleteConfigRule', 'DeleteOrganizationConfigRule', 'DeleteConfigurationAggregator', 'DeleteConfigurationRecorder', 'DeleteConformancePack', 'DeleteOrganizationConformancePack', 'DeleteDeliveryChannel', 'DeleteRemediationConfiguration', 'DeleteRetentionConfiguration')
      and error_code is null
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_configuration_recorder_stop" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_configuration_recorder_stop_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'config.amazonaws.com'
      and event_name = 'StopConfigurationRecorder'
      and error_code is null
    order by
      event_time desc;
  EOQ
}
