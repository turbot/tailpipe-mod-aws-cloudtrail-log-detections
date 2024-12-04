locals {
  cloudtrail_log_detection_common_tags = merge(local.aws_detections_common_tags, {
    service = "AWS/CloudTrail"
  })

  # Store the replace logic in local variables
  cloudtrail_logs_detect_cloudtrail_trail_updates_sql_columns                  = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters::JSON ->> 'name'")
  cloudtrail_logs_detect_ec2_security_group_ingress_egress_updates_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters::JSON ->> 'groupId'")
  # TODO: How to handle multiple possible resource paths? Split detection per event type?
  cloudtrail_logs_detect_iam_entities_created_without_cloudformation_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "response_elements::JSON -> 'role' ->> 'arn'")
  cloudtrail_logs_detect_iam_root_console_logins_sql_columns                     = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "''")
  cloudtrail_logs_detect_iam_user_login_profile_updates_sql_columns              = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters::JSON ->> 'userName'")
  cloudtrail_logs_detect_s3_bucket_deleted_sql_columns                           = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters::JSON ->> 'bucketName'")
  cloudtrail_logs_detect_rds_manual_snapshot_created_sql_columns                 = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters::JSON ->> 'dBInstanceIdentifier'")
  cloudtrail_logs_detect_rds_master_pass_updated_sql_columns                     = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters::JSON ->> 'dBInstanceIdentifier'")
  cloudtrail_logs_detect_rds_publicrestore_sql_columns                           = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters::JSON ->> 'dBInstanceIdentifier'")
  cloudtrail_logs_detect_s3_bucket_policy_modified_sql_columns                   = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters::JSON ->> 'bucketName'")
  cloudtrail_logs_detect_waf_disassociation_sql_columns                          = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters::JSON ->> 'resourceArn'")
  cloudtrail_logs_detect_iam_group_read_only_events_sql_columns                  = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters::JSON ->> 'groupName'")
  cloudtrail_logs_detect_iam_policy_modified_sql_columns                         = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters::JSON ->> 'policyArn'")
  cloudtrail_logs_detect_config_service_rule_delete_sql_columns                  = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters::JSON ->> 'configRuleName'")
  cloudtrail_logs_detect_configuration_recorder_stop_sql_columns                 = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters::JSON ->> 'configurationRecorderName'")
  cloudtrail_logs_detect_rds_db_instance_cluster_stop_sql_columns                = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "coalesce(request_parameters::JSON ->> 'dBInstanceIdentifier', request_parameters::JSON ->> 'dBClusterIdentifier')")
  cloudtrail_logs_detect_rds_db_snapshot_delete_sql_columns                      = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters::JSON ->> 'dBSnapshotIdentifier'")
  cloudtrail_logs_detect_rds_db_instance_cluster_deletion_protection_disable_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "coalesce(request_parameters::JSON ->> 'dBInstanceIdentifier', request_parameters::JSON ->> 'dBClusterIdentifier')")

}

detection_benchmark "cloudtrail_log_detections" {
  title       = "CloudTrail Log Detections"
  description = "This detection_benchmark contains recommendations when scanning CloudTrail logs."
  type        = "detection"
  children = [
    detection.cloudtrail_logs_detect_cloudtrail_trail_updates,
    detection.cloudtrail_logs_detect_ec2_security_group_ingress_egress_updates,
    detection.cloudtrail_logs_detect_iam_entities_created_without_cloudformation,
    detection.cloudtrail_logs_detect_iam_root_console_logins,
    detection.cloudtrail_logs_detect_iam_user_login_profile_updates,
    detection.cloudtrail_logs_detect_s3_bucket_deleted,
    detection.cloudtrail_logs_detect_rds_manual_snapshot_created,
    detection.cloudtrail_logs_detect_rds_master_pass_updated,
    detection.cloudtrail_logs_detect_rds_publicrestore,
    detection.cloudtrail_logs_detect_s3_bucket_policy_modified,
    detection.cloudtrail_logs_detect_waf_disassociation,
    detection.cloudtrail_logs_detect_iam_group_read_only_events,
    detection.cloudtrail_logs_detect_iam_policy_modified,
    detection.cloudtrail_logs_detect_config_service_rule_delete,
    detection.cloudtrail_logs_detect_configuration_recorder_stop,
    detection.cloudtrail_logs_detect_rds_db_instance_cluster_stop,
    detection.cloudtrail_logs_detect_rds_db_snapshot_delete,
    detection.cloudtrail_logs_detect_rds_db_instance_cluster_deletion_protection_disable
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
  query       = query.cloudtrail_logs_detect_cloudtrail_trail_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1562:001"
  })
}

detection "cloudtrail_logs_detect_ec2_security_group_ingress_egress_updates" {
  title       = "Detect EC2 Security Group Ingress/Egress Updates"
  description = "Detect EC2 security group ingress and egress rule updates to check for unauthorized VPC access or export of data."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_ec2_security_group_ingress_egress_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0001:T1190,TA0005:T1562"
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

detection "cloudtrail_logs_detect_s3_bucket_deleted" {
  title       = "Detect S3 Bucket Deleted"
  description = "Detect a S3 Bucket, Policy, or Website was deleted."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_s3_bucket_deleted

  references = [
    "https://docs.aws.amazon.com/AmazonS3/latest/userguide/DeletingObjects.html"
  ]

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

detection "cloudtrail_logs_detect_rds_manual_snapshot_created" {
  title       = "Detect RDS Manual Snapshot Created"
  description = "Detect when RDS manual snapshot is created."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_rds_manual_snapshot_created

  references = [
    "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_CreateSnapshot.html"
  ]

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0010:T1537"
  })
}

detection "cloudtrail_logs_detect_rds_master_pass_updated" {
  title       = "Detect RDS Master Password Updated"
  description = "Detect when RDS master password is updated."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_rds_master_pass_updated

  references = [
    "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.DBInstance.Modifying.html"
  ]

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0003:T1098"
  })
}

detection "cloudtrail_logs_detect_rds_publicrestore" {
  title       = "Detect RDS public restore"
  description = "Detect when RDS public instance is restored from snapshot."
  severity    = "high"
  query       = query.cloudtrail_logs_detect_rds_publicrestore

  references = [
    "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_RestoreFromSnapshot.html"
  ]

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0010:T1020"
  })
}

detection "cloudtrail_logs_detect_s3_bucket_policy_modified" {
  title       = "Detect  S3 Bucket Policy Modified"
  description = "Detect when S3 bucket policy, is modified."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_s3_bucket_policy_modified

  references = [
    "https://docs.aws.amazon.com/AmazonS3/latest/dev/using-iam-policies.html"
  ]

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0010:T1567"
  })
}

detection "cloudtrail_logs_detect_waf_disassociation" {
  title       = "Detect WAF Disassociation"
  description = "Detect when WAF is disassociated."
  severity    = "high"
  query       = query.cloudtrail_logs_detect_waf_disassociation

  references = [
    "https://attack.mitre.org/techniques/T1078/"
  ]

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0004:T1498"
  })
}

detection "cloudtrail_logs_detect_iam_group_read_only_events" {
  title       = "Detect IAM Group Read Only Event"
  description = "Detect IAM group read only event"
  severity    = "low"
  query       = query.cloudtrail_logs_detect_iam_group_read_only_events

  references = [
    "https://attack.mitre.org/techniques/T1069/"
  ]

  // tags = merge(local.cloudtrail_log_detection_common_tags, {
   //  mitre_attack_ids = "TA0040:T1485"
  // })
}

detection "cloudtrail_logs_detect_iam_policy_modified" {
  title       = "Detect IAM Policy Modified"
  description = "Detect when IAM policy is modified."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_iam_policy_modified

  references = [
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html"
  ]

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0004:T1548"
  })
}

detection "cloudtrail_logs_detect_config_service_rule_delete" {
  title       = "Detect Config Service Rule Deleted"
  description = "Detect the deletion of config service rule."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_config_service_rule_delete

  references = [
    "https://docs.aws.amazon.com/config/latest/developerguide/how-does-config-work.html",
    "https://docs.aws.amazon.com/config/latest/APIReference/API_Operations.html",
  ]

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "T1562.001"
  })
}

detection "cloudtrail_logs_detect_configuration_recorder_stop" {
  title       = "Detect Configuration Recorder Stopped"
  description = "Detect when the configuration recorder is stopped."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_configuration_recorder_stop

  references = [
    "https://awscli.amazonaws.com/v2/documentation/api/latest/reference/configservice/stop-configuration-recorder.html",
    "https://docs.aws.amazon.com/config/latest/APIReference/API_StopConfigurationRecorder.html",
  ]

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0005.T1562"
  })
}

detection "cloudtrail_logs_detect_rds_db_instance_cluster_stop" {
  title       = "Detect RDS DB Instance or Cluster Stopped"
  description = "Detect when the RDS DB instance or cluster is stopped."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_rds_db_instance_cluster_stop

  references = [
    "https://awscli.amazonaws.com/v2/documentation/api/latest/reference/rds/stop-db-cluster.html",
    "https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_StopDBCluster.html",
    "https://awscli.amazonaws.com/v2/documentation/api/latest/reference/rds/stop-db-instance.html",
    "https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_StopDBInstance.html",
  ]

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0040.T1489"
  })
}

detection "cloudtrail_logs_detect_rds_db_snapshot_delete" {
  title       = "Detect RDS DB Snapshot Deleted"
  description = "Detect when the RDS DB snapshot is deleted."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_rds_db_snapshot_delete

  references = [
    "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_DeleteSnapshot.html",
    "https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DeleteDBSnapshot.html",
  ]

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0040.T1485"
  })
}

detection "cloudtrail_logs_detect_rds_db_instance_cluster_deletion_protection_disable" {
  title       = "Detect RDS DB Instance or Cluster Deletion Protection Disabled"
  description = "Detect when the RDS DB instance or cluster deletion protection is disabled."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_rds_db_instance_cluster_deletion_protection_disable

  references = [
    "https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_ModifyDBInstance.html",
    "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_DeleteInstance.html",
  ]

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0040.T1485"
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

query "cloudtrail_logs_detect_ec2_security_group_ingress_egress_updates" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_ec2_security_group_ingress_egress_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name in ('AuthorizeSecurityGroupEgress', 'AuthorizeSecurityGroupIngress', 'RevokeSecurityGroupEgress', 'RevokeSecurityGroupIngress')
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
      and (user_identity::JSON ->> 'invoked_by') != 'cloudformation.amazonaws.com'
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
      and user_identity.type = 'Root'
      and (response_elements::JSON ->> 'ConsoleLogin') = 'Success'
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

query "cloudtrail_logs_detect_s3_bucket_deleted" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_s3_bucket_deleted_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_name = 'DeleteBucket'
      and error_code is null
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_rds_manual_snapshot_created" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_rds_manual_snapshot_created_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'rds.amazonaws.com'
      and event_name = 'CreateDBSnapshot'
      and error_code is null
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_rds_master_pass_updated" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_rds_master_pass_updated_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'rds.amazonaws.com'
      and event_name = 'ModifyDBInstance'
      and (response_elements -> 'pendingModifiedValues' -> 'masterUserPassword') is not null
      and error_code is null
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_rds_publicrestore" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_rds_publicrestore_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'rds.amazonaws.com'
      and event_name = 'RestoreDBInstanceFromDBSnapshot'
      and CAST(response_elements ->> 'publiclyAccessible' AS BOOLEAN) = true
      and error_code is null
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_s3_bucket_policy_modified" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_s3_bucket_policy_modified_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_name in ('PutBucketPolicy', 'PutBucketAcl', 'PutBucketCors', 'PutBucketLifecycle', 'PutBucketReplication', 'DeleteBucketPolicy', 'DeleteBucketCors', 'DeleteBucketLifecycle', 'DeleteBucketReplication')
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

query "cloudtrail_logs_detect_iam_group_read_only_events" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_iam_group_read_only_events_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_name in ('GetGroup', 'GetGroupPolicy', 'ListAttachedGroupPolicies', 'ListGroupPolicies', 'ListGroups', 'DeleteBucketPolicy', 'ListGroupsForUser')
      and error_code is null
    order by
      event_time desc;
  EOQ
}

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

query "cloudtrail_logs_detect_rds_db_instance_cluster_stop" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_rds_db_instance_cluster_stop_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'rds.amazonaws.com'
      and event_name in ('StopDBInstance', 'StopDBCluster')
      and error_code is null
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_rds_db_snapshot_delete" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_rds_db_snapshot_delete_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'rds.amazonaws.com'
      and (
        (event_name in ('DeleteDBSnapshot', 'DeleteDBClusterSnapshot'))
        or (event_name = 'ModifyDBInstance' and (request_parameters ->> 'backupRetentionPeriod')::int = 7)
        )
      and error_code is null
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_rds_db_instance_cluster_deletion_protection_disable" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_rds_db_instance_cluster_deletion_protection_disable_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'rds.amazonaws.com'
      and event_name in ('ModifyDBInstance', 'ModifyDBCluster')
      and (request_parameters ->> 'deletionProtection' = false)
      and error_code is null
    order by
      event_time desc;
  EOQ
}

