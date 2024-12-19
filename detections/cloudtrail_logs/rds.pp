locals {
  cloudtrail_log_detection_rds_common_tags = merge(local.cloudtrail_log_detection_common_tags, {
    service = "AWS/RDS"
  })

  cloudtrail_logs_detect_rds_db_manual_snapshot_creations_sql_columns                   = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.dBInstanceIdentifier')")
  cloudtrail_logs_detect_rds_db_instance_master_password_updates_sql_columns            = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.dBInstanceIdentifier')")
  cloudtrail_logs_detect_rds_db_instances_public_restore_sql_columns                    = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.dBInstanceIdentifier')")
  cloudtrail_logs_detect_rds_db_instance_snapshot_deletions_sql_columns                 = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.dBSnapshotIdentifier')")
  cloudtrail_logs_detect_rds_db_instances_with_iam_authentication_disabled_sql_columns  = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.name')")
  cloudtrail_logs_detect_rds_db_clusters_with_deletion_protection_disabled_sql_columns  = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.dBClusterIdentifier')")
  cloudtrail_logs_detect_rds_db_instances_with_deletion_protection_disabled_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.dBInstanceIdentifier')")
  cloudtrail_logs_detect_rds_db_cluster_snapshot_deletions_sql_columns                  = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.dBSnapshotIdentifier')")
  cloudtrail_logs_detect_public_access_granted_to_rds_db_instances_sql_columns          = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.dBInstanceIdentifier')")
}

benchmark "cloudtrail_logs_rds_detections" {
  title       = "RDS Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for RDS events."
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_rds_db_manual_snapshot_creations,
    detection.cloudtrail_logs_detect_rds_db_instance_master_password_updates,
    detection.cloudtrail_logs_detect_rds_db_instances_public_restore,
    detection.cloudtrail_logs_detect_rds_db_instance_snapshot_deletions,
    detection.cloudtrail_logs_detect_rds_db_clusters_with_deletion_protection_disabled,
    detection.cloudtrail_logs_detect_rds_db_instances_with_deletion_protection_disabled,
    detection.cloudtrail_logs_detect_public_access_granted_to_rds_db_instances,
    detection.cloudtrail_logs_detect_rds_db_instances_with_iam_authentication_disabled,
    detection.cloudtrail_logs_detect_rds_db_cluster_snapshot_deletions,
  ]

  tags = merge(local.cloudtrail_log_detection_rds_common_tags, {
    type    = "Benchmark"
  })
}

detection "cloudtrail_logs_detect_public_access_granted_to_rds_db_instances" {
  title       = "Detect Public Access Granted to RDS DB Instances"
  description = "Detect when public access is granted to RDS database instances. Making RDS instances publicly accessible can expose sensitive data to unauthorized users and increase the risk of exploitation through brute force, SQL injection, or other attacks."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_public_access_granted_to_rds_db_instances

  tags = merge(local.cloudtrail_log_detection_rds_common_tags, {
    mitre_attack_ids = "TA0001:T1190"
  })
}

detection "cloudtrail_logs_detect_rds_db_manual_snapshot_creations" {
  title       = "Detect RDS Manual Snapshot Created"
  description = "Detect when a manual snapshot of an RDS database instance is created. Manual snapshots can be used for legitimate backup purposes, but unauthorized snapshot creation may indicate data exfiltration or attempts to access sensitive data."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_rds_db_manual_snapshot_creations

  tags = merge(local.cloudtrail_log_detection_rds_common_tags, {
    mitre_attack_ids = "TA0010:T1537"
  })
}

detection "cloudtrail_logs_detect_rds_db_instance_master_password_updates" {
  title       = "Detect RDS Instances Master Password Updates"
  description = "Detect when the master password of an RDS DB instance is updated. While password updates are common for security maintenance, unexpected or unauthorized changes may indicate an attempt to compromise database access or escalate privileges."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_rds_db_instance_master_password_updates

  tags = merge(local.cloudtrail_log_detection_rds_common_tags, {
    mitre_attack_ids = "TA0003:T1098"
  })
}

detection "cloudtrail_logs_detect_rds_db_instances_public_restore" {
  title       = "Detect RDS DB Instancse Public Restore"
  description = "Detect when an RDS DB instance is restored from a snapshot with public accessibility enabled. Restoring a public DB instance can expose sensitive data to unauthorized access, increasing the risk of data exfiltration or exploitation."
  severity    = "high"
  query       = query.cloudtrail_logs_detect_rds_db_instances_public_restore

  tags = merge(local.cloudtrail_log_detection_rds_common_tags, {
    mitre_attack_ids = "TA0010:T1020"
  })
}

detection "cloudtrail_logs_detect_rds_db_instance_snapshot_deletions" {
  title       = "Detect RDS DB Instance Snapshots Deletions"
  description = "Detect when RDS DB instance snapshots are deleted. Deleting snapshots can lead to the loss of critical backups, hinder recovery efforts, and may indicate an attempt to destroy evidence or disrupt data availability."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_rds_db_instance_snapshot_deletions

  tags = merge(local.cloudtrail_log_detection_rds_common_tags, {
    mitre_attack_ids = "TA0040.T1485"
  })
}

detection "cloudtrail_logs_detect_rds_db_cluster_snapshot_deletions" {
  title       = "Detect RDS DB Cluster Snapshots Deletions"
  description = "Detect when RDS DB cluster snapshots are deleted. Deleting cluster snapshots can lead to the loss of critical backups, hinder disaster recovery, and may indicate attempts to destroy evidence or disrupt data availability."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_rds_db_cluster_snapshot_deletions

  tags = merge(local.cloudtrail_log_detection_rds_common_tags, {
    mitre_attack_ids = "TA0040.T1485"
  })
}

detection "cloudtrail_logs_detect_rds_db_clusters_with_deletion_protection_disabled" {
  title       = "Detect RDS DB Clusters Deletion Protection Disabled"
  description = "Detect when deletion protection is disabled for RDS DB clusters. Disabling deletion protection increases the risk of accidental or malicious deletion of database clusters, potentially leading to data loss and service disruption."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_rds_db_clusters_with_deletion_protection_disabled

  tags = merge(local.cloudtrail_log_detection_rds_common_tags, {
    mitre_attack_ids = "TA0040.T1485"
  })
}

detection "cloudtrail_logs_detect_rds_db_instances_with_iam_authentication_disabled" {
  title       = "Detect Exploitation of Remote Services"
  description = "Detect when IAM authentication is disabled on RDS DB instances. Disabling IAM authentication can weaken access controls, making it easier for attackers to exploit misconfigured or vulnerable services for unauthorized access or lateral movement."
  severity    = "critical"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_rds_db_instances_with_iam_authentication_disabled.md")
  query       = query.cloudtrail_logs_detect_rds_db_instances_with_iam_authentication_disabled

  tags = merge(local.cloudtrail_log_detection_rds_common_tags, {
    mitre_attack_ids = "TA0008:T1210"
  })
}

detection "cloudtrail_logs_detect_rds_db_instances_with_deletion_protection_disabled" {
  title       = "Detect RDS DB Instances Deletion Protection Disabled"
  description = "Detect when deletion protection is disabled for RDS DB instances. Disabling deletion protection increases the risk of accidental or malicious deletion of critical databases, potentially leading to data loss and service disruption."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_rds_db_instances_with_deletion_protection_disabled

  tags = merge(local.cloudtrail_log_detection_rds_common_tags, {
    mitre_attack_ids = "TA0040.T1485"
  })
}

query "cloudtrail_logs_detect_rds_db_instances_with_iam_authentication_disabled" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_rds_db_instances_with_iam_authentication_disabled_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'rds.amazonaws.com'
      and event_name = 'ModifyDBInstance'
      and json_extract_string(request_parameters, '$.enableIAMDatabaseAuthentication') = 'false'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_public_access_granted_to_rds_db_instances" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_public_access_granted_to_rds_db_instances_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'rds.amazonaws.com'
      and event_name in ('ModifyDBInstance', 'CreateDBInstance')
      and json_extract_string(request_parameters, '$.publiclyAccessible') = 'true'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_rds_db_manual_snapshot_creations" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_rds_db_manual_snapshot_creations_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'rds.amazonaws.com'
      and event_name = 'CreateDBSnapshot'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_rds_db_instance_master_password_updates" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_rds_db_instance_master_password_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'rds.amazonaws.com'
      and event_name = 'ModifyDBInstance'
      and json_extract_string(response_elements, '$.pendingModifiedValues.masterUserPassword') is not null
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_rds_db_instances_public_restore" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_rds_db_instances_public_restore_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'rds.amazonaws.com'
      and event_name = 'RestoreDBInstanceFromDBSnapshot'
      and json_extract_string(response_elements, '$.publiclyAccessible') = 'true'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_rds_db_instance_snapshot_deletions" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_rds_db_instance_snapshot_deletions_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'rds.amazonaws.com'
      and (
        (event_name = 'DeleteDBSnapshot')
        or (event_name = 'ModifyDBInstance' and json_extract_string(request_parameters, '$.backupRetentionPeriod')::int = 7)
        )
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_rds_db_cluster_snapshot_deletions" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_rds_db_cluster_snapshot_deletions_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'rds.amazonaws.com'
      and event_name = 'DeleteDBClusterSnapshot'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_rds_db_clusters_with_deletion_protection_disabled" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_rds_db_clusters_with_deletion_protection_disabled_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'rds.amazonaws.com'
      and event_name = 'ModifyDBCluster'
      and json_extract_string(request_parameters, '$.deletionProtection') = 'false'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_rds_db_instances_with_deletion_protection_disabled" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_rds_db_instances_with_deletion_protection_disabled_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'rds.amazonaws.com'
      and event_name = 'ModifyDBInstance'
      and json_extract_string(request_parameters, '$.deletionProtection') = 'false'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}
