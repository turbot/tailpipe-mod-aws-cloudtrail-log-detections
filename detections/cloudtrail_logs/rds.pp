locals {
  cloudtrail_logs_detect_rds_db_manual_snapshot_creations_sql_columns                 = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.dBInstanceIdentifier")
  cloudtrail_logs_detect_rds_db_instance_master_pass_updates_sql_columns                     = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.dBInstanceIdentifier")
  cloudtrail_logs_detect_rds_db_instance_public_restores_sql_columns                           = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.dBInstanceIdentifier")
  cloudtrail_logs_detect_rds_db_instance_snapshot_deletions_sql_columns                      = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.dBSnapshotIdentifier")
  cloudtrail_logs_detect_disabled_iam_authentication_rds_db_instances_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
  cloudtrail_logs_detect_deletion_protection_disabled_rds_db_clusters_sql_columns  = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.dBClusterIdentifier")
  cloudtrail_logs_detect_deletion_protection_disabled_rds_db_instances_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.dBInstanceIdentifier")
  cloudtrail_logs_detect_rds_db_cluster_snapshot_deletions_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.dBSnapshotIdentifier")
  cloudtrail_logs_detect_publicly_accessible_rds_db_instances_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.dBInstanceIdentifier")
}

benchmark "cloudtrail_logs_rds_detections" {
  title       = "RDS"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for RDS events."
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_rds_db_manual_snapshot_creations,
    detection.cloudtrail_logs_detect_rds_db_instance_master_pass_updates,
    detection.cloudtrail_logs_detect_rds_db_instance_public_restores,
    detection.cloudtrail_logs_detect_rds_db_instance_snapshot_deletions,
    detection.cloudtrail_logs_detect_deletion_protection_disabled_rds_db_clusters,
    detection.cloudtrail_logs_detect_deletion_protection_disabled_rds_db_instances,
    detection.cloudtrail_logs_detect_publicly_accessible_rds_db_instances,
    detection.cloudtrail_logs_detect_disabled_iam_authentication_rds_db_instances,
    detection.cloudtrail_logs_detect_rds_db_cluster_snapshot_deletions,
  ]

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    type    = "Benchmark"
    service = "AWS/RDS"
  })
}

detection "cloudtrail_logs_detect_publicly_accessible_rds_db_instances" {
  title       = "Detect RDS Instances Publicly Accessible"
  description = "Detect RDS instances publicly accessible to check for unauthorized access."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_publicly_accessible_rds_db_instances

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0001:T1190"
  })
}

detection "cloudtrail_logs_detect_rds_db_manual_snapshot_creations" {
  title       = "Detect RDS Manual Snapshots Created"
  description = "Detect when RDS manual snapshots is created."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_rds_db_manual_snapshot_creations

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0010:T1537"
  })
}

detection "cloudtrail_logs_detect_rds_db_instance_master_pass_updates" {
  title       = "Detect RDS Instances Master Password Updates"
  description = "Detect when RDS instances master password are updated."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_rds_db_instance_master_pass_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0003:T1098"
  })
}

detection "cloudtrail_logs_detect_rds_db_instance_public_restores" {
  title       = "Detect RDS DB Instances Public Restores"
  description = "Detect when RDS public DB instances are restored from snapshot."
  severity    = "high"
  query       = query.cloudtrail_logs_detect_rds_db_instance_public_restores

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0010:T1020"
  })
}

detection "cloudtrail_logs_detect_rds_db_instance_snapshot_deletions" {
  title       = "Detect RDS DB Instance Snapshots Deletions"
  description = "Detect when the RDS DB instance snapshots are deleted."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_rds_db_instance_snapshot_deletions

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0040.T1485"
  })
}

detection "cloudtrail_logs_detect_rds_db_cluster_snapshot_deletions" {
  title       = "Detect RDS DB Cluster Snapshots Deletions"
  description = "Detect when the RDS DB cluster snapshots are deleted."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_rds_db_cluster_snapshot_deletions

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0040.T1485"
  })
}


detection "cloudtrail_logs_detect_deletion_protection_disabled_rds_db_clusters" {
  title       = "Detect RDS DB Clusters Deletion Protection Disabled"
  description = "Detect when the RDS DB clusters deletion protection are disabled."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_deletion_protection_disabled_rds_db_clusters

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0040.T1485"
  })
}

detection "cloudtrail_logs_detect_disabled_iam_authentication_rds_db_instances" {
  title       = "Detect Exploitation of Remote Services"
  description = "Detect lateral movement via the exploitation of misconfigured or vulnerable services."
  severity    = "critical"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_disabled_iam_authentication_rds_db_instances.md")
  query       = query.cloudtrail_logs_detect_disabled_iam_authentication_rds_db_instances

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0008:T1210"
  })
}

detection "cloudtrail_logs_detect_deletion_protection_disabled_rds_db_instances" {
  title       = "Detect RDS DB Instances Deletion Protection Disabled"
  description = "Detect when the RDS DB instances deletion protection are disabled."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_deletion_protection_disabled_rds_db_instances

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0040.T1485"
  })
}

query "cloudtrail_logs_detect_disabled_iam_authentication_rds_db_instances" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_disabled_iam_authentication_rds_db_instances_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'rds.amazonaws.com'
      and event_name = 'ModifyDBInstance'
      and request_parameters.enableIAMDatabaseAuthentication = 'false'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_publicly_accessible_rds_db_instances" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_publicly_accessible_rds_db_instances_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'rds.amazonaws.com'
      and event_name in ('ModifyDBInstance', 'CreateDBInstance')
      and coalesce(request_parameters.publiclyAccessible, 'false') = 'true'
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

query "cloudtrail_logs_detect_rds_db_instance_master_pass_updates" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_rds_db_instance_master_pass_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'rds.amazonaws.com'
      and event_name = 'ModifyDBInstance'
      and (response_elements -> 'pendingModifiedValues' -> 'masterUserPassword') is not null
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_rds_db_instance_public_restores" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_rds_db_instance_public_restores_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'rds.amazonaws.com'
      and event_name = 'RestoreDBInstanceFromDBSnapshot'
      and cast(response_elements ->> 'publiclyAccessible' AS BOOLEAN) = true
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
        or (event_name = 'ModifyDBInstance' and (request_parameters ->> 'backupRetentionPeriod')::int = 7)
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

query "cloudtrail_logs_detect_deletion_protection_disabled_rds_db_clusters" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_deletion_protection_disabled_rds_db_clusters_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'rds.amazonaws.com'
      and event_name = 'ModifyDBCluster'
      and (request_parameters ->> 'deletionProtection' = false)
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_deletion_protection_disabled_rds_db_instances" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_deletion_protection_disabled_rds_db_instances_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'rds.amazonaws.com'
      and event_name = 'ModifyDBInstance'
      and (request_parameters ->> 'deletionProtection' = false)
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}