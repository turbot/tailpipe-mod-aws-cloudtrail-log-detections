locals {
  cloudtrail_logs_detect_rds_manual_snapshot_created_sql_columns                 = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.dBInstanceIdentifier")
  cloudtrail_logs_detect_rds_master_pass_updated_sql_columns                     = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.dBInstanceIdentifier")
  cloudtrail_logs_detect_rds_publicrestore_sql_columns                           = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.dBInstanceIdentifier")
  cloudtrail_logs_detect_rds_db_instance_stop_sql_columns                        = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.dBInstanceIdentifier")
  cloudtrail_logs_detect_rds_db_cluster_stop_sql_columns                         = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.dBClusterIdentifier")
  cloudtrail_logs_detect_rds_db_snapshot_delete_sql_columns                      = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.dBSnapshotIdentifier")
  cloudtrail_logs_detect_rds_db_instance_cluster_deletion_protection_disable_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "coalesce(request_parameters.dBInstanceIdentifier, request_parameters.dBClusterIdentifier)")
  cloudtrail_logs_detect_rds_db_instance_disable_iam_authentication_updates_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
  cloudtrail_logs_detect_rds_db_cluster_deletion_protection_disable_sql_columns  = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.dBClusterIdentifier")
  cloudtrail_logs_detect_rds_db_instance_deletion_protection_disable_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.dBInstanceIdentifier")
}

benchmark "cloudtrail_logs_rds_detections" {
  title       = "CloudTrail Log RDS Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail's RDS logs"
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_rds_manual_snapshot_created,
    detection.cloudtrail_logs_detect_rds_master_pass_updated,
    detection.cloudtrail_logs_detect_rds_publicrestore,
    detection.cloudtrail_logs_detect_rds_db_instance_stop,
    detection.cloudtrail_logs_detect_rds_db_cluster_stop,
    detection.cloudtrail_logs_detect_rds_db_snapshot_delete,
    detection.cloudtrail_logs_detect_rds_db_cluster_deletion_protection_disable,
    detection.cloudtrail_logs_detect_rds_db_instance_deletion_protection_disable,
    detection.cloudtrail_logs_detect_rds_instance_pulicly_accessible,
  ]

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    type    = "Benchmark"
    service = "AWS/RDS"
  })
}

detection "cloudtrail_logs_detect_rds_instance_pulicly_accessible" {
  title       = "Detect RDS Instances Publicly Accessible"
  description = "Detect RDS instances publicly accessible to check for unauthorized access."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_rds_instance_pulicly_accessible

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "cloudtrail_logs_detect_rds_manual_snapshot_created" {
  title       = "Detect RDS Manual Snapshots Created"
  description = "Detect when RDS manual snapshots is created."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_rds_manual_snapshot_created

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0010:T1537"
  })
}

detection "cloudtrail_logs_detect_rds_master_pass_updated" {
  title       = "Detect RDS Instances Master Password Updated"
  description = "Detect when RDS instances master password is updated."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_rds_master_pass_updated

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0003:T1098"
  })
}

detection "cloudtrail_logs_detect_rds_publicrestore" {
  title       = "Detect RDS Instances public restore"
  description = "Detect when RDS public instances are restored from snapshot."
  severity    = "high"
  query       = query.cloudtrail_logs_detect_rds_publicrestore

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0010:T1020"
  })
}

detection "cloudtrail_logs_detect_rds_db_instance_stop" {
  title       = "Detect RDS DB Instances Stopped"
  description = "Detect when the RDS DB instances is stopped."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_rds_db_instance_stop

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0040.T1489"
  })
}

detection "cloudtrail_logs_detect_rds_db_cluster_stop" {
  title       = "Detect RDS DB Clusters Stopped"
  description = "Detect when the RDS DB clusters is stopped."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_rds_db_cluster_stop

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0040.T1489"
  })
}

detection "cloudtrail_logs_detect_rds_db_snapshot_delete" {
  title       = "Detect RDS DB Snapshots Deleted"
  description = "Detect when the RDS DB snapshots is deleted."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_rds_db_snapshot_delete

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0040.T1485"
  })
}

detection "cloudtrail_logs_detect_rds_db_cluster_deletion_protection_disable" {
  title       = "Detect RDS DB Clusters Deletion Protection Disabled"
  description = "Detect when the RDS DB clusters deletion protection is disabled."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_rds_db_cluster_deletion_protection_disable

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0040.T1485"
  })
}

detection "cloudtrail_logs_detect_rds_db_instance_disable_iam_authentication_updates" {
  title       = "Detect Exploitation of Remote Services"
  description = "Detect lateral movement via the exploitation of misconfigured or vulnerable services."
  severity    = "critical"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_rds_db_instance_disable_iam_authentication_updates.md")
  query       = query.cloudtrail_logs_detect_rds_db_instance_disable_iam_authentication_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0008:T1210"
  })
}

query "cloudtrail_logs_detect_rds_db_instance_disable_iam_authentication_updates" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_rds_db_instance_disable_iam_authentication_updates_sql_columns}
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

detection "cloudtrail_logs_detect_rds_db_instance_deletion_protection_disable" {
  title       = "Detect RDS DB Instances Deletion Protection Disabled"
  description = "Detect when the RDS DB instances deletion protection is disabled."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_rds_db_instance_deletion_protection_disable

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0040.T1485"
  })
}


query "cloudtrail_logs_detect_rds_instance_pulicly_accessible" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_rds_instance_pulicly_accessible_sql_columns}
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

query "cloudtrail_logs_detect_rds_manual_snapshot_created" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_rds_manual_snapshot_created_sql_columns}
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
      ${local.cloudtrail_log_detections_where_conditions}
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
      and cast(response_elements ->> 'publiclyAccessible' AS BOOLEAN) = true
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_rds_db_instance_stop" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_rds_db_instance_stop_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'rds.amazonaws.com'
      and event_name = 'StopDBInstance'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_rds_db_cluster_stop" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_rds_db_cluster_stop_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'rds.amazonaws.com'
      and event_name = 'StopDBCluster'
      ${local.cloudtrail_log_detections_where_conditions}
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
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_rds_db_cluster_deletion_protection_disable" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_rds_db_cluster_deletion_protection_disable_sql_columns}
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

query "cloudtrail_logs_detect_rds_db_instance_deletion_protection_disable" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_rds_db_instance_deletion_protection_disable_sql_columns}
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