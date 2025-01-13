locals {
  rds_common_tags = merge(local.aws_cloudtrail_log_detections_common_tags, {
    service = "AWS/RDS"
  })

  detect_rds_db_manual_snapshot_creations_sql_columns                   = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.dBInstanceIdentifier')")
  detect_rds_db_instance_master_password_updates_sql_columns            = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.dBInstanceIdentifier')")
  detect_rds_db_instances_public_restore_sql_columns                    = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.dBInstanceIdentifier')")
  detect_rds_db_instances_with_iam_authentication_disabled_sql_columns  = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.name')")
  detect_rds_db_clusters_with_deletion_protection_disabled_sql_columns  = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.dBClusterIdentifier')")
  detect_rds_db_instances_with_deletion_protection_disabled_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.dBInstanceIdentifier')")
  detect_public_access_granted_to_rds_db_instances_sql_columns          = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.dBInstanceIdentifier')")
}

benchmark "rds_detections" {
  title       = "RDS Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for RDS events."
  type        = "detection"
  children    = [
    detection.detect_rds_db_manual_snapshot_creations,
    detection.detect_rds_db_instance_master_password_updates,
    detection.detect_rds_db_instances_public_restore,
    detection.detect_rds_db_clusters_with_deletion_protection_disabled,
    detection.detect_rds_db_instances_with_deletion_protection_disabled,
    detection.detect_public_access_granted_to_rds_db_instances,
    detection.detect_rds_db_instances_with_iam_authentication_disabled,
  ]

  tags = merge(local.rds_common_tags, {
    type    = "Benchmark"
  })
}

detection "detect_public_access_granted_to_rds_db_instances" {
  title           = "Detect Public Access Granted to RDS DB Instances"
  description     = "Detect when public access is granted to RDS database instances. Making RDS instances publicly accessible can expose sensitive data to unauthorized users and increase the risk of exploitation through brute force, SQL injection, or other attacks."
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.detect_public_access_granted_to_rds_db_instances

  tags = merge(local.rds_common_tags, {
    mitre_attack_ids = "TA0001:T1190"
  })
}

detection "detect_rds_db_manual_snapshot_creations" {
  title           = "Detect RDS Manual Snapshot Created"
  description     = "Detect when a manual snapshot of an RDS database instance is created. Manual snapshots can be used for legitimate backup purposes, but unauthorized snapshot creation may indicate data exfiltration or attempts to access sensitive data."
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.detect_rds_db_manual_snapshot_creations

  tags = merge(local.rds_common_tags, {
    mitre_attack_ids = "TA0010:T1537"
  })
}

detection "detect_rds_db_instance_master_password_updates" {
  title           = "Detect RDS Instances Master Password Updates"
  description     = "Detect when the master password of an RDS DB instance is updated. While password updates are common for security maintenance, unexpected or unauthorized changes may indicate an attempt to compromise database access or escalate privileges."
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.detect_rds_db_instance_master_password_updates

  tags = merge(local.rds_common_tags, {
    mitre_attack_ids = "TA0003:T1098"
  })
}

detection "detect_rds_db_instances_public_restore" {
  title           = "Detect RDS DB Instancse Public Restore"
  description     = "Detect when an RDS DB instance is restored from a snapshot with public accessibility enabled. Restoring a public DB instance can expose sensitive data to unauthorized access, increasing the risk of data exfiltration or exploitation."
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.detect_rds_db_instances_public_restore

  tags = merge(local.rds_common_tags, {
    mitre_attack_ids = "TA0010:T1020"
  })
}

detection "detect_rds_db_clusters_with_deletion_protection_disabled" {
  title           = "Detect RDS DB Clusters Deletion Protection Disabled"
  description     = "Detect when deletion protection is disabled for RDS DB clusters. Disabling deletion protection increases the risk of accidental or malicious deletion of database clusters, potentially leading to data loss and service disruption."
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.detect_rds_db_clusters_with_deletion_protection_disabled

  tags = merge(local.rds_common_tags, {
    mitre_attack_ids = "TA0040.T1485"
  })
}

detection "detect_rds_db_instances_with_iam_authentication_disabled" {
  title           = "Detect Exploitation of Remote Services"
  description     = "Detect when IAM authentication is disabled on RDS DB instances. Disabling IAM authentication can weaken access controls, making it easier for attackers to exploit misconfigured or vulnerable services for unauthorized access or lateral movement."
  severity        = "critical"
  display_columns = local.detection_display_columns
  # documentation = file("./detections/docs/detect_rds_db_instances_with_iam_authentication_disabled.md")
  query           = query.detect_rds_db_instances_with_iam_authentication_disabled

  tags = merge(local.rds_common_tags, {
    mitre_attack_ids = "TA0008:T1210"
  })
}

detection "detect_rds_db_instances_with_deletion_protection_disabled" {
  title           = "Detect RDS DB Instances Deletion Protection Disabled"
  description     = "Detect when deletion protection is disabled for RDS DB instances. Disabling deletion protection increases the risk of accidental or malicious deletion of critical databases, potentially leading to data loss and service disruption."
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.detect_rds_db_instances_with_deletion_protection_disabled

  tags = merge(local.rds_common_tags, {
    mitre_attack_ids = "TA0040.T1485"
  })
}

query "detect_rds_db_instances_with_iam_authentication_disabled" {
  sql = <<-EOQ
    select
      ${local.detect_rds_db_instances_with_iam_authentication_disabled_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'rds.amazonaws.com'
      and event_name = 'ModifyDBInstance'
      and json_extract_string(request_parameters, '$.enableIAMDatabaseAuthentication') = 'false'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "detect_public_access_granted_to_rds_db_instances" {
  sql = <<-EOQ
    select
      ${local.detect_public_access_granted_to_rds_db_instances_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'rds.amazonaws.com'
      and event_name in ('ModifyDBInstance', 'CreateDBInstance')
      and json_extract_string(request_parameters, '$.publiclyAccessible') = 'true'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "detect_rds_db_manual_snapshot_creations" {
  sql = <<-EOQ
    select
      ${local.detect_rds_db_manual_snapshot_creations_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'rds.amazonaws.com'
      and event_name = 'CreateDBSnapshot'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "detect_rds_db_instance_master_password_updates" {
  sql = <<-EOQ
    select
      ${local.detect_rds_db_instance_master_password_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'rds.amazonaws.com'
      and event_name = 'ModifyDBInstance'
      and json_extract_string(response_elements, '$.pendingModifiedValues.masterUserPassword') is not null
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "detect_rds_db_instances_public_restore" {
  sql = <<-EOQ
    select
      ${local.detect_rds_db_instances_public_restore_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'rds.amazonaws.com'
      and event_name = 'RestoreDBInstanceFromDBSnapshot'
      and json_extract_string(response_elements, '$.publiclyAccessible') = 'true'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "detect_rds_db_clusters_with_deletion_protection_disabled" {
  sql = <<-EOQ
    select
      ${local.detect_rds_db_clusters_with_deletion_protection_disabled_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'rds.amazonaws.com'
      and event_name = 'ModifyDBCluster'
      and json_extract_string(request_parameters, '$.deletionProtection') = 'false'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "detect_rds_db_instances_with_deletion_protection_disabled" {
  sql = <<-EOQ
    select
      ${local.detect_rds_db_instances_with_deletion_protection_disabled_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'rds.amazonaws.com'
      and event_name = 'ModifyDBInstance'
      and json_extract_string(request_parameters, '$.deletionProtection') = 'false'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}
