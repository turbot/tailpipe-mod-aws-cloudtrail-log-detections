locals {
  rds_common_tags = merge(local.aws_cloudtrail_log_detections_common_tags, {
    service = "AWS/RDS"
  })

  rds_db_instance_master_password_update_sql_columns       = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.dBInstanceIdentifier')")
  rds_db_instance_public_restore_sql_columns               = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.dBInstanceIdentifier')")
  rds_db_instance_iam_authentication_disabled_sql_columns  = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.name')")
  rds_db_cluster_deletion_protection_disabled_sql_columns  = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.dBClusterIdentifier')")
  rds_db_instance_deletion_protection_disabled_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.dBInstanceIdentifier')")
  rds_db_instance_shared_publicly_sql_columns              = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.dBInstanceIdentifier')")
}

benchmark "rds_detections" {
  title       = "RDS Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for RDS events."
  type        = "detection"
  children = [
    detection.rds_db_instance_master_password_update,
    detection.rds_db_instance_public_restore,
    detection.rds_db_cluster_deletion_protection_disabled,
    detection.rds_db_instance_deletion_protection_disabled,
    detection.rds_db_instance_shared_publicly,
    detection.rds_db_instance_iam_authentication_disabled,
  ]

  tags = merge(local.rds_common_tags, {
    type = "Benchmark"
  })
}

detection "rds_db_instance_shared_publicly" {
  title           = "RDS DB Instance Shared Publicly"
  description     = "Detect when public access is granted to RDS database instances. Making RDS instances publicly accessible can expose sensitive data to unauthorized users and increase the risk of exploitation through brute force, SQL injection, or other attacks."
  documentation   = file("./detections/docs/rds_db_instance_shared_publicly.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.rds_db_instance_shared_publicly

  tags = merge(local.rds_common_tags, {
    mitre_attack_ids = "TA0001:T1190"
  })
}

query "rds_db_instance_shared_publicly" {
  sql = <<-EOQ
    select
      ${local.rds_db_instance_shared_publicly_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'rds.amazonaws.com'
      and event_name in ('ModifyDBInstance', 'CreateDBInstance')
      and (request_parameters ->> 'publiclyAccessible') = 'true'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "rds_db_instance_master_password_update" {
  title           = "RDS DB Instance Master Password Update"
  description     = "Detect when the master password of an RDS DB instance is updated. While password updates are common for security maintenance, unexpected or unauthorized changes may indicate an attempt to compromise database access or escalate privileges."
  documentation   = file("./detections/docs/rds_db_instance_master_password_update.md")
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.rds_db_instance_master_password_update

  tags = merge(local.rds_common_tags, {
    mitre_attack_ids = "TA0003:T1098"
  })
}

query "rds_db_instance_master_password_update" {
  sql = <<-EOQ
    select
      ${local.rds_db_instance_master_password_update_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'rds.amazonaws.com'
      and event_name = 'ModifyDBInstance'
      and (response_elements -> 'pendingModifiedValues' ->> 'masterUserPassword') is not null
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "rds_db_instance_public_restore" {
  title           = "RDS DB Instance Public Restore"
  description     = "Detect when an RDS DB instance is restored from a snapshot with public accessibility enabled. Restoring a public DB instance can expose sensitive data to unauthorized access, increasing the risk of data exfiltration or exploitation."
  documentation   = file("./detections/docs/rds_db_instance_public_restore.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.rds_db_instance_public_restore

  tags = merge(local.rds_common_tags, {
    mitre_attack_ids = "TA0010:T1020"
  })
}

query "rds_db_instance_public_restore" {
  sql = <<-EOQ
    select
      ${local.rds_db_instance_public_restore_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'rds.amazonaws.com'
      and event_name = 'RestoreDBInstanceFromDBSnapshot'
      and (response_elements ->> 'publiclyAccessible') = 'true'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "rds_db_cluster_deletion_protection_disabled" {
  title           = "RDS DB Cluster Deletion Protection Disabled"
  description     = "Detect when deletion protection is disabled for RDS DB clusters. Disabling deletion protection increases the risk of accidental or malicious deletion of database clusters, potentially leading to data loss and service disruption."
  documentation   = file("./detections/docs/rds_db_cluster_deletion_protection_disabled.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.rds_db_cluster_deletion_protection_disabled

  tags = merge(local.rds_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

query "rds_db_cluster_deletion_protection_disabled" {
  sql = <<-EOQ
    select
      ${local.rds_db_cluster_deletion_protection_disabled_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'rds.amazonaws.com'
      and event_name = 'ModifyDBCluster'
      and (request_parameters ->> 'deletionProtection') = 'false'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "rds_db_instance_iam_authentication_disabled" {
  title           = "RDS DB Instance IAM Authentication Disabled"
  description     = "Detect when IAM authentication is disabled on RDS DB instances. Disabling IAM authentication can weaken access controls, making it easier for attackers to exploit misconfigured or vulnerable services for unauthorized access or lateral movement."
  documentation   = file("./detections/docs/rds_db_instance_iam_authentication_disabled.md")
  severity        = "critical"
  display_columns = local.detection_display_columns
  query           = query.rds_db_instance_iam_authentication_disabled

  tags = merge(local.rds_common_tags, {
    mitre_attack_ids = "TA0008:T1210"
  })
}

query "rds_db_instance_iam_authentication_disabled" {
  sql = <<-EOQ
    select
      ${local.rds_db_instance_iam_authentication_disabled_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'rds.amazonaws.com'
      and event_name = 'ModifyDBInstance'
      and (request_parameters ->> 'enableIAMDatabaseAuthentication') = 'false'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "rds_db_instance_deletion_protection_disabled" {
  title           = "RDS DB Instance Deletion Protection Disabled"
  description     = "Detect when deletion protection is disabled for RDS DB instances. Disabling deletion protection increases the risk of accidental or malicious deletion of critical databases, potentially leading to data loss and service disruption."
  documentation   = file("./detections/docs/rds_db_instance_deletion_protection_disabled.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.rds_db_instance_deletion_protection_disabled

  tags = merge(local.rds_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

query "rds_db_instance_deletion_protection_disabled" {
  sql = <<-EOQ
    select
      ${local.rds_db_instance_deletion_protection_disabled_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'rds.amazonaws.com'
      and event_name = 'ModifyDBInstance'
      and (request_parameters ->> 'deletionProtection') = 'false'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

