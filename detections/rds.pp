locals {
  rds_common_tags = merge(local.aws_cloudtrail_log_detections_common_tags, {
    folder  = "RDS"
    service = "AWS/RDS"
  })
}

benchmark "rds_detections" {
  title       = "RDS Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for RDS events."
  type        = "detection"
  children = [
    detection.rds_db_cluster_deletion_protection_disabled,
    detection.rds_db_instance_assigned_public_ip_address,
    detection.rds_db_instance_deletion_protection_disabled,
    detection.rds_db_instance_iam_authentication_disabled,
    detection.rds_db_instance_master_password_updated,
    detection.rds_db_instance_restored_from_public_snapshot,
  ]

  tags = merge(local.rds_common_tags, {
    type = "Benchmark"
  })
}

detection "rds_db_instance_assigned_public_ip_address" {
  title           = "RDS DB Instance Assigned Public IP Address"
  description     = "Detect when public access was granted to an RDS database instance, potentially exposing sensitive data to unauthorized users and increasing the risk of attacks such as brute force, SQL injection, or exploitation."
  documentation   = file("./detections/docs/rds_db_instance_assigned_public_ip_address.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.rds_db_instance_assigned_public_ip_address

  tags = merge(local.rds_common_tags, {
    mitre_attack_ids = "TA0001:T1190"
  })
}

query "rds_db_instance_assigned_public_ip_address" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_db_instance_identifier}
    from
      aws_cloudtrail_log
    where
      event_source = 'rds.amazonaws.com'
      and event_name in ('ModifyDBInstance', 'CreateDBInstance')
      and (request_parameters -> 'publiclyAccessible') = true
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ

  tags = local.rds_common_tags
}

detection "rds_db_instance_master_password_updated" {
  title           = "RDS DB Instance Master Password Updated"
  description     = "Detect when the master password of an RDS DB instance was updated. While a password update is common for security maintenance, an unexpected or unauthorized change may indicate an attempt to compromise database access or escalate privileges."
  documentation   = file("./detections/docs/rds_db_instance_master_password_updated.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.rds_db_instance_master_password_updated

  tags = merge(local.rds_common_tags, {
    mitre_attack_ids = "TA0003:T1098.001"
  })
}

query "rds_db_instance_master_password_updated" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_db_instance_identifier}
    from
      aws_cloudtrail_log
    where
      event_source = 'rds.amazonaws.com'
      and event_name = 'ModifyDBInstance'
      and (request_parameters -> 'masterUserPassword') is not null
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ

  tags = local.rds_common_tags
}

detection "rds_db_instance_restored_from_public_snapshot" {
  title           = "RDS DB Instance Restored from Public Snapshot"
  description     = "Detect when an RDS DB instance was restored from a public snapshot. Restoring an instance from a public snapshot could have exposed sensitive data to unauthorized access, increasing the risk of data exfiltration or exploitation."
  documentation   = file("./detections/docs/rds_db_instance_restored_from_public_snapshot.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.rds_db_instance_restored_from_public_snapshot

  tags = local.rds_common_tags
}

query "rds_db_instance_restored_from_public_snapshot" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_db_instance_identifier}
    from
      aws_cloudtrail_log
    where
      event_source = 'rds.amazonaws.com'
      and event_name = 'RestoreDBInstanceFromDBSnapshot'
      and (request_parameters -> 'publiclyAccessible') = true
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ

  tags = local.rds_common_tags
}

detection "rds_db_cluster_deletion_protection_disabled" {
  title           = "RDS DB Cluster Deletion Protection Disabled"
  description     = "Detect when deletion protection was disabled for an RDS DB cluster. Disabling deletion protection increases the risk of accidental or malicious deletion of a database cluster, potentially leading to data loss and service disruption."
  documentation   = file("./detections/docs/rds_db_cluster_deletion_protection_disabled.md")
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.rds_db_cluster_deletion_protection_disabled

  tags = merge(local.rds_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

query "rds_db_cluster_deletion_protection_disabled" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_db_cluster_identifier}
    from
      aws_cloudtrail_log
    where
      event_source = 'rds.amazonaws.com'
      and event_name = 'ModifyDBCluster'
      and (request_parameters -> 'deletionProtection') = false
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ

  tags = local.rds_common_tags
}

detection "rds_db_instance_iam_authentication_disabled" {
  title           = "RDS DB Instance IAM Authentication Disabled"
  description     = "Detect when IAM authentication was disabled on an RDS DB instance. Disabling IAM authentication could have weakened access controls, making it easier for attackers to exploit misconfigured or vulnerable services for unauthorized access or lateral movement."
  documentation   = file("./detections/docs/rds_db_instance_iam_authentication_disabled.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.rds_db_instance_iam_authentication_disabled

  tags = merge(local.rds_common_tags, {
    mitre_attack_ids = "TA0008:T1210"
  })
}

query "rds_db_instance_iam_authentication_disabled" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_db_instance_identifier}
    from
      aws_cloudtrail_log
    where
      event_source = 'rds.amazonaws.com'
      and event_name = 'ModifyDBInstance'
      and (response_elements -> 'iAMDatabaseAuthenticationEnabled') = false
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ

  tags = local.rds_common_tags
}

detection "rds_db_instance_deletion_protection_disabled" {
  title           = "RDS DB Instance Deletion Protection Disabled"
  description     = "Detect when deletion protection was disabled for an RDS DB instance. Disabling deletion protection increases the risk of accidental or malicious deletion of a critical database, potentially leading to data loss and service disruption."
  documentation   = file("./detections/docs/rds_db_instance_deletion_protection_disabled.md")
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.rds_db_instance_deletion_protection_disabled

  tags = merge(local.rds_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

query "rds_db_instance_deletion_protection_disabled" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_db_instance_identifier}
    from
      aws_cloudtrail_log
    where
      event_source = 'rds.amazonaws.com'
      and event_name = 'ModifyDBInstance'
      and (request_parameters -> 'deletionProtection') = false
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ

  tags = local.rds_common_tags
}
