locals {
  ebs_common_tags = merge(local.aws_cloudtrail_log_detections_common_tags, {
    folder  = "EBS"
    service = "AWS/EBS"
  })
}

benchmark "ebs_detections" {
  title       = "EBS Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for EBS events."
  type        = "detection"
  children = [
    detection.ebs_encryption_by_default_disabled,
    detection.ebs_snapshot_created_with_encryption_disabled,
    detection.ebs_snapshot_shared_publicly,
    detection.ebs_snapshot_unlocked,
    detection.ebs_volume_detached,
  ]

  tags = merge(local.ebs_common_tags, {
    type = "Benchmark"
  })
}

detection "ebs_encryption_by_default_disabled" {
  title           = "EBS Encryption by Default Disabled"
  description     = "Detect when EBS encryption by default was disabled in a region to check for potential misconfigurations that could leave data at rest unencrypted, increasing the risk of unauthorized access or data breaches."
  documentation   = file("./detections/docs/ebs_encryption_by_default_disabled.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.ebs_encryption_by_default_disabled

  tags = merge(local.ebs_common_tags, {
    mitre_attack_ids = "TA0005:T1578.005"
  })
}

query "ebs_encryption_by_default_disabled" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_region}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'DisableEbsEncryptionByDefault'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ

  tags = local.ebs_common_tags
}

detection "ebs_volume_detached" {
  title           = "EBS Volume Detached"
  description     = "Detect when an EBS volume was detached from an EC2 instance to check for potential risks of unauthorized modification, corruption, or data loss."
  documentation   = file("./detections/docs/ebs_volume_detached.md")
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.ebs_volume_detached

  tags = merge(local.ebs_common_tags, {
    mitre_attack_ids = "TA0040:T1478"
  })
}

query "ebs_volume_detached" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_name}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'DetachVolume'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ

  tags = local.ebs_common_tags
}

detection "ebs_snapshot_shared_publicly" {
  title           = "EBS Snapshot Shared Publicly"
  description     = "Detect when an EBS snapshot was shared publicly, potentially exposing sensitive data to unauthorized users."
  documentation   = file("./detections/docs/ebs_snapshot_shared_publicly.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.ebs_snapshot_shared_publicly

  tags = merge(local.ebs_common_tags, {
    mitre_attack_ids = "TA0001:T1078.004"
  })
}

query "ebs_snapshot_shared_publicly" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_snapshot_id}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'ModifySnapshotAttribute'
      and json_contains(
        (request_parameters -> 'createVolumePermission' -> 'add' -> 'items'),
        '{"group": "all"}'
      )
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ

  tags = local.ebs_common_tags
}

detection "ebs_snapshot_created_with_encryption_disabled" {
  title           = "EBS Snapshot Created with Encryption Disabled"
  description     = "Detect when an EBS snapshot was created with encryption disabled, which could lead to data exposure and non-compliance with security policies."
  documentation   = file("./detections/docs/ebs_snapshot_created_with_encryption_disabled.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.ebs_snapshot_created_with_encryption_disabled

  tags = merge(local.ebs_common_tags, {
    mitre_attack_ids = "TA0001:T1531"
  })
}

query "ebs_snapshot_created_with_encryption_disabled" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_response_elements_snapshot_id}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'CreateSnapshot'
      and (response_elements -> 'encrypted') = false
      ${local.detection_sql_where_conditions}
    order by
      tp_timestamp desc;
  EOQ

  tags = local.ebs_common_tags
}

detection "ebs_snapshot_unlocked" {
  title           = "EBS Snapshot Unlocked"
  description     = "Detect when an EBS snapshot was unlocked, which could allow access to data for a specified duration, potentially exposing sensitive information."
  documentation   = file("./detections/docs/ebs_snapshot_unlocked.md")
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.ebs_snapshot_unlocked

  tags = merge(local.ebs_common_tags, {
    mitre_attack_ids = "TA0010:T1537"
  })
}

query "ebs_snapshot_unlocked" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_unlock_snapshot_request_snapshot_id}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'UnlockSnapshot'
      ${local.detection_sql_where_conditions}
    order by
      tp_timestamp desc;
  EOQ

  tags = local.ebs_common_tags
}
