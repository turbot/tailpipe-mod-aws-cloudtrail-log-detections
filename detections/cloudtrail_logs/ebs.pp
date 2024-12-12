locals {
  cloudtrail_logs_detect_ec2_ebs_encryption_disabled_updates_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "recipient_account_id")

  cloudtrail_logs_detect_ebs_snapshot_deleted_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")

  cloudtrail_logs_detect_ebs_volume_deleted_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")

  cloudtrail_logs_detect_ebs_volume_updates_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
}

benchmark "cloudtrail_logs_ebs_detections" {
  title       = "CloudTrail Log EBS Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail's EBS logs"
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_ec2_ebs_encryption_disabled_updates,
    detection.cloudtrail_logs_detect_ebs_snapshot_deleted,
    detection.cloudtrail_logs_detect_ebs_volume_deleted,
    detection.cloudtrail_logs_detect_ebs_volume_updates,
  ]

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    type    = "Benchmark"
    service = "AWS/EBS"
  })
}

detection "cloudtrail_logs_detect_ec2_ebs_encryption_disabled_updates" {
  title       = "Detect EC2 EBS Encryptions Disabled Updates"
  description = "Detect EC2 EBS encryptions disabled updates to check for data at rest encryption."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_ec2_ebs_encryption_disabled_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0003:T1486,TA0040:T1565"
  })
}

detection "cloudtrail_logs_detect_ebs_snapshot_deleted" {
  title       = "Detect Inhibition of System Recovery"
  description = "Detect deletion of EBS snapshots or recovery points."
  severity    = "critical"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_ebs_snapshot_deleted.md")
  query       = query.cloudtrail_logs_detect_ebs_snapshot_deleted

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0040:T1490"
  })
}

detection "cloudtrail_logs_detect_ebs_volume_deleted" {
  title       = "Detect Disk Content Wipe"
  description = "Detect deletion or overwriting of EBS volumes or snapshots."
  severity    = "critical"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_ebs_volume_deleted.md")
  query       = query.cloudtrail_logs_detect_ebs_volume_deleted

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0040:T1561.001"
  })
}

detection "cloudtrail_logs_detect_ebs_volume_updates" {
  title       = "Detect Disk Structure Wipe"
  description = "Detect attempts to corrupt or modify the disk structure of EBS volumes."
  severity    = "critical"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_ebs_volume_updates.md")
  query       = query.cloudtrail_logs_detect_ebs_volume_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0040:T1561.002"
  })
}

query "cloudtrail_logs_detect_ebs_volume_updates" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_ebs_volume_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name in ('ModifyVolume', 'DetachVolume')
      and error_code is null
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_ebs_volume_deleted" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_ebs_volume_deleted_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'DeleteVolume'
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
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_ebs_snapshot_deleted" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_ebs_snapshot_deleted_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name in ('DeleteSnapshot', 'DeleteRecoveryPoint')
      and error_code is null
    order by
      event_time desc;
  EOQ
}
