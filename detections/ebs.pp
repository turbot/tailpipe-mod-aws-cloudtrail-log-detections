locals {
  cloudtrail_log_detection_ebs_common_tags = merge(local.cloudtrail_log_detection_common_tags, {
    service = "AWS/EBS"
  })

  cloudtrail_logs_detect_regions_with_default_ebs_encryption_disabled_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "recipient_account_id")
  cloudtrail_logs_detect_ebs_volume_detachments_sql_columns                       = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.name')")
  cloudtrail_logs_detect_public_access_granted_to_ebs_snapshots_sql_columns       = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.snapshotId')")
  cloudtrail_logs_detect_ebs_snapshots_with_encryption_disabled_sql_columns       = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.snapshotId')")
}

benchmark "cloudtrail_logs_ebs_detections" {
  title       = "EBS Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for EBS events"
  type        = "detection"
  children = [
    detection.cloudtrail_logs_detect_ebs_snapshots_with_encryption_disabled,
    detection.cloudtrail_logs_detect_ebs_volume_detachments,
    detection.cloudtrail_logs_detect_public_access_granted_to_ebs_snapshots,
    detection.cloudtrail_logs_detect_regions_with_default_ebs_encryption_disabled,
  ]

  tags = merge(local.cloudtrail_log_detection_ebs_common_tags, {
    type = "Benchmark"
  })
}

detection "cloudtrail_logs_detect_regions_with_default_ebs_encryption_disabled" {
  title           = "Detect Regions with Default EBS Encryption Disabled"
  description     = "Detect regions with default EBS encryption disabled to check for potential misconfigurations that could leave data at rest unencrypted, increasing the risk of unauthorized access or data breaches."
  severity        = "medium"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_regions_with_default_ebs_encryption_disabled

  tags = merge(local.cloudtrail_log_detection_ebs_common_tags, {
    mitre_attack_ids = "TA0003:T1486,TA0040:T1565"
  })
}

query "cloudtrail_logs_detect_regions_with_default_ebs_encryption_disabled" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_regions_with_default_ebs_encryption_disabled_sql_columns}
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

detection "cloudtrail_logs_detect_ebs_volume_detachments" {
  title           = "Detect EBS Volume Detachments"
  description     = "Detect attempts to detach EBS volumes to check for potential risks of unauthorized modification, corruption, or data loss."
  severity        = "critical"
  display_columns = local.cloudtrail_log_detection_display_columns
  # documentation = file("./detections/docs/cloudtrail_logs_detect_ebs_volume_detachments.md")
  query = query.cloudtrail_logs_detect_ebs_volume_detachments

  tags = merge(local.cloudtrail_log_detection_ebs_common_tags, {
    mitre_attack_ids = "TA0040:T1561.002"
  })
}

query "cloudtrail_logs_detect_ebs_volume_detachments" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_ebs_volume_detachments_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'DetachVolume'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_public_access_granted_to_ebs_snapshots" {
  title           = "Detect Public Access Granted to EBS Snapshots"
  description     = "Detect when an EBS snapshot is shared publicly, potentially exposing sensitive data to unauthorized users."
  severity        = "high"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_public_access_granted_to_ebs_snapshots

  tags = merge(local.cloudtrail_log_detection_ebs_common_tags, {
    mitre_attack_ids = "TA0001:T1531" # Initial Access and Resource Hijacking
  })
}

query "cloudtrail_logs_detect_public_access_granted_to_ebs_snapshots" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_public_access_granted_to_ebs_snapshots_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'ModifySnapshotAttribute'
      and json_extract_string(request_parameters, '$.attribute') = 'createVolumePermission'
      and json_extract_string(request_parameters, '$.createVolumePermission.add') like '%all%'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_ebs_snapshots_with_encryption_disabled" {
  title           = "Detect EBS Snapshots Created with Encryption Disabled"
  description     = "Detect when EBS snapshots are created with encryption disabled, which could lead to data exposure and non-compliance with security policies."
  severity        = "high"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_ebs_snapshots_with_encryption_disabled

  tags = merge(local.cloudtrail_log_detection_ebs_common_tags, {
    mitre_attack_ids = "TA0001:T1531" # Initial Access
  })
}

query "cloudtrail_logs_detect_ebs_snapshots_with_encryption_disabled" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_ebs_snapshots_with_encryption_disabled_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'CreateSnapshot'
      and (json_extract_string(response_elements, '$.encrypted') = 'false'
      or json_extract_string(response_elements, '$.encrypted') is null)
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      tp_timestamp desc;
  EOQ
}
