locals {
  ebs_common_tags = merge(local.aws_cloudtrail_log_detections_common_tags, {
    service = "AWS/EBS"
  })

  detect_regions_with_default_ebs_encryption_disabled_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "recipient_account_id")
  detect_ebs_volume_detachments_sql_columns                       = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.name')")
  detect_public_access_granted_to_ebs_snapshots_sql_columns       = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.snapshotId')")
  detect_ebs_snapshots_with_encryption_disabled_sql_columns       = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.snapshotId')")
}

benchmark "ebs_detections" {
  title       = "EBS Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for EBS events"
  type        = "detection"
  children = [
    detection.detect_ebs_snapshots_with_encryption_disabled,
    detection.detect_ebs_volume_detachments,
    detection.detect_public_access_granted_to_ebs_snapshots,
    detection.detect_regions_with_default_ebs_encryption_disabled,
  ]

  tags = merge(local.ebs_common_tags, {
    type = "Benchmark"
  })
}

detection "detect_regions_with_default_ebs_encryption_disabled" {
  title           = "Detect Regions with Default EBS Encryption Disabled"
  description     = "Detect regions with default EBS encryption disabled to check for potential misconfigurations that could leave data at rest unencrypted, increasing the risk of unauthorized access or data breaches."
  documentation   = file("./detections/docs/detect_regions_with_default_ebs_encryption_disabled.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.detect_regions_with_default_ebs_encryption_disabled

  tags = merge(local.ebs_common_tags, {
    mitre_attack_ids = "TA0003:T1486,TA0040:T1565"
  })
}

query "detect_regions_with_default_ebs_encryption_disabled" {
  sql = <<-EOQ
    select
      ${local.detect_regions_with_default_ebs_encryption_disabled_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'DisableEbsEncryptionByDefault'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "detect_ebs_volume_detachments" {
  title           = "Detect EBS Volume Detachments"
  description     = "Detect attempts to detach EBS volumes to check for potential risks of unauthorized modification, corruption, or data loss."
  severity        = "critical"
  display_columns = local.detection_display_columns
  # documentation = file("./detections/docs/detect_ebs_volume_detachments.md")
  query = query.detect_ebs_volume_detachments

  tags = merge(local.ebs_common_tags, {
    mitre_attack_ids = "TA0040:T1561.002"
  })
}

query "detect_ebs_volume_detachments" {
  sql = <<-EOQ
    select
      ${local.detect_ebs_volume_detachments_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'DetachVolume'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "detect_public_access_granted_to_ebs_snapshots" {
  title           = "Detect Public Access Granted to EBS Snapshots"
  description     = "Detect when an EBS snapshot is shared publicly, potentially exposing sensitive data to unauthorized users."
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.detect_public_access_granted_to_ebs_snapshots

  tags = merge(local.ebs_common_tags, {
    mitre_attack_ids = "TA0001:T1531" # Initial Access and Resource Hijacking
  })
}

query "detect_public_access_granted_to_ebs_snapshots" {
  sql = <<-EOQ
    select
      ${local.detect_public_access_granted_to_ebs_snapshots_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'ModifySnapshotAttribute'
      and json_extract_string(request_parameters, '$.attribute') = 'createVolumePermission'
      and json_extract_string(request_parameters, '$.createVolumePermission.add') like '%all%'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "detect_ebs_snapshots_with_encryption_disabled" {
  title           = "Detect EBS Snapshots Created with Encryption Disabled"
  description     = "Detect when EBS snapshots are created with encryption disabled, which could lead to data exposure and non-compliance with security policies."
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.detect_ebs_snapshots_with_encryption_disabled

  tags = merge(local.ebs_common_tags, {
    mitre_attack_ids = "TA0001:T1531" # Initial Access
  })
}

query "detect_ebs_snapshots_with_encryption_disabled" {
  sql = <<-EOQ
    select
      ${local.detect_ebs_snapshots_with_encryption_disabled_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'CreateSnapshot'
      and (json_extract_string(response_elements, '$.encrypted') = 'false'
      or json_extract_string(response_elements, '$.encrypted') is null)
      ${local.detection_sql_where_conditions}
    order by
      tp_timestamp desc;
  EOQ
}
