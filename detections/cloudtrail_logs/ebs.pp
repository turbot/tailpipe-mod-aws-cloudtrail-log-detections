locals {
  cloudtrail_logs_detect_regions_with_default_ebs_encryption_disabled_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "recipient_account_id")
  cloudtrail_logs_detect_ebs_volume_detachments_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
}

benchmark "cloudtrail_logs_ebs_detections" {
  title       = "EBS Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail's EBS logs"
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_regions_with_default_ebs_encryption_disabled,
    detection.cloudtrail_logs_detect_ebs_volume_detachments,
  ]

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    type    = "Benchmark"
    service = "AWS/EBS"
  })
}

detection "cloudtrail_logs_detect_regions_with_default_ebs_encryption_disabled" {
  title       = "Detect EBS Encryptions Disabled Updates"
  description = "Detect EC2 EBS encryptions disabled updates to check for data at rest encryption."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_regions_with_default_ebs_encryption_disabled

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0003:T1486,TA0040:T1565"
  })
}

detection "cloudtrail_logs_detect_ebs_volume_detachments" {
  title       = "Detect EBS Volume Detachments"
  description = "Detect attempts to corrupt or modify the disk structure of EBS volumes."
  severity    = "critical"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_ebs_volume_detachments.md")
  query       = query.cloudtrail_logs_detect_ebs_volume_detachments

  tags = merge(local.cloudtrail_log_detection_common_tags, {
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

