locals {
  cloudtrail_logs_detect_ec2_ebs_encryption_disabled_updates_sql_columns         = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "recipient_account_id")
}

benchmark "cloudtrail_logs_ebs_detections" {
  title       = "CloudTrail Log EBS Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail's EBS logs"
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_ec2_ebs_encryption_disabled_updates,
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

query "cloudtrail_logs_detect_ec2_ebs_encryption_disabled_updates" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_ec2_ebs_encryption_disabled_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'DisableEbsEncryptionByDefault'
      and error_code is null
    order by
      event_time desc;
  EOQ
}
