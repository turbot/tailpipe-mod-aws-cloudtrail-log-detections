locals {
  mitre_v151_ta0040_t1561_common_tags = merge(local.mitre_v151_ta0040_common_tags, {
    mitre_technique_id = "T1561"
  })

  cloudtrail_logs_detect_disk_wipe_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
}

benchmark "mitre_v151_ta0040_t1561" {
  title         = "T1561 Disk Wipe"
  type          = "detection"
  # documentation = file("./mitre_v151/docs/ta0040_t1561.md")
  children = [
    detection.cloudtrail_logs_detect_disk_wipe
  ]

  tags = local.mitre_v151_ta0040_t1561_common_tags
}

detection "cloudtrail_logs_detect_disk_wipe" {
  title       = "Detect Disk Wipe in EBS"
  description = "Detect deletion of EBS snapshots or volumes."
  severity    = "critical"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_disk_wipe.md")
  query       = query.cloudtrail_logs_detect_disk_wipe

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0040:T1561"
  })
}

query "cloudtrail_logs_detect_disk_wipe" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_disk_wipe_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name in ('DeleteSnapshot', 'DeleteVolume')
      and error_code is null
    order by
      event_time desc;
  EOQ
}
