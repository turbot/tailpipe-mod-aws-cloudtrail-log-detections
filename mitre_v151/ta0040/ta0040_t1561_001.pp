locals {
  mitre_v151_ta0040_t1561_001_common_tags = merge(local.mitre_v151_ta0040_common_tags, {
    mitre_technique_id = "T1561.001"
  })

  cloudtrail_logs_detect_disk_content_wipe_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
}

benchmark "mitre_v151_ta0040_t1561_001" {
  title         = "T1561.001 Disk Content Wipe"
  type          = "detection"
  # documentation = file("./mitre_v151/docs/ta0040_t1561_001.md")
  children = [
    detection.cloudtrail_logs_detect_disk_content_wipe
  ]

  tags = local.mitre_v151_ta0040_t1561_001_common_tags
}

detection "cloudtrail_logs_detect_disk_content_wipe" {
  title       = "Detect Disk Content Wipe"
  description = "Detect deletion or overwriting of EBS volumes or snapshots."
  severity    = "critical"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_disk_content_wipe.md")
  query       = query.cloudtrail_logs_detect_disk_content_wipe

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0040:T1561.001"
  })
}

query "cloudtrail_logs_detect_disk_content_wipe" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_disk_content_wipe_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name in ('DeleteVolume', 'CreateVolume')
      and error_code is null
    order by
      event_time desc;
  EOQ
}
