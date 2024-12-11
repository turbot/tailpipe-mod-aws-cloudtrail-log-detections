locals {
  mitre_v151_ta0040_t1561_002_common_tags = merge(local.mitre_v151_ta0040_common_tags, {
    mitre_technique_id = "T1561.002"
  })

  cloudtrail_logs_detect_disk_structure_wipe_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
}

benchmark "mitre_v151_ta0040_t1561_002" {
  title         = "T1561.002 Disk Structure Wipe"
  type          = "detection"
  # documentation = file("./mitre_v151/docs/ta0040_t1561_002.md")
  children = [
    detection.cloudtrail_logs_detect_disk_structure_wipe
  ]

  tags = local.mitre_v151_ta0040_t1561_002_common_tags
}

detection "cloudtrail_logs_detect_disk_structure_wipe" {
  title       = "Detect Disk Structure Wipe"
  description = "Detect attempts to corrupt or modify the disk structure of EBS volumes."
  severity    = "critical"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_disk_structure_wipe.md")
  query       = query.cloudtrail_logs_detect_disk_structure_wipe

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0040:T1561.002"
  })
}

query "cloudtrail_logs_detect_disk_structure_wipe" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_disk_structure_wipe_sql_columns}
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
