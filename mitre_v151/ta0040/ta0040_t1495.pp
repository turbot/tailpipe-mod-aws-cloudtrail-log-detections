locals {
  mitre_v151_ta0040_t1495_common_tags = merge(local.mitre_v151_ta0040_common_tags, {
    mitre_technique_id = "T1495"
  })

  cloudtrail_logs_detect_firmware_corruption_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
}

benchmark "mitre_v151_ta0040_t1495" {
  title         = "T1495 Firmware Corruption"
  type          = "detection"
  # documentation = file("./mitre_v151/docs/ta0040_t1495.md")
  children = [
    detection.cloudtrail_logs_detect_firmware_corruption
  ]

  tags = local.mitre_v151_ta0040_t1495_common_tags
}

detection "cloudtrail_logs_detect_firmware_corruption" {
  title       = "Detect Firmware Corruption"
  description = "Detect attempts to alter EC2 instance metadata or AMI configurations."
  severity    = "high"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_firmware_corruption.md")
  query       = query.cloudtrail_logs_detect_firmware_corruption

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0040:T1495"
  })
}

query "cloudtrail_logs_detect_firmware_corruption" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_firmware_corruption_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name in ('ModifyInstanceAttribute', 'ResetImageAttribute')
      and error_code is null
    order by
      event_time desc;
  EOQ
}
