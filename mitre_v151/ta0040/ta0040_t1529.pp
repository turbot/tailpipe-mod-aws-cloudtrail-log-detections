locals {
  mitre_v151_ta0040_t1529_common_tags = merge(local.mitre_v151_ta0040_common_tags, {
    mitre_technique_id = "T1529"
  })

  cloudtrail_logs_detect_system_reboot_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
}

benchmark "mitre_v151_ta0040_t1529" {
  title         = "T1529 System Shutdown/Reboot"
  type          = "detection"
  # documentation = file("./mitre_v151/docs/ta0040_t1529.md")
  children = [
    detection.cloudtrail_logs_detect_system_reboot
  ]

  tags = local.mitre_v151_ta0040_t1529_common_tags
}

detection "cloudtrail_logs_detect_system_reboot" {
  title       = "Detect System Reboot"
  description = "Detect attempts to reboot EC2 instances."
  severity    = "medium"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_system_reboot.md")
  query       = query.cloudtrail_logs_detect_system_reboot

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0040:T1529"
  })
}

query "cloudtrail_logs_detect_system_reboot" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_system_reboot_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'RebootInstances'
      and error_code is null
    order by
      event_time desc;
  EOQ
}
