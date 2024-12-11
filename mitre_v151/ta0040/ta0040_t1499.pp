locals {
  mitre_v151_ta0040_t1499_common_tags = merge(local.mitre_v151_ta0040_common_tags, {
    mitre_technique_id = "T1499"
  })

  cloudtrail_logs_detect_dos_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
}

benchmark "mitre_v151_ta0040_t1499" {
  title         = "T1499 Endpoint Denial of Service"
  type          = "detection"
  # documentation = file("./mitre_v151/docs/ta0040_t1499.md")
  children = [
    detection.cloudtrail_logs_detect_dos
  ]

  tags = local.mitre_v151_ta0040_t1499_common_tags
}

detection "cloudtrail_logs_detect_dos" {
  title       = "Detect Denial of Service Attacks"
  description = "Detect actions leading to potential denial of service on application endpoints."
  severity    = "high"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_dos.md")
  query       = query.cloudtrail_logs_detect_dos

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0040:T1499"
  })
}

query "cloudtrail_logs_detect_dos" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_dos_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'elasticloadbalancing.amazonaws.com'
      and event_name in ('RegisterTargets', 'DeregisterTargets')
      and error_code is null
    order by
      event_time desc;
  EOQ
}
