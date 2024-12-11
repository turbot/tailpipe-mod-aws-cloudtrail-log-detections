locals {
  mitre_v151_ta0008_t1563_common_tags = merge(local.mitre_v151_ta0008_common_tags, {
    mitre_technique_id = "T1563"
  })

  cloudtrail_logs_detect_session_hijacking_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")

  trusted_ip_list = "'192.168.1.1', '10.0.0.1'"  # TODO: do we need this in the locals?
}

benchmark "mitre_v151_ta0008_t1563" {
  title         = "T1563 Remote Service Session Hijacking"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0008_t1563.md")
  children = [
    detection.cloudtrail_logs_detect_session_hijacking
  ]

  tags = local.mitre_v151_ta0008_t1563_common_tags
}

detection "cloudtrail_logs_detect_session_hijacking" {
  title       = "Detect Remote Service Session Hijacking"
  description = "Detect attempts to hijack active sessions for lateral movement."
  severity    = "high"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_session_hijacking.md")
  query       = query.cloudtrail_logs_detect_session_hijacking

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0008:T1563"
  })
}

query "cloudtrail_logs_detect_session_hijacking" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_session_hijacking_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'sts.amazonaws.com'
      and event_name = 'AssumeRole'
      and source_ip_address not in (${local.trusted_ip_list})
    order by
      event_time desc;
  EOQ
}
