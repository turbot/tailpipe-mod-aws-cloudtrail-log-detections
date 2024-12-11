locals {
  mitre_v151_ta0009_t1539_common_tags = merge(local.mitre_v151_ta0009_common_tags, {
    mitre_technique_id = "T1539"
  })

  cloudtrail_logs_detect_web_session_cookie_exfiltration_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
}

benchmark "mitre_v151_ta0009_t1539" {
  title         = "T1539 Steal Web Session Cookie"
  type          = "detection"
  # documentation = file("./mitre_v151/docs/ta0009_t1539.md")
  children = [
    detection.cloudtrail_logs_detect_web_session_cookie_exfiltration
  ]

  tags = local.mitre_v151_ta0009_t1539_common_tags
}

detection "cloudtrail_logs_detect_web_session_cookie_exfiltration" {
  title       = "Detect Web Session Cookie Exfiltration"
  description = "Detect API actions that retrieve web session cookies for potential exfiltration."
  severity    = "high"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_web_session_cookie_exfiltration.md")
  query       = query.cloudtrail_logs_detect_web_session_cookie_exfiltration

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0010:T1539"
  })
}

query "cloudtrail_logs_detect_web_session_cookie_exfiltration" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_web_session_cookie_exfiltration_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'elasticloadbalancing.amazonaws.com'
      and event_name in ('GetLoadBalancerCookies')
      and error_code is null
    order by
      event_time desc;
  EOQ
}

