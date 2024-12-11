locals {
  mitre_v151_ta0008_t1210_common_tags = merge(local.mitre_v151_ta0008_common_tags, {
    mitre_technique_id = "T1210"
  })

  cloudtrail_logs_detect_exploitation_remote_services_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
}

benchmark "mitre_v151_ta0008_t1210" {
  title         = "T1210 Exploitation of Remote Services"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0008_t1210.md")
  children = [
    detection.cloudtrail_logs_detect_exploitation_remote_services
  ]

  tags = local.mitre_v151_ta0008_t1210_common_tags
}

detection "cloudtrail_logs_detect_exploitation_remote_services" {
  title       = "Detect Exploitation of Remote Services"
  description = "Detect lateral movement via the exploitation of misconfigured or vulnerable services."
  severity    = "critical"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_exploitation_remote_services.md")
  query       = query.cloudtrail_logs_detect_exploitation_remote_services

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0008:T1210"
  })
}

query "cloudtrail_logs_detect_exploitation_remote_services" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_exploitation_remote_services_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'rds.amazonaws.com'
      and event_name = 'ModifyDBInstance'
      and request_parameters->>'enableIAMDatabaseAuthentication' = 'true'
    order by
      event_time desc;
  EOQ
}
