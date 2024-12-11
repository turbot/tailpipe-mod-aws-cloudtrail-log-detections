locals {
  mitre_v151_ta0008_t1021_001_common_tags = merge(local.mitre_v151_ta0008_common_tags, {
    mitre_technique_id = "T1021.001"
  })

  cloudtrail_logs_detect_remote_services_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
}

benchmark "mitre_v151_ta0008_t1021_001" {
  title         = "T1021.001 Remote Services: AWS Management Console"
  type          = "detection"
  # documentation = file("./mitre_v151/docs/ta0008_t1021_001.md")
  children = [
    detection.cloudtrail_logs_detect_remote_services
  ]

  tags = local.mitre_v151_ta0008_t1021_001_common_tags
}

detection "cloudtrail_logs_detect_remote_services" {
  title       = "Detect Remote AWS Console Login"
  description = "Detect logins from unexpected IP addresses or regions to the AWS Management Console."
  severity    = "high"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_remote_services.md")
  query       = query.cloudtrail_logs_detect_remote_services

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0008:T1021.001"
  })
}

query "cloudtrail_logs_detect_remote_services" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_remote_services_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'signin.amazonaws.com'
      and event_name = 'ConsoleLogin'
      and source_ip_address not in (${local.trusted_ip_list})
    order by
      event_time desc;
  EOQ
}
