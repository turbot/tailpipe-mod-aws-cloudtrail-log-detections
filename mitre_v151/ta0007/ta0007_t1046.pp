locals {
  mitre_v151_ta0007_t1046_common_tags = merge(local.mitre_v151_ta0007_common_tags, {
    mitre_technique_id = "T1046"
  })

  cloudtrail_logs_detect_network_service_scanning_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
}

benchmark "mitre_v151_ta0007_t1046" {
  title         = "T1046 Network Service Scanning"
  type          = "detection"
  # documentation = file("./mitre_v151/docs/ta0007_t1046.md")
  children = [
    detection.cloudtrail_logs_detect_network_service_scanning
  ]

  tags = local.mitre_v151_ta0007_t1046_common_tags
}

detection "cloudtrail_logs_detect_network_service_scanning" {
  title       = "Detect Network Service Scanning"
  description = "Detect scanning or enumeration of AWS services."
  severity    = "high"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_network_service_scanning.md")
  query       = query.cloudtrail_logs_detect_network_service_scanning

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0007:T1046"
  })
}

query "cloudtrail_logs_detect_network_service_scanning" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_network_service_scanning_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source in (
        'ec2.amazonaws.com',
        'rds.amazonaws.com',
        'elasticloadbalancing.amazonaws.com'
      )
      and event_name like 'Describe%'
      and error_code is null
    order by
      event_time desc;
  EOQ
}
