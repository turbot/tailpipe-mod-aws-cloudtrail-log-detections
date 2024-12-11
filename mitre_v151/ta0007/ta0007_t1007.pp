locals {
  mitre_v151_ta0007_t1007_common_tags = merge(local.mitre_v151_ta0007_common_tags, {
    mitre_technique_id = "T1007"
  })

cloudtrail_logs_detect_service_discovery_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
}

benchmark "mitre_v151_ta0007_t1007" {
  title         = "T1007 System Service Discovery"
  type          = "detection"
  # documentation = file("./mitre_v151/docs/ta0007_t1007.md")
  children = [
    detection.cloudtrail_logs_detect_service_discovery
  ]

  tags = local.mitre_v151_ta0007_t1007_common_tags
}

detection "cloudtrail_logs_detect_service_discovery" {
  title       = "Detect System Service Discovery"
  description = "Detect querying for running services in AWS."
  severity    = "medium"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_service_discovery.md")
  query       = query.cloudtrail_logs_detect_service_discovery

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0007:T1007"
  })
}

query "cloudtrail_logs_detect_service_discovery" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_service_discovery_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_name like 'Describe%'
      and event_source in (
        'ec2.amazonaws.com',
        'rds.amazonaws.com',
        'elasticloadbalancing.amazonaws.com'
      )
      and error_code is null
    order by
      event_time desc;
  EOQ
}



