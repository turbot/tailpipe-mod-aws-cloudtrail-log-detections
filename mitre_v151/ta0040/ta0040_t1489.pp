locals {
  mitre_v151_ta0040_t1489_common_tags = merge(local.mitre_v151_ta0040_common_tags, {
    mitre_technique_id = "T1489"
  })

  cloudtrail_logs_detect_service_stop_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
}

benchmark "mitre_v151_ta0040_t1489" {
  title         = "T1489 Service Stop"
  type          = "detection"
  # documentation = file("./mitre_v151/docs/ta0040_t1489.md")
  children = [
    detection.cloudtrail_logs_detect_service_stop
  ]

  tags = local.mitre_v151_ta0040_t1489_common_tags
}

detection "cloudtrail_logs_detect_service_stop" {
  title       = "Detect Service Stop in EC2"
  description = "Detect unauthorized stopping of EC2 instances."
  severity    = "high"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_service_stop.md")
  query       = query.cloudtrail_logs_detect_service_stop

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0040:T1489"
  })
}

query "cloudtrail_logs_detect_service_stop" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_service_stop_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'StopInstances'
      and error_code is null
    order by
      event_time desc;
  EOQ
}
