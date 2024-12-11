locals {
  mitre_v151_ta0007_t1057_common_tags = merge(local.mitre_v151_ta0007_common_tags, {
    mitre_technique_id = "T1057"
  })

  cloudtrail_logs_detect_process_discovery_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
}

benchmark "mitre_v151_ta0007_t1057" {
  title         = "T1057 Process Discovery"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0007_t1057.md")
  children = [
    detection.cloudtrail_logs_detect_process_discovery
  ]

  tags = local.mitre_v151_ta0007_t1057_common_tags
}

detection "cloudtrail_logs_detect_process_discovery" {
  title       = "Detect Process Discovery in AWS"
  description = "Detect actions querying AWS Lambda functions or Step Functions."
  severity    = "medium"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_process_discovery.md")
  query       = query.cloudtrail_logs_detect_process_discovery

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0007:T1057"
  })
}

query "cloudtrail_logs_detect_process_discovery" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_process_discovery_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source in ('lambda.amazonaws.com', 'states.amazonaws.com')
      and event_name like 'List%'
      and error_code is null
    order by
      event_time desc;
  EOQ
}




