locals {
  mitre_v151_ta0040_t1485_common_tags = merge(local.mitre_v151_ta0040_common_tags, {
    mitre_technique_id = "T1485"
  })

  cloudtrail_logs_detect_data_destruction_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
}

benchmark "mitre_v151_ta0040_t1485" {
  title         = "T1485 Data Destruction"
  type          = "detection"
  # documentation = file("./mitre_v151/docs/ta0040_t1485.md")
  children = [
    detection.cloudtrail_logs_detect_data_destruction
  ]

  tags = local.mitre_v151_ta0040_t1485_common_tags
}

detection "cloudtrail_logs_detect_data_destruction" {
  title       = "Detect Data Destruction in S3"
  description = "Detect actions that delete S3 buckets or objects."
  severity    = "high"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_data_destruction.md")
  query       = query.cloudtrail_logs_detect_data_destruction

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

query "cloudtrail_logs_detect_data_destruction" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_data_destruction_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 's3.amazonaws.com'
      and event_name in ('DeleteBucket', 'DeleteObject')
    order by
      event_time desc;
  EOQ
}
